#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod memory;
mod settings;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt::Write;
use std::rc::Rc;
use std::time::{Duration, Instant};

use chrono::Local;
use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use slint::{ComponentHandle, ModelRc, Timer, TimerMode, VecModel};
use windows::Win32::Foundation::{COLORREF, ERROR_ALREADY_EXISTS, GetLastError, HWND};
use windows::Win32::Globalization::GetUserDefaultUILanguage;
use windows::Win32::Graphics::Dwm::{
    DWMWA_BORDER_COLOR, DWMWA_CAPTION_COLOR, DWMWA_TEXT_COLOR, DWMWA_USE_IMMERSIVE_DARK_MODE,
    DwmSetWindowAttribute,
};
use windows::Win32::System::Threading::CreateMutexW;
use windows::core::w;

use memory::Level;
use settings::{AutoMode, HistoryEntry, Language, Settings};

slint::include_modules!();

/// Keeps a RAM limit cleanup from firing every tick when it can't get below the limit.
const LIMIT_COOLDOWN: Duration = Duration::from_secs(120);

/// Seconds of load history drawn in the sparkline.
const SPARK_SAMPLES: usize = 60;

struct State {
    settings: Settings,
    history: Vec<HistoryEntry>,
    cleaning: bool,
    last_auto: Instant,
    loads: VecDeque<u32>,
}

type Shared = Rc<RefCell<State>>;

fn main() -> Result<(), slint::PlatformError> {
    if !single_instance() {
        return Ok(());
    }
    memory::enable_privileges();

    let ui = AppWindow::new()?;
    let state: Shared = Rc::new(RefCell::new(State {
        settings: Settings::load(),
        history: settings::load_history(),
        cleaning: false,
        last_auto: Instant::now(),
        loads: VecDeque::with_capacity(SPARK_SAMPLES),
    }));

    {
        let state = state.borrow();
        apply_language(state.settings.language);
        show_settings(&ui, &state.settings);
        show_history(&ui, &state.history);
    }
    show_stats(&ui, &memory::stats());

    let mem = ui.global::<Memory>();

    mem.on_clean({
        let (ui, state) = (ui.as_weak(), state.clone());
        move || start_clean(&ui.unwrap(), &state, false)
    });

    mem.on_level_changed({
        let (ui, state) = (ui.as_weak(), state.clone());
        move || {
            let mut state = state.borrow_mut();
            state.settings.clean_level = level_from_index(ui.unwrap().global::<Memory>().get_level());
            let _ = state.settings.save();
        }
    });

    mem.on_apply_auto({
        let (ui, state) = (ui.as_weak(), state.clone());
        move || {
            let ui = ui.unwrap();
            let mem = ui.global::<Memory>();
            let mut state = state.borrow_mut();
            let auto = &mut state.settings.auto_clean;
            auto.mode = match mem.get_auto_mode() {
                1 => AutoMode::Interval,
                2 => AutoMode::Limit,
                _ => AutoMode::Off,
            };
            auto.minutes = mem.get_auto_minutes() as u32;
            auto.percent = mem.get_auto_percent() as u32;
            // Restart the interval so applying doesn't trigger an immediate cleanup.
            state.last_auto = Instant::now();
            let _ = state.settings.save();
            show_settings(&ui, &state.settings);
        }
    });

    mem.on_clear_history({
        let (ui, state) = (ui.as_weak(), state.clone());
        move || {
            let mut state = state.borrow_mut();
            state.history.clear();
            let _ = settings::save_history(&mut state.history);
            show_history(&ui.unwrap(), &state.history);
        }
    });

    ui.global::<Preferences>().on_changed({
        let (ui, state) = (ui.as_weak(), state.clone());
        move || {
            let language = match ui.unwrap().global::<Preferences>().get_language() {
                1 => Language::En,
                2 => Language::PtBr,
                _ => Language::System,
            };
            let mut state = state.borrow_mut();
            state.settings.language = language;
            let _ = state.settings.save();
            apply_language(language);
        }
    });

    let timer = Timer::default();
    timer.start(TimerMode::Repeated, Duration::from_secs(1), {
        let (ui, state) = (ui.as_weak(), state.clone());
        move || {
            let Some(ui) = ui.upgrade() else { return };
            let stats = memory::stats();
            show_stats(&ui, &stats);
            {
                let loads = &mut state.borrow_mut().loads;
                if loads.len() == SPARK_SAMPLES {
                    loads.pop_front();
                }
                loads.push_back(stats.load);
                show_sparkline(&ui, loads);
            }
            if auto_clean_due(&state.borrow(), stats.load) {
                start_clean(&ui, &state, true);
            }
        }
    });

    ui.show()?;
    style_title_bar(&ui);
    slint::run_event_loop()?;
    ui.hide()
}

fn auto_clean_due(state: &State, load: u32) -> bool {
    if state.cleaning {
        return false;
    }
    let auto = state.settings.auto_clean;
    let elapsed = state.last_auto.elapsed();
    match auto.mode {
        AutoMode::Off => false,
        AutoMode::Interval => elapsed >= Duration::from_secs(u64::from(auto.minutes) * 60),
        AutoMode::Limit => load >= auto.percent && elapsed >= LIMIT_COOLDOWN,
    }
}

fn start_clean(ui: &AppWindow, state: &Shared, automatic: bool) {
    let level = {
        let mut state = state.borrow_mut();
        if state.cleaning {
            return;
        }
        state.cleaning = true;
        if automatic {
            state.last_auto = Instant::now();
        }
        state.settings.clean_level
    };
    ui.global::<Memory>().set_state(CleanState::Running);

    let (tx, rx) = futures_channel::oneshot::channel();
    std::thread::spawn(move || {
        let _ = tx.send(memory::clean(level));
    });

    let (ui, state) = (ui.as_weak(), state.clone());
    slint::spawn_local(async move {
        let report = rx.await;
        let mut state = state.borrow_mut();
        state.cleaning = false;
        let Some(ui) = ui.upgrade() else { return };
        let mem = ui.global::<Memory>();
        let Ok(report) = report else {
            mem.set_state(CleanState::Idle);
            return;
        };

        state.history.push(HistoryEntry {
            time: Local::now(),
            level,
            automatic,
            before_in_use: report.before.in_use(),
            after_in_use: report.after.in_use(),
        });
        let _ = settings::save_history(&mut state.history);

        mem.set_last_freed(format_bytes(report.freed().max(0) as u64).into());
        mem.set_state(CleanState::Done);
        show_stats(&ui, &report.after);
        show_history(&ui, &state.history);
    })
    .unwrap();
}

fn show_stats(ui: &AppWindow, stats: &memory::Stats) {
    let mem = ui.global::<Memory>();
    mem.set_load(stats.load as f32 / 100.0);
    mem.set_in_use(format_bytes(stats.in_use()).into());
    mem.set_total(format_bytes(stats.total).into());
    mem.set_available(format_bytes(stats.available).into());
    mem.set_standby(format_bytes(stats.standby).into());
    mem.set_modified(format_bytes(stats.modified).into());
    mem.set_free(format_bytes(stats.free).into());

    let total = stats.total.max(1) as f32;
    let used = stats.in_use().saturating_sub(stats.modified) as f32 / total;
    let modified = stats.modified as f32 / total;
    let standby = stats.standby as f32 / total;
    mem.set_part_used(used);
    mem.set_part_modified(modified);
    mem.set_part_standby(standby);
    mem.set_part_free((1.0 - used - modified - standby).max(0.0));
    mem.set_commit(
        format!("{} / {}", format_bytes(stats.commit_used), format_bytes(stats.commit_limit)).into(),
    );
}

/// Builds the line and the filled area as SVG paths, newest sample on the right edge.
fn show_sparkline(ui: &AppWindow, loads: &VecDeque<u32>) {
    let offset = SPARK_SAMPLES - loads.len();
    let mut line = String::new();
    for (i, load) in loads.iter().enumerate() {
        let command = if i == 0 { 'M' } else { 'L' };
        let _ = write!(line, "{command}{} {} ", offset + i, 100 - load.min(&100));
    }
    let area = format!("{line}L{} 100 L{offset} 100 Z", SPARK_SAMPLES - 1);

    let mem = ui.global::<Memory>();
    mem.set_spark_line(line.into());
    mem.set_spark_fill(area.into());
}

fn show_settings(ui: &AppWindow, settings: &Settings) {
    let mem = ui.global::<Memory>();
    mem.set_level(settings.clean_level as i32);
    mem.set_auto_mode(settings.auto_clean.mode as i32);
    mem.set_auto_minutes(settings.auto_clean.minutes as i32);
    mem.set_auto_percent(settings.auto_clean.percent as i32);
    mem.set_applied_mode(settings.auto_clean.mode as i32);
    mem.set_applied_minutes(settings.auto_clean.minutes as i32);
    mem.set_applied_percent(settings.auto_clean.percent as i32);
    ui.global::<Preferences>().set_language(settings.language as i32);
}

fn show_history(ui: &AppWindow, history: &[HistoryEntry]) {
    let biggest = history.iter().map(HistoryEntry::freed).max().unwrap_or(0).max(1) as f32;
    let rows: Vec<HistoryRow> = history
        .iter()
        .rev()
        .map(|entry| HistoryRow {
            time: entry.time.format("%d/%m %H:%M").to_string().into(),
            level: entry.level as i32,
            automatic: entry.automatic,
            freed: format_bytes(entry.freed().max(0) as u64).into(),
            ratio: entry.freed().max(0) as f32 / biggest,
        })
        .collect();
    ui.global::<Memory>().set_history(ModelRc::new(VecModel::from(rows)));
}

fn level_from_index(index: i32) -> Level {
    match index {
        0 => Level::Quick,
        2 => Level::Deep,
        _ => Level::Standard,
    }
}

fn format_bytes(bytes: u64) -> String {
    const MB: f64 = 1024.0 * 1024.0;
    let mb = bytes as f64 / MB;
    if mb >= 1024.0 { format!("{:.1} GB", mb / 1024.0) } else { format!("{mb:.0} MB") }
}

fn apply_language(language: Language) {
    const LANG_PORTUGUESE: u16 = 0x16;
    let code = match language {
        Language::En => "",
        Language::PtBr => "pt_BR",
        Language::System if unsafe { GetUserDefaultUILanguage() } & 0x3ff == LANG_PORTUGUESE => "pt_BR",
        Language::System => "",
    };
    let _ = slint::select_bundled_translation(code);
}

/// Paints the native title bar in the app's colors so it blends with the window content.
fn style_title_bar(ui: &AppWindow) {
    let window = ui.window().window_handle();
    let Ok(handle) = window.window_handle() else { return };
    let RawWindowHandle::Win32(handle) = handle.as_raw() else { return };
    let hwnd = HWND(handle.hwnd.get() as _);

    let rgb = |r: u32, g: u32, b: u32| COLORREF(r | g << 8 | b << 16);
    let dark = 1u32;
    unsafe {
        let set = |attribute, value: *const u32| {
            let _ = DwmSetWindowAttribute(hwnd, attribute, value.cast(), 4);
        };
        set(DWMWA_USE_IMMERSIVE_DARK_MODE, &dark);
        set(DWMWA_CAPTION_COLOR, &rgb(0x0a, 0x0b, 0x0d).0);
        set(DWMWA_BORDER_COLOR, &rgb(0x1f, 0x23, 0x2a).0);
        set(DWMWA_TEXT_COLOR, &rgb(0x8a, 0x91, 0x9c).0);
    }
}

fn single_instance() -> bool {
    // The handle is intentionally never closed: the mutex has to live as long as the process.
    unsafe {
        let _ = CreateMutexW(None, false, w!("Local\\EasyTune"));
        GetLastError() != ERROR_ALREADY_EXISTS
    }
}
