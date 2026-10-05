#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod memory;
mod settings;
mod system;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt::Write;
use std::rc::{Rc, Weak};
use std::time::{Duration, Instant};

use chrono::Local;
use slint::{CloseRequestResponse, ComponentHandle, ModelRc, Timer, TimerMode, VecModel};
use windows::Win32::Globalization::GetUserDefaultUILanguage;

use memory::Level;
use settings::{AutoMode, HistoryEntry, Language, Settings};

slint::include_modules!();

/// Bump when the terms text changes so everyone is asked again.
const TERMS_VERSION: u32 = 1;

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

/// Lives for the whole process. The window comes and goes; the scheduler keeps running.
struct App {
    state: RefCell<State>,
    window: RefCell<Option<AppWindow>>,
    ticker: Timer,
}

fn main() -> Result<(), slint::PlatformError> {
    if !system::single_instance() {
        return Ok(());
    }
    memory::enable_privileges();

    let app = Rc::new(App {
        state: RefCell::new(State {
            settings: Settings::load(),
            history: settings::load_history(),
            cleaning: false,
            last_auto: Instant::now(),
            loads: VecDeque::with_capacity(SPARK_SAMPLES),
        }),
        window: RefCell::new(None),
        ticker: Timer::default(),
    });
    // Nothing runs and nothing is written until the terms are accepted.
    let _terms = if app.state.borrow().settings.terms_version < TERMS_VERSION {
        Some(ask_terms(&app)?)
    } else {
        app.start()?;
        None
    };

    slint::run_event_loop_until_quit()
}

fn ask_terms(app: &Rc<App>) -> Result<TermsWindow, slint::PlatformError> {
    let terms = TermsWindow::new()?;
    apply_language(app.state.borrow().settings.language);
    terms.on_accepted({
        let (app, terms) = (Rc::downgrade(app), terms.as_weak());
        move || {
            let Some(app) = app.upgrade() else { return };
            {
                let settings = &mut app.state.borrow_mut().settings;
                settings.terms_version = TERMS_VERSION;
                settings.terms_accepted_at = Some(Local::now());
                let _ = settings.save();
            }
            let _ = terms.unwrap().hide();
            if app.start().is_err() {
                let _ = slint::quit_event_loop();
            }
        }
    });
    terms.on_declined(|| {
        let _ = slint::quit_event_loop();
    });
    terms.window().on_close_requested(|| {
        let _ = slint::quit_event_loop();
        CloseRequestResponse::HideWindow
    });
    terms.show()?;
    system::style_title_bar(terms.window());
    Ok(terms)
}

/// Wraps a callback so it only holds a weak reference to the app.
fn bind(app: &Rc<App>, f: impl Fn(&Rc<App>) + 'static) -> impl Fn() + 'static {
    let app: Weak<App> = Rc::downgrade(app);
    move || {
        if let Some(app) = app.upgrade() {
            f(&app)
        }
    }
}

impl App {
    fn start(self: &Rc<Self>) -> Result<(), slint::PlatformError> {
        self.ticker.start(TimerMode::Repeated, Duration::from_secs(1), bind(self, |app| app.tick()));
        self.open_window()
    }

    fn open_window(self: &Rc<Self>) -> Result<(), slint::PlatformError> {
        if let Some(ui) = &*self.window.borrow() {
            return ui.show();
        }

        let ui = AppWindow::new()?;
        {
            let state = self.state.borrow();
            apply_language(state.settings.language);
            show_settings(&ui, &state.settings);
            show_history(&ui, &state.history);
            show_sparkline(&ui, &state.loads);
        }
        show_stats(&ui, &memory::stats());

        let mem = ui.global::<Memory>();
        mem.on_clean(bind(self, |app| app.start_clean(false)));
        mem.on_level_changed(bind(self, |app| {
            app.with_ui(|ui| {
                let settings = &mut app.state.borrow_mut().settings;
                settings.clean_level = level_from_index(ui.global::<Memory>().get_level());
                let _ = settings.save();
            })
        }));
        mem.on_apply_auto(bind(self, |app| {
            app.with_ui(|ui| {
                let mem = ui.global::<Memory>();
                let mut state = app.state.borrow_mut();
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
                show_settings(ui, &state.settings);
            })
        }));
        mem.on_clear_history(bind(self, |app| {
            let mut state = app.state.borrow_mut();
            state.history.clear();
            let _ = settings::save_history(&mut state.history);
            app.with_ui(|ui| show_history(ui, &state.history));
        }));
        ui.global::<Preferences>().on_changed(bind(self, |app| {
            app.with_ui(|ui| {
                let language = match ui.global::<Preferences>().get_language() {
                    1 => Language::En,
                    2 => Language::PtBr,
                    _ => Language::System,
                };
                let settings = &mut app.state.borrow_mut().settings;
                settings.language = language;
                let _ = settings.save();
                apply_language(language);
            })
        }));
        ui.window().on_close_requested(|| {
            let _ = slint::quit_event_loop();
            CloseRequestResponse::HideWindow
        });

        ui.show()?;
        system::style_title_bar(ui.window());
        *self.window.borrow_mut() = Some(ui);
        Ok(())
    }

    fn with_ui(&self, f: impl FnOnce(&AppWindow)) {
        if let Some(ui) = &*self.window.borrow() {
            f(ui);
        }
    }

    fn tick(self: &Rc<Self>) {
        let stats = memory::stats();
        let due = {
            let mut state = self.state.borrow_mut();
            if state.loads.len() == SPARK_SAMPLES {
                state.loads.pop_front();
            }
            state.loads.push_back(stats.load);
            self.with_ui(|ui| {
                show_stats(ui, &stats);
                show_sparkline(ui, &state.loads);
            });
            auto_clean_due(&state, stats.load)
        };
        if due {
            self.start_clean(true);
        }
    }

    fn start_clean(self: &Rc<Self>, automatic: bool) {
        let level = {
            let mut state = self.state.borrow_mut();
            if state.cleaning {
                return;
            }
            state.cleaning = true;
            if automatic {
                state.last_auto = Instant::now();
            }
            state.settings.clean_level
        };
        self.with_ui(|ui| ui.global::<Memory>().set_state(CleanState::Running));

        let (tx, rx) = futures_channel::oneshot::channel();
        std::thread::spawn(move || {
            let _ = tx.send(memory::clean(level));
        });

        let app = Rc::downgrade(self);
        slint::spawn_local(async move {
            let report = rx.await;
            let Some(app) = app.upgrade() else { return };
            let mut state = app.state.borrow_mut();
            state.cleaning = false;
            let Ok(report) = report else {
                app.with_ui(|ui| ui.global::<Memory>().set_state(CleanState::Idle));
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

            app.with_ui(|ui| {
                let mem = ui.global::<Memory>();
                mem.set_last_freed(format_bytes(report.freed().max(0) as u64).into());
                mem.set_state(CleanState::Done);
                show_stats(ui, &report.after);
                show_history(ui, &state.history);
            });
        })
        .unwrap();
    }
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
    let area = if loads.is_empty() {
        String::new()
    } else {
        format!("{line}L{} 100 L{offset} 100 Z", SPARK_SAMPLES - 1)
    };

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

/// Needs at least one component to exist, Slint only loads the bundled catalogs then.
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
