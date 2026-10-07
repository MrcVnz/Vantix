#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod boost;
mod disk;
mod etw;
mod frames;
mod governor;
mod latency;
mod memory;
mod monitor;
mod net;
mod reg;
mod restore;
mod settings;
mod space;
mod startup;
mod system;
mod text;
mod tweaks;

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::fmt::Write;
use std::rc::{Rc, Weak};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use chrono::Local;
use slint::{CloseRequestResponse, ComponentHandle, Model, ModelRc, Timer, TimerMode, VecModel};
use windows::Win32::Globalization::GetUserDefaultUILanguage;

use memory::Level;
use settings::{AutoMode, Change, HistoryEntry, Language, Settings};
use tweaks::{CATALOG, Kind, Section};

slint::include_modules!();

/// Bump when the terms text changes so everyone is asked again.
const TERMS_VERSION: u32 = 2;

/// Seconds of load history drawn in the sparkline.
const SPARK_SAMPLES: usize = 60;

struct State {
    settings: Settings,
    /// Last scan result per cleanup category, `None` until analyzed or when blocked.
    scanned: [Option<u64>; disk::Category::ALL.len()],
    selected: [bool; disk::Category::ALL.len()],
    history: Vec<HistoryEntry>,
    cleaning: bool,
    /// Interval mode counts from here: the last apply, app start or automatic cleanup.
    interval_start: Instant,
    /// Limit mode fires once when usage crosses the limit, then waits for it to drop
    /// back below before it can fire again. Without this it would clean every tick when
    /// a cleanup can't get usage under the limit.
    limit_armed: bool,
    loads: VecDeque<u32>,
    /// Shown until the terms are accepted; closing the window then quits.
    terms_pending: bool,
    changes: Vec<Change>,
    tweaks: Vec<TweakInfo>,
    /// Waiting for the confirmation sheet.
    asked: Option<Ask>,
    /// The tweak being applied right now.
    working: Option<usize>,
    /// Bumped whenever the journal changes, so a state read that started before can't
    /// throw away a change it never saw.
    journal_version: u32,
    /// Whether the baseline restore point still exists. Windows deletes old points when
    /// their reserved space fills up, and then the next change makes a new one.
    baseline_alive: bool,
    /// When this session made the baseline. WMI takes a few seconds to list a new point,
    /// so a listing right after can't be trusted to say it's gone.
    baseline_made: Option<Instant>,
    startup: Vec<startup::Entry>,
    /// The active power plan when the tweak states were last read. Cards show only the
    /// changes made on it; changes on other plans stay in the journal.
    active_plan: Option<String>,
    /// Startup switches still being written.
    startup_writes: u32,
    bloat_running: bool,
    /// Last results, kept so they're still there when the window opens again.
    bloat: Option<Result<net::Bloat, net::BloatError>>,
    dns_running: bool,
    dns: Vec<net::Resolver>,
    /// Traffic totals at the last tick, to turn them into rates.
    traffic: Option<(Instant, HashMap<String, [u64; 2]>)>,
    ticks: u32,
    /// Since when the tray icon has been found missing, see check_tray.
    tray_missing: Option<Instant>,
    opened_without_tray: bool,
    /// The rows on the Monitor page, in screen order, for its buttons.
    programs: Vec<monitor::Program>,
    /// Frame rate recordings, newest first, and the ones picked as A and B.
    runs: Vec<frames::Run>,
    picks: Vec<usize>,
    /// Programs drawing frames, as listed on the Frame rate page.
    drawing: Vec<(u32, String)>,
    /// When the frame trace started, since frames take a moment to arrive.
    frames_since: Option<Instant>,
    /// The Disk space page: drives on offer, the last scan with the paths of its largest
    /// files, the folder shown and the records of its rows. The scan goes when the
    /// window closes, since it holds about 25 bytes per file.
    space_drives: Vec<char>,
    space: Option<(space::Scan, Vec<(u32, String)>)>,
    space_dir: u32,
    space_rows: Vec<u32>,
    space_progress: Option<Arc<AtomicU32>>,
}

/// What a tweak looks like on this machine, read off the UI thread.
#[derive(Clone, Copy, Default)]
struct TweakInfo {
    loaded: bool,
    shown: bool,
    /// `None` when the state couldn't be read.
    on: Option<bool>,
    estimate: Option<u64>,
    /// Actions only: ran in this session.
    ran: bool,
}

#[derive(Clone, Copy)]
enum Ask {
    Apply(usize),
    /// Turn off a tweak that was already in place before Vantix.
    Reset(usize),
    Undo(usize),
    UndoAll,
}

/// What actually runs for one tweak.
enum Op {
    Apply,
    Reset,
    /// The saved state and, for power plan settings, the plan it was saved from.
    Revert(Option<String>, Option<String>),
    /// Undoes a reset by applying the tweak again, on the plan the reset was made on.
    Reapply(Option<String>),
}

/// Lives for the whole process. The window comes and goes; the scheduler keeps running.
struct App {
    state: RefCell<State>,
    window: RefCell<Option<AppWindow>>,
    tray: RefCell<Option<Tray>>,
    ticker: Timer,
}

fn main() -> Result<(), slint::PlatformError> {
    if !system::single_instance() {
        return Ok(());
    }
    system::init_com();
    memory::enable_privileges();

    let app = Rc::new(App {
        state: RefCell::new(State {
            settings: Settings::load(),
            scanned: [None; disk::Category::ALL.len()],
            selected: disk::Category::ALL.map(disk::Category::selected_by_default),
            history: settings::load_history(),
            cleaning: false,
            interval_start: Instant::now(),
            limit_armed: true,
            loads: VecDeque::with_capacity(SPARK_SAMPLES),
            terms_pending: false,
            changes: settings::load_changes(),
            tweaks: vec![TweakInfo::default(); CATALOG.len()],
            asked: None,
            working: None,
            journal_version: 0,
            baseline_alive: false,
            baseline_made: None,
            startup: Vec::new(),
            active_plan: None,
            startup_writes: 0,
            bloat_running: false,
            bloat: None,
            dns_running: false,
            dns: Vec::new(),
            traffic: None,
            ticks: 0,
            tray_missing: None,
            opened_without_tray: false,
            programs: Vec::new(),
            runs: frames::load_runs(),
            picks: Vec::new(),
            drawing: Vec::new(),
            frames_since: None,
            space_drives: Vec::new(),
            space: None,
            space_dir: space::ROOT,
            space_rows: Vec::new(),
            space_progress: None,
        }),
        window: RefCell::new(None),
        tray: RefCell::new(None),
        ticker: Timer::default(),
    });
    // Nothing runs and nothing is written until the terms are accepted: the window opens
    // so people see what they're agreeing to, and the terms come up over it.
    if app.state.borrow().settings.terms_version < TERMS_VERSION {
        app.state.borrow_mut().terms_pending = true;
        app.open_window()?;
        app.with_ui(|ui| {
            ui.global::<Terms>().set_pending(true);
            justify_terms(ui);
        });
        let later = Rc::downgrade(&app);
        Timer::single_shot(Duration::from_millis(1500), move || {
            if let Some(app) = later.upgrade() {
                app.with_ui(|ui| ui.global::<Terms>().set_shown(true));
            }
        });
    } else {
        let autostart = std::env::args().any(|arg| arg == system::AUTOSTART_ARG);
        let minimized = autostart && app.state.borrow().settings.start_minimized;
        app.start(!minimized)?;
    }

    let result = slint::run_event_loop_until_quit();
    // Puts back what ProBalance and the game mode changed before the process goes, and
    // ends the network and frame traces, which would outlive the process.
    governor::stop();
    net::traffic_stop();
    frames::stop();
    latency::stop();
    net::unwatch();
    result
}

fn bind_with<T>(app: &Rc<App>, f: impl Fn(&Rc<App>, T) + 'static) -> impl Fn(T) + 'static {
    let app: Weak<App> = Rc::downgrade(app);
    move |value| {
        if let Some(app) = app.upgrade() {
            f(&app, value)
        }
    }
}

fn bind_with2<T, U>(app: &Rc<App>, f: impl Fn(&Rc<App>, T, U) + 'static) -> impl Fn(T, U) + 'static {
    let app: Weak<App> = Rc::downgrade(app);
    move |first, second| {
        if let Some(app) = app.upgrade() {
            f(&app, first, second)
        }
    }
}

fn bind_close(app: &Rc<App>) -> impl Fn() -> CloseRequestResponse + 'static {
    let app: Weak<App> = Rc::downgrade(app);
    move || {
        if let Some(app) = app.upgrade() {
            if app.state.borrow().terms_pending {
                let _ = slint::quit_event_loop();
            } else {
                app.close_window();
            }
        }
        CloseRequestResponse::HideWindow
    }
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
    fn start(self: &Rc<Self>, open_window: bool) -> Result<(), slint::PlatformError> {
        if let Err(e) = system::register_notifications() {
            system::log_error("notification registration", &e);
        }
        self.ticker.start(TimerMode::Repeated, Duration::from_secs(1), bind(self, |app| app.tick()));
        net::end_leftover_trace();
        frames::end_leftover_trace();
        latency::end_leftover_trace();
        governor::start(live_config(&self.state.borrow().settings));

        apply_language(self.state.borrow().settings.language);
        // A tray that can't be made yet is retried from the ticker, see check_tray.
        if let Err(e) = self.create_tray() {
            system::log_error("tray", &e);
        }

        if open_window { self.open_window() } else { Ok(()) }
    }

    fn create_tray(self: &Rc<Self>) -> Result<(), slint::PlatformError> {
        let tray = Tray::new()?;
        tray.set_auto_on(self.state.borrow().settings.auto_clean.mode != AutoMode::Off);
        tray.on_open(bind(self, |app| {
            let _ = app.open_window();
        }));
        tray.on_clean(bind(self, |app| app.start_clean(false)));
        tray.on_auto_toggled(bind_with(self, |app, on: bool| app.set_auto(on)));
        tray.on_quit(|| {
            let _ = slint::quit_event_loop();
        });
        *self.tray.borrow_mut() = Some(tray);
        Ok(())
    }

    /// Every few seconds, makes sure the tray icon is really there and makes it again when
    /// it isn't: at logon Explorer may not be ready for it, and an Explorer restart takes
    /// it away. If it still can't be shown after a minute, the window opens instead, so
    /// Vantix never runs without a way to reach it.
    fn check_tray(self: &Rc<Self>) {
        const EVERY: u32 = 5;
        const GIVE_UP: Duration = Duration::from_secs(60);
        let missing_since = {
            let mut state = self.state.borrow_mut();
            state.ticks = state.ticks.wrapping_add(1);
            if !state.ticks.is_multiple_of(EVERY) {
                return;
            }
            if system::tray_icon_present() {
                state.tray_missing = None;
                state.opened_without_tray = false;
                return;
            }
            *state.tray_missing.get_or_insert_with(Instant::now)
        };
        if system::taskbar_ready() {
            self.tray.borrow_mut().take();
            if let Err(e) = self.create_tray() {
                system::log_error("tray", &e);
            }
        }
        let mut state = self.state.borrow_mut();
        if missing_since.elapsed() >= GIVE_UP && !state.opened_without_tray {
            state.opened_without_tray = true;
            drop(state);
            system::log_error("tray", &"no tray icon after a minute, opening the window");
            let _ = self.open_window();
        }
    }

    /// Tray shortcut: turns automatic cleanup off, or back on with the last mode used.
    fn set_auto(&self, on: bool) {
        let mut state = self.state.borrow_mut();
        let auto = &mut state.settings.auto_clean;
        if on {
            auto.mode = if auto.last_mode == AutoMode::Off { AutoMode::Limit } else { auto.last_mode };
        } else {
            auto.mode = AutoMode::Off;
        }
        state.interval_start = Instant::now();
        state.limit_armed = true;
        let _ = state.settings.save();
        self.with_ui(|ui| show_settings(ui, &state.settings));
    }

    /// The window is destroyed, not hidden, so its renderer and fonts stop costing memory.
    fn close_window(self: &Rc<Self>) {
        let app = Rc::downgrade(self);
        // Dropping the window from inside its own close handler isn't allowed, so it
        // happens right after.
        Timer::single_shot(Duration::ZERO, move || {
            let Some(app) = app.upgrade() else { return };
            app.window.borrow_mut().take();
            app.state.borrow_mut().space = None;
            memory::trim_self();

            let mut state = app.state.borrow_mut();
            if !state.settings.tray_hint_shown {
                // Only marked as shown once Windows took it, so a failed toast is retried
                // on the next close.
                let mut shown = false;
                app.with_tray(|tray| {
                    shown = system::notify(&tray.invoke_hint_title(), &tray.invoke_hint_body())
                });
                if shown {
                    state.settings.tray_hint_shown = true;
                    let _ = state.settings.save();
                }
            }
        });
    }

    fn with_tray(&self, f: impl FnOnce(&Tray)) {
        if let Some(tray) = &*self.tray.borrow() {
            f(tray);
        }
    }

    fn open_window(self: &Rc<Self>) -> Result<(), slint::PlatformError> {
        if let Some(ui) = &*self.window.borrow() {
            ui.show()?;
            ui.window().set_minimized(false);
            return Ok(());
        }

        let ui = AppWindow::new()?;
        let (text_font, display_font) = text::ui_fonts();
        ui.global::<Theme>().set_text_font(text_font.into());
        ui.global::<Theme>().set_display_font(display_font.into());
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
                if auto.mode != AutoMode::Off {
                    auto.last_mode = auto.mode;
                }
                let on = auto.mode != AutoMode::Off;
                app.with_tray(|tray| tray.set_auto_on(on));
                // The interval counts from now; the limit watches from the next tick.
                state.interval_start = Instant::now();
                state.limit_armed = true;
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
        let prefs = ui.global::<Preferences>();
        prefs.on_changed(bind(self, |app| {
            app.with_ui(|ui| {
                let prefs = ui.global::<Preferences>();
                let language = match prefs.get_language() {
                    1 => Language::En,
                    2 => Language::PtBr,
                    _ => Language::System,
                };
                let settings = &mut app.state.borrow_mut().settings;
                settings.language = language;
                settings.start_minimized = prefs.get_start_minimized();
                settings.notifications = prefs.get_notifications();
                let _ = settings.save();
                apply_language(language);
            })
        }));
        prefs.on_autostart_toggled(bind_with(self, |app, on: bool| {
            if system::set_autostart(on).is_err() {
                app.with_ui(|ui| ui.global::<Preferences>().set_start_with_windows(!on));
            }
        }));
        prefs.on_reset_all(|| {
            system::unregister_all();
            let _ = std::fs::remove_dir_all(settings::data_dir());
            let _ = slint::quit_event_loop();
        });
        let protection = ui.global::<Protection>();
        protection.on_refresh(bind(self, |app| app.refresh_protection()));
        protection.on_create(bind(self, |app| app.create_restore_point()));
        protection.on_enable(bind(self, |app| app.enable_protection()));
        protection.on_remove(bind_with(self, |app, sequence: i32| app.remove_restore_point(sequence as u32)));
        protection.on_open_system_restore(|| {
            let _ = std::process::Command::new(tweaks::system_tool("rstrui.exe")).spawn();
        });
        ui.global::<Job>().on_dismiss(bind(self, |app| {
            app.state.borrow_mut().asked = None;
            app.with_ui(|ui| ui.global::<Job>().set_state(JobState::Idle));
        }));

        let storage = ui.global::<Storage>();
        storage.on_analyze(bind(self, |app| app.analyze_storage()));
        storage.on_clean(bind(self, |app| app.clean_storage()));
        storage.on_toggled({
            let app = Rc::downgrade(self);
            move |index, on| {
                if let Some(app) = app.upgrade() {
                    app.state.borrow_mut().selected[index as usize] = on;
                    app.with_ui(|ui| app.show_storage(ui, None));
                }
            }
        });
        self.show_storage(&ui, None);

        let live = ui.global::<Live>();
        show_live(&ui, &self.state.borrow().settings);
        live.on_changed(bind(self, |app| {
            app.with_ui(|ui| {
                let live = ui.global::<Live>();
                let mut state = app.state.borrow_mut();
                let settings = &mut state.settings;
                let had_gpu = settings.game_mode.gpu;
                settings.probalance = live.get_probalance();
                let game = &mut settings.game_mode;
                game.enabled = live.get_game_mode();
                game.priority = live.get_priority();
                game.cores = live.get_cores();
                game.eco = live.get_eco();
                game.services = live.get_services();
                game.standby = live.get_standby();
                game.wifi = live.get_wifi();
                game.gpu = live.get_gpu();
                if had_gpu && !game.gpu {
                    governor::forget_gpu_choices();
                }
                let _ = settings.save();
                governor::configure(live_config(settings));
            })
        }));

        let startup = ui.global::<Startup>();
        startup.on_refresh(bind(self, |app| app.refresh_startup()));
        startup.on_toggled({
            let app = Rc::downgrade(self);
            move |index, on| {
                if let Some(app) = app.upgrade() {
                    app.toggle_startup(index as usize, on);
                }
            }
        });

        let internet = ui.global::<Net>();
        internet.on_add_host(bind(self, |app| app.add_host()));
        internet.on_remove_host(bind_with(self, |app, i: i32| {
            let mut state = app.state.borrow_mut();
            if (i as usize) < state.settings.ping_hosts.len() {
                state.settings.ping_hosts.remove(i as usize);
                let _ = state.settings.save();
            }
        }));
        internet.on_run_bloat(bind(self, |app| app.run_bloat()));
        internet.on_run_dns(bind(self, |app| app.run_dns()));
        internet.on_use_dns(bind_with(self, |app, row: i32| {
            let provider = app.state.borrow().dns.get(row as usize).and_then(|r| r.provider);
            if let (Some(provider), Some(tweak)) = (provider, dns_tweak()) {
                net::choose_dns(provider);
                app.ask(Ask::Apply(tweak));
            }
        }));
        internet.on_undo_dns(bind(self, |app| {
            if let Some(tweak) = dns_tweak() {
                app.ask(Ask::Undo(tweak));
            }
        }));
        internet.on_limit_upload(bind_with(self, |app, program: slint::SharedString| {
            let mbps = app.state.borrow().settings.upload_mbps;
            let (Some(mbps), Some(tweak)) = (mbps, limit_tweak()) else { return };
            // Half the line leaves the other half for everything else, games and calls included.
            net::choose_limit(&program, (mbps * 500_000.0).max(1_000_000.0) as u64);
            app.ask(Ask::Apply(tweak));
        }));
        internet.on_remove_limit(bind_with(self, |app, program: slint::SharedString| {
            let program = program.to_string();
            app.run_job(
                move || net::remove_limit(&program),
                |app, result| {
                    if let Some(Err(e)) = result {
                        system::log_error(net::LIMIT_TWEAK, &e);
                    }
                    app.refresh_tweaks();
                },
            );
        }));
        internet.set_upload_known(self.state.borrow().settings.upload_mbps.is_some());

        let rates = ui.global::<Frames>();
        rates.set_length(frames::LENGTH as i32);
        rates.on_record(bind_with(self, |app, i: i32| {
            if let Some((pid, name)) = app.state.borrow().drawing.get(i as usize) {
                frames::record(*pid, name);
            }
            app.with_ui(|ui| app.show_frames(ui));
        }));
        rates.on_cancel(bind(self, |app| {
            frames::cancel();
            app.with_ui(|ui| app.show_frames(ui));
        }));
        rates.on_pick(bind_with(self, |app, i: i32| {
            {
                let mut state = app.state.borrow_mut();
                let i = i as usize;
                if let Some(at) = state.picks.iter().position(|&p| p == i) {
                    state.picks.remove(at);
                } else if state.picks.len() < 2 {
                    state.picks.push(i);
                } else {
                    state.picks = vec![i];
                }
            }
            app.with_ui(|ui| app.show_runs(ui));
        }));
        let latency = ui.global::<Latency>();
        latency.on_start(bind(self, |app| {
            let failed = latency::start().is_err();
            app.with_ui(|ui| {
                ui.global::<Latency>().set_failed(failed);
                show_latency(ui);
            });
        }));
        latency.on_stop(bind(self, |app| {
            latency::stop();
            app.with_ui(show_latency);
        }));
        let disk = ui.global::<Space>();
        disk.on_scan(bind(self, |app| app.scan_space()));
        disk.on_enter(bind_with(self, |app, i: i32| {
            let Some(&record) = app.state.borrow().space_rows.get(i as usize) else { return };
            app.state.borrow_mut().space_dir = record;
            app.with_ui(|ui| show_space(ui, &mut app.state.borrow_mut()));
        }));
        disk.on_up(bind(self, |app| {
            {
                let mut state = app.state.borrow_mut();
                let up = state.space.as_ref().and_then(|(scan, _)| scan.parent(state.space_dir));
                state.space_dir = up.unwrap_or(space::ROOT);
            }
            app.with_ui(|ui| show_space(ui, &mut app.state.borrow_mut()));
        }));
        disk.on_reveal(bind_with(self, |app, i: i32| {
            let state = app.state.borrow();
            if let (Some((scan, _)), Some(&record)) = (&state.space, state.space_rows.get(i as usize)) {
                reveal(&scan.path(record));
            }
        }));
        disk.on_reveal_largest(bind_with(self, |app, i: i32| {
            if let Some((_, path)) = app.state.borrow().space.as_ref().and_then(|(_, l)| l.get(i as usize)) {
                reveal(path);
            }
        }));
        {
            let mut state = self.state.borrow_mut();
            let volumes = space::volumes();
            let labels: Vec<slint::SharedString> = volumes.iter().map(|letter| format!("{letter}:").into()).collect();
            state.space_drives = volumes;
            disk.set_drives(ModelRc::new(VecModel::from(labels)));
            let system = std::env::var("SystemDrive").ok().and_then(|d| d.chars().next());
            let at = state.space_drives.iter().position(|&l| Some(l) == system).unwrap_or(0);
            disk.set_drive(at as i32);
        }
        rates.on_remove(bind_with(self, |app, i: i32| {
            {
                let mut state = app.state.borrow_mut();
                if (i as usize) < state.runs.len() {
                    state.runs.remove(i as usize);
                    state.picks.clear();
                    frames::save_runs(&mut state.runs);
                }
            }
            app.with_ui(|ui| app.show_runs(ui));
        }));
        self.show_runs(&ui);

        let monitor = ui.global::<Monitor>();
        monitor.set_sort(monitor::sort() as i32);
        monitor.on_sorted(|key| {
            monitor::set_sort(match key {
                1 => monitor::Sort::Gpu,
                2 => monitor::Sort::Memory,
                _ => monitor::Sort::Cpu,
            })
        });
        monitor.on_end(bind_with(self, |app, i: i32| {
            app.on_program(i, |p| {
                monitor::end(&p.name, &p.pids);
            })
        }));
        monitor.on_eco(bind_with2(self, |app, i: i32, on: bool| {
            app.on_program(i, move |p| {
                monitor::set_eco(&p.name, &p.pids, on);
            })
        }));
        monitor.on_trim(bind_with(self, |app, i: i32| {
            app.on_program(i, |p| {
                monitor::trim(&p.name, &p.pids);
            })
        }));
        self.show_bloat(&ui);
        self.show_dns(&ui);

        let terms = ui.global::<Terms>();
        terms.on_accepted(bind(self, |app| app.accept_terms()));
        terms.on_declined(|| {
            let _ = slint::quit_event_loop();
        });

        let tweaks = ui.global::<Tweaks>();
        tweaks.on_activate(bind_with(self, |app, i: i32| app.ask(Ask::Apply(i as usize))));
        tweaks.on_undo(bind_with(self, |app, i: i32| app.ask(Ask::Undo(i as usize))));
        tweaks.on_undo_all(bind(self, |app| app.ask(Ask::UndoAll)));
        tweaks.on_reset(bind_with(self, |app, i: i32| app.ask(Ask::Reset(i as usize))));
        tweaks.on_restart(|| {
            if let Err(e) = tweaks::restart() {
                system::log_error("restart", &e);
            }
        });
        let job = ui.global::<Job>();
        job.on_confirm(bind(self, |app| app.confirm(true)));
        job.on_proceed_without_point(bind(self, |app| app.confirm(false)));
        self.show_tweaks(&ui);
        // Reading some states starts PowerShell, which waits for the terms like the rest.
        if !self.state.borrow().terms_pending {
            self.refresh_tweaks();
        }

        ui.window().on_close_requested(bind_close(self));
        repaint_after_restore(&ui);

        ui.show()?;
        style_when_ready(ui.as_weak(), 0);
        *self.window.borrow_mut() = Some(ui);
        Ok(())
    }

    fn with_ui(&self, f: impl FnOnce(&AppWindow)) {
        if let Some(ui) = &*self.window.borrow() {
            f(ui);
        }
    }

    fn with_ui_value<T>(&self, f: impl FnOnce(&AppWindow) -> T) -> Option<T> {
        self.window.borrow().as_ref().map(f)
    }

    fn tick(self: &Rc<Self>) {
        if system::show_requested() {
            let _ = self.open_window();
        }
        self.check_tray();
        let stats = memory::stats();
        self.with_tray(|tray| tray.set_load(stats.load as i32));
        let status = governor::status();
        self.with_ui(|ui| {
            let live = ui.global::<Live>();
            live.set_game(status.game.unwrap_or_default().into());
            live.set_restrained(status.restrained as i32);
            live.set_efficient(status.efficient as i32);
        });
        self.tick_internet();
        self.tick_monitor();
        self.tick_frames();
        if let Some(progress) = &self.state.borrow().space_progress {
            let done = progress.load(Ordering::Relaxed) as f32 / 1000.0;
            self.with_ui(|ui| ui.global::<Space>().set_progress(done));
        }
        if self.with_ui_value(|ui| ui.get_page() == LATENCY_PAGE).unwrap_or(false) {
            self.with_ui(show_latency);
        }
        let due = {
            let mut state = self.state.borrow_mut();
            if state.loads.len() == SPARK_SAMPLES {
                state.loads.pop_front();
            }
            state.loads.push_back(stats.load);
            let auto = state.settings.auto_clean;
            if auto.mode == AutoMode::Limit && stats.load < auto.percent {
                state.limit_armed = true;
            }
            self.with_ui(|ui| {
                show_stats(ui, &stats);
                show_sparkline(ui, &state.loads);
                show_auto_status(ui, &state);
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
                state.interval_start = Instant::now();
                state.limit_armed = false;
            }
            state.settings.clean_level
        };
        self.with_ui(|ui| ui.global::<Memory>().set_state(CleanState::Running));

        self.run_job(
            move || memory::clean(level),
            move |app, report| {
                let mut state = app.state.borrow_mut();
                state.cleaning = false;
                let Some(report) = report else {
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

                let freed = format_bytes(report.freed().max(0) as u64);
                if automatic && state.settings.notifications {
                    app.with_tray(|tray| {
                        let body = tray.invoke_freed_body(freed.as_str().into());
                        system::notify(&tray.invoke_freed_title(), &body);
                    });
                }

                app.with_ui(|ui| {
                    let mem = ui.global::<Memory>();
                    mem.set_last_freed(freed.as_str().into());
                    mem.set_state(CleanState::Done);
                    show_stats(ui, &report.after);
                    show_history(ui, &state.history);
                });
            },
        );
    }

    /// Runs `work` on its own thread and hands the result back on the UI thread. `None`
    /// means the work panicked.
    fn run_job<T: Send + 'static>(
        self: &Rc<Self>,
        work: impl FnOnce() -> T + Send + 'static,
        done: impl FnOnce(&Rc<App>, Option<T>) + 'static,
    ) {
        let (tx, rx) = futures_channel::oneshot::channel();
        std::thread::spawn(move || {
            let _ = tx.send(work());
        });
        let app = Rc::downgrade(self);
        slint::spawn_local(async move {
            let result = rx.await.ok();
            if let Some(app) = app.upgrade() {
                done(&app, result);
            }
        })
        .unwrap();
    }

    /// Reads the chosen drive's file table off the UI thread, then the paths of its
    /// largest files, which take a lookup per folder.
    fn scan_space(self: &Rc<Self>) {
        if self.state.borrow().space_progress.is_some() {
            return;
        }
        let Some(letter) = self
            .with_ui_value(|ui| ui.global::<Space>().get_drive())
            .and_then(|i| self.state.borrow().space_drives.get(i as usize).copied())
        else {
            return;
        };
        let progress = Arc::new(AtomicU32::new(0));
        {
            let mut state = self.state.borrow_mut();
            // The old scan's memory goes before the new one is built.
            state.space = None;
            state.space_progress = Some(progress.clone());
        }
        self.with_ui(|ui| {
            let disk = ui.global::<Space>();
            disk.set_scanning(true);
            disk.set_scanned(false);
            disk.set_error("".into());
            disk.set_progress(0.0);
        });
        self.run_job(
            move || {
                let scan = space::scan(letter, &progress)?;
                let largest =
                    scan.largest_files(LARGEST_FILES).iter().map(|e| (e.record, scan.path(e.record))).collect();
                Ok::<_, std::io::Error>((scan, largest))
            },
            |app, result| {
                let error = match result {
                    Some(Ok(scan)) => {
                        let mut state = app.state.borrow_mut();
                        state.space = Some(scan);
                        state.space_dir = space::ROOT;
                        None
                    }
                    Some(Err(e)) => Some(e.to_string()),
                    None => Some(String::from("the scan panicked")),
                };
                if let Some(e) = &error {
                    system::log_error("disk space scan", e);
                }
                let mut state = app.state.borrow_mut();
                state.space_progress = None;
                // The window closed while it read: nothing shows it, so it isn't kept.
                if app.window.borrow().is_none() {
                    state.space = None;
                }
                app.with_ui(|ui| {
                    let disk = ui.global::<Space>();
                    disk.set_scanning(false);
                    if error.is_some() {
                        disk.set_error(disk.invoke_failed());
                    }
                    show_space(ui, &mut state);
                });
            },
        );
    }

    /// Measures every category in parallel; each one is a handful of folders.
    fn analyze_storage(self: &Rc<Self>) {
        self.with_ui(|ui| {
            let rows = ui.global::<Storage>().get_rows();
            for i in 0..rows.row_count() {
                let mut row = rows.row_data(i).unwrap();
                row.state = RowState::Scanning;
                rows.set_row_data(i, row);
            }
            ui.global::<Storage>().set_busy(true);
        });
        self.run_job(
            || {
                std::thread::scope(|scope| {
                    let jobs: Vec<_> =
                        disk::Category::ALL.iter().map(|&c| scope.spawn(move || disk::scan(c))).collect();
                    jobs.into_iter().map(|job| job.join().ok()).collect::<Vec<_>>()
                })
            },
            |app, outcomes| {
                let outcomes = outcomes.unwrap_or_default();
                {
                    let mut state = app.state.borrow_mut();
                    for (i, outcome) in outcomes.iter().enumerate() {
                        state.scanned[i] = match outcome {
                            Some(disk::Outcome::Done(tally)) => Some(tally.bytes),
                            _ => None,
                        };
                    }
                }
                app.with_ui(|ui| {
                    ui.global::<Storage>().set_busy(false);
                    app.show_storage(ui, Some(&outcomes));
                });
            },
        );
    }

    fn clean_storage(self: &Rc<Self>) {
        let chosen: Vec<disk::Category> = {
            let state = self.state.borrow();
            disk::Category::ALL
                .iter()
                .enumerate()
                .filter(|(i, _)| state.selected[*i] && state.scanned[*i].is_some())
                .map(|(_, &c)| c)
                .collect()
        };
        self.with_ui(|ui| {
            let storage = ui.global::<Storage>();
            storage.set_busy(true);
            let rows = storage.get_rows();
            for (i, category) in disk::Category::ALL.iter().enumerate() {
                if chosen.contains(category) {
                    let mut row = rows.row_data(i).unwrap();
                    row.state = RowState::Cleaning;
                    rows.set_row_data(i, row);
                }
            }
        });

        self.run_job(
            move || {
                let (free_before, _) = disk::system_drive_space();
                let outcomes: Vec<_> = chosen.iter().map(|&c| (c, disk::clean(c))).collect();
                let (free_after, _) = disk::system_drive_space();
                (outcomes, free_after.saturating_sub(free_before))
            },
            |app, result| {
                app.with_ui(|ui| {
                    let storage = ui.global::<Storage>();
                    storage.set_busy(false);
                    let Some((outcomes, gained)) = result else { return };
                    let rows = storage.get_rows();
                    for (category, outcome) in outcomes {
                        let i = disk::Category::ALL.iter().position(|&c| c == category).unwrap();
                        let mut row = rows.row_data(i).unwrap();
                        match outcome {
                            disk::Outcome::Done(tally) => {
                                row.state = RowState::Done;
                                row.freed = format_bytes(tally.bytes).into();
                                row.skipped = tally.skipped as i32;
                            }
                            disk::Outcome::Blocked(process) => {
                                row.state = RowState::Blocked;
                                row.blocker = process.trim_end_matches(".exe").into();
                            }
                        }
                        rows.set_row_data(i, row);
                        app.state.borrow_mut().scanned[i] = None;
                    }
                    storage.set_gained(if gained > 0 { format_bytes(gained).into() } else { "".into() });
                    storage.set_selected_total("".into());
                    app.show_drive(ui);
                });
            },
        );
    }

    /// Rebuilds the rows from the last scan; with `outcomes`, from a fresh one.
    fn show_storage(&self, ui: &AppWindow, outcomes: Option<&[Option<disk::Outcome>]>) {
        let storage = ui.global::<Storage>();
        let state = self.state.borrow();
        let current = storage.get_rows();
        let rows: Vec<CleanupRow> = disk::Category::ALL
            .iter()
            .enumerate()
            .map(|(i, _)| {
                let mut row = current.row_data(i).unwrap_or_default();
                row.selected = state.selected[i];
                if let Some(outcome) = outcomes.and_then(|o| o.get(i)) {
                    match outcome {
                        Some(disk::Outcome::Done(tally)) => {
                            row.state = RowState::Ready;
                            row.size = format_bytes(tally.bytes).into();
                            row.files = tally.files as i32;
                        }
                        Some(disk::Outcome::Blocked(process)) => {
                            row.state = RowState::Blocked;
                            row.blocker = process.trim_end_matches(".exe").into();
                        }
                        None => row.state = RowState::Idle,
                    }
                }
                row
            })
            .collect();
        storage.set_rows(ModelRc::new(VecModel::from(rows)));

        let selected: u64 = state
            .scanned
            .iter()
            .zip(state.selected)
            .filter(|(_, on)| *on)
            .filter_map(|(bytes, _)| *bytes)
            .sum();
        let any_scanned = state.scanned.iter().any(Option::is_some);
        storage.set_selected_total(if any_scanned { format_bytes(selected).into() } else { "".into() });
        drop(state);
        self.show_drive(ui);
    }

    fn show_drive(&self, ui: &AppWindow) {
        let storage = ui.global::<Storage>();
        let (free, total) = disk::system_drive_space();
        storage.set_drive(std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into()).into());
        storage.set_free(format_bytes(free).into());
        storage.set_total(format_bytes(total).into());
        storage.set_used(if total == 0 { 0.0 } else { 1.0 - free as f32 / total as f32 });
    }

    fn refresh_protection(self: &Rc<Self>) {
        self.with_ui(|ui| ui.global::<Protection>().set_loading(true));
        self.run_job(
            || (restore::protection_enabled(), restore::list()),
            |app, result| {
                let Some((enabled, Ok(points))) = result else {
                    app.with_ui(|ui| ui.global::<Protection>().set_loading(false));
                    return;
                };
                // Points Windows deleted on its own just don't show up; the list in settings
                // isn't trimmed here, because a point made seconds ago isn't listed yet.
                let rows: Vec<RestorePoint> = {
                    let state = app.state.borrow();
                    let settings = &state.settings;
                    points
                        .iter()
                        .map(|point| RestorePoint {
                            sequence: point.sequence as i32,
                            description: point.description.as_str().into(),
                            created: point
                                .created
                                .map(|time| time.format("%d/%m/%Y %H:%M").to_string())
                                .unwrap_or_default()
                                .into(),
                            own: settings.own_points.contains(&point.sequence),
                            baseline: settings.baseline_point == Some(point.sequence),
                        })
                        .collect()
                };
                app.with_ui(|ui| {
                    let protection = ui.global::<Protection>();
                    protection.set_loading(false);
                    protection.set_enabled(enabled);
                    protection.set_points(ModelRc::new(VecModel::from(rows)));
                })
            },
        );
    }

    /// Only for points Vantix made itself; the UI offers nothing else.
    fn remove_restore_point(self: &Rc<Self>, sequence: u32) {
        if !self.state.borrow().settings.own_points.contains(&sequence) {
            return;
        }
        self.with_ui(|ui| ui.global::<Protection>().set_loading(true));
        self.run_job(
            move || restore::remove(sequence),
            move |app, result| {
                match result {
                    Some(Ok(())) => {
                        let mut state = app.state.borrow_mut();
                        state.settings.own_points.retain(|s| *s != sequence);
                        if state.settings.baseline_point == Some(sequence) {
                            state.settings.baseline_point = None;
                            state.baseline_alive = false;
                        }
                        let _ = state.settings.save();
                    }
                    Some(Err(error)) => {
                        system::log_error("remove restore point", &error);
                        app.show_job(JobState::Failed, &format!("#{sequence}"), false);
                        app.set_job(JobState::Failed, &error.message());
                    }
                    None => {}
                }
                app.refresh_protection();
            },
        );
    }

    fn create_restore_point(self: &Rc<Self>) {
        let name = self
            .with_ui_value(|ui| ui.global::<Protection>().get_new_name().trim().to_string())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| "Vantix manual point".into());
        self.show_job(JobState::CreatingPoint, &name, false);

        self.run_job(
            move || restore::create(&name),
            |app, result| {
                match result {
                    Some(Ok(sequence)) => {
                        {
                            let mut state = app.state.borrow_mut();
                            state.settings.own_points.push(sequence);
                            let _ = state.settings.save();
                        }
                        app.with_ui(|ui| ui.global::<Protection>().set_new_name("".into()));
                        app.set_job(JobState::Done, "");
                    }
                    Some(Err(error)) => app.set_job(JobState::PointFailed, &error.message()),
                    None => app.set_job(JobState::Failed, ""),
                }
                app.refresh_protection();
                // WMI can lag a moment behind a brand new point.
                let later = Rc::downgrade(app);
                Timer::single_shot(Duration::from_secs(3), move || {
                    if let Some(app) = later.upgrade() {
                        app.refresh_protection();
                    }
                });
            },
        );
    }

    fn enable_protection(self: &Rc<Self>) {
        self.run_job(restore::enable_protection, |app, result| {
            if let Some(Err(error)) = result {
                app.show_job(JobState::Failed, "System Restore", false);
                app.set_job(JobState::Failed, &error.message());
            }
            app.refresh_protection();
        });
    }

    fn show_job(&self, state: JobState, subject: &str, has_change: bool) {
        self.with_ui(|ui| {
            let job = ui.global::<Job>();
            job.set_subject(subject.into());
            job.set_has_change(has_change);
            job.set_detail("".into());
            job.set_freed("".into());
            job.set_tweak(-1);
            job.set_undo(false);
            job.set_reset(false);
            job.set_reboot(false);
            job.set_slow(false);
            job.set_with_point(false);
            job.set_baseline(false);
            job.set_protection_off(false);
            job.set_toggle(false);
            job.set_elapsed(0);
            job.set_state(state);
        });
    }

    fn accept_terms(self: &Rc<Self>) {
        {
            let mut state = self.state.borrow_mut();
            state.terms_pending = false;
            state.settings.terms_version = TERMS_VERSION;
            state.settings.terms_accepted_at = Some(Local::now());
            let _ = state.settings.save();
        }
        self.with_ui(|ui| {
            let terms = ui.global::<Terms>();
            terms.set_shown(false);
            terms.set_pending(false);
        });
        if self.start(false).is_err() {
            let _ = slint::quit_event_loop();
        }
        // The window opened before the governor knew the hardware.
        self.with_ui(|ui| show_live(ui, &self.state.borrow().settings));
        self.refresh_tweaks();
    }

    /// Reads every tweak's real state in parallel. A few of them start PowerShell, which
    /// takes about a second.
    fn refresh_tweaks(self: &Rc<Self>) {
        let (version, baseline, plans) = {
            let state = self.state.borrow();
            let mut plans: Vec<String> = state.changes.iter().filter_map(|c| c.plan.clone()).collect();
            plans.dedup();
            (state.journal_version, state.settings.baseline_point, plans)
        };
        self.run_job(
            move || {
                let alive = baseline.is_some_and(|sequence| {
                    restore::list().is_ok_and(|points| points.iter().any(|p| p.sequence == sequence))
                });
                let reads = std::thread::scope(|scope| {
                    let jobs: Vec<_> = CATALOG
                        .iter()
                        .map(|tweak| {
                            scope.spawn(move || {
                                let shown = (tweak.shown)();
                                let on = match &tweak.kind {
                                    Kind::Toggle { read, .. } if shown => {
                                        read().inspect_err(|e| system::log_error(tweak.id, e)).ok()
                                    }
                                    _ => None,
                                };
                                (shown, on, (tweak.estimate)())
                            })
                        })
                        .collect();
                    jobs.into_iter().map(|job| job.join().ok()).collect::<Vec<_>>()
                });
                let gone: Vec<String> = plans.into_iter().filter(|plan| !boost::plan_exists(plan)).collect();
                (reads, alive, boost::active_plan(), gone)
            },
            move |app, results| {
                let Some((results, alive, active, gone)) = results else { return };
                {
                    let mut state = app.state.borrow_mut();
                    let fresh =
                        state.baseline_made.is_some_and(|made| made.elapsed() < Duration::from_secs(120));
                    state.baseline_alive = alive || fresh;
                    for (info, result) in state.tweaks.iter_mut().zip(results) {
                        let (shown, on, estimate) = result.unwrap_or((false, None, None));
                        *info = TweakInfo { loaded: true, shown, on, estimate, ran: info.ran };
                    }
                    state.active_plan = active.clone();
                    // Only trusted when no change landed while these states were read.
                    let current = state.journal_version == version && state.working.is_none();
                    // Plan settings from before the journal kept plans were made on the plan
                    // that's active now, unless the plan changed since.
                    let mut dirty = false;
                    if current {
                        for change in &mut state.changes {
                            if change.plan.is_none()
                                && CATALOG.iter().any(|t| t.id == change.id && t.on_plan)
                            {
                                change.plan = active.clone();
                                dirty = true;
                            }
                        }
                    }
                    // A change that Windows or the user undid elsewhere has nothing left to
                    // undo, and neither has one whose plan was deleted. Changes on a plan that
                    // isn't active can't be checked, so they stay.
                    let stale: Vec<(String, Option<String>)> = state
                        .changes
                        .iter()
                        .filter(|change| match (CATALOG.iter().position(|t| t.id == change.id), &change.plan) {
                            (None, _) => true,
                            (Some(_), Some(plan)) if gone.contains(plan) => true,
                            (Some(_), Some(plan)) if Some(plan) != active.as_ref() => false,
                            // A reset is stale once the tweak is back on, a change once it's off.
                            (Some(i), _) => state.tweaks[i].on == Some(change.reset),
                        })
                        .map(|change| (change.id.clone(), change.plan.clone()))
                        .collect();
                    if current && !stale.is_empty() {
                        state.changes.retain(|c| !stale.contains(&(c.id.clone(), c.plan.clone())));
                        dirty = true;
                    }
                    if dirty {
                        let _ = settings::save_changes(&state.changes);
                    }
                }
                app.with_ui(|ui| app.show_tweaks(ui));
            },
        );
    }

    fn refresh_startup(self: &Rc<Self>) {
        self.run_job(startup::list, |app, entries| {
            let Some(entries) = entries else { return };
            // Read while a switch was being written, so it may show the old state.
            if app.state.borrow().startup_writes > 0 {
                return;
            }
            app.state.borrow_mut().startup = entries;
            app.with_ui(|ui| app.show_startup(ui));
        });
    }

    /// Updates one row in place, so the list keeps its scroll position. A failure rebuilds
    /// the list instead: the switch already flipped itself and only a new row puts it back.
    /// The entry is found again by what it is, since the list may have been read anew.
    fn toggle_startup(self: &Rc<Self>, index: usize, on: bool) {
        let Some(entry) = self.state.borrow().startup.get(index).cloned() else { return };
        self.state.borrow_mut().startup_writes += 1;
        self.run_job(
            {
                let entry = entry.clone();
                move || startup::set_enabled(&entry, on)
            },
            move |app, result| {
                app.state.borrow_mut().startup_writes -= 1;
                if !matches!(result, Some(Ok(()))) {
                    if let Some(Err(e)) = result {
                        system::log_error("startup", &e);
                    }
                    app.with_ui(|ui| app.show_startup(ui));
                    return;
                }
                let mut state = app.state.borrow_mut();
                let Some(index) = state.startup.iter().position(|e| e.same(&entry)) else { return };
                let entry = &mut state.startup[index];
                entry.enabled = on;
                let row = startup_row(entry);
                let count = state.startup.iter().filter(|e| e.enabled).count() as i32;
                app.with_ui(|ui| {
                    let startup = ui.global::<Startup>();
                    startup.get_rows().set_row_data(index, row);
                    startup.set_enabled_count(count);
                });
            },
        );
    }

    fn show_startup(&self, ui: &AppWindow) {
        let state = self.state.borrow();
        let rows: Vec<StartupRow> = state.startup.iter().map(startup_row).collect();
        let startup = ui.global::<Startup>();
        startup.set_enabled_count(state.startup.iter().filter(|e| e.enabled).count() as i32);
        startup.set_rows(ModelRc::new(VecModel::from(rows)));
        startup.set_loaded(true);
    }

    fn show_tweaks(&self, ui: &AppWindow) {
        let state = self.state.borrow();
        let change = |id: &str| {
            state.changes.iter().find(|c| c.id == id && (c.plan.is_none() || c.plan == state.active_plan))
        };
        let row = |i: usize| {
            let (tweak, info) = (&CATALOG[i], state.tweaks[i]);
            let applied = change(tweak.id);
            let pending = applied.is_some_and(|c| c.reboot && tweaks::same_boot(c.boot));
            let state = if state.working == Some(i) {
                TweakState::Busy
            } else if let Kind::Action { .. } = tweak.kind {
                if info.ran { TweakState::Ran } else { TweakState::Action }
            } else if !info.loaded {
                TweakState::Loading
            } else {
                match (info.on, applied.map(|c| c.reset)) {
                    (Some(true), Some(false)) => TweakState::On,
                    (Some(true), _) => TweakState::System,
                    (Some(false), Some(true)) => TweakState::Reverted,
                    (Some(false), _) => TweakState::Off,
                    (None, _) => TweakState::Unknown,
                }
            };
            TweakRow {
                index: i as i32,
                state,
                gain: tweak.gain as i32,
                cost: tweak.cost as i32,
                reboot: tweak.reboot,
                pending,
                estimate: info.estimate.map(format_bytes).unwrap_or_default().into(),
                freed: applied.and_then(|c| c.freed).map(format_bytes).unwrap_or_default().into(),
            }
        };
        let section = |section: Section| -> Vec<TweakRow> {
            (0..CATALOG.len())
                .filter(|&i| {
                    CATALOG[i].section == section && (!state.tweaks[i].loaded || state.tweaks[i].shown)
                })
                .map(row)
                .collect()
        };

        let changes: Vec<ChangeRow> = state
            .changes
            .iter()
            .rev()
            .filter_map(|change| {
                let index = CATALOG.iter().position(|t| t.id == change.id)?;
                Some(ChangeRow {
                    index: index as i32,
                    time: change.time.format("%d/%m/%Y %H:%M").to_string().into(),
                    freed: change.freed.map(format_bytes).unwrap_or_default().into(),
                    pending: change.reboot && tweaks::same_boot(change.boot),
                    reset: change.reset,
                })
            })
            .collect();

        let tweaks = ui.global::<Tweaks>();
        tweaks.set_performance(ModelRc::new(VecModel::from(section(Section::Performance))));
        tweaks.set_games(ModelRc::new(VecModel::from(section(Section::Games))));
        tweaks.set_internet(ModelRc::new(VecModel::from(section(Section::Internet))));
        tweaks.set_network(ModelRc::new(VecModel::from(section(Section::Network))));
        tweaks.set_input(ModelRc::new(VecModel::from(section(Section::Input))));
        tweaks.set_storage(ModelRc::new(VecModel::from(section(Section::Storage))));
        tweaks.set_background(ModelRc::new(VecModel::from(section(Section::Background))));
        tweaks.set_pending_count(changes.iter().filter(|c| c.pending).count() as i32);
        tweaks.set_changes(ModelRc::new(VecModel::from(changes)));
        tweaks.set_busy(state.working.is_some());
    }

    fn tweak_title(&self, i: usize) -> String {
        self.with_ui_value(|ui| {
            ui.global::<TweakText>().get_titles().row_data(i).unwrap_or_default().to_string()
        })
        .unwrap_or_default()
    }

    /// Puts up the confirmation sheet with what the change gives, costs and needs.
    fn ask(self: &Rc<Self>, ask: Ask) {
        let (index, undo) = match ask {
            Ask::Apply(i) | Ask::Reset(i) => (Some(i), false),
            Ask::Undo(i) => (Some(i), true),
            Ask::UndoAll => (None, true),
        };
        let reset = matches!(ask, Ask::Reset(_));
        let mut subject = index.map(|i| self.tweak_title(i)).unwrap_or_default();
        // Which service is about to be set, right in the title.
        if let (Ask::Apply(i), Some(name)) = (ask, net::chosen_dns())
            && CATALOG[i].id == net::DNS_TWEAK
        {
            subject = format!("{subject}: {name}");
        }
        if let (Ask::Apply(i), Some((program, bits))) = (ask, net::chosen_limit())
            && CATALOG[i].id == net::LIMIT_TWEAK
        {
            let program = program.trim_end_matches(".exe");
            subject = format!("{subject}: {program}, {}", format_mbps(bits as f64 / 1e6));
        }
        // Only changes that can be undone need a restore point; a retrim has nothing to save.
        // One point covers them all: the one made before Vantix's first change.
        let toggle = index.is_some_and(|i| matches!(CATALOG[i].kind, Kind::Toggle { .. }));
        let protection = !undo && toggle && restore::protection_enabled();
        let baseline = self.state.borrow().baseline_alive;
        self.state.borrow_mut().asked = Some(ask);
        self.show_job(JobState::Confirm, &subject, true);
        self.with_ui(|ui| {
            let job = ui.global::<Job>();
            let tweak = index.map(|i| &CATALOG[i]);
            job.set_tweak(index.map_or(-1, |i| i as i32));
            job.set_undo(undo);
            job.set_reset(reset);
            job.set_gain(tweak.map_or(0, |t| t.gain as i32));
            job.set_cost(tweak.map_or(0, |t| t.cost as i32));
            job.set_reboot(tweak.is_some_and(|t| t.reboot));
            job.set_slow(tweak.is_some_and(|t| t.slow));
            job.set_with_point(protection && !baseline);
            job.set_baseline(protection && baseline);
            job.set_protection_off(!undo && toggle && !protection);
        });
    }

    /// From the confirmation sheet, or with `use_point` false from the "apply without a
    /// restore point" button after the point failed.
    fn confirm(self: &Rc<Self>, use_point: bool) {
        let Some(ask) = self.state.borrow().asked else { return };
        let with_point =
            use_point && self.with_ui_value(|ui| ui.global::<Job>().get_with_point()).unwrap_or(false);
        let (Ask::Apply(i) | Ask::Reset(i)) = ask else {
            self.apply(ask);
            return;
        };
        if !with_point {
            self.apply(ask);
            return;
        }

        let title = self.tweak_title(i);
        self.show_job(JobState::CreatingPoint, &title, true);
        self.run_job(
            move || restore::create(&format!("Vantix: {title}")),
            move |app, result| match result {
                Some(Ok(sequence)) => {
                    {
                        let mut state = app.state.borrow_mut();
                        state.settings.baseline_point = Some(sequence);
                        state.settings.own_points.push(sequence);
                        state.baseline_alive = true;
                        state.baseline_made = Some(Instant::now());
                        let _ = state.settings.save();
                    }
                    app.apply(ask)
                }
                Some(Err(error)) => app.set_job(JobState::PointFailed, &error.message()),
                None => app.set_job(JobState::PointFailed, ""),
            },
        );
    }

    fn apply(self: &Rc<Self>, ask: Ask) {
        let work: Vec<(usize, Op)> = {
            let mut state = self.state.borrow_mut();
            state.asked = None;
            let undo = |change: &Change| {
                if change.reset {
                    Op::Reapply(change.plan.clone())
                } else {
                    Op::Revert(change.previous.clone(), change.plan.clone())
                }
            };
            let work = match ask {
                Ask::Apply(i) => vec![(i, Op::Apply)],
                Ask::Reset(i) => vec![(i, Op::Reset)],
                Ask::Undo(i) => {
                    state.changes.iter().filter(|c| c.id == CATALOG[i].id).map(|c| (i, undo(c))).collect()
                }
                Ask::UndoAll => state
                    .changes
                    .iter()
                    .rev()
                    .filter_map(|c| CATALOG.iter().position(|t| t.id == c.id).map(|i| (i, undo(c))))
                    .collect(),
            };
            state.working = work.first().map(|w| w.0);
            work
        };
        let subject = match ask {
            Ask::UndoAll => String::new(),
            Ask::Apply(i) | Ask::Reset(i) | Ask::Undo(i) => self.tweak_title(i),
        };
        self.show_job(JobState::Applying, &subject, true);
        let slow = work.iter().any(|(i, _)| CATALOG[*i].slow);
        self.with_ui(|ui| {
            // The progress and done titles say which way the change went.
            let job = ui.global::<Job>();
            let index = match ask {
                Ask::Apply(i) | Ask::Reset(i) | Ask::Undo(i) => Some(i),
                Ask::UndoAll => None,
            };
            job.set_tweak(index.map_or(-1, |i| i as i32));
            job.set_undo(matches!(ask, Ask::Undo(_) | Ask::UndoAll));
            job.set_reset(matches!(ask, Ask::Reset(_)));
            job.set_toggle(index.is_some_and(|i| matches!(CATALOG[i].kind, Kind::Toggle { .. })));
            job.set_slow(slow);
            self.show_tweaks(ui);
        });

        self.run_job(
            move || {
                let (free_before, _) = disk::system_drive_space();
                let active = boost::active_plan();
                let mut outcomes = Vec::new();
                for (i, op) in work {
                    let tweak = &CATALOG[i];
                    // Undo goes to the plan the change was made on; new changes land on the
                    // active one.
                    let plan = match &op {
                        Op::Revert(_, plan) | Op::Reapply(plan) => plan.clone().or_else(|| active.clone()),
                        Op::Apply | Op::Reset => active.clone(),
                    }
                    .filter(|_| tweak.on_plan);
                    let result = boost::on_plan(plan.as_deref(), || match (&tweak.kind, &op) {
                        (Kind::Toggle { apply, .. }, Op::Apply) => apply(),
                        (Kind::Toggle { reset, .. }, Op::Reset) => reset().map(|_| None),
                        (Kind::Toggle { revert, .. }, Op::Revert(previous, _)) => {
                            revert(previous.as_deref()).map(|_| None)
                        }
                        (Kind::Toggle { apply, .. }, Op::Reapply(_)) => apply().map(|_| None),
                        (Kind::Action { run }, _) => run().map(|_| None),
                    });
                    let failed = result.is_err();
                    outcomes.push((i, op, plan, result));
                    if failed {
                        break;
                    }
                }
                let (free_after, _) = disk::system_drive_space();
                (outcomes, free_after.saturating_sub(free_before), active)
            },
            |app, result| {
                let Some((outcomes, gained, active)) = result else {
                    app.state.borrow_mut().working = None;
                    app.set_job(JobState::Failed, "");
                    app.with_ui(|ui| app.show_tweaks(ui));
                    app.refresh_tweaks();
                    return;
                };
                // Under 1 MB is just the noise of other programs writing.
                let gained = (gained >= 1 << 20).then_some(gained);
                let mut error = None;
                let mut reboot = false;
                {
                    let mut state = app.state.borrow_mut();
                    state.working = None;
                    state.journal_version += 1;
                    for (i, op, plan, result) in outcomes {
                        let tweak = &CATALOG[i];
                        match result {
                            Ok(previous) => {
                                reboot |= tweak.reboot;
                                // Old entries of a plan setting have no plan yet; they belong to
                                // the plan that was active, like the change replacing them.
                                state.changes.retain(|c| {
                                    let owner = c.plan.as_ref().or(active.as_ref()).filter(|_| tweak.on_plan);
                                    c.id != tweak.id || owner != plan.as_ref()
                                });
                                let journal = |reset: bool| Change {
                                    id: tweak.id.into(),
                                    time: Local::now(),
                                    previous: previous.clone(),
                                    boot: tweaks::boot_time(),
                                    reboot: tweak.reboot,
                                    freed: gained,
                                    reset,
                                    plan: plan.clone(),
                                };
                                // A change on another plan doesn't alter what the card shows.
                                if let Kind::Toggle { .. } = tweak.kind
                                    && (plan.is_none() || plan == active)
                                {
                                    let on = matches!(op, Op::Apply | Op::Reapply(_));
                                    state.tweaks[i].on = Some(on);
                                }
                                match (&tweak.kind, op) {
                                    (Kind::Action { .. }, _) => state.tweaks[i].ran = true,
                                    (_, Op::Apply) => state.changes.push(journal(false)),
                                    (_, Op::Reset) => state.changes.push(journal(true)),
                                    (_, Op::Revert(..) | Op::Reapply(_)) => {}
                                }
                            }
                            Err(e) => {
                                system::log_error(tweak.id, &e);
                                error = Some(e.message());
                            }
                        }
                    }
                    let _ = settings::save_changes(&state.changes);
                }
                match error {
                    Some(message) => app.set_job(JobState::Failed, &message),
                    None => {
                        app.with_ui(|ui| {
                            let job = ui.global::<Job>();
                            job.set_freed(gained.map(format_bytes).unwrap_or_default().into());
                            job.set_reboot(reboot);
                        });
                        app.set_job(JobState::Done, "");
                    }
                }
                app.with_ui(|ui| {
                    app.show_tweaks(ui);
                    app.show_dns(ui);
                });
                app.refresh_tweaks();
                app.refresh_protection();
            },
        );
    }

    /// Samples only while the Monitor page is on screen.
    fn tick_monitor(&self) {
        let open = self.with_ui_value(|ui| ui.get_page() == MONITOR_PAGE).unwrap_or(false);
        if !open {
            monitor::unwatch();
            return;
        }
        monitor::watch();
        let snapshot = monitor::snapshot();
        let mut state = self.state.borrow_mut();
        self.with_ui(|ui| show_monitor(ui, snapshot.as_ref(), &mut state.programs));
    }

    /// The frame trace runs while its page is open or a recording is under way, which
    /// carries on with the window closed.
    fn tick_frames(&self) {
        if let Some(result) = frames::finished() {
            let notify = self.state.borrow().settings.notifications;
            match result {
                Ok(run) => {
                    let name = run.name.trim_end_matches(".exe").to_string();
                    let (average, low) = (format!("{:.0}", run.average), format!("{:.0}", run.low1));
                    {
                        let mut state = self.state.borrow_mut();
                        state.runs.insert(0, run);
                        for pick in &mut state.picks {
                            *pick += 1;
                        }
                        frames::save_runs(&mut state.runs);
                    }
                    if notify {
                        self.with_tray(|tray| {
                            let body = tray.invoke_recorded_body(name.into(), average.into(), low.into());
                            system::notify(&tray.invoke_recorded_title(), &body);
                        });
                    }
                }
                Err(name) if notify => self.with_tray(|tray| {
                    let body = tray.invoke_recorded_short(name.trim_end_matches(".exe").into());
                    system::notify(&tray.invoke_recorded_title(), &body);
                }),
                Err(_) => {}
            }
            self.with_ui(|ui| self.show_runs(ui));
        }

        let open = self.with_ui_value(|ui| ui.get_page() == FRAMES_PAGE).unwrap_or(false);
        if open || frames::recording() {
            let failed = frames::start().is_err();
            let since = *self.state.borrow_mut().frames_since.get_or_insert_with(Instant::now);
            self.with_ui(|ui| {
                let rates = ui.global::<Frames>();
                rates.set_failed(failed);
                rates.set_warming(since.elapsed() < Duration::from_secs(4));
            });
        } else {
            frames::stop();
            self.state.borrow_mut().frames_since = None;
        }
        if open {
            self.with_ui(|ui| self.show_frames(ui));
        }
    }

    fn show_frames(&self, ui: &AppWindow) {
        let live = frames::live();
        let rows: Vec<LiveRow> = live
            .iter()
            .take(8)
            .map(|l| LiveRow {
                name: l.name.trim_end_matches(".exe").into(),
                fps: format!("{:.0}", l.fps).into(),
                frame_time: format!("{:.1} ms", 1000.0 / l.fps).into(),
            })
            .collect();
        self.state.borrow_mut().drawing = live.into_iter().take(8).map(|l| (l.pid, l.name)).collect();
        let rates = ui.global::<Frames>();
        rates.set_live(ModelRc::new(VecModel::from(rows)));
        let (progress, target) = frames::progress();
        let (stage, seconds) = match progress {
            frames::Progress::Idle => (0, 0),
            frames::Progress::Countdown(s) => (1, s),
            frames::Progress::Recording(s) => (2, s),
        };
        rates.set_stage(stage);
        rates.set_seconds(seconds as i32);
        rates.set_target(target.trim_end_matches(".exe").into());
    }

    fn show_runs(&self, ui: &AppWindow) {
        let state = self.state.borrow();
        let rows: Vec<RunRow> = state
            .runs
            .iter()
            .enumerate()
            .map(|(i, run)| RunRow {
                name: run.name.trim_end_matches(".exe").into(),
                time: format!("{}, {:.0} s", run.time.format("%d/%m %H:%M"), run.seconds).into(),
                average: format!("{:.0}", run.average).into(),
                low1: format!("{:.0}", run.low1).into(),
                low01: format!("{:.0}", run.low01).into(),
                pick: state.picks.iter().position(|&p| p == i).map_or(0, |at| at as i32 + 1),
            })
            .collect();
        let rates = ui.global::<Frames>();
        rates.set_runs(ModelRc::new(VecModel::from(rows)));
        let pair = match state.picks.as_slice() {
            &[a, b] => state.runs.get(a).zip(state.runs.get(b)),
            _ => None,
        };
        rates.set_comparing(pair.is_some());
        if let Some((a, b)) = pair {
            let c = frames::compare(a, b);
            let sign = |v: f64| if v.abs() < 0.05 { 0 } else { v.signum() as i32 };
            rates.set_name_a(a.name.trim_end_matches(".exe").into());
            rates.set_name_b(b.name.trim_end_matches(".exe").into());
            rates.set_diff_average(format!("{:+.1}%", c.average).into());
            rates.set_diff_low1(format!("{:+.1}%", c.low1).into());
            rates.set_diff_low01(format!("{:+.1}%", c.low01).into());
            rates.set_sign_average(sign(c.average));
            rates.set_sign_low1(sign(c.low1));
            rates.set_sign_low01(sign(c.low01));
            rates.set_real(c.real);
        }
    }

    /// Runs a button of the Monitor page on its row's processes, off the UI thread. The
    /// next sample shows the result.
    fn on_program(self: &Rc<Self>, i: i32, f: impl FnOnce(&monitor::Program) + Send + 'static) {
        let Some(program) = self.state.borrow().programs.get(i as usize).cloned() else { return };
        self.run_job(move || f(&program), |_, _| {});
    }

    /// The live ping runs only while its tab is on screen and the traffic count only while
    /// its own is, so neither costs anything the rest of the time.
    fn tick_internet(&self) {
        let tab = self.with_ui_value(|ui| (ui.get_page() == INTERNET_PAGE).then(|| ui.global::<Net>().get_tab()));
        let tab = tab.flatten();
        if tab == Some(0) {
            net::watch(&self.state.borrow().settings.ping_hosts);
        } else {
            net::unwatch();
        }
        if tab != Some(3) {
            net::traffic_stop();
            self.state.borrow_mut().traffic = None;
        }
        let Some(tab) = tab else { return };
        let connection = net::connection();
        self.with_ui(|ui| {
            let internet = ui.global::<Net>();
            internet.set_adapter(connection.as_ref().map(|c| c.name.as_str()).unwrap_or_default().into());
            internet.set_gateway(
                connection.as_ref().and_then(|c| c.gateway).map(|g| g.to_string()).unwrap_or_default().into(),
            );
            match tab {
                0 => show_pings(ui),
                3 => self.show_usage(ui),
                _ => {}
            }
            if self.state.borrow().bloat_running {
                show_bloat_progress(ui);
            }
        });
    }

    fn add_host(&self) {
        let Some(host) = self.with_ui_value(|ui| ui.global::<Net>().get_new_host().trim().to_string()) else {
            return;
        };
        let mut state = self.state.borrow_mut();
        let hosts = &mut state.settings.ping_hosts;
        if host.is_empty() || host.len() > 253 || host.contains(char::is_whitespace) || hosts.len() >= MAX_HOSTS {
            return;
        }
        if !hosts.iter().any(|h| h.eq_ignore_ascii_case(&host)) {
            hosts.push(host);
            let _ = state.settings.save();
        }
        self.with_ui(|ui| ui.global::<Net>().set_new_host("".into()));
    }

    fn show_usage(&self, ui: &AppWindow) {
        let internet = ui.global::<Net>();
        if net::traffic_start().is_err() {
            internet.set_usage_failed(true);
            return;
        }
        internet.set_usage_failed(false);
        let totals = net::traffic();
        let now = Instant::now();
        let previous = self.state.borrow_mut().traffic.replace((now, totals.clone()));
        let mut rows: Vec<(String, [u64; 2], [f64; 2])> = totals
            .into_iter()
            .map(|(name, total)| {
                let rate = previous.as_ref().map_or([0.0; 2], |(at, last)| {
                    let seconds = now.duration_since(*at).as_secs_f64().max(0.2);
                    let before = last.get(&name).copied().unwrap_or_default();
                    [0, 1].map(|i| total[i].saturating_sub(before[i]) as f64 / seconds)
                });
                (name, total, rate)
            })
            .filter(|(_, total, _)| total[0] + total[1] > 0)
            .collect();
        rows.sort_by(|a, b| {
            (b.2[0] + b.2[1]).total_cmp(&(a.2[0] + a.2[1])).then((b.1[0] + b.1[1]).cmp(&(a.1[0] + a.1[1])))
        });
        // As many as fit without scrolling: the list is rebuilt every second, which would
        // throw a scrolled list back to the top.
        rows.truncate(12);
        let busiest = rows.iter().map(|r| r.2[0] + r.2[1]).fold(0.0, f64::max).max(1.0);
        let limits = net::known_limits();
        let rows: Vec<UsageRow> = rows
            .into_iter()
            .map(|(name, total, rate)| UsageRow {
                limit: limits
                    .iter()
                    .find(|(program, _)| program.eq_ignore_ascii_case(&name))
                    .map(|(_, bits)| format_mbps(*bits as f64 / 1e6))
                    .unwrap_or_default()
                    .into(),
                // Sending a lot now or since the tab opened: a button that comes and goes
                // with every second's rate would move under the pointer.
                can_limit: net::limitable(&name) && (rate[1] >= 125_000.0 || total[1] >= 5 << 20),
                program: name.as_str().into(),
                name: name.trim_end_matches(".exe").into(),
                down: format_rate(rate[0]).into(),
                up: format_rate(rate[1]).into(),
                total_down: format_traffic(total[0]).into(),
                total_up: format_traffic(total[1]).into(),
                share: ((rate[0] + rate[1]) / busiest) as f32,
            })
            .collect();
        internet.set_usage(ModelRc::new(VecModel::from(rows)));
    }

    fn run_bloat(self: &Rc<Self>) {
        if std::mem::replace(&mut self.state.borrow_mut().bloat_running, true) {
            return;
        }
        self.with_ui(|ui| self.show_bloat(ui));
        self.run_job(net::bufferbloat, |app, result| {
            {
                let mut state = app.state.borrow_mut();
                state.bloat_running = false;
                state.bloat = Some(result.unwrap_or(Err(net::BloatError::NoServer)));
                if let Some(Ok(bloat)) = &state.bloat
                    && bloat.upload.mbps > 0.0
                {
                    state.settings.upload_mbps = Some(bloat.upload.mbps);
                    let _ = state.settings.save();
                }
            }
            app.with_ui(|ui| {
                app.show_bloat(ui);
                ui.global::<Net>().set_upload_known(app.state.borrow().settings.upload_mbps.is_some());
            });
        });
    }

    fn show_bloat(&self, ui: &AppWindow) {
        let state = self.state.borrow();
        let internet = ui.global::<Net>();
        let code = match &state.bloat {
            _ if state.bloat_running => 1,
            None => 0,
            Some(Ok(_)) => 2,
            Some(Err(net::BloatError::NoPing)) => 3,
            Some(Err(net::BloatError::NoServer)) => 4,
        };
        if state.bloat_running {
            internet.set_bloat_progress(0.0);
            internet.set_bloat_ping("".into());
            internet.set_bloat_speed("".into());
        }
        internet.set_bloat_state(code);
        if let Some(Ok(bloat)) = &state.bloat {
            let added = |latency: f64| format!("+{}", format_ms((latency - bloat.idle).max(0.0)));
            internet.set_bloat(BloatResult {
                grade: bloat.grade().to_string().into(),
                idle: format_ms(bloat.idle).into(),
                down_speed: format_mbps(bloat.download.mbps).into(),
                down_ping: format_ms(bloat.download.latency).into(),
                down_added: added(bloat.download.latency).into(),
                down_lost: bloat.download.lost as i32,
                up_speed: format_mbps(bloat.upload.mbps).into(),
                up_ping: format_ms(bloat.upload.latency).into(),
                up_added: added(bloat.upload.latency).into(),
                up_lost: bloat.upload.lost as i32,
                data: format_bytes(bloat.data).into(),
            });
        }
    }

    fn run_dns(self: &Rc<Self>) {
        if std::mem::replace(&mut self.state.borrow_mut().dns_running, true) {
            return;
        }
        self.with_ui(|ui| ui.global::<Net>().set_dns_running(true));
        self.run_job(net::dns_benchmark, |app, result| {
            {
                let mut state = app.state.borrow_mut();
                state.dns_running = false;
                state.dns = result.unwrap_or_default();
            }
            app.with_ui(|ui| app.show_dns(ui));
        });
    }

    fn show_dns(&self, ui: &AppWindow) {
        let state = self.state.borrow();
        let internet = ui.global::<Net>();
        let resolvers = &state.dns;
        // Read again rather than taken from the benchmark, which may predate a change.
        let in_use = net::current_dns();
        let is_current = |r: &net::Resolver| in_use.contains(&r.address);
        let changed = state.changes.iter().any(|c| c.id == net::DNS_TWEAK && !c.reset);
        // Sorted best first, so the first of each kind is the one to compare.
        let best = resolvers.first().filter(|r| r.reliable());
        let current = resolvers.iter().find(|r| is_current(r));
        let name = |r: &net::Resolver| if r.name.is_empty() { r.address.to_string() } else { r.name.clone() };
        let verdict = match (best, current) {
            (Some(best), Some(current)) if !current.reliable() => {
                internet.set_dns_missed(current.failed as i32);
                internet.set_dns_best(name(best).into());
                3
            }
            (Some(best), Some(current)) => {
                let gain = current.score().unwrap_or(0.0) - best.score().unwrap_or(0.0);
                // A few ms either way is noise between runs, not a reason to switch.
                if gain < 3.0 {
                    1
                } else {
                    internet.set_dns_best(name(best).into());
                    internet.set_dns_gain(format_ms(gain).into());
                    2
                }
            }
            _ => 0,
        };
        let rows: Vec<DnsRow> = resolvers
            .iter()
            .map(|r| DnsRow {
                name: r.name.as_str().into(),
                address: r.address.to_string().into(),
                cached: r.cached.map(format_ms).unwrap_or_else(|| "-".into()).into(),
                uncached: r.uncached.map(format_ms).unwrap_or_else(|| "-".into()).into(),
                failed: r.failed as i32,
                sent: r.sent as i32,
                current: is_current(r),
                best: best.is_some_and(|b| b.address == r.address),
                provider: r.provider.is_some(),
                vantix: changed && is_current(r) && r.provider.is_some(),
            })
            .collect();
        internet.set_dns_settable(net::dns_adapter().is_some());
        internet.set_dns_verdict(verdict);
        internet.set_dns(ModelRc::new(VecModel::from(rows)));
        internet.set_dns_running(state.dns_running);
    }

    fn set_job(&self, state: JobState, detail: &str) {
        self.with_ui(|ui| {
            let job = ui.global::<Job>();
            job.set_detail(detail.into());
            job.set_state(state);
        });
    }
}

const INTERNET_PAGE: i32 = 8;
const MONITOR_PAGE: i32 = 9;
const FRAMES_PAGE: i32 = 10;
const LATENCY_PAGE: i32 = 11;
/// Rows on the Disk space page: the largest files, and the items of a folder.
const LARGEST_FILES: usize = 20;
const FOLDER_ROWS: usize = 100;
/// Ping targets the user can add, on top of the router and Cloudflare.
const MAX_HOSTS: usize = 5;

fn dns_tweak() -> Option<usize> {
    CATALOG.iter().position(|t| t.id == net::DNS_TWEAK)
}

fn limit_tweak() -> Option<usize> {
    CATALOG.iter().position(|t| t.id == net::LIMIT_TWEAK)
}

fn show_pings(ui: &AppWindow) {
    let readings = net::readings();
    let rows: Vec<PingRow> = readings
        .iter()
        .map(|reading| {
            let series = &reading.series;
            let (line, lost) = ping_paths(series);
            let ms = |value: Option<f64>| value.map(format_ms).unwrap_or_default();
            PingRow {
                label: reading.label.as_str().into(),
                address: match reading.address {
                    net::Lookup::Found(address) => address.to_string().into(),
                    _ => "".into(),
                },
                now: match series.last() {
                    Some(Some(time)) => format_ms(time).into(),
                    Some(None) => "-".into(),
                    None => "".into(),
                },
                average: ms(series.average()).into(),
                jitter: ms(series.jitter()).into(),
                loss: series.loss().map(|loss| format!("{:.0}%", loss * 100.0)).unwrap_or_default().into(),
                line: line.into(),
                lost: lost.into(),
                state: match reading.address {
                    net::Lookup::Found(_) => 0,
                    net::Lookup::Pending => 1,
                    net::Lookup::Failed => 2,
                },
                host: match reading.target {
                    net::Target::Host(i) => i as i32,
                    _ => -1,
                },
            }
        })
        .collect();
    let internet = ui.global::<Net>();
    internet.set_verdict(ping_verdict(&readings));
    internet.set_pings(ModelRc::new(VecModel::from(rows)));
}

/// Round trips as a line on a 59 x 40 box, scaled to the slowest one, and a red mark per
/// lost ping. A lost ping breaks the line.
fn ping_paths(series: &net::Series) -> (String, String) {
    let scale = series.max().unwrap_or(1.0).max(5.0) * 1.15;
    let offset = net::SERIES_LEN - series.0.len();
    let (mut line, mut lost, mut pen_up) = (String::new(), String::new(), true);
    for (i, sample) in series.0.iter().enumerate() {
        let x = offset + i;
        match sample {
            Some(time) => {
                let y = 38 - (time / scale * 36.0).round() as i32;
                let _ = write!(line, "{}{x} {y} ", if pen_up { 'M' } else { 'L' });
                pen_up = false;
            }
            None => {
                let _ = write!(lost, "M{x} 4 L{x} 36 ");
                pen_up = true;
            }
        }
    }
    (line, lost)
}

/// Compares the router with Cloudflare to tell where trouble starts. Needs 20 seconds of
/// pings; before that one lost ping would read as 10% loss. A target that never answered
/// most likely blocks pings, which says nothing about the connection, so it's left out.
fn ping_verdict(readings: &[net::Reading]) -> i32 {
    let find = |target| {
        readings
            .iter()
            .find(|r| r.target == target)
            .map(|r| &r.series)
            .filter(|s| s.0.len() >= 20 && s.average().is_some())
    };
    let Some(internet) = find(net::Target::Cloudflare) else { return 0 };
    let shaky = |series: &net::Series, jitter: f64| {
        series.loss().unwrap_or(0.0) >= 0.02 || series.jitter().unwrap_or(0.0) > jitter
    };
    match find(net::Target::Gateway) {
        Some(home) if shaky(home, 5.0) => 2,
        _ if shaky(internet, 10.0) => 3,
        _ => 1,
    }
}

fn show_bloat_progress(ui: &AppWindow) {
    let progress = net::bloat_progress();
    let (done, phase) = match progress.phase {
        net::Phase::Idle => (0.0, 0),
        net::Phase::Download => (5.0, 1),
        net::Phase::Upload => (13.0, 2),
    };
    let internet = ui.global::<Net>();
    internet.set_bloat_phase(phase);
    internet.set_bloat_progress(((done + progress.elapsed.as_secs_f64()) / 21.0).min(1.0) as f32);
    internet.set_bloat_ping(progress.ping.map(format_ms).unwrap_or_default().into());
    internet.set_bloat_speed(if progress.mbps > 0.0 { format_mbps(progress.mbps).into() } else { "".into() });
}

fn format_ms(ms: f64) -> String {
    if ms < 10.0 { format!("{ms:.1} ms") } else { format!("{ms:.0} ms") }
}

fn format_mbps(mbps: f64) -> String {
    if mbps < 10.0 { format!("{mbps:.1} Mbps") } else { format!("{mbps:.0} Mbps") }
}

fn format_rate(bytes_per_second: f64) -> String {
    if bytes_per_second < 1.0 { String::new() } else { format!("{}/s", format_traffic(bytes_per_second as u64)) }
}

/// Like format_bytes, but down to KB: most programs move little.
fn format_traffic(bytes: u64) -> String {
    if bytes < 1024 * 1024 { format!("{} KB", bytes.div_ceil(1024)) } else { format_bytes(bytes) }
}

fn auto_clean_due(state: &State, load: u32) -> bool {
    if state.cleaning {
        return false;
    }
    let auto = state.settings.auto_clean;
    match auto.mode {
        AutoMode::Off => false,
        AutoMode::Interval => interval_remaining(state).is_zero(),
        AutoMode::Limit => state.limit_armed && load >= auto.percent,
    }
}

fn interval_remaining(state: &State) -> Duration {
    let interval = Duration::from_secs(u64::from(state.settings.auto_clean.minutes) * 60);
    interval.saturating_sub(state.interval_start.elapsed())
}

/// What the scheduler is waiting for, so it's visible that it runs.
fn show_auto_status(ui: &AppWindow, state: &State) {
    let mem = ui.global::<Memory>();
    let left = interval_remaining(state).as_secs();
    let (h, m, s) = (left / 3600, left / 60 % 60, left % 60);
    let countdown = if h > 0 { format!("{h}:{m:02}:{s:02}") } else { format!("{m}:{s:02}") };
    mem.set_auto_countdown(countdown.into());
    mem.set_auto_armed(state.limit_armed);
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

/// The line and the filled area of a sparkline as SVG paths, on a 59 x 100 box with the
/// newest sample on the right edge. Values are percentages.
fn spark_paths(values: impl ExactSizeIterator<Item = u32>) -> (String, String) {
    let offset = SPARK_SAMPLES - values.len().min(SPARK_SAMPLES);
    let mut line = String::new();
    for (i, value) in values.take(SPARK_SAMPLES).enumerate() {
        let command = if i == 0 { 'M' } else { 'L' };
        let _ = write!(line, "{command}{} {} ", offset + i, 100 - value.min(100));
    }
    if line.is_empty() {
        return (line, String::new());
    }
    let area = format!("{line}L{} 100 L{offset} 100 Z", SPARK_SAMPLES - 1);
    (line, area)
}

fn show_sparkline(ui: &AppWindow, loads: &VecDeque<u32>) {
    let (line, area) = spark_paths(loads.iter().copied());
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
    let prefs = ui.global::<Preferences>();
    prefs.set_language(settings.language as i32);
    prefs.set_start_with_windows(system::autostart_enabled());
    prefs.set_start_minimized(settings.start_minimized);
    prefs.set_notifications(settings.notifications);
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

fn live_config(settings: &Settings) -> governor::Config {
    governor::Config { probalance: settings.probalance, game: settings.game_mode }
}

fn show_live(ui: &AppWindow, settings: &Settings) {
    let live = ui.global::<Live>();
    let game = settings.game_mode;
    live.set_probalance(settings.probalance);
    live.set_game_mode(game.enabled);
    live.set_priority(game.priority);
    live.set_cores(game.cores);
    live.set_eco(game.eco);
    live.set_services(game.services);
    live.set_standby(game.standby);
    live.set_wifi(game.wifi);
    live.set_gpu(game.gpu);
    let capabilities = governor::capabilities();
    let (kind, preferred, total) = capabilities.cores.map_or((0, 0, 0), |cores| {
        let kind = match cores.kind {
            governor::CoreKind::PerformanceCores => 1,
            governor::CoreKind::VCache => 2,
        };
        (kind, cores.preferred as i32, cores.total as i32)
    });
    live.set_cores_kind(kind);
    live.set_cores_preferred(preferred);
    live.set_cores_total(total);
    live.set_has_wifi(capabilities.wifi);
    live.set_has_hybrid_gpu(capabilities.hybrid_gpu);
}

fn startup_row(entry: &startup::Entry) -> StartupRow {
    StartupRow {
        name: entry.name.as_str().into(),
        publisher: entry.publisher.as_str().into(),
        all_users: entry.all_users,
        enabled: entry.enabled,
        memory: entry.memory.map(format_bytes).unwrap_or_default().into(),
    }
}

/// Sizes on the Disk space page, which go from a few bytes to terabytes.
fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 { format!("{bytes} B") } else { format!("{value:.1} {}", UNITS[unit]) }
}

/// Opens Explorer on the folder of `path` with it selected.
fn reveal(path: &str) {
    use std::os::windows::process::CommandExt;
    let _ = std::process::Command::new("explorer.exe").raw_arg(format!("/select,\"{path}\"")).spawn();
}

fn show_space(ui: &AppWindow, state: &mut State) {
    let disk = ui.global::<Space>();
    let Some((scan, largest)) = &state.space else {
        disk.set_scanned(false);
        return;
    };
    disk.set_scanned(true);
    disk.set_files(scan.files.to_string().into());
    disk.set_used(format_size(scan.total()).into());
    disk.set_seconds(format!("{:.1}", scan.seconds).into());
    let dir = scan.get(state.space_dir);
    disk.set_path(scan.path(state.space_dir).into());
    disk.set_can_up(scan.parent(state.space_dir).is_some());
    let children = scan.children(state.space_dir);
    let shown = &children[..children.len().min(FOLDER_ROWS)];
    let records: Vec<u32> = shown.iter().map(|e| e.record).collect();
    let names = scan.names(&records);
    let rows: Vec<SpaceRow> = shown
        .iter()
        .zip(names)
        .map(|(e, name)| SpaceRow {
            name: name.into(),
            detail: Default::default(),
            size: format_size(e.size).into(),
            share: (e.size as f64 / dir.size.max(1) as f64) as f32,
            files: if e.folder { e.files.to_string().into() } else { Default::default() },
            folder: e.folder,
        })
        .collect();
    disk.set_rows(ModelRc::new(VecModel::from(rows)));
    disk.set_more((children.len() - shown.len()) as i32);
    let largest: Vec<SpaceRow> = largest
        .iter()
        .map(|(record, path)| {
            let (folder, name) = path.rsplit_once('\\').unwrap_or(("", path));
            SpaceRow {
                name: name.into(),
                detail: folder.into(),
                size: format_size(scan.get(*record).size).into(),
                ..Default::default()
            }
        })
        .collect();
    disk.set_largest(ModelRc::new(VecModel::from(largest)));
    state.space_rows = records;
}

/// Microseconds as the Latency page shows them: whole below a millisecond.
fn format_micros(us: f64) -> String {
    if us < 1000.0 { format!("{us:.0} µs") } else { format!("{:.2} ms", us / 1000.0) }
}

fn show_latency(ui: &AppWindow) {
    let page = ui.global::<Latency>();
    page.set_running(latency::running());
    let Some(report) = latency::report() else {
        page.set_measured(false);
        return;
    };
    let level = |us: f64| if us >= latency::BAD { 2 } else if us >= latency::WARN { 1 } else { 0 };
    let seconds = report.seconds as u64;
    page.set_measured(true);
    page.set_elapsed(if seconds < 60 { format!("{seconds} s") } else { format!("{} min {} s", seconds / 60, seconds % 60) }.into());
    let (isr, isr_driver) = report.worst_isr().map_or((String::from("-"), ""), |(us, name)| (format_micros(us), name));
    let (dpc, dpc_driver) = report.worst_dpc().map_or((String::from("-"), ""), |(us, name)| (format_micros(us), name));
    page.set_isr(isr.into());
    page.set_isr_driver(isr_driver.into());
    page.set_dpc(dpc.into());
    page.set_dpc_driver(dpc_driver.into());
    let worst = report.drivers.first();
    page.set_level(worst.map_or(0, |d| level(d.worst())));
    page.set_worst(worst.map(|d| format_micros(d.worst())).unwrap_or_default().into());
    page.set_worst_driver(worst.map(|d| d.name.clone()).unwrap_or_default().into());
    let max = |count: u64, us: f64| if count == 0 { String::from("-") } else { format_micros(us) };
    let rows: Vec<DriverRow> = report
        .drivers
        .iter()
        .take(15)
        .map(|d| DriverRow {
            name: d.name.clone().into(),
            description: d.description.clone().into(),
            isrs: d.isr_count.to_string().into(),
            isr_max: max(d.isr_count, d.isr_max).into(),
            dpcs: d.dpc_count.to_string().into(),
            dpc_max: max(d.dpc_count, d.dpc_max).into(),
            busy: format!("{:.2}%", d.busy).into(),
            level: level(d.worst()),
        })
        .collect();
    page.set_drivers(ModelRc::new(VecModel::from(rows)));
}

fn show_monitor(ui: &AppWindow, snapshot: Option<&monitor::Snapshot>, shown: &mut Vec<monitor::Program>) {
    let m = ui.global::<Monitor>();
    let Some(s) = snapshot else {
        m.set_ready(false);
        shown.clear();
        m.set_programs(ModelRc::default());
        return;
    };
    if !m.get_ready() {
        let info = monitor::cpu_info();
        m.set_cpu_name(info.name.as_str().into());
        m.set_cpu_cores(info.cores as i32);
        m.set_cpu_threads(info.threads as i32);
        m.set_cpu_performance(info.performance as i32);
        m.set_cpu_l3(format_bytes(info.l3).into());
        m.set_cpu_base(format_ghz(f64::from(info.base_mhz)).into());
        let features: Vec<slint::SharedString> = info.features.iter().map(|f| (*f).into()).collect();
        m.set_features(ModelRc::new(VecModel::from(features)));
        m.set_ready(true);
    }
    let percent = |value: f64| value.round().clamp(0.0, 100.0) as u32;
    // Rates scale to the busiest second of the minute, with a floor so idle noise stays flat.
    let scaled = |series: &VecDeque<f64>, floor: f64| {
        let top = series.iter().copied().fold(floor, f64::max);
        series.iter().map(|v| (v / top * 100.0).round() as u32).collect::<Vec<_>>()
    };

    m.set_cores(ModelRc::new(VecModel::from(s.cores.clone())));
    m.set_cpu_load(format!("{:.0}%", s.cpu).into());
    m.set_cpu_clock(if s.mhz > 0.0 { format_ghz(s.mhz) } else { String::new() }.into());
    let (line, area) = spark_paths(s.history[0].iter().map(|v| percent(*v)));
    m.set_cpu_line(line.into());
    m.set_cpu_area(area.into());

    m.set_has_gpu(!s.gpus.is_empty());
    if let Some(gpu) = s.gpus.first() {
        m.set_gpu_name(gpu.name.as_str().into());
        m.set_gpu_load(format!("{:.0}%", gpu.load).into());
        m.set_gpu_memory(format!("{} / {}", format_bytes(gpu.memory_used), format_bytes(gpu.memory_total)).into());
        let (line, area) = spark_paths(s.history[1].iter().map(|v| percent(*v)));
        m.set_gpu_line(line.into());
        m.set_gpu_area(area.into());
    }

    let read: f64 = s.disks.iter().map(|d| d.read).sum();
    let write: f64 = s.disks.iter().map(|d| d.write).sum();
    let active = s.disks.iter().map(|d| d.active).fold(0.0, f32::max);
    m.set_disk_load(format!("{active:.0}%").into());
    m.set_disk_read(format_speed(read).into());
    m.set_disk_write(format_speed(write).into());
    let (line, area) = spark_paths(s.history[2].iter().map(|v| percent(*v)));
    m.set_disk_line(line.into());
    m.set_disk_area(area.into());

    m.set_net_total(format_speed(s.net[0] + s.net[1]).into());
    m.set_net_down(format_speed(s.net[0]).into());
    m.set_net_up(format_speed(s.net[1]).into());
    let (line, area) = spark_paths(scaled(&s.history[3], 100.0 * 1024.0).into_iter());
    m.set_net_line(line.into());
    m.set_net_area(area.into());

    // While the pointer is over the list, rows keep their place and only their numbers
    // change, so a button never moves away from under it.
    let programs: Vec<monitor::Program> = if m.get_hovering() && !shown.is_empty() {
        shown
            .iter()
            .map(|old| s.programs.iter().find(|p| p.name == old.name).cloned().unwrap_or_else(|| old.clone()))
            .collect()
    } else {
        s.programs.clone()
    };
    let rows: Vec<ProgramRow> = programs
        .iter()
        .map(|p| ProgramRow {
            name: p.name.trim_end_matches(".exe").into(),
            count: p.pids.len() as i32,
            cpu: format_percent(p.cpu).into(),
            gpu: format_percent(p.gpu).into(),
            memory: format_bytes(p.memory).into(),
            eco: p.eco.map_or(-1, i32::from),
            can_end: p.can_end,
        })
        .collect();
    *shown = programs;
    // In place when the count is the same, so each row keeps its state, like a pending End.
    let model = m.get_programs();
    match model.as_any().downcast_ref::<VecModel<ProgramRow>>() {
        Some(current) if current.row_count() == rows.len() => {
            for (i, row) in rows.into_iter().enumerate() {
                current.set_row_data(i, row);
            }
        }
        _ => m.set_programs(ModelRc::new(VecModel::from(rows))),
    }
}

fn format_ghz(mhz: f64) -> String {
    format!("{:.2} GHz", mhz / 1000.0)
}

fn format_percent(value: f32) -> String {
    if value < 0.05 { "0%".into() } else if value < 10.0 { format!("{value:.1}%") } else { format!("{value:.0}%") }
}

/// Bytes per second, never empty.
fn format_speed(bytes_per_second: f64) -> String {
    format!("{}/s", format_traffic(bytes_per_second as u64))
}

fn format_bytes(bytes: u64) -> String {
    const MB: f64 = 1024.0 * 1024.0;
    let mb = bytes as f64 / MB;
    if mb >= 1024.0 { format!("{:.1} GB", mb / 1024.0) } else { format!("{mb:.0} MB") }
}

/// Windows drops a minimized window's pixels, and Slint 1.18's software renderer keeps
/// treating its buffer as still on screen, so after a restore only the parts that changed
/// get drawn and the rest shows whatever was behind. Making everything dirty once fixes it.
fn repaint_after_restore(ui: &AppWindow) {
    use slint::winit_030::winit::event::WindowEvent;
    use slint::winit_030::{EventResult, WinitWindowAccessor};

    let weak = ui.as_weak();
    let mut hidden = false;
    ui.window().on_winit_window_event(move |_, event| {
        match event {
            WindowEvent::Resized(size) if size.width == 0 || size.height == 0 => hidden = true,
            WindowEvent::Occluded(true) => hidden = true,
            WindowEvent::Resized(_) | WindowEvent::Occluded(false) if hidden => {
                hidden = false;
                if let Some(ui) = weak.upgrade() {
                    ui.set_repaint(!ui.get_repaint());
                }
            }
            _ => {}
        }
        EventResult::Propagate
    });
}

/// Retries every 50 ms until the native window exists, for at most a second.
fn style_when_ready<T: ComponentHandle + 'static>(component: slint::Weak<T>, attempt: u32) {
    Timer::single_shot(Duration::from_millis(if attempt == 0 { 0 } else { 50 }), move || {
        let Some(strong) = component.upgrade() else { return };
        if system::style_window(strong.window()) {
            fit_to_screen(strong.window());
        } else if attempt < 20 {
            style_when_ready(component, attempt + 1);
        }
    });
}

/// The same as min-width and min-height in ui/app.slint.
const MIN_SIZE: (f64, f64) = (1000.0, 560.0);

/// Slint 1.18 never hands the window's min-width and min-height to Windows, so the window
/// could be dragged or restored smaller than the layout, which then got cut off. Both the
/// minimum and the opening size are also capped to the screen's free area: on a small
/// laptop screen, or 1080p at 150%, 1180 x 800 doesn't fit, and pages scroll instead.
fn fit_to_screen(window: &slint::Window) {
    use slint::winit_030::WinitWindowAccessor;
    use slint::winit_030::winit::dpi::{LogicalSize, PhysicalPosition};

    let Some((left, top, right, bottom)) = system::work_area(window) else { return };
    let scale = f64::from(window.scale_factor());
    window.with_winit_window(|winit| {
        let (inner, outer) = (winit.inner_size(), winit.outer_size());
        let frame = (outer.width.saturating_sub(inner.width) as i32, outer.height.saturating_sub(inner.height) as i32);
        let fits = |space: i32, frame: i32| f64::from((space - frame).max(1)) / scale;
        let (max_width, max_height) = (fits(right - left, frame.0), fits(bottom - top, frame.1));
        winit.set_min_inner_size(Some(LogicalSize::new(MIN_SIZE.0.min(max_width), MIN_SIZE.1.min(max_height))));

        let (width, height) = (f64::from(inner.width) / scale, f64::from(inner.height) / scale);
        if width > max_width || height > max_height {
            let (width, height) = (width.min(max_width), height.min(max_height));
            let _ = winit.request_inner_size(LogicalSize::new(width, height));
            let outer_width = (width * scale) as i32 + frame.0;
            let outer_height = (height * scale) as i32 + frame.1;
            let x = left + (right - left - outer_width) / 2;
            let y = top + (bottom - top - outer_height) / 2;
            winit.set_outer_position(PhysicalPosition::new(x.max(left), y.max(top)));
        }
    });
}

/// Breaks the terms into justified lines, in whatever language the UI is in now.
fn justify_terms(ui: &AppWindow) {
    let terms = ui.global::<Terms>();
    let (size, width) = (terms.get_font_size(), terms.get_line_width());
    // A few pixels of slack for kerning, which the measurement leaves out.
    let paragraphs: Option<Vec<TermsParagraph>> = terms
        .get_paragraphs()
        .iter()
        .map(|text| {
            let lines = text::justify(&text, size, width - 4.0)?;
            let lines: Vec<TermsLine> = lines
                .into_iter()
                .map(|line| TermsLine {
                    words: ModelRc::new(VecModel::from(
                        line.words.into_iter().map(slint::SharedString::from).collect::<Vec<_>>(),
                    )),
                    last: line.last,
                })
                .collect();
            Some(TermsParagraph { lines: ModelRc::new(VecModel::from(lines)) })
        })
        .collect();
    terms.set_justified(ModelRc::new(VecModel::from(paragraphs.unwrap_or_default())));
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
