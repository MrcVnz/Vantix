#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod boost;
mod disk;
mod memory;
mod reg;
mod restore;
mod settings;
mod system;
mod text;
mod tweaks;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt::Write;
use std::rc::{Rc, Weak};
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
    Revert(Option<String>),
    /// Undoes a reset by applying the tweak again.
    Reapply,
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

    slint::run_event_loop_until_quit()
}

fn bind_with<T>(app: &Rc<App>, f: impl Fn(&Rc<App>, T) + 'static) -> impl Fn(T) + 'static {
    let app: Weak<App> = Rc::downgrade(app);
    move |value| {
        if let Some(app) = app.upgrade() {
            f(&app, value)
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

        let tray = Tray::new()?;
        apply_language(self.state.borrow().settings.language);
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

        if open_window { self.open_window() } else { Ok(()) }
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
        let stats = memory::stats();
        self.with_tray(|tray| tray.set_load(stats.load as i32));
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
        self.refresh_tweaks();
    }

    /// Reads every tweak's real state in parallel. A few of them start PowerShell, which
    /// takes about a second.
    fn refresh_tweaks(self: &Rc<Self>) {
        let (version, baseline) = {
            let state = self.state.borrow();
            (state.journal_version, state.settings.baseline_point)
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
                (reads, alive)
            },
            move |app, results| {
                let Some((results, alive)) = results else { return };
                {
                    let mut state = app.state.borrow_mut();
                    let fresh =
                        state.baseline_made.is_some_and(|made| made.elapsed() < Duration::from_secs(120));
                    state.baseline_alive = alive || fresh;
                    for (info, result) in state.tweaks.iter_mut().zip(results) {
                        let (shown, on, estimate) = result.unwrap_or((false, None, None));
                        *info = TweakInfo { loaded: true, shown, on, estimate, ran: info.ran };
                    }
                    // A change that Windows or the user undid elsewhere has nothing left to
                    // undo. Only trusted when no change landed while these states were read.
                    let current = state.journal_version == version && state.working.is_none();
                    let stale: Vec<String> = state
                        .changes
                        .iter()
                        .filter(|change| {
                            CATALOG
                                .iter()
                                .position(|t| t.id == change.id)
                                // A reset is stale once the tweak is back on, a change once it's off.
                                .is_none_or(|i| state.tweaks[i].on == Some(change.reset))
                        })
                        .map(|change| change.id.clone())
                        .collect();
                    if current && !stale.is_empty() {
                        state.changes.retain(|change| !stale.contains(&change.id));
                        let _ = settings::save_changes(&state.changes);
                    }
                }
                app.with_ui(|ui| app.show_tweaks(ui));
            },
        );
    }

    fn show_tweaks(&self, ui: &AppWindow) {
        let state = self.state.borrow();
        let change = |id: &str| state.changes.iter().find(|change| change.id == id);
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
        let subject = index.map(|i| self.tweak_title(i)).unwrap_or_default();
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
                if change.reset { Op::Reapply } else { Op::Revert(change.previous.clone()) }
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
            ui.global::<Job>().set_slow(slow);
            self.show_tweaks(ui);
        });

        self.run_job(
            move || {
                let (free_before, _) = disk::system_drive_space();
                let mut outcomes = Vec::new();
                for (i, op) in work {
                    let result = match (&CATALOG[i].kind, &op) {
                        (Kind::Toggle { apply, .. }, Op::Apply) => apply(),
                        (Kind::Toggle { reset, .. }, Op::Reset) => reset().map(|_| None),
                        (Kind::Toggle { revert, .. }, Op::Revert(previous)) => {
                            revert(previous.as_deref()).map(|_| None)
                        }
                        (Kind::Toggle { apply, .. }, Op::Reapply) => apply().map(|_| None),
                        (Kind::Action { run }, _) => run().map(|_| None),
                    };
                    let failed = result.is_err();
                    outcomes.push((i, op, result));
                    if failed {
                        break;
                    }
                }
                let (free_after, _) = disk::system_drive_space();
                (outcomes, free_after.saturating_sub(free_before))
            },
            |app, result| {
                let Some((outcomes, gained)) = result else {
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
                    for (i, op, result) in outcomes {
                        let tweak = &CATALOG[i];
                        match result {
                            Ok(previous) => {
                                reboot |= tweak.reboot;
                                state.changes.retain(|c| c.id != tweak.id);
                                let journal = |reset: bool| Change {
                                    id: tweak.id.into(),
                                    time: Local::now(),
                                    previous: previous.clone(),
                                    boot: tweaks::boot_time(),
                                    reboot: tweak.reboot,
                                    freed: gained,
                                    reset,
                                };
                                if let Kind::Toggle { .. } = tweak.kind {
                                    let on = matches!(op, Op::Apply | Op::Reapply);
                                    state.tweaks[i].on = Some(on);
                                }
                                match (&tweak.kind, op) {
                                    (Kind::Action { .. }, _) => state.tweaks[i].ran = true,
                                    (_, Op::Apply) => state.changes.push(journal(false)),
                                    (_, Op::Reset) => state.changes.push(journal(true)),
                                    (_, Op::Revert(_) | Op::Reapply) => {}
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
                app.with_ui(|ui| app.show_tweaks(ui));
                app.refresh_tweaks();
                app.refresh_protection();
            },
        );
    }

    fn set_job(&self, state: JobState, detail: &str) {
        self.with_ui(|ui| {
            let job = ui.global::<Job>();
            job.set_detail(detail.into());
            job.set_state(state);
        });
    }
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
        if !system::style_window(strong.window()) && attempt < 20 {
            style_when_ready(component, attempt + 1);
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
