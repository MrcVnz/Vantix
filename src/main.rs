#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod disk;
mod memory;
mod reg;
mod restore;
mod settings;
mod system;

use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt::Write;
use std::rc::{Rc, Weak};
use std::time::{Duration, Instant};

use chrono::Local;
use slint::{CloseRequestResponse, ComponentHandle, Model, ModelRc, Timer, TimerMode, VecModel};
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
    /// Last scan result per cleanup category, `None` until analyzed or when blocked.
    scanned: [Option<u64>; disk::Category::ALL.len()],
    selected: [bool; disk::Category::ALL.len()],
    history: Vec<HistoryEntry>,
    cleaning: bool,
    last_auto: Instant,
    loads: VecDeque<u32>,
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
    memory::enable_privileges();

    let app = Rc::new(App {
        state: RefCell::new(State {
            settings: Settings::load(),
            scanned: [None; disk::Category::ALL.len()],
            selected: disk::Category::ALL.map(disk::Category::selected_by_default),
            history: settings::load_history(),
            cleaning: false,
            last_auto: Instant::now(),
            loads: VecDeque::with_capacity(SPARK_SAMPLES),
        }),
        window: RefCell::new(None),
        tray: RefCell::new(None),
        ticker: Timer::default(),
    });
    // Nothing runs and nothing is written until the terms are accepted.
    let _terms = if app.state.borrow().settings.terms_version < TERMS_VERSION {
        Some(ask_terms(&app)?)
    } else {
        let autostart = std::env::args().any(|arg| arg == system::AUTOSTART_ARG);
        let minimized = autostart && app.state.borrow().settings.start_minimized;
        app.start(!minimized)?;
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
            if app.start(true).is_err() {
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
    style_when_ready(terms.as_weak(), 0);
    Ok(terms)
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
            app.close_window();
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
        let _ = system::register_notifications();
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
        state.last_auto = Instant::now();
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
                state.settings.tray_hint_shown = true;
                let _ = state.settings.save();
                app.with_tray(|tray| {
                    let _ = system::notify(&tray.invoke_hint_title(), &tray.invoke_hint_body());
                });
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
        protection.on_open_system_restore(|| {
            let _ = std::process::Command::new("rstrui.exe").spawn();
        });
        ui.global::<Job>().on_dismiss(bind(self, |app| {
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

        ui.window().on_close_requested(bind_close(self));

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
                        let _ = system::notify(&tray.invoke_freed_title(), &body);
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
            || (restore::protection_enabled(), restore::list().unwrap_or_default()),
            |app, result| {
                app.with_ui(|ui| {
                    let protection = ui.global::<Protection>();
                    protection.set_loading(false);
                    let Some((enabled, points)) = result else { return };
                    protection.set_enabled(enabled);
                    let rows: Vec<RestorePoint> = points
                        .iter()
                        .map(|point| RestorePoint {
                            sequence: point.sequence as i32,
                            description: point.description.as_str().into(),
                            created: point
                                .created
                                .map(|time| time.format("%d/%m/%Y %H:%M").to_string())
                                .unwrap_or_default()
                                .into(),
                        })
                        .collect();
                    protection.set_points(ModelRc::new(VecModel::from(rows)));
                })
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
                    Some(Ok(_)) => {
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
            job.set_elapsed(0);
            job.set_state(state);
        });
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

/// Retries every 50 ms until the native window exists, for at most a second.
fn style_when_ready<T: ComponentHandle + 'static>(component: slint::Weak<T>, attempt: u32) {
    Timer::single_shot(Duration::from_millis(if attempt == 0 { 0 } else { 50 }), move || {
        let Some(strong) = component.upgrade() else { return };
        if !system::style_window(strong.window()) && attempt < 20 {
            style_when_ready(component, attempt + 1);
        }
    });
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
