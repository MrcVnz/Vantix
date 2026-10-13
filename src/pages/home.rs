//! The Home page: the update check, download and install, the notes of the update that
//! brought this version, and a summary of the PC that leads to the other pages.

use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chrono::Local;
use slint::ComponentHandle;

use crate::{App, AppWindow, Home, State, UpdateStep, bind, drive_row, format_bytes, health, system, update};

pub const HOME_PAGE: i32 = 13;
/// How often Vantix asks GitHub on its own, and how long it waits after a try that got
/// no answer.
const CHECK_EVERY: chrono::TimeDelta = chrono::TimeDelta::hours(24);
const RETRY_AFTER: Duration = Duration::from_secs(60 * 60);

const REPO: &str = "https://github.com/MrcVnz/Vantix";

#[derive(Default)]
pub struct HomeState {
    step: Step,
    /// The last check, answered or not.
    tried: Option<Instant>,
    /// The notes of the update that brought this version, until dismissed.
    notes: Option<String>,
    /// The system drive's verdict as the Storage page numbers it. Read once each time the
    /// window opens, not on a timer: asking a hard drive for its health can spin it up.
    disk: Option<i32>,
    disk_read: bool,
}

impl HomeState {
    pub fn new() -> Self {
        Self { notes: update::whats_new(), ..Self::default() }
    }
}

#[derive(Default)]
enum Step {
    #[default]
    Idle,
    Checking,
    Current,
    NoReleases,
    /// Why, as Home.why numbers it.
    Failed(i32),
    Available(update::Release),
    Downloading(update::Release, Arc<AtomicU64>),
    Ready(update::Release, PathBuf),
    Installing,
}

impl App {
    pub(crate) fn connect_home(self: &Rc<Self>, ui: &AppWindow) {
        let home = ui.global::<Home>();
        home.set_version(env!("CARGO_PKG_VERSION").into());
        self.state.borrow_mut().home.disk_read = false;
        home.on_check(bind(self, |app| app.check_update()));
        home.on_download(bind(self, |app| app.download_update()));
        home.on_install(bind(self, |app| app.install_update()));
        home.on_poll(bind(self, |app| app.with_ui(|ui| show_home(ui, &app.state.borrow()))));
        home.on_link(|which| {
            let url = match which {
                0 => REPO.to_string(),
                1 => format!("{REPO}/blob/main/CONTRIBUTING.md"),
                _ => format!("{REPO}/issues/new"),
            };
            // Through Explorer, so the browser opens as the user and not elevated.
            let _ = std::process::Command::new("explorer.exe").arg(url).spawn();
        });
        home.on_dismiss_notes(bind(self, |app| {
            update::dismiss_whats_new();
            app.state.borrow_mut().home.notes = None;
            app.with_ui(|ui| show_home(ui, &app.state.borrow()));
        }));
        show_home(ui, &self.state.borrow());
    }

    /// Asks GitHub once a day on its own, and reads the drive's health when the page shows.
    pub(crate) fn tick_home(self: &Rc<Self>) {
        let (due, disk_due) = {
            let state = self.state.borrow();
            let home = &state.home;
            let idle = matches!(home.step, Step::Idle | Step::Current | Step::NoReleases | Step::Failed(_));
            let stale = state.settings.update_checked_at.is_none_or(|at| Local::now() - at >= CHECK_EVERY);
            let waited = home.tried.is_none_or(|at| at.elapsed() >= RETRY_AFTER);
            let open = self.with_ui_value(|ui| ui.get_page() == HOME_PAGE).unwrap_or(false);
            (idle && stale && waited, open && !home.disk_read)
        };
        if due {
            self.check_update();
        }
        if disk_due {
            self.read_system_disk();
        }
        self.with_ui(|ui| show_home(ui, &self.state.borrow()));
    }

    fn check_update(self: &Rc<Self>) {
        {
            let home = &mut self.state.borrow_mut().home;
            if matches!(home.step, Step::Checking | Step::Downloading(..) | Step::Installing) {
                return;
            }
            home.step = Step::Checking;
            home.tried = Some(Instant::now());
        }
        self.with_ui(|ui| show_home(ui, &self.state.borrow()));
        self.run_job(update::check, |app, result| {
            let mut state = app.state.borrow_mut();
            let answered = matches!(result, Some(Ok(_)));
            state.home.step = match result {
                Some(Ok(update::Check::Current)) => Step::Current,
                Some(Ok(update::Check::NoReleases)) => Step::NoReleases,
                Some(Ok(update::Check::Newer(release))) => Step::Available(release),
                Some(Err(e)) => {
                    system::log_error("update check", &e);
                    Step::Failed(why(e))
                }
                None => Step::Failed(0),
            };
            if answered {
                state.settings.update_checked_at = Some(Local::now());
                let _ = state.settings.save();
            }
            app.with_ui(|ui| show_home(ui, &state));
        });
    }

    fn download_update(self: &Rc<Self>) {
        let (release, done) = {
            let home = &mut self.state.borrow_mut().home;
            let Step::Available(release) = std::mem::take(&mut home.step) else { return };
            let done = Arc::new(AtomicU64::new(0));
            home.step = Step::Downloading(release.clone(), done.clone());
            (release, done)
        };
        self.with_ui(|ui| show_home(ui, &self.state.borrow()));
        self.run_job(
            move || {
                let path = update::download(&release, &done);
                (release, path)
            },
            |app, result| {
                let mut state = app.state.borrow_mut();
                state.home.step = match result {
                    Some((release, Ok(path))) => Step::Ready(release, path),
                    Some((_, Err(e))) => {
                        system::log_error("update download", &e);
                        Step::Failed(why(e))
                    }
                    None => Step::Failed(4),
                };
                app.with_ui(|ui| show_home(ui, &state));
            },
        );
    }

    /// Swaps the exe and quits the way the tray's Quit does, so the governor puts back
    /// what it changed before the new one starts.
    fn install_update(self: &Rc<Self>) {
        let (release, path) = {
            let home = &mut self.state.borrow_mut().home;
            let Step::Ready(release, path) = std::mem::take(&mut home.step) else { return };
            home.step = Step::Installing;
            (release, path)
        };
        self.with_ui(|ui| show_home(ui, &self.state.borrow()));
        self.run_job(
            move || update::install(&path, &release),
            |app, result| match result {
                Some(Ok(())) => {
                    let _ = slint::quit_event_loop();
                }
                failed => {
                    if let Some(Err(e)) = failed {
                        system::log_error("update install", &e);
                    }
                    app.state.borrow_mut().home.step = Step::Failed(5);
                    app.with_ui(|ui| show_home(ui, &app.state.borrow()));
                }
            },
        );
    }

    fn read_system_disk(self: &Rc<Self>) {
        self.state.borrow_mut().home.disk_read = true;
        self.run_job(
            || {
                let system = system_drive();
                health::drives()
                    .iter()
                    .find(|drive| drive.letters.split_whitespace().any(|l| l.eq_ignore_ascii_case(&system)))
                    .map(|drive| drive_row(drive).verdict)
            },
            |app, verdict| {
                // A drive that wasn't found has nothing to say, like one that doesn't answer.
                app.state.borrow_mut().home.disk = Some(verdict.flatten().unwrap_or(3));
                app.with_ui(|ui| show_home(ui, &app.state.borrow()));
            },
        );
    }
}

fn system_drive() -> String {
    std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into())
}

fn why(error: update::Error) -> i32 {
    match error {
        update::Error::Offline => 0,
        update::Error::Refused(_) | update::Error::Unreadable => 1,
        update::Error::NoExe => 2,
        update::Error::BadHash => 3,
        update::Error::Disk => 4,
    }
}

fn show_home(ui: &AppWindow, state: &State) {
    let page = ui.global::<Home>();
    let home = &state.home;
    let (step, release) = match &home.step {
        Step::Idle => (UpdateStep::Idle, None),
        Step::Checking => (UpdateStep::Checking, None),
        Step::Current => (UpdateStep::Current, None),
        Step::NoReleases => (UpdateStep::None, None),
        Step::Failed(why) => {
            page.set_why(*why);
            (UpdateStep::Failed, None)
        }
        Step::Available(release) => (UpdateStep::Available, Some(release)),
        Step::Downloading(release, done) => {
            let done = done.load(Ordering::Relaxed);
            page.set_progress(if release.size == 0 { 0.0 } else { done as f32 / release.size as f32 });
            page.set_got(format_bytes(done).into());
            page.set_size(format_bytes(release.size).into());
            (UpdateStep::Downloading, Some(release))
        }
        Step::Ready(release, _) => (UpdateStep::Ready, Some(release)),
        Step::Installing => (UpdateStep::Installing, None),
    };
    page.set_step(step);
    if let Some(release) = release {
        page.set_latest(release.version.as_str().into());
    }
    page.set_notes(home.notes.as_deref().unwrap_or_default().into());
    page.set_disk(home.disk.unwrap_or(-1));
    page.set_disk_name(system_drive().into());
    page.set_baseline(state.baseline_alive);
    page.set_changes(state.changes.len() as i32);
}
