//! User settings and cleanup history, stored as JSON under %APPDATA%\Vantix.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Local};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::memory::Level;

const HISTORY_LIMIT: usize = 200;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    #[default]
    System,
    En,
    PtBr,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AutoMode {
    #[default]
    Off,
    Interval,
    Limit,
}

/// Both values are kept even when unused so switching modes doesn't reset them.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct AutoClean {
    pub mode: AutoMode,
    pub minutes: u32,
    pub percent: u32,
    /// What the tray toggle turns back on.
    pub last_mode: AutoMode,
}

impl Default for AutoClean {
    fn default() -> Self {
        Self { mode: AutoMode::Off, minutes: 30, percent: 80, last_mode: AutoMode::Limit }
    }
}

/// The real-time game mode and what it does while a game runs.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct GameMode {
    pub enabled: bool,
    pub priority: bool,
    pub cores: bool,
    pub eco: bool,
    pub services: bool,
    pub standby: bool,
    pub wifi: bool,
    pub gpu: bool,
}

impl Default for GameMode {
    fn default() -> Self {
        Self {
            enabled: false,
            priority: true,
            cores: true,
            eco: true,
            services: true,
            standby: true,
            wifi: true,
            gpu: true,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub terms_version: u32,
    pub terms_accepted_at: Option<DateTime<Local>>,
    pub language: Language,
    pub clean_level: Level,
    pub auto_clean: AutoClean,
    /// Only applies to starts from the logon task.
    pub start_minimized: bool,
    pub notifications: bool,
    /// A toast when game mode finds a game.
    pub game_notice: bool,
    pub tray_hint_shown: bool,
    /// Sequence number of the restore point made before Vantix's first system change.
    /// Later changes rely on it and the journal instead of making a point each.
    pub baseline_point: Option<u32>,
    /// Every restore point Vantix made, the baseline and the manual ones. Only these can
    /// be deleted from the app.
    pub own_points: Vec<u32>,
    pub probalance: bool,
    pub game_mode: GameMode,
    /// Extra targets for the live ping, as typed: names or IPv4 addresses.
    pub ping_hosts: Vec<String>,
    /// Upload speed from the last bufferbloat test, which upload limits are set from.
    pub upload_mbps: Option<f64>,
    /// Folders searched for duplicates; `None` until changed, which means the user's own
    /// folders (see dupes::default_folders).
    pub dup_folders: Option<Vec<std::path::PathBuf>>,
    /// Exe names game mode always treats as games, and never does.
    pub games: Vec<String>,
    pub not_games: Vec<String>,
    /// Last time GitHub answered whether there's a newer version.
    pub update_checked_at: Option<DateTime<Local>>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            terms_version: 0,
            terms_accepted_at: None,
            language: Language::System,
            clean_level: Level::default(),
            auto_clean: AutoClean::default(),
            start_minimized: true,
            notifications: true,
            game_notice: true,
            tray_hint_shown: false,
            baseline_point: None,
            own_points: Vec::new(),
            probalance: false,
            game_mode: GameMode::default(),
            ping_hosts: Vec::new(),
            upload_mbps: None,
            dup_folders: None,
            games: Vec::new(),
            not_games: Vec::new(),
            update_checked_at: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub time: DateTime<Local>,
    pub level: Level,
    pub automatic: bool,
    pub before_in_use: u64,
    pub after_in_use: u64,
}

impl HistoryEntry {
    pub fn freed(&self) -> i64 {
        self.before_in_use as i64 - self.after_in_use as i64
    }
}

/// One applied tweak, kept until it's undone. This is what "Undo" works from.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Change {
    pub id: String,
    pub time: DateTime<Local>,
    /// What the tweak needs to put the old state back.
    pub previous: Option<String>,
    /// Boot it was applied in, to tell when a change that needs a restart took effect.
    pub boot: i64,
    pub reboot: bool,
    /// Free space measured on the Windows drive before and after.
    pub freed: Option<u64>,
    /// The tweak was already in place before Vantix and this turned it off.
    #[serde(default)]
    pub reset: bool,
    /// An interrupted operation must remain available even when only partly applied.
    #[serde(default)]
    pub recovery: bool,
    /// Power plan the change was made on, for the settings that live in a plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<String>,
}

pub fn data_dir() -> PathBuf {
    let base = std::env::var_os("APPDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    base.join("Vantix")
}

impl Settings {
    pub fn load() -> Self {
        read_json(&data_dir().join("settings.json")).ok().unwrap_or_default()
    }

    pub fn save(&self) -> io::Result<()> {
        write_json(&data_dir().join("settings.json"), self)
    }
}

pub fn load_history() -> Vec<HistoryEntry> {
    read_json(&data_dir().join("history.json")).ok().unwrap_or_default()
}

pub fn save_history(history: &mut Vec<HistoryEntry>) -> io::Result<()> {
    if history.len() > HISTORY_LIMIT {
        history.drain(..history.len() - HISTORY_LIMIT);
    }
    write_json(&data_dir().join("history.json"), history)
}

/// Why a file that exists couldn't be used.
#[derive(Clone, Debug, PartialEq)]
pub enum Unreadable {
    /// Damaged: moved aside under this name, so nothing overwrites it.
    Moved(PathBuf),
    /// Couldn't be read or moved, so it's left alone.
    Locked,
}

/// What went wrong with the undo journal this session, kept for the window to tell.
static JOURNAL: std::sync::Mutex<Option<Unreadable>> = std::sync::Mutex::new(None);
/// The journal as last loaded or saved, for the checks that run on worker threads: one
/// read of the file at start instead of one per tweak on every refresh.
static CACHE: std::sync::Mutex<Vec<Change>> = std::sync::Mutex::new(Vec::new());

/// The journal as the window has it. Changes made since the last save aren't in it yet.
pub fn journal() -> Vec<Change> {
    CACHE.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

pub fn in_journal(id: &str) -> bool {
    CACHE.lock().unwrap_or_else(|e| e.into_inner()).iter().any(|c| c.id == id)
}

/// The undo journal. Empty when missing or unusable; `journal_problem` says which.
pub fn load_changes() -> Vec<Change> {
    let mut changes: Vec<Change> = match read_json(&data_dir().join("changes.json")) {
        Ok(changes) => changes,
        Err(problem) => {
            JOURNAL.lock().unwrap().get_or_insert(problem);
            Vec::new()
        }
    };
    // Prepared before a system write, including operations interrupted before completion.
    let pending: Vec<Change> = read_json(&pending_path()).unwrap_or_default();
    let had_pending = !pending.is_empty();
    merge_records(&mut changes, pending, true);
    if had_pending && save_changes(&changes).is_ok() {
        clear_pending();
    }
    *CACHE.lock().unwrap_or_else(|e| e.into_inner()) = changes.clone();
    changes
}

fn pending_path() -> PathBuf {
    #[cfg(test)]
    if let Some(path) = TEST_PENDING.with(|path| path.borrow().clone()) {
        return path;
    }
    data_dir().join("changes.pending.json")
}

#[cfg(test)]
thread_local! {
    static TEST_PENDING: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

thread_local! {
    static PREPARING: std::cell::RefCell<Option<Change>> = const { std::cell::RefCell::new(None) };
}

static WRITERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static PENDING_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn preparing() -> bool {
    WRITERS.load(std::sync::atomic::Ordering::SeqCst) != 0
}

/// The guard also clears the context when a Windows operation panics.
pub fn with_change<T>(change: Change, work: impl FnOnce() -> windows::core::Result<T>) -> windows::core::Result<T> {
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            PREPARING.with(|slot| slot.replace(None));
            WRITERS.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
    {
        let _lock = PENDING_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        WRITERS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
    let _guard = Guard;
    let reset = change.reset;
    PREPARING.with(|slot| slot.replace(Some(change)));
    if reset {
        checkpoint(None)?;
    }
    let result = work();
    if result.is_ok() {
        PREPARING.with(|slot| -> windows::core::Result<()> {
            let mut context = slot.borrow_mut();
            let change = context.as_mut().unwrap();
            let _lock = PENDING_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let path = pending_path();
            let mut pending: Vec<Change> = read_json(&path).map_err(|_| recovery_error("recovery journal is unreadable"))?;
            if let Some(record) = pending.iter_mut().find(|c| c.id == change.id && c.plan == change.plan) {
                record.recovery = false;
                write_json(&path, &pending).map_err(recovery_error)?;
            }
            Ok(())
        })?;
    }
    result
}

fn recovery_error(error: impl std::fmt::Display) -> windows::core::Error {
    windows::core::Error::new(windows::Win32::Foundation::E_FAIL, format!("cannot save recovery data: {error}"))
}

/// Called with the exact undo data BEFORE the first corresponding system write.
/// Direct integration tests without an application transaction keep their old behavior.
pub fn checkpoint(previous: Option<String>) -> windows::core::Result<()> {
    PREPARING.with(|slot| {
        let mut context = slot.borrow_mut();
        let Some(change) = context.as_mut() else { return Ok(()) };
        if !change.reset {
            change.previous = previous;
            // Repeated service edits undo to the state before the first edit.
            if change.id.starts_with("service:")
                && let Some(original) = journal().into_iter().find(|c| c.id == change.id)
            {
                change.previous = original.previous;
            }
        }
        change.recovery = true;
        let _lock = PENDING_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        persist_pending(&pending_path(), change).map_err(recovery_error)
    })
}

/// A reset with an exact snapshot can recover that snapshot instead of reapplying.
pub fn checkpoint_restore(previous: Option<String>) -> windows::core::Result<()> {
    PREPARING.with(|slot| {
        if let Some(change) = slot.borrow_mut().as_mut() {
            change.reset = false;
        }
    });
    checkpoint(previous)
}

fn persist_pending(path: &Path, change: &Change) -> io::Result<()> {
    let mut pending: Vec<Change> = read_json(path).map_err(|_| io::Error::other("recovery journal is unreadable"))?;
    if let Some(existing) = pending.iter_mut().find(|c| c.id == change.id && c.plan == change.plan) {
        *existing = change.clone();
    } else {
        pending.push(change.clone());
    }
    write_json(path, &pending)
}

/// Only after undo succeeds. If saving fails, keep the original journal entry so
/// undo can be retried; never let an older pending apply resurrect the undone change.
pub fn forget_pending(id: &str, plan: Option<&str>) -> windows::core::Result<()> {
    let _lock = PENDING_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = pending_path();
    let mut pending: Vec<Change> = read_json(&path).map_err(|_| recovery_error("recovery journal is unreadable"))?;
    let before = pending.len();
    pending.retain(|c| c.id != id || c.plan.as_deref() != plan);
    if pending.len() != before {
        write_json(&path, &pending).map_err(recovery_error)?;
    }
    Ok(())
}

/// Commit under the same lock that starts writers. Never clear another job's snapshot.
pub fn commit_journal(changes: &mut Vec<Change>) -> io::Result<()> {
    let _lock = PENDING_LOCK.try_lock().map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "recovery journal is busy"))?;
    if preparing() {
        return Err(io::Error::new(io::ErrorKind::WouldBlock, "a system change is still running"));
    }
    let pending: Vec<Change> = read_json(&pending_path()).map_err(|_| io::Error::other("recovery journal is unreadable"))?;
    merge_records(changes, pending, false);
    save_changes(changes)?;
    match fs::remove_file(pending_path()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn merge_records(changes: &mut Vec<Change>, pending: Vec<Change>, restarted: bool) {
    for mut change in pending {
        if let Some(existing) = changes.iter_mut().find(|c| c.id == change.id && c.plan == change.plan) {
            if change.recovery || change.time > existing.time || (restarted && existing.recovery) {
                change.recovery = true;
                *existing = change;
            }
        } else {
            change.recovery = true;
            changes.push(change);
        }
    }
}

/// Once the journal holds them.
pub fn clear_pending() {
    let _ = fs::remove_file(pending_path());
}

pub fn journal_problem() -> Option<Unreadable> {
    JOURNAL.lock().unwrap().clone()
}

pub fn save_changes(changes: &[Change]) -> io::Result<()> {
    // What the window holds is the truth, saved or not.
    *CACHE.lock().unwrap_or_else(|e| e.into_inner()) = changes.to_vec();
    // A journal that's there but couldn't be read still holds changes this session
    // doesn't know about. Writing ours over it would lose them for good.
    if *JOURNAL.lock().unwrap() == Some(Unreadable::Locked) {
        return Err(io::Error::other("changes.json couldn't be read"));
    }
    write_json(&data_dir().join("changes.json"), changes)
}

/// A missing file is the default. A damaged one is moved aside and logged, and one that
/// can't be read at all is left where it is; both come back as errors.
pub(crate) fn read_json<T: DeserializeOwned + Default>(path: &Path) -> Result<T, Unreadable> {
    let failed = |what: &str, error: &dyn std::fmt::Display| {
        crate::system::log_error(&format!("{what} {}", path.display()), error);
    };
    let text = match fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(T::default()),
        // Not UTF-8: damaged, like bad JSON.
        Err(e) if e.kind() == io::ErrorKind::InvalidData => {
            failed("read", &e);
            None
        }
        Err(e) => {
            failed("read", &e);
            return Err(Unreadable::Locked);
        }
    };
    if let Some(text) = text {
        // A byte order mark, as Notepad writes, isn't damage.
        match serde_json::from_str(text.strip_prefix('\u{feff}').unwrap_or(&text)) {
            Ok(value) => return Ok(value),
            Err(e) => failed("parse", &e),
        }
    }
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    let kept = path.with_file_name(format!("{stem}.bad-{}.json", Local::now().format("%Y%m%d-%H%M%S")));
    match fs::rename(path, &kept) {
        Ok(()) => Err(Unreadable::Moved(kept)),
        Err(e) => {
            failed("move aside", &e);
            Err(Unreadable::Locked)
        }
    }
}

/// Writes to a sibling temp file first so a crash mid-write never leaves a truncated file.
/// The temp file reaches the disk before the rename: otherwise a power cut can keep the
/// rename and lose the data, leaving an empty file where the undo journal was.
pub(crate) fn write_json<T: Serialize + ?Sized>(path: &Path, value: &T) -> io::Result<()> {
    fs::create_dir_all(path.parent().unwrap())?;
    let tmp = path.with_extension("json.tmp");
    let mut file = fs::File::create(&tmp)?;
    io::Write::write_all(&mut file, &serde_json::to_vec_pretty(value)?)?;
    file.sync_all()?;
    drop(file);
    fs::rename(tmp, path)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn change(id: &str) -> Change {
        Change { id: id.into(), time: Local::now(), previous: None, boot: 0, reboot: false,
            freed: None, reset: false, recovery: true, plan: None }
    }

    #[test]
    fn interrupted_records_keep_exact_snapshots_and_completed_results() {
        let mut old = change("dns");
        old.previous = Some("old adapter".into());
        old.recovery = false;
        let mut pending = change("dns");
        pending.previous = Some("new adapter".into());
        let mut changes = vec![old.clone()];
        merge_records(&mut changes, vec![pending.clone()], false);
        assert_eq!(changes[0].previous, pending.previous);
        assert!(changes[0].recovery);

        pending.recovery = false;
        old.time = pending.time + chrono::TimeDelta::seconds(1);
        let mut changes = vec![old.clone()];
        merge_records(&mut changes, vec![pending.clone()], false);
        assert_eq!(changes[0].previous, old.previous);
        assert!(!changes[0].recovery);
        changes[0].time = pending.time - chrono::TimeDelta::seconds(1);
        merge_records(&mut changes, vec![pending.clone()], true);
        assert_eq!(changes[0].previous, pending.previous);
        assert!(changes[0].recovery);
    }

    #[test]
    fn recovery_is_durable_before_write_and_failure_blocks_mutation() {
        let dir = std::env::temp_dir().join(format!("vantix-write-ahead-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("pending.json");
        TEST_PENDING.with(|slot| slot.replace(Some(path.clone())));
        let result: windows::core::Result<()> = with_change(change("test"), || {
            checkpoint(Some("original".into()))?;
            let disk: Vec<Change> = read_json(&path).unwrap();
            assert_eq!(disk[0].previous.as_deref(), Some("original"));
            assert!(disk[0].recovery);
            Err(recovery_error("simulated system failure"))
        });
        assert!(result.is_err());
        assert!(PREPARING.with(|slot| slot.borrow().is_none()));
        let disk: Vec<Change> = read_json(&path).unwrap();
        assert!(disk[0].recovery);

        let mut reset = change("reset-test");
        reset.reset = true;
        let result: windows::core::Result<()> = with_change(reset, || {
            let disk: Vec<Change> = read_json(&path).unwrap();
            assert!(disk.iter().any(|c| c.id == "reset-test" && c.reset && c.recovery));
            checkpoint_restore(Some("exact pre-reset state".into()))?;
            Err(recovery_error("interrupted reset"))
        });
        assert!(result.is_err());
        let disk: Vec<Change> = read_json(&path).unwrap();
        let reset = disk.iter().find(|c| c.id == "reset-test").unwrap();
        assert!(!reset.reset);
        assert_eq!(reset.previous.as_deref(), Some("exact pre-reset state"));

        with_change(change("test"), || checkpoint(Some("original".into()))).unwrap();
        let disk: Vec<Change> = read_json(&path).unwrap();
        assert!(!disk.iter().find(|c| c.id == "test").unwrap().recovery);
        forget_pending("test", None).unwrap();
        let disk: Vec<Change> = read_json(&path).unwrap();
        assert_eq!(disk.len(), 1);
        assert_eq!(disk[0].id, "reset-test");

        let invalid = dir.join("not-a-directory");
        fs::write(&invalid, b"file").unwrap();
        TEST_PENDING.with(|slot| slot.replace(Some(invalid.join("pending.json"))));
        let mutated = std::cell::Cell::new(false);
        let result = with_change(change("test"), || {
            checkpoint(Some("before".into()))?;
            mutated.set(true);
            Ok(())
        });
        assert!(result.is_err());
        assert!(!mutated.get());
        TEST_PENDING.with(|slot| slot.replace(None));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn damaged_json_is_moved_aside() {
        let dir = std::env::temp_dir().join(format!("vantix-settings-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("changes.json");
        assert_eq!(read_json::<Vec<u32>>(&path), Ok(Vec::new()));

        write_json(&path, &[1u32, 2]).unwrap();
        assert_eq!(read_json::<Vec<u32>>(&path), Ok(vec![1, 2]));

        fs::write(&path, "\u{feff}[3]").unwrap();
        assert_eq!(read_json::<Vec<u32>>(&path), Ok(vec![3]));

        for damage in [&b"[1, 2"[..], &[0xff, 0xfe, 0x00][..]] {
            fs::write(&path, damage).unwrap();
            let Err(Unreadable::Moved(kept)) = read_json::<Vec<u32>>(&path) else { panic!("not moved") };
            assert!(!path.exists());
            assert_eq!(fs::read(&kept).unwrap(), damage);
            fs::remove_file(kept).unwrap();
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
