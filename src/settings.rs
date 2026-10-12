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

/// The undo journal. Empty when missing or unusable; `journal_problem` says which.
pub fn load_changes() -> Vec<Change> {
    read_json(&data_dir().join("changes.json")).unwrap_or_else(|problem| {
        JOURNAL.lock().unwrap().get_or_insert(problem);
        Vec::new()
    })
}

pub fn journal_problem() -> Option<Unreadable> {
    JOURNAL.lock().unwrap().clone()
}

pub fn save_changes(changes: &[Change]) -> io::Result<()> {
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
pub(crate) fn write_json<T: Serialize + ?Sized>(path: &Path, value: &T) -> io::Result<()> {
    fs::create_dir_all(path.parent().unwrap())?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(value)?)?;
    fs::rename(tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

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
