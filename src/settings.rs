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
        read_json(&data_dir().join("settings.json")).unwrap_or_default()
    }

    pub fn save(&self) -> io::Result<()> {
        write_json(&data_dir().join("settings.json"), self)
    }
}

pub fn load_history() -> Vec<HistoryEntry> {
    read_json(&data_dir().join("history.json")).unwrap_or_default()
}

pub fn save_history(history: &mut Vec<HistoryEntry>) -> io::Result<()> {
    if history.len() > HISTORY_LIMIT {
        history.drain(..history.len() - HISTORY_LIMIT);
    }
    write_json(&data_dir().join("history.json"), history)
}

pub fn load_changes() -> Vec<Change> {
    read_json(&data_dir().join("changes.json")).unwrap_or_default()
}

pub fn save_changes(changes: &[Change]) -> io::Result<()> {
    write_json(&data_dir().join("changes.json"), changes)
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Option<T> {
    let text = fs::read_to_string(path).ok()?;
    serde_json::from_str(&text).ok()
}

/// Writes to a sibling temp file first so a crash mid-write never leaves a truncated file.
fn write_json<T: Serialize + ?Sized>(path: &Path, value: &T) -> io::Result<()> {
    fs::create_dir_all(path.parent().unwrap())?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(value)?)?;
    fs::rename(tmp, path)
}
