//! User settings and cleanup history, stored as JSON under %APPDATA%\EasyTune.

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
}

impl Default for AutoClean {
    fn default() -> Self {
        Self { mode: AutoMode::Off, minutes: 30, percent: 80 }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub language: Language,
    pub clean_level: Level,
    pub auto_clean: AutoClean,
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

pub fn data_dir() -> PathBuf {
    let base = std::env::var_os("APPDATA").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    base.join("EasyTune")
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
