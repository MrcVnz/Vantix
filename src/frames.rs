//! Frame rate of games, from the same ETW event PresentMon reads: Present_Info of the
//! kernel graphics driver, which every API goes through, Direct3D, OpenGL and Vulkan
//! alike. It counts the frames a program hands to Windows, per process. Windows filters
//! the event by id, so the session costs next to nothing.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use windows::Win32::System::Diagnostics::Etw::EVENT_RECORD;
use windows::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};
use windows::Win32::System::Threading::GetCurrentProcessId;
use windows::core::GUID;

use crate::{etw, net, settings};

const SESSION: &str = "Vantix Frames";
const DXGKRNL: GUID = GUID::from_u128(0x802ec45a_1e99_4b83_9920_87c98277ba9d);
const PRESENT_INFO: u16 = 184;
/// Microsoft-Windows-DxgKrnl's Present keyword.
const PRESENT_KEYWORD: u64 = 0x800_0000;

/// Seconds to switch to the game after asking for a recording.
pub const COUNTDOWN: u32 = 5;
pub const LENGTH: u32 = 60;
/// Recordings kept in frames.json.
const KEEP: usize = 20;

#[derive(Default)]
struct Frames {
    /// Present times per process over the last two seconds, in QPC ticks.
    recent: HashMap<u32, VecDeque<i64>>,
    recording: Option<Recording>,
}

struct Recording {
    pid: u32,
    name: String,
    start: i64,
    end: i64,
    times: Vec<i64>,
}

static ON: AtomicBool = AtomicBool::new(false);
static FRAMES: Mutex<Option<Frames>> = Mutex::new(None);

fn frequency() -> i64 {
    let mut frequency = 0;
    let _ = unsafe { QueryPerformanceFrequency(&mut frequency) };
    frequency.max(1)
}

fn now() -> i64 {
    let mut now = 0;
    let _ = unsafe { QueryPerformanceCounter(&mut now) };
    now
}

pub fn start() -> windows::core::Result<()> {
    if ON.swap(true, Ordering::Relaxed) {
        return Ok(());
    }
    *FRAMES.lock().unwrap() = Some(Frames::default());
    let provider = etw::Provider { guid: DXGKRNL, level: 4, keywords: PRESENT_KEYWORD, events: &[PRESENT_INFO] };
    let result = etw::start(SESSION, &[provider], 64, 16, on_event);
    if result.is_err() {
        ON.store(false, Ordering::Relaxed);
    }
    result
}

pub fn stop() {
    if ON.swap(false, Ordering::Relaxed) {
        etw::stop(SESSION);
        *FRAMES.lock().unwrap() = None;
    }
}

pub fn end_leftover_trace() {
    if !ON.load(Ordering::Relaxed) {
        etw::stop(SESSION);
    }
}

unsafe extern "system" fn on_event(record: *mut EVENT_RECORD) {
    let record = unsafe { &*record };
    let header = &record.EventHeader;
    if header.ProviderId != DXGKRNL || header.EventDescriptor.Id != PRESENT_INFO {
        return;
    }
    let (pid, time) = (header.ProcessId, header.TimeStamp);
    let window = 2 * frequency();
    let mut frames = FRAMES.lock().unwrap();
    let Some(frames) = frames.as_mut() else { return };
    let times = frames.recent.entry(pid).or_default();
    times.push_back(time);
    while times.front().is_some_and(|&t| time - t > window) {
        times.pop_front();
    }
    if let Some(recording) = frames.recording.as_mut()
        && recording.pid == pid
        && (recording.start..recording.end).contains(&time)
    {
        recording.times.push(time);
    }
}

pub struct Live {
    pub pid: u32,
    pub name: String,
    pub fps: f64,
}

/// Programs drawing at least 10 frames a second, busiest first. The desktop compositor
/// and Vantix itself are left out. Events arrive up to a second late, when the session
/// flushes, so the rate comes from the span of the frames received, not from the clock.
pub fn live() -> Vec<Live> {
    let (frequency, now, own) = (frequency(), now(), unsafe { GetCurrentProcessId() });
    let rates: Vec<(u32, f64)> = {
        let mut frames = FRAMES.lock().unwrap();
        let Some(frames) = frames.as_mut() else { return Vec::new() };
        frames.recent.retain(|_, times| times.back().is_some_and(|&t| now - t < 3 * frequency));
        frames
            .recent
            .iter()
            .filter(|(_, times)| times.len() >= 10)
            .map(|(pid, times)| {
                let span = (times.back().unwrap() - times.front().unwrap()) as f64 / frequency as f64;
                (*pid, (times.len() - 1) as f64 / span.max(1e-3))
            })
            .collect()
    };
    let mut list: Vec<Live> = rates
        .into_iter()
        .filter(|&(pid, fps)| pid != own && fps >= 10.0)
        .map(|(pid, fps)| Live { pid, name: net::process_name(pid), fps })
        .filter(|live| !live.name.eq_ignore_ascii_case("dwm.exe"))
        .collect();
    list.sort_by(|a, b| b.fps.total_cmp(&a.fps));
    list
}

/// Records `pid` for LENGTH seconds after COUNTDOWN seconds. Replaces a recording that
/// hasn't finished.
pub fn record(pid: u32, name: &str) {
    let (frequency, now) = (frequency(), now());
    let start = now + i64::from(COUNTDOWN) * frequency;
    if let Some(frames) = FRAMES.lock().unwrap().as_mut() {
        frames.recording =
            Some(Recording { pid, name: name.into(), start, end: start + i64::from(LENGTH) * frequency, times: Vec::new() });
    }
}

pub fn cancel() {
    if let Some(frames) = FRAMES.lock().unwrap().as_mut() {
        frames.recording = None;
    }
}

pub enum Progress {
    Idle,
    /// Seconds until it starts.
    Countdown(u32),
    /// Seconds recorded.
    Recording(u32),
}

pub fn progress() -> (Progress, String) {
    let (frequency, now) = (frequency(), now());
    let frames = FRAMES.lock().unwrap();
    let Some(recording) = frames.as_ref().and_then(|f| f.recording.as_ref()) else {
        return (Progress::Idle, String::new());
    };
    let progress = if now < recording.start {
        Progress::Countdown(((recording.start - now) / frequency + 1) as u32)
    } else {
        Progress::Recording(((now - recording.start) / frequency).min(i64::from(LENGTH)) as u32)
    };
    (progress, recording.name.clone())
}

pub fn recording() -> bool {
    FRAMES.lock().unwrap().as_ref().is_some_and(|f| f.recording.is_some())
}

/// A recording that ended, or `None` while one runs or none was asked for. One whose
/// program closed early still counts if it got 10 seconds; shorter ones come back as an
/// error with the program's name.
pub fn finished() -> Option<Result<Run, String>> {
    let (frequency, now) = (frequency(), now());
    let mut frames = FRAMES.lock().unwrap();
    let frames = frames.as_mut()?;
    let recording = frames.recording.as_ref()?;
    let quiet = recording.times.last().map_or(now - recording.start, |&t| now - t);
    let gone = now > recording.start + 3 * frequency && quiet > 3 * frequency;
    // The last second of frames is still on its way.
    if now < recording.end + frequency * 3 / 2 && !gone {
        return None;
    }
    let recording = frames.recording.take()?;
    let run = Run::from_times(&recording.name, &recording.times, frequency).filter(|run| run.seconds >= 10.0);
    Some(run.ok_or(recording.name))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Run {
    pub name: String,
    pub time: DateTime<Local>,
    pub seconds: f64,
    pub frames: u32,
    pub average: f64,
    /// FPS at the frame time that 99% of frames beat.
    pub low1: f64,
    /// The same for 99.9%.
    pub low01: f64,
    /// Frames in each whole second, which tells how much the rate wanders by itself.
    pub per_second: Vec<f64>,
}

impl Run {
    fn from_times(name: &str, times: &[i64], frequency: i64) -> Option<Self> {
        let (&first, &last) = (times.first()?, times.last()?);
        if times.len() < 3 || last <= first {
            return None;
        }
        let frequency = frequency as f64;
        let seconds = (last - first) as f64 / frequency;
        let mut gaps: Vec<f64> = times.windows(2).map(|w| (w[1] - w[0]) as f64 / frequency).collect();
        gaps.sort_by(f64::total_cmp);
        // The frame time that `share` of the frames beat: of 1000 frames, 99.9% is the
        // slowest one.
        let at = |share: f64| {
            let index = ((gaps.len() as f64 * share) as usize).min(gaps.len() - 1);
            1.0 / gaps[index].max(1e-6)
        };
        let mut per_second = vec![0.0; seconds.floor() as usize];
        for &t in times {
            if let Some(slot) = per_second.get_mut(((t - first) as f64 / frequency) as usize) {
                *slot += 1.0;
            }
        }
        Some(Self {
            name: name.into(),
            time: Local::now(),
            seconds,
            frames: times.len() as u32 - 1,
            average: (times.len() - 1) as f64 / seconds,
            low1: at(0.99),
            low01: at(0.999),
            per_second,
        })
    }
}

/// How B differs from A, in percent of A, and whether the average moved by more than
/// the rate wanders from second to second on its own.
pub struct Comparison {
    pub average: f64,
    pub low1: f64,
    pub low01: f64,
    pub real: bool,
}

pub fn compare(a: &Run, b: &Run) -> Comparison {
    let percent = |a: f64, b: f64| if a > 0.0 { (b - a) / a * 100.0 } else { 0.0 };
    let spread = |values: &[f64]| {
        let n = values.len().max(2) as f64;
        let mean = values.iter().sum::<f64>() / n;
        values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / (n - 1.0) / n
    };
    let noise = 2.0 * (spread(&a.per_second) + spread(&b.per_second)).sqrt();
    Comparison {
        average: percent(a.average, b.average),
        low1: percent(a.low1, b.low1),
        low01: percent(a.low01, b.low01),
        real: (b.average - a.average).abs() > noise.max(a.average * 0.01),
    }
}

fn path() -> std::path::PathBuf {
    settings::data_dir().join("frames.json")
}

pub fn load_runs() -> Vec<Run> {
    std::fs::read_to_string(path()).ok().and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default()
}

/// Newest first.
pub fn save_runs(runs: &mut Vec<Run>) {
    runs.truncate(KEEP);
    if let Ok(text) = serde_json::to_vec_pretty(runs) {
        let _ = std::fs::create_dir_all(settings::data_dir());
        let _ = std::fs::write(path(), text);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stats_of_a_steady_rate() {
        let frequency = 10_000_000;
        let times: Vec<i64> = (0..=600).map(|i| i * frequency / 100).collect();
        let run = Run::from_times("x", &times, frequency).unwrap();
        assert!((run.average - 100.0).abs() < 0.01);
        assert!((run.low1 - 100.0).abs() < 0.01);
        assert_eq!(run.per_second.len(), 6);
        let same = compare(&run, &run);
        assert!(!same.real && same.average.abs() < 1e-9);
    }

    #[test]
    fn one_slow_frame_shows_in_the_lows() {
        let frequency = 10_000_000;
        let mut times: Vec<i64> = (0..=1000).map(|i| i * frequency / 100).collect();
        // One 50 ms hitch in 10 seconds.
        for t in times.iter_mut().skip(500) {
            *t += frequency / 25;
        }
        let run = Run::from_times("x", &times, frequency).unwrap();
        assert!(run.low01 < 25.0, "{}", run.low01);
        assert!(run.low1 > 99.0, "{}", run.low1);
    }

    /// Runs a known presenter (VX_PRESENTER, a scratch tool that presents through D3D11 or
    /// OpenGL at 100 FPS) and reads it back: `cargo test frames_presenter -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn frames_presenter() {
        let exe = std::env::var("VX_PRESENTER").expect("VX_PRESENTER");
        for mode in ["dx", "gl"] {
            start().unwrap();
            // Closes 21 s into the recording, which ends it early like a game quitting.
            let mut child = std::process::Command::new(&exe).args([mode, "100", "30"]).spawn().unwrap();
            std::thread::sleep(std::time::Duration::from_secs(4));
            let live = live();
            let found = live.iter().find(|l| l.pid == child.id()).map(|l| l.fps);
            println!("{mode} live: {found:?} of {:?}", live.iter().map(|l| (&l.name, l.fps)).collect::<Vec<_>>());
            record(child.id(), "presenter");
            child.wait().unwrap();
            let run = loop {
                std::thread::sleep(std::time::Duration::from_millis(500));
                if let Some(run) = finished() {
                    break run.expect("too short");
                }
            };
            println!(
                "{mode} run: {:.1}s {} frames avg {:.1} low1 {:.1} low01 {:.1}",
                run.seconds, run.frames, run.average, run.low1, run.low01
            );
            stop();
            assert!(found.is_some_and(|fps| (fps - 100.0).abs() <= 2.0));
            assert!((run.average - 100.0).abs() < 1.0);
            assert!(run.seconds > 19.0, "{}", run.seconds);
        }
    }
}
