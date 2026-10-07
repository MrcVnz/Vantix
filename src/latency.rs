//! System latency, the way LatencyMon measures it: the kernel reports every interrupt
//! routine (ISR) and deferred procedure call (DPC) with when it started and when it
//! ended. While one runs, nothing else gets that core, audio and the game included, so
//! a driver whose routines run long is what makes audio crackle and frames stutter.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use windows::Win32::System::Diagnostics::Etw::{EVENT_RECORD, EVENT_TRACE_FLAG_DPC, EVENT_TRACE_FLAG_INTERRUPT};
use windows::Win32::System::Performance::QueryPerformanceFrequency;
use windows::Win32::System::ProcessStatus::{EnumDeviceDrivers, GetDeviceDriverBaseNameW, GetDeviceDriverFileNameW};
use windows::core::GUID;

use crate::{etw, memory, startup};

const SESSION: &str = "Vantix Latency";
/// The kernel's PerfInfo events: ISRs and DPCs.
const PERFINFO: GUID = GUID::from_u128(0xce1dbfb4_137e_4da6_87b0_3f59aa102cbc);
/// Interrupts of devices that signal by message (MSI): NVMe, graphics, network.
const ISR_MSI: u8 = 50;
const THREAD_DPC: u8 = 66;
const ISR: u8 = 67;
const DPC: u8 = 68;
const TIMER_DPC: u8 = 69;

/// Routines longer than this, in microseconds, can starve audio at small buffers.
pub const WARN: f64 = 500.0;
/// Longer than this they cause audible dropouts and frame stutter.
pub const BAD: f64 = 2000.0;

#[derive(Clone, Copy, Default)]
struct Tally {
    count: u64,
    /// QPC ticks.
    total: i64,
    max: i64,
}

impl Tally {
    fn add(&mut self, other: Tally) {
        self.count += other.count;
        self.total += other.total;
        self.max = self.max.max(other.max);
    }
}

struct Routines {
    since: Instant,
    /// When the trace stopped, so a finished measurement keeps its length.
    until: Option<Instant>,
    /// Per routine address, as the kernel reports them; mapped to drivers when read.
    isr: HashMap<u64, Tally>,
    dpc: HashMap<u64, Tally>,
}

static ON: AtomicBool = AtomicBool::new(false);
static ROUTINES: Mutex<Option<Routines>> = Mutex::new(None);
/// File descriptions by driver name, read once per driver.
static DESCRIPTIONS: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

fn frequency() -> i64 {
    let mut frequency = 0;
    let _ = unsafe { QueryPerformanceFrequency(&mut frequency) };
    frequency.max(1)
}

/// Starts a new measurement; the previous one is dropped.
pub fn start() -> windows::core::Result<()> {
    if ON.swap(true, Ordering::Relaxed) {
        return Ok(());
    }
    // Without SeDebugPrivilege, Windows 11 24H2 and later hand out zeroed driver
    // addresses, and no routine could be matched to its driver.
    memory::enable_privileges();
    *ROUTINES.lock().unwrap() =
        Some(Routines { since: Instant::now(), until: None, isr: HashMap::new(), dpc: HashMap::new() });
    // A busy machine runs tens of thousands of DPCs a second; small buffers drop them.
    let result = etw::start_kernel(SESSION, EVENT_TRACE_FLAG_DPC | EVENT_TRACE_FLAG_INTERRUPT, 256, 64, on_event);
    if result.is_err() {
        ON.store(false, Ordering::Relaxed);
        *ROUTINES.lock().unwrap() = None;
    }
    result
}

/// Stops the trace and keeps what it measured for `report`.
pub fn stop() {
    if ON.swap(false, Ordering::Relaxed) {
        etw::stop(SESSION);
        if let Some(routines) = ROUTINES.lock().unwrap().as_mut() {
            routines.until = Some(Instant::now());
        }
    }
}

pub fn running() -> bool {
    ON.load(Ordering::Relaxed)
}

pub fn end_leftover_trace() {
    if !running() {
        etw::stop(SESSION);
    }
}

unsafe extern "system" fn on_event(record: *mut EVENT_RECORD) {
    let record = unsafe { &*record };
    let header = &record.EventHeader;
    let opcode = header.EventDescriptor.Opcode;
    if header.ProviderId != PERFINFO || !matches!(opcode, ISR_MSI | THREAD_DPC | ISR | DPC | TIMER_DPC) {
        return;
    }
    // All of them start with InitialTime and Routine; the event itself is logged when
    // the routine returns.
    let data = etw::payload(record);
    let (Some(start), Some(routine)) = (data.get(0..8), data.get(8..16)) else { return };
    let ticks = header.TimeStamp - i64::from_le_bytes(start.try_into().unwrap());
    let routine = u64::from_le_bytes(routine.try_into().unwrap());
    if ticks < 0 || !running() {
        return;
    }
    let mut routines = ROUTINES.lock().unwrap();
    let Some(routines) = routines.as_mut() else { return };
    let map = if matches!(opcode, ISR | ISR_MSI) { &mut routines.isr } else { &mut routines.dpc };
    map.entry(routine).or_default().add(Tally { count: 1, total: ticks, max: ticks });
}

/// Kernel modules by load address, lowest first.
fn modules() -> Vec<(u64, String)> {
    let mut bases = vec![std::ptr::null_mut(); 1024];
    let mut needed = 0;
    let size = size_of_val(bases.as_slice()) as u32;
    if unsafe { EnumDeviceDrivers(bases.as_mut_ptr(), size, &mut needed) }.is_err() {
        return Vec::new();
    }
    bases.truncate(needed as usize / size_of::<*mut core::ffi::c_void>());
    let mut list: Vec<(u64, String)> = bases
        .into_iter()
        .filter(|base| !base.is_null())
        .map(|base| {
            let mut name = [0u16; 260];
            let n = unsafe { GetDeviceDriverBaseNameW(base, &mut name) } as usize;
            (base as u64, String::from_utf16_lossy(&name[..n]))
        })
        .collect();
    list.sort_by_key(|(base, _)| *base);
    list
}

/// What the driver file says it is, such as "NVIDIA Windows Kernel Mode Driver".
fn description(base: u64, name: &str) -> String {
    let mut cache = DESCRIPTIONS.lock().unwrap();
    let cache = cache.get_or_insert_default();
    if let Some(text) = cache.get(name) {
        return text.clone();
    }
    let mut path = [0u16; 520];
    let n = unsafe { GetDeviceDriverFileNameW(base as *const _, &mut path) } as usize;
    let path = String::from_utf16_lossy(&path[..n]);
    // Kernel paths: \SystemRoot\..., \??\C:\... or one relative to the Windows folder.
    let windows = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let path = if let Some(rest) = path.strip_prefix(r"\SystemRoot\") {
        PathBuf::from(&windows).join(rest)
    } else if let Some(rest) = path.strip_prefix(r"\??\") {
        PathBuf::from(rest)
    } else if path.contains(':') {
        PathBuf::from(path)
    } else {
        PathBuf::from(&windows).join(path.trim_start_matches('\\'))
    };
    let text = startup::version_info(&path).0;
    cache.insert(name.into(), text.clone());
    text
}

#[derive(Clone, Default)]
pub struct Driver {
    pub name: String,
    pub description: String,
    pub isr_count: u64,
    /// Microseconds.
    pub isr_max: f64,
    pub dpc_count: u64,
    pub dpc_max: f64,
    /// Share of one core spent in this driver's routines, in percent.
    pub busy: f64,
}

impl Driver {
    pub fn worst(&self) -> f64 {
        self.isr_max.max(self.dpc_max)
    }
}

pub struct Report {
    pub seconds: f64,
    /// Longest routine first.
    pub drivers: Vec<Driver>,
}

impl Report {
    /// The longest ISR, in microseconds, with the driver that ran it.
    pub fn worst_isr(&self) -> Option<(f64, &str)> {
        let driver = self.drivers.iter().filter(|d| d.isr_count > 0).max_by(|a, b| a.isr_max.total_cmp(&b.isr_max))?;
        Some((driver.isr_max, &driver.name))
    }

    pub fn worst_dpc(&self) -> Option<(f64, &str)> {
        let driver = self.drivers.iter().filter(|d| d.dpc_count > 0).max_by(|a, b| a.dpc_max.total_cmp(&b.dpc_max))?;
        Some((driver.dpc_max, &driver.name))
    }
}

/// What the measurement found so far, or the last one after a stop. `None` when none ran.
pub fn report() -> Option<Report> {
    let (seconds, isr, dpc) = {
        let routines = ROUTINES.lock().unwrap();
        let routines = routines.as_ref()?;
        let end = routines.until.unwrap_or_else(Instant::now);
        (end.duration_since(routines.since).as_secs_f64(), routines.isr.clone(), routines.dpc.clone())
    };
    let modules = modules();
    let owner = |routine: u64| {
        let i = modules.partition_point(|(base, _)| *base <= routine);
        modules.get(i.wrapping_sub(1)).map_or((0, "?"), |(base, name)| (*base, name.as_str()))
    };
    let mut by_driver: HashMap<&str, (u64, Tally, Tally)> = HashMap::new();
    for (routine, tally) in &isr {
        let (base, name) = owner(*routine);
        by_driver.entry(name).or_insert((base, Tally::default(), Tally::default())).1.add(*tally);
    }
    for (routine, tally) in &dpc {
        let (base, name) = owner(*routine);
        by_driver.entry(name).or_insert((base, Tally::default(), Tally::default())).2.add(*tally);
    }
    let micros = 1e6 / frequency() as f64;
    let mut drivers: Vec<Driver> = by_driver
        .into_iter()
        .map(|(name, (base, isr, dpc))| Driver {
            name: name.into(),
            description: if base == 0 { String::new() } else { description(base, name) },
            isr_count: isr.count,
            isr_max: isr.max as f64 * micros,
            dpc_count: dpc.count,
            dpc_max: dpc.max as f64 * micros,
            // Microseconds busy over microseconds measured, in percent.
            busy: (isr.total + dpc.total) as f64 * micros / 1e4 / seconds.max(1e-3),
        })
        .collect();
    drivers.sort_by(|a, b| b.worst().total_cmp(&a.worst()));
    Some(Report { seconds, drivers })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Watches the machine for 10 seconds and prints what each driver did:
    /// `cargo test latency_live -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn latency_live() {
        start().unwrap();
        std::thread::sleep(std::time::Duration::from_secs(12));
        stop();
        let report = report().unwrap();
        for d in &report.drivers {
            println!(
                "{:<16} {:<44} isr {:>6} max {:>7.1} us  dpc {:>6} max {:>7.1} us  busy {:.3}%",
                d.name, d.description, d.isr_count, d.isr_max, d.dpc_count, d.dpc_max, d.busy
            );
        }
        println!("{:.1} s, worst isr {:?}, worst dpc {:?}", report.seconds, report.worst_isr(), report.worst_dpc());
        assert!(report.worst_dpc().is_some() && report.worst_isr().is_some());
    }
}
