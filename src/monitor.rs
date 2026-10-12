//! The Monitor page: CPU per core and clock, graphics card load and memory, disks, the
//! network and the busiest programs. A thread samples once a second, and only while the
//! page is open: the GPU counters alone cost a few milliseconds of CPU per read. No
//! temperatures, which need a kernel driver.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use windows::Wdk::Graphics::Direct3D::{
    D3DKMT_ADAPTERINFO, D3DKMT_ADAPTERREGISTRYINFO, D3DKMT_ADAPTERTYPE, D3DKMT_CLOSEADAPTER, D3DKMT_ENUMADAPTERS2,
    D3DKMT_QUERYADAPTERINFO, D3DKMT_SEGMENTSIZEINFO, D3DKMTCloseAdapter, D3DKMTEnumAdapters2,
    D3DKMTQueryAdapterInfo, KMTQAITYPE_ADAPTERREGISTRYINFO, KMTQAITYPE_ADAPTERTYPE,
    KMTQAITYPE_DRIVERVERSION, KMTQAITYPE_GETSEGMENTSIZE,
};
use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SystemProcessInformation};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{GetIfEntry2, MIB_IF_ROW2};
use windows::Win32::System::Performance::{
    PDH_FMT, PDH_FMT_COUNTERVALUE_ITEM_W, PDH_FMT_DOUBLE, PDH_HCOUNTER, PDH_HQUERY, PDH_MORE_DATA,
    PdhAddEnglishCounterW, PdhCloseQuery, PdhCollectQueryData, PdhGetFormattedCounterArrayW, PdhOpenQueryW,
};
use windows::Win32::System::Power::{CallNtPowerInformation, PROCESSOR_POWER_INFORMATION, ProcessorInformation};
use windows::Win32::System::ProcessStatus::EmptyWorkingSet;
use windows::Win32::System::Registry::HKEY_LOCAL_MACHINE;
use windows::Win32::System::Services::{
    CloseServiceHandle, ENUM_SERVICE_STATUS_PROCESSW, EnumServicesStatusExW, OpenSCManagerW, SC_ENUM_PROCESS_INFO,
    SC_MANAGER_ENUMERATE_SERVICE, SERVICE_STATE_ALL, SERVICE_WIN32,
};
use windows::Win32::System::SystemInformation::{
    CACHE_RELATIONSHIP, GetLogicalProcessorInformationEx, RelationCache, RelationProcessorCore,
    SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,
};
use windows::Win32::System::Threading::{
    GetCurrentProcessId, GetProcessInformation, IsProcessCritical, OpenProcess, PROCESS_ACCESS_RIGHTS,
    PROCESS_NAME_WIN32, PROCESS_PROTECTION_LEVEL_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SET_INFORMATION, PROCESS_SET_QUOTA, PROCESS_TERMINATE, PROTECTION_LEVEL_NONE,
    ProcessProtectionLevelInfo,
    QueryFullProcessImageNameW, TerminateProcess,
};
use windows::core::{BOOL, HSTRING, PWSTR};

use crate::{governor, net, reg};

/// Seconds of history behind each sparkline.
pub const HISTORY: usize = 60;
/// Rows in the program list. It's rebuilt every second, so it never scrolls.
pub const ROWS: usize = 12;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Sort {
    Cpu,
    Gpu,
    Memory,
}

/// The kinds of engine shown per card, by the name the counters use. Anything else, like
/// the security engine, still counts towards the card's load but gets no bar of its own.
pub const ENGINES: [&str; 5] = ["3D", "Compute", "Copy", "VideoDecode", "VideoEncode"];

/// A card's load, as the last sample found it. Its name and the rest of what doesn't
/// change are in `adapters`, in the same order.
#[derive(Clone, Default)]
pub struct Gpu {
    pub load: f32,
    pub memory_used: u64,
    pub memory_total: u64,
    /// Load per kind of engine, in the order of `ENGINES`.
    pub engines: [f32; ENGINES.len()],
}

#[derive(Clone, Default)]
pub struct Disk {
    pub name: String,
    pub read: f64,
    pub write: f64,
    pub active: f32,
}

/// Every process with the same exe name, as one row.
#[derive(Clone, Default)]
pub struct Program {
    pub name: String,
    pub pids: Vec<u32>,
    pub cpu: f32,
    pub gpu: f32,
    /// Private working set, what Task Manager calls Memory.
    pub memory: u64,
    /// EcoQoS on the first process, `None` when Windows doesn't let Vantix look.
    pub eco: Option<bool>,
    pub can_end: bool,
}

#[derive(Clone, Default)]
pub struct Snapshot {
    /// The performance counters have been read: before that the page shows the parts that
    /// cost nothing, the programs and the network, and a dash in place of the rest.
    pub measured: bool,
    pub cores: Vec<f32>,
    pub cpu: f32,
    pub mhz: f64,
    pub gpus: Vec<Gpu>,
    pub disks: Vec<Disk>,
    /// Bytes per second down and up on the connection in use.
    pub net: [f64; 2],
    pub programs: Vec<Program>,
    /// CPU %, GPU %, busiest disk's active time % and network bytes/s over the last
    /// minute, oldest first.
    pub history: [VecDeque<f64>; 4],
}

pub struct CpuInfo {
    pub name: String,
    pub cores: u32,
    pub threads: u32,
    /// Performance cores on a hybrid CPU, 0 when all cores are the same kind.
    pub performance: u32,
    pub base_mhz: u32,
    pub l3: u64,
    /// Which of `FEATURES` this CPU has, as indices: the UI reads the name and the
    /// explanation from the same place.
    pub features: Vec<usize>,
    /// For each physical core, where its threads sit in `Snapshot::cores`, so the chart
    /// can put the two threads of an SMT core side by side under one label.
    pub groups: Vec<Vec<usize>>,
}

static STOP: Mutex<Option<Arc<AtomicBool>>> = Mutex::new(None);
static LATEST: Mutex<Option<Snapshot>> = Mutex::new(None);
static SORT: AtomicU8 = AtomicU8::new(0);

pub fn watch() {
    let mut stop = STOP.lock().unwrap();
    if stop.is_some() {
        return;
    }
    let flag = Arc::new(AtomicBool::new(false));
    *stop = Some(flag.clone());
    std::thread::spawn(move || run(&flag));
}

pub fn unwatch() {
    if let Some(flag) = STOP.lock().unwrap().take() {
        flag.store(true, Ordering::Relaxed);
    }
    *LATEST.lock().unwrap() = None;
}

/// `None` until the first second has been measured.
pub fn snapshot() -> Option<Snapshot> {
    LATEST.lock().unwrap().clone()
}

pub fn set_sort(sort: Sort) {
    SORT.store(sort as u8, Ordering::Relaxed);
}

pub fn sort() -> Sort {
    match SORT.load(Ordering::Relaxed) {
        1 => Sort::Gpu,
        2 => Sort::Memory,
        _ => Sort::Cpu,
    }
}

/// PDH handles aren't tied to a thread, and only the sampling thread ever touches this
/// one, a call at a time.
struct Counters(Query);
unsafe impl Send for Counters {}
unsafe impl Sync for Counters {}

static COUNTERS: OnceLock<Option<Counters>> = OnceLock::new();
/// The counters are open and their first reading taken, so the sampling thread may use
/// them. Until then it keeps away: a PDH query is for one thread at a time.
static READY: AtomicBool = AtomicBool::new(false);

/// The counters of the whole page, opened once per run of Vantix. The first open reads
/// Windows' counter tables, a few hundred milliseconds and about 6 MB that stay with the
/// process until it exits, so keeping the query costs no memory on top and every later
/// visit to the page starts measuring at once.
fn counters() -> Option<&'static Query> {
    COUNTERS
        .get_or_init(|| {
            Query::open(&[
                r"\Processor Information(*)\% Processor Utility",
                r"\Processor Information(_Total)\% Processor Performance",
                r"\GPU Engine(*)\Utilization Percentage",
                r"\GPU Adapter Memory(*)\Dedicated Usage",
                r"\GPU Adapter Memory(*)\Shared Usage",
                r"\PhysicalDisk(*)\Disk Read Bytes/sec",
                r"\PhysicalDisk(*)\Disk Write Bytes/sec",
                r"\PhysicalDisk(*)\% Idle Time",
            ])
            .map(Counters)
        })
        .as_ref()
        .map(|counters| &counters.0)
}

/// Opens the counters away from the sampling thread, which meanwhile shows the parts
/// that cost nothing, and takes the first reading, the one every later value is a
/// difference from.
fn warm() {
    if READY.load(Ordering::Acquire) {
        return;
    }
    std::thread::spawn(|| {
        if let Some(query) = counters() {
            query.collect();
        }
        READY.store(true, Ordering::Release);
    });
}

/// Sleeps in short steps, so leaving the page stops the thread right away. `false` when
/// it has to stop.
fn nap(stop: &AtomicBool, time: Duration) -> bool {
    let until = Instant::now() + time;
    loop {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return true;
        }
        std::thread::sleep(left.min(Duration::from_millis(50)));
    }
}

fn run(stop: &AtomicBool) {
    warm();
    let adapters = adapters();
    let info = cpu_info();
    let (base_mhz, threads) = (info.base_mhz, info.threads.max(1));
    let mut history: [VecDeque<f64>; 4] = Default::default();
    let mut times: HashMap<u32, u64> = HashMap::new();
    let mut octets: Option<(u32, u64, u64)> = None;
    // Open already from an earlier visit: then the reading starts here, and its first
    // difference lands with the cheap sample. A visit that ended minutes ago left a
    // reading too old to subtract from.
    let mut query = READY.load(Ordering::Acquire).then(counters).flatten();
    if let Some(query) = query {
        query.collect();
    }
    let mut last = Instant::now();
    // The parts that cost nothing, the programs and the network, are on screen in a
    // quarter second.
    let mut wait = Duration::from_millis(250);
    while nap(stop, wait) {
        wait = Duration::from_secs(1);
        if query.is_none() && READY.load(Ordering::Acquire) {
            // The warm-up left the first reading behind, so this sample can already be
            // the difference from it.
            query = counters();
        }
        let elapsed = last.elapsed().as_secs_f64();
        last = Instant::now();
        let mut snapshot = Snapshot::default();
        let mut gpu_by_pid: HashMap<u32, f32> = HashMap::new();

        if let Some(query) = query.filter(|q| q.collect()) {
            snapshot.measured = true;
            // Instances are "group,number", plus totals per group and overall.
            let mut cores: Vec<((u32, u32), f32)> = query
                .read(0)
                .into_iter()
                .filter_map(|(name, value)| {
                    let (group, number) = name.split_once(',')?;
                    Some(((group.parse().ok()?, number.parse().ok()?), value.clamp(0.0, 100.0) as f32))
                })
                .collect();
            cores.sort_by_key(|c| c.0);
            snapshot.cores = cores.into_iter().map(|c| c.1).collect();
            snapshot.cpu = snapshot.cores.iter().sum::<f32>() / snapshot.cores.len().max(1) as f32;
            snapshot.mhz = query.read(1).first().map_or(0.0, |(_, percent)| percent * f64::from(base_mhz) / 100.0);

            // Task Manager's way: per card, the busiest kind of engine, summed over programs.
            let mut engines: HashMap<(usize, String), f64> = HashMap::new();
            let mut per_pid: HashMap<(u32, String), f64> = HashMap::new();
            for (name, value) in query.read(2) {
                let (Some(pid), Some(luid), Some(kind)) = (field(&name, "pid_"), luid(&name), name.rsplit_once("engtype_"))
                else {
                    continue;
                };
                let Some(card) = adapters.iter().position(|a| a.luid == luid) else { continue };
                *engines.entry((card, kind.1.to_string())).or_default() += value;
                if let Ok(pid) = pid.parse() {
                    *per_pid.entry((pid, kind.1.to_string())).or_default() += value;
                }
            }
            for ((pid, _), value) in per_pid {
                let entry = gpu_by_pid.entry(pid).or_default();
                *entry = entry.max(value.min(100.0) as f32);
            }
            let dedicated = query.read(3);
            let shared = query.read(4);
            snapshot.gpus = adapters
                .iter()
                .enumerate()
                .map(|(card, adapter)| {
                    let load = engines.iter().filter(|((c, _), _)| *c == card).map(|(_, v)| *v).fold(0.0, f64::max);
                    let usage = if adapter.integrated { &shared } else { &dedicated };
                    let used = usage.iter().filter(|(name, _)| luid(name) == Some(adapter.luid)).map(|(_, v)| *v).sum::<f64>();
                    // "Compute_0" and "Compute_1" are one kind of engine on the chart.
                    let per_engine = ENGINES.map(|kind| {
                        engines
                            .iter()
                            .filter(|((c, name), _)| *c == card && name.starts_with(kind))
                            .map(|(_, v)| *v)
                            .sum::<f64>()
                            .clamp(0.0, 100.0) as f32
                    });
                    Gpu {
                        load: load.min(100.0) as f32,
                        memory_used: used as u64,
                        memory_total: adapter.memory,
                        engines: per_engine,
                    }
                })
                .collect();

            let (reads, writes, idle) = (query.read(5), query.read(6), query.read(7));
            snapshot.disks = reads
                .iter()
                .filter(|(name, _)| name != "_Total")
                .map(|(name, read)| {
                    let value = |list: &[(String, f64)]| list.iter().find(|(n, _)| n == name).map_or(0.0, |(_, v)| *v);
                    Disk {
                        name: disk_name(name),
                        read: *read,
                        write: value(&writes),
                        active: (100.0 - value(&idle)).clamp(0.0, 100.0) as f32,
                    }
                })
                .collect();
            snapshot.disks.sort_by(|a, b| a.name.cmp(&b.name));
        }

        if let Some(connection) = net::connection() {
            let mut row = MIB_IF_ROW2 { InterfaceIndex: connection.index, ..Default::default() };
            if unsafe { GetIfEntry2(&mut row) }.is_ok() {
                if let Some((index, down, up)) = octets
                    && index == connection.index
                {
                    snapshot.net = [
                        row.InOctets.saturating_sub(down) as f64 / elapsed,
                        row.OutOctets.saturating_sub(up) as f64 / elapsed,
                    ];
                }
                octets = Some((connection.index, row.InOctets, row.OutOctets));
            }
        }

        snapshot.programs = programs(&mut times, &gpu_by_pid, elapsed, threads);

        let values = [
            f64::from(snapshot.cpu),
            snapshot.gpus.iter().map(|g| f64::from(g.load)).fold(0.0, f64::max),
            snapshot.disks.iter().map(|d| f64::from(d.active)).fold(0.0, f64::max),
            snapshot.net[0] + snapshot.net[1],
        ];
        // The first sample has no counters yet, and a zero there would draw a dip that
        // never happened. The network comes from somewhere else and is always good.
        for (i, (series, value)) in history.iter_mut().zip(values).enumerate() {
            if i < 3 && !snapshot.measured {
                continue;
            }
            if series.len() == HISTORY {
                series.pop_front();
            }
            series.push_back(value);
        }
        snapshot.history = history.clone();
        if !stop.load(Ordering::Relaxed) {
            *LATEST.lock().unwrap() = Some(snapshot);
        }
    }
}

/// "pid_1234_luid_..." gives "1234" for "pid_".
fn field<'a>(name: &'a str, key: &str) -> Option<&'a str> {
    let rest = &name[name.find(key)? + key.len()..];
    Some(rest.split('_').next().unwrap_or(rest))
}

/// The adapter part of a GPU counter instance, "luid_0x00000000_0x0000D1A5".
fn luid(name: &str) -> Option<(u32, u32)> {
    let rest = &name[name.find("luid_0x")? + 7..];
    let mut parts = rest.split('_');
    let high = u32::from_str_radix(parts.next()?, 16).ok()?;
    let low = u32::from_str_radix(parts.next()?.trim_start_matches("0x"), 16).ok()?;
    Some((high, low))
}

/// "0 C: D:" as "Disk 0 (C: D:)".
fn disk_name(instance: &str) -> String {
    match instance.split_once(' ') {
        Some((number, letters)) if !letters.trim().is_empty() => format!("{number} ({})", letters.trim()),
        Some((number, _)) => number.to_string(),
        None => instance.to_string(),
    }
}

// Processes, all of them in one call. The documented struct hides most fields behind
// reserved bytes, so this spells out the start of the real layout, which hasn't changed
// since Windows Vista.

#[repr(C)]
struct ProcessEntry {
    next: u32,
    threads: u32,
    private_working_set: i64,
    hard_faults: u32,
    threads_high_watermark: u32,
    cycle_time: u64,
    create_time: i64,
    user_time: i64,
    kernel_time: i64,
    name_length: u16,
    name_capacity: u16,
    name: *const u16,
    base_priority: i32,
    pid: usize,
    parent: usize,
}

/// One process, as the enumeration hands it over.
pub struct Raw {
    pub pid: u32,
    /// Whoever created it. The id can already belong to someone else, so it's only worth
    /// anything together with a name that's still there.
    parent: u32,
    pub name: String,
    /// User plus kernel time, in 100 ns units.
    pub cpu_time: u64,
    /// Private working set, what Task Manager calls Memory.
    pub memory: u64,
}

/// Every process but Vantix itself, in one call.
pub fn process_list() -> Vec<Raw> {
    const INFO_LENGTH_MISMATCH: i32 = 0xC000_0004_u32 as i32;
    let mut buffer: Vec<u64> = vec![0; 256 * 1024];
    loop {
        let mut needed = 0u32;
        let status = unsafe {
            NtQuerySystemInformation(
                SystemProcessInformation,
                buffer.as_mut_ptr().cast(),
                (buffer.len() * 8) as u32,
                &mut needed,
            )
        };
        if status.0 == INFO_LENGTH_MISMATCH {
            buffer = vec![0; needed as usize / 8 + 16 * 1024];
            continue;
        }
        if status.is_err() {
            return Vec::new();
        }
        break;
    }

    let own = unsafe { GetCurrentProcessId() };
    let mut list = Vec::new();
    let mut offset = 0usize;
    loop {
        let entry = unsafe { &*buffer.as_ptr().cast::<u8>().add(offset).cast::<ProcessEntry>() };
        let pid = entry.pid as u32;
        if pid != 0 && pid != own && !entry.name.is_null() {
            list.push(Raw {
                pid,
                parent: entry.parent as u32,
                name: unsafe {
                    String::from_utf16_lossy(std::slice::from_raw_parts(entry.name, usize::from(entry.name_length) / 2))
                },
                cpu_time: (entry.user_time + entry.kernel_time) as u64,
                memory: entry.private_working_set.max(0) as u64,
            });
        }
        if entry.next == 0 {
            break;
        }
        offset += entry.next as usize;
    }
    list
}

fn programs(times: &mut HashMap<u32, u64>, gpu: &HashMap<u32, f32>, elapsed: f64, threads: u32) -> Vec<Program> {
    let budget = elapsed * 10_000_000.0 * f64::from(threads);
    let mut seen: HashMap<u32, u64> = HashMap::new();
    let mut groups: HashMap<String, Program> = HashMap::new();
    for entry in process_list() {
        seen.insert(entry.pid, entry.cpu_time);
        let cpu =
            times.get(&entry.pid).map_or(0.0, |before| entry.cpu_time.saturating_sub(*before) as f64 / budget * 100.0);
        let program = groups
            .entry(entry.name.to_ascii_lowercase())
            .or_insert_with(|| Program { name: entry.name.clone(), ..Default::default() });
        program.pids.push(entry.pid);
        program.cpu += cpu as f32;
        program.gpu += gpu.get(&entry.pid).copied().unwrap_or(0.0);
        program.memory += entry.memory;
    }
    *times = seen;

    let mut list: Vec<Program> = groups.into_values().collect();
    let key = |p: &Program| match sort() {
        Sort::Cpu => (p.cpu as f64, p.memory as f64),
        Sort::Gpu => (p.gpu as f64, p.cpu as f64),
        Sort::Memory => (p.memory as f64, p.cpu as f64),
    };
    list.sort_by(|a, b| key(b).partial_cmp(&key(a)).unwrap_or(std::cmp::Ordering::Equal));
    list.truncate(ROWS);
    for program in &mut list {
        program.cpu = program.cpu.min(100.0);
        program.gpu = program.gpu.min(100.0);
        let first = program.pids[0];
        program.eco = with_process(first, PROCESS_QUERY_LIMITED_INFORMATION, governor::eco_set).flatten();
        program.can_end = endable(&program.name)
            && with_process(first, PROCESS_QUERY_LIMITED_INFORMATION, |handle| !critical(handle)).unwrap_or(false);
    }
    list
}

fn with_process<T>(pid: u32, access: PROCESS_ACCESS_RIGHTS, f: impl FnOnce(HANDLE) -> T) -> Option<T> {
    let handle = unsafe { OpenProcess(access, false, pid) }.ok()?;
    let result = f(handle);
    let _ = unsafe { CloseHandle(handle) };
    Some(result)
}

fn critical(handle: HANDLE) -> bool {
    let mut critical = BOOL(0);
    unsafe { IsProcessCritical(handle, &mut critical) }.is_err() || critical.as_bool()
}

/// Windows itself, which ending would log the user off or crash the PC, even where the
/// process isn't flagged critical.
fn endable(name: &str) -> bool {
    const CORE: [&str; 11] = [
        "system", "registry", "memory compression", "secure system", "smss.exe", "csrss.exe", "wininit.exe",
        "services.exe", "lsass.exe", "winlogon.exe", "svchost.exe",
    ];
    !CORE.contains(&name.to_ascii_lowercase().as_str())
}

/// The process ids still belong to `name`: an id freed since the last second can already
/// be another program.
fn each_of(name: &str, pids: &[u32], access: PROCESS_ACCESS_RIGHTS, mut f: impl FnMut(HANDLE) -> bool) -> usize {
    let mut done = 0;
    for &pid in pids {
        let ok = with_process(pid, access | PROCESS_QUERY_LIMITED_INFORMATION, |handle| {
            image_name(handle).is_some_and(|n| n.eq_ignore_ascii_case(name)) && f(handle)
        });
        done += usize::from(ok == Some(true));
    }
    done
}

fn image_name(handle: HANDLE) -> Option<String> {
    let mut path = [0u16; 1024];
    let mut len = path.len() as u32;
    unsafe { QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(path.as_mut_ptr()), &mut len) }.ok()?;
    let path = String::from_utf16_lossy(&path[..len as usize]);
    Some(path.rsplit('\\').next().unwrap_or(&path).to_string())
}

/// What came of pressing End, so the row can say it instead of looking like nothing
/// happened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndOutcome {
    /// Nothing by that name is left.
    Ended,
    /// Windows protects the process: antivirus and anti-cheat run this way, and so does
    /// anything whose end would take the PC down with it.
    Protected,
    /// A service owns it, so the service manager starts it again. Holds the display name
    /// of the first service and the names of every service in the process, which is what
    /// Stop service needs.
    Service { display: String, names: Vec<String> },
    /// Something started it again, by the name of the process that did.
    Reopened(String),
    /// Part of Windows, which Vantix never ends.
    Core,
    /// It's still there and none of the reasons above explain it.
    Failed,
}

/// Ends every process of `name` and says what happened. Takes about two seconds: it goes
/// back to see whether the program is really gone, which is the only honest answer.
pub fn end(name: &str) -> EndOutcome {
    if !endable(name) {
        return EndOutcome::Core;
    }
    let mut protected = false;
    // Three rounds, because a program being ended can start a child in between, and
    // because the sample the row came from is up to a second old.
    for round in 0..3 {
        let mut found = 0;
        for process in process_list().iter().filter(|p| p.name.eq_ignore_ascii_case(name)) {
            found += 1;
            protected |= kill(process.pid, name) == Kill::Protected;
        }
        if found == 0 {
            break;
        }
        if round < 2 {
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    // A service, or a program with a watchdog, is back on its feet by now.
    std::thread::sleep(Duration::from_millis(1500));
    let list = process_list();
    let left: Vec<&Raw> = list.iter().filter(|p| p.name.eq_ignore_ascii_case(name)).collect();
    if left.is_empty() {
        return EndOutcome::Ended;
    }
    if protected {
        return EndOutcome::Protected;
    }
    let owner = service_names().into_iter().find(|(pid, _)| left.iter().any(|p| p.pid == *pid));
    if let Some((_, services)) = owner {
        let display = services[0].1.clone();
        return EndOutcome::Service { display, names: services.into_iter().map(|(name, _)| name).collect() };
    }
    let parent = left.iter().find_map(|process| {
        list.iter().find(|other| other.pid == process.parent && !other.name.eq_ignore_ascii_case(name))
    });
    match parent {
        Some(parent) => EndOutcome::Reopened(parent.name.trim_end_matches(".exe").to_string()),
        None => EndOutcome::Failed,
    }
}

#[derive(PartialEq, Eq)]
enum Kill {
    Ended,
    Protected,
    Failed,
}

fn kill(pid: u32, name: &str) -> Kill {
    let access = PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION;
    let Some(handle) = unsafe { OpenProcess(access, false, pid) }.ok() else {
        // Being refused the handle at all is the wall a protected process puts up.
        return if protected(pid) { Kill::Protected } else { Kill::Failed };
    };
    let outcome = if !image_name(handle).is_some_and(|n| n.eq_ignore_ascii_case(name)) {
        // The id already belongs to another program, so this one is gone.
        Kill::Ended
    } else if critical(handle) {
        // Ending a critical process bug checks Windows on the spot.
        Kill::Protected
    } else if unsafe { TerminateProcess(handle, 1) }.is_ok() {
        Kill::Ended
    } else {
        Kill::Failed
    };
    let _ = unsafe { CloseHandle(handle) };
    if outcome == Kill::Failed && protected(pid) { Kill::Protected } else { outcome }
}

/// Protected processes, how Windows keeps antivirus and anti-cheat alive. A process
/// Vantix can't even open for a look counts as protected: it's the same wall.
fn protected(pid: u32) -> bool {
    let Some(handle) = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok() else {
        return true;
    };
    let mut level = PROCESS_PROTECTION_LEVEL_INFORMATION::default();
    let read = unsafe {
        GetProcessInformation(
            handle,
            ProcessProtectionLevelInfo,
            (&raw mut level).cast(),
            size_of::<PROCESS_PROTECTION_LEVEL_INFORMATION>() as u32,
        )
    }
    .is_ok();
    let _ = unsafe { CloseHandle(handle) };
    read && level.ProtectionLevel != PROTECTION_LEVEL_NONE
}

/// The services in each process that runs one, as (name, display name). Several can share
/// a process, and the first display name is as good as any for saying who owns it.
fn service_names() -> HashMap<u32, Vec<(String, String)>> {
    let mut map = HashMap::new();
    unsafe {
        let Ok(manager) = OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE) else { return map };
        let (mut needed, mut count, mut resume) = (0u32, 0u32, 0u32);
        let _ = EnumServicesStatusExW(
            manager,
            SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32,
            SERVICE_STATE_ALL,
            None,
            &mut needed,
            &mut count,
            Some(&mut resume),
            None,
        );
        // Aligned for the struct, which a Vec<u8> wouldn't be.
        let mut buffer: Vec<u64> = vec![0; needed as usize / 8 + 2];
        let bytes = std::slice::from_raw_parts_mut(buffer.as_mut_ptr().cast::<u8>(), buffer.len() * 8);
        if needed > 0
            && EnumServicesStatusExW(
                manager,
                SC_ENUM_PROCESS_INFO,
                SERVICE_WIN32,
                SERVICE_STATE_ALL,
                Some(bytes),
                &mut needed,
                &mut count,
                Some(&mut resume),
                None,
            )
            .is_ok()
        {
            let items = bytes.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>();
            for i in 0..count as usize {
                let item = &*items.add(i);
                let pid = item.ServiceStatusProcess.dwProcessId;
                // Windows leaves a name empty rather than pointing at an empty string.
                let text = |value: PWSTR| {
                    if value.is_null() { String::new() } else { value.to_string().unwrap_or_default() }
                };
                let name = text(item.lpServiceName);
                let display = match text(item.lpDisplayName) {
                    display if !display.is_empty() => display,
                    _ => name.clone(),
                };
                if pid != 0 && !name.is_empty() {
                    map.entry(pid).or_default().push((name, display));
                }
            }
        }
        let _ = CloseServiceHandle(manager);
    }
    map
}

pub fn set_eco(name: &str, pids: &[u32], on: bool) -> usize {
    each_of(name, pids, PROCESS_SET_INFORMATION, |handle| governor::eco(handle, on))
}

/// Moves the processes' pages out to the standby list. They come back from RAM, not the
/// disk, as soon as they're touched, so this only helps right before something needs
/// the memory, like starting a game.
pub fn trim(name: &str, pids: &[u32]) -> usize {
    each_of(name, pids, PROCESS_SET_QUOTA, |handle| unsafe { EmptyWorkingSet(handle) }.is_ok())
}

// Graphics cards, from the kernel graphics interface. DXGI would tell the same, but it
// loads the graphics driver into Vantix for good.

pub struct Adapter {
    luid: (u32, u32),
    pub name: String,
    /// What the driver's own page calls its version, like "32.0.15.7697". Empty when the
    /// display class key says nothing about this card.
    pub driver: String,
    /// The driver model Windows talks to it with, like "WDDM 3.1".
    pub wddm: String,
    /// Dedicated memory, or the shared memory it may use when it has none of its own.
    pub memory: u64,
    pub integrated: bool,
}

/// The graphics cards, read once: names, memory and driver don't change while Vantix runs.
pub fn adapters() -> &'static [Adapter] {
    static ADAPTERS: OnceLock<Vec<Adapter>> = OnceLock::new();
    ADAPTERS.get_or_init(enumerate_adapters)
}

fn enumerate_adapters() -> Vec<Adapter> {
    let drivers = driver_versions();
    unsafe {
        let mut enumerate = D3DKMT_ENUMADAPTERS2::default();
        if D3DKMTEnumAdapters2(&mut enumerate).is_err() || enumerate.NumAdapters == 0 {
            return Vec::new();
        }
        let mut list = vec![D3DKMT_ADAPTERINFO::default(); enumerate.NumAdapters as usize];
        enumerate.pAdapters = list.as_mut_ptr();
        if D3DKMTEnumAdapters2(&mut enumerate).is_err() {
            return Vec::new();
        }
        let mut adapters = Vec::new();
        for info in &list[..enumerate.NumAdapters as usize] {
            let mut kind = D3DKMT_ADAPTERTYPE::default();
            let mut registry = D3DKMT_ADAPTERREGISTRYINFO::default();
            let mut sizes = D3DKMT_SEGMENTSIZEINFO::default();
            // The driver model as a number, 3100 for WDDM 3.1.
            let mut model = 0i32;
            let ok = query(info.hAdapter, KMTQAITYPE_ADAPTERTYPE, &mut kind)
                && query(info.hAdapter, KMTQAITYPE_ADAPTERREGISTRYINFO, &mut registry)
                && query(info.hAdapter, KMTQAITYPE_GETSEGMENTSIZE, &mut sizes);
            let wddm = if query(info.hAdapter, KMTQAITYPE_DRIVERVERSION, &mut model) {
                format!("WDDM {}.{}", model / 1000, model % 1000 / 100)
            } else {
                String::new()
            };
            let _ = D3DKMTCloseAdapter(&D3DKMT_CLOSEADAPTER { hAdapter: info.hAdapter });
            // Bit 0 renders, bit 2 is a software device such as the Basic Render Driver.
            let flags = kind.Anonymous.Value;
            if !ok || flags & 1 == 0 || flags & 4 != 0 {
                continue;
            }
            let name = String::from_utf16_lossy(&registry.AdapterString);
            let name = name.trim_end_matches('\0').trim().to_string();
            let integrated = sizes.DedicatedVideoMemorySize < 1 << 30;
            adapters.push(Adapter {
                luid: (info.AdapterLuid.HighPart as u32, info.AdapterLuid.LowPart),
                driver: drivers
                    .iter()
                    .find(|(card, _)| card.eq_ignore_ascii_case(&name))
                    .map(|(_, version)| version.clone())
                    .unwrap_or_default(),
                wddm,
                name,
                memory: if integrated { sizes.SharedSystemMemorySize } else { sizes.DedicatedVideoMemorySize },
                integrated,
            });
        }
        // The card that does the work first.
        adapters.sort_by_key(|a| a.integrated);
        adapters
    }
}

/// Card name and driver version from the display class key, which is where Device
/// Manager reads them too. `D3DKMTQueryAdapterInfo` only tells the driver model.
fn driver_versions() -> Vec<(String, String)> {
    const CLASS: &str = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}";
    reg::subkeys(HKEY_LOCAL_MACHINE, CLASS)
        .into_iter()
        .filter_map(|key| {
            let path = format!(r"{CLASS}\{key}");
            let name = reg::get_string(HKEY_LOCAL_MACHINE, &path, "DriverDesc").ok()??;
            let version = reg::get_string(HKEY_LOCAL_MACHINE, &path, "DriverVersion").ok()??;
            Some((name, version))
        })
        .collect()
}

unsafe fn query<T>(adapter: u32, kind: windows::Wdk::Graphics::Direct3D::KMTQUERYADAPTERINFOTYPE, out: &mut T) -> bool {
    let mut query = D3DKMT_QUERYADAPTERINFO {
        hAdapter: adapter,
        Type: kind,
        pPrivateDriverData: (out as *mut T).cast(),
        PrivateDriverDataSize: size_of::<T>() as u32,
    };
    unsafe { D3DKMTQueryAdapterInfo(&mut query) }.is_ok()
}

// Performance counters by their English names, which work in every Windows language.
// A counter Windows doesn't have, like the GPU ones before Windows 10 1709, reads empty.

struct Query {
    query: PDH_HQUERY,
    counters: Vec<Option<PDH_HCOUNTER>>,
}

impl Query {
    fn open(paths: &[&str]) -> Option<Self> {
        let mut query = PDH_HQUERY::default();
        if unsafe { PdhOpenQueryW(None, 0, &mut query) } != 0 {
            return None;
        }
        let counters = paths
            .iter()
            .map(|path| {
                let mut counter = PDH_HCOUNTER::default();
                let status = unsafe { PdhAddEnglishCounterW(query, &HSTRING::from(*path), 0, &mut counter) };
                (status == 0).then_some(counter)
            })
            .collect();
        Some(Self { query, counters })
    }

    fn collect(&self) -> bool {
        unsafe { PdhCollectQueryData(self.query) == 0 }
    }

    /// Instance name and value of every instance of one counter. Values above 100 are
    /// kept: the processor utility goes past it while the CPU boosts.
    fn read(&self, i: usize) -> Vec<(String, f64)> {
        const NOCAP100: u32 = 0x8000;
        let Some(Some(counter)) = self.counters.get(i) else { return Vec::new() };
        let format = PDH_FMT(PDH_FMT_DOUBLE.0 | NOCAP100);
        let (mut size, mut count) = (0u32, 0u32);
        unsafe {
            if PdhGetFormattedCounterArrayW(*counter, format, &mut size, &mut count, None) != PDH_MORE_DATA {
                return Vec::new();
            }
            let mut buffer = vec![0u64; size as usize / 8 + 1];
            let items = buffer.as_mut_ptr().cast::<PDH_FMT_COUNTERVALUE_ITEM_W>();
            if PdhGetFormattedCounterArrayW(*counter, format, &mut size, &mut count, Some(items)) != 0 {
                return Vec::new();
            }
            (0..count as usize)
                .map(|i| &*items.add(i))
                // 0 is valid data, 1 valid and new.
                .filter(|item| item.FmtValue.CStatus <= 1)
                .map(|item| (item.szName.to_string().unwrap_or_default(), item.FmtValue.Anonymous.doubleValue))
                .collect()
        }
    }
}

impl Drop for Query {
    fn drop(&mut self) {
        unsafe { PdhCloseQuery(self.query) };
    }
}

// The CPU itself, read once.

pub fn cpu_info() -> &'static CpuInfo {
    static INFO: OnceLock<CpuInfo> = OnceLock::new();
    INFO.get_or_init(|| {
        let (cores, threads, performance, groups) = core_counts();
        let base_mhz = base_mhz(threads as usize);
        CpuInfo {
            name: brand(),
            cores,
            threads,
            performance,
            base_mhz,
            l3: l3_size(),
            features: features(),
            groups,
        }
    })
}

#[cfg(target_arch = "x86_64")]
fn brand() -> String {
    use std::arch::x86_64::__cpuid;
    let mut bytes = Vec::with_capacity(48);
    if __cpuid(0x8000_0000).eax >= 0x8000_0004 {
        for leaf in 0x8000_0002..=0x8000_0004u32 {
            let r = __cpuid(leaf);
            for word in [r.eax, r.ebx, r.ecx, r.edx] {
                bytes.extend(word.to_le_bytes());
            }
        }
    }
    String::from_utf8_lossy(&bytes).trim_matches(['\0', ' ']).split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(not(target_arch = "x86_64"))]
fn brand() -> String {
    String::new()
}

/// The instruction sets the card can show, in the order the UI explains them in.
pub const FEATURES: [&str; 8] = ["SSE4.2", "AVX", "AVX2", "FMA3", "AVX-512", "AES-NI", "SHA", "BMI2"];

/// Which of them the CPU and Windows both support, so programs can really use them.
fn features() -> Vec<usize> {
    #[cfg(not(target_arch = "x86_64"))]
    return Vec::new();
    #[cfg(target_arch = "x86_64")]
    {
        let has = [
            std::arch::is_x86_feature_detected!("sse4.2"),
            std::arch::is_x86_feature_detected!("avx"),
            std::arch::is_x86_feature_detected!("avx2"),
            std::arch::is_x86_feature_detected!("fma"),
            std::arch::is_x86_feature_detected!("avx512f"),
            std::arch::is_x86_feature_detected!("aes"),
            std::arch::is_x86_feature_detected!("sha"),
            std::arch::is_x86_feature_detected!("bmi2"),
        ];
        (0..FEATURES.len()).filter(|i| has[*i]).collect()
    }
}

/// Cores, threads, how many cores are of the faster kind on a hybrid CPU, and which
/// threads belong to each core. The counters name a thread "group,number", the same pair
/// the affinity masks give here, so sorting the pairs puts the thread list of every core
/// in the order the samples arrive in.
fn core_counts() -> (u32, u32, u32, Vec<Vec<usize>>) {
    let mut classes = Vec::new();
    let mut cores: Vec<Vec<(u16, u32)>> = Vec::new();
    for_each_relation(RelationProcessorCore, |info| {
        let core = unsafe { &info.Anonymous.Processor };
        classes.push(core.EfficiencyClass);
        let masks = unsafe { std::slice::from_raw_parts(core.GroupMask.as_ptr(), usize::from(core.GroupCount)) };
        let mut threads = Vec::new();
        for mask in masks {
            threads.extend((0..usize::BITS).filter(|bit| mask.Mask >> bit & 1 == 1).map(|bit| (mask.Group, bit)));
        }
        cores.push(threads);
    });
    let mut all: Vec<(u16, u32)> = cores.iter().flatten().copied().collect();
    all.sort_unstable();
    let mut groups: Vec<Vec<usize>> = cores
        .iter()
        .map(|threads| threads.iter().filter_map(|t| all.iter().position(|a| a == t)).collect())
        .collect();
    groups.sort_by_key(|threads| threads.first().copied().unwrap_or(usize::MAX));
    let top = classes.iter().copied().max().unwrap_or(0);
    let hybrid = classes.iter().any(|&c| c != top);
    let performance = if hybrid { classes.iter().filter(|&&c| c == top).count() as u32 } else { 0 };
    (classes.len() as u32, all.len() as u32, performance, groups)
}

fn l3_size() -> u64 {
    let mut total = 0u64;
    for_each_relation(RelationCache, |info| {
        let cache: &CACHE_RELATIONSHIP = unsafe { &info.Anonymous.Cache };
        if cache.Level == 3 {
            total += u64::from(cache.CacheSize);
        }
    });
    total
}

fn for_each_relation(
    relation: windows::Win32::System::SystemInformation::LOGICAL_PROCESSOR_RELATIONSHIP,
    mut f: impl FnMut(&SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX),
) {
    unsafe {
        let mut len = 0u32;
        let _ = GetLogicalProcessorInformationEx(relation, None, &mut len);
        let mut buffer = vec![0u64; len as usize / 8 + 1];
        if GetLogicalProcessorInformationEx(relation, Some(buffer.as_mut_ptr().cast()), &mut len).is_err() {
            return;
        }
        let bytes = buffer.as_ptr().cast::<u8>();
        let mut offset = 0usize;
        while offset < len as usize {
            let info = &*bytes.add(offset).cast::<SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>();
            if info.Size == 0 {
                break;
            }
            f(info);
            offset += info.Size as usize;
        }
    }
}

/// The rated clock, what "% Processor Performance" is a percentage of. The call wants
/// room for every processor.
fn base_mhz(threads: usize) -> u32 {
    let threads = threads.max(1);
    let mut info = vec![PROCESSOR_POWER_INFORMATION::default(); threads];
    let size = (threads * size_of::<PROCESSOR_POWER_INFORMATION>()) as u32;
    let status = unsafe { CallNtPowerInformation(ProcessorInformation, None, 0, Some(info.as_mut_ptr().cast()), size) };
    if status.is_err() {
        return 0;
    }
    info.iter().map(|p| p.MaxMhz).max().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Private memory of the sampler alone, without the UI:
    /// `cargo test monitor_memory -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn monitor_memory() {
        use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
        use windows::Win32::System::Threading::GetCurrentProcess;
        let private = || {
            let mut c = PROCESS_MEMORY_COUNTERS::default();
            unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut c, size_of::<PROCESS_MEMORY_COUNTERS>() as u32) }
                .unwrap();
            c.PagefileUsage >> 20
        };
        cpu_info();
        println!("before: {} MB", private());
        watch();
        std::thread::sleep(Duration::from_secs(8));
        println!("sampling: {} MB", private());
        unwatch();
        std::thread::sleep(Duration::from_secs(2));
        println!("after: {} MB", private());
    }

    /// How long the page takes to have something to show. The fixed facts come from
    /// `cpu_info` and `adapters`, the first sample from the thread:
    /// `cargo test monitor_open -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn monitor_open() {
        for round in 1..=2 {
            let start = Instant::now();
            cpu_info();
            adapters();
            let fixed = start.elapsed();
            watch();
            let mut first = None;
            while start.elapsed() < Duration::from_secs(8) {
                match snapshot() {
                    Some(s) if s.measured => break,
                    Some(_) if first.is_none() => first = Some(start.elapsed()),
                    _ => std::thread::sleep(Duration::from_millis(10)),
                }
            }
            let full = start.elapsed();
            println!("round {round}: facts {fixed:?}, first rows {first:?}, with counters {full:?}");
            assert!(fixed < Duration::from_millis(100), "fixed facts took {fixed:?}");
            assert!(full < Duration::from_millis(1500), "the first full sample took {full:?}");
            unwatch();
        }
    }

    /// End against processes made for it: three of the same program, one that Windows
    /// is never allowed to end, and one that something else keeps starting again.
    /// `cargo test end_says_what_happened -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn end_says_what_happened() {
        use std::process::{Command, Stdio};
        // A program that sits there for half a minute and does nothing else.
        let spawn = || {
            Command::new("ping")
                .args(["-n", "30", "127.0.0.1"])
                .stdout(Stdio::null())
                .spawn()
                .expect("ping didn't start")
        };

        let mut kids: Vec<_> = (0..3).map(|_| spawn()).collect();
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(end("ping.exe"), EndOutcome::Ended);
        for kid in &mut kids {
            let _ = kid.wait();
        }

        // Part of Windows: nothing is even tried.
        assert_eq!(end("svchost.exe"), EndOutcome::Core);

        // A loop that starts it again as soon as it's gone.
        let mut keeper = Command::new("cmd")
            .args(["/c", "for /l %i in () do @ping -n 30 127.0.0.1 >nul"])
            .spawn()
            .expect("cmd didn't start");
        std::thread::sleep(Duration::from_millis(600));
        match end("ping.exe") {
            EndOutcome::Reopened(by) => println!("reopened by {by}"),
            other => panic!("expected Reopened, got {other:?}"),
        }
        let _ = keeper.kill();
        let _ = keeper.wait();
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(end("ping.exe"), EndOutcome::Ended);

        // Defender's own process, if it's running: protected, and ending it does nothing.
        if process_list().iter().any(|p| p.name.eq_ignore_ascii_case("MsMpEng.exe")) {
            assert_eq!(end("MsMpEng.exe"), EndOutcome::Protected);
        }
        println!("services holding a process: {}", service_names().len());
    }

    /// `cargo test monitor_sample -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn monitor_sample() {
        let info = cpu_info();
        println!(
            "{} | {} cores {} threads {} P | base {} MHz | L3 {} MB | {:?}",
            info.name,
            info.cores,
            info.threads,
            info.performance,
            info.base_mhz,
            info.l3 >> 20,
            info.features.iter().map(|i| FEATURES[*i]).collect::<Vec<_>>()
        );
        println!("core groups {:?}", info.groups);
        for a in adapters() {
            println!(
                "gpu {} driver {} {} luid {:x?} memory {} MB integrated {}",
                a.name,
                a.driver,
                a.wddm,
                a.luid,
                a.memory >> 20,
                a.integrated
            );
        }
        let start = Instant::now();
        watch();
        while snapshot().is_none_or(|s| s.history[0].len() < 2) && start.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(100));
        }
        let s = snapshot().expect("no sample");
        unwatch();
        println!("cpu {:.1}% at {:.0} MHz, cores {:?}", s.cpu, s.mhz, s.cores.iter().map(|c| *c as u32).collect::<Vec<_>>());
        for (card, g) in adapters().iter().zip(&s.gpus) {
            println!(
                "{} {:.1}% {} / {} MB engines {:?}",
                card.name,
                g.load,
                g.memory_used >> 20,
                g.memory_total >> 20,
                ENGINES.iter().zip(g.engines).collect::<Vec<_>>()
            );
        }
        for d in &s.disks {
            println!("disk {} read {:.0} write {:.0} active {:.1}%", d.name, d.read, d.write, d.active);
        }
        println!("net down {:.0} up {:.0} B/s", s.net[0], s.net[1]);
        for p in &s.programs {
            println!(
                "{:<28} x{:<3} cpu {:>5.1}% gpu {:>5.1}% mem {:>6} MB eco {:?} end {}",
                p.name,
                p.pids.len(),
                p.cpu,
                p.gpu,
                p.memory >> 20,
                p.eco,
                p.can_end
            );
        }
    }
}
