//! What runs beside the UI while Vantix is open: ProBalance and the real-time game mode.
//! A thread wakes once a second, measures every process and steps in only while there's
//! a reason. Everything it changes is put back when the reason ends, when the feature is
//! turned off and when Vantix exits. What would outlive a crash (stopped services, Wi-Fi
//! scanning off) is also written to game.json and undone on the next start.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread::JoinHandle;
use std::time::Duration;

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};
use windows::Wdk::Graphics::Direct3D::{
    D3DKMT_SCHEDULINGPRIORITYCLASS_HIGH, D3DKMT_SCHEDULINGPRIORITYCLASS_NORMAL, D3DKMTSetProcessSchedulingPriorityClass,
};
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE, HWND, RECT};
use windows::Win32::Graphics::Gdi::{GetMonitorInfoW, MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromWindow};
use windows::Win32::NetworkManagement::WiFi::{
    WLAN_INTERFACE_INFO_LIST, WlanCloseHandle, WlanEnumInterfaces, WlanFreeMemory, WlanOpenHandle, WlanQueryInterface,
    WlanSetInterface,
    wlan_interface_state_connected, wlan_intf_opcode_background_scan_enabled,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT,
    SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STOP, SERVICE_STOP_PENDING, StartServiceW,
};
use windows::Win32::System::SystemInformation::{
    CACHE_RELATIONSHIP, GetLogicalProcessorInformationEx, GetSystemCpuSetInformation, RelationCache,
    SYSTEM_CPU_SET_INFORMATION, SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX,
};
use windows::Win32::System::Threading::{
    BELOW_NORMAL_PRIORITY_CLASS, GetExitCodeProcess, GetPriorityClass, GetProcessInformation, GetProcessTimes,
    GetSystemTimes,
    HIGH_PRIORITY_CLASS, NORMAL_PRIORITY_CLASS, OpenProcess, OpenThread, PROCESS_NAME_WIN32, PROCESS_POWER_THROTTLING_CURRENT_VERSION, PROCESS_POWER_THROTTLING_EXECUTION_SPEED,
    PROCESS_POWER_THROTTLING_STATE, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION,
    PROCESS_SET_LIMITED_INFORMATION, ProcessPowerThrottling, QueryFullProcessImageNameW, SetPriorityClass,
    SetProcessDefaultCpuSets, SetProcessInformation, SetThreadSelectedCpuSets, THREAD_SET_LIMITED_INFORMATION,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GWL_STYLE, GetClassNameW, GetForegroundWindow, GetWindowLongW, GetWindowRect, GetWindowThreadProcessId, WS_CAPTION,
};
use windows::core::{GUID, HSTRING, PWSTR};

use crate::memory;
use crate::reg::{self, HKEY_CURRENT_USER};
use crate::settings::{GameMode, data_dir};

/// What the UI turned on, copied in whenever it changes.
#[derive(Clone, Default)]
pub struct Config {
    pub probalance: bool,
    pub game: GameMode,
    /// Exe names the user marked as games, found in front even in a window.
    pub always: Vec<String>,
    /// Exe names the user marked as never a game.
    pub never: Vec<String>,
}

/// What the UI shows about the running features.
#[derive(Clone, Default)]
pub struct Status {
    /// Exe name of the game being boosted.
    pub game: Option<String>,
    /// Processes ProBalance holds back right now.
    pub restrained: usize,
    /// Background processes in efficiency mode for the game.
    pub efficient: usize,
    pub last: Option<LastGame>,
}

/// The latest game found, so the user can see what game mode did with it.
#[derive(Clone)]
pub struct LastGame {
    pub name: String,
    pub started: DateTime<Local>,
    /// `None` while it's still running.
    pub ended: Option<DateTime<Local>>,
    pub priority: bool,
    pub cores: bool,
    pub services: usize,
    pub wifi: bool,
    /// The most background programs in efficiency mode at once.
    pub efficient: usize,
}

/// What this machine has, read once: which features make sense here at all.
#[derive(Clone, Default)]
pub struct Capabilities {
    pub cores: Option<Cores>,
    pub wifi: bool,
    /// More than one real graphics card, as on laptops with integrated and dedicated GPUs.
    pub hybrid_gpu: bool,
}

#[derive(Clone)]
pub struct Cores {
    pub kind: CoreKind,
    /// CPU set ids of the logical processors the game goes to.
    ids: Vec<u32>,
    pub preferred: usize,
    pub total: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CoreKind {
    /// Intel hybrid: P-cores and E-cores.
    PerformanceCores,
    /// Ryzen X3D with two CCDs, one of them with the stacked cache.
    VCache,
}

struct Shared {
    config: Mutex<Config>,
    status: Mutex<Status>,
    stop: AtomicBool,
    thread: Mutex<Option<JoinHandle<()>>>,
    capabilities: Capabilities,
}

static SHARED: OnceLock<Shared> = OnceLock::new();

/// Starts the thread, after undoing whatever a crash left behind.
pub fn start(config: Config) {
    restore_leftovers();
    let shared = SHARED.get_or_init(|| Shared {
        config: Mutex::new(config),
        status: Mutex::new(Status::default()),
        stop: AtomicBool::new(false),
        thread: Mutex::new(None),
        capabilities: Capabilities { cores: preferred_cores(), wifi: has_wifi(), hybrid_gpu: hybrid_gpu() },
    });
    let mut thread = shared.thread.lock().unwrap();
    if thread.is_none() {
        *thread = Some(std::thread::spawn(run));
    }
}

pub fn configure(config: Config) {
    if let Some(shared) = SHARED.get() {
        *shared.config.lock().unwrap() = config;
    }
}

pub fn status() -> Status {
    SHARED.get().map(|shared| shared.status.lock().unwrap().clone()).unwrap_or_default()
}

pub fn capabilities() -> Capabilities {
    SHARED.get().map(|shared| shared.capabilities.clone()).unwrap_or_default()
}

/// Puts everything back and waits for the thread, so nothing is left changed at exit.
pub fn stop() {
    let Some(shared) = SHARED.get() else { return };
    shared.stop.store(true, Ordering::Relaxed);
    if let Some(thread) = shared.thread.lock().unwrap().take() {
        let _ = thread.join();
    }
}

// ProBalance: when the whole CPU is busy, a background process eating a big share of it
// drops to Below Normal until it calms down. The foreground app and the game never do.

const BUSY: f64 = 0.75;
const HOG: f64 = 0.08;
const CALM: f64 = 0.02;
/// Seconds a process has to stay over HOG, and then under CALM, before anything changes.
const HOT_TICKS: u32 = 2;
const CALM_TICKS: u32 = 3;

/// Never held back or put in efficiency mode: the shell, audio, input and peripheral
/// software, voice chat, recording, overlays and anti-cheats, which lag, crackle or flag
/// the game when slowed down.
const EXEMPT: &[&str] = &[
    "dwm.exe",
    "csrss.exe",
    "winlogon.exe",
    "explorer.exe",
    "sihost.exe",
    "ctfmon.exe",
    "audiodg.exe",
    "taskmgr.exe",
    "conhost.exe",
    "textinputhost.exe",
    "shellexperiencehost.exe",
    "startmenuexperiencehost.exe",
    "searchhost.exe",
    "gameinputsvc.exe",
    "gameinputredistservice.exe",
    "lghub.exe",
    "lghub_agent.exe",
    "lghub_system_tray.exe",
    "razercentralservice.exe",
    "razer synapse service.exe",
    "rzsdkservice.exe",
    "icue.exe",
    "steelseriesgg.exe",
    "steelseriesengine.exe",
    "discord.exe",
    "steam.exe",
    "steamwebhelper.exe",
    "ts3client_win64.exe",
    "teamspeak.exe",
    "mumble.exe",
    "spotify.exe",
    "obs64.exe",
    "obs32.exe",
    "streamlabs obs.exe",
    "nvcontainer.exe",
    "nvidia share.exe",
    "nvidia overlay.exe",
    "nvsphelper64.exe",
    "amdrsserv.exe",
    "radeonsoftware.exe",
    "rtss.exe",
    "msiafterburner.exe",
    "vgc.exe",
    "vgtray.exe",
    "easyanticheat.exe",
    "easyanticheat_eos.exe",
    "beservice.exe",
    "faceit.exe",
];

/// Programs that often run fullscreen without being games.
const NOT_GAMES: &[&str] = &[
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "opera_gx.exe",
    "vivaldi.exe",
    "vlc.exe",
    "mpc-hc64.exe",
    "mpc-be64.exe",
    "potplayermini64.exe",
    "wmplayer.exe",
    "microsoft.media.player.exe",
    "applicationframehost.exe",
    "mstsc.exe",
    "vmware.exe",
    "virtualboxvm.exe",
    "powerpnt.exe",
    "acrobat.exe",
    "steam.exe",
    "steamwebhelper.exe",
    "vantix.exe",
];

/// Seconds a fullscreen window has to stay in front before it counts as a game, so a
/// quick fullscreen flash doesn't start anything.
const GAME_TICKS: u32 = 3;
/// Standby is only purged when free memory is this low and standby holds at least this.
const STANDBY_FLOOR: u64 = 1 << 30;
const SERVICES: [&str; 2] = ["WSearch", "DoSvc"];

struct Process {
    handle: HANDLE,
    created: u64,
    cpu: u64,
    name: String,
    /// Lowercased full path, empty when it couldn't be read.
    path: String,
    /// The same path as Windows spells it, for the GPU choice.
    image: String,
    session: u32,
    hot: u32,
    calm: u32,
}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

struct Game {
    pid: u32,
    name: String,
    /// The game's own folder: helpers in it (anti-cheat, crash reporter, launcher UI) are
    /// part of the game and never slowed down.
    folder: String,
    raised: bool,
    cores: bool,
    services: Vec<String>,
    wifi: Vec<GUID>,
}

#[derive(Default)]
struct Governor {
    processes: HashMap<u32, Process>,
    system: (u64, u64),
    restrained: HashSet<u32>,
    efficient: HashSet<u32>,
    /// Processes that can't be opened, so they aren't tried again every second.
    blocked: HashSet<u32>,
    candidate: Option<(u32, u32)>,
    game: Option<Game>,
    last: Option<LastGame>,
    ticks: u64,
    me: u32,
    session: u32,
    windows: String,
}

fn run() {
    let shared = SHARED.get().unwrap();
    let mut governor = Governor {
        me: std::process::id(),
        session: session_of(std::process::id()),
        windows: format!(
            "{}\\",
            std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()).to_lowercase()
        ),
        ..Default::default()
    };
    while !shared.stop.load(Ordering::Relaxed) {
        let config = shared.config.lock().unwrap().clone();
        governor.tick(&config, &shared.capabilities);
        *shared.status.lock().unwrap() = Status {
            game: governor.game.as_ref().map(|game| game.name.clone()),
            restrained: governor.restrained.len(),
            efficient: governor.efficient.len(),
            last: governor.last.clone(),
        };
        std::thread::sleep(Duration::from_secs(1));
    }
    governor.release_all();
    governor.end_game();
}

impl Governor {
    fn tick(&mut self, config: &Config, capabilities: &Capabilities) {
        // Both off is the default: nothing is measured and no process is kept open.
        if !config.probalance && !config.game.enabled {
            self.release_all();
            self.end_game();
            self.processes.clear();
            self.blocked.clear();
            self.system = (0, 0);
            return;
        }
        self.ticks += 1;
        let busy = self.sample();
        let foreground = foreground_pid();

        if config.probalance {
            self.balance(busy, foreground);
        } else {
            self.release_all();
        }

        if !config.game.enabled {
            self.end_game();
            return;
        }
        // Gone, or just marked as not a game.
        if let Some(game) = &self.game
            && (!alive(self.processes.get(&game.pid).map(|p| p.handle)) || listed(&config.never, &game.name))
        {
            self.end_game();
        }
        if self.game.is_none() {
            self.detect_game(foreground, config, capabilities);
        }
        if self.game.is_some() {
            self.during_game(foreground, config.game);
        }
    }

    /// Refreshes every process's CPU time and returns how busy the whole CPU was since
    /// the last tick, from 0 to 1.
    fn sample(&mut self) -> f64 {
        let mut seen = HashSet::new();
        let mut running = HashSet::new();
        memory::for_each_process(|entry| {
            let pid = entry.th32ProcessID;
            running.insert(pid);
            // Services and other sessions are never acted on, so they aren't tracked.
            if pid == 0 || pid == 4 || self.blocked.contains(&pid) || session_of(pid) != self.session {
                return;
            }
            seen.insert(pid);
            let fresh = match self.processes.get(&pid) {
                Some(process) => times(process.handle).is_none_or(|(created, _)| created != process.created),
                None => true,
            };
            if fresh {
                match open(pid, memory::exe_name(entry)) {
                    Some(process) => {
                        self.processes.insert(pid, process);
                    }
                    None => {
                        self.blocked.insert(pid);
                    }
                }
            }
        });
        self.blocked.retain(|pid| running.contains(pid));
        self.processes.retain(|pid, _| seen.contains(pid));
        self.restrained.retain(|pid| seen.contains(pid));
        self.efficient.retain(|pid| seen.contains(pid));

        let (idle, total) = system_times();
        let (last_idle, last_total) = std::mem::replace(&mut self.system, (idle, total));
        let elapsed = total.saturating_sub(last_total);
        if elapsed == 0 || last_total == 0 {
            for process in self.processes.values_mut() {
                process.cpu = times(process.handle).map_or(0, |(_, cpu)| cpu);
            }
            return 0.0;
        }
        for process in self.processes.values_mut() {
            let cpu = times(process.handle).map_or(process.cpu, |(_, cpu)| cpu);
            let share = cpu.saturating_sub(process.cpu) as f64 / elapsed as f64;
            process.cpu = cpu;
            process.hot = if share >= HOG { process.hot + 1 } else { 0 };
            process.calm = if share < CALM { process.calm + 1 } else { 0 };
        }
        1.0 - idle.saturating_sub(last_idle) as f64 / elapsed as f64
    }

    fn exempt(&self, pid: u32, process: &Process) -> bool {
        pid == self.me
            || process.session != self.session
            || listed(EXEMPT, &process.name)
            || self.game.as_ref().is_some_and(|game| {
                game.pid == pid || !game.folder.is_empty() && process.path.starts_with(&game.folder)
            })
    }

    fn balance(&mut self, busy: f64, foreground: u32) {
        let mut restrain = Vec::new();
        let mut release = Vec::new();
        for (&pid, process) in &self.processes {
            if self.restrained.contains(&pid) {
                if process.calm >= CALM_TICKS || pid == foreground || self.exempt(pid, process) {
                    release.push(pid);
                }
            } else if busy >= BUSY
                && process.hot >= HOT_TICKS
                && pid != foreground
                && !self.exempt(pid, process)
                && unsafe { GetPriorityClass(process.handle) } == NORMAL_PRIORITY_CLASS.0
            {
                restrain.push(pid);
            }
        }
        for pid in release {
            self.release(pid);
        }
        for pid in restrain {
            let handle = self.processes[&pid].handle;
            if unsafe { SetPriorityClass(handle, BELOW_NORMAL_PRIORITY_CLASS) }.is_ok() {
                self.restrained.insert(pid);
            }
        }
    }

    /// Back to Normal, unless something else changed the priority in the meantime.
    fn release(&mut self, pid: u32) {
        self.restrained.remove(&pid);
        if let Some(process) = self.processes.get(&pid) {
            unsafe {
                if GetPriorityClass(process.handle) == BELOW_NORMAL_PRIORITY_CLASS.0 {
                    let _ = SetPriorityClass(process.handle, NORMAL_PRIORITY_CLASS);
                }
            }
        }
    }

    fn release_all(&mut self) {
        for pid in self.restrained.clone() {
            self.release(pid);
        }
    }

    /// A game is a window that covers its whole monitor and stays in front, from a
    /// program outside the Windows folder that isn't a browser or player. The user's own
    /// lists come first: a game marked by hand counts in a window too.
    fn detect_game(&mut self, foreground: u32, config: &Config, capabilities: &Capabilities) {
        let fullscreen = foreground != 0 && fullscreen_foreground();
        let candidate = self
            .processes
            .get(&foreground)
            .filter(|process| {
                process.session == self.session
                    && !listed(&config.never, &process.name)
                    && (listed(&config.always, &process.name)
                        || fullscreen
                            && !process.path.is_empty()
                            && !process.path.starts_with(&self.windows)
                            && !listed(NOT_GAMES, &process.name))
            })
            .map(|process| (process.handle, process.name.clone(), process.image.clone()));
        let Some((handle, name, image)) = candidate else {
            self.candidate = None;
            return;
        };
        let ticks = match self.candidate {
            Some((pid, ticks)) if pid == foreground => ticks + 1,
            _ => 1,
        };
        self.candidate = Some((foreground, ticks));
        if ticks < GAME_TICKS {
            return;
        }
        self.candidate = None;
        self.begin_game(foreground, handle, name, image, config.game, capabilities);
    }

    fn begin_game(
        &mut self,
        pid: u32,
        handle: HANDLE,
        name: String,
        image: String,
        config: GameMode,
        capabilities: &Capabilities,
    ) {
        let path = image.to_lowercase();
        // At least two levels deep, like D:\Games\Name\, or a library root would cover
        // every other program in it.
        let folder = path
            .rsplit_once('\\')
            .map(|(folder, _)| format!("{folder}\\"))
            .filter(|folder| folder.matches('\\').count() >= 3)
            .unwrap_or_default();
        let mut game = Game {
            pid,
            name,
            folder,
            raised: false,
            cores: false,
            services: Vec::new(),
            wifi: Vec::new(),
        };
        if config.priority {
            unsafe {
                if GetPriorityClass(handle) == NORMAL_PRIORITY_CLASS.0 {
                    game.raised = SetPriorityClass(handle, HIGH_PRIORITY_CLASS).is_ok();
                }
                let _ = D3DKMTSetProcessSchedulingPriorityClass(handle, D3DKMT_SCHEDULINGPRIORITYCLASS_HIGH);
            }
        }
        if config.cores
            && let Some(cores) = &capabilities.cores
        {
            game.cores = pin(pid, handle, Some(&cores.ids));
        }
        // Written down before each change, so a crash in the middle still leaves the way
        // back; without a record that can be saved, the change isn't made at all.
        if config.services {
            let running: Vec<String> =
                SERVICES.iter().filter(|name| with_service(name, service_running)).map(|name| name.to_string()).collect();
            if !running.is_empty() && update_leftovers(|l| add_missing(&mut l.services, &running)) {
                game.services = running.iter().filter(|name| stop_service(name)).cloned().collect();
                let kept: Vec<&String> = running.iter().filter(|name| !game.services.contains(name)).collect();
                if !kept.is_empty() {
                    update_leftovers(|l| l.services.retain(|name| !kept.contains(&name)));
                }
            }
        }
        if config.wifi {
            let scanning = wifi_scanning();
            if !scanning.is_empty() && update_leftovers(|l| add_missing(&mut l.wifi, &scanning)) {
                game.wifi = set_wifi_scan(&scanning, false);
                let kept: Vec<&GUID> = scanning.iter().filter(|guid| !game.wifi.contains(guid)).collect();
                if !kept.is_empty() {
                    update_leftovers(|l| l.wifi.retain(|guid| !kept.contains(&guid)));
                }
            }
        }
        if config.gpu && capabilities.hybrid_gpu {
            prefer_dedicated_gpu(&image);
        }
        self.last = Some(LastGame {
            name: game.name.clone(),
            started: Local::now(),
            ended: None,
            priority: config.priority,
            cores: game.cores,
            services: game.services.len(),
            wifi: !game.wifi.is_empty(),
            efficient: 0,
        });
        self.game = Some(game);
    }

    fn during_game(&mut self, foreground: u32, config: GameMode) {
        if config.eco {
            // Whatever comes to the front runs at full speed, with all its processes: a
            // browser alt-tabbed to has its tabs in processes of their own.
            let front = self.processes.get(&foreground).map(|p| p.path.clone()).filter(|path| !path.is_empty());
            let in_front = |process: &Process| front.as_deref() == Some(process.path.as_str());
            for pid in self.efficient.clone() {
                if let Some(process) = self.processes.get(&pid)
                    && in_front(process)
                {
                    eco(process.handle, false);
                    self.efficient.remove(&pid);
                }
            }
            let targets: Vec<u32> = self
                .processes
                .iter()
                .filter(|&(&pid, process)| {
                    !in_front(process)
                        && !self.efficient.contains(&pid)
                        && !self.exempt(pid, process)
                        && !process.path.is_empty()
                        && !process.path.starts_with(&self.windows)
                })
                .map(|(&pid, _)| pid)
                .collect();
            for pid in targets {
                // Browsers and others put their own idle processes in efficiency mode; those
                // are left as they are, so ending the game doesn't undo their choice.
                let handle = self.processes[&pid].handle;
                if !eco_set(handle).unwrap_or(true) && eco(handle, true) {
                    self.efficient.insert(pid);
                }
            }
        } else {
            self.end_eco();
        }
        if let Some(last) = &mut self.last {
            last.efficient = last.efficient.max(self.efficient.len());
        }

        if config.standby && self.ticks.is_multiple_of(5) {
            let stats = memory::stats();
            if stats.free < STANDBY_FLOOR && stats.standby >= STANDBY_FLOOR {
                memory::purge_standby();
            }
        }
    }

    fn end_eco(&mut self) {
        for pid in std::mem::take(&mut self.efficient) {
            if let Some(process) = self.processes.get(&pid) {
                eco(process.handle, false);
            }
        }
    }

    fn end_game(&mut self) {
        self.end_eco();
        let Some(game) = self.game.take() else { return };
        if let Some(last) = &mut self.last {
            last.ended = Some(Local::now());
        }
        if let Some(process) = self.processes.get(&game.pid)
            && alive(Some(process.handle))
        {
            unsafe {
                if game.raised && GetPriorityClass(process.handle) == HIGH_PRIORITY_CLASS.0 {
                    let _ = SetPriorityClass(process.handle, NORMAL_PRIORITY_CLASS);
                }
                let _ = D3DKMTSetProcessSchedulingPriorityClass(process.handle, D3DKMT_SCHEDULINGPRIORITYCLASS_NORMAL);
            }
            if game.cores {
                pin(game.pid, process.handle, None);
            }
        }
        put_back(&game.services, &game.wifi);
    }
}

fn listed(list: &[impl AsRef<str>], name: &str) -> bool {
    list.iter().any(|entry| entry.as_ref().eq_ignore_ascii_case(name))
}

fn open(pid: u32, name: String) -> Option<Process> {
    unsafe {
        let access = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION | PROCESS_SET_LIMITED_INFORMATION;
        let handle = OpenProcess(access, false, pid).or_else(|_| OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)).ok()?;
        let Some((created, cpu)) = times(handle) else {
            let _ = CloseHandle(handle);
            return None;
        };
        let mut path = [0u16; 1024];
        let mut len = path.len() as u32;
        let image = match QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(path.as_mut_ptr()), &mut len) {
            Ok(()) => String::from_utf16_lossy(&path[..len as usize]),
            Err(_) => String::new(),
        };
        let path = image.to_lowercase();
        Some(Process { handle, created, cpu, name, path, image, session: session_of(pid), hot: 0, calm: 0 })
    }
}

fn filetime(time: FILETIME) -> u64 {
    u64::from(time.dwHighDateTime) << 32 | u64::from(time.dwLowDateTime)
}

/// Creation time and kernel plus user time, in 100 ns units.
fn times(handle: HANDLE) -> Option<(u64, u64)> {
    let (mut created, mut exited, mut kernel, mut user) = Default::default();
    unsafe { GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) }.ok()?;
    Some((filetime(created), filetime(kernel) + filetime(user)))
}

/// Idle and total time of all cores, in 100 ns units. Kernel time includes idle time.
fn system_times() -> (u64, u64) {
    let (mut idle, mut kernel, mut user) = Default::default();
    match unsafe { GetSystemTimes(Some(&mut idle), Some(&mut kernel), Some(&mut user)) } {
        Ok(()) => (filetime(idle), filetime(kernel) + filetime(user)),
        Err(_) => (0, 0),
    }
}

fn alive(handle: Option<HANDLE>) -> bool {
    const STILL_ACTIVE: u32 = 259;
    let mut code = 0;
    handle.is_some_and(|handle| unsafe { GetExitCodeProcess(handle, &mut code) }.is_ok() && code == STILL_ACTIVE)
}

fn session_of(pid: u32) -> u32 {
    let mut session = u32::MAX;
    let _ = unsafe { ProcessIdToSessionId(pid, &mut session) };
    session
}

fn foreground_pid() -> u32 {
    let mut pid = 0;
    unsafe {
        let window = GetForegroundWindow();
        if !window.is_invalid() {
            GetWindowThreadProcessId(window, Some(&mut pid));
        }
    }
    pid
}

/// The foreground window covers its whole monitor without a title bar and isn't the
/// desktop itself. The title bar check keeps out maximized windows, which also cover the
/// monitor when the taskbar hides itself.
fn fullscreen_foreground() -> bool {
    unsafe {
        let window: HWND = GetForegroundWindow();
        if GetWindowLongW(window, GWL_STYLE) as u32 & WS_CAPTION.0 == WS_CAPTION.0 {
            return false;
        }
        let mut class = [0u16; 64];
        let len = GetClassNameW(window, &mut class).max(0) as usize;
        let class = String::from_utf16_lossy(&class[..len]);
        if matches!(class.as_str(), "Progman" | "WorkerW" | "Shell_TrayWnd") {
            return false;
        }
        let mut rect = RECT::default();
        let mut monitor = MONITORINFO { cbSize: size_of::<MONITORINFO>() as u32, ..Default::default() };
        GetWindowRect(window, &mut rect).is_ok()
            && GetMonitorInfoW(MonitorFromWindow(window, MONITOR_DEFAULTTONEAREST), &mut monitor).as_bool()
            && rect.left <= monitor.rcMonitor.left
            && rect.top <= monitor.rcMonitor.top
            && rect.right >= monitor.rcMonitor.right
            && rect.bottom >= monitor.rcMonitor.bottom
    }
}

/// Whether the process already chose efficiency mode itself; `None` when it can't be read.
pub fn eco_set(handle: HANDLE) -> Option<bool> {
    let mut state =
        PROCESS_POWER_THROTTLING_STATE { Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION, ..Default::default() };
    unsafe {
        GetProcessInformation(
            handle,
            ProcessPowerThrottling,
            (&raw mut state).cast(),
            size_of::<PROCESS_POWER_THROTTLING_STATE>() as u32,
        )
    }
    .ok()?;
    Some(state.ControlMask & PROCESS_POWER_THROTTLING_EXECUTION_SPEED != 0)
}

/// EcoQoS on, or back to letting Windows decide.
pub fn eco(handle: HANDLE, on: bool) -> bool {
    let state = PROCESS_POWER_THROTTLING_STATE {
        Version: PROCESS_POWER_THROTTLING_CURRENT_VERSION,
        ControlMask: if on { PROCESS_POWER_THROTTLING_EXECUTION_SPEED } else { 0 },
        StateMask: if on { PROCESS_POWER_THROTTLING_EXECUTION_SPEED } else { 0 },
    };
    unsafe {
        SetProcessInformation(
            handle,
            ProcessPowerThrottling,
            (&raw const state).cast(),
            size_of::<PROCESS_POWER_THROTTLING_STATE>() as u32,
        )
    }
    .is_ok()
}

/// Steers the process to the given CPU sets, or frees it with `None`. CPU sets are soft:
/// Windows still uses the other cores when these are full. The default only covers new
/// threads, so the running ones are moved one by one.
fn pin(pid: u32, process: HANDLE, ids: Option<&[u32]>) -> bool {
    let ok = unsafe { SetProcessDefaultCpuSets(process, ids) }.as_bool();
    unsafe {
        let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) else { return ok };
        let mut entry = THREADENTRY32 { dwSize: size_of::<THREADENTRY32>() as u32, ..Default::default() };
        let mut more = Thread32First(snapshot, &mut entry).is_ok();
        while more {
            if entry.th32OwnerProcessID == pid
                && let Ok(thread) = OpenThread(THREAD_SET_LIMITED_INFORMATION, false, entry.th32ThreadID)
            {
                let _ = SetThreadSelectedCpuSets(thread, ids.unwrap_or(&[]));
                let _ = CloseHandle(thread);
            }
            more = Thread32Next(snapshot, &mut entry).is_ok();
        }
        let _ = CloseHandle(snapshot);
    }
    ok
}

/// The cores a game should run on, when the CPU has cores that are better than others.
fn preferred_cores() -> Option<Cores> {
    // Logical processor index, CPU set id and efficiency class, for group 0.
    let sets: Vec<(u8, u32, u8)> = cpu_sets();
    let total = sets.len();
    let best = sets.iter().map(|s| s.2).max()?;
    if sets.iter().any(|s| s.2 != best) {
        let ids: Vec<u32> = sets.iter().filter(|s| s.2 == best).map(|s| s.1).collect();
        return Some(Cores { kind: CoreKind::PerformanceCores, preferred: ids.len(), ids, total });
    }
    let caches = l3_caches();
    let biggest = caches.iter().max_by_key(|c| c.0)?;
    if caches.len() < 2 || caches.iter().all(|c| c.0 == biggest.0) {
        return None;
    }
    let ids: Vec<u32> = sets.iter().filter(|s| biggest.1 & (1usize << s.0) != 0).map(|s| s.1).collect();
    (!ids.is_empty()).then_some(Cores { kind: CoreKind::VCache, preferred: ids.len(), ids, total })
}

fn cpu_sets() -> Vec<(u8, u32, u8)> {
    unsafe {
        let mut len = 0u32;
        let _ = GetSystemCpuSetInformation(None, 0, &mut len, None, None);
        let mut buffer = vec![0u8; len as usize];
        if !GetSystemCpuSetInformation(Some(buffer.as_mut_ptr().cast()), len, &mut len, None, None).as_bool() {
            return Vec::new();
        }
        let mut sets = Vec::new();
        let mut offset = 0usize;
        while offset + size_of::<u32>() * 2 <= len as usize {
            let info = &*(buffer.as_ptr().add(offset) as *const SYSTEM_CPU_SET_INFORMATION);
            if info.Size == 0 {
                break;
            }
            let set = info.Anonymous.CpuSet;
            if set.Group == 0 {
                sets.push((set.LogicalProcessorIndex, set.Id, set.EfficiencyClass));
            }
            offset += info.Size as usize;
        }
        sets
    }
}

/// Size and group 0 processor mask of every L3 cache.
fn l3_caches() -> Vec<(u32, usize)> {
    unsafe {
        let mut len = 0u32;
        let _ = GetLogicalProcessorInformationEx(RelationCache, None, &mut len);
        let mut buffer = vec![0u8; len as usize];
        if GetLogicalProcessorInformationEx(RelationCache, Some(buffer.as_mut_ptr().cast()), &mut len).is_err() {
            return Vec::new();
        }
        let mut caches = Vec::new();
        let mut offset = 0usize;
        while offset < len as usize {
            let info = &*(buffer.as_ptr().add(offset) as *const SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX);
            if info.Size == 0 {
                break;
            }
            let cache: &CACHE_RELATIONSHIP = &info.Anonymous.Cache;
            let mask = cache.Anonymous.GroupMask;
            if cache.Level == 3 && mask.Group == 0 {
                caches.push((cache.CacheSize, mask.Mask));
            }
            offset += info.Size as usize;
        }
        caches
    }
}

/// Two graphics cards plugged in, from the device list. Asking DXGI instead would load
/// the graphics driver into Vantix for good.
fn hybrid_gpu() -> bool {
    crate::boost::graphics_cards() >= 2
}

const GPU_KEY: &str = r"Software\Microsoft\DirectX\UserGpuPreferences";
const GPU_DEDICATED: &str = "GpuPreference=2;";

/// Takes effect the next time the game starts. A choice the user already made in
/// Settings stays as it is.
fn prefer_dedicated_gpu(path: &str) {
    // An entry for a value that never got written is harmless: forgetting only removes
    // values that still say what Vantix wrote.
    if reg::get_string(HKEY_CURRENT_USER, GPU_KEY, path).is_ok_and(|value| value.is_none())
        && update_leftovers(|l| add_missing(&mut l.gpu, &[path.to_string()]))
    {
        let _ = reg::set_string(HKEY_CURRENT_USER, GPU_KEY, path, GPU_DEDICATED);
    }
}

/// Removes the GPU choices Vantix made, when the option is turned off.
pub fn forget_gpu_choices() {
    update_leftovers(|l| {
        for path in std::mem::take(&mut l.gpu) {
            if reg::get_string(HKEY_CURRENT_USER, GPU_KEY, &path).ok().flatten().as_deref() == Some(GPU_DEDICATED) {
                let _ = reg::delete_value(HKEY_CURRENT_USER, GPU_KEY, &path);
            }
        }
    });
}

fn service_running(service: windows::Win32::System::Services::SC_HANDLE) -> bool {
    let mut status = SERVICE_STATUS::default();
    unsafe { QueryServiceStatus(service, &mut status) }.is_ok() && status.dwCurrentState == SERVICE_RUNNING
}

/// Stops a running service. Returns whether it was running and stopped.
fn stop_service(name: &str) -> bool {
    with_service(name, |service| {
        let mut status = SERVICE_STATUS::default();
        service_running(service) && unsafe { ControlService(service, SERVICE_CONTROL_STOP, &mut status) }.is_ok()
    })
}

/// Starts a service again, waiting first if it's still stopping, which refuses a start.
/// Returns whether it's running or starting.
fn start_service(name: &str) -> bool {
    with_service(name, |service| {
        for _ in 0..60 {
            let mut status = SERVICE_STATUS::default();
            if unsafe { QueryServiceStatus(service, &mut status) }.is_err() {
                return false;
            }
            match status.dwCurrentState {
                SERVICE_RUNNING | SERVICE_START_PENDING => return true,
                SERVICE_STOP_PENDING => std::thread::sleep(Duration::from_millis(250)),
                _ => return unsafe { StartServiceW(service, None) }.is_ok(),
            }
        }
        false
    })
}

fn with_service(name: &str, f: impl FnOnce(windows::Win32::System::Services::SC_HANDLE) -> bool) -> bool {
    unsafe {
        let Ok(manager) = OpenSCManagerW(None, None, SC_MANAGER_CONNECT) else { return false };
        let result = match OpenServiceW(manager, &HSTRING::from(name), SERVICE_QUERY_STATUS | SERVICE_STOP | SERVICE_START) {
            Ok(service) => {
                let result = f(service);
                let _ = CloseServiceHandle(service);
                result
            }
            Err(_) => false,
        };
        let _ = CloseServiceHandle(manager);
        result
    }
}

fn has_wifi() -> bool {
    with_wlan(|_, interfaces| !interfaces.is_empty()).unwrap_or(false)
}

fn has_wlan() -> bool {
    with_wlan(|_, _| ()).is_some()
}

/// Connected interfaces that scan in the background now. Windows scans every minute or so
/// even while connected, which shows up as a ping spike. One already off, by the user, a
/// vendor tool or a policy, is left out, so the game mode never turns it on afterwards.
fn wifi_scanning() -> Vec<GUID> {
    with_wlan(|handle, interfaces| {
        interfaces
            .iter()
            .filter(|(guid, connected)| *connected && wifi_scan_on(handle, guid) == Some(true))
            .map(|(guid, _)| *guid)
            .collect()
    })
    .unwrap_or_default()
}

fn wifi_scan_on(handle: HANDLE, guid: &GUID) -> Option<bool> {
    unsafe {
        let (mut size, mut data) = (0u32, std::ptr::null_mut());
        if WlanQueryInterface(handle, guid, wlan_intf_opcode_background_scan_enabled, None, &mut size, &mut data, None)
            != 0
            || data.is_null()
        {
            return None;
        }
        let on = (size >= 4).then(|| *data.cast::<u32>() != 0);
        WlanFreeMemory(data);
        on
    }
}

/// Turns background scanning on or off for `guids` and returns the ones it changed.
fn set_wifi_scan(guids: &[GUID], on: bool) -> Vec<GUID> {
    with_wlan(|handle, _| {
        let value: u32 = on.into();
        guids
            .iter()
            .filter(|guid| unsafe {
                WlanSetInterface(handle, *guid, wlan_intf_opcode_background_scan_enabled, 4, (&raw const value).cast(), None)
                    == 0
            })
            .copied()
            .collect()
    })
    .unwrap_or_default()
}

/// Starts the services and turns scanning back on, then crosses off what went back. What
/// didn't stays listed and is tried again when Vantix next starts. An interface that's
/// gone is crossed off too: Windows doesn't keep the setting once the adapter goes away.
fn put_back(services: &[String], wifi: &[GUID]) {
    let started: Vec<&String> = services.iter().filter(|name| start_service(name)).collect();
    let present: Vec<GUID> = with_wlan(|_, interfaces| interfaces.iter().map(|(guid, _)| *guid).collect()).unwrap_or_default();
    let waiting: Vec<GUID> = wifi.iter().filter(|guid| present.contains(guid)).copied().collect();
    let back = set_wifi_scan(&waiting, true);
    // Without the WLAN service there's no telling, so everything stays listed.
    let wlan_up = has_wlan();
    update_leftovers(|l| {
        l.services.retain(|name| !started.contains(&name));
        l.wifi.retain(|guid| !wifi.contains(guid) || (!back.contains(guid) && (!wlan_up || present.contains(guid))));
    });
}

/// Every WLAN interface and whether it's connected.
fn with_wlan<T>(f: impl FnOnce(HANDLE, &[(GUID, bool)]) -> T) -> Option<T> {
    unsafe {
        let mut version = 0;
        let mut handle = HANDLE::default();
        if WlanOpenHandle(2, None, &mut version, &mut handle) != 0 {
            return None;
        }
        let mut list: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
        let mut interfaces = Vec::new();
        if WlanEnumInterfaces(handle, None, &mut list) == 0 && !list.is_null() {
            let count = (*list).dwNumberOfItems as usize;
            let first = (&raw const (*list).InterfaceInfo).cast::<windows::Win32::NetworkManagement::WiFi::WLAN_INTERFACE_INFO>();
            for i in 0..count {
                let info = &*first.add(i);
                interfaces.push((info.InterfaceGuid, info.isState == wlan_interface_state_connected));
            }
            WlanFreeMemory(list.cast());
        }
        let result = f(handle, &interfaces);
        WlanCloseHandle(handle, None);
        Some(result)
    }
}

/// What has to be put back even if Vantix dies in the middle of a game.
#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct Leftovers {
    services: Vec<String>,
    #[serde(with = "guids")]
    wifi: Vec<GUID>,
    /// Games Vantix pointed at the dedicated GPU.
    gpu: Vec<String>,
}

mod guids {
    use serde::{Deserialize, Deserializer, Serializer};
    use windows::core::GUID;

    pub fn serialize<S: Serializer>(guids: &[GUID], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(guids.iter().map(|guid| format!("{guid:?}")))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<GUID>, D::Error> {
        let texts = Vec::<String>::deserialize(d)?;
        Ok(texts.iter().filter_map(|text| GUID::try_from(text.as_str()).ok()).collect())
    }
}

fn leftovers_path() -> std::path::PathBuf {
    data_dir().join("game.json")
}

/// The governor thread and the window both change game.json; one at a time.
static LEFTOVERS: Mutex<()> = Mutex::new(());

fn load_leftovers() -> Leftovers {
    let _lock = LEFTOVERS.lock().unwrap_or_else(|e| e.into_inner());
    crate::settings::read_json(&leftovers_path()).unwrap_or_default()
}

/// Reads, changes and writes game.json under the lock, the write atomic. False when it
/// couldn't be written, or when the file is there but unreadable, which a write would
/// wipe. A damaged one has been moved aside and starts over empty.
fn update_leftovers(change: impl FnOnce(&mut Leftovers)) -> bool {
    let _lock = LEFTOVERS.lock().unwrap_or_else(|e| e.into_inner());
    let mut leftovers = match crate::settings::read_json(&leftovers_path()) {
        Ok(leftovers) => leftovers,
        Err(crate::settings::Unreadable::Moved(_)) => Leftovers::default(),
        Err(crate::settings::Unreadable::Locked) => return false,
    };
    change(&mut leftovers);
    crate::settings::write_json(&leftovers_path(), &leftovers)
        .inspect_err(|e| crate::system::log_error("save game.json", e))
        .is_ok()
}

fn add_missing<T: PartialEq + Clone>(list: &mut Vec<T>, items: &[T]) {
    for item in items {
        if !list.contains(item) {
            list.push(item.clone());
        }
    }
}

fn restore_leftovers() {
    let leftovers = load_leftovers();
    if !leftovers.services.is_empty() || !leftovers.wifi.is_empty() {
        put_back(&leftovers.services, &leftovers.wifi);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::process::CommandExt;
    use std::process::{Child, Command};

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    /// Killed when dropped, so a failed assert doesn't leave it running.
    struct Spawned(Child);

    impl Drop for Spawned {
        fn drop(&mut self) {
            let _ = self.0.kill();
        }
    }

    fn powershell(script: &str) -> Spawned {
        let child = Command::new(crate::tweaks::system_tool(r"WindowsPowerShell\v1.0\powershell.exe"))
            .args(["-NoProfile", "-Command", script])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .unwrap();
        Spawned(child)
    }

    fn governor() -> Governor {
        Governor {
            me: std::process::id(),
            session: session_of(std::process::id()),
            windows: format!("{}\\", std::env::var("SystemRoot").unwrap().to_lowercase()),
            ..Default::default()
        }
    }

    fn priority(pid: u32) -> u32 {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).unwrap();
            let class = GetPriorityClass(handle);
            let _ = CloseHandle(handle);
            class
        }
    }

    /// Spins every core but one in a background process, checks it gets held back, then
    /// turns ProBalance off and checks it's let go:
    /// `cargo test probalance_round_trip -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn probalance_round_trip() {
        let threads = std::thread::available_parallelism().unwrap().get().saturating_sub(1).max(2);
        let hog = powershell(&format!(
            "1..{threads} | % {{ $r = [runspacefactory]::CreateRunspace(); $r.Open(); \
             $p = [powershell]::Create(); $p.Runspace = $r; [void]$p.AddScript('while($true){{}}'); \
             [void]$p.BeginInvoke() }}; Start-Sleep 60"
        ));
        let pid = hog.0.id();
        let mut governor = governor();
        let on = Config { probalance: true, ..Default::default() };
        let mut held = false;
        for _ in 0..15 {
            governor.tick(&on, &Capabilities::default());
            if governor.restrained.contains(&pid) {
                held = true;
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
        let while_held = priority(pid);
        governor.tick(&Config::default(), &Capabilities::default());
        let after = priority(pid);
        drop(hog);
        assert!(held, "hog was never held back");
        assert_eq!(while_held, BELOW_NORMAL_PRIORITY_CLASS.0);
        assert_eq!(after, NORMAL_PRIORITY_CLASS.0, "not let go");
        println!("hog {pid}: normal -> below normal -> normal");
    }

    /// Treats a sleeping process as the game, checks what the session changes and that
    /// ending it puts everything back. Stops Windows Search for a moment:
    /// `cargo test game_round_trip -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn game_round_trip() {
        let scratch = std::env::temp_dir().join("vantix-governor-test");
        std::fs::create_dir_all(scratch.join("Vantix")).unwrap();
        // Keeps game.json out of the real data folder.
        unsafe { std::env::set_var("APPDATA", &scratch) };

        let fake = powershell("Start-Sleep 60");
        let pid = fake.0.id();
        let mut governor = governor();
        governor.sample();
        let search_before = with_service("WSearch", service_running);
        let own_eco: Vec<u32> =
            governor.processes.iter().filter(|(_, p)| eco_set(p.handle) == Some(true)).map(|(&pid, _)| pid).collect();
        let process = &governor.processes[&pid];
        let (handle, name, image) = (process.handle, process.name.clone(), process.image.clone());
        let config = GameMode { enabled: true, ..Default::default() };
        governor.begin_game(pid, handle, name, image, config, &Capabilities::default());
        governor.during_game(0, config);

        let raised = priority(pid);
        let search_during = with_service("WSearch", service_running);
        let efficient = governor.efficient.len();
        let saved = load_leftovers().services;

        governor.end_game();
        std::thread::sleep(Duration::from_secs(2));
        let restored = priority(pid);
        let own_eco_kept = own_eco.iter().all(|pid| {
            governor.processes.get(pid).is_none_or(|p| eco_set(p.handle) == Some(true))
        });
        let search_after = with_service("WSearch", service_running);
        drop(fake);

        assert_eq!(raised, HIGH_PRIORITY_CLASS.0);
        assert!(efficient > 0, "nothing went to efficiency mode");
        assert!(!search_during, "Windows Search still running");
        assert_eq!(saved.contains(&"WSearch".to_string()), search_before);
        assert_eq!(restored, NORMAL_PRIORITY_CLASS.0);
        assert!(governor.efficient.is_empty());
        assert!(own_eco_kept, "a program's own efficiency mode was undone");
        assert_eq!(search_after, search_before, "Windows Search not back");
        assert!(load_leftovers().services.is_empty());
        println!(
            "priority high -> normal, {efficient} in efficiency mode, {} kept their own, search {search_before} -> {search_during} -> {search_after}",
            own_eco.len()
        );
    }

    /// Starts a game session and never ends it, as if Vantix died mid-game, then runs what
    /// the next start runs. Stops Windows Search for a moment:
    /// `cargo test crash_recovery -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn crash_recovery() {
        let scratch = std::env::temp_dir().join("vantix-crash-test");
        std::fs::create_dir_all(scratch.join("Vantix")).unwrap();
        unsafe { std::env::set_var("APPDATA", &scratch) };

        let fake = powershell("Start-Sleep 60");
        let pid = fake.0.id();
        let mut governor = governor();
        governor.sample();
        let search_before = with_service("WSearch", service_running);
        let process = &governor.processes[&pid];
        let (handle, name, image) = (process.handle, process.name.clone(), process.image.clone());
        let config = GameMode { enabled: true, priority: false, cores: false, ..Default::default() };
        governor.begin_game(pid, handle, name, image, config, &Capabilities::default());
        let journal = load_leftovers().services;
        let search_during = with_service("WSearch", service_running);
        // The crash: the session is dropped without end_game.
        std::mem::forget(governor);

        restore_leftovers();
        std::thread::sleep(Duration::from_secs(2));
        let search_after = with_service("WSearch", service_running);
        drop(fake);
        println!("search {search_before} -> {search_during} -> {search_after}, journal {journal:?}");

        assert_eq!(journal.contains(&"WSearch".to_string()), search_before);
        assert_eq!(search_after, search_before, "Windows Search not back");
        assert!(load_leftovers().services.is_empty());
    }

    /// Turns background scanning off on the connected Wi-Fi and back, through game.json as
    /// the game mode does, and checks every interface ends as it began:
    /// `cargo test wifi_scan_round_trip -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn wifi_scan_round_trip() {
        let scratch = std::env::temp_dir().join("vantix-wifi-test");
        std::fs::create_dir_all(scratch.join("Vantix")).unwrap();
        unsafe { std::env::set_var("APPDATA", &scratch) };
        let state = || {
            with_wlan(|handle, interfaces| {
                interfaces.iter().map(|(guid, _)| (*guid, wifi_scan_on(handle, guid))).collect::<Vec<_>>()
            })
            .unwrap_or_default()
        };

        let before = state();
        if before.is_empty() {
            println!("no Wi-Fi on this PC, nothing to check");
            return;
        }
        let scanning = wifi_scanning();
        assert!(update_leftovers(|l| add_missing(&mut l.wifi, &scanning)));
        let off = set_wifi_scan(&scanning, false);
        let during = state();
        put_back(&[], &scanning);
        let after = state();
        println!("before {before:?}\nduring {during:?}\nafter  {after:?}");

        assert_eq!(off, scanning);
        assert!(during.iter().all(|(guid, on)| !off.contains(guid) || *on == Some(false)));
        assert_eq!(after, before);
        assert!(load_leftovers().wifi.is_empty());
    }

    /// A program on the always list counts in a window, one on the never list doesn't, and
    /// marking the running game as never ends it. Every boost is off, so nothing changes:
    /// `cargo test game_lists -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn game_lists() {
        let scratch = std::env::temp_dir().join("vantix-governor-test");
        std::fs::create_dir_all(scratch.join("Vantix")).unwrap();
        unsafe { std::env::set_var("APPDATA", &scratch) };

        let fake = powershell("Start-Sleep 60");
        let pid = fake.0.id();
        let mut governor = governor();
        governor.sample();
        let name = governor.processes[&pid].name.clone();
        let off = GameMode {
            enabled: true,
            priority: false,
            cores: false,
            eco: false,
            services: false,
            standby: false,
            wifi: false,
            gpu: false,
        };
        let never = Config { game: off, never: vec![name.to_uppercase()], ..Default::default() };
        for _ in 0..GAME_TICKS + 1 {
            governor.detect_game(pid, &never, &Capabilities::default());
        }
        assert!(governor.game.is_none(), "a program on the never list was taken for a game");

        let always = Config { game: off, always: vec![name.clone()], ..Default::default() };
        for _ in 0..GAME_TICKS {
            governor.detect_game(pid, &always, &Capabilities::default());
        }
        assert_eq!(governor.game.as_ref().map(|game| game.pid), Some(pid), "always list ignored");
        let last = governor.last.clone().unwrap();
        assert!(last.ended.is_none() && !last.priority && last.services == 0);

        let marked = Config { never: vec![name.clone()], ..always };
        governor.tick(&marked, &Capabilities::default());
        drop(fake);
        assert!(governor.game.is_none(), "still boosting after marking it not a game");
        assert!(governor.last.as_ref().unwrap().ended.is_some());
        println!("{name}: never skipped, always taken in a window, marked not a game and let go");
    }

    #[test]
    fn cores_on_this_cpu() {
        match preferred_cores() {
            Some(cores) => println!("preferred {} of {} ({})", cores.preferred, cores.total, cores.kind as u8),
            None => println!("every core alike"),
        }
    }
}
