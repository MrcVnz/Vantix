//! Internet diagnostics: live ping, bufferbloat, DNS benchmark and traffic per program,
//! plus the repairs on the Repair tab. Only the repairs change the system. Every call that
//! measures blocks, so run it off the UI thread; the live ping and the traffic monitor run
//! on threads of their own.

use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasher, RandomState};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{CloseHandle, GlobalFree, HANDLE, HGLOBAL};
use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses,
    GetBestInterface, ICMP_ECHO_REPLY, IP_ADAPTER_ADDRESSES_LH, IcmpCloseHandle, IcmpCreateFile,
    IcmpSendEcho, SendARP,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinHttp::{
    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_FLAG_SECURE, WINHTTP_QUERY_DATE, WINHTTP_QUERY_FLAG_NUMBER,
    WINHTTP_QUERY_STATUS_CODE, WinHttpCloseHandle, WinHttpConnect, WinHttpDetectAutoProxyConfigUrl,
    WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse,
    WinHttpSendRequest, WinHttpSetTimeouts, WinHttpWriteData,
};
use windows::Win32::Networking::WinInet::{INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED};
use windows::Win32::Networking::WinSock::SOCKET_ADDRESS;
use windows::Win32::System::Diagnostics::Etw::EVENT_RECORD;
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::core::{GUID, HSTRING, PCWSTR, PWSTR};

use crate::{etw, reg, tweaks};

/// Anycast, so it answers from close by nearly everywhere, and the same network as the
/// speed test server.
const CLOUDFLARE: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

/// A network adapter, as far as Vantix cares.
#[derive(Clone, Default)]
pub struct Connection {
    pub name: String,
    /// As in the registry, "{7BA715F8-...}". Stays the same across restarts, unlike the index.
    pub guid: String,
    pub index: u32,
    pub up: bool,
    pub gateway: Option<Ipv4Addr>,
    /// IPv4 of this PC on the adapter, when it has one.
    pub ip: Option<Ipv4Addr>,
    /// Driver description from GetAdaptersAddresses, for VPN brand matching.
    pub description: String,
    pub dns: Vec<IpAddr>,
    pub dhcp: bool,
    /// Cable, Wi-Fi or a PPPoE dial-up. VPN and virtual adapters get their DNS from
    /// whatever made them, so Vantix leaves those alone.
    pub physical: bool,
    pub wifi: bool,
    /// Has a global IPv6 address, so IPv6 DNS servers can be reached through it.
    pub ipv6: bool,
    /// The IPv6 component is bound to the adapter at all.
    pub ipv6_bound: bool,
}

/// The adapter Windows sends internet traffic through.
pub fn connection() -> Option<Connection> {
    let mut index = 0;
    if unsafe { GetBestInterface(u32::from_ne_bytes(CLOUDFLARE.octets()), &mut index) } != 0 {
        return None;
    }
    adapters().into_iter().find(|a| a.index == index && a.up)
}

pub fn adapters() -> Vec<Connection> {
    const DHCP_ENABLED: u32 = 0x4;
    const IPV6_ENABLED: u32 = 0x100;
    const ETHERNET: u32 = 6;
    const PPP: u32 = 23;
    const WIFI: u32 = 71;
    let flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST;
    let mut size = 16 * 1024;
    // The list can grow between the size query and the read, hence the retry.
    for _ in 0..3 {
        let mut buffer = vec![0u64; size as usize / 8 + 1];
        let first = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        match unsafe { GetAdaptersAddresses(0, flags, None, Some(first), &mut size) } {
            0 => {}
            111 => continue, // ERROR_BUFFER_OVERFLOW, size now holds what's needed
            _ => return Vec::new(),
        }
        let mut list = Vec::new();
        let mut adapter = first;
        while !adapter.is_null() {
            let a = unsafe { &*adapter };
            {
                let mut gateway = None;
                let mut next = a.FirstGatewayAddress;
                while !next.is_null() && gateway.is_none() {
                    let entry = unsafe { &*next };
                    if let Some(IpAddr::V4(v4)) = socket_ip(&entry.Address) {
                        gateway = Some(v4);
                    }
                    next = entry.Next;
                }
                let mut dns = Vec::new();
                let mut next = a.FirstDnsServerAddress;
                while !next.is_null() {
                    let entry = unsafe { &*next };
                    // Windows lists fec0:0:0:ffff::1 to 3 when IPv6 has no DNS server of its
                    // own. Nothing answers there; they're placeholders, not servers.
                    dns.extend(socket_ip(&entry.Address).filter(|ip| match ip {
                        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 != 0xfec0,
                        IpAddr::V4(_) => true,
                    }));
                    next = entry.Next;
                }
                let mut ipv6 = false;
                let mut ip = None;
                let mut next = a.FirstUnicastAddress;
                while !next.is_null() {
                    let entry = unsafe { &*next };
                    match socket_ip(&entry.Address) {
                        Some(IpAddr::V6(v6)) => {
                            ipv6 |= v6.segments()[0] & 0xe000 == 0x2000;
                        }
                        // First IPv4 is the PC address; link-local only counts when
                        // there is nothing else.
                        Some(IpAddr::V4(v4))
                            if ip.is_none() || ip.is_some_and(|a: Ipv4Addr| a.is_link_local()) =>
                        {
                            ip = Some(v4);
                        }
                        _ => {}
                    }
                    next = entry.Next;
                }
                list.push(Connection {
                    name: unsafe { a.FriendlyName.to_string() }.unwrap_or_default(),
                    guid: unsafe { a.AdapterName.to_string() }.unwrap_or_default(),
                    index: unsafe { a.Anonymous1.Anonymous.IfIndex },
                    up: a.OperStatus == IfOperStatusUp,
                    gateway,
                    ip,
                    description: unsafe { a.Description.to_string() }.unwrap_or_default(),
                    dns,
                    dhcp: unsafe { a.Anonymous2.Flags } & DHCP_ENABLED != 0,
                    ipv6_bound: unsafe { a.Anonymous2.Flags } & IPV6_ENABLED != 0,
                    physical: matches!(a.IfType, ETHERNET | WIFI | PPP),
                    wifi: a.IfType == WIFI,
                    ipv6,
                });
            }
            adapter = a.Next;
        }
        return list;
    }
    Vec::new()
}

fn socket_ip(address: &SOCKET_ADDRESS) -> Option<IpAddr> {
    const AF_INET: u16 = 2;
    const AF_INET6: u16 = 23;
    let raw = address.lpSockaddr.cast::<u8>();
    if raw.is_null() {
        return None;
    }
    unsafe {
        match raw.cast::<u16>().read_unaligned() {
            AF_INET => Some(IpAddr::V4(Ipv4Addr::from(raw.add(4).cast::<[u8; 4]>().read_unaligned()))),
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(raw.add(8).cast::<[u8; 16]>().read_unaligned()))),
            _ => None,
        }
    }
}

pub fn uses_dhcp() -> bool {
    connection().is_some_and(|c| c.dhcp)
}

// Repairs, run from the Repair tab like any other action.

pub fn flush_dns() -> windows::core::Result<()> {
    tweaks::run("ipconfig.exe", &["/flushdns"]).map(drop)
}

/// Only the adapter in use: renewing all of them fails on any that's unplugged.
pub fn renew_ip() -> windows::core::Result<()> {
    let Some(connection) = connection() else {
        return Err(windows::core::Error::new(windows::Win32::Foundation::E_FAIL, "no connected adapter"));
    };
    tweaks::run("ipconfig.exe", &["/renew", &connection.name]).map(drop)
}

pub fn reset_stack() -> windows::core::Result<()> {
    tweaks::run("netsh.exe", &["winsock", "reset"])?;
    // Often exits with an error for a single key it isn't allowed to reset, after
    // resetting everything else, so only the log hears about it.
    if let Err(e) = tweaks::run("netsh.exe", &["int", "ip", "reset"]) {
        crate::system::log_error("netsh int ip reset", &e);
    }
    Ok(())
}

// Ping. IcmpSendEcho only reports whole milliseconds, which reads as 0 on a cable to the
// router, so the time is taken around the call instead.

struct Icmp(HANDLE);

impl Icmp {
    fn new() -> Option<Self> {
        unsafe { IcmpCreateFile() }.ok().map(Self)
    }

    /// Round trip in milliseconds, `None` when it got lost.
    fn ping(&self, to: Ipv4Addr, timeout: Duration) -> Option<f64> {
        let payload = [0x56u8; 32];
        let mut reply = [0u64; (size_of::<ICMP_ECHO_REPLY>() + 32 + 8) / 8 + 8];
        let start = Instant::now();
        let count = unsafe {
            IcmpSendEcho(
                self.0,
                u32::from_ne_bytes(to.octets()),
                payload.as_ptr().cast(),
                payload.len() as u16,
                None,
                reply.as_mut_ptr().cast(),
                size_of_val(&reply) as u32,
                timeout.as_millis() as u32,
            )
        };
        let elapsed = start.elapsed();
        let status = unsafe { reply.as_ptr().cast::<ICMP_ECHO_REPLY>().read() }.Status;
        (count > 0 && status == 0).then_some(elapsed.as_secs_f64() * 1000.0)
    }
}

impl Drop for Icmp {
    fn drop(&mut self) {
        unsafe {
            let _ = IcmpCloseHandle(self.0);
        }
    }
}

/// Last round trips of one target, oldest first. `None` is a lost one.
#[derive(Clone, Default)]
pub struct Series(pub VecDeque<Option<f64>>);

/// Seconds of history kept per target.
pub const SERIES_LEN: usize = 60;

impl Series {
    fn push(&mut self, sample: Option<f64>) {
        if self.0.len() == SERIES_LEN {
            self.0.pop_front();
        }
        self.0.push_back(sample);
    }

    fn answered(&self) -> impl Iterator<Item = f64> + '_ {
        self.0.iter().flatten().copied()
    }

    pub fn last(&self) -> Option<Option<f64>> {
        self.0.back().copied()
    }

    pub fn average(&self) -> Option<f64> {
        let count = self.answered().count();
        (count > 0).then(|| self.answered().sum::<f64>() / count as f64)
    }

    /// Mean difference between consecutive answers, as RFC 3550 and most games count it.
    pub fn jitter(&self) -> Option<f64> {
        let answered: Vec<f64> = self.answered().collect();
        (answered.len() > 1).then(|| {
            answered.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (answered.len() - 1) as f64
        })
    }

    /// Share of pings that got no answer, 0 to 1.
    pub fn loss(&self) -> Option<f64> {
        (!self.0.is_empty())
            .then(|| self.0.iter().filter(|s| s.is_none()).count() as f64 / self.0.len() as f64)
    }

    pub fn max(&self) -> Option<f64> {
        self.answered().reduce(f64::max)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Gateway,
    Cloudflare,
    /// Index into the hosts the user added.
    Host(usize),
}

#[derive(Clone, PartialEq, Eq)]
pub enum Lookup {
    Pending,
    Found(Ipv4Addr),
    /// No gateway, or a host name that didn't resolve to an IPv4 address.
    Failed,
}

#[derive(Clone)]
pub struct Reading {
    pub target: Target,
    pub label: String,
    pub address: Lookup,
    pub series: Series,
}

struct Watch {
    hosts: Vec<String>,
    stop: Arc<AtomicBool>,
    readings: Arc<Mutex<Vec<Reading>>>,
}

static WATCH: Mutex<Option<Watch>> = Mutex::new(None);

/// Pings the gateway, Cloudflare and `hosts` once a second each, until `unwatch`. A call
/// with the same hosts while it runs does nothing.
pub fn watch(hosts: &[String]) {
    let mut watch = WATCH.lock().unwrap();
    if watch.as_ref().is_some_and(|w| w.hosts == hosts) {
        return;
    }
    if let Some(old) = watch.take() {
        old.stop.store(true, Ordering::Relaxed);
    }
    let mut targets = vec![(Target::Gateway, String::new()), (Target::Cloudflare, "Cloudflare".to_string())];
    targets.extend(hosts.iter().enumerate().map(|(i, host)| (Target::Host(i), host.clone())));
    let readings: Vec<Reading> = targets
        .iter()
        .map(|(target, label)| Reading {
            target: *target,
            label: label.clone(),
            address: Lookup::Pending,
            series: Series::default(),
        })
        .collect();
    let stop = Arc::new(AtomicBool::new(false));
    let readings = Arc::new(Mutex::new(readings));
    for (i, (target, label)) in targets.into_iter().enumerate() {
        let (stop, readings) = (stop.clone(), readings.clone());
        std::thread::spawn(move || ping_loop(i, target, &label, &stop, &readings));
    }
    *watch = Some(Watch { hosts: hosts.to_vec(), stop, readings });
}

pub fn unwatch() {
    if let Some(old) = WATCH.lock().unwrap().take() {
        old.stop.store(true, Ordering::Relaxed);
    }
}

pub fn readings() -> Vec<Reading> {
    WATCH.lock().unwrap().as_ref().map(|w| w.readings.lock().unwrap().clone()).unwrap_or_default()
}

fn ping_loop(i: usize, target: Target, label: &str, stop: &AtomicBool, readings: &Mutex<Vec<Reading>>) {
    let address = match target {
        Target::Gateway => connection().and_then(|c| c.gateway),
        Target::Cloudflare => Some(CLOUDFLARE),
        Target::Host(_) => resolve(label),
    };
    readings.lock().unwrap()[i].address = address.map_or(Lookup::Failed, Lookup::Found);
    let (Some(address), Some(icmp)) = (address, Icmp::new()) else { return };
    let mut next = Instant::now();
    while !stop.load(Ordering::Relaxed) {
        let sample = icmp.ping(address, Duration::from_millis(900));
        readings.lock().unwrap()[i].series.push(sample);
        next += Duration::from_secs(1);
        std::thread::sleep(next.saturating_duration_since(Instant::now()));
    }
}

/// The first IPv4 address of a host name, or the address itself when one was typed.
fn resolve(host: &str) -> Option<Ipv4Addr> {
    if let Ok(address) = host.parse() {
        return Some(address);
    }
    (host, 0).to_socket_addrs().ok()?.find_map(|a| match a.ip() {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(_) => None,
    })
}

// Bufferbloat: how much the ping grows while the line is full. A router that queues too
// much turns every download into lag for everything else on the network. The load comes
// from Cloudflare's speed test endpoints, which exist for this.

const SPEED_HOST: &str = "speed.cloudflare.com";
const IDLE: Duration = Duration::from_secs(5);
const LOADED: Duration = Duration::from_secs(8);
/// Pings in the first seconds of load are left out: the queue is still filling.
const RAMP: Duration = Duration::from_secs(2);
const PING_EVERY: Duration = Duration::from_millis(250);
const PING_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum Phase {
    #[default]
    Idle,
    Download,
    Upload,
}

/// What the test is doing right now, for the UI.
#[derive(Clone, Copy, Default)]
pub struct Progress {
    pub phase: Phase,
    pub elapsed: Duration,
    pub ping: Option<f64>,
    /// Megabits per second over the current phase, 0 while idle.
    pub mbps: f64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Load {
    pub mbps: f64,
    /// Average round trip while loaded.
    pub latency: f64,
    pub lost: u32,
}

#[derive(Clone, Copy, Debug)]
pub struct Bloat {
    pub idle: f64,
    pub download: Load,
    pub upload: Load,
    /// Bytes moved, both ways.
    pub data: u64,
}

impl Bloat {
    /// The worst growth of the two directions, which is what decides the grade.
    pub fn added(&self) -> f64 {
        (self.download.latency - self.idle).max(self.upload.latency - self.idle).max(0.0)
    }

    /// Waveform's scale: A under 30 ms of added latency, then B, C, D and F at 400 ms.
    /// Waveform also has A+ under 5 ms, folded into A here.
    pub fn grade(&self) -> char {
        match self.added() {
            a if a < 30.0 => 'A',
            a if a < 60.0 => 'B',
            a if a < 200.0 => 'C',
            a if a < 400.0 => 'D',
            _ => 'F',
        }
    }
}

#[derive(Debug)]
pub enum BloatError {
    /// 1.1.1.1 doesn't answer pings from here.
    NoPing,
    /// The speed test server couldn't be reached.
    NoServer,
}

static PROGRESS: Mutex<Progress> =
    Mutex::new(Progress { phase: Phase::Idle, elapsed: Duration::ZERO, ping: None, mbps: 0.0 });

pub fn bloat_progress() -> Progress {
    *PROGRESS.lock().unwrap()
}

/// Takes about 21 seconds and moves as much data as the line can in 16 of them: over
/// 1 GB on a gigabit line.
pub fn bufferbloat() -> Result<Bloat, BloatError> {
    let icmp = Icmp::new().ok_or(BloatError::NoPing)?;
    *PROGRESS.lock().unwrap() = Progress::default();

    let idle: Vec<f64> =
        sample_pings(&icmp, IDLE, Phase::Idle, None).into_iter().filter_map(|(_, p)| p).collect();
    if idle.is_empty() {
        return Err(BloatError::NoPing);
    }
    let idle = idle.iter().sum::<f64>() / idle.len() as f64;

    let (download, down_bytes) = loaded(&icmp, Phase::Download);
    let (upload, up_bytes) = if down_bytes > 0 { loaded(&icmp, Phase::Upload) } else { Default::default() };
    if down_bytes == 0 || up_bytes == 0 {
        return Err(BloatError::NoServer);
    }
    Ok(Bloat { idle, download, upload, data: down_bytes + up_bytes })
}

/// Ping idle and under a full download, for "test this tweak": the bufferbloat test cut
/// to its download half, about 10 seconds.
#[derive(Clone, Copy, Debug)]
pub struct LoadCheck {
    /// Average ping while the download runs, in ms.
    pub loaded: f64,
}

pub fn load_check() -> Result<LoadCheck, BloatError> {
    let icmp = Icmp::new().ok_or(BloatError::NoPing)?;
    *PROGRESS.lock().unwrap() = Progress::default();
    // A short idle start, only to know 1.1.1.1 answers at all.
    if sample_pings(&icmp, Duration::from_secs(2), Phase::Idle, None).iter().all(|(_, p)| p.is_none()) {
        return Err(BloatError::NoPing);
    }
    let (load, bytes) = loaded(&icmp, Phase::Download);
    if bytes == 0 {
        return Err(BloatError::NoServer);
    }
    Ok(LoadCheck { loaded: load.latency })
}

/// How a second check compares to the first: -1 better, 0 within noise, 1 worse. Pings
/// under load swing a few ms between runs, so less than 5 ms or 15% is noise.
pub fn compare_checks(before: &LoadCheck, after: &LoadCheck) -> i32 {
    let change = after.loaded - before.loaded;
    if change.abs() < 5.0_f64.max(before.loaded * 0.15) {
        0
    } else if change < 0.0 {
        -1
    } else {
        1
    }
}

/// Bytes moved by the streams of one phase, and when the ramp ended with how many.
struct Meter<'a> {
    bytes: &'a AtomicU64,
    began: Instant,
    ramped: Option<(Instant, u64)>,
}

/// One direction at full speed with pings alongside. Returns the result and the bytes moved.
fn loaded(icmp: &Icmp, phase: Phase) -> (Load, u64) {
    let bytes = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    // Several connections, so one TCP window doesn't cap the speed on a far server.
    let streams = if phase == Phase::Download { 6 } else { 4 };
    let workers: Vec<_> = (0..streams)
        .map(|_| {
            let (bytes, stop) = (bytes.clone(), stop.clone());
            std::thread::spawn(move || match phase {
                Phase::Upload => upload_stream(&bytes, &stop),
                _ => download_stream(&bytes, &stop),
            })
        })
        .collect();

    let mut meter = Meter { bytes: &bytes, began: Instant::now(), ramped: None };
    let pings = sample_pings(icmp, LOADED, phase, Some(&mut meter));
    let total = bytes.load(Ordering::Relaxed);
    stop.store(true, Ordering::Relaxed);
    // Not joined: a stream stuck in a slow read would hold the result up. They stop on
    // their own at the next chunk or time out.
    drop(workers);

    let (at, from) = meter.ramped.unwrap_or((meter.began, 0));
    let mbps = total.saturating_sub(from) as f64 * 8.0 / at.elapsed().as_secs_f64().max(0.1) / 1e6;
    let measured: Vec<Option<f64>> =
        pings.into_iter().filter(|(when, _)| *when >= RAMP).map(|(_, p)| p).collect();
    // A ping lost under load is the queue overflowing, the worst case of bloat, so it
    // counts as the full timeout instead of dropping out of the average.
    let latency = if measured.is_empty() {
        PING_TIMEOUT.as_secs_f64() * 1000.0
    } else {
        measured.iter().map(|p| p.unwrap_or(PING_TIMEOUT.as_secs_f64() * 1000.0)).sum::<f64>()
            / measured.len() as f64
    };
    let lost = measured.iter().filter(|p| p.is_none()).count() as u32;
    (Load { mbps, latency, lost }, total)
}

/// Pings every 250 ms for `length`, each with the time it was sent. Under load it also
/// reports the speed and notes when the ramp ended.
fn sample_pings(
    icmp: &Icmp,
    length: Duration,
    phase: Phase,
    mut meter: Option<&mut Meter>,
) -> Vec<(Duration, Option<f64>)> {
    let start = Instant::now();
    let mut pings = Vec::new();
    let mut next = start;
    while start.elapsed() < length {
        let sent = start.elapsed();
        // Under heavy bloat a ping can take the whole timeout, so there are fewer of them.
        let ping = icmp.ping(CLOUDFLARE, PING_TIMEOUT);
        pings.push((sent, ping));
        let mut mbps = 0.0;
        if let Some(meter) = meter.as_deref_mut() {
            let moved = meter.bytes.load(Ordering::Relaxed);
            if meter.ramped.is_none() && meter.began.elapsed() >= RAMP {
                meter.ramped = Some((Instant::now(), moved));
            }
            if let Some((at, from)) = meter.ramped {
                mbps = moved.saturating_sub(from) as f64 * 8.0 / at.elapsed().as_secs_f64().max(0.25) / 1e6;
            }
        }
        *PROGRESS.lock().unwrap() = Progress { phase, elapsed: start.elapsed(), ping, mbps };
        next += PING_EVERY;
        std::thread::sleep(next.saturating_duration_since(Instant::now()));
    }
    pings
}

/// A WinHTTP handle that closes itself.
pub(crate) struct Http(pub(crate) *mut core::ffi::c_void);

impl Http {
    fn ok(self) -> Option<Self> {
        (!self.0.is_null()).then_some(self)
    }
}

impl Drop for Http {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = WinHttpCloseHandle(self.0);
            }
        }
    }
}

pub(crate) fn http_connection(host: &str, port: u16) -> Option<(Http, Http)> {
    unsafe {
        let session = Http(WinHttpOpen(
            &HSTRING::from(concat!("Vantix/", env!("CARGO_PKG_VERSION"))),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            PCWSTR::null(),
            PCWSTR::null(),
            0,
        ))
        .ok()?;
        WinHttpSetTimeouts(session.0, 5000, 5000, 5000, 5000).ok()?;
        let connection = Http(WinHttpConnect(session.0, &HSTRING::from(host), port, 0)).ok()?;
        Some((session, connection))
    }
}

pub(crate) fn request(connection: &Http, verb: &str, path: &str) -> Option<Http> {
    unsafe {
        Http(WinHttpOpenRequest(
            connection.0,
            &HSTRING::from(verb),
            &HSTRING::from(path),
            PCWSTR::null(),
            PCWSTR::null(),
            std::ptr::null(),
            WINHTTP_FLAG_SECURE,
        ))
        .ok()
    }
}

/// Received a 200. Anything else ends the stream, so a refusal can't turn into a loop of
/// requests.
fn answered_ok(request: &Http) -> bool {
    status(request) == Some(200)
}

/// Waits for the answer to a sent request and gives its HTTP status.
pub(crate) fn status(request: &Http) -> Option<u32> {
    let mut status = 0u32;
    let mut size = 4u32;
    unsafe {
        WinHttpReceiveResponse(request.0, std::ptr::null_mut()).ok()?;
        WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            PCWSTR::null(),
            Some((&raw mut status).cast()),
            &mut size,
            std::ptr::null_mut(),
        )
        .ok()?;
    }
    Some(status)
}

fn download_stream(bytes: &AtomicU64, stop: &AtomicBool) {
    let Some((_session, connection)) = http_connection(SPEED_HOST, 443) else { return };
    let mut buffer = vec![0u8; 64 * 1024];
    while !stop.load(Ordering::Relaxed) {
        // The endpoint refuses more than 50 MB per request.
        let Some(request) = request(&connection, "GET", "/__down?bytes=25000000") else { return };
        unsafe {
            if WinHttpSendRequest(request.0, None, None, 0, 0, 0).is_err() || !answered_ok(&request) {
                return;
            }
            loop {
                let mut read = 0;
                if stop.load(Ordering::Relaxed)
                    || WinHttpReadData(request.0, buffer.as_mut_ptr().cast(), buffer.len() as u32, &mut read)
                        .is_err()
                    || read == 0
                {
                    break;
                }
                bytes.fetch_add(u64::from(read), Ordering::Relaxed);
            }
        }
    }
}

fn upload_stream(bytes: &AtomicU64, stop: &AtomicBool) {
    const BODY: u32 = 25_000_000;
    let Some((_session, connection)) = http_connection(SPEED_HOST, 443) else { return };
    // Not all zeros, so nothing along the way can compress it.
    let mut seed = random();
    let chunk: Vec<u8> = (0..64 * 1024)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u8
        })
        .collect();
    let headers: Vec<u16> = "Content-Type: application/octet-stream".encode_utf16().collect();
    while !stop.load(Ordering::Relaxed) {
        let Some(request) = request(&connection, "POST", "/__up") else { return };
        unsafe {
            if WinHttpSendRequest(request.0, Some(&headers), None, 0, BODY, 0).is_err() {
                return;
            }
            let mut sent = 0;
            while sent < BODY && !stop.load(Ordering::Relaxed) {
                let size = (BODY - sent).min(chunk.len() as u32);
                let mut written = 0;
                if WinHttpWriteData(request.0, Some(chunk.as_ptr().cast()), size, &mut written).is_err() {
                    break;
                }
                sent += written;
                bytes.fetch_add(u64::from(written), Ordering::Relaxed);
            }
            if sent == BODY && !answered_ok(&request) {
                return;
            }
        }
    }
}

// DNS benchmark: raw queries over UDP to each resolver, so what's timed is the resolver
// and the path to it, not Windows' own DNS cache.

const DOMAINS: [&str; 20] = [
    "google.com",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "whatsapp.com",
    "wikipedia.org",
    "amazon.com",
    "netflix.com",
    "twitch.tv",
    "discord.com",
    "reddit.com",
    "microsoft.com",
    "apple.com",
    "steampowered.com",
    "x.com",
    "tiktok.com",
    "cloudflare.com",
    "github.com",
    "spotify.com",
    "epicgames.com",
];

/// A public DNS service: main and backup servers for IPv4 and IPv6. The benchmark times
/// the first IPv4 one; setting it sets all of them.
pub struct Provider {
    pub name: &'static str,
    v4: [Ipv4Addr; 2],
    v6: [Ipv6Addr; 2],
    /// Its DNS over HTTPS address.
    doh: &'static str,
}

pub const PROVIDERS: [Provider; 5] = [
    Provider {
        name: "Cloudflare",
        v4: [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)],
        v6: [
            Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
            Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001),
        ],
        doh: "https://cloudflare-dns.com/dns-query",
    },
    Provider {
        name: "Google",
        v4: [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)],
        v6: [
            Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
            Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844),
        ],
        doh: "https://dns.google/dns-query",
    },
    Provider {
        name: "Quad9",
        v4: [Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(149, 112, 112, 112)],
        v6: [
            Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe),
            Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0x9),
        ],
        doh: "https://dns.quad9.net/dns-query",
    },
    Provider {
        name: "OpenDNS",
        v4: [Ipv4Addr::new(208, 67, 222, 222), Ipv4Addr::new(208, 67, 220, 220)],
        v6: [
            Ipv6Addr::new(0x2620, 0x119, 0x35, 0, 0, 0, 0, 0x35),
            Ipv6Addr::new(0x2620, 0x119, 0x53, 0, 0, 0, 0, 0x53),
        ],
        doh: "https://doh.opendns.com/dns-query",
    },
    Provider {
        name: "AdGuard",
        v4: [Ipv4Addr::new(94, 140, 14, 14), Ipv4Addr::new(94, 140, 15, 15)],
        v6: [
            Ipv6Addr::new(0x2a10, 0x50c0, 0, 0, 0, 0, 0xad1, 0xff),
            Ipv6Addr::new(0x2a10, 0x50c0, 0, 0, 0, 0, 0xad2, 0xff),
        ],
        doh: "https://dns.adguard-dns.com/dns-query",
    },
];

/// The service an address belongs to, any of its four servers.
fn provider_of(address: IpAddr) -> Option<usize> {
    PROVIDERS.iter().position(|p| match address {
        IpAddr::V4(v4) => p.v4.contains(&v4),
        IpAddr::V6(v6) => p.v6.contains(&v6),
    })
}

/// The DNS servers in use, with a known service's backup and IPv6 servers folded into
/// its main one, so it shows once.
pub fn current_dns() -> Vec<IpAddr> {
    let mut list: Vec<IpAddr> = Vec::new();
    for address in connection().map(|c| c.dns).unwrap_or_default() {
        let address = provider_of(address).map_or(address, |p| IpAddr::V4(PROVIDERS[p].v4[0]));
        if !list.contains(&address) {
            list.push(address);
        }
    }
    list
}

#[derive(Clone, Debug)]
pub struct Resolver {
    /// Index into PROVIDERS, `None` for one that isn't a known public service, like the router.
    pub provider: Option<usize>,
    /// Empty for a resolver that isn't a known public one, like the router.
    pub name: String,
    pub address: IpAddr,
    /// Median time for names the resolver already has cached, in ms.
    pub cached: Option<f64>,
    /// Median time for names it has to look up, in ms.
    pub uncached: Option<f64>,
    /// Mean difference between consecutive cached answers, in ms.
    pub jitter: Option<f64>,
    pub failed: u32,
    pub sent: u32,
}

impl Resolver {
    /// What browsing feels like: most names are popular and cached, some aren't.
    pub fn score(&self) -> Option<f64> {
        Some(self.cached? * 0.7 + self.uncached? * 0.3)
    }

    /// More than one query in 50 lost is too flaky to recommend.
    pub fn reliable(&self) -> bool {
        self.failed <= 1 && self.score().is_some()
    }
}

/// Queries each server gets: the names twice (to fill its cache, then timed) and half of
/// them again under a random label it can't have cached.
pub const DNS_QUERIES: u32 = DOMAINS.len() as u32 * 2 + DOMAINS.len() as u32 / 2;

/// Where one server is in a benchmark run, written by its thread and read by the tick.
pub struct DnsProbe {
    pub address: IpAddr,
    provider: Option<usize>,
    /// 0 queued, 1 testing, 2 done.
    pub state: AtomicU8,
    pub sent: AtomicU32,
    pub failed: AtomicU32,
    started: Mutex<Option<Instant>>,
    /// Timed answers so far: cached names, then new ones.
    times: Mutex<(Vec<f64>, Vec<f64>)>,
}

impl DnsProbe {
    /// What the server has shown so far; the final numbers once it's done.
    pub fn resolver(&self) -> Resolver {
        let (cached, uncached) = self.times.lock().unwrap().clone();
        let jitter = (cached.len() > 1)
            .then(|| cached.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (cached.len() - 1) as f64);
        Resolver {
            provider: self.provider,
            name: self.provider.map(|p| PROVIDERS[p].name.to_string()).unwrap_or_default(),
            address: self.address,
            cached: median(cached),
            uncached: median(uncached),
            jitter,
            failed: self.failed.load(Ordering::Relaxed),
            sent: self.sent.load(Ordering::Relaxed),
        }
    }
}

/// One benchmark: the servers in use first, then the public ones.
pub struct DnsRun {
    pub probes: Vec<DnsProbe>,
    cancel: AtomicBool,
}

impl DnsRun {
    pub fn new() -> Self {
        let mut addresses = current_dns();
        for provider in &PROVIDERS {
            let address = IpAddr::V4(provider.v4[0]);
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
        let probes = addresses
            .into_iter()
            .map(|address| DnsProbe {
                address,
                provider: provider_of(address),
                state: AtomicU8::new(0),
                sent: AtomicU32::new(0),
                failed: AtomicU32::new(0),
                started: Mutex::new(None),
                times: Mutex::new((Vec::new(), Vec::new())),
            })
            .collect();
        Self { probes, cancel: AtomicBool::new(false) }
    }

    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    /// Seconds left, from how fast each server has been going. They run side by side,
    /// so the slowest one decides. `None` until every server has answered something.
    pub fn eta(&self) -> Option<f64> {
        let mut left: f64 = 0.0;
        for probe in &self.probes {
            if probe.state.load(Ordering::Relaxed) == 2 {
                continue;
            }
            let sent = probe.sent.load(Ordering::Relaxed);
            let elapsed = (*probe.started.lock().unwrap())?.elapsed().as_secs_f64();
            if sent == 0 {
                return None;
            }
            left = left.max(elapsed / sent as f64 * DNS_QUERIES.saturating_sub(sent) as f64);
        }
        Some(left)
    }
}

/// Runs every server of `run` side by side, each on its own thread, and returns them
/// fastest first. Takes a few seconds; a cancelled run returns only the servers that
/// had finished.
pub fn dns_benchmark(run: &DnsRun) -> Vec<Resolver> {
    let scope = connection_scope();
    std::thread::scope(|s| {
        for probe in &run.probes {
            s.spawn(move || measure_resolver(probe, scope, &run.cancel));
        }
    });
    let mut results: Vec<Resolver> =
        run.probes.iter().filter(|p| p.state.load(Ordering::Relaxed) == 2).map(DnsProbe::resolver).collect();
    rank_resolvers(&mut results);
    results
}

/// Reliable ones first, then by score.
pub fn rank_resolvers(results: &mut [Resolver]) {
    results.sort_by(|a, b| {
        b.reliable()
            .cmp(&a.reliable())
            .then(a.score().unwrap_or(f64::MAX).total_cmp(&b.score().unwrap_or(f64::MAX)))
    });
}

/// Zone for link-local IPv6 resolvers, which only mean something on one interface.
fn connection_scope() -> u32 {
    let mut index = 0;
    unsafe { GetBestInterface(u32::from_ne_bytes(CLOUDFLARE.octets()), &mut index) };
    index
}

fn measure_resolver(probe: &DnsProbe, scope: u32, cancel: &AtomicBool) {
    *probe.started.lock().unwrap() = Some(Instant::now());
    probe.state.store(1, Ordering::Relaxed);
    let target = match probe.address {
        IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80 => {
            SocketAddr::V6(SocketAddrV6::new(v6, 53, 0, scope))
        }
        address => SocketAddr::new(address, 53),
    };
    let local: SocketAddr =
        if probe.address.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    let socket = UdpSocket::bind(local)
        .ok()
        .filter(|s| s.connect(target).is_ok() && s.set_read_timeout(Some(Duration::from_secs(1))).is_ok());
    let Some(socket) = socket else {
        probe.state.store(2, Ordering::Relaxed);
        return;
    };
    let ask = |name: &str| {
        let time = lookup(&socket, name);
        probe.sent.fetch_add(1, Ordering::Relaxed);
        if time.is_none() {
            probe.failed.fetch_add(1, Ordering::Relaxed);
        }
        time
    };
    let stop = || cancel.load(Ordering::Relaxed);
    // The first round puts every name in the resolver's cache, the second is timed.
    for domain in DOMAINS {
        if stop() {
            return;
        }
        ask(domain);
    }
    for domain in DOMAINS {
        if stop() {
            return;
        }
        if let Some(ms) = ask(domain) {
            probe.times.lock().unwrap().0.push(ms);
        }
    }
    // A random label under a real domain: no resolver has that cached, so it has to ask
    // the domain's own servers.
    for domain in DOMAINS.iter().step_by(2) {
        if stop() {
            return;
        }
        if let Some(ms) = ask(&format!("{:x}.{domain}", random() & 0xffff_ffff)) {
            probe.times.lock().unwrap().1.push(ms);
        }
    }
    probe.state.store(2, Ordering::Relaxed);
}

// Setting the DNS servers, from the DNS tab. What was there before is saved per family,
// DHCP or a fixed list, with the adapter's GUID, so undo puts back exactly that, even
// after a restart or with another adapter in use. netsh rather than SetInterfaceDnsSettings,
// which only exists from Windows 10 2004.

pub const DNS_TWEAK: &str = "dns-servers";
const V4_INTERFACES: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
const V6_INTERFACES: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces";

/// The service the next apply sets, picked in the DNS tab right before asking.
static CHOSEN: Mutex<Option<usize>> = Mutex::new(None);

pub fn choose_dns(provider: usize) {
    *CHOSEN.lock().unwrap() = Some(provider);
}

pub fn chosen_dns() -> Option<&'static str> {
    CHOSEN.lock().unwrap().map(|p| PROVIDERS[p].name)
}

/// One adapter's own DNS settings. An empty list means the servers come from DHCP.
struct SavedDns {
    guid: String,
    v4: Vec<String>,
    v6: Vec<String>,
}

impl SavedDns {
    fn read(guid: &str) -> Self {
        Self { guid: guid.into(), v4: fixed_dns(V4_INTERFACES, guid), v6: fixed_dns(V6_INTERFACES, guid) }
    }

    /// "{guid};1.1.1.1,1.0.0.1;dhcp"
    fn encode(&self) -> String {
        let list =
            |servers: &[String]| if servers.is_empty() { "dhcp".to_string() } else { servers.join(",") };
        format!("{};{};{}", self.guid, list(&self.v4), list(&self.v6))
    }

    fn decode(text: &str) -> Option<Self> {
        let mut parts = text.split(';');
        let guid = parts.next()?.to_string();
        let list = |part: Option<&str>| -> Option<Vec<String>> {
            let part = part?;
            Some(if part == "dhcp" { Vec::new() } else { part.split(',').map(String::from).collect() })
        };
        Some(Self { guid, v4: list(parts.next())?, v6: list(parts.next())? })
    }

    /// What the journal says was there before Vantix's DNS change, if one is in place.
    fn from_journal() -> Option<Self> {
        let changes = crate::settings::load_changes();
        changes.iter().find(|c| c.id == DNS_TWEAK)?.previous.as_deref().and_then(Self::decode)
    }

    fn put_back(&self) -> windows::core::Result<()> {
        // An adapter that was removed has nothing left to put back.
        let Some(adapter) = adapters().into_iter().find(|a| a.guid.eq_ignore_ascii_case(&self.guid)) else {
            return Ok(());
        };
        set_family("ipv4", adapter.index, &self.v4)?;
        // IPv6 can be off on the adapter, which fails here; it had DHCP then anyway.
        if let Err(e) = set_family("ipv6", adapter.index, &self.v6)
            && !self.v6.is_empty()
        {
            return Err(e);
        }
        let _ = flush_dns();
        Ok(())
    }
}

/// The fixed servers of one family, empty when DHCP provides them.
fn fixed_dns(interfaces: &str, guid: &str) -> Vec<String> {
    reg::get_string(reg::HKEY_LOCAL_MACHINE, &format!(r"{interfaces}\{guid}"), "NameServer")
        .ok()
        .flatten()
        .unwrap_or_default()
        .split([',', ' '])
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

/// Sets one family's servers by interface index, which netsh takes in every language;
/// an empty list goes back to DHCP. validate=no skips netsh's own slow reachability test.
fn set_family(family: &str, index: u32, servers: &[String]) -> windows::core::Result<()> {
    let name = format!("name={index}");
    let Some(first) = servers.first() else {
        return tweaks::run("netsh.exe", &["interface", family, "set", "dnsservers", &name, "source=dhcp"])
            .map(drop);
    };
    let address = format!("address={first}");
    let args = [
        "interface",
        family,
        "set",
        "dnsservers",
        &name,
        "source=static",
        &address,
        "register=primary",
        "validate=no",
    ];
    tweaks::run("netsh.exe", &args)?;
    for (i, server) in servers.iter().enumerate().skip(1) {
        let (address, index) = (format!("address={server}"), format!("index={}", i + 1));
        tweaks::run(
            "netsh.exe",
            &["interface", family, "add", "dnsservers", &name, &address, &index, "validate=no"],
        )?;
    }
    Ok(())
}

fn failure(message: &str) -> windows::core::Error {
    windows::core::Error::new(windows::Win32::Foundation::E_FAIL, message)
}

/// The adapter in use if Vantix may set its DNS: cable, Wi-Fi or PPPoE.
pub fn dns_adapter() -> Option<Connection> {
    connection().filter(|c| c.physical && !c.guid.is_empty())
}

/// On while a known service is set by hand on the adapter Vantix changed, or on the one
/// in use when nothing was changed yet.
pub fn dns_set() -> windows::core::Result<bool> {
    let guid = match SavedDns::from_journal() {
        Some(saved) => saved.guid,
        None => dns_adapter().map(|a| a.guid).unwrap_or_default(),
    };
    let fixed = fixed_dns(V4_INTERFACES, &guid);
    Ok(fixed.first().and_then(|s| s.parse().ok()).is_some_and(|ip| provider_of(IpAddr::V4(ip)).is_some()))
}

pub fn set_dns() -> windows::core::Result<Option<String>> {
    let provider = (*CHOSEN.lock().unwrap()).ok_or_else(|| failure("no DNS service picked"))?;
    let adapter = dns_adapter().ok_or_else(|| failure("no cable or Wi-Fi connection"))?;
    // Switching from one service to another keeps what was there before Vantix. A change
    // left on another adapter is put back first, since this one replaces it in the journal.
    let saved = match SavedDns::from_journal() {
        Some(saved) if saved.guid.eq_ignore_ascii_case(&adapter.guid) => saved,
        Some(other) => {
            other.put_back()?;
            SavedDns::read(&adapter.guid)
        }
        None => SavedDns::read(&adapter.guid),
    };
    let provider = &PROVIDERS[provider];
    set_family("ipv4", adapter.index, &provider.v4.map(|ip| ip.to_string()))?;
    // Only with IPv6 internet: IPv6 servers the PC can't reach would make every lookup
    // wait for them first.
    if adapter.ipv6 {
        set_family("ipv6", adapter.index, &provider.v6.map(|ip| ip.to_string()))?;
    }
    let _ = flush_dns();
    Ok(Some(saved.encode()))
}

pub fn restore_dns(previous: Option<&str>) -> windows::core::Result<()> {
    previous.and_then(SavedDns::decode).ok_or_else(|| failure("nothing saved to put back"))?.put_back()
}

/// Back to DHCP on the adapter in use, for DNS that was set before Vantix.
pub fn reset_dns() -> windows::core::Result<()> {
    let adapter = dns_adapter().ok_or_else(|| failure("no cable or Wi-Fi connection"))?;
    SavedDns { guid: adapter.guid, v4: Vec::new(), v6: Vec::new() }.put_back()
}

/// Time to an answer in ms, `None` on a timeout or a server failure.
fn lookup(socket: &UdpSocket, name: &str) -> Option<f64> {
    let id = random() as u16;
    let mut query = Vec::with_capacity(64);
    query.extend(id.to_be_bytes());
    query.extend([0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // recursion desired, one question
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend(label.as_bytes());
    }
    query.extend([0, 0, 1, 0, 1]); // end of name, type A, class IN

    let start = Instant::now();
    socket.send(&query).ok()?;
    let mut answer = [0u8; 1500];
    loop {
        let len = socket.recv(&mut answer).ok()?;
        // A late answer to an earlier query that timed out has another id.
        if len < 12 || answer[..2] != id.to_be_bytes() || answer[2] & 0x80 == 0 {
            if start.elapsed() > Duration::from_secs(1) {
                return None;
            }
            continue;
        }
        const SERVFAIL: u8 = 2;
        const REFUSED: u8 = 5;
        let code = answer[3] & 0x0f;
        return (code != SERVFAIL && code != REFUSED).then(|| start.elapsed().as_secs_f64() * 1000.0);
    }
}

fn median(mut values: Vec<f64>) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(f64::total_cmp);
    Some(values[values.len() / 2])
}

/// Std seeds every RandomState from the OS once per thread and steps it per call.
fn random() -> u64 {
    RandomState::new().hash_one(Instant::now())
}

// Driver settings of the adapter, the ones in its Advanced tab. A keyword is only touched
// when the driver lists it and takes the value, and the adapter restarts so the driver
// reads it, which drops the connection for a few seconds. The adapter's GUID goes first
// in what's saved, so undo finds the same adapter after a restart or with another one in use.

const NET_CLASS: &str = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";

pub struct Property {
    keyword: &'static str,
    /// Values that count as on; the first is the one written. `MAX` for a number set to
    /// the highest the driver takes.
    on: &'static [&'static str],
    /// `DEFAULT` for whatever the driver ships with.
    off: &'static str,
}

/// The highest value the driver lists for a numeric keyword.
const MAX: &str = "max";
/// The driver's own default for the keyword.
const DEFAULT: &str = "default";

pub struct AdapterSetting {
    id: &'static str,
    /// `Some(true)` only on Wi-Fi, `Some(false)` only on cable.
    wifi: Option<bool>,
    properties: &'static [Property],
    /// Offered only while off, since turning it off would only make things worse.
    one_way: bool,
}

pub const INTERRUPT_MODERATION: AdapterSetting = AdapterSetting {
    id: "interrupt-moderation-off",
    wifi: Some(false),
    properties: &[Property { keyword: "*InterruptModeration", on: &["0"], off: "1" }],
    one_way: false,
};

/// Realtek ships its own switches next to the standard one, and any of them left on
/// keeps the link dropping into low power between packets.
pub const EEE: AdapterSetting = AdapterSetting {
    id: "eee-off",
    wifi: Some(false),
    properties: &[
        Property { keyword: "*EEE", on: &["0"], off: "1" },
        Property { keyword: "AdvancedEEE", on: &["0"], off: "1" },
        Property { keyword: "EnableGreenEthernet", on: &["0"], off: "1" },
        Property { keyword: "GreenEthernet", on: &["0"], off: "1" },
    ],
    one_way: false,
};

pub const RSS: AdapterSetting = AdapterSetting {
    id: "rss-on",
    wifi: None,
    properties: &[Property { keyword: "*RSS", on: &["1"], off: "0" }],
    one_way: true,
};

/// Intel's keywords: 2 prefers 5 GHz, 3 prefers 6 GHz on the drivers that have it.
pub const WIFI_BAND: AdapterSetting = AdapterSetting {
    id: "wifi-band",
    wifi: Some(true),
    properties: &[Property { keyword: "RoamingPreferredBandType", on: &["2", "3"], off: "0" }],
    one_way: false,
};

/// Intel's 0 to 4, 2 being the default.
pub const WIFI_ROAMING: AdapterSetting = AdapterSetting {
    id: "wifi-roaming-low",
    wifi: Some(true),
    properties: &[Property { keyword: "RoamAggressiveness", on: &["0"], off: "2" }],
    one_way: false,
};

/// The card cutting large sends into packets itself. Off, the CPU does it, which some
/// Realtek and Intel cards need to stop sending in bursts that queue up behind a game.
pub const LSO: AdapterSetting = AdapterSetting {
    id: "lso-off",
    wifi: None,
    properties: &[
        Property { keyword: "*LsoV2IPv4", on: &["0"], off: "1" },
        Property { keyword: "*LsoV2IPv6", on: &["0"], off: "1" },
    ],
    one_way: false,
};

/// Pause frames: a busy switch or router can tell the card to stop sending for a moment.
pub const FLOW_CONTROL: AdapterSetting = AdapterSetting {
    id: "flow-control-off",
    wifi: Some(false),
    properties: &[Property { keyword: "*FlowControl", on: &["0"], off: DEFAULT }],
    one_way: false,
};

/// Holds incoming broadcast and multicast packets to wake the PC less often.
pub const PACKET_COALESCING: AdapterSetting = AdapterSetting {
    id: "packet-coalescing-off",
    wifi: None,
    properties: &[Property { keyword: "*PacketCoalescing", on: &["0"], off: "1" }],
    one_way: false,
};

/// Room for packets that arrive or leave in a burst before the CPU gets to them. Some
/// drivers ship well below what the card takes; a full ring drops packets.
pub const BUFFERS: AdapterSetting = AdapterSetting {
    id: "adapter-buffers-max",
    wifi: None,
    properties: &[
        Property { keyword: "*ReceiveBuffers", on: &[MAX], off: DEFAULT },
        Property { keyword: "*TransmitBuffers", on: &[MAX], off: DEFAULT },
    ],
    one_way: true,
};

/// The adapter's driver key, found by its GUID.
fn class_key(guid: &str) -> Option<String> {
    let id = |key: &str| reg::get_string(reg::HKEY_LOCAL_MACHINE, key, "NetCfgInstanceId").ok().flatten();
    reg::subkeys(reg::HKEY_LOCAL_MACHINE, NET_CLASS)
        .into_iter()
        .map(|sub| format!(r"{NET_CLASS}\{sub}"))
        .find(|key| id(key).is_some_and(|id| id.eq_ignore_ascii_case(guid)))
}

/// The value to write: `MAX` and `DEFAULT` come from the driver's list.
fn value_for(key: &str, keyword: &str, value: &str) -> Option<String> {
    let params = format!(r"{key}\Ndi\Params\{keyword}");
    let read = |name| reg::get_string(reg::HKEY_LOCAL_MACHINE, &params, name).ok().flatten();
    match value {
        MAX => read("max"),
        DEFAULT => read("Default"),
        value => Some(value.to_string()),
    }
}

/// Whether the driver lists the keyword and takes `value` for it.
fn accepts(key: &str, keyword: &str, value: &str) -> bool {
    let params = format!(r"{key}\Ndi\Params\{keyword}");
    let choices = format!(r"{params}\enum");
    let Some(value) = value_for(key, keyword, value) else { return false };
    reg::key_exists(reg::HKEY_LOCAL_MACHINE, &params)
        && (!reg::key_exists(reg::HKEY_LOCAL_MACHINE, &choices)
            || reg::get_string(reg::HKEY_LOCAL_MACHINE, &choices, &value).is_ok_and(|v| v.is_some()))
}

/// Whether the value in use counts as on. A number set to `MAX` is on at the driver's
/// highest or above it.
fn is_on(key: &str, p: &Property) -> bool {
    let Some(current) = property(key, p.keyword) else { return false };
    if p.on[0] == MAX {
        let number = |text: &str| text.trim().parse::<u64>().ok();
        let max = value_for(key, p.keyword, MAX).as_deref().and_then(number);
        return number(&current).zip(max).is_some_and(|(current, max)| current >= max);
    }
    p.on.contains(&current.as_str())
}

/// What the driver uses: the value set, or its default when none is.
fn property(key: &str, keyword: &str) -> Option<String> {
    let params = format!(r"{key}\Ndi\Params\{keyword}");
    reg::get_string(reg::HKEY_LOCAL_MACHINE, key, keyword)
        .ok()
        .flatten()
        .or_else(|| reg::get_string(reg::HKEY_LOCAL_MACHINE, &params, "Default").ok().flatten())
}

/// The GUID a journal entry was saved with, when the tweak is in the journal.
fn journal_guid(id: &str) -> Option<String> {
    let previous = crate::settings::load_changes().into_iter().find(|c| c.id == id)?.previous?;
    previous.split('|').next().map(String::from)
}

fn in_journal(id: &str) -> bool {
    crate::settings::load_changes().iter().any(|c| c.id == id)
}

/// The adapter Vantix changed, or else the one in use if it's the right kind. Returns
/// its GUID and driver key.
fn setting_adapter(id: &str, wifi: Option<bool>) -> Option<(String, String)> {
    let guid = match journal_guid(id) {
        Some(guid) => guid,
        None => dns_adapter().filter(|a| wifi.is_none_or(|w| w == a.wifi))?.guid,
    };
    let key = class_key(&guid)?;
    Some((guid, key))
}

fn changed_adapter(id: &str, wifi: Option<bool>) -> windows::core::Result<(String, String)> {
    setting_adapter(id, wifi).ok_or_else(|| failure("no adapter to change"))
}

fn present(setting: &AdapterSetting, key: &str) -> Vec<&'static Property> {
    setting.properties.iter().filter(|p| accepts(key, p.keyword, p.on[0])).collect()
}

fn setting_on(setting: &AdapterSetting, key: &str) -> bool {
    let properties = present(setting, key);
    !properties.is_empty() && properties.iter().all(|p| is_on(key, p))
}

fn shows_setting(setting: &AdapterSetting) -> bool {
    in_journal(setting.id)
        || setting_adapter(setting.id, setting.wifi).is_some_and(|(_, key)| {
            !present(setting, &key).is_empty() && !(setting.one_way && setting_on(setting, &key))
        })
}

fn read_setting(setting: &AdapterSetting) -> windows::core::Result<bool> {
    Ok(setting_adapter(setting.id, setting.wifi).is_some_and(|(_, key)| setting_on(setting, &key)))
}

/// Saved as "{guid}|keyword=old|keyword=-", "-" for a value that wasn't set.
fn apply_setting(setting: &AdapterSetting) -> windows::core::Result<Option<String>> {
    let (guid, key) = changed_adapter(setting.id, setting.wifi)?;
    let mut saved = vec![guid.clone()];
    for p in present(setting, &key) {
        if is_on(&key, p) {
            continue;
        }
        let Some(value) = value_for(&key, p.keyword, p.on[0]) else { continue };
        let written = reg::get_string(reg::HKEY_LOCAL_MACHINE, &key, p.keyword).and_then(|old| {
            saved.push(format!("{}={}", p.keyword, old.as_deref().unwrap_or("-")));
            reg::set_string(reg::HKEY_LOCAL_MACHINE, &key, p.keyword, &value)
        });
        // Nothing reaches the journal on an error, so what was already written goes back.
        if let Err(e) = written {
            let _ = revert_setting(Some(&saved.join("|")));
            return Err(e);
        }
    }
    let saved = saved.join("|");
    if let Err(e) = restart_adapter(&guid) {
        let _ = revert_setting(Some(&saved));
        return Err(e);
    }
    Ok(Some(saved))
}

fn revert_setting(previous: Option<&str>) -> windows::core::Result<()> {
    let mut parts = previous.unwrap_or_default().split('|');
    let guid = parts.next().unwrap_or_default();
    // An adapter that was removed has nothing left to put back.
    let Some(key) = class_key(guid) else { return Ok(()) };
    for (keyword, value) in parts.filter_map(|pair| pair.split_once('=')) {
        match value {
            "-" => reg::delete_value(reg::HKEY_LOCAL_MACHINE, &key, keyword)?,
            value => reg::set_string(reg::HKEY_LOCAL_MACHINE, &key, keyword, value)?,
        }
    }
    restart_adapter(guid)
}

fn reset_setting(setting: &AdapterSetting) -> windows::core::Result<()> {
    let (guid, key) = changed_adapter(setting.id, setting.wifi)?;
    for p in present(setting, &key) {
        if accepts(&key, p.keyword, p.off)
            && let Some(value) = value_for(&key, p.keyword, p.off)
        {
            reg::set_string(reg::HKEY_LOCAL_MACHINE, &key, p.keyword, &value)?;
        }
    }
    restart_adapter(&guid)
}

/// The driver only reads its settings when the adapter starts. One that's disabled is
/// left that way and reads them whenever it's turned back on. Waits for the link to come
/// back, so whatever reads the connection next finds it; an unplugged cable never does.
fn restart_adapter(guid: &str) -> windows::core::Result<()> {
    let was_up = adapters().iter().any(|a| a.guid.eq_ignore_ascii_case(guid) && a.up);
    let quoted = guid.replace('\'', "");
    tweaks::powershell(&format!(
        "$a = Get-NetAdapter | Where-Object InterfaceGuid -eq '{quoted}'; \
         if ($a -and $a.Status -ne 'Disabled') {{ \
         $a | Restart-NetAdapter -Confirm:$false -ErrorAction Stop }}"
    ))?;
    let start = Instant::now();
    while was_up && start.elapsed() < Duration::from_secs(20) {
        if adapters().iter().any(|a| a.guid.eq_ignore_ascii_case(guid) && a.up && a.gateway.is_some()) {
            break;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Ok(())
}

macro_rules! adapter_tweak {
    ($shown:ident, $read:ident, $apply:ident, $revert:ident, $reset:ident, $setting:expr) => {
        pub fn $shown() -> bool {
            shows_setting(&$setting)
        }
        pub fn $read() -> windows::core::Result<bool> {
            read_setting(&$setting)
        }
        pub fn $apply() -> windows::core::Result<Option<String>> {
            apply_setting(&$setting)
        }
        pub fn $revert(previous: Option<&str>) -> windows::core::Result<()> {
            revert_setting(previous)
        }
        pub fn $reset() -> windows::core::Result<()> {
            reset_setting(&$setting)
        }
    };
}

adapter_tweak!(
    shows_moderation,
    moderation_off,
    disable_moderation,
    restore_moderation,
    reset_moderation,
    INTERRUPT_MODERATION
);
adapter_tweak!(shows_eee, eee_off, disable_eee, restore_eee, reset_eee, EEE);
adapter_tweak!(shows_rss, rss_on, enable_rss, restore_rss, reset_rss, RSS);
adapter_tweak!(shows_wifi_band, wifi_band, set_wifi_band, restore_wifi_band, reset_wifi_band, WIFI_BAND);
adapter_tweak!(
    shows_wifi_roaming,
    wifi_roaming_low,
    set_wifi_roaming,
    restore_wifi_roaming,
    reset_wifi_roaming,
    WIFI_ROAMING
);
adapter_tweak!(shows_lso, lso_off, disable_lso, restore_lso, reset_lso, LSO);
adapter_tweak!(
    shows_flow_control,
    flow_control_off,
    disable_flow_control,
    restore_flow_control,
    reset_flow_control,
    FLOW_CONTROL
);
adapter_tweak!(
    shows_coalescing,
    coalescing_off,
    disable_coalescing,
    restore_coalescing,
    reset_coalescing,
    PACKET_COALESCING
);
adapter_tweak!(shows_buffers, buffers_max, raise_buffers, restore_buffers, reset_buffers, BUFFERS);

// "Allow the computer to turn off this device to save power". Bit 0x10 unticks it, 0x08
// with it stops the wake-up handling Windows adds on top. Windows only uses it on laptops
// and on USB adapters, so desktops with a card on the board don't see the tweak.

const ADAPTER_SLEEP: &str = "adapter-sleep-off";
const NO_POWER_OFF: u32 = 0x18;

fn shows_adapter_sleep_on(key: &str) -> bool {
    let usb = reg::get_string(reg::HKEY_LOCAL_MACHINE, key, "DeviceInstanceID")
        .ok()
        .flatten()
        .is_some_and(|id| id.starts_with(r"USB\"));
    usb || crate::boost::has_battery()
}

pub fn shows_adapter_sleep() -> bool {
    in_journal(ADAPTER_SLEEP)
        || setting_adapter(ADAPTER_SLEEP, None).is_some_and(|(_, key)| shows_adapter_sleep_on(&key))
}

pub fn adapter_sleep_off() -> windows::core::Result<bool> {
    let Some((_, key)) = setting_adapter(ADAPTER_SLEEP, None) else { return Ok(false) };
    let value = reg::get_dword(reg::HKEY_LOCAL_MACHINE, &key, "PnPCapabilities")?;
    Ok(value.is_some_and(|v| v & NO_POWER_OFF == NO_POWER_OFF))
}

/// Saved as "{guid}|old", "-" when the value wasn't set.
pub fn disable_adapter_sleep() -> windows::core::Result<Option<String>> {
    let (guid, key) = changed_adapter(ADAPTER_SLEEP, None)?;
    let old = reg::get_dword(reg::HKEY_LOCAL_MACHINE, &key, "PnPCapabilities")?;
    reg::set_dword(reg::HKEY_LOCAL_MACHINE, &key, "PnPCapabilities", old.unwrap_or(0) | NO_POWER_OFF)?;
    Ok(Some(format!("{guid}|{}", old.map_or("-".into(), |v| v.to_string()))))
}

pub fn restore_adapter_sleep(previous: Option<&str>) -> windows::core::Result<()> {
    let (guid, old) = previous.unwrap_or_default().split_once('|').unwrap_or_default();
    let Some(key) = class_key(guid) else { return Ok(()) };
    match old.parse() {
        Ok(value) => reg::set_dword(reg::HKEY_LOCAL_MACHINE, &key, "PnPCapabilities", value),
        Err(_) => reg::delete_value(reg::HKEY_LOCAL_MACHINE, &key, "PnPCapabilities"),
    }
}

pub fn reset_adapter_sleep() -> windows::core::Result<()> {
    let (_, key) = changed_adapter(ADAPTER_SLEEP, None)?;
    let value = reg::get_dword(reg::HKEY_LOCAL_MACHINE, &key, "PnPCapabilities")?.unwrap_or(0);
    reg::set_dword(reg::HKEY_LOCAL_MACHINE, &key, "PnPCapabilities", value & !NO_POWER_OFF)
}

// More repairs from the Repair tab. The ones with a journal entry keep one, so undo puts
// back exactly what was there before Vantix touched it.

/// WinINet and WinHTTP proxy leftovers: a VPN or malware set it once and it stayed, and
/// everything else sees "no internet" while requests die on a dead address. WinHTTP is
/// the machine-wide one; `netsh winhttp` keeps it in a binary blob under Internet Settings.
pub const PROXY_TWEAK: &str = "proxy-reset";
const PROXY_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const WINHTTP_CONNECTIONS: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";
const WINHTTP_SETTINGS: &str = "WinHttpSettings";
/// WinINet keeps the user's settings twice: the plain values above and this blob, which
/// is the one it trusts. Clearing only the values lets it write them back from here.
const USER_CONNECTIONS: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";
const USER_SETTINGS: &str = "DefaultConnectionSettings";

/// Whether a connection settings blob enables a proxy. WinHTTP's and WinINet's share the
/// layout (little endian): version, counter, flags (bit 0 always set, bit 1 manual proxy,
/// bit 2 setup script, bit 3 auto detect), then proxy, bypass and setup script as length
/// prefixed ASCII strings. Windows keeps a blob even for direct access, so a missing
/// value and a flags-only blob both mean none. Auto detect alone doesn't count: Windows
/// ships with it on, and it only matters when a script is found (see `wpad_script`).
fn winhttp_has_proxy(blob: &[u8]) -> bool {
    let words =
        |at: usize| blob.get(at..at + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).unwrap_or(0);
    if blob.len() < 12 {
        return false;
    }
    let flags = words(8);
    let mut at = 12;
    let mut strings = [""; 3];
    let mut present = [false; 3];
    for i in 0..3 {
        let len = words(at) as usize;
        at += 4;
        if let Some(text) = blob.get(at..at + len) {
            present[i] = len > 0;
            strings[i] = std::str::from_utf8(text).unwrap_or("");
        }
        at += len;
    }
    let manual = flags & 2 != 0 && present[0] && !strings[0].is_empty();
    let script = flags & 4 != 0 && present[2] && !strings[2].is_empty();
    manual || script
}

/// Whether any proxy is set where it would break traffic: the user's WinINet one or the
/// machine-wide WinHTTP one.
pub fn proxy_set() -> windows::core::Result<bool> {
    let user = reg::get_dword(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyEnable")?.is_some_and(|v| v != 0)
        || reg::get_string(reg::HKEY_CURRENT_USER, PROXY_KEY, "AutoConfigURL")?
            .is_some_and(|s| !s.is_empty());
    let machine = reg::get_binary(reg::HKEY_LOCAL_MACHINE, WINHTTP_CONNECTIONS, WINHTTP_SETTINGS)?
        .is_some_and(|blob| winhttp_has_proxy(&blob));
    let blob = reg::get_binary(reg::HKEY_CURRENT_USER, USER_CONNECTIONS, USER_SETTINGS)?
        .is_some_and(|blob| winhttp_has_proxy(&blob));
    Ok(user || machine || blob)
}

/// The flags word of the user's connection settings blob.
fn connection_flags() -> Option<u32> {
    let blob = reg::get_binary(reg::HKEY_CURRENT_USER, USER_CONNECTIONS, USER_SETTINGS).ok()??;
    blob.get(8..12).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// The blob with manual proxy and setup script turned off, and auto detect too when it
/// found a script. The strings stay, as Windows leaves them when the boxes are unticked;
/// the counter goes up so WinINet reads it as new.
fn direct_blob(mut blob: Vec<u8>, auto_detect_off: bool) -> Vec<u8> {
    if blob.len() >= 12 {
        let word = |b: &[u8], at: usize| u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]);
        let counter = word(&blob, 4).wrapping_add(1);
        let mut flags = (word(&blob, 8) & !(2 | 4)) | 1;
        if auto_detect_off {
            flags &= !8;
        }
        blob[4..8].copy_from_slice(&counter.to_le_bytes());
        blob[8..12].copy_from_slice(&flags.to_le_bytes());
    }
    blob
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        text.push(HEX[(b >> 4) as usize] as char);
        text.push(HEX[(b & 15) as usize] as char);
    }
    text
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// Tells running programs the proxy changed, so no logoff is needed.
fn notify_proxy_changed() {
    unsafe {
        let _ = windows::Win32::Networking::WinInet::InternetSetOptionW(
            None,
            INTERNET_OPTION_SETTINGS_CHANGED,
            None,
            0,
        );
        let _ =
            windows::Win32::Networking::WinInet::InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0);
    }
}

/// Saved as "enable|server|override|autoproxy|winhttp-hex|connections-hex", `-` for
/// nothing set. The blobs are raw hex, so undo writes back exactly what was there.
pub fn reset_proxy() -> windows::core::Result<Option<String>> {
    let mut fields = Vec::new();
    let dashed =
        |value: windows::core::Result<Option<String>>| value.ok().flatten().unwrap_or_else(|| "-".into());
    fields.push(match reg::get_dword(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyEnable")? {
        Some(enable) => enable.to_string(),
        None => "-".into(),
    });
    for name in ["ProxyServer", "ProxyOverride", "AutoConfigURL"] {
        let value = dashed(reg::get_string(reg::HKEY_CURRENT_USER, PROXY_KEY, name));
        fields.push(if value.is_empty() { "-".into() } else { value });
    }
    let winhttp = reg::get_binary(reg::HKEY_LOCAL_MACHINE, WINHTTP_CONNECTIONS, WINHTTP_SETTINGS)?;
    fields.push(winhttp.as_deref().map(hex_encode).unwrap_or_else(|| "-".into()));
    let user = reg::get_binary(reg::HKEY_CURRENT_USER, USER_CONNECTIONS, USER_SETTINGS)?;
    fields.push(user.as_deref().map(hex_encode).unwrap_or_else(|| "-".into()));
    let saved = fields.join("|");

    reg::set_dword(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyEnable", 0)?;
    for name in ["ProxyServer", "ProxyOverride", "AutoConfigURL"] {
        let _ = reg::delete_value(reg::HKEY_CURRENT_USER, PROXY_KEY, name);
    }
    if let Some(blob) = user {
        let blob = direct_blob(blob, WPAD_FOUND.load(Ordering::Relaxed));
        reg::set_binary(reg::HKEY_CURRENT_USER, USER_CONNECTIONS, USER_SETTINGS, &blob)?;
    }
    tweaks::run("netsh.exe", &["winhttp", "reset", "proxy"])?;
    notify_proxy_changed();
    Ok(Some(saved))
}

/// The card shows reset (off) while any of them is set, whatever it's set to, or while
/// the last diagnosis saw auto detect find a script.
pub fn shows_proxy() -> bool {
    in_journal(PROXY_TWEAK) || WPAD_FOUND.load(Ordering::Relaxed) || proxy_set().unwrap_or(false)
}

/// True when no proxy is set, which is what this tweak applies.
pub fn proxy_clear() -> windows::core::Result<bool> {
    let wpad = WPAD_FOUND.load(Ordering::Relaxed) && connection_flags().is_some_and(|flags| flags & 8 != 0);
    Ok(!proxy_set()? && !wpad)
}

/// The tweak is "off" when no proxy is set, so applying and resetting are the same job.
pub fn clear_proxy() -> windows::core::Result<Option<String>> {
    reset_proxy()
}

pub fn clear_proxy_only() -> windows::core::Result<()> {
    reset_proxy().map(drop)
}

pub fn restore_proxy(previous: Option<&str>) -> windows::core::Result<()> {
    let mut parts = previous.unwrap_or_default().split('|');
    let next = |parts: &mut std::str::Split<'_, char>| parts.next().unwrap_or("-").to_string();
    let (enable, server, override_list, autoproxy, winhttp) =
        (next(&mut parts), next(&mut parts), next(&mut parts), next(&mut parts), next(&mut parts));
    // Entries saved before the user blob was kept have no sixth field: leave it alone.
    let user = parts.next();
    if enable == "-" {
        reg::delete_value(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyEnable")?;
    } else if let Ok(value) = enable.parse::<u32>() {
        reg::set_dword(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyEnable", value)?;
    } else {
        reg::delete_value(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyEnable")?;
    }
    if server == "-" {
        reg::delete_value(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyServer")?;
    } else {
        reg::set_string(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyServer", &server)?;
    }
    if override_list == "-" {
        reg::delete_value(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyOverride")?;
    } else {
        reg::set_string(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyOverride", &override_list)?;
    }
    if autoproxy == "-" {
        reg::delete_value(reg::HKEY_CURRENT_USER, PROXY_KEY, "AutoConfigURL")?;
    } else {
        reg::set_string(reg::HKEY_CURRENT_USER, PROXY_KEY, "AutoConfigURL", &autoproxy)?;
    }
    if winhttp == "-" {
        reg::delete_value(reg::HKEY_LOCAL_MACHINE, WINHTTP_CONNECTIONS, WINHTTP_SETTINGS)?;
    } else if let Some(blob) = hex_decode(&winhttp) {
        reg::set_binary(reg::HKEY_LOCAL_MACHINE, WINHTTP_CONNECTIONS, WINHTTP_SETTINGS, &blob)?;
    } else {
        tweaks::run("netsh.exe", &["winhttp", "reset", "proxy"])?;
    }
    match user {
        Some("-") => reg::delete_value(reg::HKEY_CURRENT_USER, USER_CONNECTIONS, USER_SETTINGS)?,
        Some(hex) => {
            if let Some(blob) = hex_decode(hex) {
                reg::set_binary(reg::HKEY_CURRENT_USER, USER_CONNECTIONS, USER_SETTINGS, &blob)?;
            }
        }
        None => {}
    }
    notify_proxy_changed();
    Ok(())
}

/// ARP and neighbor cache: a stale entry for the router makes the first packets to a
/// rebooted one go nowhere until it times out.
pub fn clear_arp() -> windows::core::Result<()> {
    tweaks::run("netsh.exe", &["interface", "ip", "delete", "arpcache"]).map(drop)
}

/// A clock even a few minutes off breaks TLS: every site answers with a certificate
/// "from the future" or long expired.
pub fn sync_clock() -> windows::core::Result<()> {
    tweaks::run("w32tm.exe", &["/resync", "/force"]).map(drop)
}

/// Reconnects: a Wi-Fi link stuck on a bad decision, or half a TCP window kept open
/// after a handshake that never finished, heals with a fresh start of the adapter.
pub fn restart_connection() -> windows::core::Result<()> {
    let Some(adapter) = connection() else {
        return Err(failure("no connected adapter"));
    };
    restart_adapter(&adapter.guid)
}

/// The hosts file: a line pointing a domain somewhere sends anything that touches it
/// there. Common leftovers: update servers, antivirus, sites blocked once and forgotten.
const HOSTS_PATH: &str = r"C:\Windows\System32\drivers\etc\hosts";
const HOSTS_BACKUP: &str = r"C:\Windows\System32\drivers\etc\hosts.vantix.bak";

/// Names whose redirection breaks browsing or updates. Exact names only: privacy lists
/// that send telemetry hosts like vortex.data.microsoft.com to 0.0.0.0 are someone's
/// choice and stay. Windows Update is the exception, any name under it counts.
const HOSTS_OF_INTEREST: [&str; 11] = [
    "google.com",
    "www.google.com",
    "microsoft.com",
    "www.microsoft.com",
    "update.microsoft.com",
    "windowsupdate.com",
    "apple.com",
    "www.apple.com",
    "cloudflare.com",
    "steamcommunity.com",
    "store.steampowered.com",
];

fn hosts_match(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    HOSTS_OF_INTEREST.contains(&host.as_str()) || host.ends_with(".windowsupdate.com")
}

/// Whether one raw line of the file redirects a name above. Comments after `#` don't count.
fn hosts_blocking(line: &[u8]) -> bool {
    let text = String::from_utf8_lossy(line);
    let entry = text.split('#').next().unwrap_or("");
    entry.split_whitespace().skip(1).any(hosts_match)
}

/// (total entries, blocking ones), `None` when the file is missing or unreadable.
pub fn hosts_state() -> Option<(usize, usize)> {
    hosts_state_in(HOSTS_PATH)
}

pub fn hosts_state_in(path: &str) -> Option<(usize, usize)> {
    let bytes = std::fs::read(path).ok()?;
    let entries: Vec<&[u8]> = bytes
        .split(|&b| b == b'\n')
        .filter(|line| {
            let line = line.trim_ascii();
            !line.is_empty() && !line.starts_with(b"#")
        })
        .collect();
    let blocking = entries.iter().filter(|line| hosts_blocking(line)).count();
    Some((entries.len(), blocking))
}

/// The lines the repair takes out, as text, for the confirmation.
pub fn hosts_blocking_lines() -> Vec<String> {
    let bytes = std::fs::read(HOSTS_PATH).unwrap_or_default();
    bytes
        .split(|&b| b == b'\n')
        .filter(|line| hosts_blocking(line))
        .map(|line| String::from_utf8_lossy(line.trim_ascii()).into_owned())
        .collect()
}

/// Whether any hosts line gets in the way of a name above, which is what the card
/// offers to clean.
pub fn shows_hosts() -> bool {
    in_journal(HOSTS_TWEAK) || hosts_state().is_some_and(|(_, blocking)| blocking > 0)
}

/// "On" in the toggle's terms would be blocks in place; the change makes off.
pub fn hosts_normal() -> windows::core::Result<bool> {
    Ok(hosts_state().is_some_and(|(_, blocking)| blocking == 0))
}

pub fn clear_hosts() -> windows::core::Result<()> {
    reset_hosts().map(drop)
}

/// Saved as the number of lines taken out; the bytes themselves are the backup file.
pub fn reset_hosts() -> windows::core::Result<Option<String>> {
    reset_hosts_in(HOSTS_PATH, HOSTS_BACKUP)
}

/// Works on raw bytes split at `\n`, so every kept line goes back exactly as it was,
/// line ending and ANSI characters included.
pub fn reset_hosts_in(path: &str, backup: &str) -> windows::core::Result<Option<String>> {
    let Some((_, blocking)) = hosts_state_in(path) else { return Err(failure("hosts file is missing")) };
    if blocking > 0 {
        std::fs::copy(path, backup)?;
        let bytes = std::fs::read(path)?;
        let kept: Vec<&[u8]> = bytes.split(|&b| b == b'\n').filter(|line| !hosts_blocking(line)).collect();
        if let Err(e) = std::fs::write(path, kept.join(&b'\n')) {
            let readonly = std::fs::metadata(path).is_ok_and(|m| m.permissions().readonly());
            if readonly {
                return Err(failure("hosts file is read-only, remove the read-only flag first"));
            }
            return Err(windows::core::Error::new(windows::Win32::Foundation::E_FAIL, e.to_string()));
        }
        let _ = flush_dns();
    }
    Ok(Some(blocking.to_string()))
}

pub fn restore_hosts(_: Option<&str>) -> windows::core::Result<()> {
    restore_hosts_in(HOSTS_PATH, HOSTS_BACKUP)
}

pub fn restore_hosts_in(path: &str, backup: &str) -> windows::core::Result<()> {
    std::fs::copy(backup, path)?;
    std::fs::remove_file(backup)?;
    let _ = flush_dns();
    Ok(())
}

/// IPv6 component of one adapter. Turned off only when the diagnosis says the adapter
/// has a global address with no valid routing. Undo is a separate entry, from the
/// journal, so nothing is silently turned off.
pub const IPV6_TWEAK: &str = "ipv6-adapter-off";
/// The id used in the journal for the hosts repair.
pub const HOSTS_TWEAK: &str = "hosts-reset";

/// The card shows only when the diagnosis warned about IPv6, or while the change is in
/// the journal for undo. Global IPv6 off stays out of the app.
pub fn shows_ipv6() -> bool {
    in_journal(IPV6_TWEAK)
        || RESULTS
            .lock()
            .unwrap()
            .iter()
            .any(|(layer, status, _)| *layer == Layer::Ipv6 && *status == Status::Warning)
}

/// From the adapter's own flags, so reading the cards doesn't start a PowerShell.
pub fn ipv6_off() -> windows::core::Result<bool> {
    Ok(connection().is_some_and(|adapter| !adapter.ipv6_bound))
}

/// An adapter name as a PowerShell single-quoted string.
fn quoted(name: &str) -> String {
    format!("'{}'", name.replace('\'', "''"))
}

/// Saved as the adapter's GUID, so undo finds the same adapter after a restart.
pub fn disable_ipv6() -> windows::core::Result<Option<String>> {
    let Some(adapter) = connection() else { return Err(failure("no connected adapter")) };
    tweaks::powershell(&format!(
        "Disable-NetAdapterBinding -Name {} -ComponentID ms_tcpip6 -ErrorAction Stop",
        quoted(&adapter.name)
    ))?;
    Ok(Some(adapter.guid))
}

pub fn restore_ipv6(previous: Option<&str>) -> windows::core::Result<()> {
    // An adapter that was removed has nothing left to put back.
    let Some(adapter) =
        adapters().into_iter().find(|a| a.guid.eq_ignore_ascii_case(previous.unwrap_or_default()))
    else {
        return Ok(());
    };
    tweaks::powershell(&format!(
        "Enable-NetAdapterBinding -Name {} -ComponentID ms_tcpip6 -ErrorAction Stop",
        quoted(&adapter.name)
    ))?;
    Ok(())
}

pub fn enable_ipv6() -> windows::core::Result<()> {
    restore_ipv6(Some(&connection().map(|c| c.guid).unwrap_or_default()))
}

// Name resolution that answers anyone on the network. Turning these off is about
// security, not speed: on a shared network, a device can answer an LLMNR or NetBIOS
// lookup for a name it doesn't own and collect the PC's sign-in hash.

const DNS_POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient";
const NETBT_INTERFACES: &str = r"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces";
/// NetbiosOptions: 0 from DHCP, 1 on, 2 off.
const NETBIOS_OFF: u32 = 2;

pub fn llmnr_off() -> windows::core::Result<bool> {
    Ok(reg::get_dword(reg::HKEY_LOCAL_MACHINE, DNS_POLICY, "EnableMulticast")? == Some(0))
}

/// Saved as the old value, `-` when there was none.
pub fn disable_llmnr() -> windows::core::Result<Option<String>> {
    let old = reg::get_dword(reg::HKEY_LOCAL_MACHINE, DNS_POLICY, "EnableMulticast")?;
    reg::set_dword(reg::HKEY_LOCAL_MACHINE, DNS_POLICY, "EnableMulticast", 0)?;
    Ok(Some(old.map_or("-".into(), |v| v.to_string())))
}

pub fn restore_llmnr(previous: Option<&str>) -> windows::core::Result<()> {
    match previous.and_then(|p| p.parse().ok()) {
        Some(value) => reg::set_dword(reg::HKEY_LOCAL_MACHINE, DNS_POLICY, "EnableMulticast", value),
        None => reg::delete_value(reg::HKEY_LOCAL_MACHINE, DNS_POLICY, "EnableMulticast"),
    }
}

pub fn reset_llmnr() -> windows::core::Result<()> {
    reg::delete_value(reg::HKEY_LOCAL_MACHINE, DNS_POLICY, "EnableMulticast")
}

/// Every adapter's NetBIOS setting, by its key under NetBT.
fn netbios_options() -> Vec<(String, Option<u32>)> {
    reg::subkeys(reg::HKEY_LOCAL_MACHINE, NETBT_INTERFACES)
        .into_iter()
        .filter(|sub| sub.starts_with("Tcpip_"))
        .map(|sub| {
            let value = reg::get_dword(
                reg::HKEY_LOCAL_MACHINE,
                &format!(r"{NETBT_INTERFACES}\{sub}"),
                "NetbiosOptions",
            );
            (sub, value.ok().flatten())
        })
        .collect()
}

pub fn shows_netbios() -> bool {
    !netbios_options().is_empty()
}

pub fn netbios_off() -> windows::core::Result<bool> {
    let options = netbios_options();
    Ok(!options.is_empty() && options.iter().all(|(_, value)| *value == Some(NETBIOS_OFF)))
}

/// Every adapter, the ones not in use too: a VPN or a second card brings the lookups
/// right back. Saved as "Tcpip_{guid}=old|...", `-` for no value.
pub fn disable_netbios() -> windows::core::Result<Option<String>> {
    let mut saved = Vec::new();
    for (sub, old) in netbios_options() {
        if old == Some(NETBIOS_OFF) {
            continue;
        }
        let key = format!(r"{NETBT_INTERFACES}\{sub}");
        if let Err(e) = reg::set_dword(reg::HKEY_LOCAL_MACHINE, &key, "NetbiosOptions", NETBIOS_OFF) {
            let _ = restore_netbios(Some(&saved.join("|")));
            return Err(e);
        }
        saved.push(format!("{sub}={}", old.map_or("-".into(), |v| v.to_string())));
    }
    Ok(Some(saved.join("|")))
}

pub fn restore_netbios(previous: Option<&str>) -> windows::core::Result<()> {
    for (sub, value) in previous.unwrap_or_default().split('|').filter_map(|pair| pair.split_once('=')) {
        let key = format!(r"{NETBT_INTERFACES}\{sub}");
        // An adapter that was removed has nothing left to put back.
        if !reg::key_exists(reg::HKEY_LOCAL_MACHINE, &key) {
            continue;
        }
        match value.parse() {
            Ok(value) => reg::set_dword(reg::HKEY_LOCAL_MACHINE, &key, "NetbiosOptions", value)?,
            Err(_) => reg::delete_value(reg::HKEY_LOCAL_MACHINE, &key, "NetbiosOptions")?,
        }
    }
    Ok(())
}

/// Back to "from DHCP", what Windows ships with.
pub fn reset_netbios() -> windows::core::Result<()> {
    for (sub, _) in netbios_options() {
        reg::set_dword(reg::HKEY_LOCAL_MACHINE, &format!(r"{NETBT_INTERFACES}\{sub}"), "NetbiosOptions", 0)?;
    }
    Ok(())
}

// DNS over HTTPS for the service picked on the DNS tab. Windows 11 keeps a list of
// encrypted servers; with "autoupgrade" on, every query to that address goes over HTTPS
// instead of plain UDP. Set per address, so it follows the service whichever adapter
// uses it. No UDP fallback: if the HTTPS server can't be reached, names stop resolving
// rather than silently going out in the clear.

pub const DOH_TWEAK: &str = "dns-over-https";

/// The public service set by hand on the adapter in use.
fn set_provider() -> Option<usize> {
    let adapter = dns_adapter()?;
    let first = fixed_dns(V4_INTERFACES, &adapter.guid).first()?.parse().ok()?;
    provider_of(IpAddr::V4(first))
}

/// One address in Windows' list of encrypted DNS servers.
#[derive(Clone, Debug, PartialEq)]
struct DohEntry {
    template: String,
    /// Queries to the address go over HTTPS.
    auto: bool,
    /// Plain DNS is tried when HTTPS fails.
    fallback: bool,
}

/// What `netsh dns show encryption` says about one address, `None` when it isn't listed.
/// The labels are translated, the template and the yes/no values aren't.
fn doh_entry(server: &str) -> Option<DohEntry> {
    let out = tweaks::run("netsh.exe", &["dns", "show", "encryption", &format!("server={server}")]).ok()?;
    let values: Vec<&str> =
        out.lines().filter_map(|line| line.split_once(": ").map(|(_, value)| value.trim())).collect();
    match values[..] {
        [template, auto, fallback, ..] if template.starts_with("https://") => Some(DohEntry {
            template: template.to_string(),
            auto: auto == "yes",
            fallback: fallback == "yes",
        }),
        _ => None,
    }
}

/// Writes one address and reads it back: netsh exits with 0 even when it rejects the
/// command, so its exit code says nothing. `set` needs the template too, or it's refused.
fn write_doh(server: &str, entry: Option<&DohEntry>) -> windows::core::Result<()> {
    let target = format!("server={server}");
    match entry {
        Some(entry) => {
            let verb = if doh_entry(server).is_some() { "set" } else { "add" };
            let template = format!("dohtemplate={}", entry.template);
            let auto = format!("autoupgrade={}", if entry.auto { "yes" } else { "no" });
            let fallback = format!("udpfallback={}", if entry.fallback { "yes" } else { "no" });
            tweaks::run("netsh.exe", &["dns", verb, "encryption", &target, &template, &auto, &fallback])?;
        }
        None => {
            tweaks::run("netsh.exe", &["dns", "delete", "encryption", &target])?;
        }
    }
    if doh_entry(server).as_ref() != entry {
        return Err(failure(&format!("Windows didn't take the DNS over HTTPS setting for {server}")));
    }
    Ok(())
}

fn doh_servers(provider: usize) -> Vec<String> {
    let p = &PROVIDERS[provider];
    p.v4.iter().map(|ip| ip.to_string()).chain(p.v6.iter().map(|ip| ip.to_string())).collect()
}

pub fn shows_doh() -> bool {
    crate::boost::windows_build() >= 22000 && (in_journal(DOH_TWEAK) || set_provider().is_some())
}

pub fn doh_on() -> windows::core::Result<bool> {
    let Some(provider) = set_provider() else { return Ok(false) };
    Ok(doh_entry(&PROVIDERS[provider].v4[0].to_string()).is_some_and(|entry| entry.auto))
}

/// Saved as "address=template,auto,fallback|address=-", `-` for an address Vantix added.
pub fn enable_doh() -> windows::core::Result<Option<String>> {
    enable_doh_for(set_provider().ok_or_else(|| failure("no public DNS service set"))?)
}

fn enable_doh_for(provider: usize) -> windows::core::Result<Option<String>> {
    let mut saved = Vec::new();
    for server in doh_servers(provider) {
        let old = doh_entry(&server);
        saved.push(match &old {
            Some(e) => format!("{server}={},{},{}", e.template, yes_no(e.auto), yes_no(e.fallback)),
            None => format!("{server}=-"),
        });
        let template = old.map_or_else(|| PROVIDERS[provider].doh.to_string(), |e| e.template);
        if let Err(e) = write_doh(&server, Some(&DohEntry { template, auto: true, fallback: false })) {
            let _ = restore_doh(Some(&saved.join("|")));
            return Err(e);
        }
    }
    let _ = flush_dns();
    Ok(Some(saved.join("|")))
}

fn yes_no(on: bool) -> &'static str {
    if on { "yes" } else { "no" }
}

pub fn restore_doh(previous: Option<&str>) -> windows::core::Result<()> {
    for (server, value) in previous.unwrap_or_default().split('|').filter_map(|pair| pair.split_once('=')) {
        // Addresses hold no commas and templates rarely do, so split from the right.
        let entry = value.rsplitn(3, ',').collect::<Vec<_>>();
        let entry = match entry[..] {
            [fallback, auto, template] => {
                Some(DohEntry { template: template.into(), auto: auto == "yes", fallback: fallback == "yes" })
            }
            // Saved before the template was kept: the address was listed already.
            [fallback, auto] => {
                doh_entry(server).map(|e| DohEntry { auto: auto == "yes", fallback: fallback == "yes", ..e })
            }
            _ => None,
        };
        write_doh(server, entry.as_ref())?;
    }
    let _ = flush_dns();
    Ok(())
}

/// Turns the upgrade off for the service in use, for DoH that was on before Vantix.
pub fn reset_doh() -> windows::core::Result<()> {
    let provider = set_provider().ok_or_else(|| failure("no public DNS service set"))?;
    for server in doh_servers(provider) {
        if let Some(entry) = doh_entry(&server) {
            write_doh(&server, Some(&DohEntry { auto: false, ..entry }))?;
        }
    }
    let _ = flush_dns();
    Ok(())
}

pub fn uses_wifi() -> bool {
    connection().is_some_and(|c| c.wifi)
}

// Delivery Optimization can send Windows and Store updates to PCs on the internet, which
// fills the upload and lags everything else on the line. Only offered when it's set to
// do that; the Windows default shares with the local network alone, which this keeps.
// A policy means the PC is managed, so the setting is left alone then.

const DO_SETTINGS: &str = r"S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings";
const DO_POLICY: &str = r"SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization";
const DO_UPLOAD: &str = "do-upload-off";
/// 2 shares within a group that can span the internet, 3 with anyone on it.
const DO_INTERNET: [u32; 2] = [2, 3];
const DO_LAN: u32 = 1;

fn do_mode() -> windows::core::Result<Option<u32>> {
    reg::get_dword(windows::Win32::System::Registry::HKEY_USERS, DO_SETTINGS, "DownloadMode")
}

fn do_managed() -> bool {
    reg::get_dword(reg::HKEY_LOCAL_MACHINE, DO_POLICY, "DODownloadMode").is_ok_and(|v| v.is_some())
}

pub fn shows_do_upload() -> bool {
    in_journal(DO_UPLOAD) || !do_managed() && !do_upload_off().unwrap_or(true)
}

pub fn do_upload_off() -> windows::core::Result<bool> {
    Ok(!do_mode()?.is_some_and(|m| DO_INTERNET.contains(&m)))
}

/// The service reads the setting when it starts and starts again on its own when needed.
fn set_do_mode(mode: Option<u32>) -> windows::core::Result<()> {
    let root = windows::Win32::System::Registry::HKEY_USERS;
    match mode {
        Some(mode) => reg::set_dword(root, DO_SETTINGS, "DownloadMode", mode)?,
        None => reg::delete_value(root, DO_SETTINGS, "DownloadMode")?,
    }
    let _ = tweaks::run("sc.exe", &["stop", "DoSvc"]);
    Ok(())
}

pub fn disable_do_upload() -> windows::core::Result<Option<String>> {
    let old = do_mode()?;
    set_do_mode(Some(DO_LAN))?;
    Ok(Some(old.map_or("-".into(), |v| v.to_string())))
}

pub fn restore_do_upload(previous: Option<&str>) -> windows::core::Result<()> {
    set_do_mode(previous.and_then(|v| v.parse().ok()))
}

pub fn reset_do_upload() -> windows::core::Result<()> {
    set_do_mode(Some(3))
}

// Upload limits per program, from the Network use tab. A QoS policy throttles what one
// program sends: a cloud sync or backup filling the upload is what makes the ping of
// everything else climb. Windows can't hold back what a program receives, so downloads
// aren't touched. The policies themselves are the state, all named with Vantix's prefix;
// the journal holds one entry and undoing it removes them all.

pub const LIMIT_TWEAK: &str = "upload-limits";
const LIMIT_PREFIX: &str = "Vantix upload ";

/// Program and bits per second the next apply sets, picked right before asking.
static CHOSEN_LIMIT: Mutex<Option<(String, u64)>> = Mutex::new(None);
/// What the last read found, for the Network use tab to show without asking PowerShell
/// every second.
static LIMITS: Mutex<Vec<(String, u64)>> = Mutex::new(Vec::new());

pub fn choose_limit(program: &str, bits: u64) {
    *CHOSEN_LIMIT.lock().unwrap() = Some((program.into(), bits));
}

pub fn chosen_limit() -> Option<(String, u64)> {
    CHOSEN_LIMIT.lock().unwrap().clone()
}

/// Programs with a limit, as last read, with their rate in bits per second.
pub fn known_limits() -> Vec<(String, u64)> {
    LIMITS.lock().unwrap().clone()
}

/// A program the policy can name on its own. Services share svchost.exe, so limiting it
/// would slow Windows Update and everything else with it.
pub fn limitable(program: &str) -> bool {
    let lower = program.to_ascii_lowercase();
    lower.ends_with(".exe")
        && !program.contains(['\'', '"', '\\'])
        && !matches!(lower.as_str(), "svchost.exe" | "system" | "vantix.exe")
}

fn read_limits() -> windows::core::Result<Vec<(String, u64)>> {
    let out = tweaks::powershell(&format!(
        "Get-NetQosPolicy | Where-Object Name -like '{LIMIT_PREFIX}*' | \
         ForEach-Object {{ \"$($_.AppPathName)|$($_.ThrottleRate)\" }}"
    ))?;
    let limits: Vec<(String, u64)> = out
        .lines()
        .filter_map(|line| line.trim().split_once('|'))
        .filter_map(|(program, rate)| Some((program.to_string(), rate.parse().ok()?)))
        .collect();
    *LIMITS.lock().unwrap() = limits.clone();
    Ok(limits)
}

pub fn limits_on() -> windows::core::Result<bool> {
    Ok(!read_limits()?.is_empty())
}

/// Replaces the program's limit if it already had one.
pub fn set_limit() -> windows::core::Result<Option<String>> {
    let (program, bits) = chosen_limit().ok_or_else(|| failure("no program picked"))?;
    if !limitable(&program) {
        return Err(failure("this program can't be limited on its own"));
    }
    tweaks::powershell(&format!(
        "$n = '{LIMIT_PREFIX}{program}'; \
         Remove-NetQosPolicy -Name $n -Confirm:$false -ErrorAction SilentlyContinue; \
         New-NetQosPolicy -Name $n -AppPathNameMatchCondition '{program}' \
         -ThrottleRateActionBitsPerSecond {bits} -ErrorAction Stop | Out-Null"
    ))?;
    read_limits()?;
    Ok(None)
}

pub fn remove_limit(program: &str) -> windows::core::Result<()> {
    if !limitable(program) {
        return Ok(());
    }
    tweaks::powershell(&format!(
        "Remove-NetQosPolicy -Name '{LIMIT_PREFIX}{program}' -Confirm:$false -ErrorAction Stop"
    ))?;
    read_limits().map(drop)
}

pub fn remove_limits(_: Option<&str>) -> windows::core::Result<()> {
    tweaks::powershell(&format!(
        "Get-NetQosPolicy | Where-Object Name -like '{LIMIT_PREFIX}*' | Remove-NetQosPolicy -Confirm:$false"
    ))?;
    read_limits().map(drop)
}

pub fn reset_limits() -> windows::core::Result<()> {
    remove_limits(None)
}

// Traffic per program, from the Microsoft-Windows-Kernel-Network ETW provider: it sees
// TCP and UDP, so games, voice chat and QUIC in browsers count too. A real-time session
// outlives the process that started it, so it's always stopped by name before a start
// and when Vantix exits.

const SESSION: &str = "Vantix Network";
const KERNEL_NETWORK: GUID = GUID::from_u128(0x7dd42a49_5329_4832_8dfd_43d979153a88);
/// KERNEL_NETWORK_KEYWORD_IPV4 | KERNEL_NETWORK_KEYWORD_IPV6.
const KEYWORDS: u64 = 0x30;

/// Bytes received and sent per process id since the session started.
static COUNTERS: Mutex<Option<HashMap<u32, [u64; 2]>>> = Mutex::new(None);
static SESSION_ON: AtomicBool = AtomicBool::new(false);

/// Starts counting.
pub fn traffic_start() -> windows::core::Result<()> {
    if SESSION_ON.swap(true, Ordering::Relaxed) {
        return Ok(());
    }
    *COUNTERS.lock().unwrap() = Some(HashMap::new());
    let provider = etw::Provider { guid: KERNEL_NETWORK, level: 4, keywords: KEYWORDS, events: &[] };
    // One event per send and receive adds up fast on a gigabit line; small default
    // buffers fill and drop events, which would read as less traffic than there was.
    let result = etw::start(SESSION, &[provider], 256, 64, on_event);
    if result.is_err() {
        SESSION_ON.store(false, Ordering::Relaxed);
    }
    result
}

/// Ends a session left running by a Vantix that was killed or crashed on the traffic tab.
pub fn end_leftover_trace() {
    if !SESSION_ON.load(Ordering::Relaxed) {
        etw::stop(SESSION);
    }
}

/// Ends the session, which also makes the consumer thread return.
pub fn traffic_stop() {
    if SESSION_ON.swap(false, Ordering::Relaxed) {
        etw::stop(SESSION);
        *COUNTERS.lock().unwrap() = None;
        *NAMES.lock().unwrap() = None;
    }
}

unsafe extern "system" fn on_event(record: *mut EVENT_RECORD) {
    let record = unsafe { &*record };
    // Send and receive for TCP over IPv4 and IPv6, then the same for UDP. Every one of
    // them starts with the process id and the size.
    let direction = match record.EventHeader.EventDescriptor.Id {
        11 | 27 | 43 | 59 => 0,
        10 | 26 | 42 | 58 => 1,
        _ => return,
    };
    let data = etw::payload(record);
    if record.EventHeader.ProviderId != KERNEL_NETWORK || data.len() < 8 {
        return;
    }
    let pid = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let size = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    if let Some(counters) = COUNTERS.lock().unwrap().as_mut() {
        counters.entry(pid).or_default()[direction] += u64::from(size);
    }
}

/// Totals per program name, received and sent, since `traffic_start`. Processes of the
/// same exe add up, so a browser shows as one line.
pub fn traffic() -> HashMap<String, [u64; 2]> {
    let counters: Vec<(u32, [u64; 2])> = COUNTERS
        .lock()
        .unwrap()
        .as_ref()
        .map(|c| c.iter().map(|(p, b)| (*p, *b)).collect())
        .unwrap_or_default();
    let mut names = NAMES.lock().unwrap();
    let names = names.get_or_insert_with(HashMap::new);
    let mut totals: HashMap<String, [u64; 2]> = HashMap::new();
    for (pid, bytes) in counters {
        let name = names.entry(pid).or_insert_with(|| process_name(pid)).clone();
        let total = totals.entry(name).or_default();
        total[0] += bytes[0];
        total[1] += bytes[1];
    }
    totals
}

/// Names by process id while the traffic tab is open. Ids get reused, but rarely within
/// that time; the cache is dropped when counting stops.
static NAMES: Mutex<Option<HashMap<u32, String>>> = Mutex::new(None);

pub fn process_name(pid: u32) -> String {
    match pid {
        0 => return "Idle".into(),
        4 => return "System".into(),
        _ => {}
    }
    unsafe {
        let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return format!("PID {pid}");
        };
        let mut path = [0u16; 1024];
        let mut len = path.len() as u32;
        let result =
            QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(path.as_mut_ptr()), &mut len);
        let _ = CloseHandle(handle);
        match result {
            Ok(()) => {
                let path = String::from_utf16_lossy(&path[..len as usize]);
                path.rsplit('\\').next().unwrap_or(&path).to_string()
            }
            Err(_) => format!("PID {pid}"),
        }
    }
}

// Layered diagnosis, run on the Repair tab: one button walks from the adapter up to
// HTTPS and stops at the first layer that fails, with the matching repair next to it.
// The order is from the cable up, so a failure names the layer that actually broke.

/// The layers, in the order they run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layer {
    /// Media state of the adapter in use.
    Link,
    /// A 169.254 address means the DHCP server never answered.
    Ip,
    /// The router answers pings, or at least ARP.
    Gateway,
    /// Name lookups work with the servers in use, and with 1.1.1.1 when they don't.
    Dns,
    /// TCP 443 reaches a well-known address.
    Reach,
    /// HTTPS answers, and its Date header is close to the local clock.
    Https,
    /// NCSI probe: the "no internet" icon is built on this.
    Ncsi,
    /// WinINet and WinHTTP proxies set.
    Proxy,
    /// hosts entries for everyday domains.
    Hosts,
    /// Leftover TAP/TUN adapters of VPNs that were removed.
    Vpn,
    /// A global IPv6 address whose routing has gone bad.
    Ipv6,
}

pub const LAYERS: [Layer; 11] = [
    Layer::Link,
    Layer::Ip,
    Layer::Gateway,
    Layer::Dns,
    Layer::Reach,
    Layer::Https,
    Layer::Ncsi,
    Layer::Proxy,
    Layer::Hosts,
    Layer::Vpn,
    Layer::Ipv6,
];

/// What one layer came back as, for the UI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Not reached yet, shown as queued.
    Queued,
    /// Being checked right now.
    Running,
    /// Answers as it should.
    Ok,
    /// This layer is the one that broke. Only layers Link to NCSI fail.
    Failed,
    /// Not checked, and the detail says why.
    Skipped,
    /// Works, but something here is worth a look.
    Warning,
}

/// What a layer has to say. The UI turns it into text, so it can be translated.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum Detail {
    #[default]
    None,
    Cable,
    WiFi,
    NoAdapter,
    NoLink,
    Address(Ipv4Addr),
    NoIpv4,
    Apipa,
    RouterPing(f64),
    RouterArp,
    RouterSilent(Ipv4Addr),
    NoRouter,
    DnsAnswered(IpAddr, f64),
    NoDnsServer,
    /// The servers in use are silent, 1.1.1.1 answers in this many ms.
    DnsOnlyPublic(f64),
    /// Nothing answers, not even 1.1.1.1, so the fault may be past the router.
    DnsUnsure,
    ReachPing(f64),
    ReachTcp(f64),
    Unreachable,
    Answered,
    ClockWithin(i64),
    /// HTTPS works, the clock is this many seconds off (positive when the PC is behind).
    ClockOff(i64),
    /// HTTPS fails and a sign-in page answers plain HTTP.
    HttpsPortal,
    /// HTTPS fails and the clock is this many seconds off.
    HttpsClock(i64),
    HttpsProxy,
    HttpsFailed,
    NcsiOk,
    Portal,
    /// The probe works, but its DNS name points somewhere else: something rewrites DNS.
    NcsiDns(IpAddr),
    NcsiSilent,
    NoProxy,
    ProxySet,
    /// "Automatically detect settings" finds a setup script at this address.
    Wpad(String),
    HostsClean(usize),
    /// Lines in the way, out of the total.
    HostsBlocking(usize, usize),
    NoVpnLeftovers,
    VpnLeftovers(String),
    Ipv6Ok,
    Ipv6Broken,
    NoIpv6,
    Ipv6Untested,
    EarlierFailed,
    /// Something this check needs isn't there, like the hosts file or WinHTTP.
    Untestable,
}

/// One status and detail per layer, read by the tick every 250 ms.
static RESULTS: Mutex<Vec<(Layer, Status, Detail)>> = Mutex::new(Vec::new());
/// Whether a diagnosis is running right now, so a second click does nothing.
static DIAG_ON: AtomicBool = AtomicBool::new(false);
/// Set by the proxy layer when auto-detect finds a script, so the proxy repair also
/// turns auto-detect off. Off it stays on, as Windows ships it.
static WPAD_FOUND: AtomicBool = AtomicBool::new(false);

pub fn diag_results() -> Vec<(Layer, Status, Detail)> {
    RESULTS.lock().unwrap().clone()
}

pub fn diag_running() -> bool {
    DIAG_ON.load(Ordering::Relaxed)
}

fn set_result(i: usize, status: Status, detail: Detail) {
    RESULTS.lock().unwrap()[i] = (LAYERS[i], status, detail);
}

/// Best of up to 3 pings, `None` when all got lost. The name says best because one
/// call always tries three times.
fn ping_best(icmp: &Icmp, to: Ipv4Addr) -> Option<f64> {
    let mut best = None;
    for _ in 0..3 {
        match icmp.ping(to, Duration::from_millis(800)) {
            Some(time) if best.is_none_or(|b| time < b) => best = Some(time),
            Some(_) => {}
            None => return best,
        }
    }
    best
}

/// One run of the layered diagnosis. Layers Link to NCSI stop at the first failure,
/// except that NCSI still runs after HTTPS fails, since it is the one that sees a
/// sign-in page. Proxy, hosts, VPN and IPv6 always run and only ever warn.
pub fn diagnose() {
    if DIAG_ON.swap(true, Ordering::Relaxed) {
        return;
    }
    *RESULTS.lock().unwrap() = LAYERS.map(|layer| (layer, Status::Queued, Detail::None)).to_vec();
    let icmp = Icmp::new();
    let mut stopped = false;
    let mut reach_ok = false;
    let mut https_failed = false;
    // The plain HTTP probe, fetched once: HTTPS reads it when it fails, NCSI always.
    let mut probe: Option<Option<Probe>> = None;
    for (i, layer) in LAYERS.iter().enumerate() {
        let always = matches!(layer, Layer::Proxy | Layer::Hosts | Layer::Vpn | Layer::Ipv6);
        if stopped && !always {
            set_result(i, Status::Skipped, Detail::EarlierFailed);
            continue;
        }
        set_result(i, Status::Running, Detail::None);
        let (status, detail) = match layer {
            Layer::Link => link(),
            Layer::Ip => ip(),
            Layer::Gateway => gateway(icmp.as_ref()),
            Layer::Dns => dns(),
            Layer::Reach => reach(icmp.as_ref()),
            Layer::Https => https(|| probe.get_or_insert_with(ncsi_probe).clone()),
            Layer::Ncsi => ncsi(probe.get_or_insert_with(ncsi_probe).as_ref()),
            Layer::Proxy => proxy(),
            Layer::Hosts => hosts(),
            Layer::Vpn => vpn(),
            Layer::Ipv6 => ipv6(reach_ok),
        };
        reach_ok |= *layer == Layer::Reach && status == Status::Ok;
        if *layer == Layer::Https {
            https_failed = status == Status::Failed;
        } else if status == Status::Failed || *layer == Layer::Ncsi && https_failed {
            stopped = true;
        }
        set_result(i, status, detail);
    }
    DIAG_ON.store(false, Ordering::Relaxed);
}

fn link() -> (Status, Detail) {
    match connection() {
        None => (Status::Failed, Detail::NoAdapter),
        Some(adapter) if !adapter.up => (Status::Failed, Detail::NoLink),
        Some(adapter) => (Status::Ok, if adapter.wifi { Detail::WiFi } else { Detail::Cable }),
    }
}

fn ip() -> (Status, Detail) {
    match connection() {
        Some(adapter) => check_ip(adapter.ip),
        None => (Status::Failed, Detail::NoAdapter),
    }
}

/// The PC address fails only when missing or link-local. A public address or CGNAT
/// (100.64.0.0/10) is legitimate and passes.
fn check_ip(addr: Option<Ipv4Addr>) -> (Status, Detail) {
    match addr {
        None => (Status::Failed, Detail::NoIpv4),
        Some(addr) if addr.is_link_local() => (Status::Failed, Detail::Apipa),
        Some(addr) => (Status::Ok, Detail::Address(addr)),
    }
}

/// Some routers and fibre boxes drop pings on purpose. ARP has to answer for anything
/// to work at all, so a router that answers ARP is there.
fn gateway(icmp: Option<&Icmp>) -> (Status, Detail) {
    let Some(address) = connection().and_then(|c| c.gateway) else {
        return (Status::Skipped, Detail::NoRouter);
    };
    let ping = icmp.and_then(|icmp| ping_best(icmp, address));
    check_gateway(address, ping, || answers_arp(address))
}

fn check_gateway(address: Ipv4Addr, ping: Option<f64>, arp: impl FnOnce() -> bool) -> (Status, Detail) {
    match ping {
        Some(ms) => (Status::Ok, Detail::RouterPing(ms)),
        None if arp() => (Status::Ok, Detail::RouterArp),
        None => (Status::Failed, Detail::RouterSilent(address)),
    }
}

fn answers_arp(address: Ipv4Addr) -> bool {
    let mut mac = [0u8; 8];
    let mut len = mac.len() as u32;
    let to = u32::from_ne_bytes(address.octets());
    unsafe { SendARP(to, 0, mac.as_mut_ptr().cast(), &mut len) == 0 && len > 0 }
}

fn dns() -> (Status, Detail) {
    let servers = current_dns();
    if servers.is_empty() {
        return (Status::Failed, Detail::NoDnsServer);
    }
    let scope = connection_scope();
    let answer =
        servers.iter().find_map(|server| query_server(*server, scope, "google.com").map(|ms| (*server, ms)));
    check_dns(answer, || query_server(IpAddr::V4(CLOUDFLARE), 0, "google.com"))
}

/// When neither the servers in use nor 1.1.1.1 answer, DNS can't be blamed: the
/// internet itself may be down, and Reach is the layer that can tell.
fn check_dns(answer: Option<(IpAddr, f64)>, public: impl FnOnce() -> Option<f64>) -> (Status, Detail) {
    if let Some((server, ms)) = answer {
        return (Status::Ok, Detail::DnsAnswered(server, ms));
    }
    match public() {
        Some(ms) => (Status::Failed, Detail::DnsOnlyPublic(ms)),
        None => (Status::Skipped, Detail::DnsUnsure),
    }
}

/// One raw query straight to the server, with its round trip in ms. Link-local IPv6
/// servers need the interface they live on.
fn query_server(server: IpAddr, scope: u32, domain: &str) -> Option<f64> {
    let target = match server {
        IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80 => {
            SocketAddr::V6(SocketAddrV6::new(v6, 53, 0, scope))
        }
        _ => SocketAddr::new(server, 53),
    };
    let local: SocketAddr =
        if server.is_ipv6() { "[::]:0".parse().unwrap() } else { "0.0.0.0:0".parse().unwrap() };
    let socket = UdpSocket::bind(local).ok()?;
    socket.connect(target).ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    lookup(&socket, domain)
}

fn reach(icmp: Option<&Icmp>) -> (Status, Detail) {
    if let Some(ms) = icmp.and_then(|icmp| ping_best(icmp, CLOUDFLARE)) {
        return (Status::Ok, Detail::ReachPing(ms));
    }
    // Pings may be dropped deliberately: reach out with TCP instead.
    let began = Instant::now();
    match TcpStream::connect_timeout(&SocketAddr::new(CLOUDFLARE.into(), 443), Duration::from_secs(4)) {
        Ok(_) => (Status::Ok, Detail::ReachTcp(began.elapsed().as_secs_f64() * 1000.0)),
        Err(_) => (Status::Failed, Detail::Unreachable),
    }
}

/// A clock 2 minutes or more off is worth fixing; a day or more breaks certificates.
const CLOCK_SLACK: i64 = 120;

fn https(probe: impl FnOnce() -> Option<Probe>) -> (Status, Detail) {
    let Some((_session, connection)) = http_connection(SPEED_HOST, 443) else {
        return (Status::Skipped, Detail::Untestable);
    };
    let Some(request) = request(&connection, "HEAD", "/__down?bytes=1") else {
        return (Status::Skipped, Detail::Untestable);
    };
    if unsafe { WinHttpSendRequest(request.0, None, None, 0, 0, 0).is_err() } || !answered_ok(&request) {
        let probe = probe();
        let offset = probe
            .as_ref()
            .and_then(|p| p.date.as_deref())
            .and_then(|d| clock_offset_secs(d, chrono::Utc::now()));
        return https_failure(probe.as_ref().is_some_and(|p| !p.real()), offset, || {
            proxy_set().unwrap_or(false)
        });
    }
    match http_date(&request).and_then(|date| clock_offset_secs(&date, chrono::Utc::now())) {
        Some(secs) => check_clock(secs),
        None => (Status::Ok, Detail::Answered),
    }
}

/// Why HTTPS failed, from what plain HTTP saw: a sign-in page, a clock off far enough,
/// or a proxy in the way, in that order. The portal comes first because the probe went
/// around any proxy and still got someone else's page.
fn https_failure(portal: bool, offset: Option<i64>, proxy: impl FnOnce() -> bool) -> (Status, Detail) {
    if portal {
        return (Status::Failed, Detail::HttpsPortal);
    }
    if let Some(secs) = offset.filter(|secs| secs.abs() >= CLOCK_SLACK) {
        return (Status::Failed, Detail::HttpsClock(secs));
    }
    if proxy() {
        return (Status::Failed, Detail::HttpsProxy);
    }
    (Status::Failed, Detail::HttpsFailed)
}

fn check_clock(secs: i64) -> (Status, Detail) {
    if secs.abs() >= CLOCK_SLACK {
        (Status::Warning, Detail::ClockOff(secs))
    } else {
        (Status::Ok, Detail::ClockWithin(secs.abs().max(1)))
    }
}

/// The Date header of an answered request. The first call with a null buffer always
/// reports insufficient buffer; that is how the needed size is asked for.
fn http_date(request: &Http) -> Option<String> {
    let mut size = 0u32;
    unsafe {
        let _ = WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_DATE,
            PCWSTR::null(),
            None,
            &mut size,
            std::ptr::null_mut(),
        );
    }
    if size == 0 {
        return None;
    }
    let mut buffer = vec![0u16; (size / 2) as usize];
    unsafe {
        WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_DATE,
            PCWSTR::null(),
            Some(buffer.as_mut_ptr().cast()),
            &mut size,
            std::ptr::null_mut(),
        )
        .ok()?;
    }
    Some(String::from_utf16_lossy(&buffer[..(size / 2) as usize]))
}

/// Parses a Date header like "Mon, 01 Jan 2026 12:00:00 GMT". By hand, so the layer
/// needs no other dependency.
fn parse_http_date(date: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    const MONTHS: [&str; 12] =
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let words: Vec<&str> = date.split_whitespace().collect();
    if words.len() < 5 {
        return None;
    }
    let day: u32 = words[1].parse().ok()?;
    let month = MONTHS.iter().position(|m| words[2].starts_with(m))? as u32;
    let year: i32 = words[3].parse().ok()?;
    let mut clock = words[4].split(':');
    let hour = clock.next()?.parse().ok()?;
    let minute = clock.next()?.parse().ok()?;
    let second = clock.next().unwrap_or("0").parse().ok()?;
    Some(chrono::NaiveDate::from_ymd_opt(year, month + 1, day)?.and_hms_opt(hour, minute, second)?.and_utc())
}

/// Seconds the Date header is away from the local clock, positive when the server is
/// ahead, which means the PC is behind.
fn clock_offset_secs(date: &str, now: chrono::DateTime<chrono::Utc>) -> Option<i64> {
    Some((parse_http_date(date)? - now).num_seconds())
}

/// What the plain HTTP probe got back.
#[derive(Clone)]
struct Probe {
    body: String,
    date: Option<String>,
}

impl Probe {
    /// The exact body means the real server answered; anything else is a sign-in page.
    fn real(&self) -> bool {
        self.body.contains("Microsoft Connect Test")
    }
}

/// The probe Windows itself uses: a plain HTTP GET that must answer the exact body.
/// A direct TCP connection, so a broken proxy can't hide the answer, and no TLS, so a
/// wrong clock can't either. Portal pages aren't always UTF-8, hence the lossy read.
/// One retry, as Windows does: a single lost lookup or connect isn't an outage.
fn ncsi_probe() -> Option<Probe> {
    ncsi_get().or_else(ncsi_get)
}

fn ncsi_get() -> Option<Probe> {
    let addr = "www.msftconnecttest.com:80".to_socket_addrs().ok()?.find(|a| a.is_ipv4())?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok()?;
    stream
        .write_all(
            b"GET /connecttest.txt HTTP/1.0\r\nHost: www.msftconnecttest.com\r\nConnection: close\r\n\r\n",
        )
        .ok()?;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    let clean = loop {
        match stream.read(&mut chunk) {
            Ok(0) => break true,
            Ok(n) => bytes.extend_from_slice(&chunk[..n]),
            Err(_) => break false,
        }
    };
    let probe = parse_probe(&String::from_utf8_lossy(&bytes));
    // Some servers reset the connection right after answering. What came before the
    // reset still counts when it's the real answer; a cut page might be anything.
    (clean && !bytes.is_empty() || probe.real()).then_some(probe)
}

fn parse_probe(text: &str) -> Probe {
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or(("", text));
    let date = head
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.trim().eq_ignore_ascii_case("date"))
        .map(|(_, value)| value.trim().to_string());
    Probe { body: body.to_string(), date }
}

fn ncsi(probe: Option<&Probe>) -> (Status, Detail) {
    let Some(probe) = probe else { return (Status::Skipped, Detail::NcsiSilent) };
    if !probe.real() {
        return (Status::Failed, Detail::Portal);
    }
    // Windows also checks that this name resolves to Microsoft's address. Something
    // else answering means a router, filter or malware is rewriting DNS answers.
    let expected = IpAddr::V4(Ipv4Addr::new(131, 107, 255, 255));
    let answer =
        "dns.msftncsi.com:80".to_socket_addrs().ok().and_then(|mut addrs| addrs.find(|a| a.is_ipv4()));
    match answer {
        Some(addr) if addr.ip() != expected => (Status::Warning, Detail::NcsiDns(addr.ip())),
        _ => (Status::Ok, Detail::NcsiOk),
    }
}

fn proxy() -> (Status, Detail) {
    WPAD_FOUND.store(false, Ordering::Relaxed);
    match proxy_set() {
        Ok(true) => return (Status::Warning, Detail::ProxySet),
        Ok(false) => {}
        Err(_) => return (Status::Skipped, Detail::Untestable),
    }
    match wpad_script() {
        Some(url) => {
            WPAD_FOUND.store(true, Ordering::Relaxed);
            (Status::Warning, Detail::Wpad(url))
        }
        None => (Status::Ok, Detail::NoProxy),
    }
}

/// With "Automatically detect settings" on, which is how Windows ships, the browser asks
/// DHCP and DNS for a setup script. On a home network nothing answers; a script that
/// does answer sends every request through whatever it names. Asked on a thread with a
/// time limit, since the lookup can hang on a network with a domain suffix.
fn wpad_script() -> Option<String> {
    const DHCP: u32 = 1;
    const DNS_A: u32 = 2;
    let flags = connection_flags()?;
    if flags & 8 == 0 {
        return None;
    }
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut url = PWSTR::null();
        let found =
            unsafe { WinHttpDetectAutoProxyConfigUrl(DHCP | DNS_A, &mut url) }.is_ok() && !url.is_null();
        let text = found.then(|| unsafe { url.to_string() }.unwrap_or_default());
        if !url.is_null() {
            unsafe {
                let _ = GlobalFree(Some(HGLOBAL(url.0.cast())));
            }
        }
        let _ = send.send(text.filter(|t| !t.is_empty()));
    });
    receive.recv_timeout(Duration::from_secs(6)).ok().flatten()
}

fn hosts() -> (Status, Detail) {
    match hosts_state() {
        Some((total, blocking)) if blocking > 0 => (Status::Warning, Detail::HostsBlocking(blocking, total)),
        Some((total, _)) => (Status::Ok, Detail::HostsClean(total)),
        None => (Status::Skipped, Detail::Untestable),
    }
}

/// A leftover adapter of a VPN that was removed badly keeps routing and filtering
/// rules that were set up for it. Each adapter brand comes with the programs that
/// install it, and it only counts as leftovers when none of those is still installed:
/// WireGuard being there says nothing about a dead TAP adapter from OpenVPN.
const VPN_BRANDS: [(&str, &[&str]); 8] = [
    (
        "tap-windows",
        &[
            "openvpn",
            "protonvpn",
            "proton vpn",
            "nordvpn",
            "surfshark",
            "private internet access",
            "expressvpn",
            "windscribe",
            "cyberghost",
        ],
    ),
    (
        "wintun",
        &[
            "wireguard",
            "tailscale",
            "protonvpn",
            "proton vpn",
            "nordvpn",
            "surfshark",
            "mullvad",
            "windscribe",
        ],
    ),
    ("wireguard", &["wireguard", "mullvad", "surfshark", "nordvpn", "protonvpn", "proton vpn"]),
    ("openvpn", &["openvpn"]),
    ("tailscale", &["tailscale"]),
    ("zerotier", &["zerotier"]),
    ("nordlynx", &["nordvpn"]),
    ("protonvpn", &["protonvpn", "proton vpn"]),
];

fn vpn() -> (Status, Detail) {
    let adapters: Vec<(String, String)> =
        adapters().into_iter().filter(|a| !a.up).map(|a| (a.name, a.description)).collect();
    // Only read the Uninstall keys when there is a candidate at all.
    let installed =
        if adapters.iter().any(|(_, d)| vpn_brand(d).is_some()) { installed_programs() } else { Vec::new() };
    let leftover = vpn_leftovers(&adapters, &installed);
    if leftover.is_empty() {
        (Status::Ok, Detail::NoVpnLeftovers)
    } else {
        (Status::Warning, Detail::VpnLeftovers(leftover.join(", ")))
    }
}

fn vpn_brand(description: &str) -> Option<&'static [&'static str]> {
    let description = description.to_ascii_lowercase();
    VPN_BRANDS.iter().find(|(mark, _)| description.contains(mark)).map(|(_, programs)| *programs)
}

/// Names of the adapters, out of (name, description), whose VPN program is gone.
fn vpn_leftovers(adapters: &[(String, String)], installed: &[String]) -> Vec<String> {
    adapters
        .iter()
        .filter(|(_, description)| {
            vpn_brand(description).is_some_and(|programs| {
                !installed.iter().any(|name| programs.iter().any(|p| name.contains(p)))
            })
        })
        .map(|(name, _)| name.clone())
        .collect()
}

/// Display names of installed programs, lowercased, from the Uninstall keys.
fn installed_programs() -> Vec<String> {
    let mut names = Vec::new();
    for root in [reg::HKEY_LOCAL_MACHINE, reg::HKEY_CURRENT_USER] {
        for key in [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ] {
            for sub in reg::subkeys(root, key) {
                if let Ok(Some(name)) = reg::get_string(root, &format!(r"{key}\{sub}"), "DisplayName") {
                    names.push(name.to_ascii_lowercase());
                }
            }
        }
    }
    names
}

/// IPv6 with a global address but no working route. Only warns when the adapter has a
/// global address, IPv6 to a known host fails, and IPv4 (Reach) passed: with IPv4 down
/// too, a failed IPv6 connect says nothing.
fn ipv6(reach_ok: bool) -> (Status, Detail) {
    let Some(adapter) = connection() else { return (Status::Skipped, Detail::NoIpv6) };
    if !adapter.ipv6 {
        return (Status::Skipped, Detail::NoIpv6);
    }
    let target = SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)), 443);
    if TcpStream::connect_timeout(&target, Duration::from_secs(3)).is_ok() {
        return (Status::Ok, Detail::Ipv6Ok);
    }
    if reach_ok { (Status::Warning, Detail::Ipv6Broken) } else { (Status::Skipped, Detail::Ipv6Untested) }
}

/// The tweak id that fixes a layer that failed or warns, if one applies. Captive
/// portals, rewritten DNS and VPN leftovers need steps outside the app.
pub fn repair_for(layer: Layer, detail: &Detail) -> Option<&'static str> {
    match (layer, detail) {
        (Layer::Link, _) => Some("restart-connection"),
        (Layer::Ip, _) => Some("renew-ip"),
        (Layer::Gateway, _) => Some("clear-arp"),
        (Layer::Dns, _) => Some("flush-dns"),
        (Layer::Reach, _) => Some("restart-connection"),
        (Layer::Https, Detail::HttpsClock(_) | Detail::ClockOff(_)) => Some("sync-clock"),
        (Layer::Https, Detail::HttpsProxy) => Some(PROXY_TWEAK),
        (Layer::Proxy, _) => Some(PROXY_TWEAK),
        (Layer::Hosts, _) => Some(HOSTS_TWEAK),
        (Layer::Ipv6, _) => Some(IPV6_TWEAK),
        _ => None,
    }
}

// Wi-Fi around the PC: every access point the adapter hears, on which channel and how
// loud, so a crowded channel shows up and the router can be moved to a quieter one.
// Read only. Windows 11 24H2 and later only answer a scan while location access is on
// for desktop apps.

/// One access point heard in a scan.
#[derive(Clone, Debug)]
pub struct Bss {
    pub ssid: String,
    pub bssid: [u8; 6],
    pub rssi: i32,
    /// Center frequency in MHz.
    pub mhz: u32,
    /// The one this PC is connected to.
    pub connected: bool,
}

impl Bss {
    /// 2, 5 or 6 (GHz), 0 for anything else.
    pub fn band(&self) -> u8 {
        band_channel(self.mhz).0
    }

    pub fn channel(&self) -> u32 {
        band_channel(self.mhz).1
    }
}

pub fn band_channel(mhz: u32) -> (u8, u32) {
    match mhz {
        2484 => (2, 14),
        2412..=2472 => (2, (mhz - 2407) / 5),
        5150..=5895 => (5, (mhz - 5000) / 5),
        5925..=7125 => (6, (mhz - 5950) / 5),
        _ => (0, 0),
    }
}

#[derive(Debug)]
pub enum WifiError {
    /// No Wi-Fi adapter, or the WLAN service isn't running.
    NoAdapter,
    /// Windows refused the scan: location access is off for desktop apps.
    Location,
    Failed,
}

/// Whether the PC has a Wi-Fi adapter the WLAN service knows, connected or not.
pub fn has_wifi() -> bool {
    use windows::Win32::NetworkManagement::WiFi::*;
    let mut version = 0;
    let mut handle = HANDLE::default();
    if unsafe { WlanOpenHandle(2, None, &mut version, &mut handle) } != 0 {
        return false;
    }
    let mut list: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
    let found = unsafe { WlanEnumInterfaces(handle, None, &mut list) } == 0
        && !list.is_null()
        && unsafe { (*list).dwNumberOfItems } > 0;
    unsafe {
        if !list.is_null() {
            WlanFreeMemory(list.cast());
        }
        WlanCloseHandle(handle, None);
    }
    found
}

/// Scans and returns what the first Wi-Fi adapter hears, strongest first. Takes about
/// four seconds, which is how long a scan of every channel takes.
pub fn wifi_scan() -> Result<Vec<Bss>, WifiError> {
    use windows::Win32::NetworkManagement::WiFi::*;
    const ACCESS_DENIED: u32 = 5;
    let mut version = 0;
    let mut handle = HANDLE::default();
    if unsafe { WlanOpenHandle(2, None, &mut version, &mut handle) } != 0 {
        return Err(WifiError::NoAdapter);
    }
    struct Client(HANDLE);
    impl Drop for Client {
        fn drop(&mut self) {
            unsafe { WlanCloseHandle(self.0, None) };
        }
    }
    let client = Client(handle);

    let mut list: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
    if unsafe { WlanEnumInterfaces(client.0, None, &mut list) } != 0 || list.is_null() {
        return Err(WifiError::NoAdapter);
    }
    let guid = unsafe { ((*list).dwNumberOfItems > 0).then(|| (*list).InterfaceInfo[0].InterfaceGuid) };
    unsafe { WlanFreeMemory(list.cast()) };
    let Some(guid) = guid else { return Err(WifiError::NoAdapter) };

    match unsafe { WlanScan(client.0, &guid, None, None, None) } {
        0 => std::thread::sleep(Duration::from_secs(4)),
        ACCESS_DENIED => return Err(WifiError::Location),
        // A scan already running, or the adapter being busy: the cached list still helps.
        _ => {}
    }

    let mut connected = None;
    let mut size = 0;
    let mut data: *mut core::ffi::c_void = std::ptr::null_mut();
    let query = unsafe {
        WlanQueryInterface(
            client.0,
            &guid,
            wlan_intf_opcode_current_connection,
            None,
            &mut size,
            &mut data,
            None,
        )
    };
    if query == 0 && !data.is_null() {
        let attributes = unsafe { &*data.cast::<WLAN_CONNECTION_ATTRIBUTES>() };
        connected = Some(attributes.wlanAssociationAttributes.dot11Bssid);
        unsafe { WlanFreeMemory(data) };
    }

    let mut bss: *mut WLAN_BSS_LIST = std::ptr::null_mut();
    match unsafe { WlanGetNetworkBssList(client.0, &guid, None, dot11_BSS_type_any, false, None, &mut bss) } {
        0 if !bss.is_null() => {}
        ACCESS_DENIED => return Err(WifiError::Location),
        _ => return Err(WifiError::Failed),
    }
    let mut found = Vec::new();
    unsafe {
        let count = (*bss).dwNumberOfItems as usize;
        let entries = std::slice::from_raw_parts((*bss).wlanBssEntries.as_ptr(), count);
        for entry in entries {
            let len = (entry.dot11Ssid.uSSIDLength as usize).min(32);
            found.push(Bss {
                ssid: String::from_utf8_lossy(&entry.dot11Ssid.ucSSID[..len]).into_owned(),
                bssid: entry.dot11Bssid,
                rssi: entry.lRssi,
                mhz: entry.ulChCenterFrequency / 1000,
                connected: connected == Some(entry.dot11Bssid),
            });
        }
        WlanFreeMemory(bss.cast());
    }
    found.sort_by_key(|b| std::cmp::Reverse(b.rssi));
    Ok(found)
}

/// Below this an access point is too faint to get in the way.
const HEARD: i32 = -85;

/// How much the others crowd one channel: each network that overlaps it counts by how
/// loud it is, from 1 at -85 dBm to 5 at -45 and above. On 2.4 GHz a channel overlaps the
/// four on each side; on 5 and 6 GHz only the same channel is counted, since the width
/// each router uses isn't in the scan.
pub fn crowding(networks: &[Bss], band: u8, channel: u32, own: Option<[u8; 6]>) -> u32 {
    networks
        .iter()
        .filter(|b| b.band() == band && b.rssi >= HEARD && Some(b.bssid) != own)
        .filter(|b| if band == 2 { b.channel().abs_diff(channel) < 5 } else { b.channel() == channel })
        .map(|b| ((b.rssi - HEARD) / 10 + 1).clamp(1, 5) as u32)
        .sum()
}

/// Channels worth picking on a band: on 2.4 GHz only 1, 6 and 11 don't overlap each
/// other; on 5 GHz the ones without radar checks (DFS), which every router and client takes.
const CHANNELS_2G: [u32; 3] = [1, 6, 11];
pub const CHANNELS_5G: [u32; 8] = [36, 40, 44, 48, 149, 153, 157, 161];

/// The quietest channel on a band, with how crowded it is.
pub fn quietest(networks: &[Bss], band: u8, own: Option<[u8; 6]>) -> Option<(u32, u32)> {
    let channels: &[u32] = match band {
        2 => &CHANNELS_2G,
        5 => &CHANNELS_5G,
        _ => return None,
    };
    channels.iter().map(|&c| (c, crowding(networks, band, c, own))).min_by_key(|&(_, load)| load)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `cargo test net_connection -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn net_connection() {
        let c = connection().expect("no connection");
        println!(
            "{} {} index={} physical={} ipv6={} bound={} gateway={:?} dhcp={} dns={:?} current={:?} set={:?}",
            c.name,
            c.guid,
            c.index,
            c.physical,
            c.ipv6,
            c.ipv6_bound,
            c.gateway,
            c.dhcp,
            c.dns,
            current_dns(),
            dns_set()
        );
        let icmp = Icmp::new().unwrap();
        for target in [c.gateway.unwrap(), CLOUDFLARE] {
            let times: Vec<_> = (0..5).map(|_| icmp.ping(target, Duration::from_secs(1))).collect();
            println!("{target}: {times:.2?}");
        }
    }

    /// Restarts the adapter in use twice, so the connection drops for a few seconds each
    /// time: `cargo test moderation_round_trip -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn moderation_round_trip() {
        let (_, key) = setting_adapter(INTERRUPT_MODERATION.id, Some(false)).expect("no wired adapter");
        let original = reg::get_string(reg::HKEY_LOCAL_MACHINE, &key, "*InterruptModeration").unwrap();
        let was_off = moderation_off().unwrap();
        let start = Instant::now();
        let previous = disable_moderation().unwrap();
        println!("saved {previous:?} in {:.1?}", start.elapsed());
        assert!(moderation_off().unwrap());
        restore_moderation(previous.as_deref()).unwrap();
        assert_eq!(reg::get_string(reg::HKEY_LOCAL_MACHINE, &key, "*InterruptModeration").unwrap(), original);
        assert_eq!(moderation_off().unwrap(), was_off);
        println!("connection: {:?}", connection().map(|c| c.gateway));
    }

    /// Adds a limit for a program that doesn't exist and removes it:
    /// `cargo test limit_round_trip -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn limit_round_trip() {
        let before = read_limits().unwrap();
        choose_limit("vantix-probe.exe", 8_000_000);
        let start = Instant::now();
        set_limit().unwrap();
        println!("set in {:.1?}", start.elapsed());
        assert!(known_limits().contains(&("vantix-probe.exe".into(), 8_000_000)));
        assert!(limits_on().unwrap());
        remove_limit("vantix-probe.exe").unwrap();
        assert_eq!(read_limits().unwrap(), before);
        assert!(!limitable("svchost.exe") && !limitable("System") && limitable("OneDrive.exe"));
    }

    /// `cargo test net_dns -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn net_dns() {
        let start = Instant::now();
        for r in dns_benchmark(&DnsRun::new()) {
            println!(
                "{:<12} {:<16} cached={:.1?} uncached={:.1?} jitter={:.1?} failed={}/{}",
                r.name, r.address, r.cached, r.uncached, r.jitter, r.failed, r.sent
            );
        }
        println!("took {:?}", start.elapsed());
    }

    /// Changes and puts back LLMNR, NetBIOS and DNS over HTTPS for Quad9 and AdGuard,
    /// checking each comes back as it was. Needs an elevated terminal:
    /// `cargo test net_security_round_trip -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn net_security_round_trip() {
        let llmnr = reg::get_dword(reg::HKEY_LOCAL_MACHINE, DNS_POLICY, "EnableMulticast").unwrap();
        let previous = disable_llmnr().unwrap();
        assert!(llmnr_off().unwrap());
        restore_llmnr(previous.as_deref()).unwrap();
        assert_eq!(reg::get_dword(reg::HKEY_LOCAL_MACHINE, DNS_POLICY, "EnableMulticast").unwrap(), llmnr);

        let netbios = netbios_options();
        let previous = disable_netbios().unwrap();
        assert!(netbios_off().unwrap());
        restore_netbios(previous.as_deref()).unwrap();
        assert_eq!(netbios_options(), netbios);

        // Quad9 is in Windows' own list; AdGuard isn't, so Vantix adds it and takes it out.
        for provider in [2, 4] {
            let before: Vec<_> = doh_servers(provider).iter().map(|s| doh_entry(s)).collect();
            let previous = enable_doh_for(provider).unwrap();
            println!("{}: saved {previous:?}", PROVIDERS[provider].name);
            assert!(
                doh_servers(provider).iter().all(|s| doh_entry(s).is_some_and(|e| e.auto && !e.fallback))
            );
            restore_doh(previous.as_deref()).unwrap();
            let after: Vec<_> = doh_servers(provider).iter().map(|s| doh_entry(s)).collect();
            assert_eq!(after, before);
        }
    }

    /// Restarts the adapter in use twice: `cargo test lso_round_trip -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn lso_round_trip() {
        let (_, key) = setting_adapter(LSO.id, LSO.wifi).expect("no adapter");
        let read = || {
            ["*LsoV2IPv4", "*LsoV2IPv6"].map(|k| reg::get_string(reg::HKEY_LOCAL_MACHINE, &key, k).unwrap())
        };
        let original = read();
        let was_off = lso_off().unwrap();
        let previous = disable_lso().unwrap();
        assert!(lso_off().unwrap());
        restore_lso(previous.as_deref()).unwrap();
        assert_eq!(read(), original);
        assert_eq!(lso_off().unwrap(), was_off);
        println!("connection back: {:?}", connection().map(|c| c.gateway));
    }

    /// Reads only: `cargo test net_security_read -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn net_security_read() {
        println!("llmnr off {:?}, netbios off {:?}", llmnr_off(), netbios_off());
        println!("netbios {:?}", netbios_options());
        println!("doh 1.1.1.1 {:?}, adguard {:?}", doh_entry("1.1.1.1"), doh_entry("94.140.14.14"));
        println!("provider set {:?}, doh shown {}", set_provider(), shows_doh());
        println!("wifi adapter {}, scan {:?}", has_wifi(), wifi_scan().map(|n| n.len()));
        assert!(doh_entry("1.1.1.1").is_some());
        assert_eq!(doh_entry("94.140.14.14"), None);
    }

    /// Cancels a run after a second: `cargo test net_dns_cancel -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn net_dns_cancel() {
        let run = DnsRun::new();
        let start = Instant::now();
        let results = std::thread::scope(|s| {
            let job = s.spawn(|| dns_benchmark(&run));
            std::thread::sleep(Duration::from_secs(1));
            println!("eta after 1 s: {:.1?}", run.eta());
            run.cancel();
            job.join().unwrap()
        });
        println!("stopped in {:?} with {} finished", start.elapsed(), results.len());
        assert!(start.elapsed() < Duration::from_secs(3), "a cancel stops within a query timeout");
        assert!(results.iter().all(|r| r.sent == DNS_QUERIES));
    }

    /// Downloads for 3 s while counting: `cargo test net_traffic -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn net_traffic() {
        traffic_start().unwrap();
        let bytes = AtomicU64::new(0);
        let stop = AtomicBool::new(false);
        std::thread::scope(|s| {
            s.spawn(|| download_stream(&bytes, &stop));
            std::thread::sleep(Duration::from_secs(3));
            stop.store(true, Ordering::Relaxed);
        });
        std::thread::sleep(Duration::from_millis(1500));
        let mut totals: Vec<_> = traffic().into_iter().collect();
        traffic_stop();
        totals.sort_by_key(|(_, b)| std::cmp::Reverse(b[0] + b[1]));
        println!("downloaded {} bytes", bytes.load(Ordering::Relaxed));
        for (name, [down, up]) in totals.iter().take(8) {
            println!("{name:<28} down {down:>12} up {up:>10}");
        }
    }

    #[test]
    fn saved_dns_text() {
        let saved =
            SavedDns { guid: "{A}".into(), v4: vec!["192.168.0.1".into(), "8.8.8.8".into()], v6: Vec::new() };
        let text = saved.encode();
        assert_eq!(text, "{A};192.168.0.1,8.8.8.8;dhcp");
        let back = SavedDns::decode(&text).unwrap();
        assert_eq!((back.guid, back.v4, back.v6), (saved.guid, saved.v4, saved.v6));
        assert!(SavedDns::decode("{A};dhcp").is_none());
    }

    /// Sets Quad9 on the adapter in use, checks it, puts the old settings back and checks
    /// again: `cargo test net_dns_round_trip -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn net_dns_round_trip() {
        let adapter = dns_adapter().expect("no cable or Wi-Fi connection");
        let before = SavedDns::read(&adapter.guid).encode();
        choose_dns(2);
        let previous = set_dns().unwrap();
        assert_eq!(previous.as_deref(), Some(before.as_str()));
        let during = SavedDns::read(&adapter.guid);
        println!("before {before}\nduring {}", during.encode());
        assert_eq!(during.v4, ["9.9.9.9", "149.112.112.112"]);
        assert!(dns_set().unwrap());
        restore_dns(previous.as_deref()).unwrap();
        let after = SavedDns::read(&adapter.guid).encode();
        println!("after  {after}");
        assert_eq!(after, before);
    }

    /// About 25 s and real data: `cargo test net_bufferbloat -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn net_bufferbloat() {
        let result = bufferbloat().unwrap();
        println!("{result:?} added={:.1} grade={}", result.added(), result.grade());
    }

    /// Walks every layer once on the live connection, without changing anything, and
    /// prints what each came back as: `cargo test net_diagnose -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn net_diagnose() {
        let start = Instant::now();
        diagnose();
        for (i, (layer, status, detail)) in diag_results().iter().enumerate() {
            println!("{:<2} {layer:<8?} {status:<8?} {detail:?}", i + 1);
            assert_eq!(*layer, LAYERS[i]);
            assert_ne!(*status, Status::Running, "no layer stays running");
            assert_ne!(*status, Status::Queued, "every layer gets a result");
            assert_ne!(*status, Status::Failed, "layer {layer:?} failed: {detail:?}");
            assert_ne!(*detail, Detail::None, "layer {layer:?} needs a detail");
        }
        assert!(!diag_running());
        println!("took {:?}", start.elapsed());
    }

    /// Puts one registry value back as it was, or deletes it when there was none.
    fn restore_value(
        root: windows::Win32::System::Registry::HKEY,
        key: &str,
        name: &str,
        value: &Option<Vec<u8>>,
        kind: u8,
    ) {
        let _ = match (value, kind) {
            (None, _) => reg::delete_value(root, key, name),
            (Some(bytes), b'd') => {
                reg::set_dword(root, key, name, u32::from_le_bytes(bytes[..4].try_into().unwrap()))
            }
            (Some(bytes), b's') => reg::set_string(root, key, name, std::str::from_utf8(bytes).unwrap()),
            (Some(bytes), _) => reg::set_binary(root, key, name, bytes),
        };
    }

    /// Reads the proxy, writes a fake one, clears it through the tweak's own calls,
    /// puts the original back and checks the registry byte for byte:
    /// `cargo test proxy_round_trip -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn proxy_round_trip() {
        type Saved =
            Vec<(windows::Win32::System::Registry::HKEY, &'static str, &'static str, Option<Vec<u8>>, u8)>;
        let read = || -> Saved {
            let hkcu = reg::HKEY_CURRENT_USER;
            let dword =
                |name| reg::get_dword(hkcu, PROXY_KEY, name).unwrap().map(|v| v.to_le_bytes().to_vec());
            let string = |name| reg::get_string(hkcu, PROXY_KEY, name).unwrap().map(String::into_bytes);
            vec![
                (hkcu, PROXY_KEY, "ProxyEnable", dword("ProxyEnable"), b'd'),
                (hkcu, PROXY_KEY, "ProxyServer", string("ProxyServer"), b's'),
                (hkcu, PROXY_KEY, "ProxyOverride", string("ProxyOverride"), b's'),
                (hkcu, PROXY_KEY, "AutoConfigURL", string("AutoConfigURL"), b's'),
                (
                    hkcu,
                    USER_CONNECTIONS,
                    USER_SETTINGS,
                    reg::get_binary(hkcu, USER_CONNECTIONS, USER_SETTINGS).unwrap(),
                    b'b',
                ),
                (
                    reg::HKEY_LOCAL_MACHINE,
                    WINHTTP_CONNECTIONS,
                    WINHTTP_SETTINGS,
                    reg::get_binary(reg::HKEY_LOCAL_MACHINE, WINHTTP_CONNECTIONS, WINHTTP_SETTINGS).unwrap(),
                    b'b',
                ),
            ]
        };
        struct Guard(Saved);
        impl Drop for Guard {
            fn drop(&mut self) {
                for (root, key, name, value, kind) in &self.0 {
                    restore_value(*root, key, name, value, *kind);
                }
                notify_proxy_changed();
            }
        }
        // WinINet bumps the blob's counter (bytes 4 to 8) on its own whenever it's told the
        // proxy changed, so undo can't bring that part back; everything else must match.
        let same = |mut saved: Saved| {
            for (_, _, name, value, _) in &mut saved {
                if *name == USER_SETTINGS
                    && let Some(blob) = value.as_mut().filter(|b| b.len() >= 8)
                {
                    blob[4..8].fill(0);
                }
            }
            saved
        };
        let before = read();
        let guard = Guard(before.clone());
        let before_netsh = tweaks::run("netsh.exe", &["winhttp", "show", "proxy"]).unwrap_or_default();
        reg::set_dword(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyEnable", 1).unwrap();
        reg::set_string(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyServer", "127.0.0.1:9999").unwrap();
        notify_proxy_changed();
        let faked = read();
        assert!(proxy_set().unwrap(), "a set proxy must be seen");
        assert!(!proxy_clear().unwrap(), "clear reads false while a proxy is set");
        let start = Instant::now();
        let previous = reset_proxy().unwrap();
        println!("saved {previous:?} in {:?}", start.elapsed());
        assert!(!proxy_set().unwrap(), "reset must clear WinINet, its blob and WinHTTP");
        assert!(proxy_clear().unwrap());
        let flags = connection_flags().unwrap_or(1);
        assert_eq!(flags & 6, 0, "blob has no manual proxy or script left");
        restore_proxy(previous.as_deref()).unwrap();
        // Undo puts back the fake proxy that was saved, not the original from before.
        assert_eq!(same(read()), same(faked));
        drop(guard);
        assert_eq!(same(read()), same(before));
        let after_netsh = tweaks::run("netsh.exe", &["winhttp", "show", "proxy"]).unwrap_or_default();
        assert_eq!(after_netsh, before_netsh, "WinHTTP proxy must read the same after undo");
    }

    /// Cleans scratch copies of a hosts file, never the real one.
    #[test]
    fn hosts_round_trip() {
        let dir = std::env::temp_dir().join(format!("vantix-hosts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        struct Remove(std::path::PathBuf);
        impl Drop for Remove {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _remove = Remove(dir.clone());
        let path = dir.join("hosts").to_string_lossy().into_owned();
        let backup = dir.join("hosts.bak").to_string_lossy().into_owned();
        // ANSI "Café" (0xE9) in a comment, CRLF and LF lines mixed, a privacy list entry,
        // a lookalike, and two lines that do get in the way.
        let content: &[u8] = b"# Caf\xe9\r\n127.0.0.1 localhost\r\n0.0.0.0 vortex.data.microsoft.com\r\n\
            93.184.216.34 www.google.com # test\r\n93.184.216.34 notgoogle.com\n0.0.0.0 fe2.update.windowsupdate.com\n";
        std::fs::write(&path, content).unwrap();
        assert_eq!(hosts_state_in(&path), Some((5, 2)));
        reset_hosts_in(&path, &backup).unwrap();
        let after = std::fs::read(&path).unwrap();
        assert_eq!(
            after,
            b"# Caf\xe9\r\n127.0.0.1 localhost\r\n0.0.0.0 vortex.data.microsoft.com\r\n93.184.216.34 notgoogle.com\n"
        );
        restore_hosts_in(&path, &backup).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), content);
        assert!(!std::path::Path::new(&backup).exists(), "backup goes away on undo");
    }

    /// `cargo test net_ncsi -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn net_ncsi() {
        let misses = (0..20).filter(|_| !ncsi_get().is_some_and(|p| p.real())).count();
        println!("missed {misses} of 20");
    }

    #[test]
    fn diagnose_pure_checks() {
        assert_eq!(check_ip(Some(Ipv4Addr::new(100, 64, 0, 1))).0, Status::Ok);
        assert_eq!(check_ip(Some(Ipv4Addr::new(169, 254, 1, 5))), (Status::Failed, Detail::Apipa));
        assert_eq!(check_ip(None).0, Status::Failed);

        let router = Ipv4Addr::new(192, 168, 0, 1);
        assert_eq!(check_gateway(router, None, || true), (Status::Ok, Detail::RouterArp));
        assert_eq!(check_gateway(router, None, || false), (Status::Failed, Detail::RouterSilent(router)));
        assert_eq!(check_gateway(router, Some(0.6), || panic!("no ARP after a ping")).0, Status::Ok);

        assert_eq!(check_dns(None, || None), (Status::Skipped, Detail::DnsUnsure));
        assert_eq!(check_dns(None, || Some(9.0)), (Status::Failed, Detail::DnsOnlyPublic(9.0)));

        let portal = parse_probe(
            "HTTP/1.1 200 OK\r\nDate: Thu, 01 Jan 2026 12:00:00 GMT\r\n\r\n<html>Hotel login</html>",
        );
        assert!(!portal.real());
        assert_eq!(portal.date.as_deref(), Some("Thu, 01 Jan 2026 12:00:00 GMT"));
        assert_eq!(ncsi(Some(&portal)), (Status::Failed, Detail::Portal));
        assert_eq!(https_failure(true, Some(600), || true), (Status::Failed, Detail::HttpsPortal));
        assert_eq!(https_failure(false, Some(-600), || true), (Status::Failed, Detail::HttpsClock(-600)));
        assert_eq!(https_failure(false, Some(30), || true), (Status::Failed, Detail::HttpsProxy));
        assert_eq!(https_failure(false, None, || false), (Status::Failed, Detail::HttpsFailed));
        assert!(parse_probe("HTTP/1.1 200 OK\r\n\r\nMicrosoft Connect Test").real());

        assert_eq!(check_clock(300), (Status::Warning, Detail::ClockOff(300)));
        assert_eq!(check_clock(-30), (Status::Ok, Detail::ClockWithin(30)));
        let now = chrono::DateTime::parse_from_rfc2822("Thu, 01 Jan 2026 12:00:00 GMT").unwrap().to_utc();
        assert_eq!(clock_offset_secs("Thu, 01 Jan 2026 12:05:00 GMT", now), Some(300));
        assert_eq!(clock_offset_secs("not a date", now), None);
    }

    #[test]
    fn load_check_noise() {
        let check = |loaded| LoadCheck { loaded };
        assert_eq!(compare_checks(&check(40.0), &check(44.0)), 0);
        assert_eq!(compare_checks(&check(40.0), &check(30.0)), -1);
        assert_eq!(compare_checks(&check(200.0), &check(225.0)), 0);
        assert_eq!(compare_checks(&check(200.0), &check(240.0)), 1);
    }

    #[test]
    fn wifi_channels() {
        assert_eq!(band_channel(2412), (2, 1));
        assert_eq!(band_channel(2437), (2, 6));
        assert_eq!(band_channel(2484), (2, 14));
        assert_eq!(band_channel(5180), (5, 36));
        assert_eq!(band_channel(5745), (5, 149));
        assert_eq!(band_channel(5955), (6, 1));
        let ap = |mhz, rssi, last| Bss {
            ssid: String::new(),
            bssid: [0, 0, 0, 0, 0, last],
            rssi,
            mhz,
            connected: false,
        };
        // Two loud networks on 6 and one on 7 (overlapping), a faint one on 11.
        let around =
            [ap(2437, -40, 1), ap(2437, -50, 2), ap(2442, -60, 3), ap(2462, -90, 4), ap(2437, -45, 9)];
        let own = Some([0, 0, 0, 0, 0, 9]);
        assert_eq!(crowding(&around, 2, 6, own), 5 + 4 + 3, "own network doesn't count");
        assert_eq!(crowding(&around, 2, 11, own), 3, "channel 7 overlaps 11, the faint one doesn't count");
        assert_eq!(quietest(&around, 2, own), Some((1, 0)));
        assert_eq!(quietest(&around, 5, own), Some((36, 0)));
        assert_eq!(quietest(&around, 6, own), None);
    }

    #[test]
    fn vpn_leftover_checks() {
        let tap = ("Local Area Connection".to_string(), "TAP-Windows Adapter V9".to_string());
        let wintun = ("Proton".to_string(), "Wintun Userspace Tunnel".to_string());
        let wire = || vec!["wireguard".to_string()];
        assert_eq!(vpn_leftovers(std::slice::from_ref(&tap), &wire()), ["Local Area Connection"]);
        assert!(vpn_leftovers(std::slice::from_ref(&tap), &["openvpn 2.6.12-i001 amd64".into()]).is_empty());
        assert!(vpn_leftovers(std::slice::from_ref(&wintun), &wire()).is_empty());
        assert_eq!(vpn_leftovers(&[wintun], &[]), ["Proton"]);
        assert!(vpn_leftovers(&[("Ethernet".into(), "Realtek PCIe GbE".into())], &[]).is_empty());
    }

    #[test]
    fn proxy_blob_checks() {
        // Direct access blob from Group Policy docs: version 0x18, flags 1, no strings.
        let direct = vec![0x18, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(!winhttp_has_proxy(&direct));
        assert!(!winhttp_has_proxy(&[]));
        // Manual proxy blob: flags 3 (always + manual), proxy "127.0.0.1:9999".
        let mut manual = vec![0x46, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0];
        let proxy = b"127.0.0.1:9999";
        manual.extend((proxy.len() as u32).to_le_bytes());
        manual.extend(proxy);
        manual.extend(0u32.to_le_bytes());
        manual.extend(0u32.to_le_bytes());
        manual.extend(vec![0u8; 32]);
        assert!(winhttp_has_proxy(&manual));
        let hex = hex_encode(&manual);
        assert_eq!(hex_decode(&hex).as_deref(), Some(manual.as_slice()));
        assert_eq!(hex_decode("zz"), None);
        // Auto detect alone, as Windows ships, isn't a proxy.
        let mut detect = manual.clone();
        detect[8] = 9;
        assert!(!winhttp_has_proxy(&direct_blob(detect.clone(), false)) && !winhttp_has_proxy(&detect));
        let cleared = direct_blob(manual.clone(), false);
        assert!(!winhttp_has_proxy(&cleared));
        assert_eq!((cleared[4], cleared[8]), (2, 1), "counter up, flags back to direct");
        assert_eq!(direct_blob(detect.clone(), false)[8], 9, "auto detect stays unless a script was found");
        assert_eq!(direct_blob(detect, true)[8], 1);
    }

    #[test]
    fn repair_mapping_checks() {
        assert_eq!(repair_for(Layer::Gateway, &Detail::RouterSilent(Ipv4Addr::LOCALHOST)), Some("clear-arp"));
        assert_eq!(repair_for(Layer::Https, &Detail::ClockOff(300)), Some("sync-clock"));
        assert_eq!(repair_for(Layer::Https, &Detail::HttpsClock(-300)), Some("sync-clock"));
        assert_eq!(repair_for(Layer::Https, &Detail::HttpsProxy), Some(PROXY_TWEAK));
        assert_eq!(repair_for(Layer::Https, &Detail::HttpsFailed), None);
        assert_eq!(repair_for(Layer::Ncsi, &Detail::Portal), None);
        assert_eq!(repair_for(Layer::Hosts, &Detail::HostsBlocking(1, 3)), Some(HOSTS_TWEAK));
        assert_eq!(repair_for(Layer::Vpn, &Detail::VpnLeftovers("x".into())), None);
        assert_eq!(repair_for(Layer::Ipv6, &Detail::Ipv6Broken), Some(IPV6_TWEAK));
    }
}
