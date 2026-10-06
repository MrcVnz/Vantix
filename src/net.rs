//! Internet diagnostics: live ping, bufferbloat, DNS benchmark and traffic per program,
//! plus the repairs on the Repair tab. Only the repairs change the system. Every call that
//! measures blocks, so run it off the UI thread; the live ping and the traffic monitor run
//! on threads of their own.

use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasher, RandomState};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses,
    GetBestInterface, ICMP_ECHO_REPLY, IP_ADAPTER_ADDRESSES_LH, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinHttp::{
    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_FLAG_SECURE, WinHttpCloseHandle, WinHttpConnect, WinHttpOpen,
    WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_QUERY_STATUS_CODE, WinHttpOpenRequest, WinHttpQueryHeaders, WinHttpReadData,
    WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetTimeouts, WinHttpWriteData,
};
use windows::Win32::Networking::WinSock::SOCKET_ADDRESS;
use windows::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_RECORD,
    EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE,
    EnableTraceEx2, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME,
    ProcessTrace, StartTraceW, WNODE_FLAG_TRACED_GUID,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::core::{GUID, HSTRING, PCWSTR, PWSTR};

use crate::{reg, tweaks};

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
    pub dns: Vec<IpAddr>,
    pub dhcp: bool,
    /// Cable, Wi-Fi or a PPPoE dial-up. VPN and virtual adapters get their DNS from
    /// whatever made them, so Vantix leaves those alone.
    pub physical: bool,
    pub wifi: bool,
    /// Has a global IPv6 address, so IPv6 DNS servers can be reached through it.
    pub ipv6: bool,
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
                let mut next = a.FirstUnicastAddress;
                while !next.is_null() {
                    let entry = unsafe { &*next };
                    if let Some(IpAddr::V6(v6)) = socket_ip(&entry.Address) {
                        ipv6 |= v6.segments()[0] & 0xe000 == 0x2000;
                    }
                    next = entry.Next;
                }
                list.push(Connection {
                    name: unsafe { a.FriendlyName.to_string() }.unwrap_or_default(),
                    guid: unsafe { a.AdapterName.to_string() }.unwrap_or_default(),
                    index: unsafe { a.Anonymous1.Anonymous.IfIndex },
                    up: a.OperStatus == IfOperStatusUp,
                    gateway,
                    dns,
                    dhcp: unsafe { a.Anonymous2.Flags } & DHCP_ENABLED != 0,
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
        (answered.len() > 1)
            .then(|| answered.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (answered.len() - 1) as f64)
    }

    /// Share of pings that got no answer, 0 to 1.
    pub fn loss(&self) -> Option<f64> {
        (!self.0.is_empty()).then(|| self.0.iter().filter(|s| s.is_none()).count() as f64 / self.0.len() as f64)
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

static PROGRESS: Mutex<Progress> = Mutex::new(Progress { phase: Phase::Idle, elapsed: Duration::ZERO, ping: None, mbps: 0.0 });

pub fn bloat_progress() -> Progress {
    *PROGRESS.lock().unwrap()
}

/// Takes about 21 seconds and moves as much data as the line can in 16 of them: over
/// 1 GB on a gigabit line.
pub fn bufferbloat() -> Result<Bloat, BloatError> {
    let icmp = Icmp::new().ok_or(BloatError::NoPing)?;
    *PROGRESS.lock().unwrap() = Progress::default();

    let idle: Vec<f64> = sample_pings(&icmp, IDLE, Phase::Idle, None).into_iter().filter_map(|(_, p)| p).collect();
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
    let measured: Vec<Option<f64>> = pings.into_iter().filter(|(when, _)| *when >= RAMP).map(|(_, p)| p).collect();
    // A ping lost under load is the queue overflowing, the worst case of bloat, so it
    // counts as the full timeout instead of dropping out of the average.
    let latency = if measured.is_empty() {
        PING_TIMEOUT.as_secs_f64() * 1000.0
    } else {
        measured.iter().map(|p| p.unwrap_or(PING_TIMEOUT.as_secs_f64() * 1000.0)).sum::<f64>() / measured.len() as f64
    };
    let lost = measured.iter().filter(|p| p.is_none()).count() as u32;
    (Load { mbps, latency, lost }, total)
}

/// Pings every 250 ms for `length`, each with the time it was sent. Under load it also
/// reports the speed and notes when the ramp ended.
fn sample_pings(icmp: &Icmp, length: Duration, phase: Phase, mut meter: Option<&mut Meter>) -> Vec<(Duration, Option<f64>)> {
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
struct Http(*mut core::ffi::c_void);

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

fn http_connection() -> Option<(Http, Http)> {
    unsafe {
        let session = Http(WinHttpOpen(&HSTRING::from("Vantix"), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, PCWSTR::null(), PCWSTR::null(), 0)).ok()?;
        WinHttpSetTimeouts(session.0, 5000, 5000, 5000, 5000).ok()?;
        let connection = Http(WinHttpConnect(session.0, &HSTRING::from(SPEED_HOST), 443, 0)).ok()?;
        Some((session, connection))
    }
}

fn request(connection: &Http, verb: &str, path: &str) -> Option<Http> {
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
    let mut status = 0u32;
    let mut size = 4u32;
    unsafe {
        WinHttpReceiveResponse(request.0, std::ptr::null_mut()).is_ok()
            && WinHttpQueryHeaders(
                request.0,
                WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                PCWSTR::null(),
                Some((&raw mut status).cast()),
                &mut size,
                std::ptr::null_mut(),
            )
            .is_ok()
            && status == 200
    }
}

fn download_stream(bytes: &AtomicU64, stop: &AtomicBool) {
    let Some((_session, connection)) = http_connection() else { return };
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
                    || WinHttpReadData(request.0, buffer.as_mut_ptr().cast(), buffer.len() as u32, &mut read).is_err()
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
    let Some((_session, connection)) = http_connection() else { return };
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
    "google.com", "youtube.com", "facebook.com", "instagram.com", "whatsapp.com", "wikipedia.org", "amazon.com",
    "netflix.com", "twitch.tv", "discord.com", "reddit.com", "microsoft.com", "apple.com", "steampowered.com",
    "x.com", "tiktok.com", "cloudflare.com", "github.com", "spotify.com", "epicgames.com",
];

/// A public DNS service: main and backup servers for IPv4 and IPv6. The benchmark times
/// the first IPv4 one; setting it sets all of them.
pub struct Provider {
    pub name: &'static str,
    v4: [Ipv4Addr; 2],
    v6: [Ipv6Addr; 2],
}

pub const PROVIDERS: [Provider; 5] = [
    Provider {
        name: "Cloudflare",
        v4: [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)],
        v6: [Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111), Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001)],
    },
    Provider {
        name: "Google",
        v4: [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)],
        v6: [Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888), Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844)],
    },
    Provider {
        name: "Quad9",
        v4: [Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(149, 112, 112, 112)],
        v6: [Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe), Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0x9)],
    },
    Provider {
        name: "OpenDNS",
        v4: [Ipv4Addr::new(208, 67, 222, 222), Ipv4Addr::new(208, 67, 220, 220)],
        v6: [Ipv6Addr::new(0x2620, 0x119, 0x35, 0, 0, 0, 0, 0x35), Ipv6Addr::new(0x2620, 0x119, 0x53, 0, 0, 0, 0, 0x53)],
    },
    Provider {
        name: "AdGuard",
        v4: [Ipv4Addr::new(94, 140, 14, 14), Ipv4Addr::new(94, 140, 15, 15)],
        v6: [Ipv6Addr::new(0x2a10, 0x50c0, 0, 0, 0, 0, 0xad1, 0xff), Ipv6Addr::new(0x2a10, 0x50c0, 0, 0, 0, 0, 0xad2, 0xff)],
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

/// The servers in use and the public ones, fastest first. Takes a few seconds.
pub fn dns_benchmark() -> Vec<Resolver> {
    let mut resolvers = current_dns();
    for provider in &PROVIDERS {
        let address = IpAddr::V4(provider.v4[0]);
        if !resolvers.contains(&address) {
            resolvers.push(address);
        }
    }
    let scope = connection_scope();
    let mut results: Vec<Resolver> = std::thread::scope(|s| {
        let jobs: Vec<_> = resolvers
            .into_iter()
            .map(|address| {
                s.spawn(move || measure_resolver(address, scope))
            })
            .collect();
        jobs.into_iter().filter_map(|job| job.join().ok()).collect()
    });
    results.sort_by(|a, b| {
        b.reliable().cmp(&a.reliable()).then(a.score().unwrap_or(f64::MAX).total_cmp(&b.score().unwrap_or(f64::MAX)))
    });
    results
}

/// Zone for link-local IPv6 resolvers, which only mean something on one interface.
fn connection_scope() -> u32 {
    let mut index = 0;
    unsafe { GetBestInterface(u32::from_ne_bytes(CLOUDFLARE.octets()), &mut index) };
    index
}

fn measure_resolver(address: IpAddr, scope: u32) -> Resolver {
    let provider = provider_of(address);
    let name = provider.map(|p| PROVIDERS[p].name.to_string()).unwrap_or_default();
    let mut resolver = Resolver { provider, name, address, cached: None, uncached: None, failed: 0, sent: 0 };
    let target = match address {
        IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80 => SocketAddr::V6(SocketAddrV6::new(v6, 53, 0, scope)),
        _ => SocketAddr::new(address, 53),
    };
    let local: SocketAddr = if address.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
    let Ok(socket) = UdpSocket::bind(local) else { return resolver };
    if socket.connect(target).is_err() || socket.set_read_timeout(Some(Duration::from_secs(1))).is_err() {
        return resolver;
    }
    let mut ask = |name: &str| {
        resolver.sent += 1;
        let time = lookup(&socket, name);
        if time.is_none() {
            resolver.failed += 1;
        }
        time
    };
    // The first round puts every name in the resolver's cache, the second is timed.
    for domain in DOMAINS {
        ask(domain);
    }
    let cached: Vec<f64> = DOMAINS.iter().filter_map(|domain| ask(domain)).collect();
    // A random label under a real domain: no resolver has that cached, so it has to ask
    // the domain's own servers.
    let uncached: Vec<f64> =
        DOMAINS.iter().step_by(2).filter_map(|domain| ask(&format!("{:x}.{domain}", random() & 0xffff_ffff))).collect();
    resolver.cached = median(cached);
    resolver.uncached = median(uncached);
    resolver
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
        let list = |servers: &[String]| if servers.is_empty() { "dhcp".to_string() } else { servers.join(",") };
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
        return tweaks::run("netsh.exe", &["interface", family, "set", "dnsservers", &name, "source=dhcp"]).map(drop);
    };
    let address = format!("address={first}");
    let args = ["interface", family, "set", "dnsservers", &name, "source=static", &address, "register=primary", "validate=no"];
    tweaks::run("netsh.exe", &args)?;
    for (i, server) in servers.iter().enumerate().skip(1) {
        let (address, index) = (format!("address={server}"), format!("index={}", i + 1));
        tweaks::run("netsh.exe", &["interface", family, "add", "dnsservers", &name, &address, &index, "validate=no"])?;
    }
    Ok(())
}

fn dns_error(message: &str) -> windows::core::Error {
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
    let provider = (*CHOSEN.lock().unwrap()).ok_or_else(|| dns_error("no DNS service picked"))?;
    let adapter = dns_adapter().ok_or_else(|| dns_error("no cable or Wi-Fi connection"))?;
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
    previous.and_then(SavedDns::decode).ok_or_else(|| dns_error("nothing saved to put back"))?.put_back()
}

/// Back to DHCP on the adapter in use, for DNS that was set before Vantix.
pub fn reset_dns() -> windows::core::Result<()> {
    let adapter = dns_adapter().ok_or_else(|| dns_error("no cable or Wi-Fi connection"))?;
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
    /// Values that count as on; the first is the one written.
    on: &'static [&'static str],
    off: &'static str,
}

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

/// The adapter's driver key, found by its GUID.
fn class_key(guid: &str) -> Option<String> {
    let id = |key: &str| reg::get_string(reg::HKEY_LOCAL_MACHINE, key, "NetCfgInstanceId").ok().flatten();
    reg::subkeys(reg::HKEY_LOCAL_MACHINE, NET_CLASS)
        .into_iter()
        .map(|sub| format!(r"{NET_CLASS}\{sub}"))
        .find(|key| id(key).is_some_and(|id| id.eq_ignore_ascii_case(guid)))
}

/// Whether the driver lists the keyword and takes `value` for it.
fn accepts(key: &str, keyword: &str, value: &str) -> bool {
    let params = format!(r"{key}\Ndi\Params\{keyword}");
    let choices = format!(r"{params}\enum");
    reg::key_exists(reg::HKEY_LOCAL_MACHINE, &params)
        && (!reg::key_exists(reg::HKEY_LOCAL_MACHINE, &choices)
            || reg::get_string(reg::HKEY_LOCAL_MACHINE, &choices, value).is_ok_and(|v| v.is_some()))
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
    setting_adapter(id, wifi).ok_or_else(|| dns_error("no adapter to change"))
}

fn present(setting: &AdapterSetting, key: &str) -> Vec<&'static Property> {
    setting.properties.iter().filter(|p| accepts(key, p.keyword, p.on[0])).collect()
}

fn setting_on(setting: &AdapterSetting, key: &str) -> bool {
    let properties = present(setting, key);
    !properties.is_empty()
        && properties.iter().all(|p| property(key, p.keyword).is_some_and(|v| p.on.contains(&v.as_str())))
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
        if property(&key, p.keyword).is_some_and(|v| p.on.contains(&v.as_str())) {
            continue;
        }
        let written = reg::get_string(reg::HKEY_LOCAL_MACHINE, &key, p.keyword).and_then(|old| {
            saved.push(format!("{}={}", p.keyword, old.as_deref().unwrap_or("-")));
            reg::set_string(reg::HKEY_LOCAL_MACHINE, &key, p.keyword, p.on[0])
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
        if accepts(&key, p.keyword, p.off) {
            reg::set_string(reg::HKEY_LOCAL_MACHINE, &key, p.keyword, p.off)?;
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

#[repr(C)]
struct Properties {
    base: EVENT_TRACE_PROPERTIES,
    name: [u16; 64],
}

fn properties() -> Properties {
    let mut properties = Properties { base: EVENT_TRACE_PROPERTIES::default(), name: [0; 64] };
    properties.base.Wnode.BufferSize = size_of::<Properties>() as u32;
    properties.base.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    properties.base.Wnode.ClientContext = 1; // QPC timestamps
    properties.base.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    properties.base.FlushTimer = 1;
    // One event per send and receive adds up fast on a gigabit line; small default
    // buffers fill and drop events, which would read as less traffic than there was.
    properties.base.BufferSize = 256; // KB
    properties.base.MinimumBuffers = 8;
    properties.base.MaximumBuffers = 64;
    properties.base.LoggerNameOffset = std::mem::offset_of!(Properties, name) as u32;
    properties
}

fn stop_session() {
    let mut properties = properties();
    unsafe {
        let _ = ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            &HSTRING::from(SESSION),
            &mut properties.base,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

/// Starts counting. Needs admin rights, which Vantix always has.
pub fn traffic_start() -> windows::core::Result<()> {
    if SESSION_ON.swap(true, Ordering::Relaxed) {
        return Ok(());
    }
    *COUNTERS.lock().unwrap() = Some(HashMap::new());
    let result = start_session();
    if result.is_err() {
        SESSION_ON.store(false, Ordering::Relaxed);
    }
    result
}

fn start_session() -> windows::core::Result<()> {
    stop_session();
    let name = HSTRING::from(SESSION);
    let mut properties = properties();
    let mut handle = CONTROLTRACE_HANDLE::default();
    unsafe {
        StartTraceW(&mut handle, &name, &mut properties.base).ok()?;
        let enabled = EnableTraceEx2(
            handle,
            &KERNEL_NETWORK,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            4, // TRACE_LEVEL_INFORMATION
            KEYWORDS,
            0,
            0,
            None,
        );
        if let Err(e) = enabled.ok() {
            stop_session();
            return Err(e);
        }
        let mut logger: Vec<u16> = SESSION.encode_utf16().chain([0]).collect();
        let mut logfile = EVENT_TRACE_LOGFILEW { LoggerName: PWSTR(logger.as_mut_ptr()), ..Default::default() };
        logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(on_event);
        let trace = OpenTraceW(&mut logfile);
        if trace.Value == u64::MAX {
            let error = windows::core::Error::from_thread();
            stop_session();
            return Err(error);
        }
        std::thread::spawn(move || {
            let _ = ProcessTrace(&[trace], None, None);
            let _ = CloseTrace(trace);
        });
    }
    Ok(())
}

/// Ends a session left running by a Vantix that was killed or crashed on the traffic tab.
pub fn end_leftover_trace() {
    if !SESSION_ON.load(Ordering::Relaxed) {
        stop_session();
    }
}

/// Ends the session, which also makes the consumer thread return.
pub fn traffic_stop() {
    if SESSION_ON.swap(false, Ordering::Relaxed) {
        stop_session();
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
    if record.EventHeader.ProviderId != KERNEL_NETWORK || record.UserDataLength < 8 || record.UserData.is_null() {
        return;
    }
    let data = record.UserData.cast::<u8>();
    let (pid, size) = unsafe { (data.cast::<u32>().read_unaligned(), data.add(4).cast::<u32>().read_unaligned()) };
    if let Some(counters) = COUNTERS.lock().unwrap().as_mut() {
        counters.entry(pid).or_default()[direction] += u64::from(size);
    }
}

/// Totals per program name, received and sent, since `traffic_start`. Processes of the
/// same exe add up, so a browser shows as one line.
pub fn traffic() -> HashMap<String, [u64; 2]> {
    let counters: Vec<(u32, [u64; 2])> =
        COUNTERS.lock().unwrap().as_ref().map(|c| c.iter().map(|(p, b)| (*p, *b)).collect()).unwrap_or_default();
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

fn process_name(pid: u32) -> String {
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
        let result = QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, PWSTR(path.as_mut_ptr()), &mut len);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `cargo test net_connection -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn net_connection() {
        let c = connection().expect("no connection");
        println!(
            "{} {} index={} physical={} ipv6={} gateway={:?} dhcp={} dns={:?} current={:?} set={:?}",
            c.name, c.guid, c.index, c.physical, c.ipv6, c.gateway, c.dhcp, c.dns, current_dns(), dns_set()
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

    /// `cargo test net_dns -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn net_dns() {
        let start = Instant::now();
        for r in dns_benchmark() {
            println!(
                "{:<12} {:<16} cached={:.1?} uncached={:.1?} failed={}/{}",
                r.name, r.address, r.cached, r.uncached, r.failed, r.sent
            );
        }
        println!("took {:?}", start.elapsed());
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
        let saved = SavedDns { guid: "{A}".into(), v4: vec!["192.168.0.1".into(), "8.8.8.8".into()], v6: Vec::new() };
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
}
