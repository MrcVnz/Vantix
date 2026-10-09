//! Internet diagnostics: live ping, bufferbloat, DNS benchmark and traffic per program,
//! plus the repairs on the Repair tab. Only the repairs change the system. Every call that
//! measures blocks, so run it off the UI thread; the live ping and the traffic monitor run
//! on threads of their own.

use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasher, RandomState};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses,
    GetBestInterface, ICMP_ECHO_REPLY, IP_ADAPTER_ADDRESSES_LH, IcmpCloseHandle, IcmpCreateFile,
    IcmpSendEcho,
};
use windows::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows::Win32::Networking::WinHttp::{
    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, WINHTTP_FLAG_SECURE, WINHTTP_QUERY_DATE, WINHTTP_QUERY_FLAG_NUMBER,
    WINHTTP_QUERY_STATUS_CODE, WinHttpCloseHandle, WinHttpConnect, WinHttpOpen, WinHttpOpenRequest,
    WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest, WinHttpSetTimeouts,
    WinHttpWriteData,
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
        let session = Http(WinHttpOpen(
            &HSTRING::from("Vantix"),
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            PCWSTR::null(),
            PCWSTR::null(),
            0,
        ))
        .ok()?;
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
}

pub const PROVIDERS: [Provider; 5] = [
    Provider {
        name: "Cloudflare",
        v4: [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(1, 0, 0, 1)],
        v6: [
            Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
            Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1001),
        ],
    },
    Provider {
        name: "Google",
        v4: [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(8, 8, 4, 4)],
        v6: [
            Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
            Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844),
        ],
    },
    Provider {
        name: "Quad9",
        v4: [Ipv4Addr::new(9, 9, 9, 9), Ipv4Addr::new(149, 112, 112, 112)],
        v6: [
            Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0xfe),
            Ipv6Addr::new(0x2620, 0xfe, 0, 0, 0, 0, 0, 0x9),
        ],
    },
    Provider {
        name: "OpenDNS",
        v4: [Ipv4Addr::new(208, 67, 222, 222), Ipv4Addr::new(208, 67, 220, 220)],
        v6: [
            Ipv6Addr::new(0x2620, 0x119, 0x35, 0, 0, 0, 0, 0x35),
            Ipv6Addr::new(0x2620, 0x119, 0x53, 0, 0, 0, 0, 0x53),
        ],
    },
    Provider {
        name: "AdGuard",
        v4: [Ipv4Addr::new(94, 140, 14, 14), Ipv4Addr::new(94, 140, 15, 15)],
        v6: [
            Ipv6Addr::new(0x2a10, 0x50c0, 0, 0, 0, 0, 0xad1, 0xff),
            Ipv6Addr::new(0x2a10, 0x50c0, 0, 0, 0, 0, 0xad2, 0xff),
        ],
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
        let jobs: Vec<_> =
            resolvers.into_iter().map(|address| s.spawn(move || measure_resolver(address, scope))).collect();
        jobs.into_iter().filter_map(|job| job.join().ok()).collect()
    });
    results.sort_by(|a, b| {
        b.reliable()
            .cmp(&a.reliable())
            .then(a.score().unwrap_or(f64::MAX).total_cmp(&b.score().unwrap_or(f64::MAX)))
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
        IpAddr::V6(v6) if v6.segments()[0] & 0xffc0 == 0xfe80 => {
            SocketAddr::V6(SocketAddrV6::new(v6, 53, 0, scope))
        }
        _ => SocketAddr::new(address, 53),
    };
    let local: SocketAddr =
        if address.is_ipv4() { "0.0.0.0:0".parse().unwrap() } else { "[::]:0".parse().unwrap() };
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
    let uncached: Vec<f64> = DOMAINS
        .iter()
        .step_by(2)
        .filter_map(|domain| ask(&format!("{:x}.{domain}", random() & 0xffff_ffff)))
        .collect();
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
    setting_adapter(id, wifi).ok_or_else(|| failure("no adapter to change"))
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

// More repairs from the Repair tab. The ones with a journal entry keep one, so undo puts
// back exactly what was there before Vantix touched it.

/// WinINet and WinHTTP proxy leftovers: a VPN or malware set it once and it stayed, and
/// everything else sees "no internet" while requests die on a dead address. WinHTTP is
/// the machine-wide one; `netsh winhttp` keeps it in a binary blob under Internet Settings.
pub const PROXY_TWEAK: &str = "proxy-reset";
const PROXY_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
const WINHTTP_CONNECTIONS: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections";
const WINHTTP_SETTINGS: &str = "WinHttpSettings";

/// Whether the WinHTTP blob enables a proxy. Layout (little endian): version, counter,
/// flags (bit 0 always set, bit 1 manual proxy, bit 2 setup script, bit 3 auto detect),
/// then proxy, bypass and setup script as length prefixed ASCII strings. Windows keeps a
/// blob even for direct access, so a missing value and a flags-only blob both mean none.
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
    Ok(user || machine)
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

/// Saved as "enable|server|override|autoproxy|winhttp-hex", `-` for nothing set.
/// The WinHTTP part is the raw blob in hex, so undo writes back exactly what was there.
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
    let saved = fields.join("|");

    reg::set_dword(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyEnable", 0)?;
    for name in ["ProxyServer", "ProxyOverride", "AutoConfigURL"] {
        let _ = reg::delete_value(reg::HKEY_CURRENT_USER, PROXY_KEY, name);
    }
    tweaks::run("netsh.exe", &["winhttp", "reset", "proxy"])?;
    notify_proxy_changed();
    Ok(Some(saved))
}

/// The card shows reset (off) while any of them is set, whatever it's set to.
pub fn shows_proxy() -> bool {
    in_journal(PROXY_TWEAK) || proxy_set().unwrap_or(false)
}

/// True when no proxy is set, which is what this tweak applies.
pub fn proxy_clear() -> windows::core::Result<bool> {
    Ok(!proxy_set()?)
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

/// Domains in the hosts file that look like Vantix's own: what a browser or updater
/// should reach, sent somewhere else by hand.
const HOSTS_OF_INTEREST: [&str; 6] =
    ["microsoft.com", "windowsupdate.com", "google.com", "apple.com", "cloudflare.com", "steamcommunity.com"];

/// Whether a hosts entry names the domain itself or one below it. A plain suffix
/// match would also catch "notgoogle.com".
fn hosts_match(host: &str, domain: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == domain || host.ends_with(&format!(".{domain}"))
}

fn hosts_blocking(line: &str) -> bool {
    HOSTS_OF_INTEREST
        .iter()
        .any(|domain| line.split_whitespace().skip(1).any(|host| hosts_match(host, domain)))
}

/// (total lines, blocking ones), `None` when the file is missing or unreadable.
pub fn hosts_state() -> Option<(usize, usize)> {
    hosts_state_in(HOSTS_PATH)
}

pub fn hosts_state_in(path: &str) -> Option<(usize, usize)> {
    let bytes = std::fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<&str> =
        text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).collect();
    let blocking = lines.iter().filter(|l| hosts_blocking(l)).count();
    Some((lines.len(), blocking))
}

/// Whether the hosts file is already back to safe form. The journal holds one entry,
/// so the changed form is checked by the card that offers the reset.
/// Whether any hosts line gets in the way of a domain Vantix cares about, which is what
/// the card offers to clean.
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

/// Saved as the number of blocks taken out; the bytes themselves are the backup file.
pub fn reset_hosts() -> windows::core::Result<Option<String>> {
    reset_hosts_in(HOSTS_PATH, HOSTS_BACKUP)
}

pub fn reset_hosts_in(path: &str, backup: &str) -> windows::core::Result<Option<String>> {
    let Some((_, blocking)) = hosts_state_in(path) else { return Err(failure("hosts file is missing")) };
    if blocking > 0 {
        std::fs::copy(path, backup)?;
        let bytes = std::fs::read(path)?;
        let text = String::from_utf8_lossy(&bytes).into_owned();
        let mut kept: Vec<&str> = Vec::new();
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || !hosts_blocking(trimmed) {
                kept.push(line);
            }
        }
        let out = if kept.is_empty() { String::new() } else { kept.join("\r\n") + "\r\n" };
        if let Err(e) = std::fs::write(path, out) {
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

/// The binding is on if the component is enabled; Vantix's own change is seen in the
/// journal, like everywhere else.
/// The card shows only when the diagnosis blamed IPv6, or while the change is in the
/// journal for undo. Global IPv6 off stays out of the app.
pub fn shows_ipv6() -> bool {
    if in_journal(IPV6_TWEAK) {
        return true;
    }
    STATUSES.lock().unwrap().iter().any(|(layer, status)| *layer == Layer::Ipv6 && *status == Status::Failed)
}

pub fn ipv6_off() -> windows::core::Result<bool> {
    let Some(adapter) = connection() else { return Ok(false) };
    let quoted = adapter.name.replace('\'', "");
    let out = tweaks::powershell(&format!(
        "(Get-NetAdapterBinding -Name '{quoted}' -ComponentID ms_tcpip6).Enabled"
    ))?;
    Ok(out.trim().eq_ignore_ascii_case("false"))
}

/// Saved as the adapter's GUID, so undo finds the same adapter after a restart.
pub fn disable_ipv6() -> windows::core::Result<Option<String>> {
    let Some(adapter) = connection() else { return Err(failure("no connected adapter")) };
    let quoted = adapter.name.replace('\'', "");
    tweaks::powershell(&format!(
        "Disable-NetAdapterBinding -Name '{quoted}' -ComponentID ms_tcpip6 -ErrorAction Stop"
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
    let quoted = adapter.name.replace('\'', "");
    tweaks::powershell(&format!(
        "Enable-NetAdapterBinding -Name '{quoted}' -ComponentID ms_tcpip6 -ErrorAction Stop"
    ))?;
    Ok(())
}

pub fn enable_ipv6() -> windows::core::Result<()> {
    restore_ipv6(Some(&connection().map(|c| c.guid).unwrap_or_default()))
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
    /// The router answers pings.
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
    /// This layer is the one that broke.
    Failed,
    /// Everything before it failed, so this never ran.
    Skipped,
}

/// Detail text per layer, shown under the layer name: what answered and how fast.
static DETAILS: Mutex<Option<Vec<String>>> = Mutex::new(None);
/// One status per layer, read by the tick every 250 ms.
static STATUSES: Mutex<Vec<(Layer, Status)>> = Mutex::new(Vec::new());
/// Whether a diagnosis is running right now, so the staggered retries stop.
static DIAG_ON: AtomicBool = AtomicBool::new(false);

pub fn diag_statuses() -> Vec<(Layer, Status)> {
    STATUSES.lock().unwrap().clone()
}

pub fn diag_details() -> Vec<String> {
    DETAILS.lock().unwrap().clone().unwrap_or_default()
}

pub fn diag_running() -> bool {
    DIAG_ON.load(Ordering::Relaxed)
}

fn set_status(i: usize, status: Status) {
    STATUSES.lock().unwrap()[i].1 = status;
}

fn set_detail(i: usize, detail: String) {
    if let Some(details) = DETAILS.lock().unwrap().as_mut()
        && i < details.len()
    {
        details[i] = detail;
    }
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

/// One run of the layered diagnosis. Layers 1 to 7 (Link to NCSI) stop at the first
/// failure. Proxy, hosts, VPN and IPv6 always run, each with its own status, so a dead
/// proxy is still reported when HTTPS already failed.
pub fn diagnose() {
    if DIAG_ON.swap(true, Ordering::Relaxed) {
        return;
    }
    *STATUSES.lock().unwrap() = LAYERS.map(|layer| (layer, Status::Queued)).to_vec();
    *DETAILS.lock().unwrap() = Some(vec![String::new(); LAYERS.len()]);
    let icmp = Icmp::new();
    let mut failed_early = false;
    let mut reach_ok = false;
    for (i, layer) in LAYERS.iter().enumerate() {
        // The last four checks always run, even after an early failure.
        let always = matches!(layer, Layer::Proxy | Layer::Hosts | Layer::Vpn | Layer::Ipv6);
        if failed_early && !always {
            set_status(i, Status::Skipped);
            continue;
        }
        set_status(i, Status::Running);
        let outcome = match layer {
            Layer::Link => link(),
            Layer::Ip => ip(),
            Layer::Gateway => gateway(icmp.as_ref()),
            Layer::Dns => dns(),
            Layer::Reach => reach(icmp.as_ref()),
            Layer::Https => https(),
            Layer::Ncsi => ncsi(),
            Layer::Proxy => proxy(),
            Layer::Hosts => hosts(),
            Layer::Vpn => vpn(),
            Layer::Ipv6 => ipv6(reach_ok),
        };
        if *layer == Layer::Reach && outcome.is_ok() {
            reach_ok = true;
        }
        match outcome {
            Ok(detail) => {
                set_detail(i, detail);
                set_status(i, Status::Ok);
            }
            // Irrelevant here: not a pass, not a failure.
            Err(None) => {
                set_status(i, Status::Skipped);
            }
            Err(Some(detail)) => {
                set_detail(i, detail);
                set_status(i, Status::Failed);
                if !always {
                    failed_early = true;
                }
            }
        }
    }
    DIAG_ON.store(false, Ordering::Relaxed);
}

fn link() -> Result<String, Option<String>> {
    let Some(adapter) = connection() else { return Err(Some("no connected adapter".into())) };
    if !adapter.up {
        return Err(Some("the adapter reports no link".into()));
    }
    Ok(if adapter.wifi { "Wi-Fi" } else { "cable" }.into())
}

fn ip() -> Result<String, Option<String>> {
    let Some(adapter) = connection() else { return Err(Some(String::new())) };
    check_ip(adapter.ip).map_err(Some)
}

/// Pure check for tests: the PC address fails only when missing or link-local.
/// A public gateway or CGNAT (100.64.0.0/10) is legitimate and passes.
fn check_ip(addr: Option<Ipv4Addr>) -> Result<String, String> {
    let Some(addr) = addr else { return Err("no IPv4 address on the adapter".into()) };
    if addr.is_link_local() {
        return Err("169.254 address: DHCP never answered".into());
    }
    Ok(addr.to_string())
}

fn gateway(icmp: Option<&Icmp>) -> Result<String, Option<String>> {
    let Some(address) = connection().and_then(|c| c.gateway) else { return Err(None) };
    let Some(icmp) = icmp else { return Err(None) };
    match ping_best(icmp, address) {
        Some(time) => Ok(format!("best of 3: {time:.1} ms")),
        None => Err(Some(format!("no answer from the router at {address}"))),
    }
}

fn dns() -> Result<String, Option<String>> {
    let servers = current_dns();
    if servers.is_empty() {
        return Err(Some("no DNS server set".into()));
    }
    for server in &servers {
        if let Some(ms) = query_server(*server, "google.com") {
            return Ok(format!("{server} answered in {ms:.0} ms"));
        }
    }
    // The configured servers are silent: ask 1.1.1.1 to tell a DNS outage apart
    // from a network outage.
    if let Some(ms) = query_server(IpAddr::V4(CLOUDFLARE), "google.com") {
        return Err(Some(format!("your DNS servers do not answer, 1.1.1.1 does in {ms:.0} ms")));
    }
    let first = servers[0];
    Err(Some(format!("no answer from {first}")))
}

/// One raw query straight to the server, with its round trip in ms.
fn query_server(server: IpAddr, domain: &str) -> Option<f64> {
    let local: SocketAddr =
        if server.is_ipv6() { "[::]:0".parse().unwrap() } else { "0.0.0.0:0".parse().unwrap() };
    let socket = UdpSocket::bind(local).ok()?;
    socket.connect(SocketAddr::new(server, 53)).ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    lookup(&socket, domain)
}

fn reach(icmp: Option<&Icmp>) -> Result<String, Option<String>> {
    if let Some(time) = icmp.and_then(|icmp| ping_best(icmp, CLOUDFLARE)) {
        return Ok(format!("ping to 1.1.1.1, best of 3: {time:.1} ms"));
    }
    // Pings may be dropped deliberately: reach out with TCP instead.
    tcp_check(CLOUDFLARE.into())
}

/// TCP 443 to one address, for machines and networks where ICMP does not get through.
fn tcp_check(address: IpAddr) -> Result<String, Option<String>> {
    let began = Instant::now();
    TcpStream::connect_timeout(&SocketAddr::new(address, 443), Duration::from_secs(4))
        .map_err(|_| Some(format!("cannot reach {address} on TCP 443")))?;
    Ok(format!("TCP 443, {:.1} ms", began.elapsed().as_secs_f64() * 1000.0))
}

fn https() -> Result<String, Option<String>> {
    let Some((_session, connection)) = http_connection() else { return Err(None) };
    let Some(request) = request(&connection, "HEAD", "/__down?bytes=1") else {
        return Err(None);
    };
    if unsafe { WinHttpSendRequest(request.0, None, None, 0, 0, 0).is_err() } || !answered_ok(&request) {
        // A dead proxy breaks HTTPS while raw TCP still works; the proxy layer below
        // names it, so say so here too.
        if proxy_set().unwrap_or(false) {
            return Err(Some("HTTPS failed and a proxy is set, the proxy is the likely cause".into()));
        }
        return Err(Some("the HTTPS handshake or request failed".into()));
    }
    // A clock wrong by more than a day, either way, makes every certificate look dead.
    // The first call with a null buffer always reports insufficient buffer; that is how
    // the needed size is asked for.
    let mut header_size = 0u32;
    unsafe {
        let _ = WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_DATE,
            PCWSTR::null(),
            None,
            &mut header_size,
            std::ptr::null_mut(),
        );
    }
    if header_size == 0 {
        return Err(None);
    }
    let mut buffer = vec![0u16; (header_size / 2) as usize];
    unsafe {
        if WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_DATE,
            PCWSTR::null(),
            Some(buffer.as_mut_ptr().cast()),
            &mut header_size,
            std::ptr::null_mut(),
        )
        .is_err()
        {
            return Err(None);
        }
    }
    let date = String::from_utf16_lossy(&buffer);
    let now = chrono::Utc::now();
    if sent_time_worse(&date, now).unwrap_or(false) {
        return Err(Some("answer received, but the clock is off by more than a day".into()));
    }
    match clock_offset_secs(&date, now) {
        Some(secs) if secs.abs() >= 120 => {
            let mins = secs.abs() / 60;
            let side = if secs > 0 { "ahead" } else { "behind" };
            Ok(format!("answered, clock {mins} min {side}"))
        }
        Some(secs) => Ok(format!("answered, clock within {} s", secs.abs().max(1))),
        None => Ok("answered".into()),
    }
}

/// Parses a Date header like "Mon, 01 Jan 2026 12:00:00 GMT".
fn parse_http_date(date: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    const MONTHS: [&str; 12] =
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let words: Vec<&str> = date.split_whitespace().collect();
    if words.len() < 5 {
        return None;
    }
    let day: u32 = words[1].parse().ok()?;
    let month = MONTHS.iter().position(|m| words[2].starts_with(m))? as u32;
    let year: i64 = words[3].parse().ok()?;
    let clock = words[4].trim_end_matches("GMT").trim();
    let mut clock = clock.split(':');
    let hour = clock.next()?.parse().ok()?;
    let minute = clock.next()?.parse().ok()?;
    let second = clock.next().unwrap_or("0").parse().ok()?;
    chrono::NaiveDate::from_ymd_opt(year as i32, month + 1, day)?
        .and_hms_opt(hour, minute, second)?
        .and_utc()
        .into()
}

/// Seconds the Date header is away from the local clock, positive when ahead.
fn clock_offset_secs(date: &str, now: chrono::DateTime<chrono::Utc>) -> Option<i64> {
    Some((parse_http_date(date)? - now).num_seconds())
}

/// Whether a Date header is more than a day away from the local clock.
///
/// WinHTTP quotes the header in HTTP time format like "Mon, 01 Jan 2026 12:00:00 GMT".
/// Parsing it by hand keeps the layer free of another dependency.
fn sent_time_worse(date: &str, now: chrono::DateTime<chrono::Utc>) -> Option<bool> {
    Some(clock_offset_secs(date, now)?.abs() > chrono::Duration::days(1).num_seconds())
}

fn ncsi() -> Result<String, Option<String>> {
    // The probe Windows itself uses: a plain HTTP GET that must answer the exact body.
    // A direct TCP connection, so a broken proxy cannot hide the answer.
    match ncsi_body() {
        Some(body) => check_ncsi(&body).map_err(Some),
        None => Err(None),
    }
}

/// Pure check for tests: the exact body means internet, anything else is a captive portal.
fn check_ncsi(body: &str) -> Result<String, String> {
    if body.contains("Microsoft Connect Test") {
        Ok("Windows agrees there is internet".into())
    } else {
        Err("a sign-in page is intercepting the connection".into())
    }
}

/// GETs the NCSI text file over plain HTTP with a 5 s timeout.
fn ncsi_body() -> Option<String> {
    let addr = format!("{}:80", "www.msftconnecttest.com").to_socket_addrs().ok()?.find(|a| a.is_ipv4())?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok()?;
    stream
        .write_all(
            b"GET /connecttest.txt HTTP/1.0\r\nHost: www.msftconnecttest.com\r\nConnection: close\r\n\r\n",
        )
        .ok()?;
    let mut text = String::new();
    stream.read_to_string(&mut text).ok()?;
    // Confirm the NCSI DNS name still resolves to the expected address when possible.
    // A mismatch does not fail the layer; the body above is what counts.
    let _ = ncsi_dns_ok();
    text.split("\r\n\r\n").nth(1).or(Some(text.as_str())).map(str::to_string)
}

fn ncsi_dns_ok() -> bool {
    format!("{}:80", "dns.msftncsi.com")
        .to_socket_addrs()
        .map(|mut addrs| addrs.any(|a| a.ip() == IpAddr::V4(Ipv4Addr::new(131, 107, 255, 255))))
        .unwrap_or(false)
}

fn proxy() -> Result<String, Option<String>> {
    match proxy_set() {
        Ok(false) => Ok("no proxy set".into()),
        Ok(true) => Err(Some("a proxy is set in WinINet or WinHTTP".into())),
        Err(_) => Err(None),
    }
}

fn hosts() -> Result<String, Option<String>> {
    match hosts_state() {
        Some((total, blocking)) if blocking > 0 => {
            Err(Some(format!("{blocking} of {total} lines send well-known domains elsewhere")))
        }
        Some((total, _)) => Ok(format!("{total} lines, none in the way")),
        None => Err(None),
    }
}

/// A leftover adapter of a VPN that was removed badly keeps routing and filtering
/// rules that were set up for it. Only counts when the vendor program is gone too;
/// a working VPN is not leftovers. A warning, never a stop: the layer reports it but
/// the diagnosis keeps going.
const VPN_MARKS: [&str; 8] =
    ["TAP-Windows", "Wintun", "WireGuard", "OpenVPN", "Tailscale", "ZeroTier", "NordLynx", "ProtonVPN"];

fn vpn() -> Result<String, Option<String>> {
    let leftover: Vec<String> = adapters()
        .into_iter()
        .filter(|a| !a.up)
        .filter(|a| {
            let description = a.description.to_ascii_lowercase();
            VPN_MARKS.iter().any(|mark| description.contains(&mark.to_ascii_lowercase()))
        })
        .filter(|_| !vpn_program_installed())
        .map(|a| a.name)
        .collect();
    if leftover.is_empty() {
        Ok("no leftover VPN adapters".into())
    } else {
        Err(Some(format!("leftover VPN adapters: {}", leftover.join(", "))))
    }
}

/// Whether any vendor VPN program is still installed, from the Uninstall keys.
fn vpn_program_installed() -> bool {
    for root in [reg::HKEY_LOCAL_MACHINE, reg::HKEY_CURRENT_USER] {
        for key in [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ] {
            for sub in reg::subkeys(root, key) {
                let path = format!(r"{key}\{sub}");
                let name = reg::string_values(root, &path)
                    .unwrap_or_default()
                    .into_iter()
                    .find(|(n, _)| n == "DisplayName")
                    .map(|(_, v)| v)
                    .unwrap_or_default()
                    .to_ascii_lowercase();
                if VPN_MARKS.iter().any(|mark| name.contains(&mark.to_ascii_lowercase())) {
                    return true;
                }
            }
        }
    }
    false
}

/// IPv6 with a global address but no working route. Only fails when the adapter has a
/// global address, IPv6 to a known host fails, and IPv4 (Reach) passed. Without a
/// global address the layer is skipped.
fn ipv6(reach_ok: bool) -> Result<String, Option<String>> {
    let Some(adapter) = connection() else { return Err(None) };
    if !adapter.ipv6 {
        return Err(None);
    }
    let target = "2606:4700:4700::1111".parse().map(|ip| SocketAddr::new(ip, 443));
    let Ok(target) = target else { return Err(None) };
    let ok = TcpStream::connect_timeout(&target, Duration::from_secs(3)).is_ok();
    if ok {
        return Ok("IPv6 reaches 2606:4700:4700::1111".into());
    }
    if reach_ok {
        return Err(Some("IPv6 is on but unreachable".into()));
    }
    Err(None)
}

/// The tweak id that fixes a failed layer, if one applies. Clock failures map to the
/// clock repair; captive portals and VPN leftovers need manual steps instead.
pub fn repair_for_layer(layer: Layer, detail: &str) -> Option<&'static str> {
    match layer {
        Layer::Link => Some("restart-connection"),
        Layer::Ip => Some("renew-ip"),
        Layer::Gateway => Some("clear-arp"),
        Layer::Dns => Some("flush-dns"),
        Layer::Reach => Some("restart-connection"),
        Layer::Https if detail.contains("clock") => Some("sync-clock"),
        Layer::Https => None,
        Layer::Ncsi => None,
        Layer::Proxy => Some(PROXY_TWEAK),
        Layer::Hosts => Some(HOSTS_TWEAK),
        Layer::Vpn => None,
        Layer::Ipv6 => Some(IPV6_TWEAK),
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
            c.name,
            c.guid,
            c.index,
            c.physical,
            c.ipv6,
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
        let statuses = diag_statuses();
        let details = diag_details();
        for (i, (layer, status)) in statuses.iter().enumerate() {
            println!(
                "{:<5} {:?} {}",
                format!("{}", i + 1),
                status,
                details.get(i).map(String::as_str).unwrap_or("")
            );
            assert_eq!(*layer, LAYERS[i]);
            assert_ne!(*status, Status::Running, "no layer stays running");
            assert_ne!(
                *status,
                Status::Failed,
                "layer {layer:?} failed: {}",
                details.get(i).map(String::as_str).unwrap_or("")
            );
            if *status == Status::Ok {
                assert!(
                    !details.get(i).map(String::as_str).unwrap_or("").is_empty(),
                    "layer {layer:?} Ok needs a detail"
                );
            }
        }
        // Nothing changes the system: the run itself must leave the flag down.
        assert!(!DIAG_ON.load(Ordering::Relaxed));
        assert!(!diag_running());
        println!("took {:?}", start.elapsed());
    }

    /// Reads the proxy, writes a fake one, clears it through the tweak's own calls,
    /// puts the original back and checks the registry byte for byte:
    /// `cargo test proxy_round_trip -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn proxy_round_trip() {
        struct Guard {
            enable: Option<u32>,
            server: Option<String>,
            override_list: Option<String>,
            auto: Option<String>,
            winhttp: Option<Vec<u8>>,
        }
        impl Drop for Guard {
            fn drop(&mut self) {
                match self.enable {
                    Some(v) => {
                        let _ = reg::set_dword(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyEnable", v);
                    }
                    None => {
                        let _ = reg::delete_value(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyEnable");
                    }
                }
                match &self.server {
                    Some(v) => {
                        let _ = reg::set_string(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyServer", v);
                    }
                    None => {
                        let _ = reg::delete_value(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyServer");
                    }
                }
                match &self.override_list {
                    Some(v) => {
                        let _ = reg::set_string(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyOverride", v);
                    }
                    None => {
                        let _ = reg::delete_value(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyOverride");
                    }
                }
                match &self.auto {
                    Some(v) => {
                        let _ = reg::set_string(reg::HKEY_CURRENT_USER, PROXY_KEY, "AutoConfigURL", v);
                    }
                    None => {
                        let _ = reg::delete_value(reg::HKEY_CURRENT_USER, PROXY_KEY, "AutoConfigURL");
                    }
                }
                match &self.winhttp {
                    Some(blob) => {
                        let _ = reg::set_binary(
                            reg::HKEY_LOCAL_MACHINE,
                            WINHTTP_CONNECTIONS,
                            WINHTTP_SETTINGS,
                            blob,
                        );
                    }
                    None => {
                        let _ =
                            reg::delete_value(reg::HKEY_LOCAL_MACHINE, WINHTTP_CONNECTIONS, WINHTTP_SETTINGS);
                    }
                }
                notify_proxy_changed();
            }
        }
        let read = || -> Option<String> {
            reg::get_string(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyServer").unwrap()
        };
        let saved_enable = reg::get_dword(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyEnable").unwrap();
        let saved_server = read();
        let saved_override = reg::get_string(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyOverride").unwrap();
        let saved_auto = reg::get_string(reg::HKEY_CURRENT_USER, PROXY_KEY, "AutoConfigURL").unwrap();
        let saved_winhttp =
            reg::get_binary(reg::HKEY_LOCAL_MACHINE, WINHTTP_CONNECTIONS, WINHTTP_SETTINGS).unwrap();
        let _guard = Guard {
            enable: saved_enable,
            server: saved_server.clone(),
            override_list: saved_override.clone(),
            auto: saved_auto.clone(),
            winhttp: saved_winhttp.clone(),
        };
        println!("before: enable={saved_enable:?} server={saved_server:?} winhttp={saved_winhttp:?}");
        let before_netsh = tweaks::run("netsh.exe", &["winhttp", "show", "proxy"]).unwrap_or_default();
        println!("before netsh: {before_netsh}");
        reg::set_dword(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyEnable", 1).unwrap();
        reg::set_string(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyServer", "127.0.0.1:9999").unwrap();
        notify_proxy_changed();
        assert!(proxy_set().unwrap(), "a set proxy must be seen");
        assert!(!proxy_clear().unwrap(), "clear reads false while a proxy is set");
        let start = Instant::now();
        let previous = reset_proxy().unwrap();
        println!("saved {previous:?} in {:?}", start.elapsed());
        assert!(!proxy_set().unwrap(), "reset must clear both WinINet and WinHTTP");
        assert!(proxy_clear().unwrap(), "clear reads true once the proxy is gone");
        assert_eq!(reg::get_dword(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyEnable").unwrap(), Some(0));
        restore_proxy(previous.as_deref()).unwrap();
        // Undo puts back the fake proxy that was saved, not the original from before the test.
        assert_eq!(reg::get_dword(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyEnable").unwrap(), Some(1));
        assert_eq!(read().as_deref(), Some("127.0.0.1:9999"));
        drop(_guard);
        assert_eq!(reg::get_dword(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyEnable").unwrap(), saved_enable);
        assert_eq!(read(), saved_server);
        assert_eq!(
            reg::get_string(reg::HKEY_CURRENT_USER, PROXY_KEY, "ProxyOverride").unwrap(),
            saved_override
        );
        assert_eq!(reg::get_string(reg::HKEY_CURRENT_USER, PROXY_KEY, "AutoConfigURL").unwrap(), saved_auto);
        assert_eq!(
            reg::get_binary(reg::HKEY_LOCAL_MACHINE, WINHTTP_CONNECTIONS, WINHTTP_SETTINGS).unwrap(),
            saved_winhttp
        );
        let after_netsh = tweaks::run("netsh.exe", &["winhttp", "show", "proxy"]).unwrap_or_default();
        println!("after netsh: {after_netsh}");
        assert_eq!(after_netsh, before_netsh, "WinHTTP proxy must read the same after undo");
        println!("after: enable={:?} server={:?}", saved_enable, read());
    }

    /// Cleans a scratch copy of a hosts file, never the real one:
    /// `cargo test hosts_round_trip -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn hosts_round_trip() {
        let dir = std::env::temp_dir().join(format!("vantix-hosts-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("hosts").to_string_lossy().into_owned();
        let backup = dir.join("hosts.bak").to_string_lossy().into_owned();
        struct Remove(std::path::PathBuf);
        impl Drop for Remove {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _remove = Remove(dir.clone());
        let content =
            "# comment\n127.0.0.1 localhost\n93.184.216.34 google.com\n93.184.216.34 notgoogle.com\n";
        std::fs::write(&path, content).unwrap();
        let state = hosts_state_in(&path).unwrap();
        println!("state: {state:?}");
        assert_eq!(state.1, 1, "only google.com counts, notgoogle.com must not match");
        assert!(hosts_match("mail.google.com", "google.com"));
        assert!(!hosts_match("notgoogle.com", "google.com"));
        let previous = reset_hosts_in(&path, &backup).unwrap();
        println!("removed: {previous:?}");
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(
            !after.lines().any(|l| l.split_whitespace().any(|h| h == "google.com")),
            "blocking line goes away"
        );
        assert!(after.contains("notgoogle.com"), "lookalike stays");
        assert!(after.contains("localhost"), "safe lines stay");
        restore_hosts_in(&path, &backup).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), content);
        assert!(!std::path::Path::new(&backup).exists(), "backup goes away on undo");
        println!("round trip ok");
    }

    #[test]
    fn diagnose_pure_checks() {
        assert!(check_ip(Some(Ipv4Addr::new(192, 168, 0, 23))).is_ok());
        assert!(check_ip(Some(Ipv4Addr::new(100, 64, 0, 1))).is_ok());
        assert!(check_ip(Some(Ipv4Addr::new(169, 254, 1, 5))).is_err());
        assert!(check_ip(None).is_err());
        assert!(check_ncsi("Microsoft Connect Test").is_ok());
        assert!(check_ncsi("<html>sign in to the hotel wifi</html>").is_err());
        let now = chrono::DateTime::parse_from_rfc2822("Thu, 01 Jan 2026 12:00:00 GMT")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let three_days = "Sun, 04 Jan 2026 12:00:00 GMT";
        let thirty_secs = "Thu, 01 Jan 2026 12:00:30 GMT";
        assert_eq!(sent_time_worse(three_days, now), Some(true));
        assert_eq!(sent_time_worse(thirty_secs, now), Some(false));
        assert_eq!(clock_offset_secs(thirty_secs, now), Some(30));
        assert_eq!(clock_offset_secs("not a date", now), None);
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
    }

    #[test]
    fn repair_mapping_checks() {
        assert_eq!(repair_for_layer(Layer::Link, ""), Some("restart-connection"));
        assert_eq!(repair_for_layer(Layer::Ip, ""), Some("renew-ip"));
        assert_eq!(repair_for_layer(Layer::Gateway, ""), Some("clear-arp"));
        assert_eq!(repair_for_layer(Layer::Dns, ""), Some("flush-dns"));
        assert_eq!(repair_for_layer(Layer::Https, "clock is off"), Some("sync-clock"));
        assert_eq!(repair_for_layer(Layer::Https, "handshake failed"), None);
        assert_eq!(repair_for_layer(Layer::Ncsi, ""), None);
        assert_eq!(repair_for_layer(Layer::Proxy, ""), Some(PROXY_TWEAK));
        assert_eq!(repair_for_layer(Layer::Hosts, ""), Some(HOSTS_TWEAK));
        assert_eq!(repair_for_layer(Layer::Vpn, ""), None);
        assert_eq!(repair_for_layer(Layer::Ipv6, ""), Some(IPV6_TWEAK));
    }
}
