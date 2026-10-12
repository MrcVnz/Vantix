//! Services: everything that runs on this PC without a window, what it costs while it's
//! there, what Vantix knows about it, and the few changes that are safe to make.
//!
//! The inventory opens every service for its configuration, reads the signature of its
//! file and measures the process behind it, so it takes a second or two: run it off the
//! UI thread. Changing a service goes through the same confirmation and journal as the
//! tweaks, so every change has an Undo.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use serde::Deserialize;
use windows::Win32::Foundation::{CloseHandle, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_NOT_ACTIVE};
use windows::Win32::Security::Cryptography::Catalog::{
    CATALOG_INFO, CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext, CryptCATAdminReleaseContext,
    CryptCATCatalogInfoFromContext,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows::Win32::Security::Cryptography::{
    CERT_FIND_SUBJECT_CERT, CERT_INFO, CERT_NAME_SIMPLE_DISPLAY_TYPE,
    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE,
    CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM, CertCloseStore, CertFindCertificateInStore,
    CertFreeCertificateContext, CertGetNameStringW, CryptMsgClose, CryptMsgGetParam, CryptQueryObject,
    HCERTSTORE, X509_ASN_ENCODING,
};
use windows::Win32::System::Services::{
    ChangeServiceConfig2W, ChangeServiceConfigW, CloseServiceHandle, ControlService,
    ENUM_SERVICE_STATUS_PROCESSW, ENUM_SERVICE_STATUSW, ENUM_SERVICE_TYPE, EnumDependentServicesW,
    EnumServicesStatusExW, OpenSCManagerW, OpenServiceW,
    QUERY_SERVICE_CONFIGW, QueryServiceConfig2W, QueryServiceConfigW, QueryServiceStatusEx, SC_ENUM_PROCESS_INFO,
    SC_HANDLE, SC_MANAGER_CONNECT, SC_MANAGER_ENUMERATE_SERVICE, SC_STATUS_PROCESS_INFO, SERVICE_AUTO_START,
    SERVICE_BOOT_START, SERVICE_CHANGE_CONFIG, SERVICE_CONFIG, SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
    SERVICE_CONFIG_DESCRIPTION, SERVICE_CONFIG_FAILURE_ACTIONS, SERVICE_CONFIG_TRIGGER_INFO,
    SERVICE_ACTIVE, SERVICE_CONTROL_STOP, SERVICE_ENUMERATE_DEPENDENTS, SERVICE_FAILURE_ACTIONSW,
    SERVICE_DELAYED_AUTO_START_INFO, SERVICE_DEMAND_START, SERVICE_DESCRIPTIONW, SERVICE_DISABLED,
    SERVICE_DRIVER, SERVICE_ERROR, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_START,
    SERVICE_STATE_ALL, SERVICE_STATUS, SERVICE_STATUS_PROCESS, SERVICE_STOP,
    SERVICE_SYSTEM_START, SERVICE_TRIGGER_INFO, SERVICE_WIN32, StartServiceW,
};
use windows::core::{BOOL, Error, HSTRING, Result};

use crate::{monitor, startup};

/// Windows leaves these empty rather than pointing at an empty string: a service with no
/// description, a driver with no account. Reading one as a string would read from address
/// zero.
fn text(value: windows::core::PWSTR) -> String {
    if value.is_null() {
        return String::new();
    }
    unsafe { value.to_string() }.unwrap_or_default()
}

/// A service is stopped, or on its way there.
const STOPPED: u32 = 1;
/// Leave a field of the configuration as it is.
const NO_CHANGE: u32 = 0xffff_ffff;

/// User services come in a template and one instance per signed-in user, the instance
/// named after the template with a suffix. Only templates are listed.
const SERVICE_USER_SERVICE: ENUM_SERVICE_TYPE = ENUM_SERVICE_TYPE(0x40);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Start {
    /// Drivers only: with the kernel, before Windows itself.
    Boot,
    System,
    Auto,
    /// Automatic, started a couple of minutes after sign-in so the desktop comes first.
    Delayed,
    /// On demand, but with an event that starts it: a device appearing, a port opening.
    Trigger,
    Manual,
    Disabled,
}

impl Start {
    /// What goes in the journal, so Undo puts back exactly what was there.
    pub fn id(self) -> &'static str {
        match self {
            Start::Boot => "boot",
            Start::System => "system",
            Start::Auto => "auto",
            Start::Delayed => "delayed",
            Start::Trigger => "trigger",
            Start::Manual => "manual",
            Start::Disabled => "disabled",
        }
    }

    pub fn from_id(text: &str) -> Option<Self> {
        [Start::Boot, Start::System, Start::Auto, Start::Delayed, Start::Trigger, Start::Manual, Start::Disabled]
            .into_iter()
            .find(|start| start.id() == text)
    }

    /// Runs on its own as soon as Windows starts.
    pub fn with_windows(self) -> bool {
        matches!(self, Start::Boot | Start::System | Start::Auto | Start::Delayed)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Origin {
    /// Signed as part of Windows.
    Windows,
    Microsoft,
    /// Someone else, named by `Service::signer`.
    Third,
    /// No signature at all, or one that doesn't check out.
    Unsigned,
}

/// Why a service can't be changed from here.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Block {
    /// Windows, or Vantix itself, stops working without it.
    Essential,
    AntiCheat,
    /// A kernel driver: turning one off can stop the PC from starting.
    Driver,
}

/// Why Windows starts a service on its own, beyond the start type. The UI puts these
/// into words, so they are kinds and not text.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Trigger {
    Device,
    Network,
    Domain,
    Firewall,
    Policy,
    /// A port or endpoint someone listens on.
    Endpoint,
    /// Another program says the word, which is how most on-demand services start.
    Program,
    Other,
}

#[derive(Clone)]
pub struct Service {
    pub name: String,
    pub display: String,
    /// The service's own description, from Windows.
    pub description: String,
    pub start: Start,
    pub running: bool,
    pub pid: u32,
    pub account: String,
    pub path: String,
    pub origin: Origin,
    /// Who signed the file, or the company in its version resource.
    pub signer: String,
    /// Private memory of its process, 0 when it isn't running.
    pub memory: u64,
    /// Share of the whole CPU over the measured moment.
    pub cpu: f32,
    /// How many services run inside the same process, this one included.
    pub shared: usize,
    pub driver: bool,
    pub block: Option<Block>,
    /// Services this one needs to be running first.
    pub needs: Vec<String>,
    /// Services that need this one, worked out from everyone else's list. Stopping it
    /// stops these as well, which is why the page says so before anything is pressed.
    pub needed_by: Vec<String>,
    /// What makes Windows start it even on Manual.
    pub triggers: Vec<Trigger>,
    /// Windows starts it again by itself when it stops unexpectedly.
    pub restarts: bool,
    /// The svchost group it shares, "netsvcs" and the like. Empty when it has its own
    /// process.
    pub group: String,
    /// One copy per signed-in user, which is why Windows lists it with a suffix.
    pub per_user: bool,
}

impl Service {
    /// What the catalog knows about it, if anything.
    pub fn known(&self) -> Option<&'static Entry> {
        catalog().find(self)
    }

    /// The ways of starting this service Vantix offers, in the order the UI shows them.
    pub fn choices(&self) -> Vec<Start> {
        if self.block.is_some() {
            return Vec::new();
        }
        let allowed = self.known().map(|entry| entry.allow.as_slice());
        [Start::Auto, Start::Manual, Start::Disabled]
            .into_iter()
            .filter(|start| allowed.is_none_or(|allow| allow.iter().any(|a| a == start.id())))
            .collect()
    }
}

// The inventory.

/// Every Win32 service, in display name order. `drivers` asks for kernel and file system
/// drivers instead, which are listed but never changed.
pub fn list(drivers: bool) -> Vec<Service> {
    let kind = if drivers { SERVICE_DRIVER } else { SERVICE_WIN32 | SERVICE_USER_SERVICE };
    let Some(manager) = open_manager() else { return Vec::new() };
    let mut services = Vec::new();
    let mut by_pid: HashMap<u32, usize> = HashMap::new();
    for (name, display, pid, running) in enumerate(manager, kind) {
        let mut service = Service {
            name,
            display,
            description: String::new(),
            start: Start::Manual,
            running,
            pid,
            account: String::new(),
            path: String::new(),
            origin: Origin::Unsigned,
            signer: String::new(),
            memory: 0,
            cpu: 0.0,
            shared: 1,
            driver: drivers,
            block: None,
            needs: Vec::new(),
            needed_by: Vec::new(),
            triggers: Vec::new(),
            restarts: false,
            group: String::new(),
            per_user: false,
        };
        read_config(manager, &mut service);
        service.block = block_for(&service);
        if pid != 0 {
            *by_pid.entry(pid).or_default() += 1;
        }
        services.push(service);
    }
    unsafe { CloseServiceHandle(manager) }.ok();

    // Who needs whom: every service already said what it needs, so the other direction
    // costs nothing more than a pass over the list.
    let mut needed_by: HashMap<String, Vec<String>> = HashMap::new();
    for service in &services {
        for needed in &service.needs {
            needed_by.entry(needed.to_lowercase()).or_default().push(service.display.clone());
        }
    }
    for service in &mut services {
        if let Some(mut names) = needed_by.remove(&service.name.to_lowercase()) {
            names.sort();
            names.dedup();
            service.needed_by = names;
        }
    }

    // What each process costs right now, measured over a moment.
    let load = process_load();
    for service in &mut services {
        if let Some((memory, cpu)) = load.get(&service.pid) {
            service.memory = *memory;
            service.cpu = *cpu;
        }
        service.shared = by_pid.get(&service.pid).copied().unwrap_or(1);
    }

    // Signatures are the slow part: a catalog lookup per file. The answer can't change
    // while Vantix runs, so it's kept for the next visit to the page.
    static SIGNATURES: Mutex<Option<HashMap<String, (Origin, String)>>> = Mutex::new(None);
    let mut guard = SIGNATURES.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let cache = guard.get_or_insert_with(HashMap::new);
    for service in &mut services {
        let file = binary(service).to_lowercase();
        if file.is_empty() {
            continue;
        }
        let (origin, signer) = cache.entry(file.clone()).or_insert_with(|| origin_of(&file)).clone();
        service.origin = origin;
        service.signer = signer;
    }
    drop(guard);

    services.sort_by_key(|service| service.display.to_lowercase());
    services
}

fn open_manager() -> Option<SC_HANDLE> {
    unsafe { OpenSCManagerW(None, None, SC_MANAGER_ENUMERATE_SERVICE) }.ok()
}

/// Name, display name, process id and whether it's running.
fn enumerate(manager: SC_HANDLE, kind: ENUM_SERVICE_TYPE) -> Vec<(String, String, u32, bool)> {
    let mut list = Vec::new();
    unsafe {
        let (mut needed, mut count, mut resume) = (0u32, 0u32, 0u32);
        let _ = EnumServicesStatusExW(
            manager,
            SC_ENUM_PROCESS_INFO,
            kind,
            SERVICE_STATE_ALL,
            None,
            &mut needed,
            &mut count,
            Some(&mut resume),
            None,
        );
        if needed == 0 {
            return list;
        }
        // Aligned for the struct, which a Vec<u8> wouldn't be.
        let mut buffer: Vec<u64> = vec![0; needed as usize / 8 + 2];
        let bytes = std::slice::from_raw_parts_mut(buffer.as_mut_ptr().cast::<u8>(), buffer.len() * 8);
        if EnumServicesStatusExW(
            manager,
            SC_ENUM_PROCESS_INFO,
            kind,
            SERVICE_STATE_ALL,
            Some(bytes),
            &mut needed,
            &mut count,
            Some(&mut resume),
            None,
        )
        .is_err()
        {
            return list;
        }
        let items = bytes.as_ptr().cast::<ENUM_SERVICE_STATUS_PROCESSW>();
        for i in 0..count as usize {
            let item = &*items.add(i);
            let name = text(item.lpServiceName);
            if name.is_empty() {
                continue;
            }
            let display = text(item.lpDisplayName);
            let display = if display.is_empty() { name.clone() } else { display };
            let status = &item.ServiceStatusProcess;
            list.push((name, display, status.dwProcessId, status.dwCurrentState.0 != STOPPED));
        }
    }
    // A user service is listed once as a template and once per signed-in user, the copy
    // named after the template with a suffix. The template is the one that can be changed.
    let templates: std::collections::HashSet<String> = list.iter().map(|(name, ..)| name.to_lowercase()).collect();
    list.retain(|(name, ..)| match name.rsplit_once('_') {
        Some((template, suffix)) => {
            !suffix.chars().all(|c| c.is_ascii_hexdigit()) || !templates.contains(&template.to_lowercase())
        }
        None => true,
    });
    list
}

// Changing a service. Every call here blocks on the service manager, which can take
// seconds when a service is slow to stop, so none of them belong on the UI thread.

/// Sets how a service starts and gives back what it was, for the journal. Automatic,
/// Manual and Disabled are the only ones offered: boot and system start belong to
/// drivers, and a service that starts on a trigger keeps its triggers when it goes to
/// Manual, so Windows can still start it when something needs it.
pub fn set_start(name: &str, start: Start) -> Result<Start> {
    if blocked(name).is_some() {
        return Err(Error::from(windows::Win32::Foundation::E_ACCESSDENIED));
    }
    let code = match start {
        Start::Auto | Start::Delayed => SERVICE_AUTO_START,
        Start::Manual | Start::Trigger => SERVICE_DEMAND_START,
        Start::Disabled => SERVICE_DISABLED,
        Start::Boot | Start::System => return Err(Error::from(windows::Win32::Foundation::E_INVALIDARG)),
    };
    with_service(name, SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG, |handle| unsafe {
        let before = start_of(handle);
        ChangeServiceConfigW(
            handle,
            ENUM_SERVICE_TYPE(NO_CHANGE),
            code,
            SERVICE_ERROR(NO_CHANGE),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )?;
        if matches!(start, Start::Auto | Start::Delayed) {
            let mut delay = SERVICE_DELAYED_AUTO_START_INFO { fDelayedAutostart: BOOL::from(start == Start::Delayed) };
            ChangeServiceConfig2W(
                handle,
                SERVICE_CONFIG_DELAYED_AUTO_START_INFO,
                Some((&raw mut delay).cast()),
            )?;
        }
        Ok(before)
    })
}

/// Starts or stops a service now and waits for it to get there. Gives back the state it
/// really ended in, which isn't always the one asked for: plenty of services are set to
/// start themselves again, and come back within the second. Stopping one stops the
/// services that need it first, since Windows refuses to stop it while they run.
pub fn run(name: &str, on: bool) -> Result<bool> {
    // Starting one again is harmless; stopping the ones Windows needs is not.
    if !on && blocked(name).is_some() {
        return Err(Error::from(windows::Win32::Foundation::E_ACCESSDENIED));
    }
    if !on {
        let needing = dependents(name)?;
        if needing.iter().any(|other| blocked(other).is_some()) {
            return Err(Error::from(windows::Win32::Foundation::E_ACCESSDENIED));
        }
        for other in &needing {
            with_service(other, SERVICE_STOP | SERVICE_QUERY_STATUS, |handle| unsafe {
                let mut status = SERVICE_STATUS::default();
                // One that stopped on its own meanwhile is fine.
                let _ = ControlService(handle, SERVICE_CONTROL_STOP, &mut status);
                settle(handle, false);
                Ok(())
            })?;
        }
    }
    let access = if on { SERVICE_START | SERVICE_QUERY_STATUS } else { SERVICE_STOP | SERVICE_QUERY_STATUS };
    with_service(name, access, |handle| unsafe {
        if on {
            match StartServiceW(handle, None) {
                Err(error) if error.code() == ERROR_SERVICE_ALREADY_RUNNING.to_hresult() => return Ok(true),
                result => result?,
            }
        } else {
            let mut status = SERVICE_STATUS::default();
            match ControlService(handle, SERVICE_CONTROL_STOP, &mut status) {
                // Already stopped, by the services that needed it or on its own.
                Err(error) if error.code() == ERROR_SERVICE_NOT_ACTIVE.to_hresult() => return Ok(false),
                result => result?,
            }
        }
        let mut state = settle(handle, on);
        // It got where it was asked to go; a service that starts itself again may have
        // come back already, and the row has to say so.
        if state == on {
            std::thread::sleep(Duration::from_millis(600));
            state = running(handle).unwrap_or(state);
        }
        Ok(state)
    })
}

/// Waits up to ten seconds for a service to be running or stopped: one that stops slowly
/// is still doing it. Gives back where it is.
fn settle(handle: SC_HANDLE, on: bool) -> bool {
    let mut state = !on;
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(200));
        state = running(handle).unwrap_or(!on);
        if state == on {
            break;
        }
    }
    state
}

/// The running services that need this one, in the order they can be stopped: Windows
/// lists the ones furthest down the chain first.
fn dependents(name: &str) -> Result<Vec<String>> {
    with_service(name, SERVICE_ENUMERATE_DEPENDENTS, |handle| unsafe {
        let (mut needed, mut count) = (0u32, 0u32);
        if EnumDependentServicesW(handle, SERVICE_ACTIVE, None, 0, &mut needed, &mut count).is_ok() {
            return Ok(Vec::new());
        }
        // Aligned for the struct, which a Vec<u8> wouldn't be.
        let mut buffer: Vec<u64> = vec![0; needed as usize / 8 + 1];
        EnumDependentServicesW(
            handle,
            SERVICE_ACTIVE,
            Some(buffer.as_mut_ptr().cast()),
            (buffer.len() * 8) as u32,
            &mut needed,
            &mut count,
        )?;
        let items = buffer.as_ptr().cast::<ENUM_SERVICE_STATUSW>();
        let items = std::slice::from_raw_parts(items, count as usize);
        Ok(items.iter().map(|item| text(item.lpServiceName)).filter(|n| !n.is_empty()).collect())
    })
}

fn with_service<T>(
    name: &str,
    access: u32,
    work: impl FnOnce(SC_HANDLE) -> Result<T>,
) -> Result<T> {
    unsafe {
        let manager = OpenSCManagerW(None, None, SC_MANAGER_CONNECT)?;
        let service = OpenServiceW(manager, &HSTRING::from(name), access);
        let result = match service {
            Ok(handle) => {
                let result = work(handle);
                let _ = CloseServiceHandle(handle);
                result
            }
            Err(error) => Err(error),
        };
        let _ = CloseServiceHandle(manager);
        result
    }
}

fn running(handle: SC_HANDLE) -> Option<bool> {
    let mut needed = 0u32;
    let mut status = SERVICE_STATUS_PROCESS::default();
    let bytes = unsafe {
        std::slice::from_raw_parts_mut((&raw mut status).cast::<u8>(), size_of::<SERVICE_STATUS_PROCESS>())
    };
    unsafe { QueryServiceStatusEx(handle, SC_STATUS_PROCESS_INFO, Some(bytes), &mut needed) }.ok()?;
    Some(status.dwCurrentState.0 != STOPPED)
}

/// How the service starts right now.
fn start_of(handle: SC_HANDLE) -> Start {
    let Some(buffer) = query_config(handle) else { return Start::Manual };
    let config = unsafe { &*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
    match config.dwStartType {
        SERVICE_BOOT_START => Start::Boot,
        SERVICE_SYSTEM_START => Start::System,
        SERVICE_AUTO_START if delayed(handle) => Start::Delayed,
        SERVICE_AUTO_START => Start::Auto,
        SERVICE_DISABLED => Start::Disabled,
        _ if triggered(handle) => Start::Trigger,
        _ => Start::Manual,
    }
}

/// Start type, account, file and description, which the enumeration doesn't carry.
fn read_config(manager: SC_HANDLE, service: &mut Service) {
    let Ok(handle) = (unsafe { OpenServiceW(manager, &HSTRING::from(service.name.as_str()), SERVICE_QUERY_CONFIG) })
    else {
        return;
    };
    unsafe {
        if let Some(buffer) = query_config(handle) {
            let config = &*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>();
            service.start = start_of(handle);
            service.path = text(config.lpBinaryPathName);
            service.account = text(config.lpServiceStartName);
            service.needs = multi_text(config.lpDependencies);
            // The host's group, from "svchost.exe -k netsvcs -p".
            service.group = service
                .path
                .split_once("-k ")
                .map(|(_, rest)| rest.split_whitespace().next().unwrap_or_default().to_string())
                .unwrap_or_default();
            service.per_user = config.dwServiceType.0 & SERVICE_USER_SERVICE.0 != 0;
        }
        if let Some(buffer) = query_config2(handle, SERVICE_CONFIG_DESCRIPTION) {
            let description = &*buffer.as_ptr().cast::<SERVICE_DESCRIPTIONW>();
            service.description = text(description.lpDescription);
        }
        service.triggers = triggers(handle);
        service.restarts = restarts(handle);
        let _ = CloseServiceHandle(handle);
    }
}

/// Automatic, but held back until the desktop is up.
fn delayed(handle: SC_HANDLE) -> bool {
    let Some(buffer) = query_config2(handle, SERVICE_CONFIG_DELAYED_AUTO_START_INFO) else { return false };
    let info = unsafe { &*buffer.as_ptr().cast::<SERVICE_DELAYED_AUTO_START_INFO>() };
    info.fDelayedAutostart.as_bool()
}

/// On demand, with an event registered to start it.
fn triggered(handle: SC_HANDLE) -> bool {
    let Some(buffer) = query_config2(handle, SERVICE_CONFIG_TRIGGER_INFO) else { return false };
    let info = unsafe { &*buffer.as_ptr().cast::<SERVICE_TRIGGER_INFO>() };
    info.cTriggers > 0
}

/// What Windows watches for to start this service by itself.
fn triggers(handle: SC_HANDLE) -> Vec<Trigger> {
    let Some(buffer) = query_config2(handle, SERVICE_CONFIG_TRIGGER_INFO) else { return Vec::new() };
    let info = unsafe { &*buffer.as_ptr().cast::<SERVICE_TRIGGER_INFO>() };
    if info.pTriggers.is_null() {
        return Vec::new();
    }
    let list = unsafe { std::slice::from_raw_parts(info.pTriggers, info.cTriggers as usize) };
    let mut kinds: Vec<Trigger> = list
        .iter()
        .map(|trigger| match trigger.dwTriggerType.0 {
            1 => Trigger::Device,
            2 => Trigger::Network,
            3 => Trigger::Domain,
            4 => Trigger::Firewall,
            5 => Trigger::Policy,
            6 => Trigger::Endpoint,
            20 => Trigger::Program,
            _ => Trigger::Other,
        })
        .collect();
    kinds.sort_by_key(|kind| *kind as u8);
    kinds.dedup();
    kinds
}

/// Whether Windows starts it again by itself after a crash, which is also why stopping
/// some services never sticks.
fn restarts(handle: SC_HANDLE) -> bool {
    const SC_ACTION_RESTART: i32 = 1;
    let Some(buffer) = query_config2(handle, SERVICE_CONFIG_FAILURE_ACTIONS) else { return false };
    let actions = unsafe { &*buffer.as_ptr().cast::<SERVICE_FAILURE_ACTIONSW>() };
    if actions.lpsaActions.is_null() {
        return false;
    }
    let list = unsafe { std::slice::from_raw_parts(actions.lpsaActions, actions.cActions as usize) };
    list.iter().any(|action| action.Type.0 == SC_ACTION_RESTART)
}

/// A double null terminated list, which is how Windows hands over a service's
/// dependencies. A name starting with "+" is a load order group, not a service.
fn multi_text(value: windows::core::PWSTR) -> Vec<String> {
    if value.is_null() {
        return Vec::new();
    }
    let mut names = Vec::new();
    let mut at = value.0;
    unsafe {
        while *at != 0 {
            let mut end = at;
            while *end != 0 {
                end = end.add(1);
            }
            let len = end.offset_from(at) as usize;
            let name = String::from_utf16_lossy(std::slice::from_raw_parts(at, len));
            if !name.starts_with('+') {
                names.push(name);
            }
            at = end.add(1);
        }
    }
    names
}

fn query_config(handle: SC_HANDLE) -> Option<Vec<u64>> {
    let mut needed = 0u32;
    unsafe {
        let result = QueryServiceConfigW(handle, None, 0, &mut needed);
        if result.is_ok() || needed == 0 {
            return None;
        }
        let mut buffer: Vec<u64> = vec![0; needed as usize / 8 + 2];
        let config = buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
        QueryServiceConfigW(handle, Some(config), (buffer.len() * 8) as u32, &mut needed).ok()?;
        Some(buffer)
    }
}

fn query_config2(handle: SC_HANDLE, level: SERVICE_CONFIG) -> Option<Vec<u64>> {
    let mut needed = 0u32;
    unsafe {
        let _ = QueryServiceConfig2W(handle, level, None, &mut needed);
        if needed == 0 {
            return None;
        }
        let mut buffer: Vec<u64> = vec![0; needed as usize / 8 + 2];
        let bytes = std::slice::from_raw_parts_mut(buffer.as_mut_ptr().cast::<u8>(), buffer.len() * 8);
        QueryServiceConfig2W(handle, level, Some(bytes), &mut needed).ok()?;
        Some(buffer)
    }
}

/// Memory and CPU of every process that holds a service, measured over half a second.
fn process_load() -> HashMap<u32, (u64, f32)> {
    let before: HashMap<u32, u64> = monitor::process_list().into_iter().map(|p| (p.pid, p.cpu_time)).collect();
    std::thread::sleep(Duration::from_millis(500));
    let threads = f64::from(monitor::cpu_info().threads.max(1));
    let budget = 0.5 * 10_000_000.0 * threads;
    monitor::process_list()
        .into_iter()
        .map(|process| {
            let used = before.get(&process.pid).map_or(0, |then| process.cpu_time.saturating_sub(*then));
            (process.pid, (process.memory, (used as f64 / budget * 100.0) as f32))
        })
        .collect()
}

/// The file whose signature says where the service comes from. A service sharing an
/// svchost is its own DLL, not the host Windows lends it.
fn binary(service: &Service) -> String {
    if let Some(dll) = service_dll(&service.name) {
        return dll;
    }
    let path = service.path.trim();
    // "C:\path\thing.exe -k netsvcs", quoted when the path has spaces.
    let path = if let Some(rest) = path.strip_prefix('"') {
        rest.split('"').next().unwrap_or(rest).to_string()
    } else {
        match path.to_lowercase().find(".exe") {
            Some(end) => path[..end + 4].to_string(),
            None => path.to_string(),
        }
    };
    expand(&path)
}

fn service_dll(name: &str) -> Option<String> {
    let path = format!(r"SYSTEM\CurrentControlSet\Services\{name}\Parameters");
    let dll = crate::reg::get_string(crate::reg::HKEY_LOCAL_MACHINE, &path, "ServiceDll").ok()??;
    Some(expand(&dll))
}

fn expand(path: &str) -> String {
    let mut text = path.to_string();
    if let Some(rest) = text.strip_prefix(r"\??\") {
        text = rest.to_string();
    }
    for (name, value) in [("%SystemRoot%", system_root()), ("\\SystemRoot", system_root())] {
        if text.to_lowercase().starts_with(&name.to_lowercase()) {
            text = format!("{value}{}", &text[name.len()..]);
        }
    }
    text
}

fn system_root() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())
}

// Where a file comes from: its Authenticode signer when it has one, and the company in
// its version resource when it doesn't.

fn origin_of(file: &str) -> (Origin, String) {
    let signer = signer(file);
    let company = startup::version_info(std::path::Path::new(file)).1;
    let name = if signer.is_empty() { company } else { signer.clone() };
    let in_windows = file.to_lowercase().starts_with(&system_root().to_lowercase());
    let origin = if name.is_empty() {
        Origin::Unsigned
    } else if name.contains("Microsoft Windows") || (in_windows && name.contains("Microsoft")) {
        Origin::Windows
    } else if name.contains("Microsoft") {
        Origin::Microsoft
    } else {
        Origin::Third
    };
    (origin, name)
}

/// The name on the certificate a file is signed with. Empty when the file carries no
/// signature of its own, which is the case for most of Windows: those are signed in a
/// catalog instead, and the catalog's own signature is read in its place.
fn signer(file: &str) -> String {
    let embedded = embedded_signer(file);
    if !embedded.is_empty() {
        return embedded;
    }
    catalog_signer(file)
}

fn embedded_signer(file: &str) -> String {
    unsafe {
        let mut message = std::ptr::null_mut();
        let mut store = HCERTSTORE::default();
        let path = HSTRING::from(file);
        if CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            path.as_ptr().cast(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            None,
            None,
            Some(&mut store),
            Some(&mut message),
            None,
        )
        .is_err()
        {
            return String::new();
        }
        let name = signer_name(message, store);
        let _ = CryptMsgClose(Some(message));
        let _ = CertCloseStore(Some(store), 0);
        name
    }
}

/// The signer of the first certificate the message points at.
unsafe fn signer_name(message: *mut std::ffi::c_void, store: HCERTSTORE) -> String {
    unsafe {
        let mut size = 0u32;
        if CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, None, &mut size).is_err() || size == 0 {
            return String::new();
        }
        let mut buffer: Vec<u64> = vec![0; size as usize / 8 + 2];
        if CryptMsgGetParam(message, CMSG_SIGNER_INFO_PARAM, 0, Some(buffer.as_mut_ptr().cast()), &mut size)
            .is_err()
        {
            return String::new();
        }
        let info = &*buffer.as_ptr().cast::<CMSG_SIGNER_INFO>();
        // The signer is the certificate with that issuer and serial number.
        let mut find = CERT_INFO { Issuer: info.Issuer, SerialNumber: info.SerialNumber, ..Default::default() };
        let certificate = CertFindCertificateInStore(
            store,
            X509_ASN_ENCODING,
            0,
            CERT_FIND_SUBJECT_CERT,
            Some((&raw mut find).cast()),
            None,
        );
        if certificate.is_null() {
            return String::new();
        }
        let mut name = [0u16; 256];
        let len = CertGetNameStringW(certificate, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, Some(&mut name));
        let _ = CertFreeCertificateContext(Some(certificate));
        String::from_utf16_lossy(&name[..(len as usize).saturating_sub(1)])
    }
}

/// Windows' own files are signed in catalogs under CatRoot, not in the file itself. The
/// catalog holding this file's hash carries the signature that counts.
fn catalog_signer(file: &str) -> String {
    let Some(catalog) = catalog_of(file) else { return String::new() };
    embedded_signer(&catalog)
}

/// The catalog a file's hash appears in, if any.
fn catalog_of(file: &str) -> Option<String> {
    unsafe {
        let handle = CreateFileW(
            &HSTRING::from(file),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        .ok()?;
        let found = (|| {
            let mut admin = 0isize;
            // SHA-256, the only algorithm catalogs are built with since Windows 8.
            CryptCATAdminAcquireContext2(&mut admin, None, windows::core::w!("SHA256"), None, None).ok()?;
            let mut size = 0u32;
            let mut name = None;
            if CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut size, None, None).is_ok() && size > 0 {
                let mut hash = vec![0u8; size as usize];
                if CryptCATAdminCalcHashFromFileHandle2(admin, handle, &mut size, Some(hash.as_mut_ptr()), None)
                    .is_ok()
                {
                    let context = CryptCATAdminEnumCatalogFromHash(admin, &hash, None, None);
                    if context != 0 {
                        let mut info = CATALOG_INFO { cbStruct: size_of::<CATALOG_INFO>() as u32, ..Default::default() };
                        if CryptCATCatalogInfoFromContext(context, &mut info, 0).is_ok() {
                            let path = String::from_utf16_lossy(&info.wszCatalogFile);
                            let path = path.trim_end_matches('\0').to_string();
                            name = Some(path.strip_prefix(r"\\?\").unwrap_or(&path).to_string());
                        }
                        let _ = CryptCATAdminReleaseCatalogContext(admin, context, 0);
                    }
                }
            }
            let _ = CryptCATAdminReleaseContext(admin, 0);
            name
        })();
        let _ = CloseHandle(handle);
        found
    }
}

// What Vantix knows about a service: res/services.json, written for people rather than
// for administrators, in both languages the app speaks.

#[derive(Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    #[default]
    None,
    Low,
    Medium,
    High,
}

#[derive(Deserialize)]
pub struct Text {
    en: String,
    pt: String,
}

impl Text {
    pub fn get(&self, portuguese: bool) -> &str {
        if portuguese { &self.pt } else { &self.en }
    }
}

#[derive(Deserialize)]
pub struct Entry {
    /// The service's own name, when the entry is about one service.
    #[serde(default)]
    name: String,
    /// A family instead: services whose name starts with this, whose file holds this, or
    /// whose signature carries this name.
    #[serde(default)]
    starts_with: String,
    #[serde(default)]
    file: String,
    #[serde(default)]
    signer: String,
    /// Part of the name Windows shows, for the files that carry no signature at all.
    #[serde(default)]
    display: String,
    /// What it does, in plain words.
    pub does: Text,
    /// What stops working without it.
    pub cost: Text,
    #[serde(default)]
    pub gain: Level,
    #[serde(default)]
    pub risk: Level,
    /// Which start types Vantix offers for it. Missing means all of them, an empty list
    /// means this one is never changed from here.
    #[serde(default = "all_starts")]
    pub allow: Vec<String>,
}

fn all_starts() -> Vec<String> {
    vec!["auto".into(), "manual".into(), "disabled".into()]
}

#[derive(Deserialize)]
pub struct Catalog {
    entries: Vec<Entry>,
}

impl Catalog {
    fn find(&'static self, service: &Service) -> Option<&'static Entry> {
        let name = service.name.to_lowercase();
        let file = service.path.to_lowercase();
        let signer = service.signer.to_lowercase();
        self.entries
            .iter()
            .find(|entry| !entry.name.is_empty() && entry.name.to_lowercase() == name)
            .or_else(|| {
                // The families are about other people's software. Windows has services
                // whose names start the same way, MSiSCSI and EapHost among them, and a
                // family entry has nothing to say about those.
                if service.origin == Origin::Windows {
                    return None;
                }
                let display = service.display.to_lowercase();
                self.entries.iter().find(|entry| {
                    let by_name = !entry.starts_with.is_empty() && name.starts_with(&entry.starts_with.to_lowercase());
                    let by_file = !entry.file.is_empty() && file.contains(&entry.file.to_lowercase());
                    let by_signer = !entry.signer.is_empty() && signer.contains(&entry.signer.to_lowercase());
                    let by_display = !entry.display.is_empty() && display.contains(&entry.display.to_lowercase());
                    by_name || by_file || by_signer || by_display
                })
            })
    }
}

pub fn catalog() -> &'static Catalog {
    static CATALOG: OnceLock<Catalog> = OnceLock::new();
    CATALOG.get_or_init(|| {
        serde_json::from_str(include_str!("../res/services.json")).expect("res/services.json is not valid")
    })
}

/// Services Windows or Vantix itself can't work without: the PC stops starting, signing
/// in stops working, or Vantix loses the restore points and its own scheduled start.
const ESSENTIAL: [&str; 22] = [
    "rpcss",
    "dcomlaunch",
    "rpceptmapper",
    "eventlog",
    "schedule",
    "plugplay",
    "power",
    "bfe",
    "mpssvc",
    "lsm",
    "winmgmt",
    "profsvc",
    "gpsvc",
    "samss",
    "cryptsvc",
    "dhcp",
    "dnscache",
    "nsi",
    "systemeventsbroker",
    "coremessagingregistrar",
    "usermanager",
    "staterepository",
];

/// Anti-cheat, which is never touched: a game can refuse to start, or ban the account,
/// when its guard isn't the way it left it.
const ANTI_CHEAT: [&str; 9] = [
    "vgc",
    "vgk",
    "easyanticheat",
    "easyanticheat_eos",
    "beservice",
    "bedaisy",
    "faceit",
    "faceitservice",
    "zksvc",
];

/// Whether a service is off limits, from its name alone. The page already hides the
/// buttons; this is the floor under that, so no path through Vantix can change one.
pub fn blocked(name: &str) -> Option<Block> {
    let name = name.to_lowercase();
    if ANTI_CHEAT.contains(&name.as_str()) {
        return Some(Block::AntiCheat);
    }
    if ESSENTIAL.contains(&name.as_str()) {
        return Some(Block::Essential);
    }
    None
}

fn block_for(service: &Service) -> Option<Block> {
    if service.driver {
        return Some(Block::Driver);
    }
    let file = service.path.to_lowercase();
    if ANTI_CHEAT.iter().any(|guard| file.contains(guard)) {
        return Some(Block::AntiCheat);
    }
    blocked(&service.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Which step of the inventory is at fault, when one is.
    /// `cargo test services_parts -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn services_parts() {
        let manager = open_manager().expect("no service manager");
        let found = enumerate(manager, SERVICE_WIN32 | SERVICE_USER_SERVICE);
        println!("enumerate: {} services", found.len());
        let mut sample = Service {
            name: found[0].0.clone(),
            display: found[0].1.clone(),
            description: String::new(),
            start: Start::Manual,
            running: false,
            pid: 0,
            account: String::new(),
            path: String::new(),
            origin: Origin::Unsigned,
            signer: String::new(),
            memory: 0,
            cpu: 0.0,
            shared: 1,
            driver: false,
            block: None,
            needs: Vec::new(),
            needed_by: Vec::new(),
            triggers: Vec::new(),
            restarts: false,
            group: String::new(),
            per_user: false,
        };
        read_config(manager, &mut sample);
        println!("config: {} {:?} {}", sample.name, sample.start, sample.path);
        let mut count = 0;
        for (name, display, _, _) in &found {
            let mut service = Service { name: name.clone(), display: display.clone(), ..sample.clone() };
            read_config(manager, &mut service);
            count += usize::from(!service.path.is_empty());
        }
        println!("config of all: {count} with a file");
        let file = binary(&sample);
        println!(
            "binary: [{file}] len {} raw [{:?}]",
            file.len(),
            crate::reg::get_string(
                crate::reg::HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Services\AarSvc\Parameters",
                "ServiceDll"
            )
        );
        println!("version info: {:?}", startup::version_info(std::path::Path::new(&file)));
        println!("embedded signer: {:?}", embedded_signer(&file));
        println!("catalog: {:?}", catalog_of(&file));
        println!("origin: {:?}", origin_of(&file));
        println!("load: {} processes", process_load().len());
    }

    /// A service of Vantix's own making, so the round trip touches nothing on the PC.
    /// `cargo test service_round_trip -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn service_round_trip() {
        use std::process::Command;
        const NAME: &str = "VantixTestService";
        let sc = |args: &[&str]| Command::new("sc").args(args).output().expect("sc didn't run");
        let created = sc(&[
            "create",
            NAME,
            "binPath=",
            r"C:\Windows\System32\cmd.exe /c exit",
            "start=",
            "demand",
            "DisplayName=",
            "Vantix test service",
        ]);
        if !created.status.success() {
            panic!("sc create failed, run the tests as administrator: {}", String::from_utf8_lossy(&created.stdout));
        }

        let found = || list(false).into_iter().find(|service| service.name.eq_ignore_ascii_case(NAME));
        let before = found().expect("the new service isn't listed");
        assert_eq!(before.start, Start::Manual);
        assert_eq!(before.block, None, "a service of our own shouldn't be blocked");

        let was = set_start(NAME, Start::Auto).expect("setting Automatic failed");
        assert_eq!(was, Start::Manual, "the journal would put back the wrong state");
        assert_eq!(found().unwrap().start, Start::Auto);

        let was = set_start(NAME, Start::Disabled).expect("setting Disabled failed");
        assert_eq!(was, Start::Auto);
        assert_eq!(found().unwrap().start, Start::Disabled);

        // What Undo does: back to exactly what the journal kept.
        set_start(NAME, Start::Manual).expect("putting it back failed");
        let after = found().unwrap();
        assert_eq!(after.start, before.start);
        println!("round trip ok: {} ({})", after.display, after.name);

        // Nothing is started or stopped here: a test service has no real process to run,
        // and stopping a real one would be a change to this PC. What is checked is that
        // the call refuses what it should.
        assert!(run("VantixServiceThatIsntThere", true).is_err());
        assert!(sc(&["delete", NAME]).status.success(), "the test service is still there");
    }

    /// Stops a real pair for a few seconds and starts both again: the Network Connection
    /// Broker, which the Connected Devices Platform needs. Windows refuses the stop while
    /// the dependent runs, so this is what checks that run() stops it first.
    /// `cargo test stop_with_dependents -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn stop_with_dependents() {
        let needing = dependents("NcbService").expect("can't read the dependents");
        if !needing.iter().any(|name| name.eq_ignore_ascii_case("CDPSvc")) {
            println!("CDPSvc isn't running here, nothing to check: {needing:?}");
            return;
        }
        // Windows refuses with "dependent services running" unless run() stops CDPSvc first.
        // Something may start NcbService again within the second; that's the Ok(true)
        // the Monitor row reports as "Windows started it again", not a failure.
        let stopped = run("NcbService", false).expect("stopping failed");
        println!("NcbService {}", if stopped { "came back by itself" } else { "stopped" });
        assert!(run("NcbService", true).expect("starting NcbService again failed"));
        assert!(run("CDPSvc", true).expect("starting CDPSvc again failed"));
        // Already stopped counts as stopped, not as an error.
        assert_eq!(run("PrintNotify", false).ok(), Some(false));
    }

    /// `cargo test services_list -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn services_list() {
        let services = list(false);
        println!("{} services", services.len());
        for service in services.iter().take(14) {
            println!(
                "{:<26} {:<9?} {:<8} {:>6} MB x{} {:?} needs {:?} needed by {} triggers {:?} restarts {} group {}",
                service.name,
                service.start,
                if service.running { "running" } else { "stopped" },
                service.memory >> 20,
                service.shared,
                service.origin,
                service.needs,
                service.needed_by.len(),
                service.triggers,
                service.restarts,
                service.group
            );
        }
        // What this PC runs that the catalog says nothing about, which is the list worth
        // shortening whenever it has anything in it.
        for service in services.iter().filter(|service| service.known().is_none()) {
            println!("no entry: {:<32} {:<36} {}", service.name, service.display, service.signer);
        }
        let known = services.iter().filter(|service| service.known().is_some()).count();
        let running = services.iter().filter(|service| service.running).count();
        println!(
            "{known} of {} have a catalog entry, {running} running, {} blocked",
            services.len(),
            services.iter().filter(|service| service.block.is_some()).count()
        );
        for service in services.iter().filter(|s| s.origin != Origin::Windows) {
            println!(
                "third party: {:<30} {:<28} known {}",
                service.name,
                service.signer,
                service.known().is_some()
            );
        }
        assert!(services.len() > 50, "only {} services", services.len());
        assert!(services.iter().any(|s| s.origin == Origin::Windows), "nothing came out as Windows");
        assert!(services.iter().all(|s| !s.name.is_empty() && !s.display.is_empty()));
        // A user service is listed once, as its template.
        assert!(!services.iter().any(|s| s.name.contains("AarSvc_")), "a user service instance slipped in");

        // The drivers tab reads and nothing more.
        let drivers = list(true);
        println!("{} drivers", drivers.len());
        assert!(drivers.len() > 50, "only {} drivers", drivers.len());
        assert!(drivers.iter().all(|driver| driver.block == Some(Block::Driver)));
        assert!(drivers.iter().all(|driver| driver.choices().is_empty()));

        // The floor under the UI: no path through Vantix changes these.
        assert!(set_start("RpcSs", Start::Manual).is_err(), "an essential service was changed");
        assert!(run("DcomLaunch", false).is_err(), "an essential service was stopped");
        assert_eq!(blocked("vgc"), Some(Block::AntiCheat));
        assert_eq!(blocked("Spooler"), None);
    }
}
