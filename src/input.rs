//! Input: what sits between the mouse or keyboard and the game on the PC's side.
//!
//! Polling rate, debounce and rapid trigger live in the device's firmware and its maker's
//! app; Windows can't change them. What it can show is how the device is plugged in, what
//! the port lets it do, whether Windows may put it to sleep, and what actually arrives:
//! the meter reads every report through Raw Input and times it on arrival.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{LazyLock, Mutex};

use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_GET_DEVICE_INTERFACE_LIST_PRESENT, CM_GETIDLIST_FILTER_CLASS, CM_GETIDLIST_FILTER_PRESENT,
    CM_Get_DevNode_PropertyW, CM_Get_Device_ID_List_SizeW, CM_Get_Device_ID_ListW, CM_Get_Device_IDW,
    CM_Get_Device_Interface_List_SizeW, CM_Get_Device_Interface_ListW, CM_Get_Parent, CM_LOCATE_DEVNODE_NORMAL,
    CM_Locate_DevNodeW, CR_SUCCESS,
};
use windows::Win32::Devices::Properties::{
    DEVPKEY_Device_Address, DEVPKEY_Device_BusReportedDeviceDesc, DEVPKEY_Device_DeviceDesc,
    DEVPKEY_Device_FriendlyName, DEVPROPTYPE,
};
use windows::Win32::Devices::Usb::{
    GUID_DEVINTERFACE_USB_HUB, IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX, USB_NODE_CONNECTION_INFORMATION_EX,
    USB_PIPE_INFO,
};
use windows::Win32::Foundation::{CloseHandle, DEVPROPKEY, GENERIC_WRITE, HANDLE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Storage::FileSystem::{CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_WRITE, OPEN_EXISTING};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Performance::{QueryPerformanceCounter, QueryPerformanceFrequency};
use windows::Win32::System::Threading::{GetCurrentThread, SetThreadPriority, THREAD_PRIORITY_TIME_CRITICAL};
use windows::Win32::System::Variant::{VARIANT, VT_BOOL, VT_BSTR, VariantClear};
use windows::Win32::System::Wmi::{
    WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_UPDATE_ONLY, WBEM_GENERIC_FLAG_TYPE, WBEM_INFINITE,
};
use windows::Win32::UI::Input::KeyboardAndMouse::GetKeyNameTextW;
use windows::Win32::UI::Input::{
    GetRawInputData, GetRawInputDeviceInfoW, GetRegisteredRawInputDevices, HRAWINPUT, RAWINPUT, RAWINPUTDEVICE,
    RAWINPUTHEADER, RIDEV_INPUTSINK, RIDEV_REMOVE, RIDI_DEVICENAME, RID_INPUT, RIM_TYPEKEYBOARD, RIM_TYPEMOUSE,
    RegisterRawInputDevices,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetForegroundWindow, GetMessageW,
    GetWindowThreadProcessId, MSG, PostMessageW,
    PostQuitMessage, RegisterClassW, WINDOW_EX_STYLE, WM_CLOSE, WM_DESTROY, WM_INPUT, WNDCLASSW, WS_POPUP,
};
use windows::core::{BSTR, HSTRING, PCWSTR, Result, w};

use crate::{reg, restore};

const MOUSE_CLASS: &str = "{4d36e96f-e325-11ce-bfc1-08002be10318}";
const KEYBOARD_CLASS: &str = "{4d36e96b-e325-11ce-bfc1-08002be10318}";

/// Raw Input's keyboard flags.
const KEY_BREAK: u16 = 1;
const KEY_E0: u16 = 2;
const KEY_E1: u16 = 4;
/// The mouse reports positions rather than movement: tablets and remote desktop.
const MOUSE_ABSOLUTE: u16 = 1;
/// Generic desktop page: mouse and keyboard usages.
const USAGES: [u16; 2] = [2, 6];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Speed {
    /// 1.5 Mbit/s, which caps polling at 125 Hz.
    Low,
    /// 12 Mbit/s, up to 1000 Hz.
    Full,
    /// 480 Mbit/s, needed for 2000 to 8000 Hz.
    High,
    Super,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Link {
    Usb {
        speed: Speed,
        /// Hubs between the device and the controller's own ports: a monitor, a dock, a
        /// front panel with a hub chip.
        hubs: u32,
    },
    Bluetooth,
    Ps2,
}

#[derive(Clone, Debug)]
pub struct Controller {
    pub vendor: String,
    /// Not the CPU's or the chipset's own: ASMedia, Renesas, VIA and the like.
    pub add_on: bool,
    /// Signals the CPU with messages. `None` when the driver doesn't say.
    pub msi: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct Device {
    pub name: String,
    /// What the device is first of all. Keyboards often add a mouse collection for their
    /// macro keys and mice a keyboard one, so this goes by the first interface.
    pub mouse: bool,
    pub link: Link,
    /// A wireless receiver, by what it calls itself.
    pub receiver: bool,
    pub controller: Option<Controller>,
    /// The device's own nodes and the hubs up to the controller that Windows may turn off
    /// to save power, with whether it's allowed now.
    pub power: Vec<(String, bool)>,
}

impl Device {
    pub fn power_saving(&self) -> bool {
        self.power.iter().any(|(_, on)| *on)
    }
}

/// Every keyboard and mouse plugged in, one entry per physical device. Virtual ones, like
/// the keyboards that remote desktop and vendor apps add, aren't listed. Takes about a
/// tenth of a second.
pub fn devices() -> Vec<Device> {
    let power = power_states();
    let mut found: Vec<(String, Device, u32)> = Vec::new();
    for (class, mouse) in [(MOUSE_CLASS, true), (KEYBOARD_CLASS, false)] {
        for id in present(class) {
            let Some(chain) = chain(&id) else { continue };
            let Some((key, mut device)) = describe(&chain, mouse, &power) else { continue };
            let interface = interface_number(&id);
            match found.iter_mut().find(|(k, ..)| *k == key) {
                Some((_, known, first)) => {
                    if interface < *first {
                        known.mouse = mouse;
                        *first = interface;
                    }
                    for node in device.power.drain(..) {
                        if !known.power.iter().any(|(id, _)| *id == node.0) {
                            known.power.push(node);
                        }
                    }
                }
                None => found.push((key, device, interface)),
            }
        }
    }
    found.into_iter().map(|(_, device, _)| device).collect()
}

/// The instance ids from a device up to the root, with their device nodes.
fn chain(id: &str) -> Option<Vec<(String, u32)>> {
    let mut node = 0u32;
    if unsafe { CM_Locate_DevNodeW(&mut node, &HSTRING::from(id), CM_LOCATE_DEVNODE_NORMAL) } != CR_SUCCESS {
        return None;
    }
    let mut chain = vec![(id.to_uppercase(), node)];
    while chain.len() < 16 {
        let mut parent = 0u32;
        if unsafe { CM_Get_Parent(&mut parent, node, 0) } != CR_SUCCESS {
            break;
        }
        node = parent;
        chain.push((instance_id(node).to_uppercase(), node));
    }
    Some(chain)
}

/// What a keyboard or mouse collection belongs to, keyed by the physical device so its
/// other collections join it.
fn describe(chain: &[(String, u32)], mouse: bool, power: &HashMap<String, bool>) -> Option<(String, Device)> {
    let top = &chain[0].0;
    let mut device = Device { name: String::new(), mouse, link: Link::Ps2, receiver: false, controller: None, power: Vec::new() };

    // The node plugged into a port is the first USB one whose parent is a hub.
    let port = (1..chain.len()).find(|&i| chain[i - 1].0.starts_with(r"USB\") && is_hub(&chain[i].0));
    let key = if let Some(i) = port {
        let (id, node) = &chain[i - 1];
        let speed = port_number(*node).map_or(Speed::Unknown, |port| port_speed(&chain[i].0, port));
        let hubs = chain[i..].iter().filter(|(id, _)| is_hub(id) && !id.starts_with(r"USB\ROOT_HUB")).count();
        device.link = Link::Usb { speed, hubs: hubs as u32 };
        device.name = name(*node);
        device.controller = chain[i..].iter().find(|(id, _)| id.starts_with(r"PCI\")).map(|(id, _)| controller(id));
        // Its own nodes, and the hubs on the way, are where Windows decides about sleep.
        for (id, _) in chain[1..].iter().take_while(|(id, _)| !id.starts_with(r"PCI\")) {
            if let Some(&on) = power.get(id) {
                device.power.push((id.clone(), on));
            }
        }
        id.clone()
    } else if let Some((id, node)) =
        chain.iter().rev().find(|(id, _)| id.starts_with(r"BTHENUM\") || id.starts_with(r"BTHLE\"))
    {
        device.link = Link::Bluetooth;
        device.name = name(*node);
        id.clone()
    } else if top.starts_with(r"ACPI\") {
        device.name = name(chain[0].1);
        top.clone()
    } else {
        return None;
    };
    let lower = device.name.to_lowercase();
    device.receiver =
        ["receiver", "dongle", "wireless", "lightspeed", "unifying", "2.4"].iter().any(|word| lower.contains(word));
    Some((key, device))
}

/// `&MI_01` in an instance id is the interface number; devices with one interface have
/// none and count as the first.
fn interface_number(id: &str) -> u32 {
    let upper = id.to_uppercase();
    upper
        .find("&MI_")
        .and_then(|at| upper.get(at + 4..at + 6))
        .and_then(|digits| u32::from_str_radix(digits, 16).ok())
        .unwrap_or(0)
}

fn present(class: &str) -> Vec<String> {
    let filter = HSTRING::from(class);
    let flags = CM_GETIDLIST_FILTER_CLASS | CM_GETIDLIST_FILTER_PRESENT;
    let mut len = 0;
    unsafe {
        if CM_Get_Device_ID_List_SizeW(&mut len, &filter, flags) != CR_SUCCESS {
            return Vec::new();
        }
        let mut buffer = vec![0u16; len as usize];
        if CM_Get_Device_ID_ListW(&filter, &mut buffer, flags) != CR_SUCCESS {
            return Vec::new();
        }
        buffer.split(|&c| c == 0).filter(|id| !id.is_empty()).map(String::from_utf16_lossy).collect()
    }
}

fn instance_id(node: u32) -> String {
    let mut buffer = [0u16; 512];
    if unsafe { CM_Get_Device_IDW(node, &mut buffer, 0) } != CR_SUCCESS {
        return String::new();
    }
    let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..len])
}

fn property(node: u32, key: &DEVPROPKEY) -> Option<Vec<u8>> {
    let mut kind = DEVPROPTYPE::default();
    let mut size = 0u32;
    unsafe {
        let _ = CM_Get_DevNode_PropertyW(node, key, &mut kind, None, &mut size, 0);
        if size == 0 {
            return None;
        }
        let mut buffer = vec![0u8; size as usize];
        (CM_Get_DevNode_PropertyW(node, key, &mut kind, Some(buffer.as_mut_ptr()), &mut size, 0) == CR_SUCCESS)
            .then_some(buffer)
    }
}

fn text_property(node: u32, key: &DEVPROPKEY) -> Option<String> {
    let bytes = property(node, key)?;
    let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|&pair| u16::from_le_bytes(pair)).collect();
    let len = units.iter().position(|&c| c == 0).unwrap_or(units.len());
    let text = String::from_utf16_lossy(&units[..len]).trim().to_string();
    (!text.is_empty()).then_some(text)
}

/// What the device calls itself beats what its driver calls it: "G502 HERO Gaming Mouse"
/// rather than "USB Input Device".
fn name(node: u32) -> String {
    text_property(node, &DEVPKEY_Device_BusReportedDeviceDesc)
        .or_else(|| text_property(node, &DEVPKEY_Device_FriendlyName))
        .or_else(|| text_property(node, &DEVPKEY_Device_DeviceDesc))
        .unwrap_or_default()
}

/// The port a USB device sits on, counted from 1 on its hub.
fn port_number(node: u32) -> Option<u32> {
    let bytes = property(node, &DEVPKEY_Device_Address)?;
    Some(u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?))
}

fn hub_path(hub: &str) -> Option<String> {
    let id = HSTRING::from(hub);
    let mut len = 0u32;
    unsafe {
        if CM_Get_Device_Interface_List_SizeW(&mut len, &GUID_DEVINTERFACE_USB_HUB, &id, CM_GET_DEVICE_INTERFACE_LIST_PRESENT)
            != CR_SUCCESS
            || len <= 1
        {
            return None;
        }
        let mut buffer = vec![0u16; len as usize];
        if CM_Get_Device_Interface_ListW(&GUID_DEVINTERFACE_USB_HUB, &id, &mut buffer, CM_GET_DEVICE_INTERFACE_LIST_PRESENT)
            != CR_SUCCESS
        {
            return None;
        }
        let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
        (end > 0).then(|| String::from_utf16_lossy(&buffer[..end]))
    }
}

fn is_hub(id: &str) -> bool {
    id.starts_with(r"USB\") && hub_path(id).is_some()
}

/// Asks the hub at what speed the device on `port` runs.
fn port_speed(hub: &str, port: u32) -> Speed {
    let Some(path) = hub_path(hub) else { return Speed::Unknown };
    // Room for the pipes that follow the fixed part; input devices have two or three.
    let size = size_of::<USB_NODE_CONNECTION_INFORMATION_EX>() + 31 * size_of::<USB_PIPE_INFO>();
    let mut buffer: Vec<u64> = vec![0; size / 8 + 1];
    unsafe {
        let Ok(handle) = CreateFileW(
            &HSTRING::from(path),
            GENERIC_WRITE.0,
            FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAGS_AND_ATTRIBUTES(0),
            None,
        ) else {
            return Speed::Unknown;
        };
        let info = buffer.as_mut_ptr().cast::<USB_NODE_CONNECTION_INFORMATION_EX>();
        (&raw mut (*info).ConnectionIndex).write_unaligned(port);
        let bytes = (buffer.len() * 8) as u32;
        let mut returned = 0u32;
        let asked = DeviceIoControl(
            handle,
            IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX,
            Some(info.cast()),
            bytes,
            Some(info.cast()),
            bytes,
            Some(&mut returned),
            None,
        );
        let _ = CloseHandle(handle);
        if asked.is_err() {
            return Speed::Unknown;
        }
        match (&raw const (*info).Speed).read_unaligned() {
            0 => Speed::Low,
            1 => Speed::Full,
            2 => Speed::High,
            3 => Speed::Super,
            _ => Speed::Unknown,
        }
    }
}

fn controller(id: &str) -> Controller {
    let vendor_id = id.find("VEN_").and_then(|at| id.get(at + 4..at + 8)).unwrap_or("");
    let vendor = match vendor_id {
        "1022" | "1002" => "AMD",
        "8086" => "Intel",
        "1B21" => "ASMedia",
        "1912" => "Renesas",
        "1106" => "VIA",
        "1B73" => "Fresco Logic",
        "1B6F" => "Etron",
        "10DE" => "NVIDIA",
        "104C" => "Texas Instruments",
        _ => "",
    };
    let msi = reg::get_dword(reg::HKEY_LOCAL_MACHINE, &crate::boost::msi_key(id), "MSISupported")
        .ok()
        .map(|value| value == Some(1));
    Controller {
        vendor: if vendor.is_empty() { format!("VEN_{vendor_id}") } else { vendor.to_string() },
        add_on: !matches!(vendor_id, "1022" | "8086"),
        msi,
    }
}

// Power saving per device: the "Allow the computer to turn off this device" box of Device
// Manager, which is WMI's MSPower_DeviceEnable. Through WMI the driver hears of it at
// once; the registry value it lands in differs per driver (SelectiveSuspendOn for input
// devices, WDF\IdleInWorkingState for hubs).

/// Instance id, upper case, to whether Windows may turn the device off.
fn power_states() -> HashMap<String, bool> {
    let mut states = HashMap::new();
    let _ = each_power_object(|id, on, _| {
        states.insert(id, on);
        Ok(())
    });
    states
}

fn each_power_object(
    mut f: impl FnMut(String, bool, &windows::Win32::System::Wmi::IWbemClassObject) -> Result<()>,
) -> Result<()> {
    let wmi = restore::wmi(r"ROOT\WMI")?;
    unsafe {
        let rows = wmi.ExecQuery(
            &BSTR::from("WQL"),
            &BSTR::from("SELECT * FROM MSPower_DeviceEnable"),
            WBEM_FLAG_FORWARD_ONLY,
            None,
        )?;
        restore::impersonate(&rows)?;
        loop {
            let mut row = [None];
            let mut returned = 0;
            let _ = rows.Next(WBEM_INFINITE, &mut row, &mut returned);
            let Some(row) = row[0].take().filter(|_| returned == 1) else { break };
            let name = restore::read(&row, "InstanceName", |v| {
                (v.vt == VT_BSTR).then(|| v.Anonymous.bstrVal.to_string())
            });
            let on = restore::read(&row, "Enable", |v| (v.vt == VT_BOOL).then(|| v.Anonymous.boolVal.as_bool()));
            // Instances end in "_0", the first of the device's power objects.
            if let (Some(name), Some(on)) = (name, on) {
                let id = name.rsplit_once('_').map_or(name.as_str(), |(id, _)| id).to_uppercase();
                f(id, on, &row)?;
            }
        }
    }
    Ok(())
}

/// Gives back the ids it changed. A device that refuses doesn't stop the others, so the
/// journal gets exactly what moved; it's an error only when nothing did.
fn set_power(ids: &[String], on: bool) -> Result<Vec<String>> {
    let wmi = restore::wmi(r"ROOT\WMI")?;
    let mut changed = Vec::new();
    let mut refused = None;
    each_power_object(|id, current, row| unsafe {
        if current == on || !ids.contains(&id) {
            return Ok(());
        }
        let mut value = VARIANT::default();
        let inner = &mut *value.Anonymous.Anonymous;
        inner.vt = VT_BOOL;
        inner.Anonymous.boolVal = on.into();
        let put = row
            .Put(w!("Enable"), 0, &value, 0)
            .and_then(|()| wmi.PutInstance(row, WBEM_GENERIC_FLAG_TYPE(WBEM_FLAG_UPDATE_ONLY.0), None, None));
        let _ = VariantClear(&mut value);
        match put {
            Ok(()) => changed.push(id),
            Err(error) => refused = Some(error),
        }
        Ok(())
    })?;
    match refused {
        Some(error) if changed.is_empty() => Err(error),
        _ => Ok(changed),
    }
}

/// The nodes of every keyboard and mouse that Windows may turn off.
fn power_nodes() -> Vec<(String, bool)> {
    let mut nodes: Vec<(String, bool)> = Vec::new();
    for device in devices() {
        for node in device.power {
            if !nodes.iter().any(|(id, _)| *id == node.0) {
                nodes.push(node);
            }
        }
    }
    nodes
}

fn parameters(id: &str) -> String {
    format!(r"SYSTEM\CurrentControlSet\Enum\{id}\Device Parameters")
}

pub const POWER_TWEAK: &str = "input-power-off";

pub fn shows_power() -> bool {
    crate::settings::load_changes().iter().any(|c| c.id == POWER_TWEAK)
        || power_nodes().iter().any(|(_, on)| *on)
}

/// Once Vantix made the change, it counts as made while the nodes it turned off stay off.
/// A mouse plugged in later with power saving on would otherwise make the change look
/// undone, and the journal would drop the Undo for the others.
pub fn power_off() -> Result<bool> {
    let nodes = power_nodes();
    let changes = crate::settings::load_changes();
    let made = changes.iter().find(|c| c.id == POWER_TWEAK && !c.reset);
    if let Some(previous) = made.and_then(|c| c.previous.as_deref()) {
        let mine: Vec<&str> = previous.split('|').filter_map(|pair| pair.rsplit_once('=')).map(|(id, _)| id).collect();
        return Ok(nodes.iter().filter(|(id, _)| mine.contains(&id.as_str())).all(|(_, on)| !on));
    }
    Ok(!nodes.is_empty() && nodes.iter().all(|(_, on)| !on))
}

/// Saved as the nodes it turned off, each with whether SelectiveSuspendOn was there
/// before ("id=1" or "id=-"): WMI writes it for input devices, and Undo takes it away
/// again where it didn't exist.
pub fn disable_power() -> Result<Option<String>> {
    let nodes: Vec<String> = power_nodes().into_iter().filter(|(_, on)| *on).map(|(id, _)| id).collect();
    let had: Vec<bool> = nodes
        .iter()
        .map(|id| {
            reg::get_dword(reg::HKEY_LOCAL_MACHINE, &parameters(id), "SelectiveSuspendOn").ok().flatten().is_some()
        })
        .collect();
    let changed = set_power(&nodes, false)?;
    let saved: Vec<String> = nodes
        .iter()
        .zip(had)
        .filter(|(id, _)| changed.contains(id))
        .map(|(id, had)| format!("{id}={}", if had { "1" } else { "-" }))
        .collect();
    Ok(Some(saved.join("|")))
}

pub fn restore_power(previous: Option<&str>) -> Result<()> {
    let pairs: Vec<(String, bool)> = previous
        .unwrap_or_default()
        .split('|')
        .filter_map(|pair| pair.rsplit_once('='))
        .map(|(id, had)| (id.to_string(), had == "1"))
        .collect();
    let ids: Vec<String> = pairs.iter().map(|(id, _)| id.clone()).collect();
    let changed = set_power(&ids, true)?;
    for (id, had) in pairs {
        if !had && changed.contains(&id) {
            let _ = reg::delete_value(reg::HKEY_LOCAL_MACHINE, &parameters(&id), "SelectiveSuspendOn");
        }
    }
    Ok(())
}

pub fn reset_power() -> Result<()> {
    let ids: Vec<String> = power_nodes().into_iter().map(|(id, _)| id).collect();
    set_power(&ids, true).map(drop)
}

// The meter. A hidden window on a thread of its own gets every report through Raw Input,
// in the background too, and stamps it with the performance counter on arrival. Raw
// Input registration is per process, so whatever the UI toolkit had registered is put
// back when the meter stops.

#[derive(Default)]
struct Mouse {
    name: Option<String>,
    /// Arrival time in counter ticks and how far it moved, for the last two seconds.
    reports: VecDeque<(i64, u32)>,
    last: i64,
    peak: f64,
}

#[derive(Default)]
struct Keyboard {
    name: Option<String>,
    held: HashSet<u16>,
    most: usize,
    presses: u64,
    /// Per key: when it last went down and up.
    times: HashMap<u16, (i64, i64)>,
    chatter: HashMap<u16, u32>,
    last: i64,
}

#[derive(Default)]
struct Meter {
    window: isize,
    frequency: i64,
    mice: HashMap<isize, Mouse>,
    keyboards: HashMap<isize, Keyboard>,
    /// Stop came before the window was there to close.
    stopping: bool,
}

static METER: LazyLock<Mutex<Option<Meter>>> = LazyLock::new(|| Mutex::new(None));

thread_local! {
    /// What the process had registered before the meter, to put back. Only the meter's
    /// thread touches it.
    static PREVIOUS: std::cell::RefCell<Vec<RAWINPUTDEVICE>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[derive(Clone, Debug, Default)]
pub struct MouseReading {
    pub name: String,
    /// Reports per second while it moves, from the middle interval.
    pub rate: f64,
    pub peak: f64,
    /// Average distance of an interval from the middle one, in microseconds.
    pub jitter: f64,
    /// Polls that came back empty while the mouse moved fast, as a share of all of them.
    pub missed: f64,
    pub moving: bool,
}

#[derive(Clone, Debug, Default)]
pub struct KeyboardReading {
    pub name: String,
    pub held: usize,
    pub most: usize,
    pub presses: u64,
    /// Keys that registered twice for one press, with how often.
    pub chatter: Vec<(String, u32)>,
}

#[derive(Clone, Debug, Default)]
pub struct Reading {
    pub in_front: bool,
    pub mouse: Option<MouseReading>,
    pub keyboard: Option<KeyboardReading>,
}

pub fn start() {
    let mut meter = METER.lock().unwrap();
    if meter.is_some() {
        return;
    }
    let mut frequency = 0i64;
    let _ = unsafe { QueryPerformanceFrequency(&mut frequency) };
    *meter = Some(Meter { frequency, ..Default::default() });
    drop(meter);
    std::thread::spawn(run);
}

pub fn stop() {
    let mut guard = METER.lock().unwrap();
    let Some(meter) = guard.as_mut() else { return };
    if meter.window == 0 {
        meter.stopping = true;
    } else {
        let _ = unsafe { PostMessageW(Some(HWND(meter.window as _)), WM_CLOSE, WPARAM(0), LPARAM(0)) };
    }
}

#[cfg(test)]
fn running() -> bool {
    METER.lock().unwrap().is_some()
}

fn run() {
    unsafe {
        let _ = SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
        let instance = GetModuleHandleW(None).unwrap_or_default();
        let class = WNDCLASSW {
            lpfnWndProc: Some(procedure),
            hInstance: instance.into(),
            lpszClassName: w!("VantixInputMeter"),
            ..Default::default()
        };
        // A second start finds the class already there, which is fine.
        RegisterClassW(&class);
        // Not a message-only window: those don't get input in the background.
        let window = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            w!("VantixInputMeter"),
            PCWSTR::null(),
            WS_POPUP,
            0,
            0,
            0,
            0,
            None,
            None,
            Some(instance.into()),
            None,
        );
        let Ok(window) = window else {
            *METER.lock().unwrap() = None;
            return;
        };

        PREVIOUS.set(registered());
        let wanted: Vec<RAWINPUTDEVICE> = USAGES
            .iter()
            .map(|&usage| RAWINPUTDEVICE {
                usUsagePage: 1,
                usUsage: usage,
                dwFlags: RIDEV_INPUTSINK,
                hwndTarget: window,
            })
            .collect();
        if RegisterRawInputDevices(&wanted, size_of::<RAWINPUTDEVICE>() as u32).is_err() {
            let _ = DestroyWindow(window);
            *METER.lock().unwrap() = None;
            return;
        }
        if let Some(meter) = METER.lock().unwrap().as_mut() {
            meter.window = window.0 as isize;
            if meter.stopping {
                let _ = PostMessageW(Some(window), WM_CLOSE, WPARAM(0), LPARAM(0));
            }
        }

        let mut message = MSG::default();
        while GetMessageW(&mut message, None, 0, 0).as_bool() {
            DispatchMessageW(&message);
        }
        *METER.lock().unwrap() = None;
    }
}

/// The mouse and keyboard registrations the process has now.
fn registered() -> Vec<RAWINPUTDEVICE> {
    let size = size_of::<RAWINPUTDEVICE>() as u32;
    let mut count = 0u32;
    unsafe {
        GetRegisteredRawInputDevices(None, &mut count, size);
        let mut list = vec![RAWINPUTDEVICE::default(); count as usize];
        if count == 0 || GetRegisteredRawInputDevices(Some(list.as_mut_ptr()), &mut count, size) == u32::MAX {
            return Vec::new();
        }
        list.truncate(count as usize);
        list.retain(|device| device.usUsagePage == 1 && USAGES.contains(&device.usUsage));
        list
    }
}

/// Gives the toolkit back its registrations and drops the meter's.
fn unregister(previous: &[RAWINPUTDEVICE]) {
    let size = size_of::<RAWINPUTDEVICE>() as u32;
    let list: Vec<RAWINPUTDEVICE> = USAGES
        .iter()
        .map(|&usage| {
            previous.iter().find(|device| device.usUsage == usage).copied().unwrap_or(RAWINPUTDEVICE {
                usUsagePage: 1,
                usUsage: usage,
                dwFlags: RIDEV_REMOVE,
                hwndTarget: HWND::default(),
            })
        })
        .collect();
    let _ = unsafe { RegisterRawInputDevices(&list, size) };
}

unsafe extern "system" fn procedure(window: HWND, message: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match message {
        WM_INPUT => {
            let mut now = 0i64;
            let _ = unsafe { QueryPerformanceCounter(&mut now) };
            let mut input = RAWINPUT::default();
            let mut size = size_of::<RAWINPUT>() as u32;
            let read = unsafe {
                GetRawInputData(
                    HRAWINPUT(lparam.0 as _),
                    RID_INPUT,
                    Some((&raw mut input).cast()),
                    &mut size,
                    size_of::<RAWINPUTHEADER>() as u32,
                )
            };
            if read != u32::MAX && read > 0 {
                record(&input, now);
            }
            // Windows cleans up the input in here.
            unsafe { DefWindowProcW(window, message, wparam, lparam) }
        }
        WM_CLOSE => {
            unregister(&PREVIOUS.take());
            let _ = unsafe { DestroyWindow(window) };
            LRESULT(0)
        }
        WM_DESTROY => {
            unsafe { PostQuitMessage(0) };
            LRESULT(0)
        }
        _ => unsafe { DefWindowProcW(window, message, wparam, lparam) },
    }
}

/// Whether a window of Vantix is the one in front. Windows 11 hands input to background
/// windows at about 125 Hz, so nothing measured then is true; and keys typed into other
/// programs are none of the meter's business.
fn in_front() -> bool {
    let mut pid = 0u32;
    unsafe { GetWindowThreadProcessId(GetForegroundWindow(), Some(&mut pid)) };
    pid == std::process::id()
}

fn record(input: &RAWINPUT, now: i64) {
    let mut guard = METER.lock().unwrap();
    let Some(meter) = guard.as_mut() else { return };
    if !in_front() {
        // A key let go in another window would stay held here.
        meter.keyboards.values_mut().for_each(|keyboard| keyboard.held.clear());
        return;
    }
    let device = input.header.hDevice;
    let key = device.0 as isize;
    let frequency = meter.frequency.max(1);
    if input.header.dwType == RIM_TYPEMOUSE.0 {
        let report = unsafe { input.data.mouse };
        if report.usFlags.0 & MOUSE_ABSOLUTE != 0 {
            return;
        }
        let moved = report.lLastX.unsigned_abs() + report.lLastY.unsigned_abs();
        if moved == 0 {
            return;
        }
        let mouse = meter.mice.entry(key).or_default();
        if mouse.name.is_none() {
            mouse.name = Some(raw_device_name(device));
        }
        mouse.reports.push_back((now, moved));
        mouse.last = now;
        while mouse.reports.front().is_some_and(|&(at, _)| now - at > frequency * 2) {
            mouse.reports.pop_front();
        }
    } else if input.header.dwType == RIM_TYPEKEYBOARD.0 {
        let report = unsafe { input.data.keyboard };
        // Fake keys Windows inserts around some combinations, and the Pause key's E1
        // sequence, aren't presses.
        if report.MakeCode == 0 || report.VKey == 0xff || report.Flags & KEY_E1 != 0 {
            return;
        }
        let code = report.MakeCode | if report.Flags & KEY_E0 != 0 { 0x100 } else { 0 };
        let keyboard = meter.keyboards.entry(key).or_default();
        if keyboard.name.is_none() {
            keyboard.name = Some(raw_device_name(device));
        }
        keyboard.last = now;
        let times = keyboard.times.entry(code).or_insert((i64::MIN / 2, i64::MIN / 2));
        if report.Flags & KEY_BREAK != 0 {
            keyboard.held.remove(&code);
            times.1 = now;
        } else if keyboard.held.insert(code) {
            // Down again within 40 ms of the last press, with a release in between: no
            // finger does that, a worn or bouncing switch does.
            if times.1 > times.0 && now - times.0 < frequency * 40 / 1000 {
                *keyboard.chatter.entry(code).or_default() += 1;
            } else {
                keyboard.presses += 1;
            }
            times.0 = now;
            keyboard.most = keyboard.most.max(keyboard.held.len());
        }
    }
}

/// The physical device behind a Raw Input handle, by the same name the inspector shows.
fn raw_device_name(device: HANDLE) -> String {
    let mut size = 0u32;
    unsafe {
        GetRawInputDeviceInfoW(Some(device), RIDI_DEVICENAME, None, &mut size);
        let mut buffer = vec![0u16; size as usize + 1];
        if GetRawInputDeviceInfoW(Some(device), RIDI_DEVICENAME, Some(buffer.as_mut_ptr().cast()), &mut size)
            == u32::MAX
        {
            return String::new();
        }
        let len = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
        // \\?\HID#VID_046D&PID_C08B&MI_00#8&285d7672&0&0000#{guid} is the interface of
        // HID\VID_046D&PID_C08B&MI_00\8&285d7672&0&0000.
        let path = String::from_utf16_lossy(&buffer[..len]);
        let path = path.trim_start_matches(r"\\?\");
        let id = path.rsplit_once('#').map_or(path, |(id, _)| id).replace('#', r"\");
        let Some(chain) = chain(&id) else { return String::new() };
        describe(&chain, true, &HashMap::new()).map(|(_, device)| device.name).unwrap_or_default()
    }
}

/// What the meter has seen. The mouse and keyboard shown are the ones used last.
pub fn reading() -> Reading {
    let mut now = 0i64;
    let _ = unsafe { QueryPerformanceCounter(&mut now) };
    let mut guard = METER.lock().unwrap();
    let Some(meter) = guard.as_mut() else { return Reading::default() };
    let frequency = meter.frequency.max(1) as f64;
    let mouse = meter.mice.values_mut().max_by_key(|mouse| mouse.last).map(|mouse| {
        let recent: Vec<(i64, u32)> =
            mouse.reports.iter().copied().filter(|&(at, _)| (now - at) as f64 / frequency < 1.0).collect();
        let mut reading = measure(&recent, frequency);
        reading.name = mouse.name.clone().unwrap_or_default();
        if reading.moving {
            mouse.peak = mouse.peak.max(reading.rate);
        }
        reading.peak = mouse.peak;
        reading
    });
    let keyboard = meter.keyboards.values().max_by_key(|keyboard| keyboard.last).map(|keyboard| {
        let mut chatter: Vec<(String, u32)> =
            keyboard.chatter.iter().map(|(&code, &count)| (key_name(code), count)).collect();
        chatter.sort_by_key(|&(_, count)| std::cmp::Reverse(count));
        KeyboardReading {
            name: keyboard.name.clone().unwrap_or_default(),
            held: keyboard.held.len(),
            most: keyboard.most,
            presses: keyboard.presses,
            chatter,
        }
    });
    Reading { in_front: in_front(), mouse, keyboard }
}

/// Rate, jitter and missed polls from the reports of the last second. Gaps over 50 ms are
/// the mouse resting, not lost reports.
fn measure(reports: &[(i64, u32)], frequency: f64) -> MouseReading {
    let pairs: Vec<(f64, u32, u32)> = reports
        .windows(2)
        .map(|pair| ((pair[1].0 - pair[0].0) as f64 / frequency * 1e6, pair[0].1, pair[1].1))
        .filter(|&(gap, ..)| gap < 50_000.0)
        .collect();
    if pairs.len() < 50 {
        return MouseReading::default();
    }
    let mut gaps: Vec<f64> = pairs.iter().map(|&(gap, ..)| gap).collect();
    gaps.sort_by(f64::total_cmp);
    let middle = gaps[gaps.len() / 2].max(1.0);
    let regular: Vec<f64> = gaps.iter().copied().filter(|&gap| gap < middle * 1.5).collect();
    let jitter = regular.iter().map(|gap| (gap - middle).abs()).sum::<f64>() / regular.len().max(1) as f64;
    // Moving fast enough to change every poll, a longer gap means polls with nothing in them.
    let mut missed = 0.0;
    let mut polls = 0.0;
    for &(gap, before, after) in &pairs {
        if before >= 3 && after >= 3 {
            let steps = (gap / middle).round().max(1.0);
            polls += steps;
            if gap > middle * 1.5 {
                missed += steps - 1.0;
            }
        }
    }
    MouseReading {
        name: String::new(),
        rate: 1e6 / middle,
        peak: 0.0,
        jitter,
        missed: if polls > 0.0 { missed / polls } else { 0.0 },
        moving: true,
    }
}

fn key_name(code: u16) -> String {
    let lparam = ((code as i32 & 0xff) << 16) | if code & 0x100 != 0 { 1 << 24 } else { 0 };
    let mut buffer = [0u16; 64];
    let len = unsafe { GetKeyNameTextW(lparam, &mut buffer) };
    if len <= 0 {
        return format!("0x{code:x}");
    }
    String::from_utf16_lossy(&buffer[..len as usize])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read-only: `cargo test input_devices -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn input_devices() {
        let started = std::time::Instant::now();
        let list = devices();
        println!("{} devices in {:?}", list.len(), started.elapsed());
        for device in &list {
            println!("{device:#?}");
        }
        assert!(!list.is_empty(), "no keyboard or mouse found");
    }

    /// Move the mouse fast in circles and press a few keys at once while it runs:
    /// `cargo test input_meter -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn input_meter() {
        start();
        for _ in 0..10 {
            std::thread::sleep(std::time::Duration::from_secs(1));
            println!("{:?}", reading());
        }
        stop();
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(!running(), "the meter thread didn't stop");
    }

    /// Turns power saving off on every keyboard and mouse node and back, as Apply and Undo
    /// do, and checks the registry ends where it started. Needs an elevated shell:
    /// `cargo test input_power_round_trip -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn input_power_round_trip() {
        let before = power_nodes();
        if !before.iter().any(|(_, on)| *on) {
            println!("power saving is already off everywhere, nothing to check");
            return;
        }
        let values = |nodes: &[(String, bool)]| -> Vec<Option<u32>> {
            nodes
                .iter()
                .map(|(id, _)| reg::get_dword(reg::HKEY_LOCAL_MACHINE, &parameters(id), "SelectiveSuspendOn").unwrap())
                .collect()
        };
        let registry = values(&before);
        let saved = disable_power().expect("turning power saving off failed");
        println!("saved: {saved:?}");
        let off = power_nodes();
        restore_power(saved.as_deref()).expect("putting it back failed");
        assert!(off.iter().all(|(_, on)| !on), "a node still allows power saving: {off:?}");
        assert_eq!(power_nodes(), before, "the nodes didn't come back as they were");
        assert_eq!(values(&before), registry, "SelectiveSuspendOn was left behind");
    }

    #[test]
    fn measures_a_steady_mouse() {
        // 1000 Hz with every tenth poll empty.
        let frequency = 10_000_000.0;
        let mut reports = Vec::new();
        let mut at = 0i64;
        for i in 0..900 {
            at += if i % 10 == 9 { 20_000 } else { 10_000 };
            reports.push((at, 5));
        }
        let reading = measure(&reports, frequency);
        assert!((reading.rate - 1000.0).abs() < 1.0, "rate {}", reading.rate);
        assert!(reading.missed > 0.08 && reading.missed < 0.12, "missed {}", reading.missed);
        assert!(reading.jitter < 1.0, "jitter {}", reading.jitter);
    }

    #[test]
    fn reads_interface_numbers() {
        assert_eq!(interface_number(r"HID\VID_046D&PID_C08B&MI_01&COL01\8&3B8D92B0&0&0000"), 1);
        assert_eq!(interface_number(r"HID\VID_046D&PID_C232\2&1A87F3A8&0&0000"), 0);
    }
}
