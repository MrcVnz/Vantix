//! Tweaks for Performance, Games, Input and Background. Same contract as the storage ones
//! in tweaks.rs: `read` looks at the real state, `apply` returns what `revert` needs and
//! `reset` turns the tweak off when it was already in place before Vantix.
//!
//! Saved values are text so one entry can hold several of them: numbers as decimal,
//! lists joined with commas and "-" for a value that didn't exist.

use std::cell::Cell;

use windows::Win32::Foundation::{HLOCAL, LocalFree, WIN32_ERROR};
use windows::Win32::System::Power::{
    GetPwrCapabilities, PowerGetActiveScheme, PowerReadACValueIndex, PowerReadDCValueIndex,
    PowerSetActiveScheme, PowerWriteACValueIndex, PowerWriteDCValueIndex, SYSTEM_POWER_CAPABILITIES,
};
use windows::Win32::System::Registry::HKEY;
use windows::Win32::System::SystemInformation::GetPhysicallyInstalledSystemMemory;
use windows::Win32::UI::Accessibility::{FILTERKEYS, STICKYKEYS, STICKYKEYS_FLAGS, TOGGLEKEYS};
use windows::Win32::UI::WindowsAndMessaging::{
    SPI_GETFILTERKEYS, SPI_GETMOUSE, SPI_GETSTICKYKEYS, SPI_GETTOGGLEKEYS, SPI_SETFILTERKEYS, SPI_SETMOUSE,
    SPI_SETSTICKYKEYS, SPI_SETTOGGLEKEYS, SPIF_SENDCHANGE, SPIF_UPDATEINIFILE, SystemParametersInfoW,
};
use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_GETIDLIST_FILTER_CLASS, CM_GETIDLIST_FILTER_PRESENT, CM_Get_Device_ID_List_SizeW, CM_Get_Device_ID_ListW,
    CR_SUCCESS,
};
use windows::core::{GUID, HSTRING, Result};

use crate::reg::{self, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
use crate::tweaks::{powershell, run};

type Saved = Result<Option<String>>;

/// Runs `count` steps in order. When one fails, the ones already done are undone in
/// reverse and the error comes back, so a tweak never stays half applied: a failed apply
/// gets no journal entry, and what it changed would have no way back.
fn all_or_nothing(
    what: &str,
    count: usize,
    mut step: impl FnMut(usize) -> Result<()>,
    mut undo: impl FnMut(usize) -> Result<()>,
) -> Result<()> {
    for i in 0..count {
        if let Err(e) = step(i) {
            for done in (0..i).rev() {
                if let Err(undo_error) = undo(done) {
                    crate::system::log_error(&format!("undo {what}"), &undo_error);
                }
            }
            return Err(e);
        }
    }
    Ok(())
}

fn saved(value: Option<u32>) -> String {
    value.map_or("-".into(), |v| v.to_string())
}

fn unsaved(text: &str) -> Option<u32> {
    text.parse().ok()
}

/// Puts a DWORD back to what `saved` recorded, deleting it if it didn't exist.
fn restore_dword(root: HKEY, path: &str, name: &str, previous: Option<&str>) -> Result<()> {
    match previous.and_then(unsaved) {
        Some(value) => reg::set_dword(root, path, name, value),
        None => reg::delete_value(root, path, name),
    }
}

/// A tweak that sets one DWORD. `on` decides whether the current value counts as applied,
/// which for some settings includes the value being missing.
macro_rules! dword_tweak {
    ($read:ident, $apply:ident, $revert:ident, $reset:ident, $root:expr, $path:expr, $name:expr, $value:expr,
     $on:expr, $off:expr) => {
        pub fn $read() -> Result<bool> {
            let on: fn(Option<u32>) -> bool = $on;
            Ok(on(reg::get_dword($root, $path, $name)?))
        }
        pub fn $apply() -> Saved {
            let previous = reg::get_dword($root, $path, $name)?;
            reg::set_dword($root, $path, $name, $value)?;
            Ok(Some(saved(previous)))
        }
        pub fn $revert(previous: Option<&str>) -> Result<()> {
            restore_dword($root, $path, $name, previous)
        }
        pub fn $reset() -> Result<()> {
            let off: Option<u32> = $off;
            match off {
                Some(value) => reg::set_dword($root, $path, $name, value),
                None => reg::delete_value($root, $path, $name),
            }
        }
    };
}

// Power settings, on the active plan while plugged in (AC). Laptops on battery keep
// their own values.

const SUB_PROCESSOR: GUID = GUID::from_u128(0x54533251_82be_4824_96c1_47b60b740d00);
const SUB_PCIEXPRESS: GUID = GUID::from_u128(0x501a4d13_42af_4429_9fd1_a8218c268e20);
const SUB_USB: GUID = GUID::from_u128(0x2a737441_1930_4402_8d77_b2bebba308a3);
const CPMINCORES: GUID = GUID::from_u128(0x0cc5b647_c1df_4637_891a_dec35c318583);
const PROCTHROTTLEMIN: GUID = GUID::from_u128(0x893dee8e_2bef_41e0_89c6_b55d0929964c);
const PERFBOOSTMODE: GUID = GUID::from_u128(0xbe337238_0d82_4146_a960_4f3749d470c7);
const ASPM: GUID = GUID::from_u128(0xee12f906_d277_404b_b6da_e5fa1a576df5);
const USB_SUSPEND: GUID = GUID::from_u128(0x48e6b7a6_50f5_4782_a5d4_53bb8f07e226);
const SUB_WIRELESS: GUID = GUID::from_u128(0x19cbb8fa_5279_450e_9fac_8a3d5fedd0c1);
const WIFI_POWER_SAVING: GUID = GUID::from_u128(0x12bbebe6_58d6_4636_95bb_3217ef867c1a);

fn active_scheme() -> Result<GUID> {
    unsafe {
        let mut scheme: *mut GUID = std::ptr::null_mut();
        PowerGetActiveScheme(None, &mut scheme).ok()?;
        let guid = *scheme;
        let _ = LocalFree(Some(HLOCAL(scheme.cast())));
        Ok(guid)
    }
}

thread_local! {
    /// The plan a change is undone on, when that's not the active one.
    static PLAN: Cell<Option<GUID>> = const { Cell::new(None) };
}

/// The active plan, as the journal records it for the power settings below.
pub fn active_plan() -> Option<String> {
    active_scheme().ok().map(|scheme| format!("{scheme:?}"))
}

/// Whether a plan from the journal still exists.
pub fn plan_exists(plan: &str) -> bool {
    let Ok(scheme) = GUID::try_from(plan) else { return false };
    let mut value = 0;
    unsafe {
        PowerReadACValueIndex(None, Some(&scheme), Some(&SUB_PROCESSOR), Some(&PROCTHROTTLEMIN), &mut value)
    }
    .is_ok()
}

/// Runs `f` with the power settings below aimed at `plan` instead of the active plan.
pub fn on_plan<T>(plan: Option<&str>, f: impl FnOnce() -> T) -> T {
    PLAN.set(plan.and_then(|plan| GUID::try_from(plan).ok()));
    let result = f();
    PLAN.set(None);
    result
}

fn target_scheme() -> Result<GUID> {
    PLAN.get().map_or_else(active_scheme, Ok)
}

fn power(subgroup: &GUID, setting: &GUID) -> Result<u32> {
    let scheme = target_scheme()?;
    let mut value = 0;
    unsafe { PowerReadACValueIndex(None, Some(&scheme), Some(subgroup), Some(setting), &mut value).ok()? };
    Ok(value)
}

/// Writing to the plan doesn't touch the running system until the plan is set again,
/// which only happens when it's the active one.
fn set_power(subgroup: &GUID, setting: &GUID, value: u32) -> Result<()> {
    let scheme = target_scheme()?;
    let before = power(subgroup, setting)?;
    let write = |value| unsafe { PowerWriteACValueIndex(None, &scheme, Some(subgroup), Some(setting), value).ok() };
    all_or_nothing(
        "power setting",
        2,
        |step| match step {
            0 => write(value),
            _ if scheme == active_scheme()? => unsafe { PowerSetActiveScheme(None, Some(&scheme)).ok() },
            _ => Ok(()),
        },
        |_| write(before),
    )
}

/// `$off` is what Windows' own Balanced plan uses for the setting.
macro_rules! power_tweak {
    ($read:ident, $apply:ident, $revert:ident, $reset:ident, $subgroup:expr, $setting:expr, $value:expr, $off:expr) => {
        pub fn $read() -> Result<bool> {
            Ok(power(&$subgroup, &$setting)? == $value)
        }
        pub fn $apply() -> Saved {
            let previous = power(&$subgroup, &$setting)?;
            set_power(&$subgroup, &$setting, $value)?;
            Ok(Some(previous.to_string()))
        }
        pub fn $revert(previous: Option<&str>) -> Result<()> {
            match previous.and_then(unsaved) {
                Some(value) => set_power(&$subgroup, &$setting, value),
                None => Ok(()),
            }
        }
        pub fn $reset() -> Result<()> {
            set_power(&$subgroup, &$setting, $off)
        }
    };
}

// Ultimate Performance plan. Windows ships it hidden, as a template to copy. The copy gets
// a GUID of our own so undo knows which plan to remove, and there's never a second one.
// Copies keep the template's name resource, which is how copies made by other tools or by
// hand are recognized too.

const ULTIMATE: GUID = GUID::from_u128(0xe9a42b02_d5df_448d_aa00_03f14749eb61);
const VANTIX_ULTIMATE: GUID = GUID::from_u128(0x5a17e0c1_7a3d_4e2b_9c41_86f0d2b5a9e3);
const BALANCED: GUID = GUID::from_u128(0x381b4222_f694_41f0_9685_ff5bb260df2e);

/// Modern Standby PCs only offer Balanced, and Windows switches back from any other plan.
pub fn has_power_plans() -> bool {
    let mut caps = SYSTEM_POWER_CAPABILITIES::default();
    !unsafe { GetPwrCapabilities(&mut caps) } || !caps.AoAc
}

fn set_scheme(scheme: &GUID) -> Result<()> {
    unsafe { PowerSetActiveScheme(None, Some(scheme)).ok() }
}

pub fn ultimate_on() -> Result<bool> {
    let active = active_scheme()?;
    let key = format!(r"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\{active:?}");
    let name = reg::get_string(HKEY_LOCAL_MACHINE, &key, "FriendlyName")?.unwrap_or_default();
    Ok(active == ULTIMATE || active == VANTIX_ULTIMATE || name.to_lowercase().contains("powrprof.dll,-19,"))
}

pub fn enable_ultimate() -> Saved {
    let previous = active_scheme()?;
    if set_scheme(&VANTIX_ULTIMATE).is_err() {
        run("powercfg.exe", &["/duplicatescheme", &format!("{ULTIMATE:?}"), &format!("{VANTIX_ULTIMATE:?}")])?;
        if let Err(e) = set_scheme(&VANTIX_ULTIMATE) {
            // Not left behind as a plan nobody picked.
            let _ = run("powercfg.exe", &["/delete", &format!("{VANTIX_ULTIMATE:?}")]);
            return Err(e);
        }
    }
    Ok(Some(format!("{previous:?}")))
}

/// Back to the plan that was active, or Balanced if that one was deleted since.
pub fn restore_ultimate(previous: Option<&str>) -> Result<()> {
    let previous = previous.and_then(|text| GUID::try_from(text).ok()).unwrap_or(BALANCED);
    if set_scheme(&previous).is_err() {
        set_scheme(&BALANCED)?;
    }
    // Fails when it no longer exists, which is fine.
    let _ = run("powercfg.exe", &["/delete", &format!("{VANTIX_ULTIMATE:?}")]);
    Ok(())
}

pub fn reset_ultimate() -> Result<()> {
    restore_ultimate(None)
}

// Turned off, these go to the values Balanced uses on battery, which is the closest thing
// to "power saving on" the plans define.
power_tweak!(
    core_parking_off,
    disable_core_parking,
    restore_core_parking,
    reset_core_parking,
    SUB_PROCESSOR,
    CPMINCORES,
    100,
    10
);
power_tweak!(
    full_clock,
    set_full_clock,
    restore_full_clock,
    reset_full_clock,
    SUB_PROCESSOR,
    PROCTHROTTLEMIN,
    100,
    5
);
// 2 is "Aggressive" in PERFBOOSTMODE, 1 is "Enabled".
power_tweak!(
    boost_aggressive,
    set_boost_aggressive,
    restore_boost,
    reset_boost,
    SUB_PROCESSOR,
    PERFBOOSTMODE,
    2,
    1
);
// 0 is off, 1 is moderate power savings.
power_tweak!(aspm_off, disable_aspm, restore_aspm, reset_aspm, SUB_PCIEXPRESS, ASPM, 0, 1);
power_tweak!(
    usb_suspend_off,
    disable_usb_suspend,
    restore_usb_suspend,
    reset_usb_suspend,
    SUB_USB,
    USB_SUSPEND,
    0,
    1
);

// Wi-Fi power saving, on battery too: plugged in, the plans already run Wi-Fi at full
// power, and on battery is where its naps show up as ping spikes. 0 is Maximum
// Performance; Balanced uses 2 on battery.

fn wifi_power() -> Result<(u32, u32)> {
    let scheme = target_scheme()?;
    let (subgroup, setting): (*const GUID, *const GUID) = (&SUB_WIRELESS, &WIFI_POWER_SAVING);
    let (mut ac, mut dc) = (0, 0);
    unsafe {
        PowerReadACValueIndex(None, Some(&scheme), Some(subgroup), Some(setting), &mut ac).ok()?;
        WIN32_ERROR(PowerReadDCValueIndex(None, Some(&scheme), Some(subgroup), Some(setting), &mut dc)).ok()?;
    }
    Ok((ac, dc))
}

fn set_wifi_power(ac: u32, dc: u32) -> Result<()> {
    let scheme = target_scheme()?;
    let before = wifi_power()?;
    let (subgroup, setting): (*const GUID, *const GUID) = (&SUB_WIRELESS, &WIFI_POWER_SAVING);
    let write_ac = |value| unsafe { PowerWriteACValueIndex(None, &scheme, Some(subgroup), Some(setting), value).ok() };
    let write_dc = |value| unsafe {
        WIN32_ERROR(PowerWriteDCValueIndex(None, &scheme, Some(subgroup), Some(setting), value)).ok()
    };
    all_or_nothing(
        "Wi-Fi power",
        3,
        |step| match step {
            0 => write_ac(ac),
            1 => write_dc(dc),
            _ if scheme == active_scheme()? => unsafe { PowerSetActiveScheme(None, Some(&scheme)).ok() },
            _ => Ok(()),
        },
        |step| if step == 0 { write_ac(before.0) } else { write_dc(before.1) },
    )
}

pub fn shows_wifi_power() -> bool {
    crate::net::uses_wifi() || crate::settings::in_journal("wifi-max-performance")
}

pub fn wifi_full_power() -> Result<bool> {
    Ok(wifi_power()? == (0, 0))
}

pub fn set_wifi_full_power() -> Saved {
    let (ac, dc) = wifi_power()?;
    set_wifi_power(0, 0)?;
    Ok(Some(format!("{ac},{dc}")))
}

pub fn restore_wifi_power(previous: Option<&str>) -> Result<()> {
    let Some((ac, dc)) = previous.and_then(|text| text.split_once(',')) else { return Ok(()) };
    match (unsaved(ac), unsaved(dc)) {
        (Some(ac), Some(dc)) => set_wifi_power(ac, dc),
        _ => Ok(()),
    }
}

pub fn reset_wifi_power() -> Result<()> {
    set_wifi_power(0, 2)
}

/// Laptops, and the odd desktop on a UPS that reports itself as a battery.
pub fn has_battery() -> bool {
    let mut caps = SYSTEM_POWER_CAPABILITIES::default();
    let read = unsafe { GetPwrCapabilities(&mut caps) };
    read && caps.SystemBatteriesPresent
}

// Memory integrity (HVCI). Missing means it was never turned on, unless a policy or the
// firmware did, which the running services tell.

const HVCI_KEY: &str =
    r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity";

/// Only where Memory integrity is on or was set either way. On a PC where it never ran
/// there's nothing to gain, and the card would offer to turn it on as its "undo".
pub fn shows_hvci() -> bool {
    match reg::get_dword(HKEY_LOCAL_MACHINE, HVCI_KEY, "Enabled") {
        Ok(Some(_)) => true,
        _ => hvci_running().unwrap_or(false),
    }
}

pub fn hvci_off() -> Result<bool> {
    match reg::get_dword(HKEY_LOCAL_MACHINE, HVCI_KEY, "Enabled")? {
        Some(0) => Ok(true),
        Some(_) => Ok(false),
        None => Ok(!hvci_running()?),
    }
}

fn hvci_running() -> Result<bool> {
    // 2 in SecurityServicesRunning is HVCI.
    let running = powershell(
        "(Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName Win32_DeviceGuard \
         -ErrorAction Stop).SecurityServicesRunning -join ','",
    )?;
    Ok(running.split(',').any(|service| service.trim() == "2"))
}

pub fn disable_hvci() -> Saved {
    let previous = reg::get_dword(HKEY_LOCAL_MACHINE, HVCI_KEY, "Enabled")?;
    reg::set_dword(HKEY_LOCAL_MACHINE, HVCI_KEY, "Enabled", 0)?;
    Ok(Some(saved(previous)))
}

pub fn restore_hvci(previous: Option<&str>) -> Result<()> {
    restore_dword(HKEY_LOCAL_MACHINE, HVCI_KEY, "Enabled", previous)
}

/// Windows checks the drivers at the next boot and keeps it off if one is incompatible.
pub fn reset_hvci() -> Result<()> {
    reg::set_dword(HKEY_LOCAL_MACHINE, HVCI_KEY, "Enabled", 1)
}

// Memory compression. Only worth it with 16 GB or more, where Windows rarely needs the
// extra room and the compression is just CPU time.

pub fn has_16_gb() -> bool {
    let mut kilobytes = 0u64;
    unsafe { GetPhysicallyInstalledSystemMemory(&mut kilobytes) }.is_ok() && kilobytes >= 16 * 1024 * 1024
}

pub fn memory_compression_off() -> Result<bool> {
    Ok(powershell("(Get-MMAgent -ErrorAction Stop).MemoryCompression")? == "False")
}

pub fn disable_memory_compression() -> Saved {
    powershell("Disable-MMAgent -MemoryCompression -ErrorAction Stop").map(|_| None)
}

pub fn enable_memory_compression(_: Option<&str>) -> Result<()> {
    powershell("Enable-MMAgent -MemoryCompression -ErrorAction Stop").map(drop)
}

pub fn reset_memory_compression() -> Result<()> {
    enable_memory_compression(None)
}

// MSI mode for the graphics card and network adapters: the device signals the CPU with a
// message instead of a shared interrupt line. Only devices whose driver lists the setting
// are touched, since its key is how a driver says the device can do it.

const DISPLAY_CLASS: &str = "{4d36e968-e325-11ce-bfc1-08002be10318}";
const NET_CLASS: &str = "{4d36e972-e325-11ce-bfc1-08002be10318}";

pub(crate) fn msi_key(device: &str) -> String {
    format!(
        r"SYSTEM\CurrentControlSet\Enum\{device}\Device Parameters\Interrupt Management\MessageSignaledInterruptProperties"
    )
}

/// Instance ids of the PCI devices of a class that are plugged in now.
fn pci_devices(class: &str) -> Vec<String> {
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
        buffer
            .split(|&c| c == 0)
            .map(String::from_utf16_lossy)
            .filter(|id| id.starts_with(r"PCI\"))
            .collect()
    }
}

pub fn graphics_cards() -> usize {
    pci_devices(DISPLAY_CLASS).len()
}

/// The graphics and network devices whose driver lists the MSI setting.
fn msi_devices() -> Vec<String> {
    [DISPLAY_CLASS, NET_CLASS]
        .into_iter()
        .flat_map(pci_devices)
        .filter(|id| reg::key_exists(HKEY_LOCAL_MACHINE, &msi_key(id)))
        .collect()
}

/// Shown while some device can still be switched, or to undo what Vantix did. Turning
/// MSI off on devices that already use it would only make them slower, so that isn't
/// offered, and a PC without such devices has nothing to show.
pub fn shows_msi() -> bool {
    crate::settings::in_journal("msi-mode")
        || !msi_devices().is_empty() && !msi_on().unwrap_or(true)
}

pub fn msi_on() -> Result<bool> {
    let devices = msi_devices();
    for device in &devices {
        if reg::get_dword(HKEY_LOCAL_MACHINE, &msi_key(device), "MSISupported")? != Some(1) {
            return Ok(false);
        }
    }
    Ok(!devices.is_empty())
}

/// Saved as "device=value" pairs joined with "|"; instance ids never contain either.
pub fn enable_msi() -> Saved {
    let mut off = Vec::new();
    for device in msi_devices() {
        let value = reg::get_dword(HKEY_LOCAL_MACHINE, &msi_key(&device), "MSISupported")?;
        if value != Some(1) {
            off.push((device, saved(value)));
        }
    }
    all_or_nothing(
        "MSI mode",
        off.len(),
        |i| reg::set_dword(HKEY_LOCAL_MACHINE, &msi_key(&off[i].0), "MSISupported", 1),
        |i| restore_dword(HKEY_LOCAL_MACHINE, &msi_key(&off[i].0), "MSISupported", Some(&off[i].1)),
    )?;
    Ok(Some(off.iter().map(|(device, value)| format!("{device}={value}")).collect::<Vec<_>>().join("|")))
}

pub fn restore_msi(previous: Option<&str>) -> Result<()> {
    for pair in previous.unwrap_or_default().split('|').filter(|pair| !pair.is_empty()) {
        if let Some((device, value)) = pair.rsplit_once('=') {
            restore_dword(HKEY_LOCAL_MACHINE, &msi_key(device), "MSISupported", Some(value))?;
        }
    }
    Ok(())
}

/// Line-based interrupts again. The card hides when MSI was already on without Vantix,
/// so this only runs if the journal entry was lost.
pub fn reset_msi() -> Result<()> {
    for device in msi_devices() {
        reg::set_dword(HKEY_LOCAL_MACHINE, &msi_key(&device), "MSISupported", 0)?;
    }
    Ok(())
}

// DirectX global settings: one string like "SwapEffectUpgradeEnable=1;VRROptimizeEnable=1;"
// shared by two tweaks, so each one only touches its own key.

const DX_KEY: &str = r"Software\Microsoft\DirectX\UserGpuPreferences";
const DX_VALUE: &str = "DirectXUserGlobalSettings";

fn dx_get(key: &str) -> Result<Option<String>> {
    let settings = reg::get_string(HKEY_CURRENT_USER, DX_KEY, DX_VALUE)?.unwrap_or_default();
    Ok(settings
        .split(';')
        .find_map(|pair| pair.split_once('=').filter(|(k, _)| *k == key).map(|(_, v)| v.into())))
}

fn dx_set(key: &str, value: Option<&str>) -> Result<()> {
    let settings = reg::get_string(HKEY_CURRENT_USER, DX_KEY, DX_VALUE)?.unwrap_or_default();
    let mut pairs: Vec<String> = settings
        .split(';')
        .filter(|pair| !pair.is_empty() && pair.split_once('=').is_none_or(|(k, _)| k != key))
        .map(String::from)
        .collect();
    if let Some(value) = value {
        pairs.push(format!("{key}={value}"));
    }
    if pairs.is_empty() {
        reg::delete_value(HKEY_CURRENT_USER, DX_KEY, DX_VALUE)
    } else {
        reg::set_string(HKEY_CURRENT_USER, DX_KEY, DX_VALUE, &format!("{};", pairs.join(";")))
    }
}

macro_rules! dx_tweak {
    ($read:ident, $apply:ident, $revert:ident, $reset:ident, $key:expr) => {
        pub fn $read() -> Result<bool> {
            Ok(dx_get($key)?.as_deref() == Some("1"))
        }
        pub fn $apply() -> Saved {
            let previous = dx_get($key)?;
            dx_set($key, Some("1"))?;
            Ok(Some(previous.unwrap_or("-".into())))
        }
        pub fn $revert(previous: Option<&str>) -> Result<()> {
            dx_set($key, previous.filter(|p| *p != "-"))
        }
        pub fn $reset() -> Result<()> {
            dx_set($key, Some("0"))
        }
    };
}

dx_tweak!(
    windowed_flip,
    enable_windowed_flip,
    restore_windowed_flip,
    reset_windowed_flip,
    "SwapEffectUpgradeEnable"
);
dx_tweak!(windowed_vrr, enable_windowed_vrr, restore_windowed_vrr, reset_windowed_vrr, "VRROptimizeEnable");

// Game Bar background recording: three values, all of them have to be off.

const DVR_VALUES: [(HKEY, &str, &str); 3] = [
    (HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\GameDVR", "AppCaptureEnabled"),
    (HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\GameDVR", "HistoricalCaptureEnabled"),
    (HKEY_CURRENT_USER, r"System\GameConfigStore", "GameDVR_Enabled"),
];

pub fn game_dvr_off() -> Result<bool> {
    for (root, path, name) in DVR_VALUES {
        if reg::get_dword(root, path, name)? != Some(0) {
            return Ok(false);
        }
    }
    Ok(true)
}

pub fn disable_game_dvr() -> Saved {
    let previous = DVR_VALUES
        .iter()
        .map(|&(root, path, name)| reg::get_dword(root, path, name).map(saved))
        .collect::<Result<Vec<_>>>()?;
    all_or_nothing(
        "Game DVR",
        DVR_VALUES.len(),
        |i| reg::set_dword(DVR_VALUES[i].0, DVR_VALUES[i].1, DVR_VALUES[i].2, 0),
        |i| restore_dword(DVR_VALUES[i].0, DVR_VALUES[i].1, DVR_VALUES[i].2, Some(&previous[i])),
    )?;
    Ok(Some(previous.join(",")))
}

/// Background recording on, which needs the other two on as well.
pub fn reset_game_dvr() -> Result<()> {
    for (root, path, name) in DVR_VALUES {
        reg::set_dword(root, path, name, 1)?;
    }
    Ok(())
}

pub fn restore_game_dvr(previous: Option<&str>) -> Result<()> {
    let values: Vec<&str> = previous.unwrap_or_default().split(',').collect();
    for (i, (root, path, name)) in DVR_VALUES.into_iter().enumerate() {
        restore_dword(root, path, name, values.get(i).copied())?;
    }
    Ok(())
}

// Missing means on: it's been the default since Windows 10 1903.
dword_tweak!(
    game_mode_on,
    enable_game_mode,
    restore_game_mode,
    reset_game_mode,
    HKEY_CURRENT_USER,
    r"Software\Microsoft\GameBar",
    "AutoGameModeEnabled",
    1,
    |value| value != Some(0),
    Some(0)
);
// 2 is on, 1 is off.
dword_tweak!(
    hags_on,
    enable_hags,
    restore_hags,
    reset_hags,
    HKEY_LOCAL_MACHINE,
    r"SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
    "HwSchMode",
    2,
    |value| value == Some(2),
    Some(1)
);
dword_tweak!(
    global_timer_on,
    enable_global_timer,
    restore_global_timer,
    reset_global_timer,
    HKEY_LOCAL_MACHINE,
    r"SYSTEM\CurrentControlSet\Control\Session Manager\kernel",
    "GlobalTimerResolutionRequests",
    1,
    |value| value == Some(1),
    None
);

/// The Windows build, as in 19045 for Windows 10 22H2. 0 when it can't be read, which
/// hides whatever needs a newer build.
pub fn windows_build() -> u32 {
    reg::get_string(HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber")
        .ok()
        .flatten()
        .and_then(|build| build.parse().ok())
        .unwrap_or(0)
}

/// Windows 11 is what started ignoring timer requests from hidden windows.
pub fn is_windows_11() -> bool {
    windows_build() >= 22000
}

/// "Variable refresh rate" in Graphics settings arrived in Windows 10 1903.
pub fn has_windowed_vrr() -> bool {
    windows_build() >= 18362
}

/// Hardware scheduling needs Windows 10 2004 and a GPU driver that offers it, the same
/// check Windows makes before showing the switch in Graphics settings.
pub fn has_hags() -> bool {
    use windows::Wdk::Graphics::Direct3D::{
        D3DKMT_ADAPTERINFO, D3DKMT_CLOSEADAPTER, D3DKMT_ENUMADAPTERS2, D3DKMT_QUERYADAPTERINFO,
        D3DKMT_WDDM_2_7_CAPS, D3DKMTCloseAdapter, D3DKMTEnumAdapters2, D3DKMTQueryAdapterInfo,
        KMTQAITYPE_WDDM_2_7_CAPS,
    };
    if windows_build() < 19041 {
        return false;
    }
    unsafe {
        let mut enumerate = D3DKMT_ENUMADAPTERS2::default();
        if D3DKMTEnumAdapters2(&mut enumerate).is_err() || enumerate.NumAdapters == 0 {
            return false;
        }
        let mut adapters = vec![D3DKMT_ADAPTERINFO::default(); enumerate.NumAdapters as usize];
        enumerate.pAdapters = adapters.as_mut_ptr();
        if D3DKMTEnumAdapters2(&mut enumerate).is_err() {
            return false;
        }
        let mut supported = false;
        for adapter in &adapters[..enumerate.NumAdapters as usize] {
            let mut caps = D3DKMT_WDDM_2_7_CAPS::default();
            let mut query = D3DKMT_QUERYADAPTERINFO {
                hAdapter: adapter.hAdapter,
                Type: KMTQAITYPE_WDDM_2_7_CAPS,
                pPrivateDriverData: (&raw mut caps).cast(),
                PrivateDriverDataSize: size_of::<D3DKMT_WDDM_2_7_CAPS>() as u32,
            };
            // Bit 0 is HwSchSupported.
            if D3DKMTQueryAdapterInfo(&mut query).is_ok() && caps.Anonymous.Value & 1 != 0 {
                supported = true;
            }
            let _ = D3DKMTCloseAdapter(&D3DKMT_CLOSEADAPTER { hAdapter: adapter.hAdapter });
        }
        supported
    }
}

// Mouse acceleration: the third SPI_GETMOUSE value is "Enhance pointer precision".

fn mouse() -> Result<[i32; 3]> {
    let mut values = [0i32; 3];
    unsafe { SystemParametersInfoW(SPI_GETMOUSE, 0, Some(values.as_mut_ptr().cast()), Default::default())? };
    Ok(values)
}

fn set_mouse(mut values: [i32; 3]) -> Result<()> {
    unsafe {
        SystemParametersInfoW(
            SPI_SETMOUSE,
            0,
            Some(values.as_mut_ptr().cast()),
            SPIF_UPDATEINIFILE | SPIF_SENDCHANGE,
        )
    }
}

pub fn mouse_acceleration_off() -> Result<bool> {
    Ok(mouse()?[2] == 0)
}

pub fn disable_mouse_acceleration() -> Saved {
    let previous = mouse()?;
    set_mouse([0, 0, 0])?;
    Ok(Some(previous.map(|v| v.to_string()).join(",")))
}

/// Windows' own default: thresholds 6 and 10, precision on.
pub fn reset_mouse_acceleration() -> Result<()> {
    set_mouse([6, 10, 1])
}

pub fn restore_mouse_acceleration(previous: Option<&str>) -> Result<()> {
    let values: Vec<i32> = previous.unwrap_or_default().split(',').filter_map(|v| v.parse().ok()).collect();
    match values[..] {
        [threshold1, threshold2, acceleration] => set_mouse([threshold1, threshold2, acceleration]),
        _ => reset_mouse_acceleration(),
    }
}

// Accessibility shortcuts: Shift five times (Sticky Keys), holding right Shift (Filter
// Keys) and holding Num Lock (Toggle Keys). The features stay; only the hotkeys go.

const HOTKEY_ACTIVE: u32 = 0x4;

struct Hotkeys {
    sticky: STICKYKEYS,
    filter: FILTERKEYS,
    toggle: TOGGLEKEYS,
}

fn hotkeys() -> Result<Hotkeys> {
    let mut keys = Hotkeys {
        sticky: STICKYKEYS { cbSize: size_of::<STICKYKEYS>() as u32, ..Default::default() },
        filter: FILTERKEYS { cbSize: size_of::<FILTERKEYS>() as u32, ..Default::default() },
        toggle: TOGGLEKEYS { cbSize: size_of::<TOGGLEKEYS>() as u32, ..Default::default() },
    };
    unsafe {
        SystemParametersInfoW(
            SPI_GETSTICKYKEYS,
            keys.sticky.cbSize,
            Some((&raw mut keys.sticky).cast()),
            Default::default(),
        )?;
        SystemParametersInfoW(
            SPI_GETFILTERKEYS,
            keys.filter.cbSize,
            Some((&raw mut keys.filter).cast()),
            Default::default(),
        )?;
        SystemParametersInfoW(
            SPI_GETTOGGLEKEYS,
            keys.toggle.cbSize,
            Some((&raw mut keys.toggle).cast()),
            Default::default(),
        )?;
    }
    Ok(keys)
}

fn set_hotkeys(mut keys: Hotkeys) -> Result<()> {
    let mut before = hotkeys()?;
    let set = |keys: &mut Hotkeys, i: usize| {
        let (action, size, value) = match i {
            0 => (SPI_SETSTICKYKEYS, keys.sticky.cbSize, (&raw mut keys.sticky).cast()),
            1 => (SPI_SETFILTERKEYS, keys.filter.cbSize, (&raw mut keys.filter).cast()),
            _ => (SPI_SETTOGGLEKEYS, keys.toggle.cbSize, (&raw mut keys.toggle).cast()),
        };
        unsafe { SystemParametersInfoW(action, size, Some(value), SPIF_UPDATEINIFILE | SPIF_SENDCHANGE) }
    };
    all_or_nothing("accessibility keys", 3, |i| set(&mut keys, i), |i| set(&mut before, i))
}

pub fn hotkeys_off() -> Result<bool> {
    let keys = hotkeys()?;
    Ok([keys.sticky.dwFlags.0, keys.filter.dwFlags, keys.toggle.dwFlags]
        .iter()
        .all(|f| f & HOTKEY_ACTIVE == 0))
}

pub fn disable_hotkeys() -> Saved {
    let mut keys = hotkeys()?;
    let previous = format!("{},{},{}", keys.sticky.dwFlags.0, keys.filter.dwFlags, keys.toggle.dwFlags);
    keys.sticky.dwFlags = STICKYKEYS_FLAGS(keys.sticky.dwFlags.0 & !HOTKEY_ACTIVE);
    keys.filter.dwFlags &= !HOTKEY_ACTIVE;
    keys.toggle.dwFlags &= !HOTKEY_ACTIVE;
    set_hotkeys(keys)?;
    Ok(Some(previous))
}

/// Only the hotkey bit goes back, so other accessibility changes made since stay.
pub fn restore_hotkeys(previous: Option<&str>) -> Result<()> {
    let flags: Vec<u32> = previous.unwrap_or_default().split(',').filter_map(|v| v.parse().ok()).collect();
    let was = |i: usize| flags.get(i).map_or(HOTKEY_ACTIVE, |f| f & HOTKEY_ACTIVE);
    let mut keys = hotkeys()?;
    keys.sticky.dwFlags = STICKYKEYS_FLAGS(keys.sticky.dwFlags.0 & !HOTKEY_ACTIVE | was(0));
    keys.filter.dwFlags = keys.filter.dwFlags & !HOTKEY_ACTIVE | was(1);
    keys.toggle.dwFlags = keys.toggle.dwFlags & !HOTKEY_ACTIVE | was(2);
    set_hotkeys(keys)
}

pub fn reset_hotkeys() -> Result<()> {
    let mut keys = hotkeys()?;
    keys.sticky.dwFlags = STICKYKEYS_FLAGS(keys.sticky.dwFlags.0 | HOTKEY_ACTIVE);
    keys.filter.dwFlags |= HOTKEY_ACTIVE;
    keys.toggle.dwFlags |= HOTKEY_ACTIVE;
    set_hotkeys(keys)
}

// Key repeat. Windows' own settings bottom out at a 250 ms delay and about 30 repeats a
// second. Filter Keys with no wait and no bounce time goes past both, and with those two
// at 0 it never delays or drops a key, which a Filter Keys left with other values does.

const SPI_GETKEYBOARDDELAY: u32 = 22;
const SPI_SETKEYBOARDDELAY: u32 = 23;
const SPI_GETKEYBOARDSPEED: u32 = 10;
const SPI_SETKEYBOARDSPEED: u32 = 11;

fn keyboard_repeat() -> Result<(u32, u32)> {
    let (mut delay, mut speed) = (0u32, 0u32);
    unsafe {
        SystemParametersInfoW(
            windows::Win32::UI::WindowsAndMessaging::SYSTEM_PARAMETERS_INFO_ACTION(SPI_GETKEYBOARDDELAY),
            0,
            Some((&raw mut delay).cast()),
            Default::default(),
        )?;
        SystemParametersInfoW(
            windows::Win32::UI::WindowsAndMessaging::SYSTEM_PARAMETERS_INFO_ACTION(SPI_GETKEYBOARDSPEED),
            0,
            Some((&raw mut speed).cast()),
            Default::default(),
        )?;
    }
    Ok((delay, speed))
}

/// Delay is 0 (250 ms) to 3 (1 s); speed is 0 (about 2.5 a second) to 31 (about 30).
fn set_keyboard_repeat(delay: u32, speed: u32) -> Result<()> {
    let before = keyboard_repeat()?;
    let set = |action: u32, value: u32| unsafe {
        SystemParametersInfoW(
            windows::Win32::UI::WindowsAndMessaging::SYSTEM_PARAMETERS_INFO_ACTION(action),
            value,
            None,
            SPIF_UPDATEINIFILE | SPIF_SENDCHANGE,
        )
    };
    all_or_nothing(
        "key repeat",
        2,
        |i| if i == 0 { set(SPI_SETKEYBOARDDELAY, delay) } else { set(SPI_SETKEYBOARDSPEED, speed) },
        |_| set(SPI_SETKEYBOARDDELAY, before.0),
    )
}

pub fn fast_repeat() -> Result<bool> {
    Ok(keyboard_repeat()? == (0, 31))
}

pub fn set_fast_repeat() -> Saved {
    let (delay, speed) = keyboard_repeat()?;
    set_keyboard_repeat(0, 31)?;
    Ok(Some(format!("{delay},{speed}")))
}

pub fn restore_repeat(previous: Option<&str>) -> Result<()> {
    let values: Vec<u32> = previous.unwrap_or_default().split(',').filter_map(|v| v.parse().ok()).collect();
    match values[..] {
        [delay, speed] => set_keyboard_repeat(delay, speed),
        _ => reset_repeat(),
    }
}

/// Windows' own default: the second delay step (500 ms) at full speed.
pub fn reset_repeat() -> Result<()> {
    set_keyboard_repeat(1, 31)
}

const FKF_FILTERKEYSON: u32 = 0x1;
const FKF_AVAILABLE: u32 = 0x2;
/// Repeats start after 150 ms and come every 10 ms, past the 250 ms and 33 ms that the
/// regular settings allow.
const GAME_FILTER: (u32, u32) = (150, 10);

fn filter_keys() -> Result<FILTERKEYS> {
    Ok(hotkeys()?.filter)
}

fn set_filter_keys(filter: FILTERKEYS) -> Result<()> {
    let mut keys = hotkeys()?;
    keys.filter = filter;
    set_hotkeys(keys)
}

pub fn game_filter_keys() -> Result<bool> {
    let f = filter_keys()?;
    Ok(f.dwFlags & FKF_FILTERKEYSON != 0
        && f.iWaitMSec == 0
        && f.iBounceMSec == 0
        && f.iDelayMSec > 0
        && f.iDelayMSec < 250
        && f.iRepeatMSec > 0
        && f.iRepeatMSec < 33)
}

pub fn set_game_filter_keys() -> Saved {
    let mut f = filter_keys()?;
    let previous =
        format!("{},{},{},{},{}", f.dwFlags, f.iWaitMSec, f.iDelayMSec, f.iRepeatMSec, f.iBounceMSec);
    f.dwFlags |= FKF_FILTERKEYSON | FKF_AVAILABLE;
    (f.iWaitMSec, f.iBounceMSec) = (0, 0);
    (f.iDelayMSec, f.iRepeatMSec) = GAME_FILTER;
    set_filter_keys(f)?;
    Ok(Some(previous))
}

pub fn restore_filter_keys(previous: Option<&str>) -> Result<()> {
    let values: Vec<u32> = previous.unwrap_or_default().split(',').filter_map(|v| v.parse().ok()).collect();
    let [flags, wait, delay, repeat, bounce] = values[..] else { return reset_filter_keys() };
    let mut f = filter_keys()?;
    // The hotkey bit belongs to the accessibility shortcuts tweak; leave it as it is now.
    f.dwFlags = flags & !HOTKEY_ACTIVE | f.dwFlags & HOTKEY_ACTIVE;
    (f.iWaitMSec, f.iDelayMSec, f.iRepeatMSec, f.iBounceMSec) = (wait, delay, repeat, bounce);
    set_filter_keys(f)
}

pub fn reset_filter_keys() -> Result<()> {
    let mut f = filter_keys()?;
    f.dwFlags &= !FKF_FILTERKEYSON;
    set_filter_keys(f)
}

// 8.3 names: NTFS gives every new file a second, DOS style name like PROGRA~1. 1 turns
// that off on every volume; 2, the default, leaves it to each volume.
dword_tweak!(
    short_names_off,
    disable_short_names,
    restore_short_names,
    reset_short_names,
    HKEY_LOCAL_MACHINE,
    r"SYSTEM\CurrentControlSet\Control\FileSystem",
    "NtfsDisable8dot3NameCreation",
    1,
    |value| value == Some(1),
    Some(2)
);

// Slow Keys (a key only counts after being held a while) and Bounce Keys (a key pressed
// again soon after is ignored) are the "ignore brief or repeated keystrokes" part of
// Filter Keys. While it's on, either one delays or drops presses.

pub fn filter_delay_off() -> Result<bool> {
    let f = filter_keys()?;
    Ok(f.dwFlags & FKF_FILTERKEYSON == 0 || f.iWaitMSec == 0 && f.iBounceMSec == 0)
}

pub const FILTER_DELAY_TWEAK: &str = "filter-keys-delay-off";

/// Only while one of them is set, or to undo.
pub fn shows_filter_delay() -> bool {
    crate::settings::in_journal(FILTER_DELAY_TWEAK)
        || !filter_delay_off().unwrap_or(true)
}

pub fn disable_filter_delay() -> Saved {
    let mut f = filter_keys()?;
    let previous = format!("{},{}", f.iWaitMSec, f.iBounceMSec);
    (f.iWaitMSec, f.iBounceMSec) = (0, 0);
    set_filter_keys(f)?;
    Ok(Some(previous))
}

pub fn restore_filter_delay(previous: Option<&str>) -> Result<()> {
    let values: Vec<u32> = previous.unwrap_or_default().split(',').filter_map(|v| v.parse().ok()).collect();
    let [wait, bounce] = values[..] else { return Ok(()) };
    let mut f = filter_keys()?;
    (f.iWaitMSec, f.iBounceMSec) = (wait, bounce);
    set_filter_keys(f)
}

/// Shown only while a delay is set, so a lost journal leaves no delay to put back.
pub fn reset_filter_delay() -> Result<()> {
    Ok(())
}

// Background.

// 2 is "Force Deny" for every Store app.
dword_tweak!(
    store_background_off,
    disable_store_background,
    restore_store_background,
    reset_store_background,
    HKEY_LOCAL_MACHINE,
    r"SOFTWARE\Policies\Microsoft\Windows\AppPrivacy",
    "LetAppsRunInBackground",
    2,
    |value| value == Some(2),
    None
);

// Telemetry: the policy sets the level (Home and Pro can't go below "Required", which 0
// means for them) and the Connected User Experiences service is what sends it.

const TELEMETRY_KEY: &str = r"SOFTWARE\Policies\Microsoft\Windows\DataCollection";
const DIAGTRACK_KEY: &str = r"SYSTEM\CurrentControlSet\Services\DiagTrack";
/// Service start types as `sc config` spells them, by their registry value.
const START_TYPES: [&str; 5] = ["boot", "system", "auto", "demand", "disabled"];

pub fn telemetry_off() -> Result<bool> {
    Ok(reg::get_dword(HKEY_LOCAL_MACHINE, TELEMETRY_KEY, "AllowTelemetry")? == Some(0)
        && reg::get_dword(HKEY_LOCAL_MACHINE, DIAGTRACK_KEY, "Start")? == Some(4))
}

pub fn disable_telemetry() -> Saved {
    let policy = reg::get_dword(HKEY_LOCAL_MACHINE, TELEMETRY_KEY, "AllowTelemetry")?;
    let start = reg::get_dword(HKEY_LOCAL_MACHINE, DIAGTRACK_KEY, "Start")?;
    all_or_nothing(
        "telemetry",
        2,
        |i| match i {
            0 => reg::set_dword(HKEY_LOCAL_MACHINE, TELEMETRY_KEY, "AllowTelemetry", 0),
            _ => run("sc.exe", &["config", "DiagTrack", "start=", "disabled"]).map(drop),
        },
        |_| restore_dword(HKEY_LOCAL_MACHINE, TELEMETRY_KEY, "AllowTelemetry", Some(&saved(policy))),
    )?;
    // Fails when it's already stopped, which is fine.
    let _ = run("sc.exe", &["stop", "DiagTrack"]);
    Ok(Some(format!("{},{}", saved(policy), saved(start))))
}

pub fn restore_telemetry(previous: Option<&str>) -> Result<()> {
    let (policy, start) = previous.unwrap_or_default().split_once(',').unwrap_or(("-", "2"));
    restore_dword(HKEY_LOCAL_MACHINE, TELEMETRY_KEY, "AllowTelemetry", Some(policy))?;
    let start = unsaved(start).unwrap_or(2) as usize;
    run("sc.exe", &["config", "DiagTrack", "start=", START_TYPES.get(start).copied().unwrap_or("auto")])?;
    if start == 2 {
        let _ = run("sc.exe", &["start", "DiagTrack"]);
    }
    Ok(())
}

pub fn reset_telemetry() -> Result<()> {
    restore_telemetry(Some("-,2"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_step_undoes_the_ones_before() {
        let log = std::cell::RefCell::new(Vec::new());
        let result = all_or_nothing(
            "test",
            4,
            |i| {
                log.borrow_mut().push(format!("do {i}"));
                if i == 2 { Err(windows::Win32::Foundation::E_FAIL.into()) } else { Ok(()) }
            },
            |i| {
                log.borrow_mut().push(format!("undo {i}"));
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(log.into_inner(), ["do 0", "do 1", "do 2", "undo 1", "undo 0"]);
        assert!(all_or_nothing("test", 3, |_| Ok(()), |_| panic!("nothing to undo")).is_ok());
    }

    /// Changes a few settings, one of them on the active power plan, and puts them back:
    /// `cargo test boost_round_trip -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn boost_round_trip() {
        type Toggle = (&'static str, fn() -> Result<bool>, fn() -> Saved, fn(Option<&str>) -> Result<()>);
        let toggles: [Toggle; 7] = [
            ("fast repeat", fast_repeat, set_fast_repeat, restore_repeat),
            ("game filter keys", game_filter_keys, set_game_filter_keys, restore_filter_keys),
            ("usb suspend", usb_suspend_off, disable_usb_suspend, restore_usb_suspend),
            ("windowed flip", windowed_flip, enable_windowed_flip, restore_windowed_flip),
            ("windowed vrr", windowed_vrr, enable_windowed_vrr, restore_windowed_vrr),
            ("game mode", game_mode_on, enable_game_mode, restore_game_mode),
            ("hotkeys", hotkeys_off, disable_hotkeys, restore_hotkeys),
        ];
        let dx_before = reg::get_string(HKEY_CURRENT_USER, DX_KEY, DX_VALUE).unwrap();
        for (name, read, apply, revert) in toggles {
            let before = read().unwrap();
            let previous = apply().unwrap();
            assert!(read().unwrap(), "{name} not applied");
            revert(previous.as_deref()).unwrap();
            assert_eq!(read().unwrap(), before, "{name} not restored");
            println!("{name}: {before} -> applied -> {before}, saved {previous:?}");
        }
        assert_eq!(reg::get_string(HKEY_CURRENT_USER, DX_KEY, DX_VALUE).unwrap(), dx_before);
    }

    /// Changes a setting on Balanced while another plan is active and puts it back:
    /// `cargo test inactive_plan_round_trip -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn inactive_plan_round_trip() {
        let active = active_scheme().unwrap();
        assert_ne!(active, BALANCED, "needs another plan active");
        let balanced = format!("{BALANCED:?}");
        let before = on_plan(Some(&balanced), || power(&SUB_PROCESSOR, &PROCTHROTTLEMIN)).unwrap();
        let active_before = power(&SUB_PROCESSOR, &PROCTHROTTLEMIN).unwrap();
        let previous = on_plan(Some(&balanced), set_full_clock).unwrap();
        assert_eq!(on_plan(Some(&balanced), || power(&SUB_PROCESSOR, &PROCTHROTTLEMIN)).unwrap(), 100);
        assert_eq!(active_scheme().unwrap(), active, "active plan switched");
        assert_eq!(power(&SUB_PROCESSOR, &PROCTHROTTLEMIN).unwrap(), active_before, "active plan touched");
        on_plan(Some(&balanced), || restore_full_clock(previous.as_deref())).unwrap();
        assert_eq!(on_plan(Some(&balanced), || power(&SUB_PROCESSOR, &PROCTHROTTLEMIN)).unwrap(), before);
        println!("balanced min processor: {before} -> 100 -> {before}, active plan untouched");
    }

    /// Switches to Ultimate Performance, prints what it sets and goes back:
    /// `cargo test ultimate_round_trip -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn ultimate_round_trip() {
        let before = active_scheme().unwrap();
        let previous = enable_ultimate().unwrap();
        assert!(ultimate_on().unwrap());
        for (name, subgroup, setting) in [
            ("core parking min", SUB_PROCESSOR, CPMINCORES),
            ("min processor", SUB_PROCESSOR, PROCTHROTTLEMIN),
            ("boost mode", SUB_PROCESSOR, PERFBOOSTMODE),
            ("pcie aspm", SUB_PCIEXPRESS, ASPM),
            ("usb suspend", SUB_USB, USB_SUSPEND),
        ] {
            println!("{name}: {}", power(&subgroup, &setting).unwrap());
        }
        restore_ultimate(previous.as_deref()).unwrap();
        assert_eq!(active_scheme().unwrap(), before);
        assert!(set_scheme(&VANTIX_ULTIMATE).is_err(), "copy not removed");
        println!("back to {before:?}");
    }
}

#[cfg(test)]
mod reset_tests {
    use super::*;

    /// Turns off two tweaks that are already on and applies them again:
    /// `cargo test boost_reset_round_trip -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn boost_reset_round_trip() {
        type Reset = (&'static str, fn() -> Result<bool>, fn() -> Result<()>, fn() -> Saved);
        let resets: [Reset; 2] = [
            ("game mode", game_mode_on, reset_game_mode, enable_game_mode),
            (
                "mouse acceleration",
                mouse_acceleration_off,
                reset_mouse_acceleration,
                disable_mouse_acceleration,
            ),
        ];
        for (name, read, reset, apply) in resets {
            if !read().unwrap() {
                println!("{name}: not on here, skipped");
                continue;
            }
            reset().unwrap();
            assert!(!read().unwrap(), "{name} still on after reset");
            apply().unwrap();
            assert!(read().unwrap(), "{name} not back on");
            println!("{name}: on -> off -> on");
        }
    }
}
