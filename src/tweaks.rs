//! System tweaks: what each one changes, how to read its real state and how to undo it.
//!
//! The catalog order is the order of the texts in ui/tweaks.slint. Every call here
//! blocks, some for minutes (CompactOS), so run them off the UI thread.

use std::os::windows::process::CommandExt;
use std::process::Command;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Globalization::{
    GetLocaleInfoEx, LOCALE_IDEFAULTCODEPAGE, LOCALE_NAME_SYSTEM_DEFAULT, LOCALE_RETURN_NUMBER,
    MULTI_BYTE_TO_WIDE_CHAR_FLAGS, MultiByteToWideChar,
};
use windows::Win32::Storage::FileSystem::WofIsExternalFile;
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, GetDriveTypeW, GetLogicalDrives, OPEN_EXISTING,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{
    DEVICE_SEEK_PENALTY_DESCRIPTOR, IOCTL_STORAGE_QUERY_PROPERTY, PropertyStandardQuery,
    STORAGE_PROPERTY_QUERY, StorageDeviceSeekPenaltyProperty,
};
use windows::Win32::System::SystemInformation::{GetSystemDirectoryW, GetTickCount64, GetWindowsDirectoryW};
use windows::core::{BOOL, Error, HSTRING, Result};

use crate::{boost, net, reg};

/// From WinBase.h; the windows crate only has it behind an unrelated feature.
const DRIVE_FIXED: u32 = 3;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Performance,
    Games,
    Internet,
    Input,
    Storage,
    Background,
}

/// Matches the Gain/Cost order in the UI.
#[derive(Clone, Copy)]
pub enum Level {
    None,
    Low,
    Medium,
    High,
}

pub enum Kind {
    /// An on/off change. `apply` returns whatever `revert` needs to put it back, as text.
    /// `reset` turns it off when it was already in place before Vantix: undoing that is
    /// just applying it again.
    Toggle {
        read: fn() -> Result<bool>,
        apply: fn() -> Result<Option<String>>,
        revert: fn(Option<&str>) -> Result<()>,
        reset: fn() -> Result<()>,
    },
    /// A one-off job with nothing to undo.
    Action { run: fn() -> Result<()> },
}

pub struct Tweak {
    pub id: &'static str,
    pub section: Section,
    pub gain: Level,
    pub cost: Level,
    pub reboot: bool,
    /// Hides the tweak on machines where it can't do anything.
    pub shown: fn() -> bool,
    /// Free space this would give back, when it can be known before applying.
    pub estimate: fn() -> Option<u64>,
    /// Takes minutes rather than seconds.
    pub slow: bool,
    /// A setting of the active power plan. Its changes stay with the plan they were made
    /// on, so switching plans neither undoes them nor loses track of them.
    pub on_plan: bool,
    pub kind: Kind,
}

pub const CATALOG: &[Tweak] = &[
    Tweak {
        id: "hibernation-off",
        section: Section::Storage,
        gain: Level::High,
        cost: Level::Medium,
        reboot: false,
        shown: always,
        estimate: hiberfil_size,
        slow: false,
        on_plan: false,
        kind: Kind::Toggle {
            read: hibernation_off,
            apply: disable_hibernation,
            revert: enable_hibernation,
            reset: reset_hibernation,
        },
    },
    Tweak {
        id: "reserved-storage-off",
        section: Section::Storage,
        gain: Level::Medium,
        cost: Level::Medium,
        reboot: false,
        shown: has_reserved_storage,
        estimate: none,
        slow: false,
        on_plan: false,
        kind: Kind::Toggle {
            read: reserved_storage_off,
            apply: disable_reserved_storage,
            revert: enable_reserved_storage,
            reset: reset_reserved_storage,
        },
    },
    Tweak {
        id: "compact-os",
        section: Section::Storage,
        gain: Level::Medium,
        cost: Level::Low,
        reboot: false,
        shown: always,
        estimate: none,
        slow: true,
        on_plan: false,
        kind: Kind::Toggle {
            read: compact_os_on,
            apply: enable_compact_os,
            revert: disable_compact_os,
            reset: reset_compact_os,
        },
    },
    Tweak {
        id: "last-access-off",
        section: Section::Storage,
        gain: Level::Low,
        cost: Level::Low,
        reboot: true,
        shown: always,
        estimate: none,
        slow: false,
        on_plan: false,
        kind: Kind::Toggle {
            read: last_access_off,
            apply: disable_last_access,
            revert: restore_last_access,
            reset: reset_last_access,
        },
    },
    Tweak {
        id: "retrim",
        section: Section::Storage,
        gain: Level::Low,
        cost: Level::None,
        reboot: false,
        shown: || !ssd_volumes().is_empty(),
        estimate: none,
        slow: false,
        on_plan: false,
        kind: Kind::Action { run: retrim },
    },
    Tweak {
        id: "ultimate-plan",
        section: Section::Performance,
        gain: Level::Medium,
        cost: Level::Medium,
        reboot: false,
        shown: boost::has_power_plans,
        estimate: none,
        slow: false,
        on_plan: false,
        kind: Kind::Toggle {
            read: boost::ultimate_on,
            apply: boost::enable_ultimate,
            revert: boost::restore_ultimate,
            reset: boost::reset_ultimate,
        },
    },
    Tweak {
        id: "core-parking-off",
        section: Section::Performance,
        gain: Level::Medium,
        cost: Level::Medium,
        reboot: false,
        shown: always,
        estimate: none,
        slow: false,
        on_plan: true,
        kind: Kind::Toggle {
            read: boost::core_parking_off,
            apply: boost::disable_core_parking,
            revert: boost::restore_core_parking,
            reset: boost::reset_core_parking,
        },
    },
    Tweak {
        id: "full-clock",
        section: Section::Performance,
        gain: Level::Low,
        cost: Level::Medium,
        reboot: false,
        shown: always,
        estimate: none,
        slow: false,
        on_plan: true,
        kind: Kind::Toggle {
            read: boost::full_clock,
            apply: boost::set_full_clock,
            revert: boost::restore_full_clock,
            reset: boost::reset_full_clock,
        },
    },
    Tweak {
        id: "boost-aggressive",
        section: Section::Performance,
        gain: Level::Low,
        cost: Level::Medium,
        reboot: false,
        shown: always,
        estimate: none,
        slow: false,
        on_plan: true,
        kind: Kind::Toggle {
            read: boost::boost_aggressive,
            apply: boost::set_boost_aggressive,
            revert: boost::restore_boost,
            reset: boost::reset_boost,
        },
    },
    Tweak {
        id: "pcie-aspm-off",
        section: Section::Performance,
        gain: Level::Low,
        cost: Level::Low,
        reboot: false,
        shown: always,
        estimate: none,
        slow: false,
        on_plan: true,
        kind: Kind::Toggle {
            read: boost::aspm_off,
            apply: boost::disable_aspm,
            revert: boost::restore_aspm,
            reset: boost::reset_aspm,
        },
    },
    Tweak {
        id: "usb-suspend-off",
        section: Section::Performance,
        gain: Level::Low,
        cost: Level::Low,
        reboot: false,
        shown: always,
        estimate: none,
        slow: false,
        on_plan: true,
        kind: Kind::Toggle {
            read: boost::usb_suspend_off,
            apply: boost::disable_usb_suspend,
            revert: boost::restore_usb_suspend,
            reset: boost::reset_usb_suspend,
        },
    },
    Tweak {
        id: "hvci-off",
        section: Section::Performance,
        gain: Level::High,
        cost: Level::High,
        reboot: true,
        shown: always,
        estimate: none,
        slow: false,
        on_plan: false,
        kind: Kind::Toggle {
            read: boost::hvci_off,
            apply: boost::disable_hvci,
            revert: boost::restore_hvci,
            reset: boost::reset_hvci,
        },
    },
    Tweak {
        id: "memory-compression-off",
        section: Section::Performance,
        gain: Level::Low,
        cost: Level::Medium,
        reboot: true,
        shown: boost::has_16_gb,
        estimate: none,
        slow: false,
        on_plan: false,
        kind: Kind::Toggle {
            read: boost::memory_compression_off,
            apply: boost::disable_memory_compression,
            revert: boost::enable_memory_compression,
            reset: boost::reset_memory_compression,
        },
    },
    Tweak {
        id: "msi-mode",
        section: Section::Performance,
        gain: Level::Low,
        cost: Level::Medium,
        reboot: true,
        shown: boost::shows_msi,
        estimate: none,
        slow: false,
        on_plan: false,
        kind: Kind::Toggle {
            read: boost::msi_on,
            apply: boost::enable_msi,
            revert: boost::restore_msi,
            reset: boost::reset_msi,
        },
    },
    Tweak {
        id: "windowed-flip",
        section: Section::Games,
        gain: Level::Medium,
        cost: Level::None,
        reboot: false,
        shown: always,
        estimate: none,
        slow: false,
        on_plan: false,
        kind: Kind::Toggle {
            read: boost::windowed_flip,
            apply: boost::enable_windowed_flip,
            revert: boost::restore_windowed_flip,
            reset: boost::reset_windowed_flip,
        },
    },
    Tweak {
        id: "windowed-vrr",
        section: Section::Games,
        gain: Level::Low,
        cost: Level::None,
        reboot: false,
        shown: always,
        estimate: none,
        slow: false,
        on_plan: false,
        kind: Kind::Toggle {
            read: boost::windowed_vrr,
            apply: boost::enable_windowed_vrr,
            revert: boost::restore_windowed_vrr,
            reset: boost::reset_windowed_vrr,
        },
    },
    Tweak {
        id: "game-dvr-off",
        section: Section::Games,
        gain: Level::Medium,
        cost: Level::None,
        reboot: false,
        shown: always,
        estimate: none,
        slow: false,
        on_plan: false,
        kind: Kind::Toggle {
            read: boost::game_dvr_off,
            apply: boost::disable_game_dvr,
            revert: boost::restore_game_dvr,
            reset: boost::reset_game_dvr,
        },
    },
    Tweak {
        id: "game-mode-on",
        section: Section::Games,
        gain: Level::Low,
        cost: Level::None,
        reboot: false,
        shown: always,
        estimate: none,
        slow: false,
        on_plan: false,
        kind: Kind::Toggle {
            read: boost::game_mode_on,
            apply: boost::enable_game_mode,
            revert: boost::restore_game_mode,
            reset: boost::reset_game_mode,
        },
    },
    Tweak {
        id: "hags-on",
        section: Section::Games,
        gain: Level::Low,
        cost: Level::Low,
        reboot: true,
        shown: always,
        estimate: none,
        slow: false,
        on_plan: false,
        kind: Kind::Toggle {
            read: boost::hags_on,
            apply: boost::enable_hags,
            revert: boost::restore_hags,
            reset: boost::reset_hags,
        },
    },
    Tweak {
        id: "global-timer",
        section: Section::Games,
        gain: Level::Low,
        cost: Level::Low,
        reboot: true,
        shown: boost::is_windows_11,
        estimate: none,
        slow: false,
        on_plan: false,
        kind: Kind::Toggle {
            read: boost::global_timer_on,
            apply: boost::enable_global_timer,
            revert: boost::restore_global_timer,
            reset: boost::reset_global_timer,
        },
    },
    Tweak {
        id: "mouse-acceleration-off",
        section: Section::Input,
        gain: Level::Medium,
        cost: Level::None,
        reboot: false,
        shown: always,
        estimate: none,
        slow: false,
        on_plan: false,
        kind: Kind::Toggle {
            read: boost::mouse_acceleration_off,
            apply: boost::disable_mouse_acceleration,
            revert: boost::restore_mouse_acceleration,
            reset: boost::reset_mouse_acceleration,
        },
    },
    Tweak {
        id: "accessibility-hotkeys-off",
        section: Section::Input,
        gain: Level::Low,
        cost: Level::None,
        reboot: false,
        shown: always,
        estimate: none,
        slow: false,
        on_plan: false,
        kind: Kind::Toggle {
            read: boost::hotkeys_off,
            apply: boost::disable_hotkeys,
            revert: boost::restore_hotkeys,
            reset: boost::reset_hotkeys,
        },
    },
    Tweak {
        id: "fast-key-repeat",
        section: Section::Input,
        gain: Level::Low,
        cost: Level::None,
        reboot: false,
        shown: always,
        estimate: none,
        slow: false,
        on_plan: false,
        kind: Kind::Toggle {
            read: boost::fast_repeat,
            apply: boost::set_fast_repeat,
            revert: boost::restore_repeat,
            reset: boost::reset_repeat,
        },
    },
    Tweak {
        id: "game-filter-keys",
        section: Section::Input,
        gain: Level::Medium,
        cost: Level::Low,
        reboot: false,
        shown: always,
        estimate: none,
        slow: false,
        on_plan: false,
        kind: Kind::Toggle {
            read: boost::game_filter_keys,
            apply: boost::set_game_filter_keys,
            revert: boost::restore_filter_keys,
            reset: boost::reset_filter_keys,
        },
    },
    Tweak {
        id: "store-background-off",
        section: Section::Background,
        gain: Level::Low,
        cost: Level::Low,
        reboot: false,
        shown: always,
        estimate: none,
        slow: false,
        on_plan: false,
        kind: Kind::Toggle {
            read: boost::store_background_off,
            apply: boost::disable_store_background,
            revert: boost::restore_store_background,
            reset: boost::reset_store_background,
        },
    },
    Tweak {
        id: "telemetry-off",
        section: Section::Background,
        gain: Level::Low,
        cost: Level::Low,
        reboot: false,
        shown: always,
        estimate: none,
        slow: false,
        on_plan: false,
        kind: Kind::Toggle {
            read: boost::telemetry_off,
            apply: boost::disable_telemetry,
            revert: boost::restore_telemetry,
            reset: boost::reset_telemetry,
        },
    },
    Tweak {
        id: "flush-dns",
        section: Section::Internet,
        gain: Level::Low,
        cost: Level::None,
        reboot: false,
        shown: always,
        estimate: none,
        slow: false,
        on_plan: false,
        kind: Kind::Action { run: net::flush_dns },
    },
    Tweak {
        id: "renew-ip",
        section: Section::Internet,
        gain: Level::Low,
        cost: Level::Low,
        reboot: false,
        shown: net::uses_dhcp,
        estimate: none,
        slow: false,
        on_plan: false,
        kind: Kind::Action { run: net::renew_ip },
    },
    Tweak {
        id: "reset-network",
        section: Section::Internet,
        gain: Level::Medium,
        cost: Level::Medium,
        reboot: true,
        shown: always,
        estimate: none,
        slow: false,
        on_plan: false,
        kind: Kind::Action { run: net::reset_stack },
    },
];

fn always() -> bool {
    true
}

fn none() -> Option<u64> {
    None
}

/// Boot time in Unix seconds. Two reads in the same boot can differ by a second.
pub fn boot_time() -> i64 {
    chrono::Local::now().timestamp() - unsafe { GetTickCount64() } as i64 / 1000
}

/// Whether a change made in the boot that started at `boot` still waits for a restart.
pub fn same_boot(boot: i64) -> bool {
    (boot_time() - boot).abs() < 60
}

pub fn restart() -> Result<()> {
    run("shutdown.exe", &["/r", "/t", "0"]).map(drop)
}

/// Full path of a tool in System32. A bare name would also be looked up next to our own
/// exe first, and we run elevated.
pub fn system_tool(name: &str) -> std::path::PathBuf {
    let mut buffer = [0u16; 260];
    let len = unsafe { GetSystemDirectoryW(Some(&mut buffer)) } as usize;
    std::path::PathBuf::from(String::from_utf16_lossy(&buffer[..len.min(buffer.len())])).join(name)
}

fn windows_dir() -> String {
    let mut buffer = [0u16; 260];
    let len = unsafe { GetWindowsDirectoryW(Some(&mut buffer)) } as usize;
    String::from_utf16_lossy(&buffer[..len.min(buffer.len())])
}

/// Runs a console tool from System32 without flashing a console window. Fails on a
/// non-zero exit, with whatever the tool printed as the reason.
pub fn run(program: &str, args: &[&str]) -> Result<String> {
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let output = Command::new(system_tool(program)).args(args).creation_flags(CREATE_NO_WINDOW).output()?;
    let text = decode(&output.stdout);
    if output.status.success() {
        return Ok(text);
    }
    let stderr = decode(&output.stderr);
    let reason = if stderr.trim().is_empty() { text.trim() } else { stderr.trim() };
    let code = output.status.code().unwrap_or(-1);
    let name = program.rsplit('\\').next().unwrap_or(program);
    Err(Error::new(windows::Win32::Foundation::E_FAIL, format!("{name} ({code}): {reason}")))
}

/// Console tools write in the OEM code page and PowerShell is told to write UTF-8. OEM
/// text with accents is practically never valid UTF-8, so that tells them apart.
fn decode(bytes: &[u8]) -> String {
    if let Ok(text) = std::str::from_utf8(bytes) {
        return text.to_string();
    }
    unsafe {
        // Our manifest makes CP_OEMCP mean UTF-8 inside this process, so ask the system
        // locale for the code page the tools actually use (850 on pt-BR Windows).
        let mut number = [0u16; 2];
        let code_page = match GetLocaleInfoEx(
            LOCALE_NAME_SYSTEM_DEFAULT,
            LOCALE_IDEFAULTCODEPAGE | LOCALE_RETURN_NUMBER,
            Some(&mut number),
        ) {
            2 => u32::from(number[0]) | u32::from(number[1]) << 16,
            _ => 437,
        };
        let len = MultiByteToWideChar(code_page, MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0), bytes, None);
        let mut wide = vec![0u16; len.max(0) as usize];
        let len = MultiByteToWideChar(code_page, MULTI_BYTE_TO_WIDE_CHAR_FLAGS(0), bytes, Some(&mut wide));
        String::from_utf16_lossy(&wide[..len.max(0) as usize])
    }
}

/// For the cmdlets that have no console tool equivalent. Errors come back as just the
/// message instead of PowerShell's multi-line error record.
pub fn powershell(script: &str) -> Result<String> {
    let script = format!(
        "[Console]::OutputEncoding = [Text.Encoding]::UTF8; \
         try {{ {script} }} catch {{ [Console]::Error.WriteLine($_.Exception.Message); exit 1 }}"
    );
    run(r"WindowsPowerShell\v1.0\powershell.exe", &["-NoProfile", "-NonInteractive", "-Command", &script])
        .map(|out| out.trim().to_string())
}

fn system_drive() -> String {
    std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into())
}

// Hibernation. The hiberfil.sys is sized from RAM, so on most PCs it's the biggest
// single file Windows keeps. Fast Startup is built on it and goes away too.

const POWER_KEY: &str = r"SYSTEM\CurrentControlSet\Control\Power";

fn hibernation_off() -> Result<bool> {
    Ok(reg::get_dword(reg::HKEY_LOCAL_MACHINE, POWER_KEY, "HibernateEnabled")? == Some(0))
}

fn hiberfil_size() -> Option<u64> {
    std::fs::metadata(format!("{}\\hiberfil.sys", system_drive()))
        .ok()
        .map(|m| m.len())
        .filter(|&len| len > 0)
}

fn disable_hibernation() -> Result<Option<String>> {
    run("powercfg.exe", &["/hibernate", "off"]).map(|_| None)
}

fn enable_hibernation(_: Option<&str>) -> Result<()> {
    run("powercfg.exe", &["/hibernate", "on"]).map(drop)
}

fn reset_hibernation() -> Result<()> {
    enable_hibernation(None)
}

// Reserved storage: about 7 GB Windows keeps aside so updates still install on a full disk.

fn has_reserved_storage() -> bool {
    reg::get_dword(
        reg::HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager",
        "ShippedWithReserves",
    )
    .is_ok_and(|value| value.is_some())
}

fn reserved_storage_off() -> Result<bool> {
    match powershell("(Get-WindowsReservedStorageState -ErrorAction Stop).ReservedStorageState")?.as_str() {
        "Enabled" => Ok(false),
        "Disabled" => Ok(true),
        other => {
            Err(Error::new(windows::Win32::Foundation::E_UNEXPECTED, format!("reserved storage: {other}")))
        }
    }
}

fn disable_reserved_storage() -> Result<Option<String>> {
    powershell("Set-WindowsReservedStorageState -State Disabled -ErrorAction Stop").map(|_| None)
}

fn enable_reserved_storage(_: Option<&str>) -> Result<()> {
    powershell("Set-WindowsReservedStorageState -State Enabled -ErrorAction Stop").map(drop)
}

fn reset_reserved_storage() -> Result<()> {
    enable_reserved_storage(None)
}

// CompactOS: system binaries stored compressed through WOF. `compact /compactos:query`
// only reports in the UI language, so the state is read from the files themselves.

fn compact_os_on() -> Result<bool> {
    let windows = windows_dir();
    let probes = ["explorer.exe", r"System32\notepad.exe", r"System32\cmd.exe", r"System32\taskmgr.exe"];
    let compressed = probes
        .iter()
        .filter(|probe| {
            let mut external = BOOL(0);
            let path = HSTRING::from(format!("{windows}\\{probe}"));
            unsafe { WofIsExternalFile(&path, Some(&mut external), None, None, None) }.is_ok()
                && external.as_bool()
        })
        .count();
    Ok(compressed * 2 > probes.len())
}

// compact's exit code isn't a reliable success flag here, so the files have the last word.

fn enable_compact_os() -> Result<Option<String>> {
    match run("compact.exe", &["/compactos:always"]) {
        Err(e) if !compact_os_on().unwrap_or(false) => Err(e),
        _ => Ok(None),
    }
}

fn disable_compact_os(_: Option<&str>) -> Result<()> {
    match run("compact.exe", &["/compactos:never"]) {
        Err(e) if compact_os_on().unwrap_or(true) => Err(e),
        _ => Ok(()),
    }
}

fn reset_compact_os() -> Result<()> {
    disable_compact_os(None)
}

// NTFS last access time. fsutil reports 0/1 as user managed and 2/3 as system managed;
// the low bit set means updates are off.

const FS_KEY: &str = r"SYSTEM\CurrentControlSet\Control\FileSystem";
const LAST_ACCESS: &str = "NtfsDisableLastAccessUpdate";

fn last_access_off() -> Result<bool> {
    Ok(reg::get_dword(reg::HKEY_LOCAL_MACHINE, FS_KEY, LAST_ACCESS)?.is_some_and(|value| value & 1 == 1))
}

fn disable_last_access() -> Result<Option<String>> {
    let previous = reg::get_dword(reg::HKEY_LOCAL_MACHINE, FS_KEY, LAST_ACCESS)?;
    run("fsutil.exe", &["behavior", "set", "disablelastaccess", "1"])?;
    Ok(previous.map(|value| value.to_string()))
}

/// Windows' default: system managed, updates on.
fn reset_last_access() -> Result<()> {
    reg::set_dword(reg::HKEY_LOCAL_MACHINE, FS_KEY, LAST_ACCESS, 0x8000_0002)
}

fn restore_last_access(previous: Option<&str>) -> Result<()> {
    match previous.and_then(|text| text.parse().ok()) {
        Some(value) => reg::set_dword(reg::HKEY_LOCAL_MACHINE, FS_KEY, LAST_ACCESS, value),
        None => reg::delete_value(reg::HKEY_LOCAL_MACHINE, FS_KEY, LAST_ACCESS),
    }
}

// Retrim. Windows does this weekly on its own; running it by hand only helps when that
// schedule is off or after deleting a lot of data.

fn retrim() -> Result<()> {
    let volumes = ssd_volumes();
    let mut args: Vec<&str> = volumes.iter().map(String::as_str).collect();
    args.push("/L");
    run("defrag.exe", &args).map(drop)
}

/// Fixed drives without a seek penalty, as `C:`.
fn ssd_volumes() -> Vec<String> {
    let mask = unsafe { GetLogicalDrives() };
    (0..26u8)
        .filter(|bit| mask & (1 << bit) != 0)
        .map(|bit| format!("{}:", (b'A' + bit) as char))
        .filter(|drive| unsafe { GetDriveTypeW(&HSTRING::from(format!("{drive}\\"))) } == DRIVE_FIXED)
        .filter(|drive| seek_penalty(drive) == Some(false))
        .collect()
}

fn seek_penalty(drive: &str) -> Option<bool> {
    unsafe {
        // No access rights needed for a property query, so this works on any volume.
        let device = CreateFileW(
            &HSTRING::from(format!(r"\\.\{drive}")),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            Default::default(),
            None,
        )
        .ok()?;
        let query = STORAGE_PROPERTY_QUERY {
            PropertyId: StorageDeviceSeekPenaltyProperty,
            QueryType: PropertyStandardQuery,
            ..Default::default()
        };
        let mut answer = DEVICE_SEEK_PENALTY_DESCRIPTOR::default();
        let mut returned = 0;
        let result = DeviceIoControl(
            device,
            IOCTL_STORAGE_QUERY_PROPERTY,
            Some((&raw const query).cast()),
            size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            Some((&raw mut answer).cast()),
            size_of::<DEVICE_SEEK_PENALTY_DESCRIPTOR>() as u32,
            Some(&mut returned),
            None,
        );
        let _ = CloseHandle(device);
        result.ok().map(|_| answer.IncursSeekPenalty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read-only: `cargo test tweaks_read -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn tweaks_read() {
        for tweak in CATALOG {
            let state = match &tweak.kind {
                Kind::Toggle { read, .. } => format!("{:?}", read().map_err(|e| e.message())),
                Kind::Action { .. } => "action".into(),
            };
            println!("{:<22} shown={} estimate={:?} {state}", tweak.id, (tweak.shown)(), (tweak.estimate)());
        }
        println!("ssd volumes: {:?}", ssd_volumes());
    }

    /// Changes a registry value and puts it back: `cargo test last_access_round_trip -- --ignored`
    #[test]
    #[ignore]
    fn last_access_round_trip() {
        let original = reg::get_dword(reg::HKEY_LOCAL_MACHINE, FS_KEY, LAST_ACCESS).unwrap();
        let was_off = last_access_off().unwrap();
        let previous = disable_last_access().unwrap();
        assert_eq!(previous, original.map(|v| v.to_string()));
        assert!(last_access_off().unwrap());
        restore_last_access(previous.as_deref()).unwrap();
        assert_eq!(reg::get_dword(reg::HKEY_LOCAL_MACHINE, FS_KEY, LAST_ACCESS).unwrap(), original);
        assert_eq!(last_access_off().unwrap(), was_off);
    }
}
