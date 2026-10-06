//! System Restore: status, listing and creating restore points.
//!
//! Blocking calls; run them off the UI thread. Creating a point takes anywhere from a few
//! seconds to a couple of minutes depending on the volume shadow copy.

use chrono::{DateTime, Local, NaiveDateTime, TimeZone, Utc};
use windows::Win32::Foundation::WIN32_ERROR;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx, CoSetProxyBlanket,
    EOAC_NONE, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
};
use windows::Win32::System::Restore::{
    BEGIN_SYSTEM_CHANGE, END_SYSTEM_CHANGE, MODIFY_SETTINGS, RESTOREPOINTINFOW, SRSetRestorePointW,
    STATEMGRSTATUS,
};
use windows::Win32::System::Rpc::{RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE};
use windows::Win32::System::Variant::{VARIANT, VT_BSTR, VT_I4, VariantClear};
use windows::Win32::System::Wmi::{
    IWbemClassObject, IWbemLocator, IWbemServices, WBEM_FLAG_FORWARD_ONLY, WBEM_FLAG_RETURN_IMMEDIATELY,
    WBEM_INFINITE, WbemLocator,
};
use windows::core::{BSTR, Error, HSTRING, IUnknown, Param, Result, w};

use crate::reg;

const SR_KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore";
/// Windows ignores a new point if another was made in the last 24 h unless this is 0.
const FREQUENCY: &str = "SystemRestorePointCreationFrequency";
/// System Restore's own client id in the Software Protection Platform; its value lists
/// the protected volumes.
const SPP_CLIENTS: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SPP\Clients";
const SR_CLIENT: &str = "{09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}";

#[derive(Clone, Debug)]
pub struct Point {
    pub sequence: u32,
    pub description: String,
    pub created: Option<DateTime<Local>>,
}

fn system_drive() -> String {
    std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into())
}

/// Whether System Restore protects the Windows drive.
pub fn protection_enabled() -> bool {
    // Entries look like `\\?\Volume{...}\:(C%3A)`.
    let marker = format!("({}%3A)", system_drive().trim_end_matches(':'));
    reg::get_multi_string(reg::HKEY_LOCAL_MACHINE, SPP_CLIENTS, SR_CLIENT)
        .is_ok_and(|volumes| volumes.iter().any(|v| v.contains(&marker)))
}

pub fn enable_protection() -> Result<()> {
    let wmi = connect()?;
    unsafe {
        let mut class = None;
        wmi.GetObject(&BSTR::from("SystemRestore"), Default::default(), None, Some(&mut class), None)?;
        let class = class.ok_or_else(Error::empty)?;
        let mut input = None;
        class.GetMethod(w!("Enable"), 0, &mut input, std::ptr::null_mut())?;
        let input = input.ok_or_else(Error::empty)?.SpawnInstance(0)?;
        let mut drive = bstr_variant(&format!("{}\\", system_drive()));
        input.Put(w!("Drive"), 0, &drive, 0)?;
        let _ = VariantClear(&mut drive);

        let mut output = None;
        wmi.ExecMethod(
            &BSTR::from("SystemRestore"),
            &BSTR::from("Enable"),
            Default::default(),
            None,
            &input,
            Some(&mut output),
            None,
        )?;
        match output.and_then(|out| get_u32(&out, "ReturnValue")) {
            Some(0) | None => Ok(()),
            Some(code) => Err(WIN32_ERROR(code).into()),
        }
    }
}

/// Newest first.
pub fn list() -> Result<Vec<Point>> {
    let wmi = connect()?;
    let mut points = Vec::new();
    unsafe {
        let rows = wmi.ExecQuery(
            &BSTR::from("WQL"),
            &BSTR::from("SELECT SequenceNumber, Description, CreationTime FROM SystemRestore"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            None,
        )?;
        impersonate(&rows)?;
        loop {
            let mut row = [None];
            let mut returned = 0;
            let _ = rows.Next(WBEM_INFINITE, &mut row, &mut returned);
            let Some(row) = row[0].take().filter(|_| returned == 1) else { break };
            points.push(Point {
                sequence: get_u32(&row, "SequenceNumber").unwrap_or(0),
                description: get_string(&row, "Description").unwrap_or_default(),
                created: get_string(&row, "CreationTime").and_then(|time| parse_wmi_time(&time)),
            });
        }
    }
    points.sort_by_key(|point| std::cmp::Reverse(point.sequence));
    Ok(points)
}

/// Creates a point and returns its sequence number.
pub fn create(description: &str) -> Result<u32> {
    let previous = reg::get_dword(reg::HKEY_LOCAL_MACHINE, SR_KEY, FREQUENCY)?;
    reg::set_dword(reg::HKEY_LOCAL_MACHINE, SR_KEY, FREQUENCY, 0)?;
    let result = set_point(description);
    let _ = match previous {
        Some(value) => reg::set_dword(reg::HKEY_LOCAL_MACHINE, SR_KEY, FREQUENCY, value),
        None => reg::delete_value(reg::HKEY_LOCAL_MACHINE, SR_KEY, FREQUENCY),
    };
    result
}

fn set_point(description: &str) -> Result<u32> {
    // The description is capped at 255 characters plus the terminator. The struct is
    // packed, so the text is built separately and copied in whole.
    let mut text = [0u16; 256];
    for (slot, unit) in text.iter_mut().zip(description.encode_utf16().take(255)) {
        *slot = unit;
    }
    let mut info = RESTOREPOINTINFOW {
        dwEventType: BEGIN_SYSTEM_CHANGE,
        dwRestorePtType: MODIFY_SETTINGS,
        llSequenceNumber: 0,
        szDescription: text,
    };

    let mut status = STATEMGRSTATUS::default();
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        if !SRSetRestorePointW(&info, &mut status).as_bool() {
            return Err(WIN32_ERROR(status.nStatus.0).into());
        }
        info.dwEventType = END_SYSTEM_CHANGE;
        info.llSequenceNumber = status.llSequenceNumber;
        let sequence = status.llSequenceNumber as u32;
        if !SRSetRestorePointW(&info, &mut status).as_bool() {
            return Err(WIN32_ERROR(status.nStatus.0).into());
        }
        Ok(sequence)
    }
}

fn connect() -> Result<IWbemServices> {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
        let locator: IWbemLocator = CoCreateInstance(&WbemLocator, None, CLSCTX_INPROC_SERVER)?;
        let none = BSTR::new();
        let wmi = locator.ConnectServer(&BSTR::from(r"ROOT\DEFAULT"), &none, &none, &none, 0, &none, None)?;
        impersonate(&wmi)?;
        Ok(wmi)
    }
}

/// WMI refuses System Restore calls (WBEM_E_ACCESS_DENIED) unless the proxy impersonates.
fn impersonate(proxy: impl Param<IUnknown>) -> Result<()> {
    unsafe {
        CoSetProxyBlanket(
            proxy,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            None,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
        )
    }
}

fn bstr_variant(text: &str) -> VARIANT {
    let mut variant = VARIANT::default();
    unsafe {
        let inner = &mut *variant.Anonymous.Anonymous;
        inner.vt = VT_BSTR;
        inner.Anonymous.bstrVal = std::mem::ManuallyDrop::new(BSTR::from(text));
    }
    variant
}

fn get_string(object: &IWbemClassObject, name: &str) -> Option<String> {
    read(object, name, |inner| (inner.vt == VT_BSTR).then(|| unsafe { inner.Anonymous.bstrVal.to_string() }))
}

fn get_u32(object: &IWbemClassObject, name: &str) -> Option<u32> {
    read(object, name, |inner| (inner.vt == VT_I4).then_some(unsafe { inner.Anonymous.lVal } as u32))
}

fn read<T>(
    object: &IWbemClassObject,
    name: &str,
    f: impl FnOnce(&windows::Win32::System::Variant::VARIANT_0_0) -> Option<T>,
) -> Option<T> {
    let mut variant = VARIANT::default();
    unsafe {
        object.Get(&HSTRING::from(name), 0, &mut variant, None, None).ok()?;
        let value = f(&variant.Anonymous.Anonymous);
        let _ = VariantClear(&mut variant);
        value
    }
}

/// WMI datetimes look like `20261005022241.062216-000`, in UTC with an offset in minutes.
fn parse_wmi_time(text: &str) -> Option<DateTime<Local>> {
    let naive = NaiveDateTime::parse_from_str(text.get(..14)?, "%Y%m%d%H%M%S").ok()?;
    Some(Utc.from_utc_datetime(&naive).with_timezone(&Local))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_wmi_time() {
        let time = parse_wmi_time("20261005022241.062216-000").unwrap();
        assert_eq!(time.with_timezone(&Utc).format("%Y-%m-%d %H:%M:%S").to_string(), "2026-10-05 02:22:41");
    }

    /// Creates a real restore point: `cargo test restore_create -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn restore_create() {
        let before = reg::get_dword(reg::HKEY_LOCAL_MACHINE, SR_KEY, FREQUENCY).unwrap();
        let started = std::time::Instant::now();
        let sequence = create("Vantix test").unwrap();
        println!("created #{sequence} in {:?}", started.elapsed());
        // WMI can lag a moment behind the new point.
        let listed = (0..10).any(|_| {
            std::thread::sleep(std::time::Duration::from_millis(500));
            list().unwrap().iter().any(|p| p.sequence == sequence && p.description == "Vantix test")
        });
        assert!(listed);
        assert_eq!(reg::get_dword(reg::HKEY_LOCAL_MACHINE, SR_KEY, FREQUENCY).unwrap(), before);
    }

    /// Read-only: `cargo test restore_list -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn restore_list() {
        println!("protected: {}", protection_enabled());
        for point in list().unwrap() {
            println!("{} {:?} {}", point.sequence, point.created, point.description);
        }
    }
}
