//! Thin wrappers over the registry API, enough for the values Vantix touches.

use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Registry::{
    HKEY, KEY_READ, KEY_WRITE, REG_BINARY, REG_DWORD, REG_EXPAND_SZ, REG_OPTION_NON_VOLATILE, REG_SZ,
    REG_VALUE_TYPE, RRF_RT_REG_BINARY, RRF_RT_REG_DWORD, RRF_RT_REG_MULTI_SZ, RRF_RT_REG_SZ,
    RegCloseKey, RegCreateKeyExW, RegDeleteKeyValueW, RegDeleteTreeW, RegEnumKeyExW, RegEnumValueW,
    RegGetValueW, RegOpenKeyExW, RegSetValueExW,
};
use windows::core::{HSTRING, Result};

pub use windows::Win32::System::Registry::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

pub fn set_string(root: HKEY, path: &str, name: &str, value: &str) -> Result<()> {
    let data: Vec<u8> = value.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect();
    set(root, path, name, REG_SZ, &data)
}

pub fn set_dword(root: HKEY, path: &str, name: &str, value: u32) -> Result<()> {
    set(root, path, name, REG_DWORD, &value.to_le_bytes())
}

/// `None` when the value doesn't exist.
pub fn get_dword(root: HKEY, path: &str, name: &str) -> Result<Option<u32>> {
    let mut value = 0u32;
    let mut size = 4u32;
    let status = unsafe {
        RegGetValueW(
            root,
            &HSTRING::from(path),
            &HSTRING::from(name),
            RRF_RT_REG_DWORD,
            None,
            Some((&raw mut value).cast()),
            Some(&mut size),
        )
    };
    missing_is_none(status).map(|found| found.then_some(value))
}

/// `None` when the value doesn't exist.
pub fn get_string(root: HKEY, path: &str, name: &str) -> Result<Option<String>> {
    let (path, name) = (HSTRING::from(path), HSTRING::from(name));
    let mut size = 0u32;
    let status = unsafe { RegGetValueW(root, &path, &name, RRF_RT_REG_SZ, None, None, Some(&mut size)) };
    if !missing_is_none(status)? {
        return Ok(None);
    }
    let mut buffer = vec![0u16; size as usize / 2];
    unsafe {
        RegGetValueW(
            root,
            &path,
            &name,
            RRF_RT_REG_SZ,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&mut size),
        )
        .ok()?;
    }
    let text = String::from_utf16_lossy(&buffer[..(size as usize / 2).min(buffer.len())]);
    Ok(Some(text.trim_end_matches(char::from(0)).to_string()))
}

/// Every string of a REG_MULTI_SZ value, empty when the value doesn't exist.
pub fn get_multi_string(root: HKEY, path: &str, name: &str) -> Result<Vec<String>> {
    let (path, name) = (HSTRING::from(path), HSTRING::from(name));
    let mut size = 0u32;
    let status =
        unsafe { RegGetValueW(root, &path, &name, RRF_RT_REG_MULTI_SZ, None, None, Some(&mut size)) };
    if !missing_is_none(status)? {
        return Ok(Vec::new());
    }
    let mut buffer = vec![0u16; size as usize / 2];
    unsafe {
        RegGetValueW(
            root,
            &path,
            &name,
            RRF_RT_REG_MULTI_SZ,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&mut size),
        )
        .ok()?;
    }
    Ok(buffer.split(|&c| c == 0).filter(|s| !s.is_empty()).map(String::from_utf16_lossy).collect())
}

/// `None` when the value doesn't exist.
pub fn get_binary(root: HKEY, path: &str, name: &str) -> Result<Option<Vec<u8>>> {
    let (path, name) = (HSTRING::from(path), HSTRING::from(name));
    let mut size = 0u32;
    let status = unsafe { RegGetValueW(root, &path, &name, RRF_RT_REG_BINARY, None, None, Some(&mut size)) };
    if !missing_is_none(status)? {
        return Ok(None);
    }
    let mut buffer = vec![0u8; size as usize];
    unsafe {
        RegGetValueW(
            root,
            &path,
            &name,
            RRF_RT_REG_BINARY,
            None,
            Some(buffer.as_mut_ptr().cast()),
            Some(&mut size),
        )
        .ok()?;
    }
    buffer.truncate(size as usize);
    Ok(Some(buffer))
}

pub fn set_binary(root: HKEY, path: &str, name: &str, value: &[u8]) -> Result<()> {
    set(root, path, name, REG_BINARY, value)
}

/// Name and text of every REG_SZ and REG_EXPAND_SZ value in a key, expanded. Empty when
/// the key doesn't exist.
pub fn string_values(root: HKEY, path: &str) -> Result<Vec<(String, String)>> {
    let mut key = HKEY::default();
    let status = unsafe { RegOpenKeyExW(root, &HSTRING::from(path), None, KEY_READ, &mut key) };
    if !missing_is_none(status)? {
        return Ok(Vec::new());
    }
    let mut values = Vec::new();
    for index in 0.. {
        let mut name = [0u16; 16384];
        let mut name_len = name.len() as u32;
        let mut kind = 0u32;
        let status = unsafe {
            RegEnumValueW(
                key,
                index,
                Some(windows::core::PWSTR(name.as_mut_ptr())),
                &mut name_len,
                None,
                Some(&raw mut kind),
                None,
                None,
            )
        };
        if status.is_err() {
            break;
        }
        if kind != REG_SZ.0 && kind != REG_EXPAND_SZ.0 {
            continue;
        }
        let name = String::from_utf16_lossy(&name[..name_len as usize]);
        if let Ok(Some(text)) = get_string_raw(key, &name) {
            values.push((name, text));
        }
    }
    unsafe {
        let _ = RegCloseKey(key);
    }
    Ok(values)
}

/// Names of the keys directly under a key. Empty when the key doesn't exist.
pub fn subkeys(root: HKEY, path: &str) -> Vec<String> {
    let mut key = HKEY::default();
    if unsafe { RegOpenKeyExW(root, &HSTRING::from(path), None, KEY_READ, &mut key) }.is_err() {
        return Vec::new();
    }
    let mut names = Vec::new();
    for index in 0.. {
        let mut name = [0u16; 256];
        let mut name_len = name.len() as u32;
        let name_ptr = Some(windows::core::PWSTR(name.as_mut_ptr()));
        let status = unsafe { RegEnumKeyExW(key, index, name_ptr, &mut name_len, None, None, None, None) };
        if status.is_err() {
            break;
        }
        names.push(String::from_utf16_lossy(&name[..name_len as usize]));
    }
    unsafe {
        let _ = RegCloseKey(key);
    }
    names
}

fn get_string_raw(key: HKEY, name: &str) -> Result<Option<String>> {
    let name = HSTRING::from(name);
    let flags = RRF_RT_REG_SZ;
    let mut size = 0u32;
    let status = unsafe { RegGetValueW(key, None, &name, flags, None, None, Some(&mut size)) };
    if !missing_is_none(status)? {
        return Ok(None);
    }
    let mut buffer = vec![0u16; size as usize / 2];
    unsafe {
        RegGetValueW(key, None, &name, flags, None, Some(buffer.as_mut_ptr().cast()), Some(&mut size)).ok()?;
    }
    let text = String::from_utf16_lossy(&buffer[..(size as usize / 2).min(buffer.len())]);
    Ok(Some(text.trim_end_matches(char::from(0)).to_string()))
}

pub fn key_exists(root: HKEY, path: &str) -> bool {
    let mut key = HKEY::default();
    let status = unsafe { RegOpenKeyExW(root, &HSTRING::from(path), None, KEY_READ, &mut key) };
    if status.is_ok() {
        unsafe {
            let _ = RegCloseKey(key);
        }
    }
    status.is_ok()
}

/// Missing values are not an error.
pub fn delete_value(root: HKEY, path: &str, name: &str) -> Result<()> {
    let status = unsafe { RegDeleteKeyValueW(root, &HSTRING::from(path), &HSTRING::from(name)) };
    missing_is_none(status).map(drop)
}

/// Removes a key and everything under it. Missing keys are not an error.
pub fn delete_tree(root: HKEY, path: &str) -> Result<()> {
    let status = unsafe { RegDeleteTreeW(root, &HSTRING::from(path)) };
    missing_is_none(status).map(drop)
}

fn set(root: HKEY, path: &str, name: &str, kind: REG_VALUE_TYPE, data: &[u8]) -> Result<()> {
    let mut key = HKEY::default();
    unsafe {
        RegCreateKeyExW(
            root,
            &HSTRING::from(path),
            None,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut key,
            None,
        )
        .ok()?;
        let status = RegSetValueExW(key, &HSTRING::from(name), None, kind, Some(data));
        let _ = RegCloseKey(key);
        status.ok()
    }
}

/// Ok(true) on success, Ok(false) when the key or value doesn't exist.
fn missing_is_none(status: WIN32_ERROR) -> Result<bool> {
    match status {
        ERROR_SUCCESS => Ok(true),
        ERROR_FILE_NOT_FOUND => Ok(false),
        error => Err(error.into()),
    }
}
