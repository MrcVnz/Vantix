//! Thin wrappers over the registry API, enough for the values Vantix touches.

use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, WIN32_ERROR};
use windows::Win32::System::Registry::{
    HKEY, KEY_WRITE, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ, REG_VALUE_TYPE, RRF_RT_REG_DWORD,
    RRF_RT_REG_MULTI_SZ, RRF_RT_REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteKeyValueW, RegDeleteTreeW,
    RegGetValueW, RegSetValueExW,
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
