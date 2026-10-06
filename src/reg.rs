//! Thin wrappers over the registry API, enough for the values Vantix touches.

use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Registry::{
    HKEY, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ, RegCloseKey, RegCreateKeyExW, RegDeleteTreeW,
    RegSetValueExW,
};
use windows::core::{HSTRING, Result};

pub use windows::Win32::System::Registry::HKEY_CURRENT_USER;

pub fn set_string(root: HKEY, path: &str, name: &str, value: &str) -> Result<()> {
    let data: Vec<u8> = value.encode_utf16().chain([0]).flat_map(u16::to_le_bytes).collect();
    unsafe {
        let key = create(root, path)?;
        let status = RegSetValueExW(key, &HSTRING::from(name), None, REG_SZ, Some(&data));
        let _ = RegCloseKey(key);
        status.ok()
    }
}

/// Removes a key and everything under it. Missing keys are not an error.
pub fn delete_tree(root: HKEY, path: &str) -> Result<()> {
    let status = unsafe { RegDeleteTreeW(root, &HSTRING::from(path)) };
    if status == ERROR_SUCCESS || status.0 == 2 { Ok(()) } else { status.ok() }
}

fn create(root: HKEY, path: &str) -> Result<HKEY> {
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
    }
    Ok(key)
}
