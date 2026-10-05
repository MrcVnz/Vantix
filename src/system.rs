//! Integration with the Windows shell: single instance, title bar styling.

use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use windows::Win32::Foundation::{COLORREF, ERROR_ALREADY_EXISTS, GetLastError, HWND};
use windows::Win32::Graphics::Dwm::{
    DWMWA_BORDER_COLOR, DWMWA_CAPTION_COLOR, DWMWA_TEXT_COLOR, DWMWA_USE_IMMERSIVE_DARK_MODE,
    DwmSetWindowAttribute,
};
use windows::Win32::System::Threading::CreateMutexW;
use windows::core::w;

pub fn single_instance() -> bool {
    // The handle is intentionally never closed: the mutex has to live as long as the process.
    unsafe {
        let _ = CreateMutexW(None, false, w!("Local\\EasyTune"));
        GetLastError() != ERROR_ALREADY_EXISTS
    }
}

/// Paints the native title bar in the app's colors so it blends with the window content.
/// Needs the window to be shown first, that's when the HWND exists.
pub fn style_title_bar(window: &slint::Window) {
    let handle = window.window_handle();
    let Ok(handle) = handle.window_handle() else { return };
    let RawWindowHandle::Win32(handle) = handle.as_raw() else { return };
    let hwnd = HWND(handle.hwnd.get() as _);

    let rgb = |r: u32, g: u32, b: u32| COLORREF(r | g << 8 | b << 16);
    let dark = 1u32;
    unsafe {
        let set = |attribute, value: *const u32| {
            let _ = DwmSetWindowAttribute(hwnd, attribute, value.cast(), 4);
        };
        set(DWMWA_USE_IMMERSIVE_DARK_MODE, &dark);
        set(DWMWA_CAPTION_COLOR, &rgb(0x0a, 0x0b, 0x0d).0);
        set(DWMWA_BORDER_COLOR, &rgb(0x1f, 0x23, 0x2a).0);
        set(DWMWA_TEXT_COLOR, &rgb(0x8a, 0x91, 0x9c).0);
    }
}
