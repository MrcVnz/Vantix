//! Integration with the Windows shell: single instance, title bar, logon task, toasts.

use std::io::Write;
use std::sync::OnceLock;

use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use windows::Data::Xml::Dom::XmlDocument;
use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};
use windows::Win32::Foundation::{
    COLORREF, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, HWND, LPARAM, VARIANT_FALSE, WAIT_OBJECT_0, WPARAM,
};
use windows::Win32::Graphics::Dwm::{
    DWMWA_BORDER_COLOR, DWMWA_CAPTION_COLOR, DWMWA_TEXT_COLOR, DWMWA_USE_IMMERSIVE_DARK_MODE, DWMWINDOWATTRIBUTE,
    DwmSetWindowAttribute,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::TaskScheduler::{
    IExecAction, ILogonTrigger, ITaskFolder, ITaskService, TASK_ACTION_EXEC, TASK_CREATE_OR_UPDATE,
    TASK_LOGON_INTERACTIVE_TOKEN, TASK_RUNLEVEL_HIGHEST, TASK_TRIGGER_LOGON, TaskScheduler,
};
use windows::Win32::System::Threading::{
    CreateEventW, CreateMutexW, EVENT_MODIFY_STATE, OpenEventW, SetEvent, WaitForSingleObject,
};
use windows::Win32::System::Variant::VARIANT;
use windows::Win32::UI::HiDpi::{GetDpiForWindow, GetSystemMetricsForDpi};
use windows::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;
use windows::Win32::UI::WindowsAndMessaging::{
    ICON_BIG, ICON_SMALL, IMAGE_ICON, LR_DEFAULTCOLOR, LoadImageW, SM_CXICON, SM_CXSMICON, SendMessageW,
    WM_SETICON,
};
use windows::core::{BSTR, HSTRING, Interface, PCWSTR, Result, w};

use crate::reg;
use crate::settings::data_dir;

// Every name we register in a shared namespace carries the author prefix so it can't
// clash with other tools that register generic names (GIGABYTE EasyTune owns a
// logon task called "EasyTune", for example).
const APP_ID: &str = "MrcVnz.Vantix";
const TASK_NAME: &str = "MrcVnz.Vantix";
/// Passed by the logon task so a boot start can go straight to the tray.
pub const AUTOSTART_ARG: &str = "--autostart";

/// Signaled by a second launch so the running instance brings its window up.
static SHOW_EVENT: OnceLock<usize> = OnceLock::new();

/// Toasts and the task scheduler are COM. winit only initializes it when it creates a
/// window, so a tray-only start would otherwise run them on whatever apartment the
/// windows crate falls back to.
pub fn init_com() {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
    }
}

/// Appends a line to `vantix.log` in the data folder, for failures nothing else would show.
pub fn log_error(what: &str, error: &dyn std::fmt::Display) {
    let line = format!("{} {what}: {error}\n", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"));
    let _ = std::fs::create_dir_all(data_dir());
    if let Ok(mut file) =
        std::fs::OpenOptions::new().create(true).append(true).open(data_dir().join("vantix.log"))
    {
        let _ = file.write_all(line.as_bytes());
    }
}

/// Returns false when another instance is already running, after asking it to show itself.
pub fn single_instance() -> bool {
    unsafe {
        // The handles are intentionally never closed: they have to live as long as the process.
        let _ = CreateMutexW(None, false, w!("Local\\MrcVnz.Vantix"));
        if GetLastError() == ERROR_ALREADY_EXISTS {
            if let Ok(event) = OpenEventW(EVENT_MODIFY_STATE, false, w!("Local\\MrcVnz.Vantix.Show")) {
                let _ = SetEvent(event);
            }
            return false;
        }
        if let Ok(event) = CreateEventW(None, false, false, w!("Local\\MrcVnz.Vantix.Show")) {
            let _ = SHOW_EVENT.set(event.0 as usize);
        }
        true
    }
}

/// Non-blocking check, polled from the 1 s ticker.
pub fn show_requested() -> bool {
    let Some(&event) = SHOW_EVENT.get() else { return false };
    unsafe { WaitForSingleObject(HANDLE(event as _), 0) == WAIT_OBJECT_0 }
}

/// Whether the taskbar exists yet. At logon Vantix can start before Explorer has it up.
pub fn taskbar_ready() -> bool {
    use windows::Win32::UI::WindowsAndMessaging::FindWindowW;
    unsafe { FindWindowW(w!("Shell_TrayWnd"), PCWSTR::null()) }.is_ok_and(|hwnd| !hwnd.is_invalid())
}

/// Whether our tray icon is really in the notification area. Slint 1.18 gives up for
/// good when adding it fails, as at logon before Explorer is ready, and its hidden
/// message-only window never hears Explorer restart either, so the icon can be gone
/// with no error anywhere. An empty NIM_MODIFY only succeeds on an icon that exists.
/// The class name and icon id are Slint's own, from i-slint-core's system_tray/windows.rs.
pub fn tray_icon_present() -> bool {
    use windows::Win32::UI::Shell::{NIM_MODIFY, NOTIFYICONDATAW, Shell_NotifyIconW};
    use windows::Win32::UI::WindowsAndMessaging::{FindWindowExW, GetWindowThreadProcessId, HWND_MESSAGE};
    const SLINT_TRAY_ID: u32 = 1;
    let own = std::process::id();
    let mut after: Option<HWND> = None;
    loop {
        let Ok(hwnd) = (unsafe { FindWindowExW(Some(HWND_MESSAGE), after, w!("SlintSystemTrayWindow"), PCWSTR::null()) })
        else {
            return false;
        };
        if hwnd.is_invalid() {
            return false;
        }
        let mut pid = 0;
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
        if pid == own {
            let data = NOTIFYICONDATAW {
                cbSize: size_of::<NOTIFYICONDATAW>() as u32,
                hWnd: hwnd,
                uID: SLINT_TRAY_ID,
                ..Default::default()
            };
            if unsafe { Shell_NotifyIconW(NIM_MODIFY, &data) }.as_bool() {
                return true;
            }
        }
        after = Some(hwnd);
    }
}

pub fn hwnd(window: &slint::Window) -> Option<HWND> {
    let handle = window.window_handle();
    let RawWindowHandle::Win32(handle) = handle.window_handle().ok()?.as_raw() else { return None };
    Some(HWND(handle.hwnd.get() as _))
}

/// The part of the window's monitor not taken by the taskbar, in physical pixels, as
/// left, top, right and bottom.
pub fn work_area(window: &slint::Window) -> Option<(i32, i32, i32, i32)> {
    use windows::Win32::Graphics::Gdi::{GetMonitorInfoW, MONITOR_DEFAULTTONEAREST, MONITORINFO, MonitorFromWindow};
    let hwnd = hwnd(window)?;
    let mut info = MONITORINFO { cbSize: size_of::<MONITORINFO>() as u32, ..Default::default() };
    unsafe {
        let monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);
        GetMonitorInfoW(monitor, &mut info).as_bool().then_some(())?;
    }
    let r = info.rcWork;
    Some((r.left, r.top, r.right, r.bottom))
}

/// Paints the native title bar in the app's colors and sets the window icons from the
/// exe's icon resource. Returns false while the native window doesn't exist yet: Slint
/// only creates it once the event loop runs, not on `show()`.
pub fn style_window(window: &slint::Window) -> bool {
    let handle = window.window_handle();
    let Ok(handle) = handle.window_handle() else { return false };
    let RawWindowHandle::Win32(handle) = handle.as_raw() else { return false };
    let hwnd = HWND(handle.hwnd.get() as _);
    set_icons(hwnd);

    let rgb = |r: u32, g: u32, b: u32| COLORREF(r | g << 8 | b << 16);
    let dark = 1u32;
    unsafe {
        let set = |attribute, value: *const u32| {
            let _ = DwmSetWindowAttribute(hwnd, attribute, value.cast(), 4);
        };
        // Windows 10 before 2004 knows dark mode only as attribute 19. The colors below
        // are Windows 11 only and do nothing on 10, where the bar is just dark.
        if DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, (&raw const dark).cast(), 4).is_err() {
            set(DWMWINDOWATTRIBUTE(19), &dark);
        }
        set(DWMWA_CAPTION_COLOR, &rgb(0x0a, 0x0b, 0x0d).0);
        set(DWMWA_BORDER_COLOR, &rgb(0x1f, 0x23, 0x2a).0);
        set(DWMWA_TEXT_COLOR, &rgb(0x8a, 0x91, 0x9c).0);
    }
    true
}

/// Loads each icon at the exact size Windows asks for, so it picks the hand drawn 16, 24
/// or 32 px frame from the .ico instead of shrinking one big bitmap into a blur.
fn set_icons(hwnd: HWND) {
    unsafe {
        let Ok(module) = GetModuleHandleW(None) else { return };
        let dpi = GetDpiForWindow(hwnd);
        for (kind, metric) in [(ICON_SMALL, SM_CXSMICON), (ICON_BIG, SM_CXICON)] {
            let size = GetSystemMetricsForDpi(metric, dpi);
            // Resource id 1, see res/vantix.rc.
            if let Ok(icon) =
                LoadImageW(Some(module.into()), PCWSTR(1 as _), IMAGE_ICON, size, size, LR_DEFAULTCOLOR)
            {
                SendMessageW(hwnd, WM_SETICON, Some(WPARAM(kind as usize)), Some(LPARAM(icon.0 as isize)));
            }
        }
    }
}

/// Unpackaged apps can raise toasts once their AppUserModelID is registered under HKCU
/// with a display name and icon.
pub fn register_notifications() -> Result<()> {
    const ICON: &[u8] = include_bytes!("../res/vantix.png");
    let icon = data_dir().join("icon.png");
    if std::fs::read(&icon).ok().as_deref() != Some(ICON) {
        std::fs::create_dir_all(data_dir())?;
        std::fs::write(&icon, ICON)?;
    }
    let key = format!(r"Software\Classes\AppUserModelId\{APP_ID}");
    reg::set_string(reg::HKEY_CURRENT_USER, &key, "DisplayName", "Vantix")?;
    reg::set_string(reg::HKEY_CURRENT_USER, &key, "IconUri", &icon.to_string_lossy())?;
    unsafe { SetCurrentProcessExplicitAppUserModelID(&HSTRING::from(APP_ID)) }
}

/// Raises a toast, logging any failure. Returns whether Windows accepted it.
pub fn notify(title: &str, body: &str) -> bool {
    show_toast(title, body).inspect_err(|e| log_error("toast", e)).is_ok()
}

fn show_toast(title: &str, body: &str) -> Result<()> {
    let xml = XmlDocument::new()?;
    xml.LoadXml(&HSTRING::from(format!(
        r#"<toast><visual><binding template="ToastGeneric"><text>{}</text><text>{}</text></binding></visual></toast>"#,
        escape(title),
        escape(body)
    )))?;
    let toast = ToastNotification::CreateToastNotification(&xml)?;
    ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(APP_ID))?.Show(&toast)
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// The Run key would trigger a UAC prompt on every logon because the app needs admin,
/// so autostart is a logon task with the highest run level instead.
pub fn set_autostart(enabled: bool) -> Result<()> {
    let folder = task_folder()?;
    let name = BSTR::from(TASK_NAME);
    unsafe {
        if !enabled {
            return folder
                .DeleteTask(&name, 0)
                .or_else(|e| if e.code().0 as u32 == 0x80070002 { Ok(()) } else { Err(e) });
        }

        let service = task_service()?;
        let task = service.NewTask(0)?;

        let settings = task.Settings()?;
        settings.SetDisallowStartIfOnBatteries(VARIANT_FALSE)?;
        settings.SetStopIfGoingOnBatteries(VARIANT_FALSE)?;
        settings.SetExecutionTimeLimit(&BSTR::from("PT0S"))?;

        let principal = task.Principal()?;
        principal.SetLogonType(TASK_LOGON_INTERACTIVE_TOKEN)?;
        principal.SetRunLevel(TASK_RUNLEVEL_HIGHEST)?;

        let trigger: ILogonTrigger = task.Triggers()?.Create(TASK_TRIGGER_LOGON)?.cast()?;
        trigger.SetUserId(&BSTR::from(current_user()))?;
        // Lets the desktop settle before we start sampling.
        trigger.SetDelay(&BSTR::from("PT10S"))?;

        let action: IExecAction = task.Actions()?.Create(TASK_ACTION_EXEC)?.cast()?;
        action.SetPath(&BSTR::from(std::env::current_exe()?.to_string_lossy().as_ref()))?;
        action.SetArguments(&BSTR::from(AUTOSTART_ARG))?;

        folder.RegisterTaskDefinition(
            &name,
            &task,
            TASK_CREATE_OR_UPDATE.0,
            &VARIANT::default(),
            &VARIANT::default(),
            TASK_LOGON_INTERACTIVE_TOKEN,
            &VARIANT::default(),
        )?;
    }
    Ok(())
}

/// True only when the task exists and starts this very executable.
pub fn autostart_enabled() -> bool {
    let Ok(exe) = std::env::current_exe() else { return false };
    let path = || -> Result<String> {
        unsafe {
            let task = task_folder()?.GetTask(&BSTR::from(TASK_NAME))?;
            let action: IExecAction = task.Definition()?.Actions()?.get_Item(1)?.cast()?;
            let mut path = BSTR::new();
            action.Path(&mut path)?;
            Ok(path.to_string())
        }
    };
    path().is_ok_and(|path| path.eq_ignore_ascii_case(&exe.to_string_lossy()))
}

/// Undoes everything the app registered outside its data folder.
pub fn unregister_all() {
    let _ = set_autostart(false);
    let _ = reg::delete_tree(reg::HKEY_CURRENT_USER, &format!(r"Software\Classes\AppUserModelId\{APP_ID}"));
}

fn task_service() -> Result<ITaskService> {
    unsafe {
        // Already initialized on the UI thread by init_com; S_FALSE is fine.
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let service: ITaskService = CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)?;
        let none = VARIANT::default();
        service.Connect(&none, &none, &none, &none)?;
        Ok(service)
    }
}

fn task_folder() -> Result<ITaskFolder> {
    unsafe { task_service()?.GetFolder(&BSTR::from("\\")) }
}

fn current_user() -> String {
    let domain = std::env::var("USERDOMAIN").unwrap_or_default();
    let user = std::env::var("USERNAME").unwrap_or_default();
    if domain.is_empty() { user } else { format!("{domain}\\{user}") }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates and removes a real logon task: `cargo test autostart -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn autostart_round_trip() {
        let exists =
            std::process::Command::new("schtasks").args(["/Query", "/TN", TASK_NAME]).output().unwrap();
        assert!(!exists.status.success(), "a task named {TASK_NAME} already exists, refusing to touch it");
        set_autostart(true).unwrap();
        assert!(autostart_enabled());
        let xml = std::process::Command::new("schtasks")
            .args(["/Query", "/TN", TASK_NAME, "/XML"])
            .output()
            .unwrap();
        let xml = String::from_utf8_lossy(&xml.stdout);
        assert!(xml.contains("<RunLevel>HighestAvailable</RunLevel>"));
        assert!(xml.contains("<LogonTrigger>"));
        assert!(xml.contains(AUTOSTART_ARG));
        set_autostart(false).unwrap();
        assert!(!autostart_enabled());
        // Deleting a task that isn't there is fine too.
        set_autostart(false).unwrap();
    }
}
