//! Integration with the Windows shell: single instance, title bar, logon task, toasts.

use std::sync::OnceLock;

use raw_window_handle::{HasWindowHandle, RawWindowHandle};
use windows::Data::Xml::Dom::XmlDocument;
use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};
use windows::Win32::Foundation::{
    COLORREF, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, HWND, VARIANT_FALSE, WAIT_OBJECT_0,
};
use windows::Win32::Graphics::Dwm::{
    DWMWA_BORDER_COLOR, DWMWA_CAPTION_COLOR, DWMWA_TEXT_COLOR, DWMWA_USE_IMMERSIVE_DARK_MODE,
    DwmSetWindowAttribute,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
};
use windows::Win32::System::TaskScheduler::{
    IExecAction, ILogonTrigger, ITaskFolder, ITaskService, TASK_ACTION_EXEC, TASK_CREATE_OR_UPDATE,
    TASK_LOGON_INTERACTIVE_TOKEN, TASK_RUNLEVEL_HIGHEST, TASK_TRIGGER_LOGON, TaskScheduler,
};
use windows::Win32::System::Threading::{
    CreateEventW, CreateMutexW, EVENT_MODIFY_STATE, OpenEventW, SetEvent, WaitForSingleObject,
};
use windows::Win32::System::Variant::VARIANT;
use windows::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID;
use windows::core::{BSTR, HSTRING, Interface, Result, w};

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

/// Unpackaged apps can raise toasts once their AppUserModelID is registered under HKCU
/// with a display name and icon.
pub fn register_notifications() -> Result<()> {
    let icon = data_dir().join("icon.png");
    if !icon.exists() {
        std::fs::create_dir_all(data_dir())?;
        std::fs::write(&icon, include_bytes!("../res/vantix.png"))?;
    }
    let key = format!(r"Software\Classes\AppUserModelId\{APP_ID}");
    reg::set_string(reg::HKEY_CURRENT_USER, &key, "DisplayName", "Vantix")?;
    reg::set_string(reg::HKEY_CURRENT_USER, &key, "IconUri", &icon.to_string_lossy())?;
    unsafe { SetCurrentProcessExplicitAppUserModelID(&HSTRING::from(APP_ID)) }
}

pub fn notify(title: &str, body: &str) -> Result<()> {
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
        // Already initialized on the UI thread by winit; S_FALSE is fine.
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
