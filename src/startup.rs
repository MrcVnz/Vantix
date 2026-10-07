//! Apps that start with Windows: the Run keys and the Startup folders. They're turned on
//! and off through StartupApproved, the same values Task Manager uses, so both always
//! show the same thing and nothing is deleted.

use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{CloseHandle, MAX_PATH};
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, WIN32_FIND_DATAW,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx, CoTaskMemFree,
    IPersistFile, STGM_READ,
};
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::Win32::UI::Shell::{
    FOLDERID_CommonStartup, FOLDERID_Startup, IShellLinkW, KF_FLAG_DEFAULT, SHGetKnownFolderPath, ShellLink,
};
use windows::core::{GUID, HSTRING, Interface, PWSTR, Result, w};

use crate::memory;
use crate::reg::{self, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN32: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
const APPROVED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";

#[derive(Clone)]
pub struct Entry {
    /// The program's own description, or the entry name when it has none.
    pub name: String,
    pub publisher: String,
    pub all_users: bool,
    pub enabled: bool,
    /// RAM its processes use right now, when it's running.
    pub memory: Option<u64>,
    /// Subkey of StartupApproved and the value name in it.
    approved: &'static str,
    key: String,
}

pub fn list() -> Vec<Entry> {
    unsafe {
        // Shortcuts are resolved through COM, and this runs on a worker thread.
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
    }
    let mut found: Vec<(bool, &'static str, String, Option<PathBuf>)> = Vec::new();
    for (all_users, path, approved) in [(false, RUN, "Run"), (true, RUN, "Run"), (true, RUN32, "Run32")] {
        let root = if all_users { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER };
        for (name, command) in reg::string_values(root, path).unwrap_or_default() {
            let exe = exe_path(&command);
            found.push((all_users, approved, name, exe));
        }
    }
    for (all_users, folder) in [(false, &FOLDERID_Startup), (true, &FOLDERID_CommonStartup)] {
        let Some(folder) = known_folder(folder) else { continue };
        for file in std::fs::read_dir(folder).into_iter().flatten().flatten() {
            let path = file.path();
            let name = file.file_name().to_string_lossy().into_owned();
            if name.eq_ignore_ascii_case("desktop.ini") || path.is_dir() {
                continue;
            }
            let is_link = path.extension().is_some_and(|ext| ext.eq_ignore_ascii_case("lnk"));
            let exe = if is_link { link_target(&path) } else { Some(path) };
            found.push((all_users, "StartupFolder", name, exe));
        }
    }

    let processes = processes();
    let shared = shared_folders();
    let mut entries: Vec<Entry> = found
        .into_iter()
        .map(|(all_users, approved, key, exe)| {
            let (description, publisher) = exe.as_deref().map(version_info).unwrap_or_default();
            // Launchers like Discord's Update.exe describe themselves by their file name.
            let stem = exe.as_deref().and_then(Path::file_stem).map(|stem| stem.to_string_lossy().to_lowercase());
            let name = if description.is_empty() || stem.as_deref() == Some(&description.to_lowercase()) {
                key.rsplit_once('.').filter(|_| approved == "StartupFolder").map_or(key.as_str(), |(stem, _)| stem)
            } else {
                description.as_str()
            };
            Entry {
                name: name.to_string(),
                publisher,
                all_users,
                enabled: enabled(all_users, approved, &key),
                memory: exe.as_deref().and_then(|exe| memory_of(exe, &processes, &shared)),
                approved,
                key,
            }
        })
        .collect();
    entries.sort_by_key(|entry| entry.name.to_lowercase());
    entries
}

impl Entry {
    /// Whether both describe the same startup entry, whatever its state.
    pub fn same(&self, other: &Entry) -> bool {
        self.all_users == other.all_users && self.approved == other.approved && self.key == other.key
    }
}

fn approved_root(all_users: bool) -> windows::Win32::System::Registry::HKEY {
    if all_users { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER }
}

/// The first byte is even when on (2, or 6 for a few Windows entries) and odd when off.
/// A missing value means on.
fn enabled(all_users: bool, approved: &str, key: &str) -> bool {
    let value = reg::get_binary(approved_root(all_users), &format!(r"{APPROVED}\{approved}"), key);
    value.ok().flatten().and_then(|bytes| bytes.first().copied()).is_none_or(|flag| flag & 1 == 0)
}

/// Turning one off also stores when, which Task Manager shows as well.
pub fn set_enabled(entry: &Entry, on: bool) -> Result<()> {
    let root = approved_root(entry.all_users);
    let path = format!(r"{APPROVED}\{}", entry.approved);
    let flag = reg::get_binary(root, &path, &entry.key)?.and_then(|bytes| bytes.first().copied()).unwrap_or(2);
    let mut value = vec![flag & !1 | u8::from(!on), 0, 0, 0];
    if on {
        value.extend([0; 8]);
    } else {
        let now = unsafe { GetSystemTimeAsFileTime() };
        value.extend(now.dwLowDateTime.to_le_bytes());
        value.extend(now.dwHighDateTime.to_le_bytes());
    }
    reg::set_binary(root, &path, &entry.key, &value)
}

/// The program a Run command starts: the quoted part, or everything up to ".exe" since
/// plenty of entries leave paths with spaces unquoted.
fn exe_path(command: &str) -> Option<PathBuf> {
    let command = command.trim();
    let path = match command.strip_prefix('"') {
        Some(rest) => rest.split('"').next()?,
        None => match command.to_ascii_lowercase().find(".exe") {
            Some(end) => &command[..end + 4],
            None => command.split_whitespace().next()?,
        },
    };
    Some(PathBuf::from(path))
}

fn known_folder(id: &GUID) -> Option<PathBuf> {
    unsafe {
        let path = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None).ok()?;
        let folder = path.to_string().ok().map(PathBuf::from);
        CoTaskMemFree(Some(path.0.cast()));
        folder
    }
}

fn link_target(link: &Path) -> Option<PathBuf> {
    unsafe {
        let shell_link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER).ok()?;
        shell_link.cast::<IPersistFile>().ok()?.Load(&HSTRING::from(link.as_os_str()), STGM_READ).ok()?;
        let mut path = [0u16; MAX_PATH as usize];
        let mut find = WIN32_FIND_DATAW::default();
        shell_link.GetPath(&mut path, &mut find, 0).ok()?;
        let len = path.iter().position(|&c| c == 0).unwrap_or(path.len());
        (len > 0).then(|| PathBuf::from(String::from_utf16_lossy(&path[..len])))
    }
}

/// File description and company name from the version resource.
fn version_info(path: &Path) -> (String, String) {
    unsafe {
        let file = HSTRING::from(path.as_os_str());
        let size = GetFileVersionInfoSizeW(&file, None);
        if size == 0 {
            return Default::default();
        }
        let mut data = vec![0u8; size as usize];
        if GetFileVersionInfoW(&file, None, size, data.as_mut_ptr().cast()).is_err() {
            return Default::default();
        }
        let block = data.as_ptr().cast();
        let mut pointer = std::ptr::null_mut();
        let mut len = 0u32;
        let language = if VerQueryValueW(block, w!(r"\VarFileInfo\Translation"), &mut pointer, &mut len).as_bool()
            && len >= 4
        {
            let pair = pointer as *const u16;
            format!("{:04x}{:04x}", *pair, *pair.add(1))
        } else {
            "040904b0".into()
        };
        let mut field = |name: &str| {
            let query = HSTRING::from(format!(r"\StringFileInfo\{language}\{name}"));
            if !VerQueryValueW(block, &query, &mut pointer, &mut len).as_bool() || len == 0 {
                return String::new();
            }
            let text = std::slice::from_raw_parts(pointer as *const u16, len as usize);
            String::from_utf16_lossy(text).trim_end_matches('\0').trim().to_string()
        };
        (field("FileDescription"), field("CompanyName"))
    }
}

/// Full image path, lowercased, and working set of every process we can open.
fn processes() -> Vec<(String, u64)> {
    let mut list = Vec::new();
    memory::for_each_process(|entry| unsafe {
        let Ok(process) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, entry.th32ProcessID) else {
            return;
        };
        let mut path = [0u16; 1024];
        let mut len = path.len() as u32;
        let mut counters = PROCESS_MEMORY_COUNTERS::default();
        if QueryFullProcessImageNameW(process, PROCESS_NAME_WIN32, PWSTR(path.as_mut_ptr()), &mut len).is_ok()
            && GetProcessMemoryInfo(process, &mut counters, size_of::<PROCESS_MEMORY_COUNTERS>() as u32).is_ok()
        {
            list.push((String::from_utf16_lossy(&path[..len as usize]).to_lowercase(), counters.WorkingSetSize as u64));
        }
        let _ = CloseHandle(process);
    });
    list
}

/// Programs that run something else: their memory belongs to whatever they're running,
/// and every copy of them on the system would be counted.
const HOSTS: [&str; 10] = [
    "rundll32.exe",
    "wscript.exe",
    "cscript.exe",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "mshta.exe",
    "explorer.exe",
    "java.exe",
    "javaw.exe",
];

/// Folders that hold many programs, lowercased with a trailing backslash. An exe sitting
/// right in one of them, or anywhere in the Windows folder, only counts itself.
struct Shared {
    windows: String,
    folders: Vec<String>,
}

fn shared_folders() -> Shared {
    let folder = |path: &str| format!("{}\\", path.trim_end_matches('\\').to_lowercase());
    let mut folders: Vec<String> =
        ["ProgramFiles", "ProgramFiles(x86)", "ProgramData", "LOCALAPPDATA", "APPDATA", "USERPROFILE"]
            .iter()
            .filter_map(|name| std::env::var(name).ok())
            .map(|path| folder(&path))
            .collect();
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        folders.push(folder(&format!(r"{local}\Programs")));
    }
    let windows = folder(&std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()));
    Shared { windows, folders }
}

/// Everything running from the program's own folder counts, since launchers like Steam
/// and Discord start their real work in other executables next to them.
fn memory_of(exe: &Path, processes: &[(String, u64)], shared: &Shared) -> Option<u64> {
    let exe = exe.to_string_lossy().to_lowercase();
    let (folder, name) = exe.rsplit_once('\\')?;
    if HOSTS.contains(&name) {
        return None;
    }
    let folder = format!("{folder}\\");
    // The drive root, a shared folder itself or anything in Windows.
    let alone = folder.len() <= 3 || shared.folders.contains(&folder) || folder.starts_with(&shared.windows);
    let total: u64 = processes
        .iter()
        .filter(|(path, _)| *path == exe || !alone && path.starts_with(&folder))
        .map(|(_, bytes)| bytes)
        .sum();
    (total > 0).then_some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_rules() {
        let shared = Shared {
            windows: r"c:\windows\".into(),
            folders: vec![r"c:\program files\".into(), r"c:\users\me\appdata\local\".into()],
        };
        let processes: Vec<(String, u64)> = [
            (r"c:\program files\steam\steam.exe", 10),
            (r"c:\program files\steam\bin\cef\steamwebhelper.exe", 20),
            (r"c:\program files\other\other.exe", 40),
            (r"c:\users\me\appdata\local\tool.exe", 1),
            (r"c:\users\me\appdata\local\discord\app\discord.exe", 80),
            (r"c:\windows\system32\rundll32.exe", 5),
            (r"c:\windows\system32\securityhealthsystray.exe", 2),
            (r"c:\windows\system32\svchost.exe", 300),
        ]
        .map(|(path, bytes)| (path.to_string(), bytes))
        .into();
        let memory = |exe: &str| memory_of(Path::new(exe), &processes, &shared);
        assert_eq!(memory(r"C:\Program Files\Steam\steam.exe"), Some(30));
        assert_eq!(memory(r"C:\Users\me\AppData\Local\tool.exe"), Some(1));
        assert_eq!(memory(r"C:\Windows\System32\SecurityHealthSystray.exe"), Some(2));
        assert_eq!(memory(r"C:\Windows\System32\rundll32.exe"), None);
        assert_eq!(memory(r"C:\Program Files\Steam\missing.exe"), Some(30));
        assert_eq!(memory(r"C:\Nowhere\gone.exe"), None);
    }

    /// Read-only: `cargo test startup_list -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn startup_list() {
        for entry in list() {
            println!(
                "{:<40} {:<30} all={} on={} mem={:?} [{} / {}]",
                entry.name,
                entry.publisher,
                entry.all_users,
                entry.enabled,
                entry.memory.map(|m| m >> 20),
                entry.approved,
                entry.key
            );
        }
    }
}
