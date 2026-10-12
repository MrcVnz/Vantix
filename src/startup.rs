//! What starts when you sign in: the Run keys, the Startup folders, Store apps' startup
//! tasks and scheduled tasks that run at sign in. The first three are turned on and off
//! where Task Manager does it, so both always show the same thing, and tasks are switched
//! in Task Scheduler. Nothing is deleted, except an entry whose program is gone when the
//! user removes it.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use windows::Win32::Foundation::{CloseHandle, E_FAIL, MAX_PATH, VARIANT_BOOL};
use windows::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, WIN32_FIND_DATAW,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx, CoTaskMemFree,
    IPersistFile, STGM_READ,
};
use windows::Win32::System::ProcessStatus::{GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
use windows::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
use windows::Win32::System::TaskScheduler::{
    IExecAction, IRegisteredTask, ITaskFolder, TASK_ACTION_EXEC, TASK_ACTION_TYPE, TASK_ENUM_HIDDEN,
    TASK_TRIGGER_LOGON, TASK_TRIGGER_TYPE2,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows::Win32::System::Variant::VARIANT;
use windows::Win32::UI::Shell::{
    FOLDERID_CommonStartup, FOLDERID_Startup, IShellLinkW, KF_FLAG_DEFAULT, SHGetKnownFolderPath,
    SHLoadIndirectString, ShellLink,
};
use windows::core::{BSTR, GUID, HSTRING, Interface, PWSTR, Result, w};

use crate::reg::{self, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
use crate::{dupes, memory, system};

const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN32: &str = r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run";
const APPROVED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved";
const PACKAGES: &str =
    r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages";
const TASK_STATES: &str =
    r"Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData";

#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    /// A Run key or a Startup folder.
    App,
    Store,
    /// A scheduled task with a sign in trigger.
    Task,
}

#[derive(Clone, PartialEq)]
enum Source {
    /// Switched through StartupApproved: the subkey there and the value name in it, plus
    /// the file itself for a Startup folder entry.
    Approved { approved: &'static str, key: String, file: Option<PathBuf> },
    /// A Store app's startup task, by package family and task id.
    Store { family: String, task: String },
    /// A scheduled task, by its full path.
    Task { path: String },
}

#[derive(Clone)]
pub struct Entry {
    /// The program's own description, or the entry name when it has none.
    pub name: String,
    pub publisher: String,
    pub all_users: bool,
    pub enabled: bool,
    /// Set by policy, so a switch here wouldn't stick.
    pub locked: bool,
    /// The program it starts isn't there any more.
    pub missing: bool,
    /// RAM its processes use right now, when it's running.
    pub memory: Option<u64>,
    pub kind: Kind,
    source: Source,
}

/// An entry before its program is looked at.
struct Found {
    all_users: bool,
    enabled: bool,
    locked: bool,
    /// A name that beats the program's description, as a Store app declares one.
    title: Option<String>,
    /// The entry's own name, for a program without a description.
    fallback: String,
    exe: Option<PathBuf>,
    kind: Kind,
    source: Source,
}

pub fn list() -> Vec<Entry> {
    unsafe {
        // Shortcuts are resolved through COM, and this runs on a worker thread.
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
    }
    let mut found = Vec::new();
    for (all_users, path, approved) in [(false, RUN, "Run"), (true, RUN, "Run"), (true, RUN32, "Run32")] {
        let root = if all_users { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER };
        for (name, command) in reg::string_values(root, path).unwrap_or_default() {
            found.push(Found {
                all_users,
                enabled: enabled(all_users, approved, &name),
                locked: false,
                title: None,
                fallback: name.clone(),
                exe: exe_path(&command),
                kind: Kind::App,
                source: Source::Approved { approved, key: name, file: None },
            });
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
            let exe = if is_link { link_target(&path) } else { Some(path.clone()) };
            found.push(Found {
                all_users,
                enabled: enabled(all_users, "StartupFolder", &name),
                locked: false,
                title: None,
                fallback: name.rsplit_once('.').map_or(name.as_str(), |(stem, _)| stem).to_string(),
                exe,
                kind: Kind::App,
                source: Source::Approved { approved: "StartupFolder", key: name, file: Some(path) },
            });
        }
    }
    found.extend(store_tasks());
    match logon_tasks() {
        Ok(tasks) => found.extend(tasks),
        Err(e) => system::log_error("logon tasks", &e),
    }

    let processes = processes();
    let shared = shared_folders();
    let mut entries: Vec<Entry> = found
        .into_iter()
        .map(|found| {
            let (description, publisher) = found.exe.as_deref().map(version_info).unwrap_or_default();
            // Launchers like Discord's Update.exe describe themselves by their file name.
            let stem = found.exe.as_deref().and_then(Path::file_stem).map(|stem| stem.to_string_lossy().to_lowercase());
            let name = match found.title {
                Some(title) => title,
                None if description.is_empty() || stem.as_deref() == Some(&description.to_lowercase()) => found.fallback,
                None => description,
            };
            Entry {
                name,
                publisher,
                all_users: found.all_users,
                enabled: found.enabled,
                locked: found.locked,
                missing: found.kind != Kind::Store && found.exe.as_deref().is_some_and(is_missing),
                memory: found.exe.as_deref().and_then(|exe| memory_of(exe, &processes, &shared)),
                kind: found.kind,
                source: found.source,
            }
        })
        .collect();
    entries.sort_by_key(|entry| entry.name.to_lowercase());
    entries
}

impl Entry {
    /// Whether both describe the same startup entry, whatever its state.
    pub fn same(&self, other: &Entry) -> bool {
        self.all_users == other.all_users && self.source == other.source
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

pub fn set_enabled(entry: &Entry, on: bool) -> Result<()> {
    match &entry.source {
        Source::Approved { approved, key, .. } => {
            // Turning one off also stores when, which Task Manager shows as well.
            let root = approved_root(entry.all_users);
            let path = format!(r"{APPROVED}\{approved}");
            let flag = reg::get_binary(root, &path, key)?.and_then(|bytes| bytes.first().copied()).unwrap_or(2);
            let mut value = vec![flag & !1 | u8::from(!on), 0, 0, 0];
            if on {
                value.extend([0; 8]);
            } else {
                let now = unsafe { GetSystemTimeAsFileTime() };
                value.extend(now.dwLowDateTime.to_le_bytes());
                value.extend(now.dwHighDateTime.to_le_bytes());
            }
            reg::set_binary(root, &path, key, &value)
        }
        // 2 is on and 1 is off by the user, what Task Manager writes.
        Source::Store { family, task } => {
            reg::set_dword(HKEY_CURRENT_USER, &format!(r"{TASK_STATES}\{family}\{task}"), "State", if on { 2 } else { 1 })
        }
        Source::Task { path } => unsafe { root_folder()?.GetTask(&BSTR::from(path))?.SetEnabled(VARIANT_BOOL::from(on)) },
    }
}

/// Removes an entry whose program is gone: the Run value, the Startup folder file (to the
/// Recycle Bin) or the task.
pub fn remove(entry: &Entry) -> Result<()> {
    let root = approved_root(entry.all_users);
    match &entry.source {
        Source::Approved { approved, key, file } => {
            match file {
                Some(file) if !dupes::recycle_file(file) => return Err(windows::core::Error::new(E_FAIL, "still there")),
                Some(_) => {}
                None => reg::delete_value(root, if *approved == "Run32" { RUN32 } else { RUN }, key)?,
            }
            reg::delete_value(root, &format!(r"{APPROVED}\{approved}"), key)
        }
        Source::Store { .. } => Ok(()),
        Source::Task { path } => {
            let (folder, name) = path.rsplit_once('\\').unwrap_or(("", path));
            let folder = if folder.is_empty() { "\\" } else { folder };
            unsafe { root_folder()?.GetFolder(&BSTR::from(folder))?.DeleteTask(&BSTR::from(name), 0) }
        }
    }
}

/// Only a full path can be missing: a bare name is found through PATH, and a drive that
/// isn't there, like an unplugged USB disk, says nothing about the program. Windows'
/// own folder is left out too, since a 32 bit entry's System32 is really SysWOW64.
fn is_missing(exe: &Path) -> bool {
    let windows = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()).to_lowercase();
    exe.is_absolute()
        && !exe.to_string_lossy().to_lowercase().starts_with(&windows)
        && exe.ancestors().last().is_some_and(Path::exists)
        && !exe.exists()
}

/// Store apps declare their startup tasks in their manifest. What the user picked is kept
/// in the registry, and until then the manifest's own default holds.
fn store_tasks() -> Vec<Found> {
    let mut found = Vec::new();
    let mut seen = HashSet::new();
    for full in reg::subkeys(HKEY_CURRENT_USER, PACKAGES) {
        let key = format!(r"{PACKAGES}\{full}");
        let Some(root) = reg::get_string(HKEY_CURRENT_USER, &key, "PackageRootFolder").ok().flatten() else {
            continue;
        };
        // Name_Version_Architecture_ResourceId_PublisherId; the family is the two ends.
        let parts: Vec<&str> = full.split('_').collect();
        let [name, .., publisher] = parts[..] else { continue };
        let family = format!("{name}_{publisher}");
        if seen.contains(&family) {
            continue;
        }
        let Ok(manifest) = std::fs::read_to_string(Path::new(&root).join("AppxManifest.xml")) else { continue };
        seen.insert(family.clone());
        if !manifest.contains("windows.startupTask") {
            continue;
        }
        let package = reg::get_string(HKEY_CURRENT_USER, &key, "DisplayName")
            .ok()
            .flatten()
            .and_then(|text| resource(&text, &full, name));
        for task in startup_tasks(&manifest) {
            let states = format!(r"{TASK_STATES}\{family}\{}", task.id);
            // 0 off, 1 off by the user, 2 on, 3 off by policy, 4 on by policy.
            let state = reg::get_dword(HKEY_CURRENT_USER, &states, "State").ok().flatten();
            let state = state.unwrap_or(if task.on { 2 } else { 0 });
            let title = task.display.and_then(|text| resource(&text, &full, name)).or_else(|| package.clone());
            found.push(Found {
                all_users: false,
                enabled: matches!(state, 2 | 4),
                locked: matches!(state, 3 | 4),
                title: Some(title.unwrap_or_else(|| name.to_string())),
                fallback: String::new(),
                exe: task.exe.map(|exe| Path::new(&root).join(exe)),
                kind: Kind::Store,
                source: Source::Store { family: family.clone(), task: task.id },
            });
        }
    }
    found
}

struct StartupTask {
    id: String,
    /// What the manifest asks for before the user has picked.
    on: bool,
    display: Option<String>,
    /// From the extension around it, relative to the package folder.
    exe: Option<String>,
}

fn startup_tasks(manifest: &str) -> Vec<StartupTask> {
    let mut tasks = Vec::new();
    let mut exe = None;
    for tag in manifest.split('<').skip(1) {
        let tag = tag.split('>').next().unwrap_or_default();
        let element = tag.split_whitespace().next().unwrap_or_default();
        if tag.contains("\"windows.startupTask\"") {
            exe = attribute(tag, "Executable");
        } else if element.starts_with('/') && element.ends_with("Extension") {
            exe = None;
        } else if element == "StartupTask" || element.ends_with(":StartupTask") {
            let Some(id) = attribute(tag, "TaskId") else { continue };
            tasks.push(StartupTask {
                id,
                on: attribute(tag, "Enabled").as_deref() == Some("true"),
                display: attribute(tag, "DisplayName"),
                exe: exe.clone(),
            });
        }
    }
    tasks
}

/// An attribute by its bare name, so Executable doesn't match uap10:Executable.
fn attribute(tag: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=\"");
    let mut from = 0;
    while let Some(at) = tag[from..].find(&needle) {
        let at = from + at;
        let value = &tag[at + needle.len()..];
        if tag[..at].ends_with(char::is_whitespace) {
            return value.split('"').next().map(|value| value.replace("&amp;", "&"));
        }
        from = at + needle.len();
    }
    None
}

/// A manifest string, which can point into the package's resources.
fn resource(text: &str, full: &str, name: &str) -> Option<String> {
    let Some(id) = text.strip_prefix("ms-resource:") else {
        return Some(text.to_string()).filter(|text| !text.is_empty());
    };
    let uris = if id.starts_with("//") {
        vec![format!("ms-resource:{id}")]
    } else if let Some(path) = id.strip_prefix('/') {
        vec![format!("ms-resource://{name}/{path}")]
    } else {
        vec![format!("ms-resource://{name}/Resources/{id}"), format!("ms-resource://{name}/{id}")]
    };
    uris.into_iter().find_map(|uri| {
        let mut text = [0u16; 512];
        let source = HSTRING::from(format!("@{{{full}?{uri}}}"));
        unsafe { SHLoadIndirectString(&source, &mut text, None) }.ok()?;
        let len = text.iter().position(|&c| c == 0).unwrap_or(text.len());
        Some(String::from_utf16_lossy(&text[..len])).filter(|text| !text.is_empty())
    })
}

fn root_folder() -> Result<ITaskFolder> {
    unsafe { system::task_service()?.GetFolder(&BSTR::from("\\")) }
}

/// Scheduled tasks that run when someone signs in, outside Windows' own Microsoft folder.
/// Vantix's own task is left to its setting.
fn logon_tasks() -> Result<Vec<Found>> {
    let mut found = Vec::new();
    let mut folders = vec![root_folder()?];
    while let Some(folder) = folders.pop() {
        unsafe {
            let subfolders = folder.GetFolders(0)?;
            for index in 1..=subfolders.Count()? {
                let Ok(subfolder) = subfolders.get_Item(&VARIANT::from(index)) else { continue };
                if !subfolder.Path().is_ok_and(|path| path.to_string().eq_ignore_ascii_case(r"\Microsoft")) {
                    folders.push(subfolder);
                }
            }
            let tasks = folder.GetTasks(TASK_ENUM_HIDDEN.0)?;
            for index in 1..=tasks.Count()? {
                if let Some(task) = tasks.get_Item(&VARIANT::from(index)).ok().and_then(|task| logon_task(&task)) {
                    found.push(task);
                }
            }
        }
    }
    Ok(found)
}

fn logon_task(task: &IRegisteredTask) -> Option<Found> {
    unsafe {
        let path = task.Path().ok()?.to_string();
        if path.eq_ignore_ascii_case(&format!(r"\{}", system::TASK_NAME)) {
            return None;
        }
        let definition = task.Definition().ok()?;
        let triggers = definition.Triggers().ok()?;
        let mut count = 0;
        triggers.Count(&mut count).ok()?;
        let at_logon = (1..=count).any(|index| {
            let mut kind = TASK_TRIGGER_TYPE2::default();
            triggers.get_Item(index).is_ok_and(|trigger| trigger.Type(&mut kind).is_ok() && kind == TASK_TRIGGER_LOGON)
        });
        if !at_logon {
            return None;
        }
        let actions = definition.Actions().ok()?;
        let mut count = 0;
        actions.Count(&mut count).ok()?;
        let exe = (1..=count).find_map(|index| {
            let action = actions.get_Item(index).ok()?;
            let mut kind = TASK_ACTION_TYPE::default();
            action.Type(&mut kind).ok()?;
            if kind != TASK_ACTION_EXEC {
                return None;
            }
            let mut path = BSTR::new();
            action.cast::<IExecAction>().ok()?.Path(&mut path).ok()?;
            Some(PathBuf::from(expand(path.to_string().trim().trim_matches('"'))))
        });
        let enabled = task.Enabled().ok()?;
        let name = task.Name().ok()?.to_string();
        // Updaters add a GUID to keep their names apart.
        let name = name.split('{').next().unwrap_or(&name).trim().to_string();
        Some(Found {
            all_users: false,
            enabled: enabled.as_bool(),
            locked: false,
            title: None,
            fallback: name,
            exe,
            kind: Kind::Task,
            source: Source::Task { path },
        })
    }
}

/// %VARIABLE% references, as Task Scheduler expands them when it starts the task.
fn expand(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%').map(|end| (end, std::env::var(&after[..end]))) {
            Some((end, Ok(value))) => {
                out.push_str(&value);
                rest = &after[end + 1..];
            }
            _ => {
                out.push('%');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
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
pub fn version_info(path: &Path) -> (String, String) {
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

    #[test]
    fn reads_manifest_tasks() {
        let manifest = r#"<Extensions>
        <desktop:Extension Category="windows.startupTask"
          Executable="app\Claude.exe"
          EntryPoint="Windows.FullTrustApplication">
          <desktop:StartupTask TaskId="ClaudeStartup" Enabled="false" DisplayName="Claude" />
        </desktop:Extension>
        <uap5:Extension Category="windows.startupTask">
          <uap5:StartupTask TaskId="Login" Enabled="true" DisplayName="ms-resource:AppName" />
        </uap5:Extension>
        <uap5:Extension Category="windows.appService" uap10:Executable="other.exe" Executable="x.exe"/>
        </Extensions>"#;
        let tasks = startup_tasks(manifest);
        assert_eq!(tasks.len(), 2);
        assert_eq!((tasks[0].id.as_str(), tasks[0].on), ("ClaudeStartup", false));
        assert_eq!(tasks[0].exe.as_deref(), Some(r"app\Claude.exe"));
        assert_eq!(tasks[0].display.as_deref(), Some("Claude"));
        assert_eq!((tasks[1].id.as_str(), tasks[1].on, tasks[1].exe.as_deref()), ("Login", true, None));
        assert_eq!(attribute(r#"a uap10:Executable="no" Executable="yes""#, "Executable").as_deref(), Some("yes"));
        let root = std::env::var("SystemRoot").unwrap();
        assert_eq!(expand(r"%SystemRoot%\x %NOPE_VAR% 50%"), format!(r"{root}\x %NOPE_VAR% 50%"));
    }

    /// Adds a Run value and a sign in task for a program that isn't there, switches and
    /// removes them, and switches Terminal's startup task and puts its value back:
    /// `cargo test startup_round_trip -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn startup_round_trip() {
        let gone = r"C:\Program Files\VantixTestGone\gone.exe";
        reg::set_string(HKEY_CURRENT_USER, RUN, "VantixTestGone", &format!("\"{gone}\" --tray")).unwrap();
        let made = std::process::Command::new("schtasks")
            .args(["/Create", "/TN", "VantixTestGone", "/TR", gone, "/SC", "ONLOGON", "/F"])
            .output()
            .unwrap();
        assert!(made.status.success(), "{}", String::from_utf8_lossy(&made.stderr));
        let find = |kind: Kind| list().into_iter().find(|e| e.kind == kind && e.name == "VantixTestGone");
        for kind in [Kind::App, Kind::Task] {
            let entry = find(kind).expect("listed");
            assert!(entry.missing && entry.enabled);
            set_enabled(&entry, false).unwrap();
            assert!(!find(kind).unwrap().enabled);
            remove(&entry).unwrap();
            assert!(find(kind).is_none());
        }
        assert_eq!(reg::get_binary(HKEY_CURRENT_USER, &format!(r"{APPROVED}\Run"), "VantixTestGone").unwrap(), None);

        let terminal = list().into_iter().find(|e| matches!(&e.source, Source::Store { task, .. } if task == "StartTerminalOnLoginTask"));
        let Some(terminal) = terminal else { return };
        let Source::Store { family, task } = &terminal.source else { unreachable!() };
        let key = format!(r"{TASK_STATES}\{family}\{task}");
        let before = reg::get_dword(HKEY_CURRENT_USER, &key, "State").unwrap();
        set_enabled(&terminal, true).unwrap();
        assert_eq!(reg::get_dword(HKEY_CURRENT_USER, &key, "State").unwrap(), Some(2));
        set_enabled(&terminal, false).unwrap();
        assert_eq!(reg::get_dword(HKEY_CURRENT_USER, &key, "State").unwrap(), Some(1));
        match before {
            Some(state) => reg::set_dword(HKEY_CURRENT_USER, &key, "State", state).unwrap(),
            None => reg::delete_value(HKEY_CURRENT_USER, &key, "State").unwrap(),
        }
    }

    /// Read-only: `cargo test startup_list -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn startup_list() {
        for entry in list() {
            println!(
                "{:<40} {:<30} all={} on={} locked={} missing={} mem={:?} [{}]",
                entry.name,
                entry.publisher,
                entry.all_users,
                entry.enabled,
                entry.locked,
                entry.missing,
                entry.memory.map(|m| m >> 20),
                match &entry.source {
                    Source::Approved { approved, key, .. } => format!("{approved} / {key}"),
                    Source::Store { family, task } => format!("store {family} / {task}"),
                    Source::Task { path } => format!("task {path}"),
                }
            );
        }
    }
}
