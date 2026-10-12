//! Disk cleanup: measures and deletes known cache and junk locations.
//!
//! Walks never follow reparse points (a junction inside a temp folder must not lead the
//! delete elsewhere) and skip anything in use instead of failing. They use std::fs::read_dir:
//! a hand rolled FindFirstFileExW walk with large fetch measured no faster on 99k files.

use std::collections::HashMap;
use std::os::windows::fs::MetadataExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use windows::Win32::Devices::DeviceAndDriverInstallation::{
    CM_Get_DevNode_PropertyW, CM_Get_Device_ID_List_SizeW, CM_Get_Device_ID_ListW, CM_LOCATE_DEVNODE_PHANTOM,
    CM_Locate_DevNodeW, CR_SUCCESS, INF_STYLE_WIN4, INFCONTEXT, SetupCloseInfFile, SetupFindFirstLineW,
    SetupGetStringFieldW, SetupOpenInfFileW,
};
use windows::Win32::Devices::Properties::{DEVPKEY_Device_DriverInfPath, DEVPROPTYPE};

use windows::Win32::Foundation::{ERROR_SERVICE_NOT_ACTIVE, FILETIME};
use windows::Win32::Storage::FileSystem::{
    DeleteFileW, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, GetDiskFreeSpaceExW, RemoveDirectoryW,
    SetFileAttributesW,
};
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_HANDLE,
    SC_MANAGER_CONNECT, SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START,
    SERVICE_STATUS, SERVICE_STOP, SERVICE_STOPPED, StartServiceW,
};
use windows::Win32::System::SystemInformation::GetSystemTimeAsFileTime;
use windows::Win32::UI::Shell::{
    SHERB_NOCONFIRMATION, SHERB_NOPROGRESSUI, SHERB_NOSOUND, SHEmptyRecycleBinW, SHQUERYRBINFO,
    SHQueryRecycleBinW,
};
use windows::core::{HSTRING, PCWSTR, w};

use crate::reg;

// The crate only has it behind two unrelated features.
windows_link::link!("setupapi.dll" "system" fn SetupGetInfDriverStoreLocationW(
    filename: PCWSTR,
    alternate_platform: *const core::ffi::c_void,
    locale: PCWSTR,
    buffer: *mut u16,
    size: u32,
    required: *mut u32,
) -> windows::core::BOOL);

/// Order matches the rows in ui/storage.slint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    UserTemp,
    WindowsTemp,
    UpdateCache,
    DeliveryOptimization,
    CrashDumps,
    ErrorReports,
    WindowsLogs,
    ShaderCache,
    LauncherCaches,
    GpuLeftovers,
    OldDrivers,
    WindowsOld,
    Thumbnails,
    BrowserCache,
    OldDownloads,
    DevCaches,
    RecycleBin,
}

impl Category {
    pub const ALL: [Category; 17] = [
        Category::UserTemp,
        Category::WindowsTemp,
        Category::UpdateCache,
        Category::DeliveryOptimization,
        Category::CrashDumps,
        Category::ErrorReports,
        Category::WindowsLogs,
        Category::ShaderCache,
        Category::LauncherCaches,
        Category::GpuLeftovers,
        Category::OldDrivers,
        Category::WindowsOld,
        Category::Thumbnails,
        Category::BrowserCache,
        Category::OldDownloads,
        Category::DevCaches,
        Category::RecycleBin,
    ];

    /// Whether it starts selected. The rest have a visible cost (recompiles, rebuilds,
    /// lost files, no way back) and stay opt-in.
    pub fn selected_by_default(self) -> bool {
        matches!(
            self,
            Category::UserTemp
                | Category::WindowsTemp
                | Category::UpdateCache
                | Category::DeliveryOptimization
                | Category::CrashDumps
                | Category::ErrorReports
                | Category::WindowsLogs
                | Category::GpuLeftovers
        )
    }

    /// People's own files go to the Recycle Bin instead of away for good.
    fn recycles(self) -> bool {
        self == Category::OldDownloads
    }

    /// Services holding these folders, stopped during the cleanup and started again after.
    fn services(self) -> &'static [&'static str] {
        match self {
            Category::UpdateCache => &["wuauserv", "bits"],
            Category::DeliveryOptimization => &["DoSvc"],
            _ => &[],
        }
    }

    /// Temp folders are in use by running installers and apps; only old files go.
    fn min_age(self) -> Option<Duration> {
        const DAY: u64 = 24 * 3600;
        match self {
            Category::UserTemp | Category::WindowsTemp => Some(Duration::from_secs(DAY)),
            Category::OldDownloads => Some(Duration::from_secs(DOWNLOAD_DAYS * DAY)),
            _ => None,
        }
    }

    /// Browsers and launchers lock and rewrite their cache while open.
    fn blocking_processes(self) -> &'static [&'static str] {
        match self {
            Category::BrowserCache => &["chrome.exe", "msedge.exe", "brave.exe", "firefox.exe", "opera.exe"],
            Category::LauncherCaches => &["steam.exe", "EpicGamesLauncher.exe"],
            _ => &[],
        }
    }

    fn targets(self) -> Vec<Target> {
        let local = env_path("LOCALAPPDATA");
        let windows = env_path("SystemRoot");
        let program_data = env_path("ProgramData");
        match self {
            Category::UserTemp => vec![Target::contents(std::env::temp_dir())],
            Category::WindowsTemp => vec![Target::contents(windows.join("Temp"))],
            Category::UpdateCache => vec![Target::contents(windows.join(r"SoftwareDistribution\Download"))],
            Category::DeliveryOptimization => vec![Target::contents(windows.join(
                r"ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache",
            ))],
            Category::CrashDumps => vec![
                Target::contents(local.join("CrashDumps")),
                Target::contents(windows.join("Minidump")),
                Target::contents(windows.join("LiveKernelReports")),
                Target::file(windows.join("MEMORY.DMP")),
            ],
            Category::ErrorReports => vec![
                Target::contents(program_data.join(r"Microsoft\Windows\WER\ReportArchive")),
                Target::contents(program_data.join(r"Microsoft\Windows\WER\ReportQueue")),
                Target::contents(program_data.join(r"Microsoft\Windows\WER\Temp")),
                Target::contents(local.join(r"Microsoft\Windows\WER")),
            ],
            Category::ShaderCache => [
                "D3DSCache",
                r"NVIDIA\DXCache",
                r"NVIDIA\GLCache",
                r"AMD\DxCache",
                r"AMD\DxcCache",
                r"AMD\VkCache",
                r"Intel\ShaderCache",
            ]
            .iter()
            .map(|dir| Target::contents(local.join(dir)))
            .collect(),
            Category::WindowsLogs => [r"Logs\CBS", r"Logs\DISM", "Panther"]
                .iter()
                .map(|dir| Target::contents(windows.join(dir)))
                .collect(),
            Category::LauncherCaches => launcher_caches(&local),
            Category::GpuLeftovers => {
                let drive = PathBuf::from(format!("{}\\", system_drive()));
                ["NVIDIA", "AMD"].iter().map(|dir| Target::contents(drive.join(dir))).collect()
            }
            Category::Thumbnails => {
                vec![Target::matching(local.join(r"Microsoft\Windows\Explorer"), "thumbcache_")]
            }
            Category::BrowserCache => browser_caches(&local),
            Category::OldDownloads => crate::dupes::downloads().map(Target::contents).into_iter().collect(),
            Category::DevCaches => dev_caches(&local),
            Category::OldDrivers | Category::WindowsOld | Category::RecycleBin => Vec::new(),
        }
    }
}

/// Files in Downloads untouched for this long count as old.
pub const DOWNLOAD_DAYS: u64 = 30;

/// A folder whose contents get removed (the folder itself stays), a single file, or
/// the files of a folder whose names start with a prefix.
struct Target {
    path: PathBuf,
    kind: TargetKind,
}

enum TargetKind {
    Contents,
    File,
    Prefix(&'static str),
}

impl Target {
    fn contents(path: PathBuf) -> Self {
        Self { path, kind: TargetKind::Contents }
    }
    fn file(path: PathBuf) -> Self {
        Self { path, kind: TargetKind::File }
    }
    fn matching(path: PathBuf, prefix: &'static str) -> Self {
        Self { path, kind: TargetKind::Prefix(prefix) }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Tally {
    pub bytes: u64,
    pub files: u64,
    /// Files that were in use or protected and stayed.
    pub skipped: u64,
    /// The biggest things inside, largest first, for the row to list when it opens.
    pub items: Vec<(String, u64)>,
}

/// How many of the biggest items a category lists.
const ITEMS: usize = 8;

pub enum Outcome {
    Done(Tally),
    /// A process listed in `blocking_processes` is running; nothing was touched.
    Blocked(&'static str),
}

pub fn scan(category: Category) -> Outcome {
    if let Some(process) = running_blocker(category) {
        return Outcome::Blocked(process);
    }
    match category {
        Category::RecycleBin => return Outcome::Done(recycle_bin_size()),
        Category::OldDrivers => return Outcome::Done(old_drivers_tally()),
        Category::WindowsOld => return Outcome::Done(windows_old_tally()),
        _ => {}
    }
    let targets = category.targets();
    // One folder lists what's in it; several list themselves.
    let several = targets.len() > 1;
    let mut tally = Tally::default();
    let mut groups: HashMap<PathBuf, u64> = HashMap::new();
    let cutoff = category.min_age().map(cutoff);
    for target in &targets {
        visit(target, cutoff, &mut |size, path| {
            tally.bytes += size;
            tally.files += 1;
            let group = if several { target.path.clone() } else { first_level(&target.path, path) };
            *groups.entry(group).or_default() += size;
            true
        });
    }
    tally.items = biggest(groups.into_iter().map(|(path, size)| (shown(&path), size)));
    Outcome::Done(tally)
}

/// The child of `root` that `path` is under, or the file itself.
fn first_level(root: &Path, path: &Path) -> PathBuf {
    path.strip_prefix(root)
        .ok()
        .and_then(|rest| rest.components().next())
        .map_or_else(|| path.to_path_buf(), |first| root.join(first))
}

fn biggest(items: impl Iterator<Item = (String, u64)>) -> Vec<(String, u64)> {
    let mut items: Vec<(String, u64)> = items.filter(|(_, size)| *size > 0).collect();
    items.sort_by_key(|(_, size)| std::cmp::Reverse(*size));
    items.truncate(ITEMS);
    items
}

/// A path as the list shows it, with the profile folder as ~.
fn shown(path: &Path) -> String {
    let text = path.display().to_string();
    match std::env::var("USERPROFILE") {
        Ok(home) if !home.is_empty() && text.to_lowercase().starts_with(&home.to_lowercase()) => {
            format!("~{}", &text[home.len()..])
        }
        _ => text,
    }
}

pub fn clean(category: Category) -> Outcome {
    if let Some(process) = running_blocker(category) {
        return Outcome::Blocked(process);
    }
    if category == Category::RecycleBin {
        let before = recycle_bin_size();
        let flags = SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND;
        let emptied = unsafe { SHEmptyRecycleBinW(None, PCWSTR::null(), flags) }.is_ok();
        let after = if emptied { Tally::default() } else { recycle_bin_size() };
        return Outcome::Done(Tally {
            bytes: before.bytes.saturating_sub(after.bytes),
            files: before.files.saturating_sub(after.files),
            skipped: after.files,
            items: Vec::new(),
        });
    }
    match category {
        Category::OldDrivers => return Outcome::Done(clean_old_drivers()),
        Category::WindowsOld => return Outcome::Done(clean_windows_old()),
        _ => {}
    }

    let stopped: Vec<&str> = category.services().iter().copied().filter(|name| stop_service(name)).collect();
    let mut tally = Tally::default();
    let cutoff = category.min_age().map(cutoff);
    for target in category.targets() {
        clean_target(&target, cutoff, category.recycles(), &mut tally);
    }
    for name in stopped {
        start_service(name);
    }
    Outcome::Done(tally)
}

fn clean_target(target: &Target, cutoff: Option<u64>, recycle: bool, tally: &mut Tally) {
    visit(target, cutoff, &mut |size, path| {
        let gone = if recycle { crate::dupes::recycle_file(path) } else { delete_file(path) };
        if gone {
            tally.bytes += size;
            tally.files += 1;
        } else {
            tally.skipped += 1;
        }
        true
    });
    if matches!(target.kind, TargetKind::Contents) {
        remove_empty_dirs(&target.path, true);
    }
}

/// Free and total bytes of the Windows drive.
pub fn system_drive_space() -> (u64, u64) {
    let root = HSTRING::from(format!("{}\\", std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into())));
    let (mut free, mut total) = (0u64, 0u64);
    unsafe {
        let _ = GetDiskFreeSpaceExW(&root, None, Some(&mut total), Some(&mut free));
    }
    (free, total)
}

fn env_path(name: &str) -> PathBuf {
    std::env::var_os(name).map(PathBuf::from).unwrap_or_default()
}

fn system_drive() -> String {
    std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into())
}

/// Steam's and Epic's web and download caches, and Steam's shader cache. Game files,
/// saves and logins live elsewhere.
fn launcher_caches(local: &Path) -> Vec<Target> {
    let mut targets = vec![Target::contents(local.join(r"Steam\htmlcache"))];
    let steam = reg::get_string(reg::HKEY_CURRENT_USER, r"Software\Valve\Steam", "SteamPath").ok().flatten();
    if let Some(steam) = steam.map(|path| PathBuf::from(path.replace('/', "\\"))) {
        for dir in [r"appcache\htmlcache", r"appcache\httpcache", "depotcache", r"steamapps\shadercache"] {
            targets.push(Target::contents(steam.join(dir)));
        }
    }
    // Epic keeps one webcache folder per engine version, named webcache_4430 and so on.
    let saved = local.join(r"EpicGamesLauncher\Saved");
    for dir in subdirs(&saved) {
        if dir.file_name().is_some_and(|name| name.to_string_lossy().to_lowercase().starts_with("webcache")) {
            targets.push(Target::contents(dir));
        }
    }
    targets
}

/// Download caches of package managers. Everything in them comes back from the
/// internet on the next build or install.
fn dev_caches(local: &Path) -> Vec<Target> {
    let home = env_path("USERPROFILE");
    let roaming = env_path("APPDATA");
    vec![
        Target::contents(local.join("npm-cache")),
        Target::contents(roaming.join("npm-cache")),
        Target::contents(local.join(r"pip\Cache")),
        Target::contents(local.join(r"Yarn\Cache")),
        Target::contents(local.join(r"NuGet\v3-cache")),
        Target::contents(local.join("go-build")),
        Target::contents(home.join(r".cargo\registry\cache")),
        Target::contents(home.join(r".cargo\registry\src")),
        Target::contents(home.join(r".gradle\caches")),
    ]
}

// Old driver packages. Windows keeps every driver version it ever installed in the
// driver store. A package goes only when a newer one of the same driver is there and no
// device uses it, plugged in or not: a printer that's off still needs its driver.

struct Package {
    /// The name Windows published it under, like oem12.inf.
    inf: String,
    folder: PathBuf,
    label: String,
}

fn old_drivers() -> Vec<Package> {
    let used = drivers_in_use();
    let inf_dir = env_path("SystemRoot").join("INF");
    let Ok(entries) = std::fs::read_dir(&inf_dir) else { return Vec::new() };
    // Family is the original INF name with its provider and class.
    let mut families: HashMap<String, Vec<(Vec<u32>, bool, Package)>> = HashMap::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_lowercase();
        if !name.starts_with("oem") || !name.ends_with(".inf") {
            continue;
        }
        let (Some(folder), Some(info)) = (store_folder(&name), inf_version(&entry.path())) else { continue };
        let original = folder.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
        let original = original.split(".inf").next().unwrap_or_default().to_string();
        let family = format!("{original}|{}|{}", info.provider, info.class).to_lowercase();
        let label = format!("{} {} {} ({})", info.provider, info.class, info.version_text, info.date);
        let in_use = used.contains(&name);
        families.entry(family).or_default().push((info.version, in_use, Package { inf: name, folder, label }));
    }
    // The newest of a family always stays, and so does anything newer than what a device
    // uses: the user may have rolled back on purpose.
    let mut old = Vec::new();
    for packages in families.into_values() {
        let newest = packages.iter().map(|(version, ..)| version.clone()).max().unwrap_or_default();
        let in_use = packages.iter().filter(|(_, used, _)| *used).map(|(version, ..)| version.clone()).max();
        for (version, used, package) in packages {
            let older = match &in_use {
                Some(in_use) => version < *in_use,
                None => version < newest,
            };
            if !used && older {
                old.push(package);
            }
        }
    }
    old
}

/// The published INF names of every device's driver, plugged in now or not.
fn drivers_in_use() -> Vec<String> {
    let mut used = Vec::new();
    let mut len = 0u32;
    unsafe {
        if CM_Get_Device_ID_List_SizeW(&mut len, PCWSTR::null(), Default::default()) != CR_SUCCESS {
            return used;
        }
        let mut buffer = vec![0u16; len as usize];
        if CM_Get_Device_ID_ListW(PCWSTR::null(), &mut buffer, Default::default()) != CR_SUCCESS {
            return used;
        }
        for id in buffer.split(|&c| c == 0).filter(|id| !id.is_empty()) {
            let mut node = 0u32;
            let id = HSTRING::from_wide(id);
            if CM_Locate_DevNodeW(&mut node, &id, CM_LOCATE_DEVNODE_PHANTOM) != CR_SUCCESS {
                continue;
            }
            let mut kind = DEVPROPTYPE::default();
            let mut text = [0u16; 64];
            let mut size = (text.len() * 2) as u32;
            if CM_Get_DevNode_PropertyW(
                node,
                &DEVPKEY_Device_DriverInfPath,
                &mut kind,
                Some(text.as_mut_ptr().cast()),
                &mut size,
                0,
            ) == CR_SUCCESS
            {
                let end = text.iter().position(|&c| c == 0).unwrap_or(text.len());
                used.push(String::from_utf16_lossy(&text[..end]).to_lowercase());
            }
        }
    }
    used.sort();
    used.dedup();
    used
}

/// Where the driver store keeps a published package.
fn store_folder(inf: &str) -> Option<PathBuf> {
    let mut buffer = [0u16; 520];
    let name = HSTRING::from(inf);
    let found = unsafe {
        SetupGetInfDriverStoreLocationW(
            PCWSTR(name.as_ptr()),
            std::ptr::null(),
            PCWSTR::null(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            std::ptr::null_mut(),
        )
    };
    if !found.as_bool() {
        return None;
    }
    let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
    let path = PathBuf::from(String::from_utf16_lossy(&buffer[..end]));
    path.parent().map(Path::to_path_buf)
}

struct InfVersion {
    provider: String,
    class: String,
    version: Vec<u32>,
    version_text: String,
    /// As yyyy-mm-dd, so it sorts.
    date: String,
}

fn inf_version(path: &Path) -> Option<InfVersion> {
    unsafe {
        let inf = SetupOpenInfFileW(&HSTRING::from(path.as_os_str()), PCWSTR::null(), INF_STYLE_WIN4, None);
        if inf.is_null() || inf as isize == -1 {
            return None;
        }
        let field = |key: PCWSTR, index: u32| -> Option<String> {
            let mut context = INFCONTEXT::default();
            SetupFindFirstLineW(inf, w!("Version"), key, &mut context).ok()?;
            let mut buffer = [0u16; 256];
            SetupGetStringFieldW(&context, index, Some(&mut buffer), None).ok()?;
            let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
            Some(String::from_utf16_lossy(&buffer[..end]).trim().to_string())
        };
        let provider = field(w!("Provider"), 1).unwrap_or_default();
        let class = field(w!("Class"), 1).unwrap_or_default();
        let date = field(w!("DriverVer"), 1).unwrap_or_default();
        let version_text = field(w!("DriverVer"), 2).unwrap_or_default();
        SetupCloseInfFile(inf);
        let version = version_text.split('.').map(|part| part.trim().parse().unwrap_or(0)).collect();
        // DriverVer dates are mm/dd/yyyy.
        let parts: Vec<&str> = date.split('/').collect();
        let date = match parts[..] {
            [month, day, year] => format!("{year}-{month:0>2}-{day:0>2}"),
            _ => date,
        };
        Some(InfVersion { provider, class, version, version_text, date })
    }
}

fn folder_size(path: &Path) -> u64 {
    let mut size = 0;
    walk(path, None, None, &mut |bytes, _| {
        size += bytes;
        true
    });
    size
}

fn old_drivers_tally() -> Tally {
    let mut tally = Tally::default();
    let mut items = Vec::new();
    for package in old_drivers() {
        let size = folder_size(&package.folder);
        tally.bytes += size;
        tally.files += 1;
        items.push((package.label, size));
    }
    tally.items = biggest(items.into_iter());
    tally
}

/// pnputil without /force refuses a package a device still uses, which is the last
/// guard under the checks above.
fn clean_old_drivers() -> Tally {
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut tally = Tally::default();
    for package in old_drivers() {
        let size = folder_size(&package.folder);
        let deleted = Command::new(env_path("SystemRoot").join(r"System32\pnputil.exe"))
            .args(["/delete-driver", &package.inf])
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .is_ok_and(|out| out.status.success());
        if deleted && !package.folder.exists() {
            tally.bytes += size;
            tally.files += 1;
        } else {
            tally.skipped += 1;
        }
    }
    tally
}

// The previous Windows after an upgrade, and the setup files of the upgrade itself.
// Their files belong to TrustedInstaller, so Disk Cleanup's own handlers remove them.

const UPGRADE_FOLDERS: [&str; 3] = ["Windows.old", "$WINDOWS.~BT", "$WINDOWS.~WS"];
const UPGRADE_HANDLERS: [&str; 3] = ["Previous Installations", "Temporary Setup Files", "Windows ESD installation files"];
const VOLUME_CACHES: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches";
/// Disk Cleanup runs the handlers that carry this number in their StateFlags.
const SAGE_RUN: u32 = 6587;

fn upgrade_folders() -> Vec<PathBuf> {
    let drive = PathBuf::from(format!("{}\\", system_drive()));
    UPGRADE_FOLDERS.iter().map(|name| drive.join(name)).filter(|path| path.is_dir()).collect()
}

fn windows_old_tally() -> Tally {
    let mut tally = Tally::default();
    let mut items = Vec::new();
    for folder in upgrade_folders() {
        let size = folder_size(&folder);
        tally.bytes += size;
        tally.files += 1;
        items.push((shown(&folder), size));
    }
    tally.items = biggest(items.into_iter());
    tally
}

fn clean_windows_old() -> Tally {
    let before = windows_old_tally();
    if before.files == 0 {
        return before;
    }
    let flag = format!("StateFlags{SAGE_RUN:04}");
    for handler in UPGRADE_HANDLERS {
        let _ = reg::set_dword(reg::HKEY_LOCAL_MACHINE, &format!(r"{VOLUME_CACHES}\{handler}"), &flag, 2);
    }
    let _ = Command::new(env_path("SystemRoot").join(r"System32\cleanmgr.exe"))
        .arg(format!("/sagerun:{SAGE_RUN}"))
        .status();
    for handler in UPGRADE_HANDLERS {
        let _ = reg::delete_value(reg::HKEY_LOCAL_MACHINE, &format!(r"{VOLUME_CACHES}\{handler}"), &flag);
    }
    let after = windows_old_tally();
    Tally {
        bytes: before.bytes.saturating_sub(after.bytes),
        files: before.files - after.files,
        skipped: after.files,
        items: Vec::new(),
    }
}

/// Every profile's cache folders for the Chromium browsers and Firefox. Only caches:
/// cookies, logins and history live elsewhere and are never touched.
fn browser_caches(local: &Path) -> Vec<Target> {
    let mut targets = Vec::new();
    for root in
        [r"Google\Chrome\User Data", r"Microsoft\Edge\User Data", r"BraveSoftware\Brave-Browser\User Data"]
    {
        for profile in subdirs(&local.join(root)) {
            for cache in [r"Cache\Cache_Data", "Code Cache", "GPUCache"] {
                targets.push(Target::contents(profile.join(cache)));
            }
        }
    }
    for profile in subdirs(&local.join(r"Mozilla\Firefox\Profiles")) {
        targets.push(Target::contents(profile.join("cache2")));
    }
    targets
}

fn subdirs(path: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(path)
        .map(|entries| {
            entries.flatten().filter(|e| e.file_type().is_ok_and(|t| t.is_dir())).map(|e| e.path()).collect()
        })
        .unwrap_or_default()
}

fn running_blocker(category: Category) -> Option<&'static str> {
    let blockers = category.blocking_processes();
    if blockers.is_empty() {
        return None;
    }
    let mut found = None;
    crate::memory::for_each_process(|entry| {
        if found.is_none() {
            let name = crate::memory::exe_name(entry);
            found = blockers.iter().copied().find(|b| name.eq_ignore_ascii_case(b));
        }
    });
    found
}

fn recycle_bin_size() -> Tally {
    let mut info = SHQUERYRBINFO { cbSize: size_of::<SHQUERYRBINFO>() as u32, ..Default::default() };
    unsafe {
        let _ = SHQueryRecycleBinW(PCWSTR::null(), &mut info);
    }
    Tally { bytes: info.i64Size as u64, files: info.i64NumItems as u64, ..Default::default() }
}

/// Files last written before this FILETIME value are old enough to go.
fn cutoff(age: Duration) -> u64 {
    let now = unsafe { GetSystemTimeAsFileTime() };
    filetime(now).saturating_sub(age.as_nanos() as u64 / 100)
}

fn filetime(time: FILETIME) -> u64 {
    (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
}

/// Calls `f(size, path)` for every file the target covers. Returning false stops the walk.
fn visit(target: &Target, cutoff: Option<u64>, f: &mut impl FnMut(u64, &Path) -> bool) {
    match target.kind {
        TargetKind::File => {
            if let Ok(meta) = std::fs::symlink_metadata(&target.path)
                && meta.is_file()
            {
                f(meta.len(), &target.path);
            }
        }
        TargetKind::Contents => {
            walk(&target.path, cutoff, None, f);
        }
        TargetKind::Prefix(prefix) => {
            walk(&target.path, cutoff, Some(prefix), f);
        }
    }
}

/// Returns false when `f` asked to stop.
fn walk(
    dir: &Path,
    cutoff: Option<u64>,
    prefix: Option<&str>,
    f: &mut impl FnMut(u64, &Path) -> bool,
) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else { return true };
    for entry in entries.flatten() {
        // On Windows this comes from the directory listing itself, no extra call per file.
        let Ok(meta) = entry.metadata() else { continue };
        if meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            continue;
        }
        let path = entry.path();
        let keep_going = if meta.is_dir() {
            // Prefix filtering only applies to the top level files.
            prefix.is_some() || walk(&path, cutoff, None, f)
        } else {
            // Files unpacked from an archive keep its old dates, but their creation time is
            // when they landed here; the newer of the two decides.
            let touched = meta.last_write_time().max(meta.creation_time());
            let old_enough = cutoff.is_none_or(|limit| touched < limit);
            let wanted = prefix
                .is_none_or(|p| entry.file_name().to_string_lossy().to_ascii_lowercase().starts_with(p));
            !(old_enough && wanted) || f(meta.len(), &path)
        };
        if !keep_going {
            return false;
        }
    }
    true
}

fn delete_file(path: &Path) -> bool {
    let wide = HSTRING::from(path.as_os_str());
    unsafe {
        if DeleteFileW(&wide).is_ok() {
            return true;
        }
        // Read-only files refuse deletion until the flag is cleared.
        let readonly = std::fs::symlink_metadata(path).is_ok_and(|m| m.permissions().readonly());
        readonly && SetFileAttributesW(&wide, FILE_ATTRIBUTE_NORMAL).is_ok() && DeleteFileW(&wide).is_ok()
    }
}

/// Removes empty folders under `dir`, deepest first. The root itself is kept.
fn remove_empty_dirs(dir: &Path, root: bool) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let Ok(kind) = entry.file_type() else { continue };
        if kind.is_dir() && !kind.is_symlink() {
            remove_empty_dirs(&entry.path(), false);
        }
    }
    if !root {
        unsafe {
            let _ = RemoveDirectoryW(&HSTRING::from(dir.as_os_str()));
        }
    }
}

/// Stops a service if it's running. Returns true when it was stopped by us, so the
/// caller knows to start it again.
fn stop_service(name: &str) -> bool {
    with_service(name, SERVICE_STOP | SERVICE_QUERY_STATUS, |service| unsafe {
        let mut status = SERVICE_STATUS::default();
        if QueryServiceStatus(service, &mut status).is_err() || status.dwCurrentState != SERVICE_RUNNING {
            return false;
        }
        match ControlService(service, SERVICE_CONTROL_STOP, &mut status) {
            Ok(()) => {}
            Err(e) if e.code() == ERROR_SERVICE_NOT_ACTIVE.to_hresult() => return false,
            Err(_) => return false,
        }
        // Give it up to ten seconds to let go of its files.
        for _ in 0..40 {
            if QueryServiceStatus(service, &mut status).is_ok() && status.dwCurrentState == SERVICE_STOPPED {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        true
    })
    .unwrap_or(false)
}

fn start_service(name: &str) {
    let _ = with_service(name, SERVICE_START, |service| unsafe { StartServiceW(service, None).is_ok() });
}

fn with_service<T>(name: &str, access: u32, f: impl FnOnce(SC_HANDLE) -> T) -> Option<T> {
    unsafe {
        let manager = OpenSCManagerW(None, None, SC_MANAGER_CONNECT).ok()?;
        let service = OpenServiceW(manager, &HSTRING::from(name), access);
        let result = service.as_ref().ok().map(|&s| f(s));
        if let Ok(service) = service {
            let _ = CloseServiceHandle(service);
        }
        let _ = CloseServiceHandle(manager);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A junction inside the cleaned folder must not lead the delete outside of it.
    #[test]
    fn clean_never_follows_junctions() {
        let base = std::env::temp_dir().join(format!("vantix-junction-test-{}", std::process::id()));
        let target = base.join("target");
        let victim = base.join("victim");
        std::fs::create_dir_all(target.join("sub")).unwrap();
        std::fs::create_dir_all(&victim).unwrap();
        std::fs::write(target.join("a.tmp"), b"junk").unwrap();
        std::fs::write(target.join("sub").join("b.tmp"), b"junk").unwrap();
        std::fs::write(victim.join("keep.txt"), b"precious").unwrap();
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(target.join("link"))
            .arg(&victim)
            .output()
            .unwrap();
        assert!(made.status.success(), "mklink failed");

        let mut tally = Tally::default();
        clean_target(&Target::contents(target.clone()), None, false, &mut tally);

        assert_eq!(tally.files, 2);
        assert!(victim.join("keep.txt").exists(), "followed the junction");
        assert!(target.exists(), "removed the root");
        assert!(!target.join("a.tmp").exists() && !target.join("sub").exists());
        let _ = std::fs::remove_dir(target.join("link"));
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Read-only, prints what each category would free: `cargo test disk_scan -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn disk_scan() {
        for category in Category::ALL {
            let started = std::time::Instant::now();
            match scan(category) {
                Outcome::Done(t) => {
                    println!(
                        "{category:?}: {} MB in {} files ({:?})",
                        t.bytes >> 20,
                        t.files,
                        started.elapsed()
                    );
                    for (name, size) in &t.items {
                        println!("    {:>8} KB  {name}", size >> 10);
                    }
                }
                Outcome::Blocked(p) => println!("{category:?}: blocked by {p}"),
            }
        }
    }
}
