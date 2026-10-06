//! Disk cleanup: measures and deletes known cache and junk locations.
//!
//! Walks never follow reparse points (a junction inside a temp folder must not lead the
//! delete elsewhere) and skip anything in use instead of failing. They use std::fs::read_dir:
//! a hand rolled FindFirstFileExW walk with large fetch measured no faster on 99k files.

use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

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
use windows::core::{HSTRING, PCWSTR};

/// Order matches the rows in ui/storage.slint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    UserTemp,
    WindowsTemp,
    UpdateCache,
    DeliveryOptimization,
    CrashDumps,
    ErrorReports,
    ShaderCache,
    Thumbnails,
    BrowserCache,
    RecycleBin,
}

impl Category {
    pub const ALL: [Category; 10] = [
        Category::UserTemp,
        Category::WindowsTemp,
        Category::UpdateCache,
        Category::DeliveryOptimization,
        Category::CrashDumps,
        Category::ErrorReports,
        Category::ShaderCache,
        Category::Thumbnails,
        Category::BrowserCache,
        Category::RecycleBin,
    ];

    /// Whether it starts selected. The rest have a visible cost (recompiles, rebuilds,
    /// lost files) and stay opt-in.
    pub fn selected_by_default(self) -> bool {
        !matches!(
            self,
            Category::ShaderCache | Category::Thumbnails | Category::BrowserCache | Category::RecycleBin
        )
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
        matches!(self, Category::UserTemp | Category::WindowsTemp).then_some(Duration::from_secs(24 * 3600))
    }

    /// Browsers lock and rewrite their cache while open.
    fn blocking_processes(self) -> &'static [&'static str] {
        match self {
            Category::BrowserCache => &["chrome.exe", "msedge.exe", "brave.exe", "firefox.exe", "opera.exe"],
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
            Category::Thumbnails => {
                vec![Target::matching(local.join(r"Microsoft\Windows\Explorer"), "thumbcache_")]
            }
            Category::BrowserCache => browser_caches(&local),
            Category::RecycleBin => Vec::new(),
        }
    }
}

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

#[derive(Clone, Copy, Debug, Default)]
pub struct Tally {
    pub bytes: u64,
    pub files: u64,
    /// Files that were in use or protected and stayed.
    pub skipped: u64,
}

pub enum Outcome {
    Done(Tally),
    /// A process listed in `blocking_processes` is running; nothing was touched.
    Blocked(&'static str),
}

pub fn scan(category: Category) -> Outcome {
    if let Some(process) = running_blocker(category) {
        return Outcome::Blocked(process);
    }
    if category == Category::RecycleBin {
        return Outcome::Done(recycle_bin_size());
    }
    let mut tally = Tally::default();
    let cutoff = category.min_age().map(cutoff);
    for target in category.targets() {
        visit(&target, cutoff, &mut |size, _| {
            tally.bytes += size;
            tally.files += 1;
            true
        });
    }
    Outcome::Done(tally)
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
        });
    }

    let stopped: Vec<&str> = category.services().iter().copied().filter(|name| stop_service(name)).collect();
    let mut tally = Tally::default();
    let cutoff = category.min_age().map(cutoff);
    for target in category.targets() {
        clean_target(&target, cutoff, &mut tally);
    }
    for name in stopped {
        start_service(name);
    }
    Outcome::Done(tally)
}

fn clean_target(target: &Target, cutoff: Option<u64>, tally: &mut Tally) {
    visit(target, cutoff, &mut |size, path| {
        if delete_file(path) {
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
    Tally { bytes: info.i64Size as u64, files: info.i64NumItems as u64, skipped: 0 }
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
            let old_enough = cutoff.is_none_or(|limit| meta.last_write_time() < limit);
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
        clean_target(&Target::contents(target.clone()), None, &mut tally);

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
                    )
                }
                Outcome::Blocked(p) => println!("{category:?}: blocked by {p}"),
            }
        }
    }
}
