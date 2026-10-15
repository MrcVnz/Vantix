//! Updates from GitHub Releases: asks for the latest release, downloads its exe, checks it
//! against the SHA-256 published next to it and swaps it in for the running one. Every
//! call here blocks, so run them off the UI thread.

use std::fs;
use std::io;
use std::io::{Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Networking::WinHttp::{WinHttpReadData, WinHttpSendRequest, WinHttpSetTimeouts};
use windows::Win32::Security::Cryptography::{BCRYPT_SHA256_ALG_HANDLE, BCryptHash};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, WaitForSingleObject};
use windows::Win32::Storage::FileSystem::{FILE_SHARE_READ, ReplaceFileW, REPLACE_FILE_FLAGS};
use windows::core::HSTRING;

use crate::{net, settings};

const LATEST: &str = "https://api.github.com/repos/MrcVnz/Vantix/releases/latest";
/// Every release carries these two assets: the exe and its hash, as `sha256sum` writes it.
const EXE: &str = "vantix.exe";
const SHA: &str = "vantix.exe.sha256";
/// Passed to the new exe with the old one's pid, see `wait_for_old`.
const UPDATED_ARG: &str = "--updated";
/// Where the release notes of an installed update wait to be read, in the data folder.
const NOTES: &str = "whats-new.json";

#[derive(Clone, Debug)]
pub struct Release {
    /// As "1.2.0", without the v of the tag.
    pub version: String,
    /// The release body, Markdown as written on GitHub.
    pub notes: String,
    pub size: u64,
    exe: String,
    sha: String,
    /// The hash the download matched, checked again right before the swap.
    hash: Option<[u8; 32]>,
}

pub enum Check {
    Current,
    Newer(Release),
    /// Nothing published yet. GitHub also says so for a private repo.
    NoReleases,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No answer at all: offline, DNS, a proxy or a timeout.
    Offline,
    /// An answer other than 200, like the 403 of the hourly limit.
    Refused(u32),
    Unreadable,
    /// The release is out without the exe or its hash.
    NoExe,
    /// The download didn't match its hash and was thrown away.
    BadHash,
    /// The download couldn't be saved.
    Disk,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Offline => write!(f, "no answer from GitHub"),
            Error::Refused(status) => write!(f, "GitHub answered {status}"),
            Error::Unreadable => write!(f, "unreadable answer"),
            Error::NoExe => write!(f, "the release has no {EXE} and {SHA}"),
            Error::BadHash => write!(f, "the download doesn't match its SHA-256"),
            Error::Disk => write!(f, "the download couldn't be saved"),
        }
    }
}

#[derive(Deserialize)]
struct Answer {
    tag_name: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    size: u64,
}

pub fn check() -> Result<Check, Error> {
    let (status, body) = get(LATEST, Some("Accept: application/vnd.github+json"), 1 << 20, None)?;
    match status {
        200 => {}
        404 => return Ok(Check::NoReleases),
        status => return Err(Error::Refused(status)),
    }
    let answer: Answer = serde_json::from_slice(&body).map_err(|_| Error::Unreadable)?;
    let version = parse_version(&answer.tag_name).ok_or(Error::Unreadable)?;
    if answer.draft || answer.prerelease || !newer(version, parse_version(env!("CARGO_PKG_VERSION"))) {
        return Ok(Check::Current);
    }
    let asset = |name: &str| answer.assets.iter().find(|a| a.name.eq_ignore_ascii_case(name));
    let (Some(exe), Some(sha)) = (asset(EXE), asset(SHA)) else { return Err(Error::NoExe) };
    Ok(Check::Newer(Release {
        version: format!("{}.{}.{}", version[0], version[1], version[2]),
        notes: answer.body.clone().unwrap_or_default(),
        size: exe.size,
        exe: exe.browser_download_url.clone(),
        sha: sha.browser_download_url.clone(),
        hash: None,
    }))
}

/// "v1.2.3" or "1.2" as numbers; anything else, like a "-beta" suffix, isn't a version.
fn parse_version(tag: &str) -> Option<[u32; 3]> {
    let mut version = [0; 3];
    let mut parts = tag.trim().trim_start_matches(['v', 'V']).split('.');
    for (slot, part) in version.iter_mut().zip(parts.by_ref()) {
        *slot = part.parse().ok()?;
    }
    parts.next().is_none().then_some(version)
}

fn newer(release: [u32; 3], running: Option<[u32; 3]>) -> bool {
    running.is_none_or(|running| release > running)
}

/// Downloads the release's exe into the data folder and returns where it is. It's only
/// written once its hash matches, so a bad download leaves nothing behind, and the hash
/// stays on `release` for `install`. `done` counts the bytes as they come.
pub fn download(release: &mut Release, done: &AtomicU64) -> Result<PathBuf, Error> {
    let (status, sha) = get(&release.sha, None, 4096, None)?;
    if status != 200 {
        return Err(Error::Refused(status));
    }
    let want = parse_sha(&sha).ok_or(Error::Unreadable)?;
    let (status, exe) = get(&release.exe, None, 256 << 20, Some(done))?;
    if status != 200 {
        return Err(Error::Refused(status));
    }
    if sha256(&exe) != Some(want) {
        return Err(Error::BadHash);
    }
    let dir = settings::data_dir().join("update");
    let path = dir.join(EXE);
    fs::create_dir_all(&dir).and_then(|()| fs::write(&path, &exe)).map_err(|_| Error::Disk)?;
    release.hash = Some(want);
    Ok(path)
}

/// The first word of the file, which `sha256sum` follows with the file name.
fn parse_sha(text: &[u8]) -> Option<[u8; 32]> {
    let hex = std::str::from_utf8(text).ok()?.split_whitespace().next()?;
    if hex.len() != 64 {
        return None;
    }
    let mut hash = [0; 32];
    for (byte, pair) in hash.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(hash)
}

fn sha256(data: &[u8]) -> Option<[u8; 32]> {
    let mut hash = [0; 32];
    unsafe { BCryptHash(BCRYPT_SHA256_ALG_HANDLE, None, data, &mut hash) }.ok().ok()?;
    Some(hash)
}

/// GET over HTTPS, following redirects, as GitHub's asset links need. Gives the status
/// and up to `limit` bytes of the body.
fn get(
    url: &str,
    header: Option<&str>,
    limit: usize,
    done: Option<&AtomicU64>,
) -> Result<(u32, Vec<u8>), Error> {
    let (host, port, path) = split_url(url).ok_or(Error::Unreadable)?;
    let (_session, connection) = net::http_connection(host, port).ok_or(Error::Offline)?;
    let request = net::request(&connection, "GET", path).ok_or(Error::Offline)?;
    // Longer waits than the network tests use: a slow line, or an antivirus looking at
    // the exe on its way in, can hold the first bytes for a while.
    unsafe { WinHttpSetTimeouts(request.0, 10_000, 10_000, 10_000, 30_000) }.map_err(|_| Error::Offline)?;
    let header: Option<Vec<u16>> = header.map(|h| h.encode_utf16().collect());
    unsafe { WinHttpSendRequest(request.0, header.as_deref(), None, 0, 0, 0) }.map_err(|_| Error::Offline)?;
    let status = net::status(&request).ok_or(Error::Offline)?;
    let mut body = Vec::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let mut read = 0;
        unsafe { WinHttpReadData(request.0, buffer.as_mut_ptr().cast(), buffer.len() as u32, &mut read) }
            .map_err(|_| Error::Offline)?;
        if read == 0 {
            break;
        }
        if body.len() + read as usize > limit {
            return Err(Error::Unreadable);
        }
        body.extend_from_slice(&buffer[..read as usize]);
        if let Some(done) = done {
            done.store(body.len() as u64, Ordering::Relaxed);
        }
    }
    Ok((status, body))
}

/// Host, port and path of an https URL.
fn split_url(url: &str) -> Option<(&str, u16, &str)> {
    let rest = url.strip_prefix("https://")?;
    let (authority, path) = rest.find('/').map_or((rest, "/"), |at| rest.split_at(at));
    match authority.rsplit_once(':') {
        Some((host, port)) => Some((host, port.parse().ok()?, path)),
        None => Some((authority, 443, path)),
    }
}

#[derive(Serialize, Deserialize)]
struct WhatsNew {
    version: String,
    notes: String,
}

/// Swaps the downloaded exe in for the running one and starts it. A running exe can be
/// renamed but not overwritten, so it steps aside as `<name>.old.exe`, which the new one
/// deletes once this one is gone. The path stays the same, so the logon task still
/// points at it. Anything that fails puts the old exe back. The caller then quits.
///
/// The download sat in the data folder, which programs without admin can write, and
/// the new exe runs as admin. So it's read once more and the bytes that match the hash
/// are the ones written, never the file as it is by then.
pub fn install(new: &Path, release: &Release) -> io::Result<()> {
    let bytes = fs::read(new)?;
    if release.hash.is_none() || sha256(&bytes) != release.hash {
        let _ = fs::remove_file(new);
        return Err(io::Error::new(io::ErrorKind::InvalidData, "the download changed after it was checked"));
    }
    let exe = std::env::current_exe()?;
    let old = old_exe(&exe);
    let _pinned = crate::fs_guard::pin_directory(exe.parent().ok_or_else(|| io::Error::other("missing executable directory"))?)?;
    // Finish and flush the new image before touching the running executable.
    let staged = exe.with_extension(format!("new-{}", std::process::id()));
    let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&staged)?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&staged);
        return Err(error);
    }
    drop(file);
    // Written first, so the new exe finds them however fast it starts. Notes left over
    // from a swap that failed name another version and stay hidden.
    let notes = WhatsNew { version: release.version.clone(), notes: release.notes.clone() };
    if let Ok(json) = serde_json::to_vec(&notes) {
        let _ = fs::write(settings::data_dir().join(NOTES), json);
    }
    let result = swap_prepared(&exe, &staged, &old, || {
        // A portable directory can be writable by other processes. Verify the installed
        // image while holding it against writes and replacement until CreateProcess ends.
        let mut image = fs::OpenOptions::new().read(true).share_mode(FILE_SHARE_READ.0).open(&exe)?;
        let mut installed = Vec::new();
        image.read_to_end(&mut installed)?;
        if sha256(&installed) != release.hash {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "the installed update changed"));
        }
        Command::new(&exe).arg(UPDATED_ARG).arg(std::process::id().to_string()).spawn().map(drop)
    });
    let _ = fs::remove_file(&staged);
    let _ = fs::remove_file(new);
    result
}

fn replace(exe: &Path, replacement: &Path, backup: Option<&Path>) -> io::Result<()> {
    let backup = backup.map(|path| HSTRING::from(path.as_os_str()));
    unsafe {
        ReplaceFileW(
            &HSTRING::from(exe.as_os_str()), &HSTRING::from(replacement.as_os_str()),
            backup.as_ref().map(|path| windows::core::PCWSTR(path.as_ptr())).unwrap_or(windows::core::PCWSTR::null()),
            REPLACE_FILE_FLAGS(0), None, None,
        )
    }.map_err(|error| io::Error::from_raw_os_error(error.code().0 & 0xffff))
}

fn swap_prepared(exe: &Path, staged: &Path, old: &Path, launch: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
    match fs::remove_file(old) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if let Err(error) = replace(exe, staged, Some(old)) {
        // ReplaceFile can report a partial failure. Never remove the backup to hide it.
        if !exe.exists() && old.exists() {
            fs::rename(old, exe).map_err(|restore| io::Error::other(format!("{error}; recovery failed: {restore}; backup: {}", old.display())))?;
        }
        return Err(error);
    }
    if let Err(error) = launch() {
        replace(exe, old, None).map_err(|restore| io::Error::other(format!("{error}; recovery failed: {restore}; backup: {}", old.display())))?;
        return Err(error);
    }
    Ok(())
}

fn updated() -> bool {
    std::env::args().any(|arg| arg == UPDATED_ARG)
}

/// When an exe an update just started crashes before it settled: the old exe goes back
/// in its place and starts again, so a broken release can't leave nothing that opens.
/// The broken one stays beside it as `<name>.failed.exe` until the next start.
pub fn roll_back() {
    if !updated() {
        return;
    }
    let Ok(exe) = std::env::current_exe() else { return };
    let old = old_exe(&exe);
    if !old.exists() {
        return;
    }
    let failed = exe.with_file_name(format!("{}.failed.exe", exe.file_stem().unwrap_or_default().to_string_lossy()));
    if let Err(error) = replace(&exe, &old, Some(&failed)) {
        crate::system::log_error("restore previous executable", &error);
    } else {
        let _ = fs::remove_file(settings::data_dir().join(NOTES));
        // It waits for this one to end, which still holds the single-instance lock.
        if let Err(error) = Command::new(&exe).arg(UPDATED_ARG).arg(std::process::id().to_string()).spawn() {
            crate::system::log_error("start previous executable", &error);
        }
    }
}

/// Called once the window has been up for a while: from then on a crash isn't the
/// update's fault, and the old exe can go.
pub fn settled() {
    if let Ok(exe) = std::env::current_exe() {
        delete_soon(&old_exe(&exe));
    }
}

fn delete_soon(path: &Path) {
    // Windows may still hold an exe for a moment after its process ended.
    for _ in 0..10 {
        if fs::remove_file(path).is_ok() || !path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}

fn old_exe(exe: &Path) -> PathBuf {
    let stem = exe.file_stem().unwrap_or_default().to_string_lossy();
    exe.with_file_name(format!("{stem}.old.exe"))
}

/// In the exe an update just started: waits for the one it replaced to finish closing,
/// which puts back what its governor changed, so the single-instance check that follows
/// doesn't send this one away.
pub fn wait_for_old() {
    let mut args = std::env::args().skip_while(|arg| arg != UPDATED_ARG).skip(1);
    let Some(pid) = args.next().and_then(|pid| pid.parse::<u32>().ok()) else { return };
    unsafe {
        if let Ok(process) = OpenProcess(PROCESS_SYNCHRONIZE, false, pid) {
            WaitForSingleObject(process, 30_000);
            let _ = CloseHandle(process);
        }
    }
}

/// On every start: deletes what an update leaves behind, the download, a release that
/// was rolled back and the old exe. Right after an update the old exe waits for
/// `settled`, so `roll_back` still has it. Only once this is the one instance, so a
/// second launch can't take the download away from the one running.
pub fn clean_up() {
    if let Ok(exe) = std::env::current_exe() {
        let stem = exe.file_stem().unwrap_or_default().to_string_lossy().into_owned();
        delete_soon(&exe.with_file_name(format!("{stem}.failed.exe")));
        if !updated() {
            delete_soon(&old_exe(&exe));
        }
    }
    let _ = fs::remove_dir_all(settings::data_dir().join("update"));
}

/// The notes of the update that brought this version, until they're dismissed.
pub fn whats_new() -> Option<String> {
    let text = fs::read(settings::data_dir().join(NOTES)).ok()?;
    let notes: WhatsNew = serde_json::from_slice(&text).ok()?;
    (notes.version == env!("CARGO_PKG_VERSION")).then(|| plain(&notes.notes))
}

pub fn dismiss_whats_new() {
    let _ = fs::remove_file(settings::data_dir().join(NOTES));
}

/// Release notes as plain text: headings lose their #, list items get a bullet and bold
/// markers go.
fn plain(markdown: &str) -> String {
    let lines: Vec<String> = markdown
        .lines()
        .map(|line| {
            let line = line.trim_end().replace("**", "");
            let indent = line.len() - line.trim_start().len();
            let text = line.trim_start();
            if let Some(item) = text.strip_prefix("- ").or_else(|| text.strip_prefix("* ")) {
                format!("{}• {item}", " ".repeat(indent))
            } else {
                text.trim_start_matches('#').trim_start().to_string()
            }
        })
        .collect();
    lines.join("\n").trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_keeps_backup_and_restores_on_launch_failure() {
        use windows::Win32::Storage::FileSystem::FILE_SHARE_DELETE;
        let dir = std::env::temp_dir().join(format!("vantix-swap-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("app.exe");
        let staged = dir.join("app.new");
        let old = dir.join("app.old.exe");
        fs::write(&exe, b"old").unwrap();
        fs::write(&staged, b"new").unwrap();
        // A running image can be read and renamed, but cannot be written in place.
        let running = fs::OpenOptions::new().read(true)
            .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_DELETE.0).open(&exe).unwrap();
        swap_prepared(&exe, &staged, &old, || {
            assert_eq!(fs::read(&exe).unwrap(), b"new");
            assert_eq!(fs::read(&old).unwrap(), b"old");
            Ok(())
        }).unwrap();
        drop(running);

        fs::write(&staged, b"broken").unwrap();
        assert!(swap_prepared(&exe, &staged, &old, || Err(io::Error::other("cannot launch"))).is_err());
        assert_eq!(fs::read(&exe).unwrap(), b"new");
        assert!(swap_prepared(&exe, &dir.join("missing"), &old, || Ok(())).is_err());
        assert_eq!(fs::read(&exe).unwrap(), b"new");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn versions() {
        assert_eq!(parse_version("v1.2.3"), Some([1, 2, 3]));
        assert_eq!(parse_version("0.2"), Some([0, 2, 0]));
        assert_eq!(parse_version("v1.2.3-beta"), None);
        assert_eq!(parse_version("1.2.3.4"), None);
        assert_eq!(parse_version("latest"), None);
        assert!(newer([0, 2, 0], Some([0, 1, 9])));
        assert!(newer([0, 10, 0], Some([0, 9, 0])));
        assert!(!newer([0, 1, 0], Some([0, 1, 0])));
        assert!(!newer([0, 0, 9], Some([0, 1, 0])));
    }

    #[test]
    fn hashes() {
        let line = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  vantix.exe\n";
        assert_eq!(parse_sha(line), sha256(b""));
        let upper = b"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        assert_eq!(parse_sha(upper), sha256(b""));
        assert_eq!(parse_sha(b"e3b0c442"), None);
        assert_eq!(parse_sha(b"zz"), None);
    }

    #[test]
    fn urls() {
        assert_eq!(split_url(LATEST), Some(("api.github.com", 443, "/repos/MrcVnz/Vantix/releases/latest")));
        assert_eq!(split_url("https://example.com:8443"), Some(("example.com", 8443, "/")));
        assert_eq!(split_url("http://example.com/a"), None);
    }

    #[test]
    fn notes_as_text() {
        let md = "## What's new\r\n\r\n- **Monitor** lists every process\n  * per pid\n# Fixes";
        assert_eq!(plain(md), "What's new\n\n• Monitor lists every process\n  • per pid\nFixes");
    }

    /// Asks GitHub for real. The repo has no release yet, or is private, so this sees
    /// NoReleases; once one is out it should see Current.
    #[test]
    #[ignore]
    fn asks_github() {
        match check() {
            Ok(Check::NoReleases) => println!("no releases"),
            Ok(Check::Current) => println!("current"),
            Ok(Check::Newer(release)) => println!("newer: {}", release.version),
            Err(e) => panic!("{e}"),
        }
    }
}
