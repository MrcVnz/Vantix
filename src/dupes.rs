//! Duplicate files. The candidates come from the file table (see space.rs), so listing
//! even a large folder is instant. Files of the same size are compared by a hash of their
//! first 64 KB, and the ones still alike by a hash of the whole file. The hash is xxh3,
//! which picks AVX2 or SSE2 at run time and outruns any disk, so the disk sets the pace.
//! Copies go to the Recycle Bin.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::hash::Hasher;
use std::io::Read;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::time::SystemTime;

use twox_hash::XxHash3_64;
use windows::Win32::Foundation::{HANDLE, HWND};
use windows::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
    FILE_ATTRIBUTE_RECALL_ON_OPEN, FILE_FLAG_BACKUP_SEMANTICS, GetFileInformationByHandle,
};
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx, CoTaskMemFree,
};
use windows::Win32::UI::Shell::{
    FO_DELETE, FOF_ALLOWUNDO, FOF_NOCONFIRMATION, FOF_NOERRORUI, FOF_SILENT, FOF_WANTNUKEWARNING, FOLDERID_Desktop,
    FOLDERID_Documents, FOLDERID_Downloads, FOLDERID_Music, FOLDERID_Pictures, FOLDERID_Videos,
    FOS_FORCEFILESYSTEM, FOS_PICKFOLDERS, FileOpenDialog, IFileOpenDialog, KF_FLAG_DEFAULT, SHFILEOPSTRUCTW,
    SHFileOperationW, SHGetKnownFolderPath, SIGDN_FILESYSPATH,
};
use windows::Win32::UI::Shell::Common::COMDLG_FILTERSPEC;
use windows::core::{GUID, PCWSTR, w};

use crate::space;

/// Smaller files hold little space and are many; they're left out.
pub const MIN_SIZE: u64 = 1 << 20;
const HEAD: usize = 64 << 10;
const BUFFER: usize = 1 << 20;

/// What `find` is doing, read by the UI while it runs.
#[derive(Default)]
pub struct Progress {
    /// 0 listing, 1 comparing the first 64 KB, 2 reading whole files.
    pub stage: AtomicU32,
    pub done: AtomicU64,
    pub total: AtomicU64,
    pub cancel: AtomicBool,
}

#[derive(Clone)]
pub struct Copy {
    pub path: PathBuf,
    pub size: u64,
    pub modified: SystemTime,
}

pub struct Group {
    pub size: u64,
    /// Oldest first.
    pub copies: Vec<Copy>,
}

impl Group {
    /// Space freed by keeping one copy.
    pub fn wasted(&self) -> u64 {
        self.size * (self.copies.len() as u64 - 1)
    }
}

/// Desktop, Documents, Downloads, Pictures, Videos and Music: where people's own files
/// are. System and program folders hold copies on purpose and aren't searched unless
/// added.
pub fn default_folders() -> Vec<PathBuf> {
    [
        FOLDERID_Desktop,
        FOLDERID_Documents,
        FOLDERID_Downloads,
        FOLDERID_Pictures,
        FOLDERID_Videos,
        FOLDERID_Music,
    ]
    .iter()
    .filter_map(known_folder)
    .filter(|path| path.is_dir())
    .collect()
}

pub fn downloads() -> Option<PathBuf> {
    known_folder(&FOLDERID_Downloads).filter(|path| path.is_dir())
}

fn known_folder(id: &GUID) -> Option<PathBuf> {
    unsafe {
        let path = SHGetKnownFolderPath(id, KF_FLAG_DEFAULT, None).ok()?;
        let text = path.to_string().ok();
        CoTaskMemFree(Some(path.0 as _));
        text.map(PathBuf::from)
    }
}

/// Windows' folder picker; `None` when cancelled.
pub fn pick_folder(owner: Option<HWND>) -> Option<PathBuf> {
    pick(owner, true)
}

/// Windows' file picker, for one program; `None` when cancelled.
pub fn pick_exe(owner: Option<HWND>) -> Option<PathBuf> {
    pick(owner, false)
}

fn pick(owner: Option<HWND>, folder: bool) -> Option<PathBuf> {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let dialog: IFileOpenDialog = CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER).ok()?;
        let options = dialog.GetOptions().ok()? | FOS_FORCEFILESYSTEM;
        if folder {
            dialog.SetOptions(options | FOS_PICKFOLDERS).ok()?;
        } else {
            dialog.SetOptions(options).ok()?;
            dialog.SetFileTypes(&[COMDLG_FILTERSPEC { pszName: w!("*.exe"), pszSpec: w!("*.exe") }]).ok()?;
        }
        dialog.Show(owner).ok()?;
        let path = dialog.GetResult().ok()?.GetDisplayName(SIGDN_FILESYSPATH).ok()?;
        let text = path.to_string().ok();
        CoTaskMemFree(Some(path.0 as _));
        text.map(PathBuf::from)
    }
}

/// The file table record of a folder, from its file id.
fn record_of(folder: &Path) -> Option<u32> {
    let file = std::fs::OpenOptions::new()
        .access_mode(0)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS.0)
        .open(folder)
        .ok()?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &mut info) }.ok()?;
    let id = (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow);
    Some((id & 0xffff_ffff_ffff) as u32)
}

/// Files of MIN_SIZE or more under `folders`, with their sizes. Fixed NTFS drives are
/// read from their file table; anything else is walked.
fn list(folders: &[PathBuf], cancel: &AtomicBool) -> Vec<(PathBuf, u64)> {
    let ntfs = space::volumes();
    let mut by_drive: HashMap<char, Vec<u32>> = HashMap::new();
    let mut walked = Vec::new();
    for folder in folders {
        let letter = folder.to_str().and_then(|p| p.chars().next()).map(|c| c.to_ascii_uppercase());
        match (letter.filter(|l| ntfs.contains(l)), record_of(folder)) {
            (Some(letter), Some(record)) => by_drive.entry(letter).or_default().push(record),
            _ => walk(folder, &mut walked),
        }
    }
    let mut files = walked;
    for (letter, roots) in by_drive {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let Ok(scan) = space::scan(letter, &AtomicU32::new(0)) else { continue };
        // Folders inside other chosen folders would list their files twice.
        let mut seen = HashSet::new();
        let records: Vec<u32> = roots
            .iter()
            .flat_map(|&root| scan.files_under(root))
            .filter(|&r| scan.length(r) >= MIN_SIZE && seen.insert(r))
            .collect();
        // Only sizes shared by two files or more need their paths.
        let mut sizes: HashMap<u64, u32> = HashMap::new();
        for &r in &records {
            *sizes.entry(scan.length(r)).or_default() += 1;
        }
        let records: Vec<u32> = records.into_iter().filter(|&r| sizes[&scan.length(r)] > 1).collect();
        let paths = scan.paths(&records);
        files.extend(paths.into_iter().zip(&records).map(|(path, &r)| (PathBuf::from(path), scan.length(r))));
    }
    files
}

/// Never follows junctions or links, which could lead outside the folder or loop.
fn walk(folder: &Path, files: &mut Vec<(PathBuf, u64)>) {
    let Ok(entries) = std::fs::read_dir(folder) else { return };
    for entry in entries.flatten() {
        let Ok(kind) = entry.file_type() else { continue };
        if kind.is_dir() {
            walk(&entry.path(), files);
        } else if kind.is_file()
            && let Ok(meta) = entry.metadata()
            && meta.len() >= MIN_SIZE
        {
            files.push((entry.path(), meta.len()));
        }
    }
}

/// Files only in the cloud (OneDrive and the like) would download when read.
fn readable(path: &Path) -> Option<std::fs::Metadata> {
    let meta = std::fs::metadata(path).ok()?;
    let cloud =
        FILE_ATTRIBUTE_OFFLINE.0 | FILE_ATTRIBUTE_RECALL_ON_OPEN.0 | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS.0;
    (meta.file_attributes() & cloud == 0 && meta.is_file()).then_some(meta)
}

/// xxh3 of the first `limit` bytes, or of the whole file; `None` if it can't be read
/// or the search was cancelled.
fn hash(path: &Path, limit: u64, progress: &Progress) -> Option<u64> {
    let mut file = File::open(path).ok()?.take(limit);
    let mut buffer = vec![0u8; BUFFER.min(limit as usize)];
    let mut hasher = XxHash3_64::with_seed(0);
    loop {
        if progress.cancel.load(Ordering::Relaxed) {
            return None;
        }
        let n = file.read(&mut buffer).ok()?;
        if n == 0 {
            return Some(hasher.finish());
        }
        hasher.write(&buffer[..n]);
        progress.done.fetch_add(n as u64, Ordering::Relaxed);
    }
}

/// Runs `f` over `items` on a few threads: enough to keep an SSD busy without
/// thrashing a hard drive much.
fn par_map<T: Sync, R: Send>(items: &[T], f: impl Fn(&T) -> R + Sync) -> Vec<R> {
    let next = AtomicUsize::new(0);
    let results: Mutex<Vec<Option<R>>> = Mutex::new((0..items.len()).map(|_| None).collect());
    let threads = std::thread::available_parallelism().map_or(2, |n| n.get()).min(4);
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(item) = items.get(i) else { break };
                    let result = f(item);
                    results.lock().unwrap()[i] = Some(result);
                }
            });
        }
    });
    results.into_inner().unwrap().into_iter().map(|r| r.unwrap()).collect()
}

/// Keeps the files whose key is shared with another one.
fn shared<K: std::hash::Hash + Eq + Clone, T>(items: Vec<(K, T)>) -> Vec<(K, T)> {
    let mut counts: HashMap<K, u32> = HashMap::new();
    for (key, _) in &items {
        *counts.entry(key.clone()).or_default() += 1;
    }
    items.into_iter().filter(|(key, _)| counts[key] > 1).collect()
}

/// Groups of identical files under `folders`, the most space wasted first. `None` when
/// cancelled.
pub fn find(folders: &[PathBuf], progress: &Progress) -> Option<Vec<Group>> {
    progress.stage.store(0, Ordering::Relaxed);
    let files = list(folders, &progress.cancel);
    let files: Vec<(u64, PathBuf)> = shared(files.into_iter().map(|(path, size)| (size, path)).collect());

    progress.stage.store(1, Ordering::Relaxed);
    progress.done.store(0, Ordering::Relaxed);
    progress.total.store(files.iter().map(|(size, _)| (*size).min(HEAD as u64)).sum(), Ordering::Relaxed);
    let heads = par_map(&files, |(_, path)| readable(path).and(hash(path, HEAD as u64, progress)));
    if progress.cancel.load(Ordering::Relaxed) {
        return None;
    }
    let alike: Vec<((u64, u64), PathBuf)> = shared(
        files.into_iter().zip(heads).filter_map(|((size, path), head)| Some(((size, head?), path))).collect(),
    );

    progress.stage.store(2, Ordering::Relaxed);
    progress.done.store(0, Ordering::Relaxed);
    progress.total.store(alike.iter().map(|((size, _), _)| *size).sum(), Ordering::Relaxed);
    let wholes = par_map(&alike, |((size, head), path)| {
        // Files no larger than the head were hashed whole already.
        let whole = if *size <= HEAD as u64 { Some(*head) } else { hash(path, u64::MAX, progress) };
        Some((whole?, readable(path)?.modified().ok()?))
    });
    if progress.cancel.load(Ordering::Relaxed) {
        return None;
    }
    let mut groups: HashMap<(u64, u64), Vec<Copy>> = HashMap::new();
    for (((size, _), path), whole) in alike.into_iter().zip(wholes) {
        if let Some((whole, modified)) = whole {
            groups.entry((size, whole)).or_default().push(Copy { path, size, modified });
        }
    }
    let mut groups: Vec<Group> = groups
        .into_iter()
        .filter(|(_, copies)| copies.len() > 1)
        .map(|((size, _), mut copies)| {
            copies.sort_by_key(|c| c.modified);
            Group { size, copies }
        })
        .collect();
    groups.sort_by_key(|g| std::cmp::Reverse(g.wasted()));
    Some(groups)
}

/// Moves `copies` to the Recycle Bin one by one, so a file that's open elsewhere only
/// keeps itself back. Skips any that changed since they were compared. Returns the ones
/// that are gone.
pub fn recycle(copies: &[Copy]) -> Vec<PathBuf> {
    copies
        .iter()
        .filter(|c| {
            readable(&c.path).is_some_and(|m| m.len() == c.size && m.modified().ok() == Some(c.modified))
        })
        .filter(|c| recycle_file(&c.path))
        .map(|c| c.path.clone())
        .collect()
}

/// Moves one file to the Recycle Bin and says whether it's gone from where it was.
pub fn recycle_file(path: &Path) -> bool {
    // The path, then the extra null that ends the list.
    let from: Vec<u16> = path.as_os_str().encode_wide().chain([0, 0]).collect();
    let mut operation = SHFILEOPSTRUCTW {
        wFunc: FO_DELETE,
        pFrom: PCWSTR(from.as_ptr()),
        // A drive without a Recycle Bin, such as a USB stick, would delete for good;
        // Windows asks first then.
        fFlags: (FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI | FOF_WANTNUKEWARNING).0 as u16,
        ..Default::default()
    };
    let _ = unsafe { SHFileOperationW(&mut operation) };
    !path.exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_copies_and_ignores_lookalikes() {
        let dir = std::env::temp_dir().join(format!("vantix-dupes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        let data: Vec<u8> = (0..3 * MIN_SIZE as usize).map(|i| (i * 7 % 251) as u8).collect();
        std::fs::write(dir.join("a.bin"), &data).unwrap();
        std::fs::write(dir.join("sub").join("b.bin"), &data).unwrap();
        // Same size and first 64 KB, different end.
        let mut other = data.clone();
        *other.last_mut().unwrap() ^= 1;
        std::fs::write(dir.join("c.bin"), &other).unwrap();
        std::fs::write(dir.join("small.bin"), &data[..1000]).unwrap();
        std::fs::write(dir.join("small2.bin"), &data[..1000]).unwrap();

        let groups = find(std::slice::from_ref(&dir), &Progress::default()).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(groups.len(), 1);
        let names: HashSet<_> =
            groups[0].copies.iter().map(|c| c.path.file_name().unwrap().to_owned()).collect();
        assert_eq!(names, HashSet::from(["a.bin".into(), "b.bin".into()]));
        assert_eq!(groups[0].wasted(), data.len() as u64);
    }

    /// Sends a copy to the real Recycle Bin and checks that one changed since the search
    /// stays: `cargo test dupes_recycle -- --ignored`
    #[test]
    #[ignore]
    fn dupes_recycle() {
        let dir = std::env::temp_dir().join(format!("vantix-dupes-recycle-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let data = vec![9u8; MIN_SIZE as usize];
        for name in ["keep.bin", "go.bin", "changed.bin"] {
            std::fs::write(dir.join(name), &data).unwrap();
        }
        let groups = find(std::slice::from_ref(&dir), &Progress::default()).unwrap();
        let copies: Vec<Copy> =
            groups[0].copies.iter().filter(|c| !c.path.ends_with("keep.bin")).cloned().collect();
        std::fs::write(dir.join("changed.bin"), vec![8u8; MIN_SIZE as usize]).unwrap();
        let gone = recycle(&copies);
        let left: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().file_name()).collect();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(gone.len(), 1, "{gone:?}");
        assert!(gone[0].ends_with("go.bin"));
        assert_eq!(left.len(), 2, "{left:?}");
    }

    /// xxh3 speed in memory, which shows whether the AVX2 path runs:
    /// `cargo test --release dupes_hash_speed -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn dupes_hash_speed() {
        let data = vec![7u8; 1 << 30];
        let start = std::time::Instant::now();
        let mut hasher = XxHash3_64::with_seed(0);
        for chunk in data.chunks(BUFFER) {
            hasher.write(chunk);
        }
        std::hint::black_box(hasher.finish());
        let seconds = start.elapsed().as_secs_f64();
        println!("xxh3: {:.1} GB/s, avx2 {}", 1.0 / seconds, is_x86_feature_detected!("avx2"));
    }
}
