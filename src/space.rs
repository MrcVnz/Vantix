//! Disk space by folder, read straight from the NTFS file table (the $MFT) the way
//! WizTree does: one sequential read of the table instead of opening every folder, so a
//! full drive takes seconds. Only parents and sizes are kept, about 25 bytes a file; the
//! names of the rows on screen are read back from the table when shown.

use std::collections::HashMap;
use std::fs::File;
use std::os::windows::fs::{FileExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    FILE_SHARE_READ, FILE_SHARE_WRITE, GetDriveTypeW, GetLogicalDrives, GetVolumeInformationW,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{
    FSCTL_GET_NTFS_FILE_RECORD, FSCTL_GET_NTFS_VOLUME_DATA, NTFS_FILE_RECORD_INPUT_BUFFER,
    NTFS_VOLUME_DATA_BUFFER,
};
use windows::core::HSTRING;

/// The record of the volume's root folder.
pub const ROOT: u32 = 5;
const NONE: u32 = u32::MAX;
const DRIVE_FIXED: u32 = 3;

const FILE_NAME: u32 = 0x30;
const DATA: u32 = 0x80;
const END: u32 = 0xffff_ffff;
const IN_USE: u16 = 1;
const DIRECTORY: u16 = 2;
/// $FILE_NAME namespace of the 8.3 short name, used only when there's no other.
const DOS_NAME: u8 = 2;

/// Letters of the fixed NTFS drives, the ones whose file table can be read.
pub fn volumes() -> Vec<char> {
    let mask = unsafe { GetLogicalDrives() };
    (0..26u8)
        .filter(|i| mask & (1 << i) != 0)
        .map(|i| char::from(b'A' + i))
        .filter_map(|letter| {
            let root = HSTRING::from(format!("{letter}:\\"));
            if unsafe { GetDriveTypeW(&root) } != DRIVE_FIXED {
                return None;
            }
            let mut fs = [0u16; 32];
            unsafe { GetVolumeInformationW(&root, None, None, None, None, Some(&mut fs)) }.ok()?;
            let len = fs.iter().position(|&c| c == 0).unwrap_or(fs.len());
            if String::from_utf16_lossy(&fs[..len]) != "NTFS" {
                return None;
            }
            Some(letter)
        })
        .collect()
}

fn open(letter: char) -> std::io::Result<File> {
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE).0)
        .open(format!(r"\\.\{letter}:"))
}

fn read_at(file: &File, mut buffer: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    while !buffer.is_empty() {
        let n = file.seek_read(buffer, offset)?;
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buffer = &mut buffer[n..];
        offset += n as u64;
    }
    Ok(())
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// A file reference is a 48-bit record number and a 16-bit reuse counter.
fn record_of(reference: u64) -> u32 {
    (reference & 0xffff_ffff_ffff) as u32
}

/// Puts back the last two bytes of each 512-byte stride, which NTFS swaps for a check
/// value on disk. False when the record is torn or isn't a file record.
fn fixup(record: &mut [u8]) -> bool {
    if record.len() < 48 || &record[..4] != b"FILE" {
        return false;
    }
    let (offset, count) = (usize::from(u16_at(record, 4)), usize::from(u16_at(record, 6)));
    if count < 2 || offset + count * 2 > record.len() {
        return false;
    }
    let stride = record.len() / (count - 1);
    let check = [record[offset], record[offset + 1]];
    for i in 1..count {
        let end = i * stride;
        // Records handed out by FSCTL_GET_NTFS_FILE_RECORD already have it undone.
        if record[end - 2..end] == check {
            record[end - 2] = record[offset + i * 2];
            record[end - 1] = record[offset + i * 2 + 1];
        }
    }
    true
}

struct Attribute<'a> {
    kind: u32,
    resident: bool,
    named: bool,
    /// The whole attribute, header included.
    bytes: &'a [u8],
}

impl Attribute<'_> {
    fn value(&self) -> Option<&[u8]> {
        let (len, at) = (u32_at(self.bytes, 16) as usize, usize::from(u16_at(self.bytes, 20)));
        self.bytes.get(at..at + len)
    }

    /// Bytes it takes on disk, from the runs that really are on it: the allocated size
    /// in the header counts holes in sparse streams, and $BadClus:$Bad claims the whole
    /// drive that way. Resident values live inside the record. A long attribute is split
    /// over records, each with its own runs, so every part counts.
    fn on_disk(&self, cluster: u64) -> u64 {
        if self.resident || self.bytes.len() < 64 {
            return 0;
        }
        self.runs().iter().map(|&(_, clusters)| clusters * cluster).sum()
    }

    /// Where a non-resident attribute lives: (first cluster, clusters) per run.
    fn runs(&self) -> Vec<(i64, u64)> {
        let mut runs = Vec::new();
        let mut at = usize::from(u16_at(self.bytes, 32));
        let mut lcn = 0i64;
        while let Some(&head) = self.bytes.get(at) {
            let (len_size, offset_size) = (usize::from(head & 0xf), usize::from(head >> 4));
            if head == 0 || at + 1 + len_size + offset_size > self.bytes.len() {
                break;
            }
            let mut length = 0u64;
            for i in 0..len_size {
                length |= u64::from(self.bytes[at + 1 + i]) << (8 * i);
            }
            let mut delta = 0i64;
            for i in 0..offset_size {
                delta |= i64::from(self.bytes[at + 1 + len_size + i]) << (8 * i);
            }
            if offset_size > 0 {
                // Sign-extend the delta from its stored width.
                let shift = 64 - 8 * offset_size as u32;
                lcn += (delta << shift) >> shift;
                runs.push((lcn, length));
            }
            at += 1 + len_size + offset_size;
        }
        runs
    }
}

fn attributes(record: &[u8]) -> impl Iterator<Item = Attribute<'_>> {
    let mut at = usize::from(u16_at(record, 20));
    std::iter::from_fn(move || {
        if at + 24 > record.len() {
            return None;
        }
        let kind = u32_at(record, at);
        let len = u32_at(record, at + 4) as usize;
        if kind == END || len < 24 || at + len > record.len() {
            return None;
        }
        let bytes = &record[at..at + len];
        at += len;
        Some(Attribute { kind, resident: bytes[8] == 0, named: bytes[9] != 0, bytes })
    })
}

/// The folder a record sits in and its name, preferring the long name to the 8.3 one.
fn file_name(record: &[u8]) -> Option<(u32, String)> {
    let mut found = None;
    for attribute in attributes(record).filter(|a| a.kind == FILE_NAME && a.resident) {
        let Some(value) = attribute.value().filter(|v| v.len() >= 66) else { continue };
        let len = usize::from(value[64]);
        let Some(name) = value.get(66..66 + len * 2) else { continue };
        let name: Vec<u16> = name.as_chunks::<2>().0.iter().map(|&c| u16::from_le_bytes(c)).collect();
        let parent = record_of(u64_at(value, 0));
        found = Some((parent, String::from_utf16_lossy(&name)));
        if value[65] != DOS_NAME {
            break;
        }
    }
    found
}

pub struct Scan {
    pub letter: char,
    pub seconds: f64,
    pub files: u64,
    record_size: usize,
    /// Per record: the folder it's in, or NONE when the record isn't a file in use.
    parent: Vec<u32>,
    /// Bytes on disk: a file's own, or everything under a folder.
    size: Vec<u64>,
    /// Files under a folder; 1 for a file.
    count: Vec<u32>,
    /// Bytes in a file's main stream, the size Explorer shows.
    length: Vec<u64>,
    folder: Vec<bool>,
    /// Children of each record, as `children[first[r]..first[r + 1]]`.
    first: Vec<u32>,
    children: Vec<u32>,
}

#[derive(Clone, Copy)]
pub struct Entry {
    pub record: u32,
    pub size: u64,
    pub files: u32,
    pub folder: bool,
}

/// Reads the whole file table of `letter`. `progress` goes from 0 to 1000.
pub fn scan(letter: char, progress: &AtomicU32) -> std::io::Result<Scan> {
    let started = Instant::now();
    let volume = open(letter)?;
    let mut data = NTFS_VOLUME_DATA_BUFFER::default();
    unsafe {
        DeviceIoControl(
            HANDLE(volume.as_raw_handle()),
            FSCTL_GET_NTFS_VOLUME_DATA,
            None,
            0,
            Some((&raw mut data).cast()),
            size_of::<NTFS_VOLUME_DATA_BUFFER>() as u32,
            None,
            None,
        )?;
    }
    let cluster = u64::from(data.BytesPerCluster);
    let record_size = data.BytesPerFileRecordSegment as usize;
    let records = (data.MftValidDataLength as u64 / record_size as u64) as usize;
    let invalid = || std::io::Error::new(std::io::ErrorKind::InvalidData, "unreadable file table");

    // Record 0 is the table's own entry and says where the rest of it is.
    let mut first = vec![0u8; record_size];
    read_at(&volume, &mut first, data.MftStartLcn as u64 * cluster)?;
    if !fixup(&mut first) {
        return Err(invalid());
    }
    let runs = attributes(&first)
        .find(|a| a.kind == DATA && !a.resident && !a.named)
        .map(|a| a.runs())
        .ok_or_else(invalid)?;

    let mut parent = vec![NONE; records];
    let mut own = vec![0u64; records];
    let mut length = vec![0u64; records];
    let mut folder = vec![false; records];
    // 4 MB reads: large enough that the drive streams, small enough to stay cheap.
    let chunk = (4 << 20) / record_size * record_size;
    let mut buffer = vec![0u8; chunk];
    let mut number = 0usize;
    'runs: for (lcn, clusters) in runs {
        let mut offset = lcn as u64 * cluster;
        let mut left = clusters * cluster;
        while left > 0 {
            if number >= records {
                break 'runs;
            }
            let len = (left as usize).min(chunk).min((records - number) * record_size);
            read_at(&volume, &mut buffer[..len], offset)?;
            for record in buffer[..len].chunks_exact_mut(record_size) {
                read_record(record, number, cluster, &mut parent, &mut own, &mut length, &mut folder);
                number += 1;
            }
            offset += len as u64;
            left -= len as u64;
            progress.store((number * 1000 / records.max(1)) as u32, Ordering::Relaxed);
        }
    }
    drop(buffer);
    parent[ROOT as usize] = ROOT;
    Ok(Scan::build(letter, record_size, parent, own, length, folder, started))
}

/// Takes the parent, the space used and the kind of one record. Records that continue
/// a long file elsewhere ("extension" records) add to their base record.
fn read_record(
    record: &mut [u8],
    number: usize,
    cluster: u64,
    parent: &mut [u32],
    own: &mut [u64],
    length: &mut [u64],
    folder: &mut [bool],
) {
    if !fixup(record) || u16_at(record, 22) & IN_USE == 0 {
        return;
    }
    let base = record_of(u64_at(record, 32)) as usize;
    let target = if base == 0 { number } else { base };
    if target >= parent.len() {
        return;
    }
    if base == 0 {
        folder[target] = u16_at(record, 22) & DIRECTORY != 0;
    }
    for attribute in attributes(record) {
        match attribute.kind {
            FILE_NAME if parent[target] == NONE && attribute.resident => {
                if let Some(value) = attribute.value().filter(|v| v.len() >= 66) {
                    parent[target] = record_of(u64_at(value, 0));
                }
            }
            // The unnamed stream is the file's content; only its first part has the size.
            DATA if !attribute.named => {
                if attribute.resident {
                    length[target] = attribute.value().map_or(0, |v| v.len() as u64);
                } else if attribute.bytes.len() >= 56 && u64_at(attribute.bytes, 16) == 0 {
                    length[target] = u64_at(attribute.bytes, 48);
                }
                own[target] += attribute.on_disk(cluster);
            }
            // Streams, folder indexes and the rarer ones ($EA, $BITMAP, a long attribute
            // list) all take clusters.
            _ => own[target] += attribute.on_disk(cluster),
        }
    }
}

impl Scan {
    fn build(
        letter: char,
        record_size: usize,
        mut parent: Vec<u32>,
        own: Vec<u64>,
        length: Vec<u64>,
        folder: Vec<bool>,
        started: Instant,
    ) -> Self {
        let n = parent.len();
        // A parent that isn't in use, or is a file, leaves the record out.
        for r in 0..n {
            let p = parent[r] as usize;
            if r != ROOT as usize && p != NONE as usize && (p >= n || parent[p] == NONE || !folder[p]) {
                parent[r] = NONE;
            }
        }
        let mut size = own.clone();
        let mut count = vec![0u32; n];
        let mut files = 0;
        for r in 0..n {
            if parent[r] == NONE || r == ROOT as usize {
                continue;
            }
            if !folder[r] {
                count[r] = 1;
                files += 1;
            }
            // Adds this record's own space and file to every folder above it.
            let mut p = parent[r] as usize;
            for _ in 0..1024 {
                size[p] += own[r];
                count[p] += u32::from(!folder[r]);
                if p == ROOT as usize {
                    break;
                }
                p = parent[p] as usize;
                if p == NONE as usize {
                    break;
                }
            }
        }
        drop(own);
        let mut first = vec![0u32; n + 1];
        for r in 0..n {
            if parent[r] != NONE && r != ROOT as usize {
                first[parent[r] as usize + 1] += 1;
            }
        }
        for i in 0..n {
            first[i + 1] += first[i];
        }
        let mut children = vec![0u32; first[n] as usize];
        let mut next = first.clone();
        for (r, &p) in parent.iter().enumerate() {
            if p != NONE && r != ROOT as usize {
                children[next[p as usize] as usize] = r as u32;
                next[p as usize] += 1;
            }
        }
        Scan {
            letter,
            record_size,
            seconds: started.elapsed().as_secs_f64(),
            files,
            parent,
            size,
            count,
            length,
            folder,
            first,
            children,
        }
    }

    fn entry(&self, record: u32) -> Entry {
        let r = record as usize;
        Entry { record, size: self.size[r], files: self.count[r], folder: self.folder[r] }
    }

    pub fn total(&self) -> u64 {
        self.size[ROOT as usize]
    }

    pub fn get(&self, record: u32) -> Entry {
        self.entry(record)
    }

    /// The folder `record` sits in; `None` for the root.
    pub fn parent(&self, record: u32) -> Option<u32> {
        (record != ROOT).then(|| self.parent[record as usize]).filter(|&p| p != NONE)
    }

    /// What's inside a folder, largest first.
    pub fn children(&self, record: u32) -> Vec<Entry> {
        let r = record as usize;
        let mut list: Vec<Entry> = self.children[self.first[r] as usize..self.first[r + 1] as usize]
            .iter()
            .map(|&c| self.entry(c))
            .collect();
        list.sort_by_key(|e| std::cmp::Reverse(e.size));
        list
    }

    /// The `n` files that take the most space on the whole drive, largest first.
    pub fn largest_files(&self, n: usize) -> Vec<Entry> {
        let mut list: Vec<Entry> = (0..self.parent.len() as u32)
            .filter(|&r| r != ROOT && self.parent[r as usize] != NONE && !self.folder[r as usize])
            .map(|r| self.entry(r))
            .collect();
        if list.len() > n {
            list.select_nth_unstable_by(n, |a, b| b.size.cmp(&a.size));
            list.truncate(n);
        }
        list.sort_by_key(|e| std::cmp::Reverse(e.size));
        list
    }

    /// Reads names back from the file table, one per record; empty where it can't.
    pub fn names(&self, records: &[u32]) -> Vec<String> {
        let Ok(volume) = open(self.letter) else { return vec![String::new(); records.len()] };
        records.iter().map(|&r| self.name_of(&volume, r)).collect()
    }

    fn name_of(&self, volume: &File, record: u32) -> String {
        if record == ROOT {
            return format!("{}:", self.letter);
        }
        let input = NTFS_FILE_RECORD_INPUT_BUFFER { FileReferenceNumber: i64::from(record) };
        let mut output = vec![0u8; 12 + self.record_size];
        let mut returned = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                HANDLE(volume.as_raw_handle()),
                FSCTL_GET_NTFS_FILE_RECORD,
                Some((&raw const input).cast()),
                size_of::<NTFS_FILE_RECORD_INPUT_BUFFER>() as u32,
                Some(output.as_mut_ptr().cast()),
                output.len() as u32,
                Some(&mut returned),
                None,
            )
        };
        // Windows hands back the nearest record in use at or below the one asked for.
        if ok.is_err() || returned < 12 || record_of(u64_at(&output, 0)) != record {
            return String::new();
        }
        let len = (u32_at(&output, 8) as usize).min(returned as usize - 12);
        let record = &mut output[12..12 + len];
        if !fixup(record) {
            return String::new();
        }
        file_name(record).map(|(_, name)| name).unwrap_or_default()
    }

    /// The size Explorer shows for a file.
    pub fn length(&self, record: u32) -> u64 {
        self.length[record as usize]
    }

    /// Every file under a folder, at any depth.
    pub fn files_under(&self, record: u32) -> Vec<u32> {
        let mut files = Vec::new();
        let mut stack = vec![record];
        while let Some(r) = stack.pop() {
            let r = r as usize;
            for &child in &self.children[self.first[r] as usize..self.first[r + 1] as usize] {
                if self.folder[child as usize] {
                    stack.push(child);
                } else {
                    files.push(child);
                }
            }
        }
        files
    }

    /// Full paths of many records at once. Each folder is read once, however many files
    /// it holds.
    pub fn paths(&self, records: &[u32]) -> Vec<String> {
        let Ok(volume) = open(self.letter) else { return vec![String::new(); records.len()] };
        let mut folders: HashMap<u32, String> = HashMap::from([(ROOT, format!("{}:", self.letter))]);
        records
            .iter()
            .map(|&record| {
                // Climbs to the nearest folder already known, then names the way down.
                let mut chain = Vec::new();
                let mut r = self.parent(record).unwrap_or(ROOT);
                while !folders.contains_key(&r) && chain.len() < 256 {
                    chain.push(r);
                    r = self.parent(r).unwrap_or(ROOT);
                }
                let mut path = folders.get(&r).cloned().unwrap_or_default();
                for &folder in chain.iter().rev() {
                    path = format!("{path}\\{}", self.name_of(&volume, folder));
                    folders.insert(folder, path.clone());
                }
                format!("{path}\\{}", self.name_of(&volume, record))
            })
            .collect()
    }

    /// Full path of a record, such as C:\Users\me\Videos.
    pub fn path(&self, record: u32) -> String {
        let mut chain = vec![record];
        let mut r = record;
        while let Some(p) = self.parent(r) {
            if chain.len() > 256 {
                break;
            }
            chain.push(p);
            r = p;
        }
        chain.reverse();
        let names = self.names(&chain);
        let mut path = format!("{}:\\", self.letter);
        path.push_str(&names[1..].join("\\"));
        path
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_runs_with_negative_offsets() {
        // Header (runlist at 64), then: 4 clusters at 0x100, 2 clusters 0x10 back, end.
        let mut bytes = vec![0u8; 64];
        bytes[32] = 64;
        bytes.extend([0x21, 4, 0x00, 0x01, 0x11, 2, 0xf0, 0]);
        let attribute = Attribute { kind: DATA, resident: false, named: false, bytes: &bytes };
        assert_eq!(attribute.runs(), vec![(0x100, 4), (0xf0, 2)]);
    }

    /// Scans C: and checks the total against what Windows says is used:
    /// `cargo test space_scan -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn space_scan() {
        let progress = AtomicU32::new(0);
        let scan = scan('C', &progress).unwrap();
        let (free, total) = crate::disk::system_drive_space();
        let used = total - free;
        println!(
            "{:.2} s, {} files, total {:.2} GB of {:.2} GB used, {} records",
            scan.seconds,
            scan.files,
            scan.total() as f64 / 1e9,
            used as f64 / 1e9,
            scan.parent.len()
        );
        let top = scan.children(ROOT);
        let names = scan.names(&top.iter().take(8).map(|e| e.record).collect::<Vec<_>>());
        for (e, name) in top.iter().zip(names) {
            println!("  {name:<30} {:>8.2} GB {:>8} files", e.size as f64 / 1e9, e.files);
        }
        for e in scan.largest_files(5) {
            println!("  {:>8.2} GB {}", e.size as f64 / 1e9, scan.path(e.record));
        }
        assert!(scan.total() as f64 > used as f64 * 0.85 && scan.total() <= used + (1 << 30));
        for letter in volumes().into_iter().filter(|&l| l != 'C') {
            let scan = super::scan(letter, &progress).unwrap();
            println!(
                "{letter}: {:.2} s, {} files, {:.2} GB",
                scan.seconds,
                scan.files,
                scan.total() as f64 / 1e9
            );
        }
    }
}
