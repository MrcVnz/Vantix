//! Physical memory stats and working set / standby list cleanup.
//!
//! The memory list commands go through `NtSetSystemInformation`, which is undocumented
//! but stable since Vista and is what RAMMap and similar tools use. It needs
//! SeProfileSingleProcessPrivilege; the file cache flush needs SeIncreaseQuotaPrivilege.
//!
//! Quick and Standard trim working sets one process at a time so our own UI, DWM and the
//! audio engine can be left alone: the global trim makes them refault everything and the
//! screen hitches for ~45 ms (under 1 ms when they're skipped). The global trim ignores
//! hard working set minimums, so there is no way to protect them from it. Deep still uses
//! it because it also reaches the system working set and protected processes such as
//! Memory Compression, roughly 3-4x what the per-process pass frees.

use std::ffi::c_void;
use std::mem::size_of;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS};
use windows::Win32::Foundation::{CloseHandle, HANDLE, LUID, NTSTATUS};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Memory::SetSystemFileCacheSize;
use windows::Win32::System::ProcessStatus::EmptyWorkingSet;
use windows::Win32::System::SystemInformation::{
    GetSystemInfo, GlobalMemoryStatusEx, MEMORYSTATUSEX, SYSTEM_INFO,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_QUOTA,
};
use windows::core::{PCWSTR, w};

windows_link::link!("ntdll.dll" "system" fn NtSetSystemInformation(class: SYSTEM_INFORMATION_CLASS, info: *const c_void, len: u32) -> NTSTATUS);

const SYSTEM_MEMORY_LIST_INFORMATION: SYSTEM_INFORMATION_CLASS = SYSTEM_INFORMATION_CLASS(80);

// SYSTEM_MEMORY_LIST_COMMAND
const EMPTY_WORKING_SETS: u32 = 2;
const FLUSH_MODIFIED_LIST: u32 = 3;
const PURGE_STANDBY_LIST: u32 = 4;
const PURGE_LOW_PRIORITY_STANDBY_LIST: u32 = 5;

#[repr(C)]
#[derive(Default)]
struct MemoryListInfo {
    zero_pages: usize,
    free_pages: usize,
    modified_pages: usize,
    modified_no_write_pages: usize,
    bad_pages: usize,
    standby_by_priority: [usize; 8],
    repurposed_by_priority: [usize; 8],
    modified_pagefile_pages: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Trim every process working set.
    Quick,
    /// Quick, plus flush the modified list and drop low priority standby pages.
    #[default]
    Standard,
    /// Standard, plus the whole standby list and the system file cache.
    Deep,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub total: u64,
    pub available: u64,
    pub load: u32,
    /// Zero for these when the privilege is missing.
    pub standby: u64,
    pub modified: u64,
    pub free: u64,
    pub commit_used: u64,
    pub commit_limit: u64,
}

impl Stats {
    pub fn in_use(&self) -> u64 {
        self.total - self.available
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Report {
    pub before: Stats,
    pub after: Stats,
}

impl Report {
    pub fn freed(&self) -> i64 {
        self.before.in_use() as i64 - self.after.in_use() as i64
    }
}

/// Enables the privileges the cleanup needs. Fails silently per privilege: without
/// admin rights we still get a partial cleanup through the per-process fallback.
pub fn enable_privileges() {
    for name in
        [w!("SeProfileSingleProcessPrivilege"), w!("SeIncreaseQuotaPrivilege"), w!("SeDebugPrivilege")]
    {
        let _ = enable_privilege(name);
    }
}

fn enable_privilege(name: PCWSTR) -> windows::core::Result<()> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token)?;
        let mut luid = LUID::default();
        let result = LookupPrivilegeValueW(None, name, &mut luid).and_then(|_| {
            let mut tp = TOKEN_PRIVILEGES { PrivilegeCount: 1, ..Default::default() };
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None)
        });
        let _ = CloseHandle(token);
        result
    }
}

pub fn stats() -> Stats {
    let mut status = MEMORYSTATUSEX { dwLength: size_of::<MEMORYSTATUSEX>() as u32, ..Default::default() };
    unsafe {
        let _ = GlobalMemoryStatusEx(&mut status);
    }

    let mut stats = Stats {
        total: status.ullTotalPhys,
        available: status.ullAvailPhys,
        load: status.dwMemoryLoad,
        commit_used: status.ullTotalPageFile - status.ullAvailPageFile,
        commit_limit: status.ullTotalPageFile,
        ..Default::default()
    };

    let mut info = MemoryListInfo::default();
    let status = unsafe {
        NtQuerySystemInformation(
            SYSTEM_MEMORY_LIST_INFORMATION,
            (&raw mut info).cast(),
            size_of::<MemoryListInfo>() as u32,
            std::ptr::null_mut(),
        )
    };
    if status.is_ok() {
        let page = page_size();
        stats.standby = info.standby_by_priority.iter().sum::<usize>() as u64 * page;
        stats.modified = info.modified_pages as u64 * page;
        stats.free = (info.free_pages + info.zero_pages) as u64 * page;
    }
    stats
}

/// Gives our own pages back after the window is destroyed; they fault back in on demand.
pub fn trim_self() {
    unsafe {
        let _ = EmptyWorkingSet(GetCurrentProcess());
    }
}

fn page_size() -> u64 {
    let mut info = SYSTEM_INFO::default();
    unsafe { GetSystemInfo(&mut info) };
    info.dwPageSize as u64
}

/// Skipped by the per-process trim besides ourselves: the compositor (the whole screen
/// would stutter) and the audio engine (it would crackle).
const SKIP: [&str; 2] = ["dwm.exe", "audiodg.exe"];

/// Polling interval and limit while waiting for the kernel to finish trimming.
const SETTLE_POLL: Duration = Duration::from_millis(250);
const SETTLE_LIMIT: Duration = Duration::from_secs(6);
/// Anything smaller than this per poll counts as noise, not as the trim still going.
const SETTLE_NOISE: u64 = 32 << 20;

/// Blocking, takes a few seconds: the commands return before the kernel is done moving
/// pages, so this waits for memory to settle before taking the "after" sample.
pub fn clean(level: Level) -> Report {
    let before = stats();

    if level != Level::Deep || !memory_list_command(EMPTY_WORKING_SETS) {
        trim_each_process();
    }

    if level != Level::Quick {
        memory_list_command(FLUSH_MODIFIED_LIST);
        memory_list_command(PURGE_LOW_PRIORITY_STANDBY_LIST);
    }

    if level == Level::Deep {
        memory_list_command(PURGE_STANDBY_LIST);
        // usize::MAX for both bounds tells the kernel to trim the cache as far as it can.
        unsafe {
            let _ = SetSystemFileCacheSize(usize::MAX, usize::MAX, 0);
        }
    }

    Report { before, after: settle() }
}

/// Returns the lowest point once in-use memory stops falling. Quick keeps dropping for
/// a couple of seconds after the calls return; Standard and Deep are usually done already
/// and start climbing back as apps fault pages in.
fn settle() -> Stats {
    let started = Instant::now();
    let mut lowest = stats();
    let mut flat = 0;
    while flat < 2 && started.elapsed() < SETTLE_LIMIT {
        std::thread::sleep(SETTLE_POLL);
        let now = stats();
        if now.in_use() + SETTLE_NOISE < lowest.in_use() {
            flat = 0;
        } else {
            flat += 1;
        }
        if now.in_use() < lowest.in_use() {
            lowest = now;
        }
    }
    lowest
}

fn memory_list_command(command: u32) -> bool {
    let status =
        unsafe { NtSetSystemInformation(SYSTEM_MEMORY_LIST_INFORMATION, (&raw const command).cast(), 4) };
    status.is_ok()
}

fn trim_each_process() {
    let me = std::process::id();
    for_each_process(|entry| {
        if entry.th32ProcessID == me || SKIP.iter().any(|name| exe_name(entry).eq_ignore_ascii_case(name)) {
            return;
        }
        unsafe {
            if let Ok(process) =
                OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_QUOTA, false, entry.th32ProcessID)
            {
                let _ = EmptyWorkingSet(process);
                let _ = CloseHandle(process);
            }
        }
    });
}

pub fn for_each_process(mut f: impl FnMut(&PROCESSENTRY32W)) {
    unsafe {
        let Ok(snapshot) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else {
            return;
        };
        let mut entry = PROCESSENTRY32W { dwSize: size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
        let mut more = Process32FirstW(snapshot, &mut entry).is_ok();
        while more {
            f(&entry);
            more = Process32NextW(snapshot, &mut entry).is_ok();
        }
        let _ = CloseHandle(snapshot);
    }
}

pub fn exe_name(entry: &PROCESSENTRY32W) -> String {
    let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
    String::from_utf16_lossy(&entry.szExeFile[..len])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Touches the real system, so it only runs on demand: `cargo test -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn clean_reports_sane_numbers() {
        enable_privileges();
        for level in [Level::Quick, Level::Standard, Level::Deep] {
            let report = clean(level);
            assert!(report.after.total == report.before.total);
            assert!(report.after.available <= report.after.total);
            println!(
                "{level:?}: in use {} -> {} MB, standby {} -> {} MB",
                report.before.in_use() >> 20,
                report.after.in_use() >> 20,
                report.before.standby >> 20,
                report.after.standby >> 20,
            );
        }
    }
}
