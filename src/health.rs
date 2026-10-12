//! Drive health: what each physical disk says about itself.
//!
//! NVMe drives answer with their health log page and SATA drives with their SMART
//! attributes. USB enclosures sit between the PC and the drive, and most of their bridge
//! chips pass neither through; that's said as it is rather than shown as a failure.

use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE};
use windows::Win32::Storage::FileSystem::{
    BusTypeNvme, BusTypeSas, BusTypeSata, BusTypeUsb, CreateFileW, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_READ,
    FILE_SHARE_WRITE, GetLogicalDrives, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, OPEN_EXISTING,
};
use windows::Win32::Storage::IscsiDisc::{ATA_PASS_THROUGH_EX, IOCTL_ATA_PASS_THROUGH};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{
    DEVICE_SEEK_PENALTY_DESCRIPTOR, DRIVE_LAYOUT_INFORMATION_EX, GET_LENGTH_INFORMATION,
    IOCTL_DISK_GET_DRIVE_LAYOUT_EX, IOCTL_DISK_GET_LENGTH_INFO, IOCTL_STORAGE_QUERY_PROPERTY, NVMeDataTypeLogPage,
    PARTITION_INFORMATION_EX, PARTITION_STYLE_GPT, PropertyStandardQuery, ProtocolTypeNvme, STORAGE_DEVICE_DESCRIPTOR,
    STORAGE_PROPERTY_ID, STORAGE_PROPERTY_QUERY, STORAGE_PROTOCOL_SPECIFIC_DATA, STORAGE_WRITE_CACHE_PROPERTY,
    StorageDeviceProperty, StorageDeviceProtocolSpecificProperty, StorageDeviceSeekPenaltyProperty,
    StorageDeviceWriteCacheProperty, VOLUME_DISK_EXTENTS, WriteCacheEnabled,
};
use windows::core::{GUID, HSTRING};

use crate::reg;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bus {
    Nvme,
    Sata,
    Usb,
    Other,
}

#[derive(Clone, Debug, Default)]
pub struct Nvme {
    /// Critical warning bits from the log page.
    pub warning: u8,
    pub temperature: i32,
    /// Spare blocks left and where the drive starts warning, in percent.
    pub spare: u8,
    pub spare_threshold: u8,
    /// The maker's estimate of the drive's life used, in percent. It can pass 100.
    pub used: u8,
    pub written: u128,
    pub hours: u128,
    pub unsafe_shutdowns: u128,
    pub media_errors: u128,
}

#[derive(Clone, Debug, Default)]
pub struct Ata {
    pub reallocated: Option<u64>,
    pub pending: Option<u64>,
    pub uncorrectable: Option<u64>,
    pub temperature: Option<i32>,
    pub hours: Option<u64>,
}

#[derive(Clone, Debug)]
pub enum Report {
    Nvme(Nvme),
    Ata(Ata),
    /// A USB bridge that keeps the drive's health to itself.
    Bridge,
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Good,
    /// Still fine, but worth a backup and a look now and then.
    Watch,
    /// Back it up now.
    Bad,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct Drive {
    pub model: String,
    pub bus: Bus,
    /// `None` when the drive doesn't say.
    pub ssd: Option<bool>,
    pub size: u64,
    /// Its volumes, like "C: E:".
    pub letters: String,
    pub report: Report,
    pub write_cache: Option<bool>,
    /// Every partition starts on a 4 KB boundary.
    pub aligned: Option<bool>,
}

impl Drive {
    pub fn verdict(&self) -> Verdict {
        match &self.report {
            Report::Nvme(n) => {
                // Spare below threshold, reliability degraded, or read only.
                if n.warning & 0b1101 != 0 || n.spare < n.spare_threshold || n.used >= 100 {
                    Verdict::Bad
                } else if n.media_errors > 0 || n.used >= 80 || n.warning & 0b10 != 0 || n.temperature >= 70 {
                    Verdict::Watch
                } else {
                    Verdict::Good
                }
            }
            Report::Ata(a) => {
                if a.pending.unwrap_or(0) > 0 || a.uncorrectable.unwrap_or(0) > 0 {
                    Verdict::Bad
                } else if a.reallocated.unwrap_or(0) > 0 || a.temperature.unwrap_or(0) >= 60 {
                    Verdict::Watch
                } else if a.reallocated.is_none() && a.pending.is_none() {
                    Verdict::Unknown
                } else {
                    Verdict::Good
                }
            }
            Report::Bridge | Report::Unavailable => Verdict::Unknown,
        }
    }
}

/// TRIM for NTFS, which is one setting for every SSD. `None` when it can't be read.
pub fn trim_on() -> Option<bool> {
    let value = reg::get_dword(
        reg::HKEY_LOCAL_MACHINE,
        r"SYSTEM\CurrentControlSet\Control\FileSystem",
        "DisableDeleteNotification",
    )
    .ok()?;
    Some(value.unwrap_or(0) == 0)
}

/// Every physical disk, in Windows' order. Takes a fraction of a second.
pub fn drives() -> Vec<Drive> {
    let letters = volume_disks();
    let mut drives = Vec::new();
    let mut misses = 0;
    // Disk numbers can have gaps when a disk was removed.
    for number in 0..32u32 {
        let Some(disk) = Disk::open(number) else {
            misses += 1;
            if misses > 8 {
                break;
            }
            continue;
        };
        misses = 0;
        let Some((model, bus)) = disk.describe() else { continue };
        let ssd = disk.seek_penalty().map(|penalty| !penalty);
        let report = match bus {
            Bus::Nvme => disk.nvme().map_or(Report::Unavailable, Report::Nvme),
            _ => match disk.ata() {
                Some(ata) => Report::Ata(ata),
                None if bus == Bus::Usb => Report::Bridge,
                None => Report::Unavailable,
            },
        };
        let mut mine: Vec<String> =
            letters.iter().filter(|(_, disk)| *disk == number).map(|(letter, _)| format!("{letter}:")).collect();
        mine.sort();
        drives.push(Drive {
            model,
            bus,
            ssd,
            size: disk.size().unwrap_or(0),
            letters: mine.join(" "),
            report,
            write_cache: disk.write_cache(),
            aligned: disk.aligned(),
        });
    }
    drives
}

const MICROSOFT_RESERVED: GUID = GUID::from_u128(0xe3c9e316_0b5c_4db8_817d_f92df00215ae);

struct Disk(HANDLE);

impl Drop for Disk {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

impl Disk {
    fn open(number: u32) -> Option<Self> {
        let path = HSTRING::from(format!(r"\\.\PhysicalDrive{number}"));
        let share = FILE_SHARE_READ | FILE_SHARE_WRITE;
        let open = |access: u32| unsafe {
            CreateFileW(&path, access, share, None, OPEN_EXISTING, FILE_FLAGS_AND_ATTRIBUTES(0), None).ok()
        };
        // SMART needs read and write; the descriptor alone is fine with no access at all.
        open(GENERIC_READ.0 | GENERIC_WRITE.0).or_else(|| open(0)).map(Disk)
    }

    fn control(&self, code: u32, input: Option<&[u8]>, output: &mut [u8]) -> Option<usize> {
        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                self.0,
                code,
                input.map(|i| i.as_ptr().cast()),
                input.map_or(0, |i| i.len() as u32),
                Some(output.as_mut_ptr().cast()),
                output.len() as u32,
                Some(&mut returned),
                None,
            )
            .ok()?;
        }
        Some(returned as usize)
    }

    fn property(&self, id: STORAGE_PROPERTY_ID, size: usize) -> Option<Vec<u8>> {
        let query = STORAGE_PROPERTY_QUERY { PropertyId: id, QueryType: PropertyStandardQuery, ..Default::default() };
        let input = unsafe {
            std::slice::from_raw_parts((&raw const query).cast::<u8>(), size_of::<STORAGE_PROPERTY_QUERY>())
        };
        let mut output = vec![0u8; size];
        let returned = self.control(IOCTL_STORAGE_QUERY_PROPERTY, Some(input), &mut output)?;
        output.truncate(returned);
        Some(output)
    }

    fn describe(&self) -> Option<(String, Bus)> {
        let bytes = self.property(StorageDeviceProperty, 1024)?;
        if bytes.len() < size_of::<STORAGE_DEVICE_DESCRIPTOR>() {
            return None;
        }
        let descriptor = unsafe { bytes.as_ptr().cast::<STORAGE_DEVICE_DESCRIPTOR>().read_unaligned() };
        let text = |offset: u32| -> String {
            let start = offset as usize;
            if start == 0 || start >= bytes.len() {
                return String::new();
            }
            let end = bytes[start..].iter().position(|&b| b == 0).map_or(bytes.len(), |n| start + n);
            String::from_utf8_lossy(&bytes[start..end]).trim().to_string()
        };
        let vendor = text(descriptor.VendorIdOffset);
        let product = text(descriptor.ProductIdOffset);
        let model = match (vendor.as_str(), product.as_str()) {
            ("", product) => product.to_string(),
            (vendor, product) if product.starts_with(vendor) => product.to_string(),
            (vendor, product) => format!("{vendor} {product}"),
        };
        let bus = match descriptor.BusType {
            t if t == BusTypeNvme => Bus::Nvme,
            t if t == BusTypeSata || t == BusTypeSas => Bus::Sata,
            t if t == BusTypeUsb => Bus::Usb,
            _ => Bus::Other,
        };
        Some((model, bus))
    }

    fn seek_penalty(&self) -> Option<bool> {
        let bytes = self.property(StorageDeviceSeekPenaltyProperty, size_of::<DEVICE_SEEK_PENALTY_DESCRIPTOR>())?;
        if bytes.len() < size_of::<DEVICE_SEEK_PENALTY_DESCRIPTOR>() {
            return None;
        }
        let descriptor = unsafe { bytes.as_ptr().cast::<DEVICE_SEEK_PENALTY_DESCRIPTOR>().read_unaligned() };
        Some(descriptor.IncursSeekPenalty)
    }

    fn write_cache(&self) -> Option<bool> {
        let bytes = self.property(StorageDeviceWriteCacheProperty, size_of::<STORAGE_WRITE_CACHE_PROPERTY>())?;
        if bytes.len() < size_of::<STORAGE_WRITE_CACHE_PROPERTY>() {
            return None;
        }
        let cache = unsafe { bytes.as_ptr().cast::<STORAGE_WRITE_CACHE_PROPERTY>().read_unaligned() };
        Some(cache.WriteCacheEnabled == WriteCacheEnabled)
    }

    fn size(&self) -> Option<u64> {
        let mut output = [0u8; size_of::<GET_LENGTH_INFORMATION>()];
        self.control(IOCTL_DISK_GET_LENGTH_INFO, None, &mut output)?;
        let info = unsafe { output.as_ptr().cast::<GET_LENGTH_INFORMATION>().read_unaligned() };
        Some(info.Length as u64)
    }

    /// Partitions off a 4 KB boundary make every write to an SSD touch two pages. Only
    /// drives partitioned by very old tools have them.
    fn aligned(&self) -> Option<bool> {
        let entry = size_of::<PARTITION_INFORMATION_EX>();
        let mut output = vec![0u8; size_of::<DRIVE_LAYOUT_INFORMATION_EX>() + 127 * entry];
        self.control(IOCTL_DISK_GET_DRIVE_LAYOUT_EX, None, &mut output)?;
        let layout = output.as_ptr().cast::<DRIVE_LAYOUT_INFORMATION_EX>();
        unsafe {
            let count = (*layout).PartitionCount.min(128) as usize;
            let first = (&raw const (*layout).PartitionEntry).cast::<PARTITION_INFORMATION_EX>();
            let partitions = (0..count).map(|i| first.add(i).read_unaligned());
            // The Microsoft Reserved partition holds no data, and tools that misplace it
            // place everything else right.
            let reserved = |p: &PARTITION_INFORMATION_EX| {
                p.PartitionStyle == PARTITION_STYLE_GPT && p.Anonymous.Gpt.PartitionType == MICROSOFT_RESERVED
            };
            Some(
                partitions
                    .filter(|p| p.PartitionLength > 0 && !reserved(p))
                    .all(|p| p.StartingOffset % 4096 == 0),
            )
        }
    }

    /// The health log page, through the storage stack's NVMe pass-through.
    fn nvme(&self) -> Option<Nvme> {
        const LOG: usize = 512;
        let header = size_of::<STORAGE_PROPERTY_QUERY>() - 4; // up to AdditionalParameters
        let protocol = size_of::<STORAGE_PROTOCOL_SPECIFIC_DATA>();
        let mut buffer = vec![0u8; header + protocol + LOG];
        unsafe {
            let query = buffer.as_mut_ptr().cast::<STORAGE_PROPERTY_QUERY>();
            (&raw mut (*query).PropertyId).write_unaligned(StorageDeviceProtocolSpecificProperty);
            (&raw mut (*query).QueryType).write_unaligned(PropertyStandardQuery);
            let data = STORAGE_PROTOCOL_SPECIFIC_DATA {
                ProtocolType: ProtocolTypeNvme,
                DataType: NVMeDataTypeLogPage.0 as u32,
                ProtocolDataRequestValue: 2, // SMART / health information
                ProtocolDataOffset: protocol as u32,
                ProtocolDataLength: LOG as u32,
                ..Default::default()
            };
            buffer.as_mut_ptr().add(header).cast::<STORAGE_PROTOCOL_SPECIFIC_DATA>().write_unaligned(data);
        }
        let input = buffer.clone();
        let returned = self.control(IOCTL_STORAGE_QUERY_PROPERTY, Some(&input), &mut buffer)?;
        // The answer starts with Version and Size, then the protocol data, then the page.
        let start = 8 + protocol;
        if returned < start + 200 {
            return None;
        }
        let page = &buffer[start..start + LOG];
        let wide = |at: usize| u128::from_le_bytes(page[at..at + 16].try_into().unwrap());
        Some(Nvme {
            warning: page[0],
            temperature: i32::from(u16::from_le_bytes([page[1], page[2]])) - 273,
            spare: page[3],
            spare_threshold: page[4],
            used: page[5],
            // Data units are thousands of 512-byte sectors.
            written: wide(48) * 512_000,
            hours: wide(128),
            unsafe_shutdowns: wide(144),
            media_errors: wide(160),
        })
    }

    /// SMART attributes through ATA pass-through, the way SATA drives give them.
    fn ata(&self) -> Option<Ata> {
        const DATA: usize = 512;
        let header = size_of::<ATA_PASS_THROUGH_EX>();
        let mut buffer = vec![0u8; header + DATA];
        let request = ATA_PASS_THROUGH_EX {
            Length: header as u16,
            AtaFlags: 0x01 | 0x02, // drive ready required, data in
            DataTransferLength: DATA as u32,
            TimeOutValue: 3,
            DataBufferOffset: header,
            // SMART READ DATA: feature D0, the 4F/C2 signature, command B0.
            CurrentTaskFile: [0xD0, 1, 1, 0x4F, 0xC2, 0xA0, 0xB0, 0],
            ..Default::default()
        };
        unsafe { buffer.as_mut_ptr().cast::<ATA_PASS_THROUGH_EX>().write_unaligned(request) };
        let input = buffer.clone();
        let returned = self.control(IOCTL_ATA_PASS_THROUGH, Some(&input), &mut buffer)?;
        if returned < header + 362 {
            return None;
        }
        let table = &buffer[header..];
        let mut ata = Ata::default();
        let mut any = false;
        // Thirty attributes of twelve bytes after a two-byte version.
        for entry in table[2..362].as_chunks::<12>().0 {
            let id = entry[0];
            if id == 0 {
                continue;
            }
            any = true;
            let raw = u64::from_le_bytes([entry[5], entry[6], entry[7], entry[8], entry[9], entry[10], 0, 0]);
            match id {
                5 => ata.reallocated = Some(raw),
                9 => ata.hours = Some(raw & 0xffff_ffff),
                197 => ata.pending = Some(raw),
                198 => ata.uncorrectable = Some(raw),
                // The low byte is the current temperature; the rest holds minimum and maximum.
                194 | 190 if ata.temperature.is_none() => ata.temperature = Some(i32::from(entry[5])),
                _ => {}
            }
        }
        any.then_some(ata)
    }
}

/// Each drive letter with the disk it lives on. Volumes spread over several disks are
/// left out.
fn volume_disks() -> Vec<(char, u32)> {
    let mask = unsafe { GetLogicalDrives() };
    let mut found = Vec::new();
    for (i, letter) in ('A'..='Z').enumerate() {
        if mask & (1 << i) == 0 {
            continue;
        }
        let path = HSTRING::from(format!(r"\\.\{letter}:"));
        let share = FILE_SHARE_READ | FILE_SHARE_WRITE;
        let Ok(handle) =
            (unsafe { CreateFileW(&path, 0, share, None, OPEN_EXISTING, FILE_FLAGS_AND_ATTRIBUTES(0), None) })
        else {
            continue;
        };
        let disk = Disk(handle);
        let mut output = [0u8; size_of::<VOLUME_DISK_EXTENTS>()];
        if disk.control(IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, None, &mut output).is_some() {
            let extents = unsafe { output.as_ptr().cast::<VOLUME_DISK_EXTENTS>().read_unaligned() };
            if extents.NumberOfDiskExtents == 1 {
                found.push((letter, extents.Extents[0].DiskNumber));
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read-only: `cargo test drive_health -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn drive_health() {
        let started = std::time::Instant::now();
        let list = drives();
        println!("{} drives in {:?}, TRIM {:?}", list.len(), started.elapsed(), trim_on());
        for drive in &list {
            println!("{drive:#?}\nverdict {:?}", drive.verdict());
        }
        assert!(!list.is_empty());
    }
}
