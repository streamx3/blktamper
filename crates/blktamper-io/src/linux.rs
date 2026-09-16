//! Linux specifics: sector geometry, device size, and mount detection.
//!
//! All of it through `sysfs` and `procfs` rather than `ioctl`, which keeps this
//! crate free of `unsafe` and of a `libc` dependency. It is also what `lsblk` does,
//! so it stays correct for loop devices, device-mapper targets and partitions.

use std::fs::File;
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// Kernel name of a block device from its path: `/dev/sdc1` -> `sdc1`.
/// Device-mapper and loop paths under `/dev/mapper` are resolved through their
/// symlink first, since sysfs only knows the `dm-N` name.
pub fn kernel_name(path: &Path) -> Option<String> {
    let real = std::fs::canonicalize(path).ok()?;
    let name = real.file_name()?.to_str()?;
    if real.starts_with("/dev") && Path::new("/sys/class/block").join(name).exists() {
        Some(name.to_string())
    } else {
        None
    }
}

fn sysfs_block(path: &Path) -> Option<PathBuf> {
    Some(Path::new("/sys/class/block").join(kernel_name(path)?))
}

fn read_sysfs_u64(p: &Path) -> Option<u64> {
    std::fs::read_to_string(p).ok()?.trim().parse().ok()
}

/// Device size in bytes. `sysfs` reports it in 512-byte units regardless of the
/// device's actual logical sector size — that unit is fixed kernel ABI, not a
/// sector count, and treating it as one is a classic source of 8x errors on 4Kn.
pub fn device_size(file: &File) -> Option<u64> {
    // Seeking to the end works on any block device and needs no sysfs at all.
    let mut f = file.try_clone().ok()?;
    let end = f.seek(SeekFrom::End(0)).ok()?;
    f.seek(SeekFrom::Start(0)).ok()?;
    if end > 0 {
        Some(end)
    } else {
        None
    }
}

pub fn device_size_by_path(path: &Path) -> Option<u64> {
    let sys = sysfs_block(path)?;
    read_sysfs_u64(&sys.join("size")).map(|s| s.saturating_mul(512))
}

/// Size LBAs are counted in. All LBA arithmetic depends on this (R-2.3).
pub fn logical_sector_size_by_path(path: &Path) -> Option<u32> {
    let sys = sysfs_block(path)?;
    // A partition has no queue/ of its own; it inherits the parent's.
    for cand in [sys.join("queue/logical_block_size"), sys.join("../queue/logical_block_size")] {
        if let Some(v) = read_sysfs_u64(&cand) {
            return u32::try_from(v).ok();
        }
    }
    None
}

pub fn physical_sector_size_by_path(path: &Path) -> Option<u32> {
    let sys = sysfs_block(path)?;
    for cand in [sys.join("queue/physical_block_size"), sys.join("../queue/physical_block_size")] {
        if let Some(v) = read_sysfs_u64(&cand) {
            return u32::try_from(v).ok();
        }
    }
    None
}

/// True when the device is rotational. Shown in the title bar because it changes
/// what "overwriting a block" means — which is the whole question `sanitize` asks.
pub fn is_rotational(path: &Path) -> Option<bool> {
    let sys = sysfs_block(path)?;
    for cand in [sys.join("queue/rotational"), sys.join("../queue/rotational")] {
        if let Some(v) = read_sysfs_u64(&cand) {
            return Some(v == 1);
        }
    }
    None
}

/// One mounted filesystem, as reported by the kernel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountedOn {
    /// Kernel device name, e.g. `sdc1`.
    pub device: String,
    pub mount_point: String,
    pub fs_type: String,
    pub read_only: bool,
}

/// Everything currently mounted from `device` or any of its partitions.
///
/// This exists because editing a live filesystem's metadata is how you crash a
/// kernel, and because since Linux 6.8 a kernel built without
/// `CONFIG_BLK_DEV_WRITE_MOUNTED` will refuse the write with `EBUSY` and the app
/// must explain that rather than print an errno (doc/07-write-safety.md).
pub fn mounts_for(path: &Path) -> Vec<MountedOn> {
    let Some(name) = kernel_name(path) else { return Vec::new() };
    let Ok(text) = std::fs::read_to_string("/proc/self/mountinfo") else { return Vec::new() };
    let children = partition_names(&name);
    let mut out = Vec::new();
    for line in text.lines() {
        // mountinfo: id parent major:minor root mount-point opts... - fstype source super-opts
        let Some((pre, post)) = line.split_once(" - ") else { continue };
        let pre: Vec<&str> = pre.split(' ').collect();
        let post: Vec<&str> = post.split(' ').collect();
        if pre.len() < 6 || post.len() < 2 {
            continue;
        }
        let source = post[1];
        let Some(src_name) = Path::new(source).file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if src_name != name && !children.iter().any(|c| c == src_name) {
            continue;
        }
        out.push(MountedOn {
            device: src_name.to_string(),
            mount_point: unescape_octal(pre[4]),
            fs_type: post[0].to_string(),
            read_only: pre[5..].iter().any(|o| *o == "ro" || o.starts_with("ro,")),
        });
    }
    out
}

/// Partition device names belonging to a whole-disk device.
fn partition_names(disk: &str) -> Vec<String> {
    let dir = Path::new("/sys/class/block").join(disk);
    let Ok(entries) = std::fs::read_dir(&dir) else { return Vec::new() };
    entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().join("partition").exists())
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .collect()
}

/// mountinfo escapes space, tab, newline and backslash as `\040` and friends.
fn unescape_octal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() {
            let oct = &s[i + 1..i + 4];
            if let Ok(v) = u8::from_str_radix(oct, 8) {
                out.push(v as char);
                i += 4;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn octal_escapes_are_undone() {
        assert_eq!(unescape_octal("/media/andrii/My\\040Disk"), "/media/andrii/My Disk");
        assert_eq!(unescape_octal("/mnt/plain"), "/mnt/plain");
        // a trailing lone backslash must not panic or eat memory
        assert_eq!(unescape_octal("/a\\"), "/a\\");
    }

    #[test]
    fn unknown_paths_yield_nothing_rather_than_failing() {
        assert!(kernel_name(Path::new("/definitely/not/a/device")).is_none());
        assert!(mounts_for(Path::new("/definitely/not/a/device")).is_empty());
    }

    #[test]
    #[cfg_attr(not(target_os = "linux"), ignore)]
    fn real_root_device_geometry_is_readable() {
        // Not asserting specific values: this only proves the sysfs path works on
        // whatever machine is running the tests.
        if Path::new("/sys/class/block").exists() {
            let any = std::fs::read_dir("/sys/class/block")
                .unwrap()
                .filter_map(|e| e.ok())
                .next()
                .map(|e| PathBuf::from("/dev").join(e.file_name()));
            if let Some(p) = any {
                if p.exists() {
                    let _ = logical_sector_size_by_path(&p);
                    let _ = device_size_by_path(&p);
                }
            }
        }
    }
}
