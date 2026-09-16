//! Opening a device or image, and explaining it when that fails.
//!
//! A TUI that dies with `Permission denied (os error 13)` on a device that plain
//! `sudo` would have opened is a bad first impression, and it is the *default*
//! experience for this tool: `/dev/sd*` is `root:disk 0660` and desktop users are
//! not in `disk` (R-1.5).

use crate::file::FileSource;
use crate::SourceKind;
use blktamper_core::BlockSource;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    ReadOnly,
}

/// Everything the title bar and the safety checks need to know.
#[derive(Clone, Debug)]
pub struct DeviceInfo {
    pub path: PathBuf,
    pub kind: SourceKind,
    pub len: u64,
    pub logical_sector_size: u32,
    pub physical_sector_size: u32,
    pub rotational: Option<bool>,
    /// Mounted filesystems on this device or its partitions. Non-empty means any
    /// future write path must warn loudly and may be refused by the kernel.
    pub mounts: Vec<MountInfo>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountInfo {
    pub device: String,
    pub mount_point: String,
    pub fs_type: String,
    pub read_only: bool,
}

impl DeviceInfo {
    pub fn is_mounted(&self) -> bool {
        !self.mounts.is_empty()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    #[error("{path}: permission denied\n\n{advice}")]
    Permission { path: PathBuf, advice: String },
    #[error("{path}: no such file or directory")]
    NotFound { path: PathBuf },
    #[error("{path}: is a directory, not a device or image")]
    IsDirectory { path: PathBuf },
    #[error("{path}: device is busy\n\n{advice}")]
    Busy { path: PathBuf, advice: String },
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

fn permission_advice(path: &Path) -> String {
    let p = path.display();
    format!(
        "Raw block devices are owned by root:disk with mode 0660, so an ordinary \
         account cannot read them. Any of these will work:\n\
         \n\
         \x20 sudo blktamper {p}\n\
         \x20 sudo usermod -aG disk $USER    (then log out and back in)\n\
         \n\
         Note that membership of the `disk` group grants read access to every block \
         device on the machine, which is equivalent to root for data purposes.\n\
         \n\
         To try blktamper without any of that, point it at a disk image instead."
    )
}

fn busy_advice(path: &Path) -> String {
    format!(
        "The kernel refused to open {} for this access mode.\n\
         \n\
         Since Linux 6.8, a kernel built without CONFIG_BLK_DEV_WRITE_MOUNTED \
         returns EBUSY when a mounted block device is opened for writing. \
         Unmount the filesystems on it first, or boot with \
         bdev_allow_write_mounted=1.\n\
         \n\
         blktamper opens devices read-only, so seeing this here is unusual — \
         something else may hold the device open exclusively.",
        path.display()
    )
}

/// Open a device or image read-only and gather its geometry.
pub fn open_path(path: impl AsRef<Path>, access: Access) -> Result<(Arc<dyn BlockSource>, DeviceInfo), OpenError> {
    let path = path.as_ref();
    let Access::ReadOnly = access;

    let meta = std::fs::metadata(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => OpenError::NotFound { path: path.into() },
        std::io::ErrorKind::PermissionDenied => {
            OpenError::Permission { path: path.into(), advice: permission_advice(path) }
        }
        _ => OpenError::Io { path: path.into(), source: e },
    })?;
    if meta.is_dir() {
        return Err(OpenError::IsDirectory { path: path.into() });
    }

    let mut src = FileSource::open_ro(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::PermissionDenied => {
            OpenError::Permission { path: path.into(), advice: permission_advice(path) }
        }
        std::io::ErrorKind::NotFound => OpenError::NotFound { path: path.into() },
        std::io::ErrorKind::ResourceBusy => {
            OpenError::Busy { path: path.into(), advice: busy_advice(path) }
        }
        _ => OpenError::Io { path: path.into(), source: e },
    })?;

    let (kind, logical, physical, rotational, mounts, len) = describe(path, &src);
    if let Some(l) = logical {
        src.set_logical_sector_size(l);
    }

    let info = DeviceInfo {
        path: path.to_path_buf(),
        kind,
        len: if len > 0 { len } else { src.len() },
        logical_sector_size: logical.unwrap_or(512),
        physical_sector_size: physical.unwrap_or(logical.unwrap_or(512)),
        rotational,
        mounts,
    };
    Ok((Arc::new(src) as Arc<dyn BlockSource>, info))
}

#[cfg(target_os = "linux")]
fn describe(
    path: &Path,
    src: &FileSource,
) -> (SourceKind, Option<u32>, Option<u32>, Option<bool>, Vec<MountInfo>, u64) {
    use crate::linux;
    let name = linux::kernel_name(path);
    let kind = match &name {
        Some(n) if Path::new("/sys/class/block").join(n).join("partition").exists() => {
            SourceKind::Partition
        }
        Some(_) => SourceKind::BlockDevice,
        None => SourceKind::Image,
    };
    if kind == SourceKind::Image {
        return (kind, None, None, None, Vec::new(), src.len());
    }
    let mounts = linux::mounts_for(path)
        .into_iter()
        .map(|m| MountInfo {
            device: m.device,
            mount_point: m.mount_point,
            fs_type: m.fs_type,
            read_only: m.read_only,
        })
        .collect();
    (
        kind,
        linux::logical_sector_size_by_path(path),
        linux::physical_sector_size_by_path(path),
        linux::is_rotational(path),
        mounts,
        linux::device_size_by_path(path).unwrap_or_else(|| src.len()),
    )
}

#[cfg(not(target_os = "linux"))]
fn describe(
    _path: &Path,
    src: &FileSource,
) -> (SourceKind, Option<u32>, Option<u32>, Option<bool>, Vec<MountInfo>, u64) {
    (SourceKind::Image, None, None, None, Vec::new(), src.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_paths_are_named_clearly() {
        let e = open_path("/definitely/not/here", Access::ReadOnly).unwrap_err();
        assert!(matches!(e, OpenError::NotFound { .. }));
        assert!(e.to_string().contains("/definitely/not/here"));
    }

    #[test]
    fn directories_are_rejected_with_a_reason() {
        let e = open_path("/tmp", Access::ReadOnly).unwrap_err();
        assert!(matches!(e, OpenError::IsDirectory { .. }));
    }

    #[test]
    fn permission_errors_explain_the_fix() {
        // /dev/sdc is root:disk 0660 on the development machine. Skip when the test
        // runner happens to have access, so this is never a flaky failure.
        let p = Path::new("/dev/sdc");
        if !p.exists() {
            return;
        }
        if let Err(e) = open_path(p, Access::ReadOnly) {
            let msg = e.to_string();
            assert!(msg.contains("usermod -aG disk") || msg.contains("busy"), "{msg}");
        }
    }

    #[test]
    fn an_image_opens_and_reports_its_length() {
        let img = std::path::Path::new("tests/fixtures/gen/gpt-basic.img");
        let img = if img.exists() {
            img.to_path_buf()
        } else {
            PathBuf::from("../../tests/fixtures/gen/gpt-basic.img")
        };
        if !img.exists() {
            return; // fixtures not generated
        }
        let (src, info) = open_path(&img, Access::ReadOnly).unwrap();
        assert_eq!(info.kind, SourceKind::Image);
        assert_eq!(info.len, 64 * 1024 * 1024);
        assert!(!info.is_mounted());
        let mut sig = [0u8; 8];
        src.read_at(512, &mut sig);
        assert_eq!(&sig, b"EFI PART");
    }
}
