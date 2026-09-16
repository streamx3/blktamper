//! Positioned reads from a regular file or a block device.
//!
//! Deliberately not `Read + Seek`: a seek-then-read pair is not atomic across
//! threads, and the I/O worker is not the only caller.

use blktamper_core::{BlockSource, ReadOutcome};
use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct FileSource {
    file: File,
    len: u64,
    logical: u32,
    physical: u32,
    name: String,
    path: PathBuf,
}

impl FileSource {
    /// Open read-only. Never opens for writing: a write-capable build adds a
    /// separate constructor so that "we only ever opened it O_RDONLY" stays
    /// checkable by reading one function (ADR-007).
    pub fn open_ro(path: impl AsRef<Path>) -> io::Result<FileSource> {
        let path = path.as_ref().to_path_buf();
        let file = File::open(&path)?;
        let len = probe_len(&file, &path)?;
        let (logical, physical) = probe_sector_sizes(&path);
        let name = path.display().to_string();
        Ok(FileSource { file, len, logical, physical, name, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Override the sector size. Needed whenever an image came off a 4Kn disk: the
    /// file has no sector size of its own and every LBA is then 8x wrong (R-2.3).
    pub fn set_logical_sector_size(&mut self, size: u32) {
        self.logical = size;
    }
}

fn probe_len(file: &File, path: &Path) -> io::Result<u64> {
    let meta = file.metadata()?;
    if meta.len() > 0 {
        return Ok(meta.len());
    }
    // Block devices report zero length from stat; ask the kernel properly.
    #[cfg(target_os = "linux")]
    {
        if let Some(n) = crate::linux::device_size(file) {
            return Ok(n);
        }
    }
    let _ = path;
    Ok(meta.len())
}

fn probe_sector_sizes(path: &Path) -> (u32, u32) {
    #[cfg(target_os = "linux")]
    {
        let l = crate::linux::logical_sector_size_by_path(path).unwrap_or(512);
        let p = crate::linux::physical_sector_size_by_path(path).unwrap_or(l);
        return (l, p);
    }
    #[allow(unreachable_code)]
    {
        let _ = path;
        (512, 512)
    }
}

impl BlockSource for FileSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn logical_sector_size(&self) -> u32 {
        self.logical
    }

    fn physical_sector_size(&self) -> u32 {
        self.physical
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> ReadOutcome {
        if offset >= self.len {
            buf.fill(0);
            return ReadOutcome::Short { filled: 0 };
        }
        let want = buf.len().min((self.len - offset) as usize);
        let mut done = 0usize;
        while done < want {
            match self.file.read_at(&mut buf[done..want], offset + done as u64) {
                Ok(0) => break,
                Ok(n) => done += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                // One attempt per sector. A failing drive being hammered with
                // retries is a failing drive about to stop answering at all.
                Err(_) => {
                    buf[done..].fill(0);
                    return ReadOutcome::Unreadable;
                }
            }
        }
        if done < buf.len() {
            buf[done..].fill(0);
            ReadOutcome::Short { filled: done }
        } else {
            ReadOutcome::Ok
        }
    }

    fn name(&self) -> &str {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp(data: &[u8]) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("blktamper-test-{}-{}.bin", std::process::id(), data.len()));
        let mut f = File::create(&p).unwrap();
        f.write_all(data).unwrap();
        p
    }

    #[test]
    fn reads_at_offsets() {
        let p = tmp(&(0u8..=255).collect::<Vec<_>>());
        let s = FileSource::open_ro(&p).unwrap();
        assert_eq!(s.len(), 256);
        let mut b = [0u8; 4];
        assert_eq!(s.read_at(16, &mut b), ReadOutcome::Ok);
        assert_eq!(b, [16, 17, 18, 19]);
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn reads_past_the_end_are_short() {
        let p = tmp(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let s = FileSource::open_ro(&p).unwrap();
        let mut b = [0u8; 8];
        assert_eq!(s.read_at(6, &mut b), ReadOutcome::Short { filled: 2 });
        assert_eq!(&b[..2], &[7, 8]);
        assert_eq!(s.read_at(1000, &mut b), ReadOutcome::Short { filled: 0 });
        std::fs::remove_file(p).ok();
    }
}
