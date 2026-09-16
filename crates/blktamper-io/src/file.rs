//! Positioned reads from a regular file or a block device.
//!
//! Deliberately not `Read + Seek`: a seek-then-read pair is not atomic across
//! threads, and the I/O worker is not the only caller.

use blktamper_core::{BlockSink, BlockSource, ReadOutcome, WriteError};
use std::fs::{File, OpenOptions};
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

/// Shared by the read-only and write-capable handles.
///
/// One attempt per read. A failing drive being hammered with retries is a failing
/// drive about to stop answering at all (R-2.7).
fn read_at_impl(file: &File, len: u64, offset: u64, buf: &mut [u8]) -> ReadOutcome {
    if offset >= len {
        buf.fill(0);
        return ReadOutcome::Short { filled: 0 };
    }
    let want = buf.len().min((len - offset) as usize);
    let mut done = 0usize;
    while done < want {
        match file.read_at(&mut buf[done..want], offset + done as u64) {
            Ok(0) => break,
            Ok(n) => done += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
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
        read_at_impl(&self.file, self.len, offset, buf)
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

/// A write-capable handle.
///
/// Separate from `FileSource` on purpose: "this build opened the device read-only"
/// stays checkable by looking for constructors of this type, rather than by auditing
/// every call site (ADR-007). Nothing turns a `FileSource` into one of these.
#[derive(Debug)]
pub struct FileSink {
    file: File,
    len: u64,
    logical: u32,
    physical: u32,
    name: String,
    path: PathBuf,
}

impl FileSink {
    /// Open read-write. The caller is expected to have armed first.
    pub fn open_rw(path: impl AsRef<Path>) -> io::Result<FileSink> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().read(true).write(true).open(&path)?;
        let len = probe_len(&file, &path)?;
        let (logical, physical) = probe_sector_sizes(&path);
        let name = path.display().to_string();
        Ok(FileSink { file, len, logical, physical, name, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn set_logical_sector_size(&mut self, size: u32) {
        self.logical = size;
    }
}

impl BlockSource for FileSink {
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
        read_at_impl(&self.file, self.len, offset, buf)
    }
    fn name(&self) -> &str {
        &self.name
    }
}

impl BlockSink for FileSink {
    fn write_at(&self, offset: u64, data: &[u8]) -> Result<(), WriteError> {
        let end = offset.saturating_add(data.len() as u64);
        if end > self.len {
            return Err(WriteError::PastEnd {
                offset,
                len: data.len(),
                device_len: self.len,
            });
        }
        let mut done = 0usize;
        while done < data.len() {
            match self.file.write_at(&data[done..], offset + done as u64) {
                Ok(0) => {
                    return Err(WriteError::Io {
                        offset,
                        len: data.len(),
                        source: io::Error::other("the device accepted zero bytes"),
                    })
                }
                Ok(n) => done += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(WriteError::Io { offset, len: data.len(), source: e }),
            }
        }
        Ok(())
    }

    fn flush(&self) -> Result<(), WriteError> {
        self.file
            .sync_all()
            .map_err(|e| WriteError::Io { offset: 0, len: 0, source: e })
    }
}

#[cfg(test)]
mod sink_tests {
    use super::*;
    use std::io::Write as _;

    fn tmp(name: &str, data: &[u8]) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("blktamper-sink-{}-{name}.bin", std::process::id()));
        let mut f = File::create(&p).unwrap();
        f.write_all(data).unwrap();
        p
    }

    #[test]
    fn writes_land_and_read_back() {
        let p = tmp("basic", &[0u8; 1024]);
        let s = FileSink::open_rw(&p).unwrap();
        s.write_at(512, &[0xAB; 16]).unwrap();
        s.flush().unwrap();
        let mut got = [0u8; 16];
        s.read_at(512, &mut got);
        assert_eq!(got, [0xAB; 16]);
        assert_eq!(std::fs::read(&p).unwrap()[512..528], [0xAB; 16]);
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn a_write_past_the_end_is_refused_rather_than_extending_the_file() {
        let p = tmp("pastend", &[0u8; 64]);
        let s = FileSink::open_rw(&p).unwrap();
        let err = s.write_at(60, &[1u8; 16]).unwrap_err();
        assert!(matches!(err, WriteError::PastEnd { .. }));
        assert_eq!(std::fs::metadata(&p).unwrap().len(), 64, "the file must not grow");
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn a_read_only_file_refuses_to_open_for_writing() {
        use std::os::unix::fs::PermissionsExt;
        let p = tmp("ro", &[0u8; 32]);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o444)).unwrap();
        assert!(FileSink::open_rw(&p).is_err(), "a read-only file must not open for writing");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).ok();
        std::fs::remove_file(p).ok();
    }
}
