//! The undo journal.
//!
//! Written and flushed **before** the device is touched, so a crash between the two
//! leaves a recoverable record rather than a mystery. One JSON object per line, which
//! is greppable, appendable, and readable by anything.
//!
//! It lives off the target device. Storing the record of what you overwrote on the
//! thing you overwrote would be a poor plan (doc/07-write-safety.md).

use blktamper_core::ByteEdit;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    #[error("the journal directory {0} is on the device being edited; refusing to journal onto the target")]
    OnTargetDevice(PathBuf),
    #[error("could not create the journal at {path}: {source}")]
    Create {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("could not write the journal at {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug)]
pub struct Journal {
    path: PathBuf,
    file: File,
    entries: usize,
}

impl Journal {
    /// Where journals live: `$XDG_STATE_HOME/blktamper/journal/`, falling back to
    /// `~/.local/state` and then the temp directory.
    pub fn default_dir() -> PathBuf {
        if let Some(x) = std::env::var_os("XDG_STATE_HOME") {
            return PathBuf::from(x).join("blktamper/journal");
        }
        if let Some(h) = std::env::var_os("HOME") {
            return PathBuf::from(h).join(".local/state/blktamper/journal");
        }
        std::env::temp_dir().join("blktamper/journal")
    }

    /// Open a journal for edits to `device`.
    ///
    /// `stamp` is supplied rather than read from the clock so that callers in tests
    /// get a deterministic filename.
    pub fn create(device: &Path, stamp: &str) -> Result<Journal, JournalError> {
        Journal::create_in(&Journal::default_dir(), device, stamp)
    }

    pub fn create_in(dir: &Path, device: &Path, stamp: &str) -> Result<Journal, JournalError> {
        if on_same_device(dir, device) {
            return Err(JournalError::OnTargetDevice(dir.to_path_buf()));
        }
        std::fs::create_dir_all(dir)
            .map_err(|e| JournalError::Create { path: dir.to_path_buf(), source: e })?;
        let name = device
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("device")
            .replace(['/', ' '], "_");
        let path = dir.join(format!("{stamp}-{name}.jsonl"));
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| JournalError::Create { path: path.clone(), source: e })?;
        Ok(Journal { path, file, entries: 0 })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn entries(&self) -> usize {
        self.entries
    }

    /// Record one edit and make sure it is on stable storage before returning.
    ///
    /// The `fsync` is the whole point. A journal that is still in the page cache when
    /// the machine loses power has recorded nothing.
    pub fn append(&mut self, edit: &ByteEdit, node_path: &str, device: &Path) -> Result<(), JournalError> {
        let line = format!(
            "{{\"device\":\"{}\",\"path\":\"{}\",\"offset\":{},\"len\":{},\"old\":\"{}\",\"new\":\"{}\",\"reason\":\"{}\"}}\n",
            esc(&device.display().to_string()),
            esc(node_path),
            edit.offset,
            edit.old.len(),
            hex(&edit.old),
            hex(&edit.new),
            esc(&edit.reason),
        );
        self.file
            .write_all(line.as_bytes())
            .and_then(|()| self.file.sync_all())
            .map_err(|e| JournalError::Write { path: self.path.clone(), source: e })?;
        self.entries += 1;
        Ok(())
    }

    /// Read a journal back as the edits that would undo it, newest first.
    ///
    /// Undo is just the same edits with `old` and `new` swapped, applied in reverse.
    pub fn read_undo(path: &Path) -> std::io::Result<Vec<(ByteEdit, String)>> {
        let text = std::fs::read_to_string(path)?;
        let mut out = Vec::new();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let Some(offset) = field_num(line, "offset") else { continue };
            let Some(old) = field_str(line, "old").and_then(|s| unhex(&s)) else { continue };
            let Some(new) = field_str(line, "new").and_then(|s| unhex(&s)) else { continue };
            let node = field_str(line, "path").unwrap_or_default();
            out.push((
                ByteEdit { offset, old: new, new: old, reason: "undo".into() },
                node,
            ));
        }
        out.reverse();
        Ok(out)
    }
}

/// True when the journal directory lives on the device being edited.
///
/// The rule protects one specific mistake: editing `/dev/sdc` while the journal sits
/// on `/dev/sdc1`. The record of what you overwrote must not be on the thing you are
/// overwriting.
///
/// Two subtleties make the naive check wrong:
///
/// * A block device's own `st_dev` is the devtmpfs it is listed in, not the storage
///   it addresses. The number to compare is its `st_rdev`.
/// * The journal's filesystem reports the `st_dev` of a *partition* (`8:33`), while
///   the target is usually the *whole disk* (`8:32`). They never compare equal, so
///   the partition's parent disk has to be resolved through sysfs.
///
/// Editing an image file is not a case this guards: writing into a file changes the
/// file's contents, not the filesystem that holds it, so a journal alongside it is
/// perfectly safe.
fn on_same_device(dir: &Path, device: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    let Ok(dev_meta) = std::fs::metadata(device) else { return false };
    let target_rdev = dev_meta.rdev();
    if target_rdev == 0 {
        return false; // a regular file: nothing to protect against
    }

    // st_dev of whatever filesystem the journal directory will land on.
    let mut probe = dir;
    let journal_dev = loop {
        match std::fs::metadata(probe) {
            Ok(m) => break m.dev(),
            Err(_) => match probe.parent() {
                Some(p) => probe = p,
                None => return false,
            },
        }
    };

    if journal_dev == target_rdev {
        return true;
    }
    match parent_disk_dev(journal_dev) {
        Some(parent) => parent == target_rdev,
        None => false,
    }
}

/// For a partition's `st_dev`, the `st_rdev` of the whole disk it belongs to.
fn parent_disk_dev(dev: u64) -> Option<u64> {
    let (maj, min) = (major(dev), minor(dev));
    let link = std::fs::read_link(format!("/sys/dev/block/{maj}:{min}")).ok()?;
    // .../block/sdc/sdc1 -> the parent directory is the disk
    let disk = link.parent()?.file_name()?.to_str()?.to_string();
    let text = std::fs::read_to_string(format!("/sys/class/block/{disk}/dev")).ok()?;
    let (m, n) = text.trim().split_once(':')?;
    Some(makedev(m.parse().ok()?, n.parse().ok()?))
}

// glibc's encoding, which is what `st_dev` and `st_rdev` use on Linux.
fn major(dev: u64) -> u32 {
    (((dev >> 32) & 0xffff_f000) | ((dev >> 8) & 0x0000_0fff)) as u32
}
fn minor(dev: u64) -> u32 {
    (((dev >> 12) & 0xffff_ff00) | (dev & 0x0000_00ff)) as u32
}
fn makedev(maj: u64, min: u64) -> u64 {
    ((maj & 0xffff_f000) << 32)
        | ((maj & 0x0000_0fff) << 8)
        | ((min & 0xffff_ff00) << 12)
        | (min & 0x0000_00ff)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Minimal field extraction. The journal is ours and its shape is fixed, so this is
/// cheaper and more predictable than taking a JSON dependency for six keys.
fn field_str(line: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\":\"");
    let start = line.find(&pat)? + pat.len();
    let rest = &line[start..];
    let mut out = String::new();
    let mut chars = rest.chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                other => out.push(other),
            },
            c => out.push(c),
        }
    }
    None
}

fn field_num(line: &str, key: &str) -> Option<u64> {
    let pat = format!("\"{key}\":");
    let start = line.find(&pat)? + pat.len();
    let rest = &line[start..];
    let end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
    rest[..end].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("blktamper-journal-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn edit(offset: u64, old: &[u8], new: &[u8]) -> ByteEdit {
        ByteEdit { offset, old: old.to_vec(), new: new.to_vec(), reason: "scrub record".into() }
    }

    #[test]
    fn an_entry_round_trips_into_its_own_undo() {
        let dir = tmpdir("roundtrip");
        let device = std::env::temp_dir().join("not-a-real-device.img");
        std::fs::write(&device, [0u8; 16]).unwrap();
        let mut j = Journal::create_in(&dir, &device, "2026-09-16T12-00-00").unwrap();
        j.append(&edit(0x1C2, &[0x0C], &[0x07]), "mbr.entries[0].part_type", &device).unwrap();
        j.append(&edit(0x1FC4C0, &[0xE5, 1, 2], &[0xE5, 0, 0]), "fat.root.rec", &device).unwrap();
        assert_eq!(j.entries(), 2);

        let undo = Journal::read_undo(j.path()).unwrap();
        assert_eq!(undo.len(), 2);
        // newest first, and old/new swapped so applying it puts things back
        assert_eq!(undo[0].0.offset, 0x1FC4C0);
        assert_eq!(undo[0].0.old, vec![0xE5, 0, 0]);
        assert_eq!(undo[0].0.new, vec![0xE5, 1, 2]);
        assert_eq!(undo[1].1, "mbr.entries[0].part_type");
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_file(&device).ok();
    }

    #[test]
    fn strings_with_quotes_and_newlines_survive() {
        let dir = tmpdir("escape");
        let device = std::env::temp_dir().join("odd-\"name\".img");
        std::fs::write(&device, [0u8; 4]).unwrap();
        let mut j = Journal::create_in(&dir, &device, "stamp").unwrap();
        j.append(&edit(0, &[1], &[2]), "a\"b\\c\nd", &device).unwrap();
        let text = std::fs::read_to_string(j.path()).unwrap();
        assert_eq!(text.lines().count(), 1, "an escaped newline must not split the record");
        let undo = Journal::read_undo(j.path()).unwrap();
        assert_eq!(undo[0].1, "a\"b\\c\nd");
        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_file(&device).ok();
    }

    #[test]
    fn a_truncated_line_is_skipped_rather_than_fatal() {
        let dir = tmpdir("truncated");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("j.jsonl");
        std::fs::write(
            &p,
            "{\"offset\":16,\"old\":\"00\",\"new\":\"ff\",\"path\":\"a\"}\n\
             {\"offset\":32,\"old\":\"0\n",
        )
        .unwrap();
        let undo = Journal::read_undo(&p).unwrap();
        assert_eq!(undo.len(), 1, "a crash mid-write must not make the journal unreadable");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_image_file_does_not_trip_the_on_target_guard() {
        // The guard exists for "editing /dev/sdc with the journal on /dev/sdc1",
        // not for "editing a file with the journal next to it".
        let dir = tmpdir("image");
        let device = std::env::temp_dir().join("blktamper-guard-test.img");
        std::fs::write(&device, [0u8; 16]).unwrap();
        assert!(!on_same_device(&dir, &device));
        std::fs::remove_file(&device).ok();
    }

    /// Find a mounted partition and the whole disk it belongs to, so the guard can
    /// be tested against real hardware instead of a mock.
    fn a_mounted_partition() -> Option<(PathBuf, PathBuf, PathBuf)> {
        let text = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
        for line in text.lines() {
            let (pre, post) = line.split_once(" - ")?;
            let pre: Vec<&str> = pre.split(' ').collect();
            let post: Vec<&str> = post.split(' ').collect();
            if pre.len() < 6 || post.len() < 2 {
                continue;
            }
            let (mount_point, source) = (pre[4], post[1]);
            if !source.starts_with("/dev/") || mount_point.starts_with("/sys") {
                continue;
            }
            let part = PathBuf::from(source);
            let name = part.file_name()?.to_str()?;
            if !Path::new(&format!("/sys/class/block/{name}/partition")).exists() {
                continue;
            }
            // .../block/<disk>/<part>
            let link = std::fs::read_link(format!("/sys/class/block/{name}")).ok()?;
            let disk = link.parent()?.file_name()?.to_str()?.to_string();
            let disk = PathBuf::from("/dev").join(disk);
            if disk.exists() {
                return Some((PathBuf::from(mount_point), part, disk));
            }
        }
        None
    }

    #[test]
    fn the_journal_refuses_to_sit_on_the_disk_being_edited() {
        // The mistake this exists for: editing /dev/sdX with the journal on
        // /dev/sdX1. The partition and the whole disk have different device
        // numbers, so catching it needs the parent-disk lookup, not an equality
        // check -- which is why this is tested against a real mount.
        let Some((mount_point, partition, disk)) = a_mounted_partition() else {
            eprintln!("skipping: no mounted partition found");
            return;
        };
        let dir = mount_point.join("blktamper-journal-probe");

        assert!(
            matches!(
                Journal::create_in(&dir, &disk, "probe"),
                Err(JournalError::OnTargetDevice(_))
            ),
            "journal under {} must be refused for whole-disk target {}",
            mount_point.display(),
            disk.display()
        );
        assert!(
            matches!(
                Journal::create_in(&dir, &partition, "probe"),
                Err(JournalError::OnTargetDevice(_))
            ),
            "journal under {} must be refused for partition target {}",
            mount_point.display(),
            partition.display()
        );
        assert!(!dir.exists(), "a refused journal must not have created anything");

        // ...and somewhere else on the same machine is fine.
        let elsewhere = tmpdir("elsewhere");
        if !on_same_device(&elsewhere, &disk) {
            assert!(Journal::create_in(&elsewhere, &disk, "probe").is_ok());
            std::fs::remove_dir_all(&elsewhere).ok();
        }
    }

    #[test]
    fn device_number_encoding_round_trips() {
        for (maj, min) in [(8u64, 32u64), (8, 33), (259, 0), (0, 0), (4095, 255)] {
            let d = makedev(maj, min);
            assert_eq!((major(d) as u64, minor(d) as u64), (maj, min));
        }
    }

    #[test]
    fn hex_round_trips() {
        for v in [vec![], vec![0u8], vec![0xDE, 0xAD, 0xBE, 0xEF], vec![0xFF; 32]] {
            assert_eq!(unhex(&hex(&v)).unwrap(), v);
        }
        assert!(unhex("abc").is_none());
        assert!(unhex("zz").is_none());
    }
}
