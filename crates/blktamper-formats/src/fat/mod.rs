//! FAT12 / FAT16 / FAT32.
//!
//! Tier B of ADR-002: everything here needs arithmetic on values read from disk, so
//! none of it belongs in a descriptor table. Four things in particular:
//!
//! * **Geometry.** Nine BPB fields combine into the cluster count, and the cluster
//!   count *alone* decides whether this is FAT12, FAT16 or FAT32 (fatgen §4). The
//!   `fs_type` string is a comment. Everything downstream — where the FATs are,
//!   where the root is, how wide a FAT entry is — hangs off getting this right.
//! * **Cluster chains**, with a `ChainGuard`, because a corrupt FAT describes cycles
//!   happily and a UI thread must not follow one forever.
//! * **Mirror comparison** between FAT #0 and FAT #1, lazily, because on a 58 GiB
//!   stick each table is ~7 MB and reading both eagerly to render one node is not
//!   acceptable.
//! * **Directory listing**, which is where this tool earns its keep. Deleting a file
//!   on FAT writes exactly one byte — 0xE5 over the first character of the name — and
//!   releases the cluster chain. The size, the timestamps, the first cluster and any
//!   long-filename fragments all survive. `mdir` will not show you them. This module
//!   does, marked `Status::Info`, because a user asking "did the secure-delete tool
//!   actually work" is asking precisely about that residue.

pub mod desc;
mod scrub;

use crate::common::{read_exact_opt, u16le, u32le, ChainGuard, Step};
use blktamper_core::{
    BlockSource, Children, ChecksumAlgo, Derived, DerivedKind, Diagnostic, Expander, Extent,
    FieldFlags, FormatId, FormatProbe, Link, LinkKind, Node, NodeKind, ReadCtx, ReadOutcome,
    RegionReader, Registry, RenderCtx, Repr, Score, Span, Status, StructDesc, Value,
};
use std::sync::Arc;

pub const ID: FormatId = FormatId("fat");

/// One boot sector is all `probe` may read.
const BOOT_SECTOR_LEN: usize = 512;
/// Clusters a single directory may occupy before we stop walking. A directory this
/// large is either a very unusual volume or a cycle the `ChainGuard` has not closed.
const MAX_DIR_CLUSTERS: usize = 4096;
/// Records parsed from one directory. 16384 entries is half a megabyte of listing;
/// past that the node tree is no longer something a human reads.
const MAX_DIR_ENTRIES: usize = 16384;
/// Bytes of directory data read in one expansion. Without this a 4096-cluster chain
/// of 32 KiB clusters would be asked for as a single 128 MB allocation.
const MAX_DIR_BYTES: u64 = MAX_DIR_ENTRIES as u64 * desc::ENTRY_SIZE;
/// Clusters shown for one file's chain.
const MAX_CHAIN_CLUSTERS: usize = 65536;
/// Differing cluster indices reported when two FATs disagree. The first few identify
/// the damage; the rest would just be a long list.
const MAX_FAT_DIFFS: usize = 16;
/// Bytes of each FAT compared before giving up, so the comparison stays bounded on a
/// multi-terabyte volume.
const MAX_FAT_COMPARE_BYTES: u64 = 16 << 20;
/// Chunk size for that comparison.
const FAT_COMPARE_CHUNK: usize = 64 << 10;
/// FAT entries decoded when a FAT node is expanded.
const FAT_PREVIEW_ENTRIES: u64 = 64;
/// Directory nesting followed before refusing to descend further.
const MAX_DIR_DEPTH: u32 = 64;

pub fn register(reg: &mut Registry) {
    reg.register(Arc::new(FatProbe));
}

// ---------------------------------------------------------------------- FAT type

/// Which width the allocation table entries have.
///
/// Determined by the cluster count and nothing else (fatgen §4). The thresholds look
/// off by a few — 4085 and 65525 rather than 4096 and 65536 — and that is deliberate:
/// the specification calls them "the perfectly proper way", and warns that adjusting
/// them by even one cluster will misread volumes produced by Microsoft's own tools.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatKind {
    Fat12,
    Fat16,
    Fat32,
}

impl FatKind {
    pub fn from_cluster_count(clusters: u64) -> FatKind {
        if clusters < 4085 {
            FatKind::Fat12
        } else if clusters < 65525 {
            FatKind::Fat16
        } else {
            FatKind::Fat32
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            FatKind::Fat12 => "FAT12",
            FatKind::Fat16 => "FAT16",
            FatKind::Fat32 => "FAT32",
        }
    }

    /// The `fs_type` string a formatter conventionally writes. Documentation only.
    pub fn fs_type_string(self) -> &'static str {
        match self {
            FatKind::Fat12 => "FAT12",
            FatKind::Fat16 => "FAT16",
            FatKind::Fat32 => "FAT32",
        }
    }

    /// Bits of a FAT entry that carry the cluster number. FAT32 stores 28, not 32:
    /// the top four bits are reserved and a writer must preserve them.
    pub fn mask(self) -> u32 {
        match self {
            FatKind::Fat12 => 0x0000_0FFF,
            FatKind::Fat16 => 0x0000_FFFF,
            FatKind::Fat32 => 0x0FFF_FFFF,
        }
    }

    /// Lowest value that means end-of-chain.
    pub fn eoc_min(self) -> u32 {
        match self {
            FatKind::Fat12 => 0x0000_0FF8,
            FatKind::Fat16 => 0x0000_FFF8,
            FatKind::Fat32 => 0x0FFF_FFF8,
        }
    }

    /// The single value that marks a cluster as unusable.
    pub fn bad_mark(self) -> u32 {
        match self {
            FatKind::Fat12 => 0x0000_0FF7,
            FatKind::Fat16 => 0x0000_FFF7,
            FatKind::Fat32 => 0x0FFF_FFF7,
        }
    }
}

// ---------------------------------------------------------------------- geometry

/// Everything that has to be computed before a single byte of the volume can be
/// located. Derived once, with checked arithmetic throughout, and then passed around.
///
/// `sane` is the gate: when the BPB does not describe a usable volume, every derived
/// value is zero and traversal stops rather than seeking to a wrapped offset. That is
/// a display decision, not a parse failure — the boot sector is still shown in full.
#[derive(Clone, Copy, Debug)]
pub struct Geom {
    /// Absolute byte offset of the boot sector.
    pub base: u64,
    pub bytes_per_sector: u64,
    pub sectors_per_cluster: u64,
    pub bytes_per_cluster: u64,
    pub reserved_sectors: u64,
    pub num_fats: u64,
    pub root_entries: u64,
    /// `fat_size_16` when non-zero, else `fat_size_32`.
    pub fat_size: u64,
    /// `total_sectors_16` when non-zero, else `total_sectors_32`.
    pub total_sectors: u64,
    pub root_dir_sectors: u64,
    pub data_sectors: u64,
    pub cluster_count: u64,
    pub kind: FatKind,
    pub root_cluster: u64,
    /// Absolute byte offset of FAT #0.
    pub fat_start: u64,
    /// Absolute byte offset of the fixed root directory (FAT12/16 only).
    pub root_dir_start: u64,
    /// Absolute byte offset of cluster 2.
    pub data_start: u64,
    /// False when the BPB cannot describe a volume; nothing derived may be trusted.
    pub sane: bool,
    /// Length of the device this volume sits on, when the caller knew it.
    pub device_len: u64,
}

impl Geom {
    /// Derive the layout from the first 36 bytes of the boot sector.
    ///
    /// Returns the diagnostics as well, because several of them belong on specific
    /// BPB fields rather than on the volume as a whole.
    pub fn derive(boot: &[u8], base: u64) -> (Geom, Vec<(&'static str, Diagnostic)>) {
        let mut d: Vec<(&'static str, Diagnostic)> = Vec::new();
        let b8 = |o: usize| boot.get(o).copied().unwrap_or(0) as u64;
        let b16 = |o: usize| u16le(boot, o).unwrap_or(0) as u64;
        let b32 = |o: usize| u32le(boot, o).unwrap_or(0) as u64;

        let bytes_per_sector = b16(0x0B);
        let sectors_per_cluster = b8(0x0D);
        let reserved_sectors = b16(0x0E);
        let num_fats = b8(0x10);
        let root_entries = b16(0x11);
        let ts16 = b16(0x13);
        let fs16 = b16(0x16);
        let ts32 = b32(0x20);
        let fs32 = b32(0x24);
        let root_cluster = b32(0x2C);

        let bps_ok = matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096);
        let spc_ok =
            sectors_per_cluster != 0 && sectors_per_cluster.is_power_of_two() && sectors_per_cluster <= 128;

        let mut blank = Geom {
            base,
            bytes_per_sector,
            sectors_per_cluster,
            bytes_per_cluster: 0,
            reserved_sectors,
            num_fats,
            root_entries,
            fat_size: 0,
            total_sectors: 0,
            root_dir_sectors: 0,
            data_sectors: 0,
            cluster_count: 0,
            kind: FatKind::Fat12,
            root_cluster,
            fat_start: base,
            root_dir_start: base,
            data_start: base,
            sane: false,
            device_len: u64::MAX,
        };

        if !bps_ok {
            d.push((
                "bytes_per_sector",
                Diagnostic::bad(format!(
                    "{bytes_per_sector} is not a supported sector size; nothing in this \
                     volume can be located"
                ))
                .with_hint("512, 1024, 2048 or 4096 are the only values a FAT driver accepts"),
            ));
        }
        if !spc_ok {
            d.push((
                "sectors_per_cluster",
                Diagnostic::bad(format!(
                    "{sectors_per_cluster} is not a power of two in 1..=128; the cluster \
                     size is unusable"
                )),
            ));
        }
        // Note what is *not* checked here: `fs16 != 0 && fs32 != 0`. Offset 0x24 only
        // holds `fat_size_32` on a FAT32 volume; on FAT12/16 it is the first four
        // bytes of the FAT12/16 EBPB — drive_number, reserved1, boot_signature and
        // the low byte of volume_id — so reading it as a FAT size and complaining
        // that "both are set" fires on every healthy FAT12 and FAT16 volume
        // mkfs.vfat has ever written. The real inconsistency is a non-zero
        // fat_size_16 on a volume the cluster count says is FAT32, and that needs
        // the cluster count, so it is raised further down.
        if ts16 != 0 && ts32 != 0 {
            d.push((
                "total_sectors_16",
                Diagnostic::warn(format!(
                    "both total_sectors_16 ({ts16}) and total_sectors_32 ({ts32}) are \
                     set; the 16-bit field wins and the 32-bit one is ignored"
                )),
            ));
        }

        let fat_size = if fs16 != 0 { fs16 } else { fs32 };
        let total_sectors = if ts16 != 0 { ts16 } else { ts32 };
        if fat_size == 0 {
            d.push((
                "fat_size_16",
                Diagnostic::bad("no FAT size in either field; there is no allocation table to follow"),
            ));
        }
        if total_sectors == 0 {
            d.push((
                "total_sectors_16",
                Diagnostic::bad("no volume size in either field; the volume has no extent"),
            ));
        }
        if !bps_ok || !spc_ok || fat_size == 0 || total_sectors == 0 {
            return (blank, d);
        }

        // root_dir_sectors = ((root_entries * 32) + (bytes_per_sector - 1)) / bytes_per_sector
        let root_dir_sectors = root_entries
            .checked_mul(32)
            .and_then(|n| n.checked_add(bytes_per_sector - 1))
            .map(|n| n / bytes_per_sector)
            .unwrap_or(0);

        let meta = num_fats
            .checked_mul(fat_size)
            .and_then(|n| n.checked_add(reserved_sectors))
            .and_then(|n| n.checked_add(root_dir_sectors));

        let Some(meta) = meta else {
            d.push((
                "fat_size_16",
                Diagnostic::bad("reserved + FATs + root directory overflows 64 bits"),
            ));
            return (blank, d);
        };

        let Some(data_sectors) = total_sectors.checked_sub(meta) else {
            d.push((
                "total_sectors_32",
                Diagnostic::bad(format!(
                    "the volume declares {total_sectors} sectors but its reserved area, \
                     {num_fats} FATs and root directory already need {meta}; there is no \
                     data region"
                ))
                .with_hint("either the size field or the FAT size has been altered"),
            ));
            return (blank, d);
        };

        let cluster_count = data_sectors / sectors_per_cluster;
        let kind = FatKind::from_cluster_count(cluster_count);
        if cluster_count == 0 {
            d.push((
                "sectors_per_cluster",
                Diagnostic::bad("the data region holds no whole cluster"),
            ));
        }

        let fat_start = reserved_sectors
            .checked_mul(bytes_per_sector)
            .and_then(|n| n.checked_add(base));
        let root_dir_start = num_fats
            .checked_mul(fat_size)
            .and_then(|n| n.checked_add(reserved_sectors))
            .and_then(|n| n.checked_mul(bytes_per_sector))
            .and_then(|n| n.checked_add(base));
        let data_start = root_dir_start
            .and_then(|r| root_dir_sectors.checked_mul(bytes_per_sector).and_then(|n| r.checked_add(n)));

        let (Some(fat_start), Some(root_dir_start), Some(data_start)) =
            (fat_start, root_dir_start, data_start)
        else {
            d.push((
                "total_sectors_32",
                Diagnostic::bad("the volume layout overflows a 64-bit byte offset"),
            ));
            return (blank, d);
        };

        // A FAT32 volume must leave fat_size_16 zero, because on FAT32 those two
        // bytes are the only thing that says "read the size from 0x24 instead". A
        // non-zero value here on a volume the cluster count calls FAT32 means the
        // 16-bit field wins and the whole layout shifts.
        if kind == FatKind::Fat32 && fs16 != 0 {
            d.push((
                "fat_size_16",
                Diagnostic::warn(format!(
                    "fat_size_16 is {fs16}, but {cluster_count} clusters makes this \
                     FAT32, whose FAT size must come from fat_size_32 ({fs32}) with \
                     this field left at zero (fatgen §3.1)"
                ))
                .with_hint(
                    "the 16-bit field is the one used here, so every offset past the \
                     reserved area depends on which of the two is right",
                ),
            ));
        }

        // FAT32 puts its root in the data region; FAT12/16 puts it in a fixed area
        // between the FATs and the data, and mixing the two up is the classic way to
        // read a directory out of the middle of a file.
        match kind {
            FatKind::Fat32 if root_entries != 0 => d.push((
                "root_entries",
                Diagnostic::warn(format!(
                    "root_entries is {root_entries}, but a volume with {cluster_count} \
                     clusters is FAT32, whose root directory is a cluster chain and has \
                     no fixed size"
                )),
            )),
            FatKind::Fat12 | FatKind::Fat16 if root_entries == 0 => d.push((
                "root_entries",
                Diagnostic::bad(format!(
                    "root_entries is zero, but {cluster_count} clusters makes this \
                     {} — whose root directory is the fixed area this field sizes",
                    kind.name()
                )),
            )),
            _ => {}
        }

        blank = Geom {
            bytes_per_cluster: sectors_per_cluster.saturating_mul(bytes_per_sector),
            fat_size,
            total_sectors,
            root_dir_sectors,
            data_sectors,
            cluster_count,
            kind,
            fat_start,
            root_dir_start,
            data_start,
            sane: cluster_count > 0,
            ..blank
        };
        (blank, d)
    }

    /// Record the size of the device the volume sits on, for range plausibility notes.
    pub fn with_device_len(mut self, len: u64) -> Geom {
        self.device_len = len;
        self
    }

    /// Byte offset of a data cluster, or `None` when the number is out of range or
    /// the arithmetic would overflow.
    pub fn cluster_to_byte(&self, cluster: u64) -> Option<u64> {
        if !self.sane || cluster < 2 {
            return None;
        }
        cluster
            .checked_sub(2)?
            .checked_mul(self.bytes_per_cluster)?
            .checked_add(self.data_start)
    }

    /// Highest cluster number that exists on this volume.
    pub fn last_cluster(&self) -> u64 {
        self.cluster_count.saturating_add(1)
    }

    pub fn cluster_in_range(&self, cluster: u64) -> bool {
        self.sane && cluster >= 2 && cluster <= self.last_cluster()
    }

    /// Byte offset of FAT copy `n`.
    pub fn fat_offset(&self, n: u64) -> Option<u64> {
        let len = self.fat_bytes()?;
        n.checked_mul(len)?.checked_add(self.fat_start)
    }

    pub fn fat_bytes(&self) -> Option<u64> {
        self.fat_size.checked_mul(self.bytes_per_sector)
    }

    /// Byte offset of the FAT entry for `cluster` within a FAT, plus the width to
    /// read. FAT12 entries are 12 bits and straddle byte boundaries, which is the
    /// entire reason this returns an offset rather than an index.
    fn fat_entry_offset(&self, fat: u64, cluster: u64) -> Option<(u64, usize)> {
        let base = self.fat_offset(fat)?;
        match self.kind {
            FatKind::Fat12 => {
                let off = cluster.checked_add(cluster / 2)?;
                Some((base.checked_add(off)?, 2))
            }
            FatKind::Fat16 => Some((base.checked_add(cluster.checked_mul(2)?)?, 2)),
            FatKind::Fat32 => Some((base.checked_add(cluster.checked_mul(4)?)?, 4)),
        }
    }

    /// Total bytes the volume claims, for the region node's extent.
    pub fn volume_bytes(&self) -> u64 {
        self.total_sectors.saturating_mul(self.bytes_per_sector).max(BOOT_SECTOR_LEN as u64)
    }

    fn render(&self) -> RenderCtx {
        RenderCtx {
            sector_size: if self.bytes_per_sector == 0 {
                512
            } else {
                self.bytes_per_sector as u32
            },
            cluster_base: if self.sane {
                Some((self.data_start, self.bytes_per_cluster))
            } else {
                None
            },
            device_len: self.device_len,
        }
    }

    fn ctx_at(&self, at: u64) -> ReadCtx {
        ReadCtx::at(at).with_region_base(self.base).with_render(self.render())
    }
}

/// Read one FAT entry, masked to the type's width. `None` when it is off the end of
/// the table or the device refused.
pub fn fat_entry(src: &dyn BlockSource, geom: &Geom, fat: u64, cluster: u64) -> Option<u32> {
    let (off, width) = geom.fat_entry_offset(fat, cluster)?;
    let end = geom.fat_offset(fat)?.checked_add(geom.fat_bytes()?)?;
    if off.checked_add(width as u64)? > end {
        return None;
    }
    let buf = read_exact_opt(src, off, width)?;
    let raw = match width {
        2 => u16le(&buf, 0)? as u32,
        _ => u32le(&buf, 0)?,
    };
    Some(match geom.kind {
        // 12-bit entries are packed three per two entries; the odd one is the high
        // nibble of the shared byte.
        FatKind::Fat12 => {
            if cluster % 2 == 1 {
                raw >> 4
            } else {
                raw & 0x0FFF
            }
        }
        _ => raw & geom.kind.mask(),
    })
}

/// How a cluster chain stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChainEnd {
    /// An end-of-chain marker: the normal, healthy ending.
    Eoc(u32),
    /// The chain ran into a cluster marked unusable.
    Bad(u64),
    /// The next entry reads as free. On a live file this is corruption; on a deleted
    /// one it is simply what deletion does.
    Free(u64),
    /// The next cluster number is outside the volume.
    OutOfRange(u64),
    /// The chain revisits a cluster it has already used.
    Loop(u64),
    /// Stopped at the traversal limit rather than at a marker.
    Truncated,
    /// The FAT could not be read.
    Unreadable(u64),
}

/// Follow a cluster chain from `start`, bounded and cycle-proof.
pub fn follow_chain(
    src: &dyn BlockSource,
    geom: &Geom,
    start: u64,
    limit: usize,
) -> (Vec<u64>, ChainEnd) {
    let mut out: Vec<u64> = Vec::new();
    let mut guard = ChainGuard::new(limit);
    let mut cur = start;
    loop {
        if !geom.cluster_in_range(cur) {
            return (out, ChainEnd::OutOfRange(cur));
        }
        match guard.visit(cur) {
            Step::Continue => {}
            Step::Loop => return (out, ChainEnd::Loop(cur)),
            Step::TooLong => return (out, ChainEnd::Truncated),
        }
        out.push(cur);
        let Some(next) = fat_entry(src, geom, 0, cur) else {
            return (out, ChainEnd::Unreadable(cur));
        };
        if next >= geom.kind.eoc_min() {
            return (out, ChainEnd::Eoc(next));
        }
        if next == geom.kind.bad_mark() {
            return (out, ChainEnd::Bad(cur));
        }
        if next == 0 {
            return (out, ChainEnd::Free(cur));
        }
        cur = next as u64;
    }
}

// ------------------------------------------------------------------------- probe

#[derive(Debug)]
pub struct FatProbe;

impl FormatProbe for FatProbe {
    fn id(&self) -> FormatId {
        ID
    }

    fn name(&self) -> &'static str {
        "FAT12/16/32 volume"
    }

    /// Scores, never decides.
    ///
    /// A FAT boot sector, an exFAT boot sector and an NTFS boot sector all begin with
    /// a jump instruction and an 8-byte OEM name and all end with 55 AA. The three
    /// hard discriminators are the OEM string, a sane `bytes_per_sector`, and the
    /// pair `reserved_sectors`/`num_fats`, which NTFS and exFAT both leave at zero
    /// because they have no FAT in the DOS sense. Everything past that is degree of
    /// confidence, not identity.
    fn probe(&self, src: &dyn BlockSource, at: u64) -> Score {
        let (b, outcome) = src.read_vec(at, BOOT_SECTOR_LEN);
        if outcome == ReadOutcome::Unreadable || b.len() < BOOT_SECTOR_LEN {
            return 0;
        }
        if b[desc::BOOT_SIG_OFFSET as usize] != 0x55 || b[desc::BOOT_SIG_OFFSET as usize + 1] != 0xAA
        {
            return 0;
        }
        if !(b[0] == 0xEB && b[2] == 0x90) && b[0] != 0xE9 {
            return 0;
        }
        // Say no rather than "probably not": these two are other filesystems that
        // wear the same hat, and a viewer that opens them as FAT shows nonsense.
        if &b[3..11] == b"EXFAT   " || &b[3..11] == b"NTFS    " {
            return 0;
        }
        let bps = u16::from_le_bytes([b[0x0B], b[0x0C]]) as u64;
        if !matches!(bps, 512 | 1024 | 2048 | 4096) {
            return 0;
        }
        let spc = b[0x0D] as u64;
        if spc == 0 || !spc.is_power_of_two() || spc > 128 {
            return 0;
        }
        if u16::from_le_bytes([b[0x0E], b[0x0F]]) == 0 || b[0x10] == 0 {
            return 0;
        }

        // Signature and shape agree. Geometry decides whether this is a confident
        // identification or only a plausible one.
        let mut score: u32 = 45;
        if matches!(b[0x15], 0xF0 | 0xF8..=0xFF) {
            score += 5;
        }

        let (geom, _) = Geom::derive(&b, at);
        let geom = geom.with_device_len(src.len());
        if !geom.sane {
            return score.min(40) as Score;
        }
        score += 30;

        let (sig_off, type_off) = match geom.kind {
            FatKind::Fat32 => (0x42usize, 0x52usize),
            _ => (0x26, 0x36),
        };
        if matches!(b.get(sig_off), Some(0x28) | Some(0x29)) {
            score += 10;
        }
        if b.get(type_off..type_off + 3) == Some(b"FAT") {
            score += 10;
        }
        // A volume that claims more sectors than exist is still a FAT volume, but it
        // is not self-consistent and should not be sold as certain.
        let end = at.checked_add(geom.volume_bytes());
        if end.is_none() || end.unwrap_or(u64::MAX) > src.len() {
            score = score.saturating_sub(10);
        }
        score.min(100) as Score
    }

    fn open(&self, src: Arc<dyn BlockSource>, at: u64) -> Box<dyn RegionReader> {
        Box::new(FatReader { src, base: at })
    }
}

// ------------------------------------------------------------------------ reader

#[derive(Debug)]
pub struct FatReader {
    src: Arc<dyn BlockSource>,
    base: u64,
}

impl FatReader {
    pub fn new(src: Arc<dyn BlockSource>, base: u64) -> FatReader {
        FatReader { src, base }
    }

    /// The derived layout, for callers that want the numbers without the tree.
    pub fn geometry(&self) -> Geom {
        let (boot, _) = self.src.read_vec(self.base, BOOT_SECTOR_LEN);
        Geom::derive(&boot, self.base).0.with_device_len(self.src.len())
    }
}

impl RegionReader for FatReader {
    fn scrub_plan(
        &self,
        node: &Node,
        mode: blktamper_core::scrub::ScrubMode,
    ) -> Option<blktamper_core::scrub::ScrubPlan> {
        self.plan_scrub(node, mode)
    }

    fn id(&self) -> FormatId {
        ID
    }

    fn base(&self) -> u64 {
        self.base
    }

    fn root(&self) -> Node {
        let src = &*self.src;
        let (boot, outcome) = src.read_vec(self.base, BOOT_SECTOR_LEN);
        let (geom, field_diags) = Geom::derive(&boot, self.base);
        let geom = geom.with_device_len(src.len());

        let label = if geom.sane {
            format!("{} volume", geom.kind.name())
        } else {
            "FAT volume (geometry unusable)".to_string()
        };
        let mut root = Node::region(label, Span::bytes(self.base, geom.volume_bytes()));
        root.doc = Some(
            "A FAT volume. Its type is not stored anywhere: FAT12, FAT16 and FAT32 are \
             told apart by counting clusters (fatgen §4).",
        );

        let mut kids =
            vec![boot_sector_node(&boot, outcome, &geom, &field_diags, src, "boot sector", self.base)];
        kids.push(geometry_node(&geom));

        if geom.kind == FatKind::Fat32 && geom.sane {
            kids.push(fsinfo_node(src, &geom, &boot));
            kids.push(backup_boot_node(src, &geom, &boot));
        }
        if geom.sane {
            kids.push(fat_area_node(&geom));
            kids.push(root_dir_node(&geom));
        } else {
            kids.push(
                Node::new("volume contents", NodeKind::Region).with_diag(
                    Diagnostic::bad(
                        "the BPB does not describe a usable volume, so the FATs, the root \
                         directory and the data region cannot be located",
                    )
                    .with_hint(
                        "the boot sector above is still shown in full; a FAT32 backup copy \
                         normally lives six sectors in",
                    ),
                ),
            );
        }

        let deep = kids.iter().fold(Status::Ok, |a, k| a.merge(k.deep_status()));
        root.status = root.status.merge(deep.min(Status::Warn));
        root.with_children(kids)
    }
}

// --------------------------------------------------------------- boot sector node

/// Read one descriptor out of a buffer we already hold, at `off` within it.
fn sub_struct(
    d: &'static StructDesc,
    buf: &[u8],
    off: usize,
    ctx: ReadCtx,
    outcome: ReadOutcome,
) -> Node {
    let size = d.size.unwrap_or(0) as usize;
    let end = off.saturating_add(size);
    let slice = buf.get(off..end.min(buf.len())).unwrap_or(&[]);
    let o = if outcome == ReadOutcome::Unreadable {
        ReadOutcome::Unreadable
    } else if slice.len() < size {
        ReadOutcome::Short { filled: slice.len() }
    } else {
        ReadOutcome::Ok
    };
    blktamper_core::read_struct(d, slice, o, ctx)
}

/// Attach a diagnostic to one named child of an already-built struct node.
fn annotate(mut n: Node, field: &str, diag: Diagnostic) -> Node {
    let mut kids = n.children.resolved().map(|c| c.to_vec()).unwrap_or_default();
    if let Some(k) = kids.iter_mut().find(|k| k.label == field) {
        let taken = std::mem::take(k);
        *k = taken.with_diag(diag.clone());
        n.status = n.status.merge(diag.status.min(Status::Warn));
        return n.with_children(kids);
    }
    n.with_diag(diag)
}

/// Build the tree for one boot sector.
///
/// `at` is where this sector lives and `geom.base` is where the *volume* starts:
/// for sector 0 they are the same, for the backup copy six sectors in they are not.
/// Keeping them apart is what stops the backup being measured from its own offset
/// and then reported as a volume that overruns the device.
fn boot_sector_node(
    boot: &[u8],
    outcome: ReadOutcome,
    geom: &Geom,
    field_diags: &[(&'static str, Diagnostic)],
    src: &dyn BlockSource,
    label: &'static str,
    at: u64,
) -> Node {
    let ctx = geom.ctx_at(at);
    let mut bpb = sub_struct(&desc::BPB, boot, 0, ctx, outcome);
    for (field, diag) in field_diags {
        bpb = annotate(bpb, field, diag.clone());
    }

    // The volume's own idea of its size, checked against the device it is on. A
    // formatter handed a size in the wrong unit produces exactly this, and the tail
    // of the filesystem is then permanently unreadable.
    let vol_end = geom.base.checked_add(geom.volume_bytes());
    if geom.sane {
        match vol_end {
            Some(end) if end > src.len() => {
                let over = end - src.len();
                let field = if u16le(boot, 0x13).unwrap_or(0) != 0 {
                    "total_sectors_16"
                } else {
                    "total_sectors_32"
                };
                bpb = annotate(
                    bpb,
                    field,
                    Diagnostic::bad(format!(
                        "the volume claims {} sectors, which ends {over} bytes past the end \
                         of the device; the last {} sectors cannot exist",
                        geom.total_sectors,
                        over.div_ceil(geom.bytes_per_sector.max(1))
                    ))
                    .with_hint(
                        "usually a formatter given a size in KiB where it wanted sectors; \
                         everything past the device end reads as unreadable, not as zeros",
                    ),
                );
            }
            None => {
                bpb = annotate(
                    bpb,
                    "total_sectors_32",
                    Diagnostic::bad("volume start + size overflows a 64-bit byte offset"),
                );
            }
            _ => {}
        }
    }

    // The media byte has exactly one job left: matching the low byte of FAT[0].
    if geom.sane {
        if let Some(fat0) = fat_entry(src, geom, 0, 0) {
            let media = boot.get(0x15).copied().unwrap_or(0);
            if (fat0 & 0xFF) as u8 != media {
                bpb = annotate(
                    bpb,
                    "media",
                    Diagnostic::warn(format!(
                        "media byte is {media:#04X} but FAT[0] starts {:#04X}; the one \
                         consistency check the allocation table carries does not hold",
                        fat0 & 0xFF
                    )),
                );
            }
        }
    }

    let (ext, ext_end) = match geom.kind {
        FatKind::Fat32 => (&desc::EBPB32, 0x5Ausize),
        _ => (&desc::EBPB16, 0x3Eusize),
    };
    let mut ebpb = sub_struct(
        ext,
        boot,
        desc::EBPB_OFFSET as usize,
        geom.ctx_at(at + desc::EBPB_OFFSET),
        outcome,
    );
    ebpb = annotate_ebpb(ebpb, geom, boot, ext_end);

    let code_off = ext_end as u64;
    let code_len = desc::BOOT_SIG_OFFSET.saturating_sub(code_off);
    let code_raw = boot
        .get(ext_end..desc::BOOT_SIG_OFFSET as usize)
        .map(|s| s.to_vec())
        .unwrap_or_default();
    let boot_code = Node {
        label: "boot code".into(),
        extent: Extent::bytes(at + code_off, code_len),
        kind: NodeKind::Raw,
        value: Value::Bytes(code_raw.clone()),
        repr: Repr::Raw,
        flags: FieldFlags::OPAQUE,
        doc: Some(
            "x86 boot code and its error strings, reached by the jump at offset 0. \
             Opaque here: disassembly is out of scope, but the strings inside it \
             usually name the tool that wrote the volume.",
        ),
        raw: code_raw,
        ..Default::default()
    };

    let sig_raw = boot
        .get(desc::BOOT_SIG_OFFSET as usize..BOOT_SECTOR_LEN)
        .map(|s| s.to_vec())
        .unwrap_or_default();
    let mut sig = Node {
        label: "boot_signature".into(),
        extent: Extent::bytes(at + desc::BOOT_SIG_OFFSET, 2),
        kind: NodeKind::Field,
        value: Value::Bytes(sig_raw.clone()),
        repr: Repr::Hex,
        doc: Some(
            "Must be 55 AA. Shared with the MBR and with every other boot sector, so \
             its presence proves nothing on its own — but its absence means no BIOS \
             would ever have booted this volume.",
        ),
        raw: sig_raw.clone(),
        ..Default::default()
    };
    if sig_raw != [0x55, 0xAA] {
        sig = sig.with_diag(Diagnostic::bad(format!(
            "expected 55 AA, found {}",
            blktamper_core::value::hex_bytes(&sig_raw)
        )));
    }

    let kids = vec![bpb, ebpb, boot_code, sig];
    let deep = kids.iter().fold(Status::Ok, |a, k| a.merge(k.deep_status()));
    let mut n = Node::region(label, Span::bytes(at, BOOT_SECTOR_LEN as u64));
    n.doc = Some("Sector 0 of the volume: the BPB, its type-specific extension, the boot code and 55 AA.");
    n.status = n.status.merge(deep.min(Status::Warn));
    n.with_children(kids)
}

/// Cross-checks that need the computed geometry rather than the descriptor alone.
fn annotate_ebpb(mut n: Node, geom: &Geom, boot: &[u8], ext_end: usize) -> Node {
    let type_off = ext_end - 8;
    let stored: String = boot
        .get(type_off..ext_end)
        .map(|s| blktamper_core::value::ascii_lossy(s, true))
        .unwrap_or_default();

    // fatgen §4: the string is a comment. Saying so on the node is the point — a
    // reader who trusts it on a resized volume gets the wrong entry width and then
    // the wrong data for every file.
    if geom.sane && !stored.starts_with(geom.kind.fs_type_string()) {
        n = annotate(
            n,
            "fs_type",
            Diagnostic::warn(format!(
                "fs_type says \"{stored}\" but {} clusters makes this {}; the string is \
                 documentation and the cluster count is the determination (fatgen §4)",
                geom.cluster_count,
                geom.kind.name()
            ))
            .with_hint("a resized volume commonly keeps the old string"),
        );
    }

    if geom.kind == FatKind::Fat32 {
        if geom.sane && !geom.cluster_in_range(geom.root_cluster) {
            n = annotate(
                n,
                "root_cluster",
                Diagnostic::bad(format!(
                    "root cluster {} is outside 2..={}; the root directory cannot be found",
                    geom.root_cluster,
                    geom.last_cluster()
                )),
            );
        }
        let ext_flags = u16le(boot, 0x28).unwrap_or(0);
        if ext_flags & 0x80 != 0 {
            n = annotate(
                n,
                "ext_flags",
                Diagnostic::info(format!(
                    "mirroring is disabled: only FAT #{} is live and the other {} \
                     copies are stale by design",
                    ext_flags & 0x0F,
                    geom.num_fats.saturating_sub(1)
                ))
                .with_hint("differences between the FATs below are expected, not corruption"),
            );
        }
        let backup = u16le(boot, 0x32).unwrap_or(0);
        if backup == 0 {
            n = annotate(
                n,
                "backup_boot_sector",
                Diagnostic::warn(
                    "no backup boot sector: if this sector is damaged the volume's geometry \
                     is unrecoverable",
                ),
            );
        }
    }
    n
}

// ------------------------------------------------------------------ geometry node

fn computed(label: &'static str, value: Value, repr: Repr, doc: &'static str) -> Node {
    Node {
        label: label.into(),
        extent: Extent::None,
        kind: NodeKind::Field,
        value,
        repr,
        doc: Some(doc),
        ..Default::default()
    }
}

/// Everything derived from the BPB, shown as its own subtree.
///
/// These nodes own no bytes — `Extent::None` — because they are not on the disk.
/// Showing them anyway is the point: every offset elsewhere in this tree is a
/// consequence of these five numbers, and when a volume reads wrong this is where
/// the mistake is visible.
fn geometry_node(geom: &Geom) -> Node {
    let mut kids = vec![
        computed(
            "fat type",
            Value::Text(geom.kind.name().to_string()),
            Repr::Ascii,
            "Determined by the cluster count alone: below 4085 clusters FAT12, below \
             65525 FAT16, otherwise FAT32 (fatgen §4). No field on the volume states it.",
        ),
        computed(
            "cluster count",
            Value::Uint(geom.cluster_count),
            Repr::Dec,
            "data_sectors / sectors_per_cluster. The single number the FAT type is read \
             off; clusters are numbered 2..=cluster_count+1.",
        ),
        computed(
            "data sectors",
            Value::Uint(geom.data_sectors),
            Repr::Dec,
            "total_sectors - (reserved_sectors + num_fats * fat_size + root_dir_sectors).",
        ),
        computed(
            "root dir sectors",
            Value::Uint(geom.root_dir_sectors),
            Repr::Dec,
            "((root_entries * 32) + (bytes_per_sector - 1)) / bytes_per_sector. Zero on \
             FAT32, whose root directory is an ordinary cluster chain.",
        ),
        computed(
            "fat size (sectors)",
            Value::Uint(geom.fat_size),
            Repr::Dec,
            "fat_size_16 when non-zero, otherwise fat_size_32.",
        ),
        computed(
            "total sectors",
            Value::Uint(geom.total_sectors),
            Repr::SizeSectors,
            "total_sectors_16 when non-zero, otherwise total_sectors_32.",
        ),
        computed(
            "bytes per cluster",
            Value::Uint(geom.bytes_per_cluster),
            Repr::SizeBytes,
            "The allocation granularity: every file occupies a whole number of these, \
             and the remainder of the last one is slack that still holds whatever was \
             there before.",
        ),
        computed(
            "fat #0 offset",
            Value::Uint(geom.fat_start),
            Repr::Hex,
            "base + reserved_sectors * bytes_per_sector.",
        ),
        computed(
            "cluster 2 offset",
            Value::Uint(geom.data_start),
            Repr::Hex,
            "Where the data region starts. Cluster numbering begins at 2, so this is \
             the origin every cluster-to-offset conversion is measured from.",
        ),
    ];
    if geom.kind != FatKind::Fat32 {
        kids.push(computed(
            "root dir offset",
            Value::Uint(geom.root_dir_start),
            Repr::Hex,
            "Start of the fixed root directory area, between the last FAT and the data \
             region. FAT12/16 only.",
        ));
    }

    let mut n = Node::new("geometry (computed)", NodeKind::Group).with_children(kids);
    n.doc = Some(
        "Values derived from the BPB, not stored on the volume. Every offset in this \
         tree is a consequence of them.",
    );
    n.value = Value::Composite;
    n
}

// -------------------------------------------------------------------- FSInfo node

fn fsinfo_node(src: &dyn BlockSource, geom: &Geom, boot: &[u8]) -> Node {
    let sector = u16le(boot, 0x30).unwrap_or(0) as u64;
    let at = sector
        .checked_mul(geom.bytes_per_sector)
        .and_then(|n| n.checked_add(geom.base));
    let Some(at) = at else {
        return Node::new("FAT32 FSInfo", NodeKind::Struct)
            .with_diag(Diagnostic::bad("the FSInfo sector number overflows a byte offset"));
    };

    let (bytes, outcome) = src.read_vec(at, 512);
    let ctx = geom.ctx_at(at);
    let mut n = blktamper_core::read_struct(&desc::FSINFO, &bytes, outcome, ctx);
    n.label = format!("FAT32 FSInfo @sector {sector}").into();

    let free = u32le(&bytes, 0x1E8).unwrap_or(0) as u64;
    let next = u32le(&bytes, 0x1EC).unwrap_or(0) as u64;
    if free != 0xFFFF_FFFF && free > geom.cluster_count {
        n = annotate(
            n,
            "free_count",
            Diagnostic::warn(format!(
                "{free} free clusters claimed but the volume only has {}; the hint is \
                 stale or the volume was resized",
                geom.cluster_count
            )),
        );
    }
    if next != 0xFFFF_FFFF && !geom.cluster_in_range(next) && next != 0 {
        n = annotate(
            n,
            "next_free",
            Diagnostic::warn(format!(
                "next free cluster {next} is outside 2..={}",
                geom.last_cluster()
            )),
        );
    }
    n
}

// ------------------------------------------------------------ backup boot sector

fn backup_boot_node(src: &dyn BlockSource, geom: &Geom, boot: &[u8]) -> Node {
    let sector = u16le(boot, 0x32).unwrap_or(0) as u64;
    if sector == 0 {
        return Node::new("backup boot sector", NodeKind::Region)
            .with_diag(Diagnostic::warn("backup_boot_sector is zero: there is no backup copy"));
    }
    let at = sector
        .checked_mul(geom.bytes_per_sector)
        .and_then(|n| n.checked_add(geom.base));
    let Some(at) = at else {
        return Node::new("backup boot sector", NodeKind::Region)
            .with_diag(Diagnostic::bad("the backup sector number overflows a byte offset"));
    };

    let (bytes, outcome) = src.read_vec(at, BOOT_SECTOR_LEN);
    // Derive the backup's own geometry: if it disagrees with the primary that is the
    // whole point of looking at it.
    // Derived against the *volume's* base, not the backup sector's, so that the two
    // geometries are directly comparable.
    let (bgeom, bdiags) = Geom::derive(&bytes, geom.base);
    let bgeom = bgeom.with_device_len(geom.device_len);
    let mut n = boot_sector_node(&bytes, outcome, &bgeom, &bdiags, src, "backup boot sector", at);
    n.label = format!("backup boot sector @sector {sector}").into();
    n.doc = Some(
        "A copy of sector 0, written at format time and normally never updated again. \
         When it differs from the primary, one of them describes the volume that \
         actually exists and the other describes the volume as it was created.",
    );

    let same = bytes.len() == boot.len() && bytes[..0x5A.min(bytes.len())] == boot[..0x5A.min(boot.len())];
    if !same {
        let first = boot
            .iter()
            .zip(bytes.iter())
            .position(|(a, b)| a != b)
            .unwrap_or(0);
        n = n.with_diag(
            Diagnostic::warn(format!(
                "the backup differs from the primary boot sector, first at offset {first:#x} \
                 within the sector"
            ))
            .with_hint(
                "compare the two BPBs field by field; the one that matches the FAT and the \
                 root directory is the live geometry",
            ),
        );
    } else {
        n = n.with_diag(Diagnostic::info("identical to the primary boot sector through the EBPB"));
    }
    n
}

// ------------------------------------------------------------------ the FAT area

fn fat_area_node(geom: &Geom) -> Node {
    let fat_bytes = geom.fat_bytes().unwrap_or(0);
    let total = fat_bytes.saturating_mul(geom.num_fats);
    let mut kids: Vec<Node> = Vec::new();

    for i in 0..geom.num_fats.min(8) {
        let Some(off) = geom.fat_offset(i) else { continue };
        let mut n = Node::region(format!("FAT #{i} @{off:#012X}"), Span::bytes(off, fat_bytes));
        n.doc = Some(
            "One allocation table: an array of next-cluster pointers indexed by cluster \
             number. Entry 0 holds the media byte, entry 1 holds end-of-chain plus two \
             dirty flags on FAT32, and cluster numbering therefore starts at 2.",
        );
        n = n.with_lazy(Arc::new(FatPreview { geom: *geom, fat: i }));
        kids.push(n);
    }

    if geom.num_fats >= 2 {
        let mut cmp = Node::new("mirror check", NodeKind::Group);
        cmp.value = Value::Composite;
        cmp.doc = Some(
            "Compares FAT #0 against every other copy. Expanded on demand: each table \
             is megabytes on a real volume and reading them to draw one line is not a \
             trade this viewer makes.",
        );
        cmp = cmp.with_lazy(Arc::new(FatMirror { geom: *geom }));
        kids.push(cmp);
    } else {
        kids.push(
            Node::new("mirror check", NodeKind::Group).with_diag(Diagnostic::info(
                "only one FAT: nothing to compare, and no redundancy if it is damaged",
            )),
        );
    }

    let mut n = Node::region(
        format!("FAT area ({} copies x {} sectors)", geom.num_fats, geom.fat_size),
        Span::bytes(geom.fat_start, total),
    );
    n.doc = Some("The allocation tables. Every cluster chain in the volume is read from here.");
    n.with_children(kids)
}

/// The first few entries of one FAT, decoded. Lazy: the table itself is far too big
/// to render, and the interesting part is almost always the head of it.
#[derive(Debug)]
struct FatPreview {
    geom: Geom,
    fat: u64,
}

impl Expander for FatPreview {
    fn hint_len(&self) -> Option<usize> {
        Some(FAT_PREVIEW_ENTRIES as usize + 1)
    }

    fn expand(&self, src: &dyn BlockSource) -> Vec<Node> {
        let g = &self.geom;
        let mut out = Vec::new();
        let last = FAT_PREVIEW_ENTRIES.min(g.last_cluster().saturating_add(1));
        for c in 0..=last {
            let Some((off, width)) = g.fat_entry_offset(self.fat, c) else { continue };
            let Some(raw) = read_exact_opt(src, off, width) else {
                out.push(
                    Node::new(format!("entry[{c}]"), NodeKind::Field)
                        .with_status(Status::Unreadable)
                        .with_diag(Diagnostic {
                            status: Status::Unreadable,
                            message: format!("FAT entry {c} at {off:#012X} could not be read"),
                            hint: None,
                        }),
                );
                continue;
            };
            let Some(v) = fat_entry(src, g, self.fat, c) else { continue };
            let mut n = Node {
                label: format!("entry[{c}]").into(),
                // FAT12 entries share bytes with their neighbours, so the span is the
                // byte range the entry touches rather than a clean 12-bit slice.
                extent: Extent::bytes(off, width as u64),
                kind: NodeKind::Field,
                value: Value::Uint(v as u64),
                repr: Repr::Hex,
                raw,
                ..Default::default()
            };
            n.doc = Some("Next cluster in the chain, or a reserved marker.");
            n = match c {
                0 => n.with_diag(Diagnostic::info(format!(
                    "FAT[0]: the low byte is the media descriptor ({:#04X}), the rest is \
                     all ones",
                    v & 0xFF
                ))),
                1 => {
                    let mut n = n.with_diag(Diagnostic::info(
                        "FAT[1]: end-of-chain marker. On FAT32 bit 27 clear means the volume \
                         was not unmounted cleanly and bit 26 clear means a hard error was \
                         recorded.",
                    ));
                    if g.kind == FatKind::Fat32 && v & 0x0800_0000 == 0 {
                        n = n.with_diag(Diagnostic::warn(
                            "dirty bit is clear: the volume was not cleanly unmounted",
                        ));
                    }
                    n
                }
                _ if v == 0 => n.with_diag(Diagnostic::info("free")),
                _ if v == g.kind.bad_mark() => {
                    n.with_diag(Diagnostic::warn(format!("cluster {c} is marked bad")))
                }
                _ if v >= g.kind.eoc_min() => n.with_diag(Diagnostic::info("end of chain")),
                _ if !g.cluster_in_range(v as u64) => n.with_diag(Diagnostic::bad(format!(
                    "points at cluster {v}, outside 2..={}",
                    g.last_cluster()
                ))),
                _ => n,
            };
            out.push(n);
        }
        out.push(
            Node::new(
                format!("... {} further entries not shown", g.last_cluster().saturating_sub(last)),
                NodeKind::Group,
            )
            .with_doc("Only the head of the table is decoded; follow a file's chain to see the rest."),
        );
        out
    }
}

/// Compares FAT #0 against the other copies, bounded in both work and output.
#[derive(Debug)]
struct FatMirror {
    geom: Geom,
}

impl Expander for FatMirror {
    fn expand(&self, src: &dyn BlockSource) -> Vec<Node> {
        let g = &self.geom;
        let Some(fat_bytes) = g.fat_bytes() else {
            return vec![Node::new("mirror", NodeKind::Group)
                .with_diag(Diagnostic::bad("FAT size overflows a byte count"))];
        };
        let mut out = Vec::new();
        for i in 1..g.num_fats.min(8) {
            out.push(compare_fats(src, g, 0, i, fat_bytes));
        }
        out
    }
}

/// Byte offset within a FAT -> the cluster whose entry starts there.
fn cluster_at_byte(kind: FatKind, off: u64) -> u64 {
    match kind {
        FatKind::Fat12 => off.saturating_mul(2) / 3,
        FatKind::Fat16 => off / 2,
        FatKind::Fat32 => off / 4,
    }
}

fn compare_fats(src: &dyn BlockSource, g: &Geom, a: u64, b: u64, fat_bytes: u64) -> Node {
    let mut n = Node::new(format!("FAT #{a} vs FAT #{b}"), NodeKind::Group);
    n.value = Value::Composite;
    let (Some(off_a), Some(off_b)) = (g.fat_offset(a), g.fat_offset(b)) else {
        return n.with_diag(Diagnostic::bad("a FAT lies past a 64-bit byte offset"));
    };
    n.extent = Extent::Many(vec![
        Span::bytes(off_a, fat_bytes),
        Span::bytes(off_b, fat_bytes),
    ]);

    let limit = fat_bytes.min(MAX_FAT_COMPARE_BYTES);
    let mut diffs: Vec<(u64, u8, u8)> = Vec::new();
    let mut scanned = 0u64;
    let mut unreadable = false;

    while scanned < limit && diffs.len() < MAX_FAT_DIFFS {
        let want = FAT_COMPARE_CHUNK.min((limit - scanned) as usize);
        let (Some(ba), Some(bb)) = (
            read_exact_opt(src, off_a + scanned, want),
            read_exact_opt(src, off_b + scanned, want),
        ) else {
            unreadable = true;
            break;
        };
        let common = ba.len().min(bb.len());
        for i in 0..common {
            if ba[i] != bb[i] {
                diffs.push((scanned + i as u64, ba[i], bb[i]));
                if diffs.len() >= MAX_FAT_DIFFS {
                    break;
                }
            }
        }
        if common < want {
            unreadable = true;
            break;
        }
        scanned += want as u64;
    }

    if unreadable {
        n = n.with_diag(Diagnostic {
            status: Status::Unreadable,
            message: format!("comparison stopped at {scanned:#x} bytes: the device refused a read"),
            hint: Some("a failing sector inside a FAT makes every chain through it unreadable".into()),
        });
    }

    if diffs.is_empty() {
        let how = if scanned >= fat_bytes {
            format!("all {fat_bytes} bytes identical")
        } else {
            format!("first {scanned} of {fat_bytes} bytes identical")
        };
        n.derived = Some(Derived {
            kind: DerivedKind::Mirror,
            value: Value::Uint(0),
            matches: true,
            how: how.clone(),
        });
        return n.with_diag(Diagnostic::info(format!("the two tables agree: {how}")));
    }

    let mut kids = Vec::new();
    for (off, va, vb) in &diffs {
        let cluster = cluster_at_byte(g.kind, *off);
        let mut k = Node {
            label: format!("cluster ~{cluster} @+{off:#x}").into(),
            extent: Extent::Many(vec![
                Span::bytes(off_a + off, 1),
                Span::bytes(off_b + off, 1),
            ]),
            kind: NodeKind::Field,
            value: Value::Bytes(vec![*va, *vb]),
            repr: Repr::Hex,
            raw: vec![*va, *vb],
            ..Default::default()
        };
        k.doc = Some("One byte that differs between the two tables, with the cluster whose entry contains it.");
        k = k.with_diag(Diagnostic::warn(format!(
            "FAT #{a} holds {va:#04X}, FAT #{b} holds {vb:#04X}"
        )));
        kids.push(k);
    }

    n.derived = Some(Derived {
        kind: DerivedKind::Mirror,
        value: Value::Uint(diffs.len() as u64),
        matches: false,
        how: format!("{} differing bytes in the first {scanned} compared", diffs.len()),
    });
    n = n.with_diag(
        Diagnostic::bad(format!(
            "the allocation tables disagree: {} differing bytes found in the first \
             {scanned} compared{}",
            diffs.len(),
            if diffs.len() >= MAX_FAT_DIFFS { ", reporting stopped there" } else { "" }
        ))
        .with_hint(
            "unless ext_flags disables mirroring, the two copies are written together; \
             a divergence means one of them was written by something that did not know \
             about the other, or a sector went bad",
        ),
    );
    n.with_children(kids)
}

// ------------------------------------------------------------------- directories

fn root_dir_node(geom: &Geom) -> Node {
    match geom.kind {
        FatKind::Fat32 => {
            let at = geom.cluster_to_byte(geom.root_cluster);
            let mut n = Node::region(
                format!("root directory (cluster {})", geom.root_cluster),
                Span::bytes(at.unwrap_or(geom.data_start), geom.bytes_per_cluster),
            );
            n.doc = Some(
                "On FAT32 the root is an ordinary directory in a cluster chain, so it has \
                 no size limit and can be relocated.",
            );
            if at.is_none() {
                return n.with_diag(Diagnostic::bad(format!(
                    "root cluster {} is outside the data region",
                    geom.root_cluster
                )));
            }
            n = n.with_link(Link {
                label: "root directory".into(),
                kind: LinkKind::ToCluster,
                raw: geom.root_cluster,
                resolved: at,
            });
            n.with_lazy(Arc::new(DirExpander {
                geom: *geom,
                source: DirSource::Chain(geom.root_cluster),
                depth: 0,
            }))
        }
        _ => {
            let len = geom.root_dir_sectors.saturating_mul(geom.bytes_per_sector);
            let mut n = Node::region(
                format!("root directory ({} entries)", geom.root_entries),
                Span::bytes(geom.root_dir_start, len),
            );
            n.doc = Some(
                "On FAT12/16 the root is a fixed area between the last FAT and the data \
                 region. It is not a cluster chain, cannot grow, and has no . or .. entry.",
            );
            n.with_lazy(Arc::new(DirExpander {
                geom: *geom,
                source: DirSource::Fixed(geom.root_dir_start, len),
                depth: 0,
            }))
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum DirSource {
    /// A cluster chain, starting here.
    Chain(u64),
    /// The FAT12/16 fixed root: an absolute byte offset and a length.
    Fixed(u64, u64),
}

#[derive(Debug)]
struct DirExpander {
    geom: Geom,
    source: DirSource,
    depth: u32,
}

/// One 32-byte record with the absolute offset it came from.
#[derive(Clone, Copy)]
struct Rec {
    off: u64,
    bytes: [u8; 32],
}

impl Rec {
    fn attr(&self) -> u8 {
        self.bytes[0x0B]
    }
    fn is_lfn(&self) -> bool {
        self.attr() & desc::ATTR_LONG_NAME_MASK == desc::ATTR_LONG_NAME
    }
    fn is_deleted(&self) -> bool {
        self.bytes[0] == desc::DELETED_MARK
    }
    fn is_free(&self) -> bool {
        self.bytes[0] == desc::FREE_MARK
    }
    fn is_blank(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }
    fn first_cluster(&self) -> u64 {
        let hi = u16::from_le_bytes([self.bytes[0x14], self.bytes[0x15]]) as u64;
        let lo = u16::from_le_bytes([self.bytes[0x1A], self.bytes[0x1B]]) as u64;
        (hi << 16) | lo
    }
}

impl Expander for DirExpander {
    fn expand(&self, src: &dyn BlockSource) -> Vec<Node> {
        let g = &self.geom;
        let mut out: Vec<Node> = Vec::new();

        // Work out the byte runs this directory occupies.
        let (runs, chain_note) = match self.source {
            DirSource::Fixed(off, len) => (vec![(off, len)], None),
            DirSource::Chain(start) => {
                let (clusters, end) = follow_chain(src, g, start, MAX_DIR_CLUSTERS);
                let mut runs: Vec<(u64, u64)> = Vec::new();
                let mut taken = 0u64;
                for c in &clusters {
                    if taken >= MAX_DIR_BYTES {
                        break;
                    }
                    let Some(at) = g.cluster_to_byte(*c) else { continue };
                    taken = taken.saturating_add(g.bytes_per_cluster);
                    // Contiguous clusters are merged so the whole run is one read,
                    // which is most directories in one go.
                    match runs.last_mut() {
                        Some((o, l)) if o.saturating_add(*l) == at => *l += g.bytes_per_cluster,
                        _ => runs.push((at, g.bytes_per_cluster)),
                    }
                }
                (runs, Some((clusters, end)))
            }
        };

        if let Some((clusters, end)) = &chain_note {
            out.push(chain_summary_node(g, clusters, end, "directory"));
        }
        if runs.is_empty() {
            out.push(Node::new("no readable extent", NodeKind::Group).with_diag(Diagnostic::bad(
                "this directory's cluster chain resolves to nothing readable",
            )));
            return out;
        }

        // Read the records.
        let mut recs: Vec<Rec> = Vec::new();
        let mut short_read = false;
        'runs: for (off, len) in &runs {
            let want = usize::try_from((*len).min(MAX_DIR_BYTES)).unwrap_or(0);
            let Some(buf) = read_exact_opt(src, *off, want) else {
                short_read = true;
                break;
            };
            for (i, chunk) in buf.chunks(desc::ENTRY_SIZE as usize).enumerate() {
                if chunk.len() < desc::ENTRY_SIZE as usize {
                    break;
                }
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(chunk);
                recs.push(Rec { off: off + i as u64 * desc::ENTRY_SIZE, bytes });
                if recs.len() >= MAX_DIR_ENTRIES {
                    break 'runs;
                }
            }
        }
        if short_read {
            out.push(
                Node::new("unreadable", NodeKind::Group).with_diag(Diagnostic {
                    status: Status::Unreadable,
                    message: "part of this directory could not be read".into(),
                    hint: Some("entries past the failure are not shown; this is not an empty directory".into()),
                }),
            );
        }

        out.extend(build_entries(src, g, &recs, self.depth));
        out
    }
}

/// Turn a flat run of records into labelled nodes, grouping long-filename runs with
/// the 8.3 entry they name.
///
/// The three rules that matter, all of them about what *not* to hide:
///
/// * A 0x00 first byte means "no more entries" and a driver stops there. We note it
///   and keep going, because everything after it is the previous contents of the
///   directory and that is exactly what a sanitize check is looking for.
/// * A 0xE5 first byte is a deleted entry. It is shown, marked, and told apart from
///   a never-used one.
/// * Long-filename fragments whose 8.3 entry is gone are orphans, and an orphan is
///   the strongest kind of residue there is: the name of a file that no longer has
///   a directory entry at all.
fn build_entries(src: &dyn BlockSource, g: &Geom, recs: &[Rec], depth: u32) -> Vec<Node> {
    let mut out: Vec<Node> = Vec::new();
    let mut pending: Vec<Rec> = Vec::new();
    let mut terminator: Option<u64> = None;
    let mut blanks = 0usize;

    for rec in recs {
        if rec.is_free() {
            // Any fragments still pending have lost the 8.3 entry they named, and an
            // orphaned name is the strongest residue in the directory. Flush them
            // here so they appear where they sit on disk.
            for r in std::mem::take(&mut pending) {
                out.push(orphan_lfn_node(g, &r));
            }
            if terminator.is_none() {
                terminator = Some(rec.off);
                out.push(end_of_directory_node(rec.off));
                // The marker record has a node of its own above, so it must not also
                // be counted among the unused ones below — a viewer that says "9
                // unused entries" for a 16-record cluster holding 7 used ones is
                // wrong by exactly this record.
                if rec.is_blank() {
                    continue;
                }
            }
            if rec.is_blank() {
                blanks += 1;
                continue;
            }
            // A "never used" marker over bytes that are not zero: the first character
            // was overwritten but the rest of the record is still here.
            out.push(residue_node(g, rec));
            continue;
        }
        if rec.is_lfn() {
            pending.push(*rec);
            continue;
        }
        let run = std::mem::take(&mut pending);
        out.push(entry_node(src, g, rec, &run, depth, terminator.is_some()));
    }

    for r in pending {
        out.push(orphan_lfn_node(g, &r));
    }
    if blanks > 0 {
        let mut n = Node::new(format!("{blanks} unused entries (all zero)"), NodeKind::Group);
        n.value = Value::Uint(blanks as u64);
        n.repr = Repr::Dec;
        n.doc = Some(
            "Records past the end-of-directory marker that hold nothing at all. \
             Collapsed into one line; anything non-zero is listed separately above.",
        );
        out.push(n);
    }
    out
}

fn end_of_directory_node(off: u64) -> Node {
    let mut n = Node {
        label: format!("end of directory @{off:#012X}").into(),
        extent: Extent::bytes(off, desc::ENTRY_SIZE),
        kind: NodeKind::Group,
        value: Value::Composite,
        ..Default::default()
    };
    n.doc = Some(
        "A first name byte of 0x00 tells a driver to stop reading: no entry after this \
         point is in use.",
    );
    n.with_diag(
        Diagnostic::info(
            "a driver stops here; everything listed after this point is what the \
             directory used to contain",
        )
        .with_hint("deleted names and their metadata routinely survive past this marker"),
    )
}

/// A record marked never-used whose bytes are not zero.
fn residue_node(g: &Geom, rec: &Rec) -> Node {
    let ctx = g.ctx_at(rec.off);
    let mut n = blktamper_core::read_struct(&desc::DIR_ENTRY, &rec.bytes, ReadOutcome::Ok, ctx);
    n.label = format!("residue @{:#012X}", rec.off).into();
    n.with_diag(
        Diagnostic::info(
            "marked never-used (first byte 0x00) but the remaining 31 bytes are not \
             zero: a directory entry that was overwritten rather than erased",
        )
        .with_hint("the timestamps, size and first cluster below are the old entry's"),
    )
}

/// A long-filename fragment with no 8.3 entry after it.
fn orphan_lfn_node(g: &Geom, rec: &Rec) -> Node {
    let ctx = g.ctx_at(rec.off);
    let mut n = blktamper_core::read_struct(&desc::LFN_ENTRY, &rec.bytes, ReadOutcome::Ok, ctx);
    let chunk = lfn_chunk(&rec.bytes);
    n.label = format!("orphan LFN \"{chunk}\"").into();
    n.with_diag(
        Diagnostic::info(format!(
            "long-filename fragment with no 8.3 entry after it; it still spells \
             \"{chunk}\" and its checksum {:#04X} would identify the short entry it \
             belonged to",
            rec.bytes[0x0D]
        ))
        .with_hint("the 8.3 entry has been reused; the name is all that is left of the file"),
    )
}

/// Assemble the UTF-16 units one LFN fragment carries.
///
/// Padding after the name's terminating 0x0000 is 0xFFFF, and both have to go —
/// but only from the assembled name, never from the field values, which show what
/// is actually stored.
fn lfn_chunk(b: &[u8; 32]) -> String {
    let mut units: Vec<u16> = Vec::with_capacity(13);
    for &(start, count) in &[(0x01usize, 5usize), (0x0E, 6), (0x1C, 2)] {
        for i in 0..count {
            let o = start + i * 2;
            let u = u16::from_le_bytes([b[o], b[o + 1]]);
            if u == 0x0000 || u == 0xFFFF {
                return decode_units(&units);
            }
            units.push(u);
        }
    }
    decode_units(&units)
}

fn decode_units(units: &[u16]) -> String {
    char::decode_utf16(units.iter().copied())
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// The 8.3 name as a human reads it. Never fails, never hides a byte: unprintable
/// characters become dots and a deleted first character becomes `?`.
fn short_name(b: &[u8; 32]) -> String {
    let mut name = [0u8; 11];
    name.copy_from_slice(&b[..11]);
    let deleted = name[0] == desc::DELETED_MARK;
    // A volume-label entry's 11 bytes are one name with no implied dot, so splitting
    // them 8+3 would render "BLKTAMPER" as "BLKTAMPE.R".
    let volume = b[0x0B] & 0x08 != 0 && b[0x0B] & desc::ATTR_LONG_NAME_MASK != desc::ATTR_LONG_NAME;
    if name[0] == desc::KANJI_E5 {
        // 0x05 means the real first byte is 0xE5; the substitution exists so that a
        // legitimate KANJI lead byte is not mistaken for a deletion.
        name[0] = 0xE5;
    }
    let show = |b: u8| -> char {
        if (0x20..0x7F).contains(&b) {
            b as char
        } else {
            '.'
        }
    };
    if volume {
        let mut label: String = name.iter().map(|&c| show(c)).collect();
        if deleted {
            label.replace_range(0..1, "?");
        }
        return label.trim_end().to_string();
    }
    let mut base: String = name[..8].iter().map(|&c| show(c)).collect();
    if deleted {
        base.replace_range(0..1, "?");
    }
    let base = base.trim_end().to_string();
    let ext: String = name[8..].iter().map(|&c| show(c)).collect();
    let ext = ext.trim_end().to_string();
    if ext.is_empty() {
        base
    } else {
        format!("{base}.{ext}")
    }
}

/// The checksum that ties an LFN run to a short entry (fatgen §7.2).
fn short_name_checksum(name: &[u8]) -> u8 {
    ChecksumAlgo::FatShortName.compute(name, &[]) as u8
}

/// For a deleted entry, the first-character values that would make the stored LFN
/// checksum come out right. Usually exactly one — which recovers the character 0xE5
/// destroyed.
fn recover_first_char(name: &[u8; 11], want: u8) -> Vec<u8> {
    let mut candidates = Vec::new();
    let mut probe = *name;
    for c in 0x20u16..0x100 {
        probe[0] = c as u8;
        if short_name_checksum(&probe) == want {
            candidates.push(c as u8);
        }
    }
    candidates
}

fn attr_label(attr: u8) -> Option<&'static str> {
    if attr & 0x08 != 0 {
        Some("volume label")
    } else if attr & 0x10 != 0 {
        Some("directory")
    } else {
        None
    }
}

/// One 8.3 entry, plus the long-filename run in front of it when there is one.
fn entry_node(
    src: &dyn BlockSource,
    g: &Geom,
    rec: &Rec,
    run: &[Rec],
    depth: u32,
    past_end: bool,
) -> Node {
    let deleted = rec.is_deleted();
    let attr = rec.attr();
    let mut name11 = [0u8; 11];
    name11.copy_from_slice(&rec.bytes[..11]);
    let stored_sum = short_name_checksum(&name11);

    // The long name, and whether it really belongs to this short entry.
    let long: String = run.iter().rev().map(|r| lfn_chunk(&r.bytes)).collect();
    let run_sum = run.first().map(|r| r.bytes[0x0D]);
    let checksum_ok = run_sum.map(|s| s == stored_sum).unwrap_or(true);
    let recovered = match (deleted, run_sum, checksum_ok) {
        (true, Some(want), false) => recover_first_char(&name11, want),
        _ => Vec::new(),
    };

    let short = short_name(&rec.bytes);
    let display = if long.is_empty() { short.clone() } else { long.clone() };
    let dot = short == "." || short == "..";
    let suffix = match (deleted, attr_label(attr)) {
        _ if dot => "",
        (true, Some("directory")) => " (deleted directory)",
        (true, _) => " (deleted)",
        (false, Some("directory")) => "/",
        (false, Some("volume label")) => " (volume label)",
        _ => "",
    };

    let ctx = g.ctx_at(rec.off);
    let mut short_node =
        blktamper_core::read_struct(&desc::DIR_ENTRY, &rec.bytes, ReadOutcome::Ok, ctx);
    short_node.label = format!("{short}{}", if deleted { " (8.3)" } else { "" }).into();
    short_node = add_cluster_nodes(src, g, rec, short_node, depth, attr, deleted);

    if deleted {
        short_node = short_node.with_diag(
            Diagnostic::info(
                "deleted: the first character of the name has been overwritten with 0xE5 \
                 and cannot be recovered from this entry alone",
            )
            .with_hint(
                "size, timestamps and first cluster below are untouched — deletion \
                 rewrites one byte here and clears the cluster chain, nothing else",
            ),
        );
    }
    if past_end && !deleted {
        short_node = short_node.with_diag(Diagnostic::info(
            "this entry lies past the directory's end-of-directory marker, so no driver \
             will list it",
        ));
    }

    // No long name: the short entry stands alone.
    if run.is_empty() {
        short_node.label = format!("{display}{suffix}").into();
        return short_node;
    }

    // Long-filename run. Entries are stored in reverse, so the group's extent lists
    // the short entry first in logical order and the fragments after it.
    let mut kids: Vec<Node> = Vec::new();
    let total = run.len();
    for (i, r) in run.iter().enumerate() {
        let ctx = g.ctx_at(r.off);
        let mut n = blktamper_core::read_struct(&desc::LFN_ENTRY, &r.bytes, ReadOutcome::Ok, ctx);
        let order = r.bytes[0];
        let seq = order & 0x1F;
        let last = order & 0x40 != 0;
        let chunk = lfn_chunk(&r.bytes);
        n.label = if r.is_deleted() {
            format!("LFN ?/{total} \"{chunk}\"").into()
        } else {
            format!("LFN {seq}/{total} \"{chunk}\"").into()
        };
        if r.is_deleted() {
            n = n.with_diag(Diagnostic::info(
                "the sequence number has been overwritten with 0xE5 by the delete; only \
                 the fragment's position on disk still says where it belongs in the name",
            ));
        } else if i == 0 && !last {
            n = n.with_diag(Diagnostic::warn(
                "the first fragment on disk should carry the 0x40 last-entry bit; without \
                 it the run is incomplete and the name may be missing its tail",
            ));
        } else if i > 0 && last {
            n = n.with_diag(Diagnostic::warn(
                "the 0x40 last-entry bit appears in the middle of a run: two runs have \
                 been spliced together",
            ));
        }
        // The checksum is Cover::External — the covered bytes are the *next* record's.
        n = attach_lfn_checksum(n, r.bytes[0x0D], stored_sum, deleted, &recovered);
        kids.push(n);
    }
    kids.push(short_node);

    let mut spans: Vec<Span> = vec![Span::bytes(rec.off, desc::ENTRY_SIZE)];
    spans.extend(run.iter().map(|r| Span::bytes(r.off, desc::ENTRY_SIZE)));

    let mut group = Node {
        label: format!("{display}{suffix}").into(),
        extent: Extent::Many(spans),
        kind: NodeKind::Group,
        value: Value::Text(display.clone()),
        repr: Repr::Utf16Le,
        ..Default::default()
    };
    group.doc = Some(
        "A long-filename run and the 8.3 entry it names. The fragments are stored in \
         reverse order immediately before the short entry, so this group is one file \
         spread over several non-contiguous records.",
    );

    if deleted {
        group = group.with_diag(
            Diagnostic::info(format!(
                "deleted file \"{long}\": the long-filename fragments survive in full, so \
                 the name is recoverable even though the 8.3 entry's first character is not"
            ))
            .with_hint("this is the residue a secure-delete tool is supposed to remove"),
        );
        if recovered.len() == 1 {
            group = group.with_diag(Diagnostic::info(format!(
                "the destroyed 8.3 first character was {:?}: it is the only byte for which \
                 the stored long-name checksum {:#04X} comes out right",
                recovered[0] as char, run_sum.unwrap_or(0)
            )));
        }
    } else if !checksum_ok {
        group = group.with_diag(
            Diagnostic::warn(format!(
                "the long name does not belong to this 8.3 entry: the run stores checksum \
                 {:#04X} but \"{}\" checksums to {stored_sum:#04X}",
                run_sum.unwrap_or(0),
                blktamper_core::value::ascii_lossy(&name11, true)
            ))
            .with_hint(
                "the short entry was rewritten by a tool that did not understand long \
                 names, or these fragments are leftovers from a different file",
            ),
        );
    }

    let deep = kids.iter().fold(Status::Ok, |a, k| a.merge(k.deep_status()));
    group.status = group.status.merge(deep.min(Status::Warn));
    group.with_children(kids)
}

/// Attach the computed short-name checksum to an LFN entry's checksum field.
fn attach_lfn_checksum(
    mut n: Node,
    stored: u8,
    computed: u8,
    deleted: bool,
    recovered: &[u8],
) -> Node {
    let mut kids = n.children.resolved().map(|c| c.to_vec()).unwrap_or_default();
    if let Some(k) = kids.iter_mut().find(|k| k.label == "checksum") {
        let mut taken = std::mem::take(k);
        taken.derived = Some(Derived {
            kind: DerivedKind::Checksum,
            value: Value::Uint(computed as u64),
            matches: stored == computed,
            how: "FAT short-name checksum over the 11 name bytes of the following 8.3 entry"
                .to_string(),
        });
        if stored != computed {
            let d = if deleted && recovered.len() == 1 {
                Diagnostic::info(format!(
                    "stored {stored:#04X}, computed {computed:#04X} — as expected, because \
                     the 8.3 name's first byte is the 0xE5 deletion mark. It checksums \
                     correctly with {:?} restored.",
                    recovered[0] as char
                ))
            } else if deleted {
                Diagnostic::info(format!(
                    "stored {stored:#04X}, computed {computed:#04X}: the 8.3 name's first \
                     byte was destroyed by the delete, so the two cannot agree"
                ))
            } else {
                Diagnostic::warn(format!(
                    "stored {stored:#04X}, computed {computed:#04X}: this fragment does not \
                     belong to the 8.3 entry after it"
                ))
            };
            taken = taken.with_diag(d);
        }
        n.status = n.status.merge(taken.status.min(Status::Warn));
        *k = taken;
    }
    n.with_children(kids)
}

/// Add the joined `first_cluster` node, the chain, and a lazy listing for a
/// subdirectory.
fn add_cluster_nodes(
    src: &dyn BlockSource,
    g: &Geom,
    rec: &Rec,
    mut n: Node,
    depth: u32,
    attr: u8,
    deleted: bool,
) -> Node {
    let cluster = rec.first_cluster();
    let mut kids = n.children.resolved().map(|c| c.to_vec()).unwrap_or_default();

    // The cluster number is split across two fields eleven bytes apart, so the node
    // that carries it owns both ranges rather than pretending to live in one.
    let at = g.cluster_to_byte(cluster);
    let mut fc = Node {
        label: "first_cluster".into(),
        extent: Extent::Many(vec![Span::bytes(rec.off + 0x14, 2), Span::bytes(rec.off + 0x1A, 2)]),
        kind: NodeKind::Field,
        value: Value::Uint(cluster),
        repr: Repr::Cluster,
        flags: FieldFlags::POINTER,
        raw: vec![
            rec.bytes[0x14],
            rec.bytes[0x15],
            rec.bytes[0x1A],
            rec.bytes[0x1B],
        ],
        ..Default::default()
    };
    fc.doc = Some(
        "first_cluster_hi << 16 | first_cluster_lo. Computed, because the two halves \
         sit eleven bytes apart for backwards compatibility with FAT16.",
    );
    if cluster != 0 {
        fc = fc.with_link(Link {
            label: "data".into(),
            kind: LinkKind::ToCluster,
            raw: cluster,
            resolved: at,
        });
        if !g.cluster_in_range(cluster) {
            fc = fc.with_diag(Diagnostic::bad(format!(
                "cluster {cluster} is outside 2..={}; this entry points nowhere",
                g.last_cluster()
            )));
        }
    }

    // What the FAT says about that cluster now is the difference between "the data is
    // probably still there" and "the chain has already been handed out again".
    if deleted && cluster != 0 && g.cluster_in_range(cluster) {
        let d = match fat_entry(src, g, 0, cluster) {
            Some(0) => Diagnostic::info(format!(
                "the FAT entry for cluster {cluster} reads free: the chain was released by \
                 the delete, so only the first cluster's location is still known"
            ))
            .with_hint(
                "the file's later clusters cannot be found from here, and any of them may \
                 already have been reused",
            ),
            Some(v) => Diagnostic::info(format!(
                "the FAT entry for cluster {cluster} still reads {v:#X}: the chain was not \
                 cleared, so it may be followable"
            )),
            None => Diagnostic::warn(format!("the FAT entry for cluster {cluster} is unreadable")),
        };
        fc = fc.with_diag(d);
    }

    // Slot the computed node next to the low half it was built from.
    let pos = kids.iter().position(|k| k.label == "first_cluster_lo").map(|i| i + 1);
    match pos {
        Some(i) => kids.insert(i, fc),
        None => kids.push(fc),
    }

    let is_dir = attr & 0x10 != 0;
    let is_volume = attr & 0x08 != 0;
    let dot = rec.bytes[..11] == *b".          " || rec.bytes[..11] == *b"..         ";

    if is_volume && cluster != 0 {
        kids.push(
            Node::new("volume label with a cluster", NodeKind::Group).with_diag(Diagnostic::warn(
                "an ATTR_VOLUME_ID entry must have first_cluster zero; a non-zero value \
                 is either residue or a deliberate hiding place",
            )),
        );
    }

    if cluster != 0 && g.cluster_in_range(cluster) && !dot && !is_volume {
        let mut chain = Node::new("cluster chain", NodeKind::Array);
        chain.value = Value::Composite;
        chain.doc = Some(
            "The clusters this entry's data occupies, read from FAT #0. Expanded on \
             demand: a large file is thousands of links.",
        );
        kids.push(chain.with_lazy(Arc::new(ChainExpander { geom: *g, start: cluster })));

        if is_dir && depth < MAX_DIR_DEPTH {
            let mut contents = Node::region(
                format!("contents (cluster {cluster})"),
                Span::bytes(at.unwrap_or(0), g.bytes_per_cluster),
            );
            contents.doc = Some(
                "The directory this entry names. Expanded on demand; for a deleted \
                 directory the cluster may already hold something else entirely.",
            );
            kids.push(contents.with_lazy(Arc::new(DirExpander {
                geom: *g,
                source: DirSource::Chain(cluster),
                depth: depth + 1,
            })));
        }
    }

    let deep = kids.iter().fold(Status::Ok, |a, k| a.merge(k.deep_status()));
    n.status = n.status.merge(deep.min(Status::Warn));
    n.with_children(kids)
}

/// A file's cluster chain, expanded on demand.
#[derive(Debug)]
struct ChainExpander {
    geom: Geom,
    start: u64,
}

impl Expander for ChainExpander {
    fn expand(&self, src: &dyn BlockSource) -> Vec<Node> {
        let g = &self.geom;
        let (clusters, end) = follow_chain(src, g, self.start, MAX_CHAIN_CLUSTERS);
        let mut out = vec![chain_summary_node(g, &clusters, &end, "chain")];
        for (i, c) in clusters.iter().enumerate().take(1024) {
            let at = g.cluster_to_byte(*c);
            let mut n = Node {
                label: format!("[{i}] cluster {c}").into(),
                extent: match at {
                    Some(a) => Extent::bytes(a, g.bytes_per_cluster),
                    None => Extent::None,
                },
                kind: NodeKind::Field,
                value: Value::Uint(*c),
                repr: Repr::Cluster,
                ..Default::default()
            };
            n.doc = Some("One cluster of this file's data.");
            if let Some(a) = at {
                n = n.with_link(Link {
                    label: "data".into(),
                    kind: LinkKind::ToCluster,
                    raw: *c,
                    resolved: Some(a),
                });
            }
            out.push(n);
        }
        if clusters.len() > 1024 {
            out.push(Node::new(
                format!("... {} further clusters not shown", clusters.len() - 1024),
                NodeKind::Group,
            ));
        }
        out
    }
}

/// One line describing how a chain ran and how it stopped.
fn chain_summary_node(g: &Geom, clusters: &[u64], end: &ChainEnd, what: &str) -> Node {
    let bytes = (clusters.len() as u64).saturating_mul(g.bytes_per_cluster);
    let mut n = Node {
        label: format!("{what}: {} clusters ({bytes} bytes)", clusters.len()).into(),
        extent: Extent::None,
        kind: NodeKind::Group,
        value: Value::Uint(clusters.len() as u64),
        repr: Repr::Dec,
        ..Default::default()
    };
    n.doc = Some("How far the cluster chain ran and what stopped it.");
    let d = match end {
        ChainEnd::Eoc(v) => Diagnostic::info(format!("ended cleanly at an end-of-chain marker {v:#X}")),
        ChainEnd::Bad(c) => Diagnostic::warn(format!(
            "cluster {c} is marked bad; the rest of the chain cannot be reached"
        )),
        ChainEnd::Free(c) => Diagnostic::warn(format!(
            "the FAT entry after cluster {c} reads free: the chain was truncated, which \
             is what deleting a file does"
        )),
        ChainEnd::OutOfRange(c) => Diagnostic::bad(format!(
            "next cluster {c} is outside 2..={}",
            g.last_cluster()
        )),
        ChainEnd::Loop(c) => Diagnostic::bad(format!(
            "the chain returns to cluster {c}, which it has already used; traversal \
             stopped rather than looping"
        )),
        ChainEnd::Truncated => Diagnostic::warn("traversal limit reached before the chain ended"),
        ChainEnd::Unreadable(c) => Diagnostic {
            status: Status::Unreadable,
            message: format!("the FAT entry for cluster {c} could not be read"),
            hint: None,
        },
    };
    n.with_diag(d)
}

// ---------------------------------------------------------------------- test aid

/// Expand a node's lazy children. Exists so tests and the fuzz targets can force a
/// subtree without going through the UI.
pub fn expand(node: &Node, src: &dyn BlockSource) -> Vec<Node> {
    match &node.children {
        Children::Lazy(e) => e.expand(src),
        Children::Resolved(v) => v.clone(),
        Children::None => Vec::new(),
    }
}

/// A synthetic FAT32 volume, used by the unit tests in this module and by fuzzing.
///
/// Deliberately minimal and deliberately mutable: the tests that matter here are
/// about what happens when one of these numbers is wrong.
#[doc(hidden)]
pub fn synth_fat32(total_sectors: u32, sectors_per_cluster: u8, fat_size: u32) -> Vec<u8> {
    let reserved: u16 = 32;
    let mut boot = vec![0u8; 512];
    boot[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
    boot[3..11].copy_from_slice(b"blktampr");
    boot[0x0B..0x0D].copy_from_slice(&512u16.to_le_bytes());
    boot[0x0D] = sectors_per_cluster;
    boot[0x0E..0x10].copy_from_slice(&reserved.to_le_bytes());
    boot[0x10] = 2;
    boot[0x15] = 0xF8;
    boot[0x20..0x24].copy_from_slice(&total_sectors.to_le_bytes());
    boot[0x24..0x28].copy_from_slice(&fat_size.to_le_bytes());
    boot[0x2C..0x30].copy_from_slice(&2u32.to_le_bytes());
    boot[0x30..0x32].copy_from_slice(&1u16.to_le_bytes());
    boot[0x32..0x34].copy_from_slice(&6u16.to_le_bytes());
    boot[0x40] = 0x80;
    boot[0x42] = 0x29;
    boot[0x43..0x47].copy_from_slice(&0x1234_ABCDu32.to_le_bytes());
    boot[0x47..0x52].copy_from_slice(b"SYNTH      ");
    boot[0x52..0x5A].copy_from_slice(b"FAT32   ");
    boot[0x1FE] = 0x55;
    boot[0x1FF] = 0xAA;

    let mut img = boot;
    img.resize(total_sectors as usize * 512, 0);
    // FAT #0 and #1: media byte, end-of-chain, then an end-of-chain root.
    for fat in 0..2u32 {
        let at = (reserved as usize + (fat * fat_size) as usize) * 512;
        if at + 12 <= img.len() {
            img[at..at + 4].copy_from_slice(&0x0FFF_FFF8u32.to_le_bytes());
            img[at + 4..at + 8].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
            img[at + 8..at + 12].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
        }
    }
    // FSInfo.
    let fs = 512;
    if fs + 512 <= img.len() {
        img[fs..fs + 4].copy_from_slice(&0x4161_5252u32.to_le_bytes());
        img[fs + 0x1E4..fs + 0x1E8].copy_from_slice(&0x6141_7272u32.to_le_bytes());
        img[fs + 0x1E8..fs + 0x1EC].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        img[fs + 0x1EC..fs + 0x1F0].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        img[fs + 0x1FC..fs + 0x200].copy_from_slice(&0xAA55_0000u32.to_le_bytes());
    }
    img
}

/// Write a directory record into a synthetic image at `off`.
#[doc(hidden)]
pub fn synth_entry(img: &mut [u8], off: usize, name: &[u8; 11], attr: u8, cluster: u32, size: u32) {
    if off + 32 > img.len() {
        return;
    }
    img[off..off + 11].copy_from_slice(name);
    img[off + 0x0B] = attr;
    img[off + 0x14..off + 0x16].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
    img[off + 0x1A..off + 0x1C].copy_from_slice(&(cluster as u16).to_le_bytes());
    img[off + 0x1C..off + 0x20].copy_from_slice(&size.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use blktamper_core::MemSource;

    /// 2048 sectors, 1 sector per cluster, 4-sector FATs: 2008 clusters, so FAT12 by
    /// the cluster count even though `fs_type` says FAT32.
    fn small() -> Vec<u8> {
        synth_fat32(2048, 1, 4)
    }

    /// Enough clusters to genuinely be FAT32.
    fn big() -> Vec<u8> {
        synth_fat32(100_000, 1, 800)
    }

    fn src(data: Vec<u8>) -> Arc<dyn BlockSource> {
        Arc::new(MemSource::new(data))
    }

    #[test]
    fn the_cluster_count_decides_the_type_not_the_string() {
        let (g, _) = Geom::derive(&small(), 0);
        assert!(g.cluster_count < 4085);
        assert_eq!(g.kind, FatKind::Fat12, "2008 clusters is FAT12 whatever fs_type says");

        let (g, _) = Geom::derive(&big(), 0);
        assert!(g.cluster_count >= 65525);
        assert_eq!(g.kind, FatKind::Fat32);
    }

    #[test]
    fn a_lying_fs_type_string_is_called_out() {
        let s = src(small());
        let root = FatProbe.open(s, 0).root();
        let boot = root.find_child("boot sector").expect("boot sector");
        // A FAT12 volume gets the FAT12/16 EBPB, where the string sits 22 bytes
        // earlier — so the FAT32 "FAT32   " lands elsewhere and this reads as junk.
        let said = boot
            .children
            .resolved()
            .unwrap()
            .iter()
            .any(|k| k.diags.iter().chain(k.children.resolved().unwrap_or(&[]).iter().flat_map(|c| c.diags.iter()))
                .any(|d| d.message.contains("documentation")));
        assert!(said, "must say the cluster count decides, not the string");
    }

    #[test]
    fn thresholds_are_the_spec_values_not_round_numbers() {
        assert_eq!(FatKind::from_cluster_count(4084), FatKind::Fat12);
        assert_eq!(FatKind::from_cluster_count(4085), FatKind::Fat16);
        assert_eq!(FatKind::from_cluster_count(65524), FatKind::Fat16);
        assert_eq!(FatKind::from_cluster_count(65525), FatKind::Fat32);
    }

    #[test]
    fn a_zero_sector_size_cannot_divide_by_zero() {
        let mut img = big();
        img[0x0B] = 0;
        img[0x0C] = 0;
        let (g, d) = Geom::derive(&img, 0);
        assert!(!g.sane);
        assert!(d.iter().any(|(f, _)| *f == "bytes_per_sector"));
        // and the whole tree still builds
        let root = FatProbe.open(src(img), 0).root();
        assert!(root.find_child("boot sector").is_some());
    }

    #[test]
    fn a_volume_larger_than_its_device_is_flagged() {
        // 100_000 sectors of filesystem in an image that holds 1000.
        let mut img = big();
        img.truncate(1000 * 512);
        let root = FatProbe.open(src(img), 0).root();
        let boot = root.find_child("boot sector").unwrap();
        let bpb = boot.find_child("FAT BPB").unwrap();
        let ts = bpb.find_child("total_sectors_32").unwrap();
        assert!(
            ts.diags.iter().any(|d| d.message.contains("past the end of the device")),
            "{:?}",
            ts.diags
        );
    }

    #[test]
    fn a_chain_that_loops_terminates() {
        let mut img = big();
        let (g, _) = Geom::derive(&img, 0);
        let fat = g.fat_start as usize;
        // 2 -> 3 -> 2
        img[fat + 8..fat + 12].copy_from_slice(&3u32.to_le_bytes());
        img[fat + 12..fat + 16].copy_from_slice(&2u32.to_le_bytes());
        let s = MemSource::new(img);
        let (clusters, end) = follow_chain(&s, &g, 2, 1024);
        assert_eq!(clusters, vec![2, 3]);
        assert_eq!(end, ChainEnd::Loop(2));
    }

    #[test]
    fn a_chain_into_nowhere_stops() {
        let mut img = big();
        let (g, _) = Geom::derive(&img, 0);
        let fat = g.fat_start as usize;
        img[fat + 8..fat + 12].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes());
        let s = MemSource::new(img);
        let (_, end) = follow_chain(&s, &g, 2, 1024);
        assert_eq!(end, ChainEnd::OutOfRange(0x00FF_FFFF));
    }

    #[test]
    fn diverging_fats_are_reported_with_cluster_indices() {
        let mut img = big();
        let (g, _) = Geom::derive(&img, 0);
        let fat1 = g.fat_offset(1).unwrap() as usize;
        img[fat1 + 40] ^= 0xFF; // byte 40 -> cluster 10 on FAT32
        let s = src(img);
        let root = FatProbe.open(s.clone(), 0).root();
        let area = root.find_child("FAT area (2 copies x 800 sectors)").expect("fat area");
        let cmp = area.find_child("mirror check").expect("mirror check");
        let kids = expand(cmp, &*s);
        let d = &kids[0];
        assert!(d.diags.iter().any(|x| x.message.contains("disagree")), "{:?}", d.diags);
        let first = &d.children.resolved().unwrap()[0];
        assert!(first.label.contains("cluster ~10"), "{}", first.label);
    }

    #[test]
    fn identical_fats_say_so_without_reading_them_twice() {
        let s = src(big());
        let root = FatProbe.open(s.clone(), 0).root();
        let area = root.find_child("FAT area (2 copies x 800 sectors)").unwrap();
        let cmp = area.find_child("mirror check").unwrap();
        // Nothing is read until the node is expanded.
        assert!(matches!(cmp.children, Children::Lazy(_)));
        let kids = expand(cmp, &*s);
        assert!(kids[0].diags.iter().any(|d| d.message.contains("agree")));
    }

    #[test]
    fn a_deleted_entry_is_shown_and_marked() {
        let mut img = big();
        let (g, _) = Geom::derive(&img, 0);
        let root_at = g.data_start as usize;
        synth_entry(&mut img, root_at, b"LIVE    TXT", 0x20, 0, 10);
        synth_entry(&mut img, root_at + 32, b"\xE5ELETED TXT", 0x20, 3, 4096);
        let s = src(img);
        let root = FatProbe.open(s.clone(), 0).root();
        let dir = root.find_child("root directory (cluster 2)").unwrap();
        let kids = expand(dir, &*s);
        let del = kids.iter().find(|k| k.label.starts_with("?ELETED")).expect("deleted entry shown");
        assert_eq!(del.status, Status::Info);
        assert!(del.diags.iter().any(|d| d.message.contains("0xE5")));
    }

    #[test]
    fn entries_after_the_end_marker_are_still_shown() {
        let mut img = big();
        let (g, _) = Geom::derive(&img, 0);
        let root_at = g.data_start as usize;
        synth_entry(&mut img, root_at, b"LIVE    TXT", 0x20, 0, 10);
        // record 1 left as 0x00 -> end of directory; record 2 is residue.
        synth_entry(&mut img, root_at + 64, b"\xE5LDNAME TXT", 0x20, 0, 99);
        let s = src(img);
        let root = FatProbe.open(s.clone(), 0).root();
        let kids = expand(root.find_child("root directory (cluster 2)").unwrap(), &*s);
        assert!(kids.iter().any(|k| k.label.starts_with("end of directory")));
        assert!(
            kids.iter().any(|k| k.label.starts_with("?LDNAME")),
            "residue past the terminator must still be listed"
        );
    }

    #[test]
    fn short_names_render_the_dot_and_the_deletion_mark() {
        let mut b = [0x20u8; 32];
        b[..11].copy_from_slice(b"README  TXT");
        assert_eq!(short_name(&b), "README.TXT");
        b[..11].copy_from_slice(b"DCIM       ");
        assert_eq!(short_name(&b), "DCIM");
        b[..11].copy_from_slice(b"\xE5ECRET  TXT");
        assert_eq!(short_name(&b), "?ECRET.TXT");
        // 0x05 is a KANJI lead byte, not a deletion.
        b[..11].copy_from_slice(b"\x05ANJI   TXT");
        assert_eq!(short_name(&b), ".ANJI.TXT");
    }

    #[test]
    fn the_short_name_checksum_matches_the_spec_example() {
        assert_eq!(short_name_checksum(b"FILENAMEEXT"), 0xF6);
    }

    #[test]
    fn probe_refuses_exfat_and_ntfs_rather_than_guessing() {
        for oem in [b"EXFAT   ", b"NTFS    "] {
            let mut img = big();
            img[3..11].copy_from_slice(oem);
            assert_eq!(FatProbe.probe(&*src(img), 0), 0);
        }
    }

    #[test]
    fn probe_scores_a_clean_volume_high_and_garbage_zero() {
        assert!(FatProbe.probe(&*src(big()), 0) >= 80);
        for seed in [0u8, 1, 0x55, 0xAA, 0xE5, 0xFF] {
            assert_eq!(FatProbe.probe(&*src(vec![seed; 4096]), 0), 0, "seed {seed:#x}");
        }
    }

    #[test]
    fn garbage_never_panics_and_always_produces_a_tree() {
        for seed in 0u8..=255 {
            let s = src(vec![seed; 8192]);
            let _ = FatProbe.probe(&*s, 0);
            let root = FatProbe.open(s.clone(), 0).root();
            assert!(!root.label.is_empty());
            for k in root.children.resolved().unwrap() {
                let _ = expand(k, &*s);
            }
        }
    }

    /// Write a long-filename fragment at `off`.
    fn synth_lfn(img: &mut [u8], off: usize, order: u8, checksum: u8, text: &str) {
        if off + 32 > img.len() {
            return;
        }
        img[off] = order;
        img[off + 0x0B] = 0x0F;
        img[off + 0x0D] = checksum;
        let units: Vec<u16> = text.encode_utf16().collect();
        let slots = [(0x01usize, 5usize), (0x0E, 6), (0x1C, 2)];
        let mut i = 0;
        for (start, count) in slots {
            for k in 0..count {
                let u = units.get(i).copied().unwrap_or(0x0000);
                img[off + start + k * 2..off + start + k * 2 + 2].copy_from_slice(&u.to_le_bytes());
                i += 1;
            }
        }
    }

    #[test]
    fn an_orphaned_lfn_fragment_is_shown_not_dropped() {
        // A long-filename run whose 8.3 entry has been reused: the name survives with
        // nothing left to attach it to, which is the residue that matters most.
        let mut img = big();
        let (g, _) = Geom::derive(&img, 0);
        let at = g.data_start as usize;
        synth_lfn(&mut img, at, 0x41, 0x5A, "ghost.txt");
        // record 1 left zero -> end of directory, so nothing follows the fragment
        let s = src(img);
        let root = FatProbe.open(s.clone(), 0).root();
        let kids = expand(root.find_child("root directory (cluster 2)").unwrap(), &*s);
        let orphan = kids
            .iter()
            .find(|k| k.label.starts_with("orphan LFN"))
            .unwrap_or_else(|| panic!("{:?}", kids.iter().map(|k| k.label.to_string()).collect::<Vec<_>>()));
        assert_eq!(orphan.label, "orphan LFN \"ghost.txt\"");
        assert!(orphan.diags.iter().any(|d| d.message.contains("0x5A")));
    }

    #[test]
    fn a_long_name_that_does_not_belong_to_its_short_entry_is_flagged() {
        let mut img = big();
        let (g, _) = Geom::derive(&img, 0);
        let at = g.data_start as usize;
        // checksum 0x00 cannot be right for "OTHER   TXT"
        synth_lfn(&mut img, at, 0x41, 0x00, "impostor.txt");
        synth_entry(&mut img, at + 32, b"OTHER   TXT", 0x20, 0, 1);
        let s = src(img);
        let root = FatProbe.open(s.clone(), 0).root();
        let kids = expand(root.find_child("root directory (cluster 2)").unwrap(), &*s);
        let g = kids.iter().find(|k| k.label.starts_with("impostor.txt")).expect("grouped anyway");
        assert!(
            g.diags.iter().any(|d| d.message.contains("does not belong")),
            "{:?}",
            g.diags
        );
        assert_eq!(g.deep_status(), Status::Warn);
    }

    #[test]
    fn a_never_used_record_that_is_not_zero_is_surfaced_as_residue() {
        let mut img = big();
        let (g, _) = Geom::derive(&img, 0);
        let at = g.data_start as usize;
        synth_entry(&mut img, at, b"LIVE    TXT", 0x20, 0, 10);
        // first byte 0x00 (never used) but the rest of the record still populated
        synth_entry(&mut img, at + 32, b"\x00LDNAME TXT", 0x20, 7, 1234);
        let s = src(img);
        let root = FatProbe.open(s.clone(), 0).root();
        let kids = expand(root.find_child("root directory (cluster 2)").unwrap(), &*s);
        let r = kids.iter().find(|k| k.label.starts_with("residue")).expect("residue shown");
        assert_eq!(u64_of(r, "file_size"), Some(1234));
        assert!(r.diags.iter().any(|d| d.message.contains("overwritten rather than erased")));
    }

    fn u64_of(n: &Node, field: &str) -> Option<u64> {
        n.find_child(field).and_then(|c| c.value.as_u64())
    }

    #[test]
    fn fat12_entries_unpack_from_their_shared_nibble() {
        // Two 12-bit entries, 0x123 and 0x456, pack into three bytes as 23 61 45.
        let mut img = vec![0u8; 4096];
        img[512..515].copy_from_slice(&[0x23, 0x61, 0x45]);
        let g = Geom {
            base: 0,
            bytes_per_sector: 512,
            sectors_per_cluster: 1,
            bytes_per_cluster: 512,
            reserved_sectors: 1,
            num_fats: 1,
            root_entries: 16,
            fat_size: 1,
            total_sectors: 8,
            root_dir_sectors: 1,
            data_sectors: 5,
            cluster_count: 5,
            kind: FatKind::Fat12,
            root_cluster: 0,
            fat_start: 512,
            root_dir_start: 1024,
            data_start: 1536,
            sane: true,
            device_len: 4096,
        };
        let s = MemSource::new(img);
        assert_eq!(fat_entry(&s, &g, 0, 0), Some(0x123));
        assert_eq!(fat_entry(&s, &g, 0, 1), Some(0x456));
        // and the 12-bit markers are the ones FAT12 uses, not FAT32's
        assert_eq!(FatKind::Fat12.eoc_min(), 0xFF8);
        assert_eq!(FatKind::Fat12.bad_mark(), 0xFF7);
    }

    #[test]
    fn corrupting_a_valid_volume_never_panics_however_deep_you_expand() {
        // Garbage that happens to have a valid BPB is the dangerous input: the
        // geometry is sane enough to seek with, and everything past it is hostile.
        let mut img = big();
        let (g, _) = Geom::derive(&img, 0);
        synth_entry(&mut img, g.data_start as usize, b"DIR        ", 0x10, 3, 0);
        let base = img.clone();
        // A deterministic sweep rather than a random one, so a failure is repeatable.
        for seed in 0u64..64 {
            let mut img = base.clone();
            let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
            for _ in 0..512 {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                let i = (x as usize) % img.len();
                img[i] = (x >> 32) as u8;
            }
            let s = src(img);
            let root = FatProbe.open(s.clone(), 0).root();
            let mut queue = vec![root];
            let mut visited = 0usize;
            while let Some(n) = queue.pop() {
                visited += 1;
                if visited > 4000 {
                    break;
                }
                for k in expand(&n, &*s) {
                    queue.push(k);
                }
            }
        }
    }

    #[test]
    fn a_truncated_boot_sector_is_unreadable_not_zeros() {
        let s = src(vec![0u8; 16]);
        let root = FatProbe.open(s, 0).root();
        assert!(root.find_child("boot sector").is_some());
    }
}
