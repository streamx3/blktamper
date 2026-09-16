//! exFAT: boot regions, FAT, allocation bitmap, up-case table and directory entry
//! sets.
//!
//! Tier B of ADR-002. `desc.rs` says where the bytes are; everything here is the
//! arithmetic the descriptors deliberately cannot express — the geometry shifts,
//! the two boot-region checksums, the cluster chains, and the grouping of a file's
//! 0x85/0xC0/0xC1 records into the one thing a user thinks of as "a file".
//!
//! Three things in this file are easy to get backwards, and each is called out
//! where it happens:
//!
//! * **The shifts.** `bytes_per_sector_shift` is a *shift*, read from the disk. A
//!   corrupt value of 200 must produce a diagnostic, never `1u64 << 200`. Every
//!   shift here is range-checked before it is applied.
//! * **`NoFatChain`.** Set means contiguous and the FAT holds nothing; clear means
//!   the FAT is authoritative. Reading it backwards means walking a chain that was
//!   never written, into arbitrary clusters, with full confidence.
//! * **Deletion.** Clearing bit 7 of one byte is the entire delete operation. The
//!   record keeps its name, its size and its cluster. Showing those records is the
//!   single highest-value thing this module does.

pub mod desc;
mod scrub;
pub mod types;

use crate::common::{read_desc_at, u16le, u32le, u64le, ChainGuard, Step};
use blktamper_core::value::utf16le_lossy;
use blktamper_core::{
    BlockSource, ChecksumAlgo, Children, Derived, DerivedKind, Diagnostic, Expander, FieldFlags,
    FormatId, FormatProbe, Node, NodeKind, ReadCtx, ReadOutcome, RegionReader, Registry, RenderCtx,
    Repr, Score, Span, Status, StructDesc, Value,
};
use std::borrow::Cow;
use std::sync::Arc;

pub const ID: FormatId = FormatId("exfat");

/// Spec §3.1.15: a cluster may never exceed 32 MiB
/// (`bytes_per_sector_shift + sectors_per_cluster_shift <= 25`).
const MAX_CLUSTER_BYTES: u64 = 32 * 1024 * 1024;
/// Spec §3.1.9: the four highest FAT values are reserved, so no volume may declare
/// more clusters than this.
const MAX_CLUSTER_COUNT: u64 = 0xFFFF_FFF5;
/// First FAT value meaning "end of chain"; `0xFFFFFFF7` means "bad cluster".
const FAT_END_OF_CHAIN: u32 = 0xFFFF_FFFF;
const FAT_BAD_CLUSTER: u32 = 0xFFFF_FFF7;

/// A directory this long is either enormous or corrupt; either way the UI thread
/// stops here and says so rather than building a million nodes.
const MAX_DIR_ENTRIES: usize = 8192;
/// Upper bound on a cluster chain walk. A corrupt FAT will describe a longer one.
const MAX_CLUSTER_CHAIN: usize = 1 << 16;
/// Up-case tables are 5836 bytes as written by mkfs.exfat and 0x1FFFF*2 at most.
const MAX_UPCASE_BYTES: u64 = 256 * 1024;
/// A bitmap this large covers a 64 TiB volume at 1 MiB clusters.
const MAX_BITMAP_BYTES: u64 = 8 * 1024 * 1024;
/// Cap on how many FAT entries one lazy expansion produces.
const MAX_FAT_NODES: usize = 1 << 16;
/// Cap on how many clusters the bitmap/FAT agreement check compares.
const MAX_CROSSCHECK_CLUSTERS: u64 = 1 << 16;
/// Cap on how many spans a node's `Extent::Many` carries before it is summarised.
const MAX_SPANS: usize = 64;
/// How deep subdirectory expansion may go before it refuses.
const MAX_SUBDIR_DEPTH: u32 = 16;

pub fn register(reg: &mut Registry) {
    reg.register(Arc::new(ExfatProbe));
}

// ------------------------------------------------------------------- the probe

#[derive(Debug)]
pub struct ExfatProbe;

impl FormatProbe for ExfatProbe {
    fn id(&self) -> FormatId {
        ID
    }

    fn name(&self) -> &'static str {
        "exFAT volume"
    }

    /// Scored, not decided (see `registry.rs`).
    ///
    /// The honest position: a FAT boot sector, an exFAT boot sector and an NTFS
    /// boot sector all begin with a jump instruction and all end with 55 AA, and
    /// NTFS resembles both. The one field that separates them is the eight bytes at
    /// offset 3, so nothing scores above zero without `EXFAT   ` there. Getting to
    /// 80 additionally requires geometry that is consistent with itself — because a
    /// volume someone has half-overwritten still has the name.
    fn probe(&self, src: &dyn BlockSource, at: u64) -> Score {
        let (sector, outcome) = src.read_vec(at, 512);
        if outcome == ReadOutcome::Unreadable || sector.len() < 512 {
            return 0;
        }
        if &sector[3..11] != b"EXFAT   " {
            return 0;
        }

        let mut score: u32 = 50;
        if u16le(&sector, 0x1FE) == Some(0xAA55) {
            score += 8;
        }
        // The 53 bytes where a FAT BPB would be. Zero here is what makes a FAT
        // driver decline the volume, so a non-zero value is real evidence that this
        // is not a clean exFAT volume.
        if sector[0x0B..0x40].iter().all(|&b| b == 0) {
            score += 10;
        }
        if sector[0..3] == [0xEB, 0x76, 0x90] {
            score += 2;
        }

        let (geo, _) = Geometry::from_boot(&sector, at, src.logical_sector_size());
        if geo.trusted && geo.self_consistent(src.len()) {
            score += 30;
        }
        score.min(100) as Score
    }

    fn open(&self, src: Arc<dyn BlockSource>, at: u64) -> Box<dyn RegionReader> {
        Box::new(ExfatReader { src, base: at })
    }
}

// ----------------------------------------------------------------- the geometry

/// Everything derived from the boot sector that the rest of the module needs.
///
/// Plain `Copy` numbers with no diagnostics inside, so a lazy expander can carry a
/// copy across an expansion without borrowing the reader. Diagnostics produced
/// while deriving it are returned alongside and attached to the boot sector node.
#[derive(Clone, Copy, Debug)]
pub struct Geometry {
    /// Absolute byte offset of the volume on the device.
    pub base: u64,
    pub bytes_per_sector: u64,
    pub sectors_per_cluster: u64,
    pub cluster_size: u64,
    pub partition_offset: u64,
    pub volume_length: u64,
    pub fat_offset: u64,
    pub fat_length: u64,
    pub number_of_fats: u64,
    pub cluster_heap_offset: u64,
    pub cluster_count: u64,
    pub first_cluster_of_root: u64,
    pub volume_flags: u64,
    pub fs_revision: u64,
    pub percent_in_use: u64,
    /// `volume_flags` bit 0: which FAT and bitmap a driver is to use.
    pub active_fat: u64,
    /// False when a shift was out of range, so every offset below is a fallback
    /// rather than a fact. Traversal refuses to follow anything when this is false.
    pub trusted: bool,
}

impl Geometry {
    fn from_boot(raw: &[u8], base: u64, fallback_sector: u32) -> (Geometry, Vec<Diagnostic>) {
        let mut diags = Vec::new();

        // Validate the shifts *before* shifting. This is the whole reason the
        // filesystem stores shifts rather than sizes, and the whole reason a
        // corrupt one is dangerous: `1u64 << 200` is not 2^200, it is undefined.
        let bps_shift = raw.get(0x6C).copied().unwrap_or(0);
        let spc_shift = raw.get(0x6D).copied().unwrap_or(0);
        let mut trusted = true;

        let bytes_per_sector = if (9..=12).contains(&bps_shift) {
            1u64 << bps_shift
        } else {
            trusted = false;
            diags.push(
                Diagnostic::bad(format!(
                    "bytes_per_sector_shift is {bps_shift}; the specification allows \
                     9..=12 (512..4096 bytes)"
                ))
                .with_hint(format!(
                    "every offset below is computed with the device's {fallback_sector}-byte \
                     sectors instead, and is a guess"
                )),
            );
            fallback_sector.max(1) as u64
        };

        let sectors_per_cluster = if spc_shift <= 25 {
            1u64 << spc_shift
        } else {
            trusted = false;
            diags.push(Diagnostic::bad(format!(
                "sectors_per_cluster_shift is {spc_shift}; the specification allows \
                 0..=25 and no more than 25 - bytes_per_sector_shift"
            )));
            1
        };

        let mut cluster_size =
            bytes_per_sector.checked_mul(sectors_per_cluster).unwrap_or(0);
        if cluster_size == 0 || cluster_size > MAX_CLUSTER_BYTES {
            trusted = false;
            diags.push(
                Diagnostic::bad(format!(
                    "bytes_per_sector ({bytes_per_sector}) x sectors_per_cluster \
                     ({sectors_per_cluster}) is {cluster_size} bytes; the specification caps \
                     a cluster at 32 MiB"
                ))
                .with_hint("cluster addresses below fall back to one sector per cluster"),
            );
            cluster_size = bytes_per_sector;
        }

        let volume_flags = u16le(raw, 0x6A).unwrap_or(0) as u64;
        let geo = Geometry {
            base,
            bytes_per_sector,
            sectors_per_cluster,
            cluster_size,
            partition_offset: u64le(raw, 0x40).unwrap_or(0),
            volume_length: u64le(raw, 0x48).unwrap_or(0),
            fat_offset: u32le(raw, 0x50).unwrap_or(0) as u64,
            fat_length: u32le(raw, 0x54).unwrap_or(0) as u64,
            number_of_fats: raw.get(0x6E).copied().unwrap_or(0) as u64,
            cluster_heap_offset: u32le(raw, 0x58).unwrap_or(0) as u64,
            cluster_count: u32le(raw, 0x5C).unwrap_or(0) as u64,
            first_cluster_of_root: u32le(raw, 0x60).unwrap_or(0) as u64,
            volume_flags,
            fs_revision: u16le(raw, 0x68).unwrap_or(0) as u64,
            percent_in_use: raw.get(0x70).copied().unwrap_or(0) as u64,
            active_fat: volume_flags & 1,
            trusted,
        };
        (geo, diags)
    }

    /// Byte offset of a volume-relative sector, absolute on the device.
    fn sector_byte(&self, sector: u64) -> Option<u64> {
        sector.checked_mul(self.bytes_per_sector)?.checked_add(self.base)
    }

    fn volume_bytes(&self) -> Option<u64> {
        self.volume_length.checked_mul(self.bytes_per_sector)
    }

    fn heap_byte(&self) -> Option<u64> {
        self.sector_byte(self.cluster_heap_offset)
    }

    /// Byte offset of one of the (at most two) FATs.
    fn fat_byte(&self, index: u64) -> Option<u64> {
        let off = index.checked_mul(self.fat_length)?.checked_add(self.fat_offset)?;
        self.sector_byte(off)
    }

    /// Absolute byte offset of a cluster. `None` for cluster numbers outside the
    /// heap — there is no cluster 0 or 1, and the last is `cluster_count + 1`.
    fn cluster_byte(&self, cluster: u64) -> Option<u64> {
        if !self.cluster_in_heap(cluster) {
            return None;
        }
        cluster
            .checked_sub(2)?
            .checked_mul(self.cluster_size)?
            .checked_add(self.heap_byte()?)
    }

    fn cluster_in_heap(&self, cluster: u64) -> bool {
        cluster >= 2 && self.cluster_count > 0 && cluster <= self.cluster_count + 1
    }

    fn render(&self) -> RenderCtx {
        RenderCtx {
            sector_size: u32::try_from(self.bytes_per_sector).unwrap_or(512),
            cluster_base: self.heap_byte().map(|h| (h, self.cluster_size)),
            device_len: u64::MAX,
        }
    }

    fn ctx_at(&self, at: u64) -> ReadCtx {
        ReadCtx { base: at, region_base: self.base, render: self.render() }
    }

    /// Everything the probe can check without reading past the boot sector.
    ///
    /// Deliberately strict: this is what separates "the signature is there" from
    /// "this is an exFAT volume", and over-claiming is worse than under-claiming.
    fn self_consistent(&self, device_len: u64) -> bool {
        let fats_end = match self
            .fat_length
            .checked_mul(self.number_of_fats)
            .and_then(|n| n.checked_add(self.fat_offset))
        {
            Some(v) => v,
            None => return false,
        };
        let heap_sectors = match self
            .cluster_count
            .checked_mul(self.sectors_per_cluster)
            .and_then(|n| n.checked_add(self.cluster_heap_offset))
        {
            Some(v) => v,
            None => return false,
        };
        let volume_bytes = self.volume_bytes().unwrap_or(0);
        (1..=2).contains(&self.number_of_fats)
            && self.fat_offset >= desc::BOOT_REGION_SECTORS * 2
            && self.fat_length > 0
            && self.cluster_heap_offset >= fats_end
            && self.cluster_count > 0
            && self.cluster_count <= MAX_CLUSTER_COUNT
            && heap_sectors <= self.volume_length
            && self.cluster_in_heap(self.first_cluster_of_root)
            && volume_bytes > 0
            && self.base.saturating_add(volume_bytes) <= device_len.max(1)
    }
}

// ------------------------------------------------------------------ the reader

#[derive(Debug)]
pub struct ExfatReader {
    src: Arc<dyn BlockSource>,
    base: u64,
}

impl ExfatReader {
    pub fn new(src: Arc<dyn BlockSource>, base: u64) -> ExfatReader {
        ExfatReader { src, base }
    }
}

impl RegionReader for ExfatReader {
    fn scrub_plan(
        &self,
        node: &Node,
        fill: blktamper_core::scrub::Fill,
    ) -> Option<blktamper_core::scrub::ScrubPlan> {
        self.plan_scrub(node, fill)
    }

    fn id(&self) -> FormatId {
        ID
    }

    fn base(&self) -> u64 {
        self.base
    }

    fn root(&self) -> Node {
        let src = &*self.src;
        let (boot_raw, _) = src.read_vec(self.base, 512);
        let (geo, geo_diags) = Geometry::from_boot(&boot_raw, self.base, src.logical_sector_size());

        let span_len = geo
            .volume_bytes()
            .filter(|b| *b > 0)
            .unwrap_or(desc::BOOT_REGION_SECTORS * 2 * geo.bytes_per_sector)
            .min(src.len().saturating_sub(self.base).max(1));
        let mut root = Node::region("exFAT volume", Span::bytes(self.base, span_len));

        let mut kids = Vec::new();
        let main = boot_region(src, &geo, 0, "main", &geo_diags);
        let backup = boot_region(src, &geo, desc::BACKUP_BOOT_SECTOR, "backup", &[]);
        kids.push(main);
        kids.push(backup_diff(src, &geo));
        kids.push(backup);
        kids.push(geometry_node(&geo));

        if geo.trusted {
            for i in 0..geo.number_of_fats.min(2) {
                kids.push(fat_node(src, &geo, i));
            }

            let mut root_dir = directory_node(
                src,
                &geo,
                geo.first_cluster_of_root,
                false,
                None,
                "root directory".to_string(),
                0,
            );
            let meta = root_metadata(&root_dir);

            if let Some(bm) = meta.bitmap {
                let (node, derived) = bitmap_node(src, &geo, bm);
                patch_child(&mut root_dir, bm.index, "data_length", derived);
                kids.push(node);
            } else {
                root = root.with_diag(
                    Diagnostic::bad("the root directory has no 0x81 allocation bitmap entry")
                        .with_hint(
                            "the specification requires one; without it nothing knows which \
                             clusters are in use",
                        ),
                );
            }
            if let Some(uc) = meta.upcase {
                let (node, derived) = upcase_node(src, &geo, uc);
                patch_child(&mut root_dir, uc.index, "table_checksum", derived);
                kids.push(node);
            } else {
                root = root.with_diag(Diagnostic::bad(
                    "the root directory has no 0x82 up-case table entry",
                ));
            }
            if meta.label.is_none() {
                root = root.with_diag(Diagnostic::info(
                    "the root directory has no in-use 0x83 volume label entry: the volume \
                     is unlabelled, or the label was cleared",
                ));
            }
            kids.push(root_dir);
        } else {
            root = root.with_diag(
                Diagnostic::bad(
                    "the boot sector geometry is unusable, so the FAT, the cluster heap \
                     and the root directory were not followed",
                )
                .with_hint("the boot region above is still shown in full"),
            );
        }

        kids.sort_by_key(|n| n.extent.min_byte().unwrap_or(u64::MAX));
        root.with_children(kids)
    }
}

// ------------------------------------------------------------------ boot region

/// One of the two identical 12-sector boot regions (spec §3).
fn boot_region(
    src: &dyn BlockSource,
    geo: &Geometry,
    first_sector: u64,
    which: &str,
    extra: &[Diagnostic],
) -> Node {
    let bps = geo.bytes_per_sector;
    let Some(at) = geo.sector_byte(first_sector) else {
        return Node::new(format!("{which} boot region"), NodeKind::Region)
            .with_diag(Diagnostic::bad("the boot region offset overflows a 64-bit device"));
    };
    let region_bytes = desc::BOOT_REGION_SECTORS.saturating_mul(bps);
    let mut region = Node::region(
        format!("{which} boot region (sectors {}..{})", first_sector, first_sector + 11),
        Span::bytes(at, region_bytes),
    );
    for d in extra {
        region = region.with_diag(d.clone());
    }

    let mut kids = Vec::new();

    let mut boot = read_desc_at(src, &desc::MAIN_BOOT_SECTOR, at, geo.ctx_at(at));
    boot.label = format!("{which} boot sector").into();
    boot = annotate_boot_sector(boot, geo, src.len(), first_sector);
    kids.push(boot);

    // Sectors 1..=8 — the extended boot sectors. Eight separate records, so eight
    // missing signatures read as eight findings and not one.
    let mut ext = Vec::with_capacity(desc::EXT_BOOT_SECTOR_COUNT as usize);
    for i in 0..desc::EXT_BOOT_SECTOR_COUNT {
        let sector = first_sector + desc::EXT_BOOT_FIRST_SECTOR + i;
        let Some(sat) = geo.sector_byte(sector) else { break };
        ext.push(ext_boot_sector_node(src, geo, sat, i));
    }
    if !ext.is_empty() {
        let span = Span::bytes(
            geo.sector_byte(first_sector + desc::EXT_BOOT_FIRST_SECTOR).unwrap_or(at),
            desc::EXT_BOOT_SECTOR_COUNT.saturating_mul(bps),
        );
        kids.push(array_node("extended boot sectors", span, ext, "Eight sectors of further boot code. Only the last four bytes of each are defined, and they are the same 0xAA550000 in all eight."));
    }

    // Sector 9 — ten OEM parameter records.
    if let Some(oat) = geo.sector_byte(first_sector + desc::OEM_PARAM_SECTOR) {
        kids.push(oem_param_node(src, geo, oat));
    }

    // Sector 10 — reserved.
    if let Some(rat) = geo.sector_byte(first_sector + desc::RESERVED_SECTOR) {
        let (raw, outcome) = src.read_vec(rat, bps as usize);
        let nonzero = !raw.is_empty() && !raw.iter().all(|&b| b == 0);
        let mut n = Node {
            label: "reserved sector".into(),
            extent: blktamper_core::Extent::bytes(rat, bps),
            kind: NodeKind::Raw,
            value: Value::Bytes(raw.clone()),
            repr: Repr::Raw,
            flags: FieldFlags::RESERVED,
            doc: Some(
                "Sector 10 of the boot region. Reserved by the specification and \
                 covered by the boot checksum, so anything written here changes it.",
            ),
            raw,
            ..Default::default()
        };
        if outcome == ReadOutcome::Unreadable {
            n = n.with_status(Status::Unreadable);
        } else if nonzero {
            n = n.with_diag(
                Diagnostic::warn("the reserved sector is not zero")
                    .with_hint("undocumented data, or residue from whatever was here before"),
            );
        }
        kids.push(n);
    }

    // Sector 11 — the boot checksum.
    kids.push(boot_checksum_node(src, geo, first_sector));

    kids.sort_by_key(|n| n.extent.min_byte().unwrap_or(u64::MAX));
    region.with_children(kids)
}

/// An extended boot sector. The signature is the *last* four bytes of the sector,
/// which is offset 508 only when the sector is 512 bytes; the descriptor covers
/// that case and this builds the other by hand rather than lying about the offset.
fn ext_boot_sector_node(src: &dyn BlockSource, geo: &Geometry, at: u64, index: u64) -> Node {
    if geo.bytes_per_sector == 512 {
        let mut n = read_desc_at(src, &desc::EXT_BOOT_SECTOR, at, geo.ctx_at(at));
        n.label = format!("[{index}] extended boot sector").into();
        return n;
    }
    let bps = geo.bytes_per_sector;
    let (raw, outcome) = src.read_vec(at, bps as usize);
    let sig_off = bps.saturating_sub(4);
    let stored = u32le(&raw, sig_off as usize);
    let mut n = Node {
        label: format!("[{index}] extended boot sector").into(),
        extent: blktamper_core::Extent::bytes(at, bps),
        kind: NodeKind::Struct,
        value: Value::Composite,
        repr: Repr::Raw,
        doc: Some(
            "Extended boot sector on a volume whose sector size is not 512, so the \
             0xAA550000 signature is not at offset 508 and the fixed descriptor does \
             not apply.",
        ),
        raw,
        ..Default::default()
    };
    if outcome == ReadOutcome::Unreadable {
        return n.with_status(Status::Unreadable);
    }
    match stored {
        Some(0xAA55_0000) => {}
        Some(v) => {
            n = n.with_diag(Diagnostic::bad(format!(
                "signature at offset {sig_off} is {v:#010X}, expected 0xAA550000"
            )))
        }
        None => n = n.with_diag(Diagnostic::warn("the sector is shorter than its signature")),
    }
    n
}

/// Sector 9: ten 48-byte OEM parameter records plus a reserved tail.
fn oem_param_node(src: &dyn BlockSource, geo: &Geometry, at: u64) -> Node {
    let bps = geo.bytes_per_sector;
    let mut kids = Vec::new();
    let mut null_count = 0usize;
    let mut ff_count = 0usize;
    for i in 0..desc::OEM_PARAM_COUNT {
        let Some(pat) = i.checked_mul(desc::OEM_PARAM_SIZE).and_then(|o| at.checked_add(o)) else {
            break;
        };
        if pat.saturating_add(desc::OEM_PARAM_SIZE) > at.saturating_add(bps) {
            break;
        }
        let mut n = read_desc_at(src, &desc::OEM_PARAM, pat, geo.ctx_at(pat));
        n.label = format!("[{i}]").into();
        if n.raw.iter().all(|&b| b == 0) {
            null_count += 1;
            n.label = format!("[{i}] null").into();
        } else if n.raw.iter().all(|&b| b == 0xFF) {
            ff_count += 1;
            n.label = format!("[{i}] unset (0xFF)").into();
        }
        kids.push(n);
    }
    let mut node = array_node(
        "OEM parameters",
        Span::bytes(at, bps),
        kids,
        "Sector 9: ten 48-byte vendor records. Microsoft defines only a flash-parameters \
         GUID; everything else is vendor space and is covered by the boot checksum.",
    );
    if ff_count == desc::OEM_PARAM_COUNT as usize {
        node = node.with_diag(Diagnostic::info(
            "every OEM parameter slot is 0xFF, which is how mkfs.exfat leaves an \
             unused sector; the specification's null record is all zero",
        ));
    } else if null_count == desc::OEM_PARAM_COUNT as usize {
        node = node.with_diag(Diagnostic::info("every OEM parameter slot is the null record"));
    }
    node
}

/// Sector 11: the boot region checksum (spec §3.4).
///
/// Two things about this checksum are unusual and both matter. It **skips** the
/// three excluded bytes rather than treating them as zero — `ChecksumAlgo` does
/// that correctly, but only if it is handed the right ranges. And the 4-byte value
/// is repeated for the whole sector, so a drive that wrote only part of the sector
/// leaves a sector whose copies disagree.
fn boot_checksum_node(src: &dyn BlockSource, geo: &Geometry, first_sector: u64) -> Node {
    let bps = geo.bytes_per_sector;
    let Some(at) = geo.sector_byte(first_sector + desc::BOOT_CHECKSUM_SECTOR) else {
        return Node::new("boot checksum sector", NodeKind::Region)
            .with_diag(Diagnostic::bad("the checksum sector offset overflows"));
    };
    let node = Node::region("boot checksum sector", Span::bytes(at, bps));

    let covered_len = desc::BOOT_CHECKSUM_SECTOR.saturating_mul(bps);
    let region_at = geo.sector_byte(first_sector).unwrap_or(geo.base);
    let (covered, cov_outcome) = src.read_vec(region_at, covered_len as usize);
    let (sector, sec_outcome) = src.read_vec(at, bps as usize);

    if cov_outcome == ReadOutcome::Unreadable || sec_outcome == ReadOutcome::Unreadable {
        return node.with_status(Status::Unreadable).with_diag(Diagnostic {
            status: Status::Unreadable,
            message: "the boot region could not be read, so its checksum is unknown".into(),
            hint: Some("this is an I/O error, not zeroed data".into()),
        });
    }

    let spec = &desc::BOOT_REGION_CHECKSUM;
    let computed = spec.algo.compute(&covered, spec.exclude);
    let stored = u32le(&sector, 0).map(|v| v as u64);

    let mut first = Node {
        label: "boot_checksum".into(),
        extent: blktamper_core::Extent::bytes(at, 4),
        kind: NodeKind::Field,
        value: stored.map(Value::Uint).unwrap_or(Value::Unset),
        repr: Repr::Checksum,
        flags: FieldFlags::DERIVED,
        doc: Some(
            "Rotate-right-and-add over sectors 0..=10, skipping bytes 106, 107 and \
             112 of the first sector — VolumeFlags and PercentInUse, which a driver \
             rewrites while mounted. The bytes are skipped, not zeroed.",
        ),
        raw: sector.get(0..4).map(|s| s.to_vec()).unwrap_or_default(),
        derived: Some(Derived {
            kind: DerivedKind::Checksum,
            value: Value::Uint(computed),
            matches: stored == Some(computed),
            how: format!(
                "{} over {} bytes from {region_at:#X}, skipping {} range(s)",
                spec.algo.name(),
                covered.len(),
                spec.exclude.len()
            ),
        }),
        ..Default::default()
    };
    if stored != Some(computed) {
        first = first.with_diag(
            Diagnostic::bad(format!(
                "stored {:#010X}, computed {:#010X}",
                stored.unwrap_or(0),
                computed
            ))
            .with_hint("the boot region was modified without updating sector 11"),
        );
    }
    if cov_outcome != ReadOutcome::Ok {
        first = first.with_diag(Diagnostic::warn(format!(
            "only {} of {covered_len} boot region bytes were readable, so the computed \
             value covers less than the specification requires",
            covered.len()
        )));
    }

    // The value is repeated for every four bytes of the sector. A sector whose
    // copies disagree is a partially-completed write, which is worth more than the
    // checksum result itself.
    let copies = sector.len() / 4;
    let mut disagree = Vec::new();
    let mut disagree_total = 0usize;
    for i in 1..copies {
        if u32le(&sector, i * 4) != u32le(&sector, 0) {
            disagree_total += 1;
            if disagree.len() < 8 {
                disagree.push(i);
            }
        }
    }
    let mut reps = Node {
        label: "repetitions".into(),
        extent: blktamper_core::Extent::bytes(at.saturating_add(4), bps.saturating_sub(4)),
        kind: NodeKind::Field,
        value: Value::Uint(copies as u64),
        repr: Repr::Dec,
        doc: Some(
            "The checksum is stored once per four bytes for the whole sector. All \
             copies must be identical; copies that disagree mean the sector was only \
             partly written.",
        ),
        raw: sector.get(4..).map(|s| s.to_vec()).unwrap_or_default(),
        ..Default::default()
    };
    if disagree.is_empty() {
        reps = reps.with_diag(Diagnostic::info(format!(
            "all {copies} copies of the checksum are identical"
        )));
    } else {
        reps = reps.with_diag(
            Diagnostic::bad(format!(
                "{disagree_total} of {copies} copies differ from the first, at index(es) \
                 {disagree:?}"
            ))
            .with_hint("sector 11 was written partially; treat the first copy as unverified"),
        );
    }

    node.with_children(vec![first, reps])
}

/// Compare the two boot regions byte for byte and report what actually differs.
///
/// A difference is not automatically a fault: an implementation that updates
/// `VolumeFlags` on mount touches only the main region, so the two legitimately
/// disagree in exactly the bytes the checksum skips. Saying *which* bytes differ is
/// the difference between a useful report and an alarm.
fn backup_diff(src: &dyn BlockSource, geo: &Geometry) -> Node {
    let bps = geo.bytes_per_sector;
    let len = desc::BOOT_REGION_SECTORS.saturating_mul(bps);
    let mut node = Node::new("main vs backup boot region", NodeKind::Group)
        .with_doc(
            "The backup boot region at sector 12 is a byte-for-byte copy of the main \
             one at sector 0. Differences are shown by field where the boot sector is \
             concerned and by sector otherwise.",
        );

    let (Some(main_at), Some(backup_at)) =
        (geo.sector_byte(0), geo.sector_byte(desc::BACKUP_BOOT_SECTOR))
    else {
        return node.with_diag(Diagnostic::bad("the backup boot region offset overflows"));
    };
    let (a, ao) = src.read_vec(main_at, len as usize);
    let (b, bo) = src.read_vec(backup_at, len as usize);
    if ao == ReadOutcome::Unreadable || bo == ReadOutcome::Unreadable {
        return node.with_status(Status::Unreadable).with_diag(Diagnostic {
            status: Status::Unreadable,
            message: "one of the two boot regions could not be read".into(),
            hint: None,
        });
    }
    if a.len() != b.len() {
        return node.with_diag(Diagnostic::warn(format!(
            "the two regions are different lengths on this device: {} and {} bytes readable",
            a.len(),
            b.len()
        )));
    }
    if a == b {
        return node.with_diag(Diagnostic::info(
            "the backup boot region is byte-identical to the main one",
        ));
    }

    let mut kids = Vec::new();
    // Field-level diff of the boot sector itself: a named field is worth ten byte
    // offsets.
    for fd in desc::MAIN_BOOT_SECTOR.fields {
        let (s, e) = (fd.off as usize, fd.end() as usize);
        let (Some(x), Some(y)) = (a.get(s..e), b.get(s..e)) else { continue };
        if x == y {
            continue;
        }
        let skipped = desc::CHECKSUM_SKIPPED_BYTES
            .iter()
            .any(|&i| (s..e).contains(&(i as usize)));
        let msg = format!(
            "boot sector field {} differs: main {}, backup {}",
            fd.name,
            blktamper_core::value::hex_bytes(x),
            blktamper_core::value::hex_bytes(y)
        );
        let d = if skipped {
            Diagnostic::info(msg).with_hint(
                "this field is excluded from the boot checksum and a driver rewrites it on \
                 mount, so the two regions legitimately drift here",
            )
        } else {
            Diagnostic::bad(msg).with_hint(
                "the two copies of the boot sector disagree about the volume's geometry",
            )
        };
        kids.push(
            Node::new(Cow::Owned(fd.name.to_string()), NodeKind::Group)
                .with_diag(d)
                .with_doc(fd.doc),
        );
    }

    // And a per-sector summary for the other eleven sectors.
    let mut differing_sectors = Vec::new();
    for s in 0..desc::BOOT_REGION_SECTORS {
        let (from, to) = ((s * bps) as usize, ((s + 1) * bps) as usize);
        let (Some(x), Some(y)) = (a.get(from..to), b.get(from..to)) else { continue };
        if x != y {
            differing_sectors.push(s);
        }
    }
    node = node.with_diag(Diagnostic::warn(format!(
        "the two boot regions differ at region-relative sector(s) {differing_sectors:?} \
         — that is main sector(s) {differing_sectors:?} against backup sector(s) {:?}",
        differing_sectors
            .iter()
            .map(|s| s + desc::BACKUP_BOOT_SECTOR)
            .collect::<Vec<_>>()
    )));
    if kids.is_empty() {
        node
    } else {
        node.with_children(kids)
    }
}

/// Resolve the boot sector's `Check::Cross` invariants — the Tier A/B seam.
fn annotate_boot_sector(mut boot: Node, geo: &Geometry, device_len: u64, first_sector: u64) -> Node {
    let bps = geo.bytes_per_sector;

    // partition_offset: 0 is not "the volume starts at sector 0", it is "I have no
    // meaningful value, ignore me" (spec §3.1.4).
    let actual_lba = geo.base / bps.max(1);
    if geo.partition_offset == 0 {
        if geo.base != 0 {
            boot = with_child_diag(
                boot,
                "partition_offset",
                Diagnostic::info(format!(
                    "declared 0, which the specification defines as 'no meaningful value'; \
                     this volume was actually opened at LBA {actual_lba} ({:#X})",
                    geo.base
                ))
                .with_hint(
                    "mkfs.exfat run on a plain file and then copied into a partition leaves \
                     it zero, which is legal",
                ),
            );
        }
    } else if geo.partition_offset != actual_lba {
        boot = with_child_diag(
            boot,
            "partition_offset",
            Diagnostic::warn(format!(
                "declared LBA {}, but this volume was opened at LBA {actual_lba}",
                geo.partition_offset
            ))
            .with_hint("the volume was moved, or the partition table and the volume disagree"),
        );
    }

    if let Some(vb) = geo.volume_bytes() {
        if geo.base.saturating_add(vb) > device_len && device_len > 0 {
            boot = with_child_diag(
                boot,
                "volume_length",
                Diagnostic::bad(format!(
                    "{} sectors x {bps} bytes runs to {:#X}, past the end of the {}-byte device",
                    geo.volume_length,
                    geo.base.saturating_add(vb),
                    device_len
                )),
            );
        }
    } else {
        boot = with_child_diag(
            boot,
            "volume_length",
            Diagnostic::bad("volume_length x bytes_per_sector overflows 64 bits"),
        );
    }

    // A FAT must be able to hold an entry for every cluster plus the two reserved
    // ones. A short FAT means the tail of the heap has no entries at all.
    let need_fat_bytes = geo.cluster_count.saturating_add(2).saturating_mul(4);
    let have_fat_bytes = geo.fat_length.saturating_mul(bps);
    if have_fat_bytes < need_fat_bytes {
        boot = with_child_diag(
            boot,
            "fat_length",
            Diagnostic::bad(format!(
                "{} sectors is {have_fat_bytes} bytes, but {} clusters plus the two \
                 reserved entries need {need_fat_bytes}",
                geo.fat_length, geo.cluster_count
            )),
        );
    }

    let fats_end = geo.fat_offset.saturating_add(geo.fat_length.saturating_mul(geo.number_of_fats));
    if geo.cluster_heap_offset < fats_end {
        boot = with_child_diag(
            boot,
            "cluster_heap_offset",
            Diagnostic::bad(format!(
                "the heap starts at sector {} but the {} FAT(s) end at sector {fats_end}: \
                 they overlap",
                geo.cluster_heap_offset, geo.number_of_fats
            )),
        );
    }

    let heap_sectors = geo.cluster_count.saturating_mul(geo.sectors_per_cluster);
    let heap_end = geo.cluster_heap_offset.saturating_add(heap_sectors);
    if geo.cluster_count > MAX_CLUSTER_COUNT {
        boot = with_child_diag(
            boot,
            "cluster_count",
            Diagnostic::bad(format!(
                "{} exceeds the {MAX_CLUSTER_COUNT} the format allows: the four highest \
                 FAT values are reserved",
                geo.cluster_count
            )),
        );
    } else if geo.volume_length > 0 && heap_end > geo.volume_length {
        boot = with_child_diag(
            boot,
            "cluster_count",
            Diagnostic::bad(format!(
                "{} clusters reach sector {heap_end}, past the declared volume length of {}",
                geo.cluster_count, geo.volume_length
            )),
        );
    } else if geo.cluster_count == 0 {
        boot = with_child_diag(boot, "cluster_count", Diagnostic::bad("the heap has no clusters"));
    }

    if !geo.cluster_in_heap(geo.first_cluster_of_root) {
        boot = with_child_diag(
            boot,
            "first_cluster_of_root",
            Diagnostic::bad(format!(
                "cluster {} is outside the heap's 2..={} range, so the root directory \
                 cannot be found",
                geo.first_cluster_of_root,
                geo.cluster_count.saturating_add(1)
            )),
        );
    }

    if geo.fs_revision != 0x0100 {
        boot = with_child_diag(
            boot,
            "fs_revision",
            Diagnostic::warn(format!(
                "revision {}.{:02} — the only published revision is 1.00",
                geo.fs_revision >> 8,
                geo.fs_revision & 0xFF
            )),
        );
    }

    if geo.percent_in_use > 100 && geo.percent_in_use != 0xFF {
        boot = with_child_diag(
            boot,
            "percent_in_use",
            Diagnostic::warn(format!(
                "{} is neither a percentage (0..=100) nor 0xFF ('not available')",
                geo.percent_in_use
            )),
        );
    }

    if geo.volume_flags & !0xF != 0 {
        boot = with_child_diag(
            boot,
            "volume_flags",
            Diagnostic::warn(format!(
                "reserved bits 4..15 are set ({:#06X})",
                geo.volume_flags
            )),
        );
    }
    if geo.volume_flags & 0x2 != 0 {
        boot = with_child_diag(
            boot,
            "volume_flags",
            Diagnostic::warn("VolumeDirty is set: the volume was not cleanly unmounted")
                .with_hint("metadata below may be mid-update and internally inconsistent"),
        );
    }
    if geo.volume_flags & 0x4 != 0 {
        boot = with_child_diag(
            boot,
            "volume_flags",
            Diagnostic::warn("MediaFailure is set: the driver has recorded unreadable clusters"),
        );
    }
    if geo.active_fat != 0 && geo.number_of_fats < 2 {
        boot = with_child_diag(
            boot,
            "volume_flags",
            Diagnostic::bad("ActiveFat selects the second FAT, but number_of_fats is 1"),
        );
    }

    if first_sector != 0 {
        boot = boot.with_doc(
            "The backup copy at sector 12. It must match the main boot sector except \
             in the bytes the boot checksum skips.",
        );
    }
    boot
}

// ------------------------------------------------------------- computed geometry

/// The numbers every other node is derived from, in one place, each owning no bytes
/// of its own. Without this the user has to do the shifts in their head.
fn geometry_node(geo: &Geometry) -> Node {
    let mut kids = vec![
        computed("bytes_per_sector", geo.bytes_per_sector, Repr::SizeBytes,
            "1 << bytes_per_sector_shift. Not necessarily the device's own sector size."),
        computed("sectors_per_cluster", geo.sectors_per_cluster, Repr::Dec,
            "1 << sectors_per_cluster_shift."),
        computed("cluster_size", geo.cluster_size, Repr::SizeBytes,
            "bytes_per_sector x sectors_per_cluster, capped by the specification at 32 MiB."),
        computed("volume_size", geo.volume_bytes().unwrap_or(0), Repr::SizeBytes,
            "volume_length x bytes_per_sector."),
        computed("heap_offset", geo.heap_byte().unwrap_or(0), Repr::Hex,
            "Absolute byte offset of cluster 2 on the device."),
        computed("heap_size",
            geo.cluster_count.saturating_mul(geo.cluster_size), Repr::SizeBytes,
            "cluster_count x cluster_size: the space actually available to files."),
        computed("last_cluster", geo.cluster_count.saturating_add(1), Repr::Dec,
            "Highest valid cluster number. Numbering starts at 2, so this is cluster_count + 1."),
        computed("root_directory_offset",
            geo.cluster_byte(geo.first_cluster_of_root).unwrap_or(0), Repr::Hex,
            "Absolute byte offset of the root directory's first cluster."),
    ];
    for i in 0..geo.number_of_fats.min(2) {
        kids.push(computed(
            Cow::Owned(format!("fat_{i}_offset")),
            geo.fat_byte(i).unwrap_or(0),
            Repr::Hex,
            "Absolute byte offset of this FAT on the device.",
        ));
    }
    let mut node = Node::new("geometry (computed)", NodeKind::Group)
        .with_doc(
            "Values derived from the boot sector's shifts and offsets. These own no \
             bytes: they are what the fields above mean.",
        )
        .with_children(kids);
    if !geo.trusted {
        node = node.with_diag(Diagnostic::bad(
            "one or more shifts were out of range, so these are fallbacks and not facts",
        ));
    }
    node
}

// ---------------------------------------------------------------------- the FAT

fn fat_node(src: &dyn BlockSource, geo: &Geometry, index: u64) -> Node {
    let Some(at) = geo.fat_byte(index) else {
        return Node::new(format!("FAT {index}"), NodeKind::Region)
            .with_diag(Diagnostic::bad("the FAT offset overflows a 64-bit device"));
    };
    let len = geo.fat_length.saturating_mul(geo.bytes_per_sector);
    let active = index == geo.active_fat;
    let label = if geo.number_of_fats > 1 {
        format!("FAT {index}{}", if active { " (active)" } else { "" })
    } else {
        "FAT".to_string()
    };
    let mut node = Node::region(label, Span::bytes(at, len)).with_doc(
        "One 32-bit entry per cluster, starting at cluster 0. Only files whose \
         NoFatChain bit is clear have chains here; a contiguous file has no FAT \
         entries at all, so a zero entry is not evidence that a cluster is free.",
    );

    let (head, outcome) = src.read_vec(at, 8);
    if outcome == ReadOutcome::Unreadable {
        return node.with_status(Status::Unreadable).with_diag(Diagnostic {
            status: Status::Unreadable,
            message: format!("the FAT at {at:#X} could not be read"),
            hint: None,
        });
    }

    let mut kids = Vec::new();
    let e0 = u32le(&head, 0);
    let mut n0 = fat_entry_field("entry 0 (media type)", at, 0, e0,
        "Must be 0xFFFFFFF8: the media descriptor byte 0xF8 in the low byte and 0xFF in the rest. It describes no cluster.");
    if e0 != Some(0xFFFF_FFF8) {
        n0 = n0.with_diag(Diagnostic::bad(format!(
            "expected 0xFFFFFFF8, found {:#010X}",
            e0.unwrap_or(0)
        )));
    }
    kids.push(n0);

    let e1 = u32le(&head, 4);
    let mut n1 = fat_entry_field("entry 1 (reserved)", at, 1, e1,
        "Must be 0xFFFFFFFF. Reserved by the specification; describes no cluster.");
    if e1 != Some(0xFFFF_FFFF) {
        n1 = n1.with_diag(Diagnostic::bad(format!(
            "expected 0xFFFFFFFF, found {:#010X}",
            e1.unwrap_or(0)
        )));
    }
    kids.push(n1);

    // Clusters 2.. are lazy: a 58 GiB volume has a 7 MB FAT and the UI expands only
    // what is on screen (R-3.5).
    let count = geo.cluster_count;
    let entries_span = Span::bytes(
        at.saturating_add(8),
        count.saturating_mul(4).min(len.saturating_sub(8)),
    );
    let mut entries = Node::new("entries (clusters 2..)", NodeKind::Array).with_doc(
        "One entry per cluster in the heap. Expanded on demand: on a large volume \
         this array has millions of rows.",
    );
    entries.extent = blktamper_core::Extent::One(entries_span);
    entries.value = Value::Composite;
    entries = entries.with_lazy(Arc::new(FatEntries { at, count }));
    kids.push(entries);

    node = node.with_children(kids);
    if !active && geo.number_of_fats > 1 {
        node = node.with_diag(Diagnostic::info(
            "this is not the active FAT; volume_flags bit 0 selects the other one",
        ));
    }
    node
}

fn fat_entry_field(
    label: &'static str,
    fat_at: u64,
    index: u64,
    value: Option<u32>,
    doc: &'static str,
) -> Node {
    let at = fat_at.saturating_add(index.saturating_mul(4));
    Node {
        label: label.into(),
        extent: blktamper_core::Extent::bytes(at, 4),
        kind: NodeKind::Field,
        value: value.map(|v| Value::Uint(v as u64)).unwrap_or(Value::Unset),
        repr: Repr::Hex,
        doc: Some(doc),
        raw: value.map(|v| v.to_le_bytes().to_vec()).unwrap_or_default(),
        ..Default::default()
    }
}

/// Lazily-expanded FAT entries. Holds only numbers, so it can outlive the reader.
#[derive(Debug)]
struct FatEntries {
    at: u64,
    count: u64,
}

impl Expander for FatEntries {
    fn expand(&self, src: &dyn BlockSource) -> Vec<Node> {
        let want = (self.count as usize).min(MAX_FAT_NODES);
        let start = self.at.saturating_add(8);
        let (bytes, outcome) = src.read_vec(start, want.saturating_mul(4));
        if outcome == ReadOutcome::Unreadable {
            return vec![Node::new("unreadable", NodeKind::Raw).with_diag(Diagnostic {
                status: Status::Unreadable,
                message: format!("the FAT entries at {start:#X} could not be read"),
                hint: None,
            })];
        }
        let mut out = Vec::with_capacity(want.min(bytes.len() / 4) + 1);
        for i in 0..bytes.len() / 4 {
            let cluster = i as u64 + 2;
            let v = u32le(&bytes, i * 4).unwrap_or(0);
            let at = start.saturating_add(i as u64 * 4);
            let label = match v {
                0 => format!("[{cluster}] free"),
                FAT_END_OF_CHAIN => format!("[{cluster}] end of chain"),
                FAT_BAD_CLUSTER => format!("[{cluster}] BAD CLUSTER"),
                n => format!("[{cluster}] -> {n}"),
            };
            let mut n = Node {
                label: label.into(),
                extent: blktamper_core::Extent::bytes(at, 4),
                kind: NodeKind::Field,
                value: Value::Uint(v as u64),
                repr: Repr::Hex,
                raw: v.to_le_bytes().to_vec(),
                doc: Some(
                    "Next cluster in this cluster's chain, 0xFFFFFFFF for the last, \
                     0xFFFFFFF7 for a cluster the driver marked bad, 0 for no chain.",
                ),
                ..Default::default()
            };
            if v == FAT_BAD_CLUSTER {
                n = n.with_diag(Diagnostic::warn("the driver marked this cluster unusable"));
            } else if v != 0 && v != FAT_END_OF_CHAIN && (v < 2 || v as u64 > self.count + 1) {
                n = n.with_diag(Diagnostic::bad(format!(
                    "{v} is outside the heap's 2..={} range",
                    self.count + 1
                )));
            }
            out.push(n);
        }
        if self.count as usize > want {
            out.push(Node::new("...", NodeKind::Group).with_diag(Diagnostic::info(format!(
                "{} further entries not expanded; this array holds {} in total",
                self.count as usize - want,
                self.count
            ))));
        }
        out
    }

    fn hint_len(&self) -> Option<usize> {
        usize::try_from(self.count).ok()
    }
}

// ------------------------------------------------------------ cluster resolution

/// Resolve a cluster chain into absolute byte runs.
///
/// `no_fat_chain` is the field it is fatal to read backwards: when it is set the
/// allocation is contiguous and the FAT holds nothing for this file, so walking the
/// FAT would follow a chain nobody wrote. Both branches are here, and the returned
/// diagnostics say which one was taken.
fn cluster_chain(
    src: &dyn BlockSource,
    geo: &Geometry,
    first: u64,
    no_fat_chain: bool,
    byte_len: Option<u64>,
) -> (Vec<u64>, Vec<Diagnostic>) {
    let mut diags = Vec::new();
    if first == 0 {
        return (Vec::new(), diags);
    }
    if !geo.cluster_in_heap(first) {
        diags.push(Diagnostic::bad(format!(
            "first cluster {first} is outside the heap's 2..={} range",
            geo.cluster_count.saturating_add(1)
        )));
        return (Vec::new(), diags);
    }

    if no_fat_chain {
        let want = byte_len.unwrap_or(geo.cluster_size);
        let n = want.div_ceil(geo.cluster_size.max(1)).max(1).min(MAX_CLUSTER_CHAIN as u64);
        let last = first.saturating_add(n).saturating_sub(1);
        let clamped = if geo.cluster_in_heap(last) {
            n
        } else {
            let avail = geo.cluster_count.saturating_add(2).saturating_sub(first);
            diags.push(Diagnostic::bad(format!(
                "contiguous allocation of {n} clusters from {first} runs past the last \
                 cluster ({}); only {avail} are inside the heap",
                geo.cluster_count.saturating_add(1)
            )));
            avail
        };
        diags.push(Diagnostic::info(format!(
            "NoFatChain is set: clusters {first}..={} are contiguous and the FAT was not \
             consulted",
            first.saturating_add(clamped).saturating_sub(1)
        )));
        return ((first..first.saturating_add(clamped)).collect(), diags);
    }

    let Some(fat_at) = geo.fat_byte(geo.active_fat.min(1)) else {
        diags.push(Diagnostic::bad("the active FAT's offset overflows"));
        return (Vec::new(), diags);
    };
    let mut out = Vec::new();
    let mut guard = ChainGuard::new(MAX_CLUSTER_CHAIN);
    let mut cur = first;
    loop {
        match guard.visit(cur) {
            Step::Continue => {}
            Step::Loop => {
                diags.push(
                    Diagnostic::bad(format!("the FAT chain returns to cluster {cur}: it loops"))
                        .with_hint("traversal stopped; the clusters listed so far are real"),
                );
                break;
            }
            Step::TooLong => {
                diags.push(Diagnostic::bad(format!(
                    "the FAT chain is longer than {MAX_CLUSTER_CHAIN} clusters; traversal stopped"
                )));
                break;
            }
        }
        out.push(cur);
        let Some(eat) = cur.checked_mul(4).and_then(|o| fat_at.checked_add(o)) else { break };
        let (b, outcome) = src.read_vec(eat, 4);
        if outcome == ReadOutcome::Unreadable {
            diags.push(Diagnostic {
                status: Status::Unreadable,
                message: format!("the FAT entry for cluster {cur} could not be read"),
                hint: Some("the chain beyond this point is unknown, not empty".into()),
            });
            break;
        }
        let Some(next) = u32le(&b, 0) else {
            diags.push(Diagnostic::warn(format!(
                "the FAT ends before cluster {cur}'s entry"
            )));
            break;
        };
        match next {
            FAT_END_OF_CHAIN => break,
            FAT_BAD_CLUSTER => {
                diags.push(Diagnostic::warn(format!(
                    "cluster {cur} chains to the bad-cluster marker"
                )));
                break;
            }
            0 => {
                diags.push(Diagnostic::bad(format!(
                    "the FAT entry for cluster {cur} is zero, so the chain has no end marker"
                )));
                break;
            }
            v if !geo.cluster_in_heap(v as u64) => {
                diags.push(Diagnostic::bad(format!(
                    "cluster {cur} chains to {v}, outside the heap's 2..={} range",
                    geo.cluster_count.saturating_add(1)
                )));
                break;
            }
            v => cur = v as u64,
        }
    }

    if let Some(want) = byte_len {
        let have = (out.len() as u64).saturating_mul(geo.cluster_size);
        let need = want.div_ceil(geo.cluster_size.max(1));
        if out.len() as u64 != need {
            diags.push(Diagnostic::warn(format!(
                "the chain holds {} clusters ({have} bytes) but the record declares {want} \
                 bytes, which needs {need}",
                out.len()
            )));
        }
    }
    (out, diags)
}

/// Absolute byte runs for a list of clusters, with adjacent clusters coalesced so
/// a contiguous file is one span rather than ten thousand.
fn cluster_runs(geo: &Geometry, clusters: &[u64]) -> Vec<(u64, u64)> {
    let mut runs: Vec<(u64, u64)> = Vec::new();
    for &c in clusters {
        let Some(at) = geo.cluster_byte(c) else { continue };
        match runs.last_mut() {
            Some((start, len)) if start.saturating_add(*len) == at => {
                *len = len.saturating_add(geo.cluster_size)
            }
            _ => runs.push((at, geo.cluster_size)),
        }
    }
    runs
}

fn runs_to_extent(runs: &[(u64, u64)]) -> blktamper_core::Extent {
    match runs.len() {
        0 => blktamper_core::Extent::None,
        1 => blktamper_core::Extent::One(Span::bytes(runs[0].0, runs[0].1)),
        _ => blktamper_core::Extent::Many(
            runs.iter().take(MAX_SPANS).map(|&(a, l)| Span::bytes(a, l)).collect(),
        ),
    }
}

/// Read a cluster chain's bytes, bounded, keeping the runs so every byte can be
/// mapped back to an absolute offset.
fn read_runs(src: &dyn BlockSource, runs: &[(u64, u64)], limit: u64) -> (Vec<u8>, Vec<Diagnostic>) {
    let mut out = Vec::new();
    let mut diags = Vec::new();
    for &(at, len) in runs {
        if out.len() as u64 >= limit {
            break;
        }
        let want = len.min(limit - out.len() as u64) as usize;
        let (b, outcome) = src.read_vec(at, want);
        if outcome == ReadOutcome::Unreadable {
            diags.push(Diagnostic {
                status: Status::Unreadable,
                message: format!("{want} bytes at {at:#X} could not be read"),
                hint: Some(
                    "this run and everything after it is missing from the data below, and \
                     is not zeros"
                        .into(),
                ),
            });
            // Not `continue`: the bytes of later runs would slide into the gap and
            // every record after it would be reported at the wrong offset. A record
            // shown at an address it does not occupy is worse than one not shown.
            break;
        }
        let short = b.len() < want;
        out.extend_from_slice(&b);
        if short {
            diags.push(Diagnostic {
                status: Status::Unreadable,
                message: format!(
                    "only {} of {want} bytes at {at:#X} were readable",
                    b.len()
                ),
                hint: Some("the rest of this run, and every run after it, is not shown".into()),
            });
            break;
        }
    }
    (out, diags)
}

/// Absolute offset of byte `i` of a run list.
fn abs_of(runs: &[(u64, u64)], i: u64) -> Option<u64> {
    let mut acc = 0u64;
    for &(at, len) in runs {
        if i < acc.saturating_add(len) {
            return at.checked_add(i - acc);
        }
        acc = acc.saturating_add(len);
    }
    None
}

// ----------------------------------------------------------------- directories

/// A directory: its cluster chain, its entry sets, and everything left behind in it.
fn directory_node(
    src: &dyn BlockSource,
    geo: &Geometry,
    first_cluster: u64,
    no_fat_chain: bool,
    byte_len: Option<u64>,
    label: String,
    depth: u32,
) -> Node {
    let (clusters, chain_diags) = cluster_chain(src, geo, first_cluster, no_fat_chain, byte_len);
    let runs = cluster_runs(geo, &clusters);
    let mut node = Node::new(Cow::Owned(label), NodeKind::Region).with_doc(
        "A directory is a plain array of 32-byte entries stored in ordinary clusters. \
         Nothing distinguishes an allocated entry from a deleted one except bit 7 of \
         its first byte.",
    );
    node.extent = runs_to_extent(&runs);
    node.value = Value::Composite;
    for d in chain_diags {
        node = node.with_diag(d);
    }
    if runs.is_empty() {
        return node.with_diag(Diagnostic::bad("no clusters could be resolved for this directory"));
    }

    let limit = (MAX_DIR_ENTRIES as u64).saturating_mul(desc::ENTRY_SIZE);
    let (flat, read_diags) = read_runs(src, &runs, limit);
    for d in read_diags {
        node = node.with_diag(d);
    }
    node.raw = flat.iter().take(4096).copied().collect();

    let total_bytes: u64 = runs.iter().map(|r| r.1).sum();
    if total_bytes > limit {
        node = node.with_diag(Diagnostic::warn(format!(
            "this directory is {total_bytes} bytes; only the first {limit} were scanned"
        )));
    }

    let slots = flat.len() / desc::ENTRY_SIZE as usize;
    let mut kids: Vec<Node> = Vec::new();
    let mut past_eod = false;
    let mut eod_zero_slots = 0usize;
    let mut residue = 0usize;
    let mut k = 0usize;

    while k < slots {
        let off = k * desc::ENTRY_SIZE as usize;
        let t = flat[off];
        let at = abs_of(&runs, off as u64).unwrap_or(0);

        if t == types::END_OF_DIRECTORY {
            if !past_eod {
                past_eod = true;
                kids.push(
                    entry_node(&flat[off..off + 32], at, geo, &desc::GENERIC_ENTRY, "end of directory")
                        .with_diag(Diagnostic::info(
                            "the first entry with type 0x00 ends the directory; nothing at or \
                             after it is allocated",
                        )),
                );
            } else if flat[off..off + 32].iter().all(|&b| b == 0) {
                eod_zero_slots += 1;
            } else {
                // Type byte zero but the rest is not: a record whose first byte was
                // overwritten and whose remaining 31 are still there.
                residue += 1;
                kids.push(mark_residue(
                    entry_node(&flat[off..off + 32], at, geo, &desc::GENERIC_ENTRY, "zeroed type byte"),
                    t,
                ));
            }
            k += 1;
            continue;
        }

        // Past the end-of-directory marker the same records are parsed the same
        // way — a deleted entry set out there is still an entry set, and grouping
        // it is what turns five rows of fragments back into a filename.
        let (mut n, used) = if types::undeleted(t) == types::FILE {
            entry_set_node(src, geo, &flat, &runs, k, slots, depth)
        } else {
            (single_entry_node(&flat[off..off + 32], at, geo, t), 1)
        };
        if past_eod {
            residue += 1;
            n = mark_residue(n, t);
        }
        kids.push(n);
        k += used.max(1);
    }

    if eod_zero_slots > 0 {
        kids.push(
            Node::new("unallocated slots", NodeKind::Group)
                .with_doc(
                    "Entry slots past the end-of-directory marker that are entirely zero. \
                     They are listed as a count because there is nothing in them to show.",
                )
                .with_diag(Diagnostic::info(format!(
                    "{eod_zero_slots} zeroed entry slots follow the end-of-directory marker"
                ))),
        );
    }
    if residue > 0 {
        node = node.with_diag(
            Diagnostic::warn(format!(
                "{residue} non-zero entry slot(s) survive past the end-of-directory marker"
            ))
            .with_hint(
                "this is unallocated space that still holds records; it is the first place \
                 to look for what a delete left behind",
            ),
        );
    }
    let deleted = kids.iter().filter(|k| k.label.contains("deleted")).count();
    if deleted > 0 {
        node = node.with_diag(Diagnostic::info(format!(
            "{deleted} entry or entry set(s) here are marked not-in-use and are shown below"
        )));
    }

    node.with_children(kids)
}

/// One 32-byte record parsed with the descriptor for its type, deleted or not.
fn single_entry_node(bytes: &[u8], at: u64, geo: &Geometry, t: u8) -> Node {
    let restored = types::undeleted(t);
    let d: &'static StructDesc = match restored {
        types::ALLOCATION_BITMAP => &desc::ALLOCATION_BITMAP,
        types::UPCASE_TABLE => &desc::UPCASE_TABLE,
        types::VOLUME_LABEL => &desc::VOLUME_LABEL,
        types::VOLUME_GUID => &desc::VOLUME_GUID,
        types::STREAM_EXTENSION => &desc::STREAM_EXTENSION,
        types::FILE_NAME => &desc::FILE_NAME,
        _ => &desc::GENERIC_ENTRY,
    };
    let live = types::is_in_use(t);
    let base_label = format!("{} entry", types::entry_type_label(restored));
    let label = if live { base_label.clone() } else { format!("deleted {base_label}") };
    let mut n = entry_node(bytes, at, geo, d, &label);
    let payload_blank = bytes[1..].iter().all(|&b| b == 0);

    if restored == types::VOLUME_LABEL {
        if let Some(text) = n.find_child("volume_label").and_then(|c| c.value.as_str()) {
            let count = n.find_child("character_count").and_then(|c| c.value.as_u64()).unwrap_or(0);
            let shown: String = text.chars().take(count as usize).collect();
            n.label = Cow::Owned(format!("{label} \"{shown}\""));
        }
    }
    if restored == types::VOLUME_GUID && !(payload_blank && !live) {
        let (stored, computed, restored_ck) = set_checksum(bytes, !live);
        n = attach_set_checksum(n, stored, computed, restored_ck, live);
    }

    if !live {
        n = n.with_diag(
            Diagnostic::info(format!(
                "InUse (bit 7) is clear: the type byte is {t:#04X} where a live record \
                 would be {restored:#04X}"
            ))
            .with_hint(
                "deleting this record changed one bit; every other byte below is the \
                 original content",
            ),
        );
        if payload_blank {
            n = n.with_diag(Diagnostic::info(
                "nothing survives in it: every byte but the type byte is zero, so this is \
                 a slot that was pre-allocated and never used, or one that was overwritten",
            ));
        }
    }
    if types::is_secondary(t) {
        n = n.with_diag(Diagnostic::warn(
            "a secondary entry appearing on its own: it belongs to an entry set whose \
             0x85 primary is missing or was overwritten",
        ));
    }
    n
}

/// Tag a record that lies past the end-of-directory marker.
///
/// No driver will ever read these slots, which is exactly why they are the last
/// place a filename survives: nothing has any reason to overwrite them.
fn mark_residue(mut n: Node, t: u8) -> Node {
    n.label = Cow::Owned(format!("residue: {}", n.label));
    n.with_diag(
        Diagnostic::warn(format!(
            "this slot is past the end-of-directory marker, so no driver will read it, \
             but it still holds a {} record",
            types::entry_type_label(types::undeleted(t))
        ))
        .with_hint("unallocated directory space that was never overwritten"),
    )
}

fn entry_node(
    bytes: &[u8],
    at: u64,
    geo: &Geometry,
    d: &'static StructDesc,
    label: &str,
) -> Node {
    let mut n = blktamper_core::read_struct(d, bytes, ReadOutcome::Ok, geo.ctx_at(at));
    n.label = Cow::Owned(label.to_string());
    n
}

// ----------------------------------------------------------------- entry sets

/// Group a 0x85 primary and its secondaries into the one row a user thinks of as
/// "a file" (spec §6.3).
///
/// The set is presented as a `Group` with `Extent::Many` over all of its 32-byte
/// records, so the hex pane highlights the whole thing and expanding it shows each
/// record's own fields.
#[allow(clippy::too_many_arguments)]
fn entry_set_node(
    src: &dyn BlockSource,
    geo: &Geometry,
    flat: &[u8],
    runs: &[(u64, u64)],
    k: usize,
    slots: usize,
    depth: u32,
) -> (Node, usize) {
    let es = desc::ENTRY_SIZE as usize;
    let off = k * es;
    let prim = &flat[off..off + es];
    let declared = prim[1] as usize;
    let available = slots - k - 1;
    let secondaries = declared.min(available);
    let total = 1 + secondaries;
    let set = &flat[off..off + total * es];
    let live = types::is_in_use(prim[0]);

    // Parse every record of the set with its own descriptor.
    let mut kids = Vec::with_capacity(total);
    let mut stream: Option<&[u8]> = None;
    let mut name_units: Vec<u16> = Vec::new();
    let mut name_entries = 0usize;
    let mut name_residue = false;
    let mut mixed = false;

    for i in 0..total {
        let eo = off + i * es;
        let bytes = &flat[eo..eo + es];
        let at = abs_of(runs, eo as u64).unwrap_or(0);
        let t = bytes[0];
        if types::is_in_use(t) != live {
            mixed = true;
        }
        let restored = types::undeleted(t);
        let (d, label): (&'static StructDesc, String) = match (i, restored) {
            (0, _) => (&desc::FILE_ENTRY, "file entry".into()),
            (_, types::STREAM_EXTENSION) => (&desc::STREAM_EXTENSION, "stream extension".into()),
            (_, types::FILE_NAME) => {
                (&desc::FILE_NAME, format!("file name [{name_entries}]"))
            }
            _ => (&desc::GENERIC_ENTRY, types::entry_type_label(t).to_string()),
        };
        if i > 0 && restored == types::STREAM_EXTENSION && stream.is_none() {
            stream = Some(bytes);
        }
        if i > 0 && restored == types::FILE_NAME {
            name_entries += 1;
            for c in bytes[2..es].chunks_exact(2) {
                name_units.push(u16::from_le_bytes([c[0], c[1]]));
            }
        }
        let label = if types::is_in_use(t) { label } else { format!("deleted {label}") };
        kids.push(entry_node(bytes, at, geo, d, &label));
    }

    // Everything the stream extension governs.
    let name_length = stream.and_then(|s| s.get(3).copied()).unwrap_or(0) as usize;
    let first_cluster = stream.and_then(|s| u32le(s, 0x14)).unwrap_or(0) as u64;
    let data_length = stream.and_then(|s| u64le(s, 0x18)).unwrap_or(0);
    let valid_len = stream.and_then(|s| u64le(s, 0x08)).unwrap_or(0);
    let sec_flags = stream.and_then(|s| s.get(1).copied()).unwrap_or(0);
    let no_fat_chain = sec_flags & 0x02 != 0;
    let alloc_possible = sec_flags & 0x01 != 0;
    let stored_hash = stream.and_then(|s| u16le(s, 4));
    let attrs = u16le(prim, 4).unwrap_or(0);
    let is_dir = attrs & 0x10 != 0;

    if name_units.len() > name_length {
        name_residue = name_units[name_length..].iter().any(|&u| u != 0);
    }
    let shown: Vec<u16> = name_units.iter().copied().take(name_length).collect();
    let mut name_bytes = Vec::with_capacity(shown.len() * 2);
    for u in &shown {
        name_bytes.extend_from_slice(&u.to_le_bytes());
    }
    let name = utf16le_lossy(&name_bytes, false);

    let kind = match (live, is_dir) {
        (true, true) => "directory",
        (true, false) => "file",
        (false, true) => "deleted directory",
        (false, false) => "deleted file",
    };
    let mut node = Node::new(Cow::Owned(format!("{kind} \"{name}\"")), NodeKind::Group)
        .with_doc(
            "An entry set: a 0x85 file entry, one 0xC0 stream extension, and one 0xC1 \
             file name entry per 15 code units of the name. The records are only \
             meaningful together, which is why the set checksum covers all of them.",
        );
    node.value = Value::Composite;
    node.raw = set.to_vec();
    node.extent = blktamper_core::Extent::Many(
        (0..total)
            .filter_map(|i| abs_of(runs, (off + i * es) as u64))
            .map(|a| Span::bytes(a, desc::ENTRY_SIZE))
            .collect(),
    );

    // The set checksum, and — the part that matters forensically — whether it would
    // match if the InUse bits were put back.
    let (stored_ck, computed_ck, restored_ck) = set_checksum(set, !live || mixed);
    if let Some(primary) = kids.first_mut() {
        let taken = std::mem::take(primary);
        *primary = attach_set_checksum(taken, stored_ck, computed_ck, restored_ck, live && !mixed);
    }
    if !live {
        if restored_ck == stored_ck && stored_ck.is_some() {
            node = node.with_diag(
                Diagnostic::info(
                    "the set checksum matches once the InUse bits are restored: nothing but \
                     those bits was changed, so the record is intact",
                )
                .with_hint("the name, size and first cluster below are the original values"),
            );
        } else if stored_ck.is_some() {
            node = node.with_diag(Diagnostic::warn(
                "the set checksum does not match even with the InUse bits restored: part of \
                 this record was overwritten after it was deleted",
            ));
        }
        node = node.with_diag(
            Diagnostic::info(format!(
                "deleted: the type bytes are {:#04X}/{:#04X}/{:#04X}... where a live set \
                 would be 0x85/0xC0/0xC1",
                prim[0],
                set.get(es).copied().unwrap_or(0),
                set.get(2 * es).copied().unwrap_or(0)
            ))
            .with_hint(
                "a delete clears one bit per record and nothing else; the filename above is \
                 still on the disk",
            ),
        );
    }
    if mixed {
        node = node.with_diag(
            Diagnostic::warn(
                "the records in this set do not agree about whether they are in use",
            )
            .with_hint(
                "a set that was partly rewritten: one record was reused while its \
                 neighbours were not",
            ),
        );
    }

    // Structure.
    if declared > available {
        node = node.with_diag(Diagnostic::bad(format!(
            "secondary_count says {declared} but only {available} entries remain in this \
             directory; the set is truncated"
        )));
    }
    if declared < 2 {
        node = node.with_diag(Diagnostic::bad(format!(
            "secondary_count is {declared}; every file needs at least a stream extension \
             and one file name entry"
        )));
    }
    if stream.is_none() {
        node = node.with_diag(Diagnostic::bad(
            "the set has no 0xC0 stream extension, so its size and first cluster are unknown",
        ));
    }
    let expect_names = name_length.div_ceil(15);
    if stream.is_some() && name_entries != expect_names {
        node = node.with_diag(Diagnostic::warn(format!(
            "name_length {name_length} needs {expect_names} file name entries, but the set \
             has {name_entries}"
        )));
    }
    if name_residue {
        node = node.with_diag(
            Diagnostic::info(
                "the file name entries hold non-zero code units past name_length",
            )
            .with_hint("padding from a longer name this slot held before"),
        );
    }
    match name_hash_ascii(&shown) {
        Some(h) if stored_hash == Some(h) => {}
        Some(h) => {
            node = node.with_diag(Diagnostic::warn(format!(
                "name_hash is {:#06X} but the assembled name hashes to {h:#06X}",
                stored_hash.unwrap_or(0)
            )));
        }
        None => {
            node = node.with_diag(Diagnostic::info(
                "name_hash not verified: the name contains code units outside ASCII and \
                 hashing them needs the volume's up-case table, which this build does not \
                 expand",
            ));
        }
    }
    if valid_len > data_length {
        node = node.with_diag(Diagnostic::warn(format!(
            "valid_data_length {valid_len} exceeds data_length {data_length}"
        )));
    } else if valid_len < data_length {
        node = node.with_diag(
            Diagnostic::info(format!(
                "{} bytes of the allocation past valid_data_length were never written",
                data_length - valid_len
            ))
            .with_hint("allocated but unwritten space still holds whatever was there before"),
        );
    }
    if !alloc_possible && (first_cluster != 0 || data_length != 0) {
        node = node.with_diag(Diagnostic::warn(
            "AllocationPossible is clear, so first_cluster and data_length must both be \
             zero, and they are not",
        ));
    }

    // Where the bytes are.
    if first_cluster != 0 && geo.trusted {
        // A directory that is walked through the FAT ends at its end-of-chain
        // marker, so its declared length adds nothing. A *contiguous* one has no
        // chain at all: data_length is the only thing that says how many clusters
        // it occupies, and dropping it here would silently hide every entry past
        // the first cluster.
        let want = if is_dir && !no_fat_chain { None } else { Some(data_length) };
        let (clusters, diags) = cluster_chain(src, geo, first_cluster, no_fat_chain, want);
        let runs2 = cluster_runs(geo, &clusters);
        let mut data = Node::new(
            if is_dir { "directory clusters" } else { "file data" },
            NodeKind::Region,
        )
        .with_doc(
            "The clusters this record owns, resolved either arithmetically (NoFatChain \
             set) or by walking the FAT (NoFatChain clear).",
        );
        data.extent = runs_to_extent(&runs2);
        data.value = Value::Uint(clusters.len() as u64);
        data.repr = Repr::Dec;
        for d in diags {
            data = data.with_diag(d);
        }
        if runs2.len() > MAX_SPANS {
            data = data.with_diag(Diagnostic::info(format!(
                "{} runs, of which the first {MAX_SPANS} are highlighted",
                runs2.len()
            )));
        }
        if is_dir && depth < MAX_SUBDIR_DEPTH && live {
            data = data.with_lazy(Arc::new(SubdirExpander {
                geo: *geo,
                first_cluster,
                no_fat_chain,
                byte_len: want,
                depth: depth + 1,
                name: name.clone(),
            }));
        } else if is_dir && depth >= MAX_SUBDIR_DEPTH {
            data = data.with_diag(Diagnostic::warn(format!(
                "not expanded: {MAX_SUBDIR_DEPTH} levels of nesting is the limit"
            )));
        } else if is_dir && !live {
            data = data.with_diag(
                Diagnostic::info(
                    "a deleted directory's clusters are free and may already belong to \
                     something else; they are not expanded as a directory",
                )
                .with_hint("the byte range is still shown, so the hex pane can be pointed at it"),
            );
        }
        kids.push(data);
    }

    if declared > available {
        (node.with_children(kids), available + 1)
    } else {
        (node.with_children(kids), total)
    }
}

/// `(stored, computed, computed-with-InUse-restored)` for an entry set (spec §6.3.3).
///
/// The third value is what makes a deleted record readable with confidence: if it
/// matches the stored checksum, the only bytes that changed since the record was
/// live are the InUse bits.
fn set_checksum(set: &[u8], try_restore: bool) -> (Option<u64>, u64, Option<u64>) {
    let spec = &desc::ENTRY_SET_CHECKSUM;
    let stored = u16le(set, 2).map(|v| v as u64);
    let computed = spec.algo.compute(set, spec.exclude);
    let restored = if try_restore {
        let mut copy = set.to_vec();
        for i in (0..copy.len()).step_by(desc::ENTRY_SIZE as usize) {
            copy[i] |= types::IN_USE;
        }
        Some(spec.algo.compute(&copy, spec.exclude))
    } else {
        None
    };
    (stored, computed, restored)
}

/// A mismatch on a *live* set is a fault: someone edited the record and did not
/// update the checksum. On a deleted one it is not — the type bytes themselves were
/// changed, and the only question worth asking is whether anything *else* was,
/// which is what the restored value answers. Reporting the second case as `Bad`
/// would paint every pristine mkfs.exfat volume red.
fn attach_set_checksum(
    node: Node,
    stored: Option<u64>,
    computed: u64,
    restored: Option<u64>,
    live: bool,
) -> Node {
    let effective = if live { computed } else { restored.unwrap_or(computed) };
    let matches = stored == Some(effective);
    let name = desc::ENTRY_SET_CHECKSUM.algo.name();
    let how = if live {
        format!("{name} over the whole set, skipping bytes 2..4")
    } else {
        format!(
            "{name} over the whole set with the InUse bits restored, skipping bytes \
             2..4 (as stored it is {computed:#06X})"
        )
    };
    let derived = Derived {
        kind: DerivedKind::Checksum,
        value: Value::Uint(effective),
        matches,
        how,
    };
    let mut node = node;
    if let Children::Resolved(kids) = &mut node.children {
        if let Some(slot) = kids.iter_mut().find(|k| k.label == "set_checksum") {
            slot.derived = Some(derived);
            if !matches {
                let msg =
                    format!("stored {:#06X}, computed {effective:#06X}", stored.unwrap_or(0));
                let d = if live {
                    Diagnostic::bad(msg)
                        .with_hint("the entry set was modified without updating its checksum")
                } else {
                    Diagnostic::info(msg).with_hint(
                        "a deleted record whose checksum does not come back even with the \
                         InUse bits restored: something overwrote part of it",
                    )
                };
                let taken = std::mem::take(slot);
                *slot = taken.with_diag(d);
            }
            return node;
        }
    }
    node
}

/// Name hash over an ASCII name (spec §7.2.3.1).
///
/// `None` when the name has code units outside ASCII: up-casing those correctly
/// needs the volume's own up-case table, and a hash computed with the wrong
/// up-casing would be reported as a mismatch that is really our fault.
fn name_hash_ascii(units: &[u16]) -> Option<u16> {
    if units.iter().any(|&u| u > 0x7F) {
        return None;
    }
    let mut bytes = Vec::with_capacity(units.len() * 2);
    for &u in units {
        let up = if (0x61..=0x7A).contains(&u) { u - 0x20 } else { u };
        bytes.extend_from_slice(&up.to_le_bytes());
    }
    Some(ChecksumAlgo::ExfatEntrySet.compute(&bytes, &[]) as u16)
}

/// Expands a subdirectory when the user opens it, and not before (R-3.5).
#[derive(Debug)]
struct SubdirExpander {
    geo: Geometry,
    first_cluster: u64,
    no_fat_chain: bool,
    /// `Some` only for a contiguous directory, where it is the sole record of how
    /// many clusters the directory occupies.
    byte_len: Option<u64>,
    depth: u32,
    name: String,
}

impl Expander for SubdirExpander {
    fn expand(&self, src: &dyn BlockSource) -> Vec<Node> {
        let node = directory_node(
            src,
            &self.geo,
            self.first_cluster,
            self.no_fat_chain,
            self.byte_len,
            format!("contents of \"{}\"", self.name),
            self.depth,
        );
        match node.children {
            Children::Resolved(kids) => kids,
            _ => vec![node],
        }
    }
}

// ------------------------------------------------- bitmap and up-case table

/// What the root directory's critical primary entries point at.
#[derive(Clone, Copy, Debug)]
struct MetaRef {
    /// Index of the entry's node among the root directory's children, for patching.
    index: usize,
    first_cluster: u64,
    data_length: u64,
    stored_checksum: Option<u64>,
}

#[derive(Default, Debug)]
struct RootMeta {
    bitmap: Option<MetaRef>,
    upcase: Option<MetaRef>,
    label: Option<String>,
}

fn root_metadata(root_dir: &Node) -> RootMeta {
    let mut meta = RootMeta::default();
    let Some(kids) = root_dir.children.resolved() else { return meta };
    for (i, k) in kids.iter().enumerate() {
        let t = k.find_child("entry_type").and_then(|c| c.value.as_u64()).unwrap_or(0) as u8;
        if !types::is_in_use(t) {
            continue;
        }
        let get = |n: &str| k.find_child(n).and_then(|c| c.value.as_u64());
        let r = MetaRef {
            index: i,
            first_cluster: get("first_cluster").unwrap_or(0),
            data_length: get("data_length").unwrap_or(0),
            stored_checksum: get("table_checksum"),
        };
        match t {
            types::ALLOCATION_BITMAP if meta.bitmap.is_none() => meta.bitmap = Some(r),
            types::UPCASE_TABLE if meta.upcase.is_none() => meta.upcase = Some(r),
            types::VOLUME_LABEL if meta.label.is_none() => {
                meta.label = k.find_child("volume_label").and_then(|c| c.value.as_str()).map(str::to_string);
            }
            _ => {}
        }
    }
    meta
}

/// Attach a computed value to a field of a directory entry that was already parsed.
fn patch_child(dir: &mut Node, index: usize, field: &str, derived: Option<Derived>) {
    let Some(derived) = derived else { return };
    let Children::Resolved(kids) = &mut dir.children else { return };
    let Some(entry) = kids.get_mut(index) else { return };
    let matches = derived.matches;
    let computed = derived.value.as_u64().unwrap_or(0);
    let Children::Resolved(fields) = &mut entry.children else { return };
    let Some(slot) = fields.iter_mut().find(|f| f.label == field) else { return };
    let stored = slot.value.as_u64().unwrap_or(0);
    slot.derived = Some(derived);
    if !matches {
        let taken = std::mem::take(slot);
        *slot = taken.with_diag(Diagnostic::bad(format!(
            "stored {stored:#X}, computed {computed:#X}"
        )));
    }
}

/// The allocation bitmap: one bit per cluster, starting at cluster 2 in bit 0.
fn bitmap_node(src: &dyn BlockSource, geo: &Geometry, r: MetaRef) -> (Node, Option<Derived>) {
    let want = geo.cluster_count.div_ceil(8);
    let (clusters, chain_diags) = cluster_chain(src, geo, r.first_cluster, false, Some(r.data_length));
    let runs = cluster_runs(geo, &clusters);
    let mut node = Node::new("allocation bitmap", NodeKind::Region).with_doc(
        "The authority on which clusters are in use. Bit 0 of byte 0 is cluster 2. \
         The FAT is not an authority: a contiguous file has no FAT entries at all.",
    );
    node.extent = runs_to_extent(&runs);
    node.value = Value::Composite;
    for d in chain_diags {
        node = node.with_diag(d);
    }

    let derived = Some(Derived {
        kind: DerivedKind::Computed,
        value: Value::Uint(want),
        matches: r.data_length == want,
        how: format!("ceil({} clusters / 8)", geo.cluster_count),
    });
    if r.data_length != want {
        node = node.with_diag(Diagnostic::bad(format!(
            "the entry declares {} bytes but {} clusters need {want}",
            r.data_length, geo.cluster_count
        )));
    }

    let (bits, read_diags) = read_runs(src, &runs, r.data_length.min(MAX_BITMAP_BYTES));
    for d in read_diags {
        node = node.with_diag(d);
    }
    if bits.is_empty() {
        return (node.with_diag(Diagnostic::bad("the bitmap could not be read")), derived);
    }

    let allocated: u64 = bits.iter().map(|b| b.count_ones() as u64).sum();
    let counted = (bits.len() as u64).saturating_mul(8).min(geo.cluster_count);
    let free = counted.saturating_sub(allocated);
    let pct = allocated.saturating_mul(100).checked_div(counted).unwrap_or(0);

    let mut kids = vec![
        computed("allocated_clusters", allocated, Repr::Dec,
            "Set bits in the bitmap, over the range that was read."),
        computed("free_clusters", free, Repr::Dec,
            "Clear bits in the bitmap, over the range that was read."),
        computed("allocated_bytes", allocated.saturating_mul(geo.cluster_size), Repr::SizeBytes,
            "allocated_clusters x cluster_size."),
        computed("percent_in_use (computed)", pct, Repr::Dec,
            "Rounded down. Compare with the boot sector's advisory percent_in_use."),
    ];
    if geo.percent_in_use != pct && geo.percent_in_use != 0xFF {
        kids.push(
            Node::new("percent_in_use disagreement", NodeKind::Group).with_diag(
                Diagnostic::info(format!(
                    "the boot sector says {}%, the bitmap says {pct}%",
                    geo.percent_in_use
                ))
                .with_hint(
                    "percent_in_use is advisory and rounded; a small difference is normal",
                ),
            ),
        );
    }

    // Cheap agreement check against the FAT. A cluster that is allocated but has a
    // zero FAT entry is perfectly legal — that is what NoFatChain means — so only
    // the other direction is a finding.
    kids.push(bitmap_fat_crosscheck(src, geo, &bits));

    (node.with_children(kids), derived)
}

fn bitmap_fat_crosscheck(src: &dyn BlockSource, geo: &Geometry, bits: &[u8]) -> Node {
    let mut node = Node::new("bitmap vs FAT", NodeKind::Group).with_doc(
        "A cluster with a FAT chain must be allocated in the bitmap. The converse is \
         not true: a contiguous file is allocated in the bitmap and absent from the \
         FAT, which is exactly what NoFatChain means.",
    );
    let Some(fat_at) = geo.fat_byte(geo.active_fat.min(1)) else {
        return node.with_diag(Diagnostic::warn("the active FAT's offset overflows"));
    };
    let n = geo.cluster_count.min(MAX_CROSSCHECK_CLUSTERS);
    let (fat, outcome) = src.read_vec(
        fat_at.saturating_add(8),
        (n.saturating_mul(4)).min(usize::MAX as u64) as usize,
    );
    if outcome == ReadOutcome::Unreadable {
        return node.with_status(Status::Unreadable).with_diag(Diagnostic {
            status: Status::Unreadable,
            message: "the FAT could not be read, so no comparison was made".into(),
            hint: None,
        });
    }

    let mut chained_but_free = Vec::new();
    let mut allocated_without_chain = 0u64;
    let mut compared = 0u64;
    for i in 0..n {
        let Some(v) = u32le(&fat, (i as usize).saturating_mul(4)) else { break };
        let byte = (i / 8) as usize;
        let Some(&b) = bits.get(byte) else { break };
        let alloc = b >> (i % 8) & 1 == 1;
        compared += 1;
        if v != 0 && !alloc {
            if chained_but_free.len() < 8 {
                chained_but_free.push(i + 2);
            }
        } else if alloc && v == 0 {
            allocated_without_chain += 1;
        }
    }

    node = node.with_children(vec![computed(
        "clusters_compared",
        compared,
        Repr::Dec,
        "How many clusters the comparison covered before its bound was reached.",
    )]);
    if !chained_but_free.is_empty() {
        node = node.with_diag(
            Diagnostic::warn(format!(
                "cluster(s) {chained_but_free:?} have a FAT entry but are marked free in \
                 the bitmap"
            ))
            .with_hint(
                "a chain through unallocated space: either the bitmap is stale or the \
                 chain is a remnant",
            ),
        );
    }
    if allocated_without_chain > 0 {
        node = node.with_diag(Diagnostic::info(format!(
            "{allocated_without_chain} cluster(s) are allocated with a zero FAT entry, \
             which is the normal state for a contiguous (NoFatChain) file"
        )));
    }
    if chained_but_free.is_empty() && allocated_without_chain == 0 {
        node = node.with_diag(Diagnostic::info(format!(
            "the bitmap and the FAT agree over the first {compared} clusters"
        )));
    }
    node
}

/// The up-case table: geometry and checksum, but never expanded until asked.
fn upcase_node(src: &dyn BlockSource, geo: &Geometry, r: MetaRef) -> (Node, Option<Derived>) {
    let (clusters, chain_diags) = cluster_chain(src, geo, r.first_cluster, false, Some(r.data_length));
    let runs = cluster_runs(geo, &clusters);
    let mut node = Node::new("up-case table", NodeKind::Region).with_doc(
        "Maps UTF-16 code units to their upper-case form, so filename comparison does \
         not depend on the host's locale. Stored run-length compressed: a 0xFFFF entry \
         is followed by a count of code units that map to themselves.",
    );
    node.extent = runs_to_extent(&runs);
    node.value = Value::Composite;
    for d in chain_diags {
        node = node.with_diag(d);
    }

    let mut kids = vec![
        computed("table_bytes", r.data_length, Repr::SizeBytes,
            "Length from the 0x82 entry. 5836 bytes is what mkfs.exfat writes; the maximum is 0x1FFFF x 2."),
        computed("code_units", r.data_length / 2, Repr::Dec,
            "Entries in the compressed table, which is not the number of code units it covers."),
    ];

    let mut derived = None;
    if r.data_length > MAX_UPCASE_BYTES {
        node = node.with_diag(Diagnostic::warn(format!(
            "the table declares {} bytes, more than the {MAX_UPCASE_BYTES} this build will \
             read, so its checksum was not verified",
            r.data_length
        )));
    } else {
        let (table, read_diags) = read_runs(src, &runs, r.data_length);
        for d in read_diags {
            node = node.with_diag(d);
        }
        if table.len() as u64 == r.data_length && !table.is_empty() {
            let spec = &desc::UPCASE_CHECKSUM;
            let computed_ck = spec.algo.compute(&table, spec.exclude);
            derived = Some(Derived {
                kind: DerivedKind::Checksum,
                value: Value::Uint(computed_ck),
                matches: r.stored_checksum == Some(computed_ck),
                how: format!("rotate-right-and-add over {} table bytes", table.len()),
            });
            if r.stored_checksum != Some(computed_ck) {
                node = node.with_diag(Diagnostic::bad(format!(
                    "the 0x82 entry stores {:#010X} but the table hashes to {computed_ck:#010X}",
                    r.stored_checksum.unwrap_or(0)
                )));
            } else {
                node = node.with_diag(Diagnostic::info(
                    "the table matches the checksum in its directory entry",
                ));
            }
        } else if !runs.is_empty() {
            node = node.with_diag(Diagnostic::warn(format!(
                "only {} of {} table bytes were readable, so the checksum was not verified",
                table.len(),
                r.data_length
            )));
        }
    }

    // The mapping itself is expanded only when the user opens it: a fully decoded
    // table is 65536 rows and nobody wants it by default.
    let mut entries = Node::new("mappings", NodeKind::Array).with_doc(
        "Decoded run-length entries. Expanded on demand — a full table describes \
         65536 code units.",
    );
    entries.extent = runs_to_extent(&runs);
    entries.value = Value::Composite;
    entries = entries.with_lazy(Arc::new(UpcaseEntries {
        runs: runs.clone(),
        len: r.data_length.min(MAX_UPCASE_BYTES),
    }));
    kids.push(entries);

    (node.with_children(kids), derived)
}

/// Decodes the compressed up-case table, on demand only.
#[derive(Debug)]
struct UpcaseEntries {
    runs: Vec<(u64, u64)>,
    len: u64,
}

impl Expander for UpcaseEntries {
    fn expand(&self, src: &dyn BlockSource) -> Vec<Node> {
        let (table, _) = read_runs(src, &self.runs, self.len);
        let mut out = Vec::new();
        let mut i = 0usize;
        let mut unit: u32 = 0;
        while i + 1 < table.len() && out.len() < MAX_FAT_NODES {
            let v = u16::from_le_bytes([table[i], table[i + 1]]);
            let at = abs_of(&self.runs, i as u64).unwrap_or(0);
            if v == 0xFFFF && i + 3 < table.len() {
                let n = u16::from_le_bytes([table[i + 2], table[i + 3]]) as u32;
                out.push(Node {
                    label: format!("U+{unit:04X}..U+{:04X} identity", unit.saturating_add(n).saturating_sub(1))
                        .into(),
                    extent: blktamper_core::Extent::bytes(at, 4),
                    kind: NodeKind::Field,
                    value: Value::Uint(n as u64),
                    repr: Repr::Dec,
                    doc: Some("A compressed run: this many code units map to themselves."),
                    raw: table[i..i + 4].to_vec(),
                    ..Default::default()
                });
                unit = unit.saturating_add(n);
                i += 4;
            } else {
                if v as u32 != unit {
                    out.push(Node {
                        label: format!("U+{unit:04X} -> U+{v:04X}").into(),
                        extent: blktamper_core::Extent::bytes(at, 2),
                        kind: NodeKind::Field,
                        value: Value::Uint(v as u64),
                        repr: Repr::Hex,
                        doc: Some("Upper-case form of this code unit."),
                        raw: table[i..i + 2].to_vec(),
                        ..Default::default()
                    });
                }
                unit = unit.saturating_add(1);
                i += 2;
            }
        }
        if out.is_empty() {
            out.push(
                Node::new("empty", NodeKind::Group)
                    .with_diag(Diagnostic::warn("the table decoded to no mappings")),
            );
        }
        out
    }
}

// --------------------------------------------------------------------- helpers

/// A node that owns no bytes: something this module worked out rather than read.
fn computed(
    label: impl Into<Cow<'static, str>>,
    value: u64,
    repr: Repr,
    doc: &'static str,
) -> Node {
    Node {
        label: label.into(),
        extent: blktamper_core::Extent::None,
        kind: NodeKind::Field,
        value: Value::Uint(value),
        repr,
        doc: Some(doc),
        flags: FieldFlags::DERIVED,
        ..Default::default()
    }
}

fn array_node(
    label: &'static str,
    span: Span,
    kids: Vec<Node>,
    doc: &'static str,
) -> Node {
    let mut n = Node::new(label, NodeKind::Array).with_doc(doc);
    n.extent = blktamper_core::Extent::One(span);
    n.value = Value::Composite;
    n.with_children(kids)
}

/// Attach a diagnostic to a named child, or to the node itself when there is no
/// such child (a short read, or a descriptor that changed under us).
fn with_child_diag(mut node: Node, name: &str, d: Diagnostic) -> Node {
    if let Children::Resolved(kids) = &mut node.children {
        if let Some(slot) = kids.iter_mut().find(|k| k.label == name) {
            let taken = std::mem::take(slot);
            *slot = taken.with_diag(d);
            return node;
        }
    }
    node.with_diag(d)
}

// ---------------------------------------------------------------- test fixture

/// Build a small but genuinely valid exFAT volume whose root directory holds
/// `root_entries` after the three entries a volume must have.
///
/// Real images from `mkfs.exfat` are the primary evidence (see `tests/exfat.rs`),
/// but they cannot be made to contain a truncated entry set, a chain that loops or
/// a shift of 200. This builds those. Geometry: 512-byte sectors, one sector per
/// cluster, 1000 clusters, root at cluster 2, bitmap at 3, up-case table at 4, and
/// cluster 5 pre-allocated for a synthesized file.
///
/// The output is a real volume, not a mock: `fsck.exfat -n` from exfatprogs 1.2.2
/// reports it `clean. directories 1, files 1` when it is given one entry set at
/// cluster 5, which is what makes tests built on it worth anything.
#[doc(hidden)]
pub fn synth_volume(root_entries: &[u8]) -> Vec<u8> {
    const BPS: usize = 512;
    const FAT_OFF: usize = 24;
    const FAT_LEN: usize = 8;
    const HEAP_OFF: usize = 32;
    const CLUSTERS: u32 = 1000;
    let volume_sectors = HEAP_OFF + CLUSTERS as usize;
    let mut img = vec![0u8; volume_sectors * BPS];
    let cluster = |n: usize| HEAP_OFF * BPS + (n - 2) * BPS;

    img[0..3].copy_from_slice(&[0xEB, 0x76, 0x90]);
    img[3..11].copy_from_slice(b"EXFAT   ");
    img[0x48..0x50].copy_from_slice(&(volume_sectors as u64).to_le_bytes());
    img[0x50..0x54].copy_from_slice(&(FAT_OFF as u32).to_le_bytes());
    img[0x54..0x58].copy_from_slice(&(FAT_LEN as u32).to_le_bytes());
    img[0x58..0x5C].copy_from_slice(&(HEAP_OFF as u32).to_le_bytes());
    img[0x5C..0x60].copy_from_slice(&CLUSTERS.to_le_bytes());
    img[0x60..0x64].copy_from_slice(&2u32.to_le_bytes());
    img[0x64..0x68].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    img[0x68..0x6A].copy_from_slice(&0x0100u16.to_le_bytes());
    img[0x6C] = 9; // 512-byte sectors
    img[0x6D] = 0; // one sector per cluster
    img[0x6E] = 1;
    img[0x6F] = 0x80;
    img[0x1FE] = 0x55;
    img[0x1FF] = 0xAA;

    for s in 1..=8 {
        let end = (s + 1) * BPS;
        img[end - 4..end].copy_from_slice(&0xAA55_0000u32.to_le_bytes());
    }

    let fat = FAT_OFF * BPS;
    for (i, v) in [0xFFFF_FFF8u32, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF]
        .iter()
        .enumerate()
    {
        img[fat + i * 4..fat + i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }

    // Clusters 2..=5 are in use: root directory, bitmap, up-case table, and one
    // spare for whatever entry set the caller passes in.
    img[cluster(3)] = 0b0000_1111;
    let table: [u8; 4] = [0xFF, 0xFF, 0x00, 0x00];
    img[cluster(4)..cluster(4) + 4].copy_from_slice(&table);
    let table_ck = desc::UPCASE_CHECKSUM.algo.compute(&table, desc::UPCASE_CHECKSUM.exclude) as u32;

    let root = cluster(2);
    let mut e = [0u8; 32];
    e[0] = types::VOLUME_LABEL;
    e[1] = 5;
    for (i, c) in "SYNTH".encode_utf16().enumerate() {
        e[2 + i * 2..4 + i * 2].copy_from_slice(&c.to_le_bytes());
    }
    img[root..root + 32].copy_from_slice(&e);

    let mut e = [0u8; 32];
    e[0] = types::ALLOCATION_BITMAP;
    e[0x14..0x18].copy_from_slice(&3u32.to_le_bytes());
    e[0x18..0x20].copy_from_slice(&(CLUSTERS as u64 / 8).to_le_bytes());
    img[root + 32..root + 64].copy_from_slice(&e);

    let mut e = [0u8; 32];
    e[0] = types::UPCASE_TABLE;
    e[4..8].copy_from_slice(&table_ck.to_le_bytes());
    e[0x14..0x18].copy_from_slice(&4u32.to_le_bytes());
    e[0x18..0x20].copy_from_slice(&4u64.to_le_bytes());
    img[root + 64..root + 96].copy_from_slice(&e);

    let n = root_entries.len().min(BPS - 96);
    img[root + 96..root + 96 + n].copy_from_slice(&root_entries[..n]);

    // Sector 11 holds the checksum of sectors 0..=10, repeated; sectors 12..=23 are
    // a copy of the whole region.
    let spec = &desc::BOOT_REGION_CHECKSUM;
    let ck = spec.algo.compute(&img[..11 * BPS], spec.exclude) as u32;
    for i in 0..BPS / 4 {
        img[11 * BPS + i * 4..11 * BPS + i * 4 + 4].copy_from_slice(&ck.to_le_bytes());
    }
    let (main, rest) = img.split_at_mut(12 * BPS);
    rest[..12 * BPS].copy_from_slice(main);
    img
}

/// A 0x85/0xC0/0xC1 entry set for `name`, with a correct set checksum and name
/// hash. `deleted` clears the `InUse` bit of every record, which is exactly what
/// deleting the file would do.
#[doc(hidden)]
pub fn synth_entry_set(
    name: &str,
    first_cluster: u32,
    length: u64,
    no_fat_chain: bool,
    deleted: bool,
) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let parts = units.len().div_ceil(15).max(1);
    let mut out = vec![0u8; (2 + parts) * 32];
    out[0] = types::FILE;
    out[1] = (1 + parts) as u8;
    out[4..6].copy_from_slice(&0x0020u16.to_le_bytes()); // Archive
    out[32] = types::STREAM_EXTENSION;
    out[33] = 0x01 | if no_fat_chain { 0x02 } else { 0x00 };
    out[35] = units.len() as u8;
    let hash = name_hash_ascii(&units).unwrap_or(0);
    out[36..38].copy_from_slice(&hash.to_le_bytes());
    out[40..48].copy_from_slice(&length.to_le_bytes());
    out[52..56].copy_from_slice(&first_cluster.to_le_bytes());
    out[56..64].copy_from_slice(&length.to_le_bytes());
    for p in 0..parts {
        let o = (2 + p) * 32;
        out[o] = types::FILE_NAME;
        for (i, u) in units.iter().skip(p * 15).take(15).enumerate() {
            out[o + 2 + i * 2..o + 4 + i * 2].copy_from_slice(&u.to_le_bytes());
        }
    }
    let spec = &desc::ENTRY_SET_CHECKSUM;
    let ck = spec.algo.compute(&out, spec.exclude) as u16;
    out[2..4].copy_from_slice(&ck.to_le_bytes());
    if deleted {
        for i in (0..out.len()).step_by(32) {
            out[i] &= !types::IN_USE;
        }
    }
    out
}

#[cfg(test)]
mod tests;
