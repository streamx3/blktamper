//! GPT — the GUID Partition Table (UEFI specification chapter 5.3).
//!
//! Layouts live in `desc.rs` and the type-GUID table in `guids.rs` (Tier A);
//! everything that needs arithmetic on values read off the disk is here (Tier B),
//! per ADR-002.
//!
//! Three things make GPT worth more than its 20 fields, and all three are Tier B:
//!
//! * **Two checksums of different shapes.** `header_crc32` covers `header_size`
//!   bytes of its own struct with its own field zeroed, which the generic reader
//!   does from a `ChecksumSpec`. `entries_crc32` covers bytes in a different part of
//!   the disk whose length is the product of two attacker-controlled 32-bit fields,
//!   which it cannot — so that one is computed here and attached by hand.
//! * **Two copies of everything.** The primary and backup headers disagree by
//!   design in exactly three fields. A diff that does not know which three reports
//!   false differences every time and is therefore ignored, which is worse than not
//!   having one.
//! * **Unused entries are evidence.** UEFI says a zero type GUID means the slot is
//!   free. It says nothing about the other 112 bytes, and most tools leave them
//!   alone. A cleared type GUID over an intact name and unique GUID is precisely
//!   what a partial wipe looks like, and surfacing it is the highest-value thing
//!   this module does.
//!
//! LBAs inside a GPT are absolute on the device (UEFI 5.3.1), so this reader
//! resolves them as `lba * sector_size` regardless of where it was opened. `base` is
//! only where it looks for the primary header: `base + one sector`, which is LBA 1
//! for the normal whole-device case.

pub mod desc;
pub mod guids;

use crate::common::{in_bounds, lba_to_byte, read_desc_at, read_exact_opt};
use blktamper_core::{
    BlockSource, ChecksumAlgo, Children, Derived, DerivedKind, Diagnostic, Expander, Extent,
    FieldFlags, FormatId, FormatProbe, Node, NodeKind, ReadCtx, RegionReader, Registry, RenderCtx,
    Repr, Score, Span, Status, Value,
};
use std::sync::Arc;

pub const ID: FormatId = FormatId("gpt");

/// Entries we are willing to materialise. Every real table has 128; `num_entries` is
/// a 32-bit value read off the disk, and multiplied by `entry_size` it is an
/// allocation request from an untrusted source. A header claiming four billion
/// entries must produce a diagnostic, not a `Vec::with_capacity`.
const MAX_ENTRIES: u32 = 4096;

/// Ceiling on `entry_size`, for the same reason. One block is already generous:
/// UEFI requires at least 128 bytes and every writer uses exactly that.
const MAX_ENTRY_SIZE: u32 = 4096;

/// Most bytes we will read purely to verify `entries_crc32`. The usual array is
/// 16 KiB; this leaves room for an unusual one without letting a corrupt header
/// turn a checksum check into a multi-gigabyte read.
const MAX_ARRAY_BYTES: u64 = 4 * 1024 * 1024;

/// MBR geometry, needed only to say whether LBA 0 protects this GPT or contradicts
/// it. Deliberately not `mbr::desc`: this check must work in a `--features gpt`
/// build with no MBR module compiled in.
const MBR_ENTRIES_OFFSET: usize = 0x1BE;
const MBR_ENTRY_SIZE: usize = 16;
const MBR_BOOT_SIG_OFFSET: usize = 0x1FE;
const MBR_TYPE_PROTECTIVE: u8 = 0xEE;

pub fn register(reg: &mut Registry) {
    reg.register(Arc::new(GptProbe));
}

#[derive(Debug)]
pub struct GptProbe;

impl FormatProbe for GptProbe {
    fn id(&self) -> FormatId {
        ID
    }

    fn name(&self) -> &'static str {
        "GPT partition table"
    }

    /// Score the sector one block past `at`, which is LBA 1 for a whole device.
    ///
    /// "EFI PART" is eight bytes of very specific ASCII and nothing else in scope
    /// carries it, so a signature match is worth more here than `55 AA` is for an
    /// MBR — but it is still only 50, because a signature says a GPT was written
    /// here once, not that this one describes this disk. The other 50 come from
    /// geometry that has to agree with the device we are actually looking at.
    ///
    /// The header CRC deliberately contributes nothing. A GPT with a broken CRC is
    /// still unambiguously a GPT, and is the single case this tool exists for;
    /// scoring it down would hide it behind whatever else matched.
    fn probe(&self, src: &dyn BlockSource, at: u64) -> Score {
        let ss = src.logical_sector_size().max(1) as u64;
        let Some(hdr_at) = at.checked_add(ss) else { return 0 };
        let Some(hdr) = read_exact_opt(src, hdr_at, ss as usize) else { return 0 };
        if hdr.len() < desc::MIN_HEADER_SIZE as usize || !hdr.starts_with(desc::SIGNATURE) {
            return 0;
        }

        let mut score: u32 = 50;
        let last_lba = (src.len() / ss).saturating_sub(1);
        let facts = HeaderFacts::from_bytes(&hdr);

        if facts.revision == desc::REVISION_1_0 as u64 {
            score += 8;
        }
        if facts.header_size >= desc::MIN_HEADER_SIZE as u64 && facts.header_size <= ss {
            score += 7;
        }
        if facts.my_lba == hdr_at / ss {
            score += 10;
        }
        if facts.alternate_lba != 0
            && facts.alternate_lba != facts.my_lba
            && facts.alternate_lba <= last_lba
        {
            score += 10;
        }
        if facts.entry_size >= desc::MIN_ENTRY_SIZE as u64
            && facts.entry_size <= MAX_ENTRY_SIZE as u64
            && facts.entry_size % 8 == 0
        {
            score += 8;
        }
        if facts.num_entries > 0 && facts.num_entries <= MAX_ENTRIES as u64 {
            score += 7;
        }
        score.min(100) as Score
    }

    fn open(&self, src: Arc<dyn BlockSource>, at: u64) -> Box<dyn RegionReader> {
        Box::new(GptReader { src, base: at })
    }
}

#[derive(Debug)]
pub struct GptReader {
    src: Arc<dyn BlockSource>,
    base: u64,
}

/// The numbers from a header that traversal and the cross-checks need.
///
/// Read once from the node tree (or straight from bytes, for the probe) so that no
/// later code re-decodes an offset and gets it subtly different.
#[derive(Clone, Copy, Debug, Default)]
struct HeaderFacts {
    present: bool,
    revision: u64,
    header_size: u64,
    my_lba: u64,
    alternate_lba: u64,
    first_usable: u64,
    last_usable: u64,
    disk_guid: [u8; 16],
    entries_lba: u64,
    num_entries: u64,
    entry_size: u64,
    entries_crc32: u64,
    /// Whether the generic reader's `header_crc32` comparison passed.
    crc_ok: bool,
}

impl HeaderFacts {
    /// Straight from a block, for the probe — which must not build a node tree.
    fn from_bytes(b: &[u8]) -> HeaderFacts {
        use crate::common::{u32le, u64le};
        HeaderFacts {
            present: b.starts_with(desc::SIGNATURE),
            revision: u32le(b, 0x08).unwrap_or(0) as u64,
            header_size: u32le(b, 0x0C).unwrap_or(0) as u64,
            my_lba: u64le(b, 0x18).unwrap_or(0),
            alternate_lba: u64le(b, 0x20).unwrap_or(0),
            first_usable: u64le(b, 0x28).unwrap_or(0),
            last_usable: u64le(b, 0x30).unwrap_or(0),
            disk_guid: b.get(0x38..0x48).and_then(|s| <[u8; 16]>::try_from(s).ok()).unwrap_or_default(),
            entries_lba: u64le(b, 0x48).unwrap_or(0),
            num_entries: u32le(b, 0x50).unwrap_or(0) as u64,
            entry_size: u32le(b, 0x54).unwrap_or(0) as u64,
            entries_crc32: u32le(b, 0x58).unwrap_or(0) as u64,
            crc_ok: false,
        }
    }

    fn from_node(n: &Node) -> HeaderFacts {
        let u = |name: &str| n.find_child(name).and_then(|c| c.value.as_u64()).unwrap_or(0);
        HeaderFacts {
            present: n.find_child("signature").is_some_and(|c| c.raw.starts_with(desc::SIGNATURE)),
            revision: u("revision"),
            header_size: u("header_size"),
            my_lba: u("my_lba"),
            alternate_lba: u("alternate_lba"),
            first_usable: u("first_usable_lba"),
            last_usable: u("last_usable_lba"),
            disk_guid: guid_child(n, "disk_guid"),
            entries_lba: u("entries_lba"),
            num_entries: u("num_entries"),
            entry_size: u("entry_size"),
            entries_crc32: u("entries_crc32"),
            crc_ok: n
                .find_child("header_crc32")
                .and_then(|c| c.derived.as_ref())
                .is_some_and(|d| d.matches),
        }
    }
}

fn guid_child(n: &Node, name: &str) -> [u8; 16] {
    n.find_child(name)
        .and_then(|c| c.value.as_bytes())
        .and_then(|b| <[u8; 16]>::try_from(b).ok())
        .unwrap_or([0; 16])
}

/// Where the entry array is and how much of it we are prepared to look at.
#[derive(Debug, Default)]
struct ArrayPlan {
    /// Absolute byte offset, when `entries_lba` resolved to somewhere on the device.
    at: Option<u64>,
    /// Entries to materialise — clamped, and not necessarily `num_entries`.
    count: u32,
    /// Stride, clamped to something a multiplication can survive.
    entry_size: u32,
    /// The exact range `entries_crc32` covers, when it was readable in full. Kept so
    /// the primary and backup arrays can be compared without reading them twice.
    bytes: Option<Vec<u8>>,
}

impl RegionReader for GptReader {
    fn id(&self) -> FormatId {
        ID
    }

    fn base(&self) -> u64 {
        self.base
    }

    fn root(&self) -> Node {
        let src = &*self.src;
        let ss = self.sector_size();
        let device_lbas = src.len() / ss;
        let last_lba = device_lbas.saturating_sub(1);

        // Primary: one block past the region start, LBA 1 on a whole device.
        let primary_at = self.base.saturating_add(ss);
        let mut primary = self.read_header(primary_at, "primary header");
        let pf = HeaderFacts::from_node(&primary);
        annotate_header(&mut primary, &pf, primary_at / ss, last_lba, ss, true);
        let pplan = self.plan_entries(&mut primary, &pf);

        // Backup: the device's last LBA is where the spec puts it, so that is where
        // we look even when the primary is unreadable. `locate_backup` only differs
        // when the last LBA holds nothing and the primary names somewhere that does
        // — an image dd'd into a larger file, which is a real and common case.
        let backup_lba = self.locate_backup(&pf, last_lba);
        let backup_at = lba_to_byte(backup_lba, self.sector_bytes()).unwrap_or(0);
        let mut backup = self.read_header(backup_at, "backup header");
        let bf = HeaderFacts::from_node(&backup);
        annotate_header(&mut backup, &bf, backup_lba, last_lba, ss, false);
        let bplan = self.plan_entries(&mut backup, &bf);

        let entries = self.array_node(
            "partition entries",
            &pplan,
            &pf,
            device_lbas,
            "The primary partition entry array, expanded on demand: 128 entries of \
             128 bytes is 16 KiB and most of it is empty, but every slot still gets \
             a node because an empty slot is not necessarily a blank one.",
        );
        let backup_entries = self.array_node(
            "partition entries (backup)",
            &bplan,
            &bf,
            device_lbas,
            "The backup partition entry array, immediately before the backup header. \
             A tool that rewrites only the primary leaves this one describing the \
             disk as it was.",
        );

        let compare = compare_copies(&primary, &backup, &pf, &bf, &pplan, &bplan, ss);

        let mut root = Node {
            label: "GPT".into(),
            extent: region_extent(&[
                (primary_at, ss),
                span_of(&pplan),
                span_of(&bplan),
                (backup_at, ss),
            ]),
            kind: NodeKind::Region,
            value: Value::Composite,
            repr: Repr::Raw,
            doc: Some(
                "GUID Partition Table (UEFI 5.3). Two complete copies: a header at \
                 LBA 1 with its entry array after it, and a header at the last LBA \
                 with its entry array before it.",
            ),
            ..Default::default()
        };

        root = root.with_diag(protective_mbr_diag(src, self.base, device_lbas));
        for d in presence_diags(&pf, &bf, primary_at / ss, backup_lba) {
            root = root.with_diag(d);
        }

        let kids = vec![primary, entries, backup_entries, backup, compare];
        root.with_children(kids)
    }
}

impl GptReader {
    pub fn new(src: Arc<dyn BlockSource>, base: u64) -> GptReader {
        GptReader { src, base }
    }

    fn sector_size(&self) -> u64 {
        self.sector_bytes() as u64
    }

    fn sector_bytes(&self) -> u32 {
        self.src.logical_sector_size().max(1)
    }

    fn render(&self) -> RenderCtx {
        RenderCtx {
            sector_size: self.src.logical_sector_size(),
            cluster_base: None,
            device_len: self.src.len(),
        }
    }

    /// Read one header block.
    ///
    /// The whole block is handed to the generic reader even though the descriptor is
    /// 92 bytes, for one reason: `header_crc32` covers `header_size` bytes, and a
    /// header claiming more than 92 must be checksummed over what it claims. The
    /// node then owns the whole block and the bytes past the header become a child,
    /// so the record still tiles and a non-zero tail is visible.
    fn read_header(&self, at: u64, label: &'static str) -> Node {
        let ss = self.sector_size();
        let src = &*self.src;
        let (block, outcome) = src.read_vec(at, ss as usize);
        let ctx = ReadCtx::at(at).with_render(self.render());
        let mut n = blktamper_core::read_struct(&desc::GPT_HEADER, &block, outcome, ctx);
        n.label = label.into();

        let covered = if block.is_empty() { desc::MIN_HEADER_SIZE as u64 } else { block.len() as u64 };
        n.extent = Extent::bytes(at, covered);

        let pad_off = desc::MIN_HEADER_SIZE as usize;
        if block.len() > pad_off {
            let raw = block[pad_off..].to_vec();
            let dirty = raw.iter().any(|&b| b != 0);
            let mut pad = Node {
                label: "block padding".into(),
                extent: Extent::bytes(at + pad_off as u64, raw.len() as u64),
                kind: NodeKind::Raw,
                value: Value::Bytes(raw.clone()),
                repr: Repr::Raw,
                flags: FieldFlags::RESERVED,
                doc: Some(
                    "UEFI 5.3.2: everything from the end of the header to the end of \
                     the block is reserved and must be zero.",
                ),
                raw,
                ..Default::default()
            };
            let header_size = crate::common::u32le(&block, 0x0C).unwrap_or(0) as u64;
            if header_size > desc::MIN_HEADER_SIZE as u64 {
                pad = pad.with_diag(Diagnostic::info(format!(
                    "header_size claims {header_size} bytes, so the first {} bytes \
                     here are inside the header and inside its CRC",
                    header_size - desc::MIN_HEADER_SIZE as u64
                )));
            }
            if dirty {
                pad = pad.with_diag(
                    Diagnostic::warn("reserved tail of the header block is not zero").with_hint(
                        "residue from whatever occupied this block before the GPT was \
                         written, or an extension nobody documented",
                    ),
                );
            }
            let status = pad.status;
            let mut kids = n.children.resolved().map(|c| c.to_vec()).unwrap_or_default();
            kids.push(pad);
            n = n.with_children(kids);
            n.status = n.status.merge(status.min(Status::Warn));
        }
        n
    }

    /// Prefer the spec's location; fall back to whatever `alternate_lba` names when
    /// the last LBA holds no signature and the alternate does.
    fn locate_backup(&self, pf: &HeaderFacts, last_lba: u64) -> u64 {
        if self.has_signature(last_lba) {
            return last_lba;
        }
        let alt = pf.alternate_lba;
        if pf.present && alt != 0 && alt != pf.my_lba && alt <= last_lba && self.has_signature(alt) {
            return alt;
        }
        last_lba
    }

    fn has_signature(&self, lba: u64) -> bool {
        let Some(at) = lba_to_byte(lba, self.sector_bytes()) else { return false };
        read_exact_opt(&*self.src, at, desc::SIGNATURE.len())
            .is_some_and(|b| b.starts_with(desc::SIGNATURE))
    }

    /// Resolve the entry array's geometry, verify `entries_crc32`, and report every
    /// way the three fields that describe it can be wrong.
    ///
    /// Every multiplication here is checked before it happens: `num_entries` and
    /// `entry_size` are both 32-bit values straight off the disk, and their product
    /// is the length of a read.
    fn plan_entries(&self, node: &mut Node, f: &HeaderFacts) -> ArrayPlan {
        let src = &*self.src;
        let ss = self.sector_size();
        let mut plan = ArrayPlan::default();

        if f.entry_size < desc::MIN_ENTRY_SIZE as u64 {
            diag_on(
                node,
                "entry_size",
                Diagnostic::bad(format!(
                    "{} is below the {} bytes UEFI 5.3.2 requires; entries are shown \
                     at a {}-byte stride instead",
                    f.entry_size,
                    desc::MIN_ENTRY_SIZE,
                    desc::MIN_ENTRY_SIZE
                )),
            );
        } else if f.entry_size % 8 != 0 {
            diag_on(
                node,
                "entry_size",
                Diagnostic::bad(format!("{} is not a multiple of 8", f.entry_size)),
            );
        } else if f.entry_size > MAX_ENTRY_SIZE as u64 {
            diag_on(
                node,
                "entry_size",
                Diagnostic::bad(format!(
                    "{} is larger than a block; entries are shown at a {}-byte stride \
                     instead",
                    f.entry_size, MAX_ENTRY_SIZE
                )),
            );
        }
        plan.entry_size =
            f.entry_size.clamp(desc::MIN_ENTRY_SIZE as u64, MAX_ENTRY_SIZE as u64) as u32;

        if f.num_entries == 0 {
            diag_on(node, "num_entries", Diagnostic::warn("the table declares no entries"));
        } else if f.num_entries > MAX_ENTRIES as u64 {
            diag_on(
                node,
                "num_entries",
                Diagnostic::bad(format!(
                    "{} entries is past anything a partition table needs; only the \
                     first {MAX_ENTRIES} are shown",
                    f.num_entries
                ))
                .with_hint(
                    "a 32-bit count read from the disk is an allocation request from \
                     an untrusted source, so it is clamped before it is multiplied",
                ),
            );
        }
        plan.count = f.num_entries.min(MAX_ENTRIES as u64) as u32;

        let Some(at) = lba_to_byte(f.entries_lba, self.sector_bytes()) else {
            diag_on(
                node,
                "entries_lba",
                Diagnostic::bad("entries_lba times the sector size overflows 64 bits"),
            );
            return plan;
        };
        if at >= src.len() {
            diag_on(
                node,
                "entries_lba",
                Diagnostic::bad(format!(
                    "the entry array starts at {at:#x}, past the end of the {}-byte \
                     device",
                    src.len()
                )),
            );
        } else {
            plan.at = Some(at);
        }

        let declared = f.num_entries.checked_mul(f.entry_size);
        if let Some(len) = declared.filter(|l| *l > 0) {
            let end_lba = f.entries_lba.saturating_add(len.div_ceil(ss));
            let usable_end = f.last_usable.saturating_add(1);
            if f.first_usable <= f.last_usable
                && f.entries_lba < usable_end
                && f.first_usable < end_lba
            {
                diag_on(
                    node,
                    "entries_lba",
                    Diagnostic::warn(format!(
                        "the entry array occupies LBA {}..{end_lba}, inside the usable \
                         range {}..{}",
                        f.entries_lba, f.first_usable, f.last_usable
                    ))
                    .with_hint(
                        "a partition placed there would overwrite the table that \
                         describes it",
                    ),
                );
            }
        }

        self.verify_entries_crc(node, f, at, declared, &mut plan);
        plan
    }

    fn verify_entries_crc(
        &self,
        node: &mut Node,
        f: &HeaderFacts,
        at: u64,
        declared: Option<u64>,
        plan: &mut ArrayPlan,
    ) {
        let src = &*self.src;
        let d = match declared {
            None => Some(Diagnostic::bad(
                "num_entries times entry_size overflows 64 bits, so entries_crc32 \
                 covers no range that can be checked",
            )),
            Some(0) => Some(Diagnostic::warn(
                "the declared entry array is zero bytes long, so entries_crc32 \
                 cannot be checked against anything",
            )),
            Some(len) if len > MAX_ARRAY_BYTES => Some(
                Diagnostic::warn(format!(
                    "the array claims {len} bytes; this reader will not read more \
                     than {MAX_ARRAY_BYTES} to check a checksum, so entries_crc32 is \
                     unverified"
                ))
                .with_hint("the stored value is shown as-is, not compared"),
            ),
            Some(len) if !in_bounds(src, at, len) => Some(Diagnostic::bad(format!(
                "the array runs from {at:#x} for {len} bytes, past the end of the \
                 {}-byte device; entries_crc32 is unverified",
                src.len()
            ))),
            Some(len) => match read_exact_opt(src, at, len as usize) {
                Some(bytes) if bytes.len() as u64 == len => {
                    let computed = ChecksumAlgo::Crc32.compute(&bytes, &[]);
                    let matches = f.entries_crc32 == computed;
                    set_derived(
                        node,
                        "entries_crc32",
                        Derived {
                            kind: DerivedKind::Checksum,
                            value: Value::Uint(computed),
                            matches,
                            how: format!(
                                "CRC-32 over {} entries x {} bytes = {len} bytes at \
                                 {at:#x}",
                                f.num_entries, f.entry_size
                            ),
                        },
                    );
                    plan.bytes = Some(bytes);
                    (!matches).then(|| {
                        Diagnostic::bad(format!(
                            "stored {:#010X}, computed {computed:#010X}",
                            f.entries_crc32
                        ))
                        .with_hint(
                            "an entry was changed without updating the array \
                             checksum, which is what an editor that does not know \
                             about GPT leaves behind",
                        )
                    })
                }
                _ => Some(Diagnostic {
                    status: Status::Unreadable,
                    message: "the entry array could not be read, so entries_crc32 is \
                              unverified"
                        .into(),
                    hint: Some("the device returned an error; this is not zeroed data".into()),
                }),
            },
        };
        if let Some(d) = d {
            diag_on(node, "entries_crc32", d);
        }
    }

    fn array_node(
        &self,
        label: &'static str,
        plan: &ArrayPlan,
        f: &HeaderFacts,
        device_lbas: u64,
        doc: &'static str,
    ) -> Node {
        let mut n = Node::new(label, NodeKind::Array).with_doc(doc);
        n.value = Value::Composite;
        let Some(at) = plan.at else {
            return n.with_diag(Diagnostic::bad(
                "the entry array's location could not be resolved, so no entries are \
                 shown",
            ));
        };
        let len = (plan.count as u64).saturating_mul(plan.entry_size as u64);
        n.extent = Extent::bytes(at, len);
        n.with_lazy(Arc::new(EntryArray {
            at,
            count: plan.count,
            entry_size: plan.entry_size,
            first_usable: f.first_usable,
            last_usable: f.last_usable,
            device_lbas,
            render: self.render(),
        }))
    }
}

/// Expands the entry array on demand.
///
/// 128 entries of 128 bytes is not expensive, but `num_entries` is not 128 because
/// we checked — it is 128 because the disk said so. The `Expander` seam means the
/// cost of a lie about the count is paid only if somebody opens the node, and the
/// count was clamped before it got here anyway (R-3.5).
#[derive(Debug)]
struct EntryArray {
    at: u64,
    count: u32,
    entry_size: u32,
    first_usable: u64,
    last_usable: u64,
    device_lbas: u64,
    render: RenderCtx,
}

impl Expander for EntryArray {
    fn hint_len(&self) -> Option<usize> {
        Some(self.count as usize)
    }

    fn expand(&self, src: &dyn BlockSource) -> Vec<Node> {
        let mut nodes: Vec<Node> = Vec::with_capacity(self.count as usize);
        let mut facts: Vec<EntryFacts> = Vec::with_capacity(self.count as usize);

        for i in 0..self.count {
            let Some(off) = (i as u64)
                .checked_mul(self.entry_size as u64)
                .and_then(|d| self.at.checked_add(d))
            else {
                break;
            };
            let ctx = ReadCtx::at(off).with_render(self.render);
            let mut n = read_desc_at(src, &desc::GPT_ENTRY, off, ctx);
            let f = EntryFacts::from_node(&n);
            n.label = label_for_entry(i, &f).into();
            n = annotate_entry(n, &f, self);
            if self.entry_size as u64 > desc::ENTRY_DESC_SIZE {
                n = with_vendor_tail(n, src, off, self.entry_size);
            }
            facts.push(f);
            nodes.push(n);
        }

        mark_overlaps(&mut nodes, &facts);
        nodes
    }
}

/// What one entry says, decoded once.
#[derive(Clone, Debug, Default)]
struct EntryFacts {
    type_guid: [u8; 16],
    unique_guid: [u8; 16],
    first_lba: u64,
    last_lba: u64,
    attributes: u64,
    name: String,
    /// Non-zero bytes after the name's terminating NUL: a longer name that was
    /// overwritten by a shorter one, still legible.
    name_tail_dirty: bool,
}

impl EntryFacts {
    fn from_node(n: &Node) -> EntryFacts {
        let u = |name: &str| n.find_child(name).and_then(|c| c.value.as_u64()).unwrap_or(0);
        EntryFacts {
            type_guid: guid_child(n, "type_guid"),
            unique_guid: guid_child(n, "unique_guid"),
            first_lba: u("first_lba"),
            last_lba: u("last_lba"),
            attributes: u("attributes"),
            name: n
                .find_child("name")
                .and_then(|c| c.value.as_str())
                .unwrap_or_default()
                .to_string(),
            name_tail_dirty: n
                .find_child("name")
                .is_some_and(|c| name_tail_is_dirty(&c.raw)),
        }
    }

    fn is_unused(&self) -> bool {
        guids::is_unused(&self.type_guid)
    }

    /// Everything a supposedly-free slot still holds. Empty means genuinely blank.
    fn leftovers(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.unique_guid.iter().any(|&b| b != 0) {
            v.push("the unique GUID");
        }
        if self.first_lba != 0 || self.last_lba != 0 {
            v.push("the LBA range");
        }
        if !self.name.is_empty() {
            v.push("the name");
        }
        if self.attributes != 0 {
            v.push("the attributes");
        }
        v
    }
}

/// True when anything after the name's first NUL code unit is non-zero.
fn name_tail_is_dirty(raw: &[u8]) -> bool {
    let units: Vec<u16> =
        raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
    match units.iter().position(|&u| u == 0) {
        Some(nul) => units[nul + 1..].iter().any(|&u| u != 0),
        None => false,
    }
}

fn label_for_entry(i: u32, f: &EntryFacts) -> String {
    if f.is_unused() {
        return format!("[{i}] --");
    }
    let ty = guids::type_label(&f.type_guid).unwrap_or("unknown type");
    if f.name.is_empty() {
        format!("[{i}] {ty}")
    } else {
        format!("[{i}] {ty} \"{}\"", f.name)
    }
}

/// Everything one entry can be wrong about, or interesting about, on its own.
fn annotate_entry(mut n: Node, f: &EntryFacts, arr: &EntryArray) -> Node {
    if f.is_unused() {
        let left = f.leftovers();
        if !left.is_empty() {
            return n.with_diag(
                Diagnostic::info(format!("slot is unused but {} survive", left.join(", ")))
                    .with_hint(
                        "clearing the type GUID is all most tools do to delete a \
                         partition; the name and unique GUID still say what was here",
                    ),
            );
        }
        return n;
    }

    if f.first_lba > f.last_lba {
        n = n.with_diag(
            Diagnostic::bad(format!(
                "first_lba {} is above last_lba {}, so the partition has no sectors",
                f.first_lba, f.last_lba
            ))
            .with_hint("last_lba is inclusive, not a length and not an exclusive end"),
        );
    }
    if arr.first_usable <= arr.last_usable
        && (f.first_lba < arr.first_usable || f.last_lba > arr.last_usable)
    {
        n = n.with_diag(Diagnostic::warn(format!(
            "LBA {}..{} is outside the usable range {}..{} the header declares",
            f.first_lba, f.last_lba, arr.first_usable, arr.last_usable
        )));
    }
    if arr.device_lbas > 0 && f.last_lba >= arr.device_lbas {
        n = n.with_diag(
            Diagnostic::bad(format!(
                "ends at LBA {} but the device has only {} sectors",
                f.last_lba, arr.device_lbas
            ))
            .with_hint("either the table is from a larger disk or the sector size is wrong"),
        );
    }
    if f.unique_guid.iter().all(|&b| b == 0) {
        n = n.with_diag(Diagnostic::warn(
            "the partition's unique GUID is all zero, so nothing identifies it",
        ));
    }
    if f.name_tail_dirty {
        n = n.with_diag(
            Diagnostic::info("bytes after the end of the name are not zero").with_hint(
                "a longer name overwritten by a shorter one leaves its tail in place",
            ),
        );
    }
    n
}

/// Bytes of an entry past the 128 UEFI defines, when `entry_size` is larger.
fn with_vendor_tail(mut n: Node, src: &dyn BlockSource, off: u64, entry_size: u32) -> Node {
    let tail_at = off.saturating_add(desc::ENTRY_DESC_SIZE);
    let tail_len = entry_size as u64 - desc::ENTRY_DESC_SIZE;
    let raw = read_exact_opt(src, tail_at, tail_len as usize).unwrap_or_default();
    let mut tail = Node {
        label: "vendor tail".into(),
        extent: Extent::bytes(tail_at, tail_len),
        kind: NodeKind::Raw,
        value: Value::Bytes(raw.clone()),
        repr: Repr::Raw,
        flags: FieldFlags::OPAQUE,
        doc: Some(
            "Bytes past the 128 UEFI 5.3.3 defines. Their meaning belongs to the \
             entry's type GUID; nothing here interprets them.",
        ),
        raw,
        ..Default::default()
    };
    if tail.raw.is_empty() {
        tail = tail.with_status(Status::Unreadable);
    }
    n.extent = Extent::bytes(off, entry_size as u64);
    let mut kids = n.children.resolved().map(|c| c.to_vec()).unwrap_or_default();
    kids.push(tail);
    n.with_children(kids)
}

/// Overlap partners named individually on one entry before the rest are counted
/// instead.
///
/// The pair loop is quadratic in the number of live entries, and `num_entries` is
/// clamped to `MAX_ENTRIES` rather than known to be 128. A table whose 4096 slots all
/// claim the same sectors therefore produces ~16.8 million formatted diagnostics —
/// gigabytes of them, from a few megabytes of disk. Clamping the count and then
/// allocating a string per *pair* would just move the allocation request from the
/// disk one level down (R-3.5). Naming the first few partners is the whole finding;
/// the rest is a number.
const MAX_OVERLAP_DIAGS: usize = 8;

/// Flag partitions that claim the same sectors. Two tools writing the same disk
/// without reading each other is exactly how this happens, and the result is silent
/// until one of the filesystems is mounted.
fn mark_overlaps(nodes: &mut [Node], facts: &[EntryFacts]) {
    let live: Vec<usize> = facts
        .iter()
        .enumerate()
        .filter(|(_, f)| !f.is_unused() && f.first_lba <= f.last_lba)
        .map(|(i, _)| i)
        .collect();
    let mut named = vec![0usize; facts.len()];
    let mut unnamed = vec![0usize; facts.len()];
    for (a_pos, &i) in live.iter().enumerate() {
        for &j in &live[a_pos + 1..] {
            let (a, b) = (&facts[i], &facts[j]);
            if a.first_lba <= b.last_lba && b.first_lba <= a.last_lba {
                for (x, y) in [(i, j), (j, i)] {
                    if named[x] >= MAX_OVERLAP_DIAGS {
                        unnamed[x] += 1;
                        continue;
                    }
                    named[x] += 1;
                    let msg = format!(
                        "overlaps entry {y}: {}..{} against {}..{}",
                        facts[x].first_lba, facts[x].last_lba, facts[y].first_lba, facts[y].last_lba
                    );
                    if let Some(slot) = nodes.get_mut(x) {
                        let taken = std::mem::take(slot);
                        *slot = taken.with_diag(Diagnostic::bad(msg));
                    }
                }
            }
        }
    }
    for (x, &more) in unnamed.iter().enumerate() {
        if more == 0 {
            continue;
        }
        if let Some(slot) = nodes.get_mut(x) {
            let taken = std::mem::take(slot);
            *slot = taken.with_diag(
                Diagnostic::bad(format!(
                    "and {more} further entries overlap this one, not listed \
                     individually"
                ))
                .with_hint(
                    "a table where everything overlaps everything is one finding \
                     about the table, not one per pair",
                ),
            );
        }
    }
}

/// Fields whose values are *expected* to differ between the two copies.
///
/// `my_lba` and `alternate_lba` are swapped by design, `entries_lba` names each
/// copy's own array, and `header_crc32` covers all three — so it differs as a
/// consequence, not as a finding. A diff that reports these four reports four false
/// differences on every healthy disk, and a diff nobody trusts is worse than none.
/// The swap itself is checked instead, in `mirror_diags`.
pub const MIRRORED_FIELDS: &[&str] = &["my_lba", "alternate_lba", "entries_lba", "header_crc32"];

/// One field on which the primary and backup headers genuinely disagree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderDiff {
    pub field: &'static str,
    pub primary: String,
    pub backup: String,
}

/// Compare two header nodes field by field, skipping the four that are supposed to
/// differ. Comparison is on raw bytes, so a field that decoded to the same number
/// from different bytes still shows up.
pub fn diff_headers(primary: &Node, backup: &Node) -> Vec<HeaderDiff> {
    let mut out = Vec::new();
    for fd in desc::GPT_HEADER.fields {
        if MIRRORED_FIELDS.contains(&fd.name) {
            continue;
        }
        let a = primary.find_child(fd.name);
        let b = backup.find_child(fd.name);
        let same = match (a, b) {
            (Some(a), Some(b)) => a.raw == b.raw,
            (None, None) => true,
            _ => false,
        };
        if !same {
            out.push(HeaderDiff { field: fd.name, primary: show(a), backup: show(b) });
        }
    }
    out
}

fn show(n: Option<&Node>) -> String {
    match n {
        None => "(absent)".into(),
        Some(n) if n.value.is_unset() => {
            format!("?? ({})", blktamper_core::value::hex_bytes(&n.raw))
        }
        Some(n) => n.value.to_string(),
    }
}

/// The invariants that tie the two copies together, checked rather than assumed.
fn mirror_diags(p: &HeaderFacts, b: &HeaderFacts, ss: u64) -> Vec<Diagnostic> {
    let mut out = Vec::new();
    if !p.present || !b.present {
        return out;
    }
    if b.alternate_lba != p.my_lba {
        out.push(
            Diagnostic::bad(format!(
                "the backup's alternate_lba is {} but the primary lives at LBA {}",
                b.alternate_lba, p.my_lba
            ))
            .with_hint("the two copies were written by different tools, or at different times"),
        );
    }
    if p.alternate_lba != b.my_lba {
        out.push(Diagnostic::bad(format!(
            "the primary's alternate_lba is {} but the backup was found at LBA {}",
            p.alternate_lba, b.my_lba
        )));
    }
    if let Some(len) = b.num_entries.checked_mul(b.entry_size).filter(|l| *l > 0) {
        let end = b.entries_lba.saturating_add(len.div_ceil(ss));
        if end != b.my_lba {
            out.push(Diagnostic::warn(format!(
                "the backup entry array runs to LBA {end} but the backup header is at \
                 LBA {}; the array should end where the header starts",
                b.my_lba
            )));
        }
    }
    out
}

/// The primary-versus-backup view: what differs, what is supposed to differ, and
/// whether the two entry arrays are byte-identical.
fn compare_copies(
    primary: &Node,
    backup: &Node,
    pf: &HeaderFacts,
    bf: &HeaderFacts,
    pplan: &ArrayPlan,
    bplan: &ArrayPlan,
    ss: u64,
) -> Node {
    let mut n = Node::new("primary vs backup", NodeKind::Group).with_doc(
        "Field-by-field comparison of the two headers, and of the two entry arrays. \
         my_lba, alternate_lba, entries_lba and header_crc32 are expected to differ \
         and are checked as a mirrored pair instead of being reported.",
    );

    let diffs = diff_headers(primary, backup);
    let mut kids: Vec<Node> = Vec::new();
    for d in &diffs {
        kids.push(
            Node::new(format!("{} differs", d.field), NodeKind::Group)
                .with_diag(Diagnostic::bad(format!(
                    "primary {} / backup {}",
                    d.primary, d.backup
                )))
                .with_doc(
                    "A field that must be identical in both copies is not. One of the \
                     two was written by something that did not update the other.",
                ),
        );
    }

    for d in mirror_diags(pf, bf, ss) {
        n = n.with_diag(d);
    }

    match (&pplan.bytes, &bplan.bytes) {
        (Some(a), Some(b)) if a == b => {
            n = n.with_diag(Diagnostic::info(
                "the two entry arrays are byte-identical over the range each header \
                 declares",
            ));
        }
        (Some(a), Some(b)) => {
            let differing = a.iter().zip(b.iter()).filter(|(x, y)| x != y).count()
                + a.len().abs_diff(b.len());
            n = n.with_diag(
                Diagnostic::bad(format!(
                    "the two entry arrays differ in {differing} bytes"
                ))
                .with_hint(
                    "one copy describes the disk as it is and the other as it was; \
                     compare the entries before trusting either",
                ),
            );
        }
        _ => {
            n = n.with_diag(Diagnostic::info(
                "one of the entry arrays could not be read in full, so the two were \
                 not compared",
            ));
        }
    }

    if diffs.is_empty() && pf.present && bf.present {
        n = n.with_diag(Diagnostic::info(
            "the two headers agree on every field that must match",
        ));
    } else if !diffs.is_empty() {
        // When the copies disagree, the useful question is which one to believe,
        // and each header's own CRC answers it: a copy that checksums correctly was
        // written deliberately by something that understood GPT.
        n = n.with_diag(match (pf.crc_ok, bf.crc_ok) {
            (true, false) => Diagnostic::info(
                "the primary passes its own CRC and the backup does not, so the \
                 primary is the copy that was written whole",
            ),
            (false, true) => Diagnostic::info(
                "the backup passes its own CRC and the primary does not, so the \
                 backup is the copy that was written whole",
            ),
            (true, true) => Diagnostic::warn(
                "both headers pass their own CRC, so both were written deliberately \
                 — the disagreement is between two tools, not corruption",
            ),
            (false, false) => Diagnostic::warn(
                "neither header passes its own CRC, so neither copy can be trusted \
                 on its own",
            ),
        });
    }
    n.with_children(kids)
}

/// Say plainly which copies exist. A missing primary with an intact backup is a
/// recoverable disk, and that sentence is the most useful thing the tool can print.
fn presence_diags(pf: &HeaderFacts, bf: &HeaderFacts, p_lba: u64, b_lba: u64) -> Vec<Diagnostic> {
    match (pf.present, bf.present) {
        (true, true) => Vec::new(),
        (false, false) => vec![Diagnostic::bad(format!(
            "neither LBA {p_lba} nor LBA {b_lba} carries the EFI PART signature"
        ))
        .with_hint("every field below was read anyway; nothing here has been refused")],
        (false, true) => vec![Diagnostic::bad(format!(
            "the primary header at LBA {p_lba} has no signature, but the backup at LBA \
             {b_lba} is intact"
        ))
        .with_hint("the table can be rebuilt from the backup; read it before writing anything")],
        (true, false) => vec![Diagnostic::warn(format!(
            "the backup header at LBA {b_lba} has no signature; only the primary copy \
             survives"
        ))
        .with_hint(
            "common on an image that was truncated, or a disk that was grown without \
             moving the backup",
        )],
    }
}

/// Whether LBA 0 protects this GPT, contradicts it, or is not there at all.
///
/// UEFI 5.2.3 wants exactly one 0xEE entry starting at LBA 1 and covering the disk.
/// Hybrid layouts that put real entries alongside it exist in the wild and are a
/// finding, not an error: both tables describe the same disk and which one wins
/// depends on who is reading.
fn protective_mbr_diag(src: &dyn BlockSource, at: u64, device_lbas: u64) -> Diagnostic {
    let Some(s) = read_exact_opt(src, at, 512) else {
        return Diagnostic {
            status: Status::Unreadable,
            message: "LBA 0 could not be read, so whether a protective MBR is present \
                      is unknown"
                .into(),
            hint: None,
        };
    };
    if s.len() < 512 {
        return Diagnostic::warn("LBA 0 is shorter than 512 bytes, so there is no MBR there");
    }
    if s[MBR_BOOT_SIG_OFFSET] != 0x55 || s[MBR_BOOT_SIG_OFFSET + 1] != 0xAA {
        return Diagnostic::warn("no protective MBR: LBA 0 has no 55 AA signature").with_hint(
            "legacy tools will read this disk as unpartitioned, and some will offer to \
             initialise it",
        );
    }

    let mut protective = 0usize;
    let mut other = 0usize;
    let mut geometry = (0u64, 0u64);
    for i in 0..4 {
        let o = MBR_ENTRIES_OFFSET + i * MBR_ENTRY_SIZE;
        let Some(e) = s.get(o..o + MBR_ENTRY_SIZE) else { break };
        let ty = e[4];
        let start = u32::from_le_bytes([e[8], e[9], e[10], e[11]]) as u64;
        let count = u32::from_le_bytes([e[12], e[13], e[14], e[15]]) as u64;
        if ty == 0 && start == 0 && count == 0 {
            continue;
        }
        if ty == MBR_TYPE_PROTECTIVE {
            protective += 1;
            geometry = (start, count);
        } else {
            other += 1;
        }
    }

    if protective >= 1 && other >= 1 {
        return Diagnostic::warn(format!(
            "hybrid MBR: a 0xEE entry alongside {other} real MBR entries"
        ))
        .with_hint(
            "the MBR and the GPT describe the same disk differently; which one a tool \
             believes is up to the tool",
        );
    }
    if protective == 0 {
        return Diagnostic::warn(
            "LBA 0 holds an MBR with no 0xEE entry, so this GPT is not protected",
        )
        .with_hint("a tool that reads only the MBR will not see the GPT's partitions");
    }
    if protective > 1 {
        return Diagnostic::warn(format!("{protective} separate 0xEE entries in the MBR"));
    }

    let (start, count) = geometry;
    let expected = device_lbas.saturating_sub(1);
    if start == 1 && (count == expected || count == 0xFFFF_FFFF) {
        Diagnostic::info(format!(
            "protective MBR is well formed: one 0xEE entry covering {count} sectors \
             from LBA 1"
        ))
    } else {
        Diagnostic::warn(format!(
            "the 0xEE entry starts at LBA {start} and covers {count} sectors; a \
             protective MBR should start at LBA 1 and cover {expected}"
        ))
        .with_hint("a disk that was resized, or a table copied from a different disk")
    }
}

/// All the cross-field checks the descriptor names but cannot evaluate: the ones
/// that need to know how big the device actually is.
fn annotate_header(
    node: &mut Node,
    f: &HeaderFacts,
    at_lba: u64,
    last_lba: u64,
    ss: u64,
    is_primary: bool,
) {
    if f.header_size < desc::MIN_HEADER_SIZE as u64 {
        diag_on(
            node,
            "header_size",
            Diagnostic::bad(format!(
                "{} is below the {} bytes UEFI 5.3.2 requires, so header_crc32 covers \
                 less than the header",
                f.header_size,
                desc::MIN_HEADER_SIZE
            ))
            .with_hint("a header this short cannot reach entries_lba or the entry counts"),
        );
    } else if f.header_size > ss {
        diag_on(
            node,
            "header_size",
            Diagnostic::bad(format!(
                "{} is larger than the {ss}-byte block, so header_crc32 could only be \
                 computed over the {ss} bytes that exist",
                f.header_size
            )),
        );
    }

    if !f.present {
        // Nothing below means anything without a signature; the field-level check
        // has already said so and the root diagnostic says what to do about it.
        return;
    }

    if f.my_lba != at_lba {
        diag_on(
            node,
            "my_lba",
            Diagnostic::bad(format!(
                "the header says it lives at LBA {} but was read from LBA {at_lba}",
                f.my_lba
            ))
            .with_hint("a table copied from another disk, or written to the wrong sector"),
        );
    }

    if f.alternate_lba == 0 {
        diag_on(
            node,
            "alternate_lba",
            Diagnostic::warn("alternate_lba is zero: no second copy is claimed"),
        );
    } else if f.alternate_lba == f.my_lba {
        diag_on(
            node,
            "alternate_lba",
            Diagnostic::bad("alternate_lba points at this header itself"),
        );
    } else if f.alternate_lba > last_lba {
        diag_on(
            node,
            "alternate_lba",
            Diagnostic::bad(format!(
                "alternate_lba {} is past the device's last LBA {last_lba}",
                f.alternate_lba
            ))
            .with_hint("the image or device is smaller than the disk this table was written for"),
        );
    } else if is_primary && f.alternate_lba != last_lba {
        diag_on(
            node,
            "alternate_lba",
            Diagnostic::warn(format!(
                "the backup header should be at the device's last LBA {last_lba}, not \
                 {}",
                f.alternate_lba
            )),
        );
    }

    if f.first_usable > f.last_usable {
        diag_on(
            node,
            "first_usable_lba",
            Diagnostic::bad(format!(
                "first_usable_lba {} is above last_usable_lba {}, so no partition can \
                 be placed anywhere",
                f.first_usable, f.last_usable
            )),
        );
    }
    if f.last_usable > last_lba {
        diag_on(
            node,
            "last_usable_lba",
            Diagnostic::bad(format!(
                "last_usable_lba {} is past the device's last LBA {last_lba}",
                f.last_usable
            ))
            .with_hint("a partition ending up there would run off the end of the device"),
        );
    }

    if f.disk_guid.iter().all(|&b| b == 0) {
        diag_on(
            node,
            "disk_guid",
            Diagnostic::warn("the disk GUID is all zero, so the table identifies no disk"),
        );
    }
}

/// Attach a diagnostic to a named child, bubbling severity the way the generic
/// reader does — capped at `Warn`, so a struct is never redder than its worst field
/// makes it look.
fn diag_on(node: &mut Node, field: &str, d: Diagnostic) {
    let status = d.status;
    if let Children::Resolved(kids) = &mut node.children {
        if let Some(slot) = kids.iter_mut().find(|k| k.label == field) {
            let taken = std::mem::take(slot);
            *slot = taken.with_diag(d);
            node.status = node.status.merge(status.min(Status::Warn));
            return;
        }
    }
    node.status = node.status.merge(status);
    node.diags.push(d);
}

/// Attach a computed value to a named child. Used only for `Cover::External`
/// checksums, where the generic reader deliberately leaves the comparison undone.
fn set_derived(node: &mut Node, field: &str, d: Derived) {
    if let Children::Resolved(kids) = &mut node.children {
        if let Some(slot) = kids.iter_mut().find(|k| k.label == field) {
            slot.derived = Some(d);
        }
    }
}

fn span_of(plan: &ArrayPlan) -> (u64, u64) {
    match plan.at {
        Some(at) => (at, (plan.count as u64).saturating_mul(plan.entry_size as u64)),
        None => (0, 0),
    }
}

/// The region's provenance: the four areas a GPT actually occupies, not the whole
/// device it describes.
fn region_extent(parts: &[(u64, u64)]) -> Extent {
    let spans: Vec<Span> = parts
        .iter()
        .filter(|(_, len)| *len > 0)
        .map(|&(at, len)| Span::bytes(at, len))
        .collect();
    match spans.len() {
        0 => Extent::None,
        1 => Extent::One(spans[0]),
        _ => Extent::Many(spans),
    }
}

/// A synthetic GPT, used by the tests in this module and by the fuzz targets.
///
/// Builds a consistent table — both CRCs correct — so that tests can corrupt one
/// thing at a time and see exactly that one thing reported.
#[doc(hidden)]
pub fn synth_gpt(device_lbas: u64, entries: &[([u8; 16], u64, u64, &str)]) -> Vec<u8> {
    let ss = 512usize;
    let num_entries = 128u32;
    let entry_size = 128u32;
    let array_lbas = (num_entries as u64 * entry_size as u64).div_ceil(ss as u64);
    // Stated rather than discovered as a subtract-with-overflow inside the header
    // builder: a fuzz target that passes a length through to here has to be told
    // what it got wrong, and this is a generator, not a parser — refusing is right.
    assert!(
        device_lbas > 2 * array_lbas + 2,
        "synth_gpt needs at least {} sectors for two headers and two entry arrays, got {device_lbas}",
        2 * array_lbas + 3
    );
    let mut data = vec![0u8; device_lbas as usize * ss];

    let mut array = vec![0u8; num_entries as usize * entry_size as usize];
    for (i, (ty, first, last, name)) in entries.iter().take(num_entries as usize).enumerate() {
        let o = i * entry_size as usize;
        array[o..o + 16].copy_from_slice(ty);
        array[o + 16..o + 32].copy_from_slice(&[(i as u8) + 1; 16]);
        array[o + 32..o + 40].copy_from_slice(&first.to_le_bytes());
        array[o + 40..o + 48].copy_from_slice(&last.to_le_bytes());
        for (j, u) in name.encode_utf16().take(36).enumerate() {
            array[o + 56 + j * 2..o + 58 + j * 2].copy_from_slice(&u.to_le_bytes());
        }
    }
    let array_crc = ChecksumAlgo::Crc32.compute(&array, &[]) as u32;

    let last_lba = device_lbas - 1;
    let backup_array_lba = last_lba - array_lbas;
    let header = |my: u64, alt: u64, entries_lba: u64| -> Vec<u8> {
        let mut h = vec![0u8; 92];
        h[0..8].copy_from_slice(desc::SIGNATURE);
        h[8..12].copy_from_slice(&desc::REVISION_1_0.to_le_bytes());
        h[12..16].copy_from_slice(&92u32.to_le_bytes());
        h[24..32].copy_from_slice(&my.to_le_bytes());
        h[32..40].copy_from_slice(&alt.to_le_bytes());
        h[40..48].copy_from_slice(&(2 + array_lbas).to_le_bytes());
        h[48..56].copy_from_slice(&(backup_array_lba - 1).to_le_bytes());
        h[56..72].copy_from_slice(&[0x5A; 16]);
        h[72..80].copy_from_slice(&entries_lba.to_le_bytes());
        h[80..84].copy_from_slice(&num_entries.to_le_bytes());
        h[84..88].copy_from_slice(&entry_size.to_le_bytes());
        h[88..92].copy_from_slice(&array_crc.to_le_bytes());
        let crc = ChecksumAlgo::Crc32.compute(&h, &[(16, 4)]) as u32;
        h[16..20].copy_from_slice(&crc.to_le_bytes());
        h
    };

    // Protective MBR.
    data[MBR_ENTRIES_OFFSET + 4] = MBR_TYPE_PROTECTIVE;
    data[MBR_ENTRIES_OFFSET + 8..MBR_ENTRIES_OFFSET + 12].copy_from_slice(&1u32.to_le_bytes());
    let cover = u32::try_from(last_lba).unwrap_or(0xFFFF_FFFF);
    data[MBR_ENTRIES_OFFSET + 12..MBR_ENTRIES_OFFSET + 16].copy_from_slice(&cover.to_le_bytes());
    data[MBR_BOOT_SIG_OFFSET] = 0x55;
    data[MBR_BOOT_SIG_OFFSET + 1] = 0xAA;

    let p = header(1, last_lba, 2);
    data[ss..ss + 92].copy_from_slice(&p);
    let b = header(last_lba, 1, backup_array_lba);
    let boff = last_lba as usize * ss;
    data[boff..boff + 92].copy_from_slice(&b);
    data[2 * ss..2 * ss + array.len()].copy_from_slice(&array);
    let baoff = backup_array_lba as usize * ss;
    data[baoff..baoff + array.len()].copy_from_slice(&array);
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use blktamper_core::{MemSource, Status};

    const DEVICE_LBAS: u64 = 2048;

    fn good() -> Vec<u8> {
        synth_gpt(
            DEVICE_LBAS,
            &[
                (guids::EFI_SYSTEM, 40, 1023, "ESP"),
                (guids::LINUX_FILESYSTEM, 1024, 2000, "root"),
            ],
        )
    }

    fn src_of(data: Vec<u8>) -> Arc<dyn BlockSource> {
        Arc::new(MemSource::new(data))
    }

    fn entries_of(root: &Node, src: &dyn BlockSource, label: &str) -> Vec<Node> {
        let arr = root.find_child(label).expect("entry array node");
        match &arr.children {
            Children::Lazy(e) => e.expand(src),
            Children::Resolved(v) => v.clone(),
            // An array whose location could not be resolved is a legitimate outcome
            // on a hostile image — but it has to say why rather than show nothing.
            Children::None => {
                assert!(!arr.diags.is_empty(), "an array with no children must explain itself");
                Vec::new()
            }
        }
    }

    #[test]
    fn a_consistent_table_scores_high_and_reports_clean() {
        let src = src_of(good());
        assert_eq!(GptProbe.probe(&*src, 0), 100);
        let root = GptProbe.open(src.clone(), 0).root();
        let primary = root.find_child("primary header").unwrap();
        assert_eq!(primary.deep_status(), Status::Ok, "{:?}", primary.diags);
        assert!(primary.find_child("header_crc32").unwrap().derived.as_ref().unwrap().matches);
        assert!(primary.find_child("entries_crc32").unwrap().derived.as_ref().unwrap().matches);
        assert!(diff_headers(primary, root.find_child("backup header").unwrap()).is_empty());
    }

    #[test]
    fn the_entry_array_is_lazy_and_still_lists_every_slot() {
        let src = src_of(good());
        let root = GptProbe.open(src.clone(), 0).root();
        let arr = root.find_child("partition entries").unwrap();
        assert_eq!(arr.children.len_hint(), Some(128));
        let kids = entries_of(&root, &*src, "partition entries");
        assert_eq!(kids.len(), 128, "every slot gets a node, used or not");
        assert!(kids[0].label.contains("EFI System"));
        assert_eq!(kids[2].label, "[2] --");
    }

    #[test]
    fn a_corrupt_header_crc_is_shown_and_nothing_is_refused() {
        let mut data = good();
        data[512 + 16] ^= 0xFF;
        let src = src_of(data);
        // Still obviously a GPT: the CRC is deliberately not part of the score.
        assert_eq!(GptProbe.probe(&*src, 0), 100);
        let root = GptProbe.open(src.clone(), 0).root();
        let crc = root.find_child("primary header").unwrap().find_child("header_crc32").unwrap();
        assert!(!crc.derived.as_ref().unwrap().matches);
        assert_eq!(crc.status, Status::Bad);
        // and every other field is still there with its value
        assert_eq!(
            root.find_child("primary header").unwrap().find_child("num_entries").unwrap().value,
            Value::Uint(128)
        );
    }

    #[test]
    fn a_cleared_type_guid_over_an_intact_name_is_surfaced() {
        // The sanitize question: the slot reads as free, the evidence is still there.
        let mut data = good();
        let e0 = 2 * 512;
        data[e0..e0 + 16].fill(0);
        let src = src_of(data);
        let root = GptProbe.open(src.clone(), 0).root();
        let kids = entries_of(&root, &*src, "partition entries");
        assert_eq!(kids[0].label, "[0] --");
        assert!(
            kids[0].diags.iter().any(|d| d.message.contains("unused but")),
            "{:?}",
            kids[0].diags
        );
        assert!(kids[0].diags[0].message.contains("the name"));
    }

    #[test]
    fn an_absurd_entry_count_is_clamped_rather_than_allocated() {
        let mut data = good();
        data[512 + 0x50..512 + 0x54].copy_from_slice(&u32::MAX.to_le_bytes());
        let src = src_of(data);
        let root = GptProbe.open(src.clone(), 0).root();
        let n = root.find_child("primary header").unwrap().find_child("num_entries").unwrap();
        assert_eq!(n.status, Status::Bad);
        assert!(n.diags.iter().any(|d| d.message.contains("only the first")));
        let arr = root.find_child("partition entries").unwrap();
        assert_eq!(arr.children.len_hint(), Some(MAX_ENTRIES as usize));
    }

    #[test]
    fn an_overflowing_entry_geometry_reports_instead_of_multiplying() {
        let mut data = good();
        data[512 + 0x50..512 + 0x54].copy_from_slice(&u32::MAX.to_le_bytes());
        data[512 + 0x54..512 + 0x58].copy_from_slice(&u32::MAX.to_le_bytes());
        let src = src_of(data);
        let root = GptProbe.open(src, 0).root();
        let h = root.find_child("primary header").unwrap();
        assert!(h.find_child("entries_crc32").unwrap().derived.is_none());
        assert!(h
            .find_child("entries_crc32")
            .unwrap()
            .diags
            .iter()
            .any(|d| d.message.contains("unverified") || d.message.contains("overflow")));
    }

    #[test]
    fn a_swapped_backup_that_does_not_point_back_is_a_finding() {
        let mut data = good();
        let boff = (DEVICE_LBAS as usize - 1) * 512;
        data[boff + 0x20..boff + 0x28].copy_from_slice(&999u64.to_le_bytes());
        let src = src_of(data);
        let root = GptProbe.open(src, 0).root();
        let cmp = root.find_child("primary vs backup").unwrap();
        assert!(
            cmp.diags.iter().any(|d| d.message.contains("does not") || d.message.contains("but the primary lives")),
            "{:?}",
            cmp.diags
        );
    }

    #[test]
    fn a_disk_guid_that_differs_between_the_copies_is_a_real_difference() {
        let mut data = good();
        let boff = (DEVICE_LBAS as usize - 1) * 512;
        data[boff + 0x38] ^= 0xFF;
        let src = src_of(data);
        let root = GptProbe.open(src, 0).root();
        let d = diff_headers(
            root.find_child("primary header").unwrap(),
            root.find_child("backup header").unwrap(),
        );
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].field, "disk_guid");

        // Editing the backup also broke its own CRC, which is what says which copy
        // to believe — the whole point of reporting the difference at all.
        let cmp = root.find_child("primary vs backup").unwrap();
        assert!(
            cmp.diags.iter().any(|x| x.message.contains("the primary passes its own CRC")),
            "{:?}",
            cmp.diags
        );
    }

    #[test]
    fn overlapping_partitions_are_flagged_on_both() {
        let src = src_of(synth_gpt(
            DEVICE_LBAS,
            &[
                (guids::LINUX_FILESYSTEM, 40, 1023, "a"),
                (guids::LINUX_FILESYSTEM, 1000, 2000, "b"),
            ],
        ));
        let root = GptProbe.open(src.clone(), 0).root();
        let kids = entries_of(&root, &*src, "partition entries");
        assert!(kids[0].diags.iter().any(|d| d.message.contains("overlaps entry 1")));
        assert!(kids[1].diags.iter().any(|d| d.message.contains("overlaps entry 0")));
    }

    #[test]
    fn a_missing_protective_mbr_is_noted() {
        let mut data = good();
        data[MBR_BOOT_SIG_OFFSET] = 0;
        let src = src_of(data);
        let root = GptProbe.open(src, 0).root();
        assert!(root.diags.iter().any(|d| d.message.contains("no protective MBR")));
    }

    #[test]
    fn a_hybrid_mbr_is_a_finding_not_an_error() {
        let mut data = good();
        let o = MBR_ENTRIES_OFFSET + MBR_ENTRY_SIZE;
        data[o + 4] = 0x83;
        data[o + 8..o + 12].copy_from_slice(&2048u32.to_le_bytes());
        data[o + 12..o + 16].copy_from_slice(&1024u32.to_le_bytes());
        let src = src_of(data);
        let root = GptProbe.open(src, 0).root();
        assert!(root.diags.iter().any(|d| d.message.contains("hybrid MBR")));
    }

    #[test]
    fn a_wiped_primary_with_an_intact_backup_says_so() {
        let mut data = good();
        data[512..1024].fill(0);
        let src = src_of(data);
        assert_eq!(GptProbe.probe(&*src, 0), 0, "no signature, no claim");
        let root = GptProbe.open(src, 0).root();
        assert!(
            root.diags.iter().any(|d| d.message.contains("backup at LBA")),
            "{:?}",
            root.diags
        );
    }

    #[test]
    fn a_reserved_attribute_bit_is_a_warning() {
        let mut data = good();
        let attrs = 2 * 512 + 0x30;
        data[attrs + 1] = 0x01; // bit 8, inside the reserved run
        let src = src_of(data);
        let root = GptProbe.open(src.clone(), 0).root();
        let kids = entries_of(&root, &*src, "partition entries");
        let a = kids[0].find_child("attributes").unwrap();
        assert_eq!(a.status, Status::Warn);
        let bit = a.children.resolved().unwrap().iter().find(|b| b.label.starts_with("8.")).unwrap();
        assert_eq!(bit.value, Value::Bool(true));
    }

    #[test]
    fn the_header_block_tail_is_shown_and_checked() {
        let mut data = good();
        data[512 + 200] = 0x41;
        let src = src_of(data);
        let root = GptProbe.open(src, 0).root();
        let pad = root.find_child("primary header").unwrap().find_child("block padding").unwrap();
        assert_eq!(pad.raw.len(), 512 - 92);
        assert!(pad.diags.iter().any(|d| d.message.contains("not zero")));
    }

    #[test]
    fn garbage_and_zeros_never_panic_and_never_claim_a_gpt() {
        for seed in [0u8, 1, 0x55, 0xAA, 0xEF, 0xFF] {
            let src = src_of(vec![seed; 64 * 1024]);
            assert_eq!(GptProbe.probe(&*src, 0), 0);
            let root = GptProbe.open(src.clone(), 0).root();
            assert!(root.find_child("primary header").is_some());
            let _ = entries_of(&root, &*src, "partition entries");
        }
    }

    #[test]
    fn a_truncated_image_produces_unreadable_not_zeros() {
        let mut data = good();
        data.truncate(3 * 512);
        let src = src_of(data);
        let root = GptProbe.open(src, 0).root();
        // The backup lives past the end now; it must not read as a header of zeros.
        let b = root.find_child("backup header").unwrap();
        assert!(b.deep_status().is_anomaly());
        assert_ne!(
            b.find_child("signature").map(|n| n.value.clone()),
            Some(Value::Text("EFI PART".into()))
        );
    }

    #[test]
    fn a_tampered_entry_turns_the_array_crc_red() {
        // The other half of "two checksums of different shapes": entries_crc32 is
        // computed here rather than by the generic reader, so its mismatch path is
        // ours to get right and has to be exercised on its own.
        let mut data = good();
        data[2 * 512 + 0x38] ^= 0x20; // one letter of entry 0's name
        let src = src_of(data);
        let root = GptProbe.open(src, 0).root();
        let ec = root.find_child("primary header").unwrap().find_child("entries_crc32").unwrap();
        assert_eq!(ec.status, Status::Bad);
        assert!(!ec.derived.as_ref().unwrap().matches);
        assert!(ec.diags.iter().any(|d| d.message.contains("stored") && d.message.contains("computed")));
        // The backup array is untouched, so the two copies must now disagree.
        let cmp = root.find_child("primary vs backup").unwrap();
        assert!(cmp.diags.iter().any(|d| d.message.contains("entry arrays differ")), "{:?}", cmp.diags);
    }

    #[test]
    fn a_table_where_everything_overlaps_is_one_finding_per_entry_not_thousands() {
        // MAX_ENTRIES slots all claiming the same sectors is O(n^2) pairs. Naming
        // every pair means ~16.8 million formatted diagnostics — gigabytes of them
        // out of a few megabytes of disk, which is the clamped `num_entries`
        // allocation request reappearing one level down (R-3.5).
        let n = MAX_ENTRIES;
        let ss = 512usize;
        let mut data = vec![0u8; 8 * 1024 * 1024];
        data[ss..ss + 8].copy_from_slice(desc::SIGNATURE);
        data[ss + 0x0C..ss + 0x10].copy_from_slice(&92u32.to_le_bytes());
        data[ss + 0x18..ss + 0x20].copy_from_slice(&1u64.to_le_bytes());
        data[ss + 0x48..ss + 0x50].copy_from_slice(&2u64.to_le_bytes());
        data[ss + 0x50..ss + 0x54].copy_from_slice(&n.to_le_bytes());
        data[ss + 0x54..ss + 0x58].copy_from_slice(&128u32.to_le_bytes());
        for i in 0..n as usize {
            let o = 2 * ss + i * 128;
            data[o..o + 16].copy_from_slice(&guids::LINUX_FILESYSTEM);
            data[o + 32..o + 40].copy_from_slice(&100u64.to_le_bytes());
            data[o + 40..o + 48].copy_from_slice(&200u64.to_le_bytes());
        }
        let src = src_of(data);
        let root = GptProbe.open(src.clone(), 0).root();
        let kids = entries_of(&root, &*src, "partition entries");
        assert_eq!(kids.len(), n as usize);
        // Every entry still says it overlaps, and says how many it did not name.
        let named = kids[0].diags.iter().filter(|d| d.message.starts_with("overlaps entry")).count();
        assert_eq!(named, MAX_OVERLAP_DIAGS, "{:?}", kids[0].diags);
        assert!(kids[0].diags.iter().any(|d| d.message.contains("overlaps entry 1")));
        assert!(
            kids[0].diags.iter().any(|d| d.message.contains("further entries overlap")),
            "{:?}",
            kids[0].diags
        );
        assert_eq!(kids[0].deep_status(), Status::Bad);
    }

    #[test]
    fn a_region_near_the_top_of_the_address_space_does_not_panic() {
        // A base offset comes from whatever opened this region — a link resolved
        // from an on-disk LBA, in the end. Byte offsets above u64::MAX / 8 cannot be
        // expressed in the bit-granular spans the tree uses, and that has to
        // degrade, not abort (R-3.5: parsing never fails).
        for base in [1u64 << 61, (1u64 << 61) + 512, u64::MAX - 4096, u64::MAX] {
            let src = src_of(vec![0u8; 64 * 1024]);
            let _ = GptProbe.probe(&*src, base);
            let root = GptProbe.open(src.clone(), base).root();
            assert!(root.find_child("primary header").is_some());
            let _ = entries_of(&root, &*src, "partition entries");
        }
    }

    #[test]
    fn a_device_that_claims_an_exabyte_does_not_panic() {
        // The backup header sits at the last LBA, so a source that overstates its
        // length puts `read_header` past 2^61 bytes without any hostile field.
        #[derive(Debug)]
        struct Huge(u64);
        impl BlockSource for Huge {
            fn len(&self) -> u64 {
                self.0
            }
            fn read_at(&self, _o: u64, b: &mut [u8]) -> blktamper_core::ReadOutcome {
                b.fill(0);
                blktamper_core::ReadOutcome::Ok
            }
        }
        for len in [1u64 << 62, u64::MAX] {
            let src: Arc<dyn BlockSource> = Arc::new(Huge(len));
            let _ = GptProbe.probe(&*src, 0);
            let root = GptProbe.open(src.clone(), 0).root();
            assert!(root.find_child("backup header").is_some());
        }
    }

    #[test]
    fn every_field_of_every_entry_survives_hostile_bytes() {
        // Not a fuzz target, just the cheapest version of one: whatever the bytes
        // are, the tree has the same shape.
        for seed in 0u8..=255 {
            let mut data = good();
            data[2 * 512..3 * 512].fill(seed);
            let src = src_of(data);
            let root = GptProbe.open(src.clone(), 0).root();
            let kids = entries_of(&root, &*src, "partition entries");
            assert_eq!(kids.len(), 128);
            for k in kids.iter().take(4) {
                assert!(k.find_child("type_guid").is_some());
                assert!(k.find_child("name").is_some());
            }
        }
    }
}
