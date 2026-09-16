//! MBR and the extended boot record chain.
//!
//! This module is the reference implementation for every other format here: a
//! `FormatProbe` that scores rather than decides, a `RegionReader` that always
//! produces a full tree, descriptors in `desc.rs` (Tier A) and traversal in this
//! file (Tier B). See ADR-002.

pub mod desc;
pub mod types;

use crate::common::{lba_to_byte, read_desc_at, ChainGuard, Step};
use blktamper_core::{
    BlockSource, Diagnostic, FormatId, FormatProbe, Link, LinkKind, Node, NodeKind, ReadCtx,
    RegionReader, Registry, RenderCtx, Repr, Score, Status, Value,
};
use std::sync::Arc;

pub const ID: FormatId = FormatId("mbr");

/// Extended chains are short in practice. Anything past this is corruption, and a
/// UI thread must not follow it forever.
const MAX_LOGICAL_PARTITIONS: usize = 128;

pub fn register(reg: &mut Registry) {
    reg.register(Arc::new(MbrProbe));
}

#[derive(Debug)]
pub struct MbrProbe;

impl FormatProbe for MbrProbe {
    fn id(&self) -> FormatId {
        ID
    }

    fn name(&self) -> &'static str {
        "MBR partition table"
    }

    fn probe(&self, src: &dyn BlockSource, at: u64) -> Score {
        let (sector, outcome) = src.read_vec(at, 512);
        if sector.len() < 512 || outcome == blktamper_core::ReadOutcome::Unreadable {
            return 0;
        }
        if sector[0x1FE] != 0x55 || sector[0x1FF] != 0xAA {
            return 0;
        }

        // 55 AA alone is weak: it is also on every FAT and NTFS boot sector. What
        // distinguishes an MBR is four entries that look like partition entries.
        let mut score: u32 = 35;
        let ss = src.logical_sector_size() as u64;
        let device_sectors = src.len() / ss.max(1);
        let mut plausible = 0;
        let mut populated = 0;
        for i in 0..desc::ENTRY_COUNT {
            let o = desc::ENTRIES_OFFSET as usize + i * desc::ENTRY_SIZE as usize;
            let e = &sector[o..o + 16];
            let status = e[0];
            let ty = e[4];
            let start = u32::from_le_bytes([e[8], e[9], e[10], e[11]]) as u64;
            let count = u32::from_le_bytes([e[12], e[13], e[14], e[15]]) as u64;
            if ty == 0 && start == 0 && count == 0 {
                plausible += 1; // a properly empty slot is evidence too
                continue;
            }
            populated += 1;
            let status_ok = status == 0x00 || status == 0x80;
            let fits = count > 0 && start.saturating_add(count) <= device_sectors.max(1);
            if status_ok && fits {
                plausible += 1;
            }
        }
        if plausible == desc::ENTRY_COUNT {
            score += 45;
        } else {
            score += 10 * plausible as u32;
        }
        if populated == 0 {
            // 55 AA with four empty slots: could be an MBR, could be a wiped boot
            // sector. Say so quietly rather than confidently.
            score = score.min(40);
        }
        // A FAT/exFAT boot sector starts with a jump instruction; an MBR normally
        // does not, and this is the cheapest way to tell them apart.
        if sector[0] == 0xEB || sector[0] == 0xE9 {
            score = score.saturating_sub(25);
        }
        score.min(100) as Score
    }

    fn open(&self, src: Arc<dyn BlockSource>, at: u64) -> Box<dyn RegionReader> {
        Box::new(MbrReader { src, base: at })
    }
}

#[derive(Debug)]
pub struct MbrReader {
    src: Arc<dyn BlockSource>,
    base: u64,
}

impl MbrReader {
    pub fn new(src: Arc<dyn BlockSource>, base: u64) -> MbrReader {
        MbrReader { src, base }
    }

    fn ctx(&self) -> ReadCtx {
        ReadCtx::at(self.base).with_render(RenderCtx {
            sector_size: self.src.logical_sector_size(),
            cluster_base: None,
            device_len: self.src.len(),
        })
    }

    /// True when this looks like the decoy MBR a GPT disk carries.
    fn protective_info(entries: &[EntryFacts]) -> Option<String> {
        let used: Vec<&EntryFacts> = entries.iter().filter(|e| !e.is_empty()).collect();
        let protective = used.len() == 1 && used[0].part_type == types::TYPE_GPT_PROTECTIVE;
        if !protective {
            return None;
        }
        Some(format!(
            "protective MBR: one 0xEE entry covering {} sectors from LBA {}. The real \
             partition table is the GPT at LBA 1.",
            used[0].num_sectors, used[0].lba_first
        ))
    }
}

/// The handful of numbers from an entry that traversal and checks need.
#[derive(Clone, Copy, Debug, Default)]
struct EntryFacts {
    status: u64,
    part_type: u64,
    lba_first: u64,
    num_sectors: u64,
}

impl EntryFacts {
    fn from_node(n: &Node) -> EntryFacts {
        let g = |name: &str| n.find_child(name).and_then(|c| c.value.as_u64()).unwrap_or(0);
        EntryFacts {
            status: g("status"),
            part_type: g("part_type"),
            lba_first: g("lba_first"),
            num_sectors: g("num_sectors"),
        }
    }
    fn is_empty(&self) -> bool {
        self.part_type == 0 && self.lba_first == 0 && self.num_sectors == 0
    }
    fn end_lba(&self) -> Option<u64> {
        self.lba_first.checked_add(self.num_sectors)
    }
}

impl RegionReader for MbrReader {
    fn id(&self) -> FormatId {
        ID
    }

    fn base(&self) -> u64 {
        self.base
    }

    fn root(&self) -> Node {
        let src = &*self.src;
        let ss = src.logical_sector_size() as u64;
        let device_sectors = src.len() / ss.max(1);
        let ctx = self.ctx();

        let mut root = read_desc_at(src, &desc::MBR_HEADER, self.base, ctx);
        root.kind = NodeKind::Region;
        root.label = "MBR".into();

        // Parse the four entries and hang them off the placeholder field, so the
        // descriptor still tiles sector 0 exactly and no bogus gap appears.
        let mut facts = Vec::with_capacity(desc::ENTRY_COUNT);
        let mut entry_nodes = Vec::with_capacity(desc::ENTRY_COUNT);
        for i in 0..desc::ENTRY_COUNT {
            let at = self.base + desc::ENTRIES_OFFSET + i as u64 * desc::ENTRY_SIZE;
            let mut n = read_desc_at(src, &desc::PART_ENTRY, at, ctx);
            let fx = EntryFacts::from_node(&n);
            facts.push(fx);
            n.label = label_for_entry(i, &fx).into();
            n = annotate_entry(n, &fx, device_sectors, ss);
            entry_nodes.push(n);
        }

        // Cross-entry checks: overlap is the finding that matters most, because it
        // is how two tools end up writing over each other.
        let overlaps = find_overlaps(&facts);
        for (i, j) in &overlaps {
            let msg = format!(
                "overlaps partition {}: {}..{} vs {}..{}",
                j,
                facts[*i].lba_first,
                facts[*i].end_lba().unwrap_or(u64::MAX),
                facts[*j].lba_first,
                facts[*j].end_lba().unwrap_or(u64::MAX)
            );
            entry_nodes[*i] = std::mem::take(&mut entry_nodes[*i]).with_diag(Diagnostic::bad(msg));
        }

        // Extended partitions: follow the EBR chain.
        for (i, fx) in facts.iter().enumerate() {
            if types::is_extended(fx.part_type) && fx.num_sectors > 0 {
                let logicals = self.walk_ebr_chain(*fx, ss);
                if !logicals.is_empty() {
                    let n = std::mem::take(&mut entry_nodes[i]);
                    let existing = n.children.resolved().map(|c| c.to_vec()).unwrap_or_default();
                    let mut kids = existing;
                    kids.push(
                        Node::new("logical partitions", NodeKind::Array)
                            .with_children(logicals)
                            .with_doc(
                                "Logical partitions found by following the extended \
                                 boot record chain.",
                            ),
                    );
                    entry_nodes[i] = n.with_children(kids);
                }
            }
        }

        if let Some(msg) = MbrReader::protective_info(&facts) {
            root = root.with_diag(
                Diagnostic::info(msg)
                    .with_hint("open the GPT at LBA 1 to see the real partition table"),
            );
        }

        // Attach the entries to the placeholder field.
        let mut kids = root.children.resolved().map(|c| c.to_vec()).unwrap_or_default();
        if let Some(slot) = kids.iter_mut().find(|k| k.label == "entries") {
            slot.kind = NodeKind::Array;
            slot.value = Value::Composite;
            slot.repr = Repr::Raw;
            let deep = entry_nodes.iter().fold(Status::Ok, |a, n| a.merge(n.deep_status()));
            slot.status = slot.status.merge(deep);
            slot.children = blktamper_core::Children::Resolved(entry_nodes);
        }
        root.with_children(kids)
    }
}

impl MbrReader {
    /// Walk the extended boot record chain.
    ///
    /// The trap: entry 0 of each EBR describes a logical partition at an offset
    /// *relative to that EBR*, while entry 1 points at the next EBR at an offset
    /// *relative to the start of the extended partition*. Two different bases, and
    /// mixing them up is the classic way to misread an extended layout.
    fn walk_ebr_chain(&self, ext: EntryFacts, ss: u64) -> Vec<Node> {
        let src = &*self.src;
        let mut out = Vec::new();
        let mut guard = ChainGuard::new(MAX_LOGICAL_PARTITIONS);
        let ext_start = ext.lba_first;
        let mut ebr_lba = ext_start;
        let mut index = 0usize;

        loop {
            match guard.visit(ebr_lba) {
                Step::Continue => {}
                Step::Loop => {
                    out.push(
                        Node::new("chain loops", NodeKind::Group).with_diag(
                            Diagnostic::bad(format!(
                                "EBR at LBA {ebr_lba} has already been visited; the chain \
                                 is circular and traversal stopped here"
                            )),
                        ),
                    );
                    break;
                }
                Step::TooLong => {
                    out.push(Node::new("chain too long", NodeKind::Group).with_diag(
                        Diagnostic::bad(format!(
                            "stopped after {MAX_LOGICAL_PARTITIONS} extended boot records"
                        )),
                    ));
                    break;
                }
            }

            let Some(ebr_at) = lba_to_byte(ebr_lba, ss as u32) else { break };
            if ebr_at >= src.len() {
                out.push(Node::new(format!("EBR @LBA {ebr_lba}"), NodeKind::Struct).with_diag(
                    Diagnostic::bad("extended boot record lies past the end of the device"),
                ));
                break;
            }

            let ctx = ReadCtx::at(ebr_at)
                .with_region_base(ext_start.saturating_mul(ss))
                .with_render(RenderCtx {
                    sector_size: ss as u32,
                    cluster_base: None,
                    device_len: src.len(),
                });

            let mut ebr = read_desc_at(src, &desc::EBR_HEADER, ebr_at, ctx);
            ebr.label = format!("EBR @LBA {ebr_lba}").into();
            ebr.kind = NodeKind::Struct;

            // Entry 0: the logical partition, relative to this EBR.
            let e0_at = ebr_at + desc::ENTRIES_OFFSET;
            let mut e0 = read_desc_at(src, &desc::PART_ENTRY, e0_at, ctx);
            let f0 = EntryFacts::from_node(&e0);
            let abs = ebr_lba.checked_add(f0.lba_first);
            e0.label = format!("logical {} ({})", index + 1, type_label(f0.part_type)).into();
            e0 = e0.with_doc(
                "Entry 0 of an EBR: the logical partition, at an offset relative to \
                 this EBR's own sector.",
            );
            if let Some(abs) = abs.filter(|_| !f0.is_empty()) {
                let resolved = lba_to_byte(abs, ss as u32);
                e0 = e0
                    .with_link(Link {
                        label: "volume header".into(),
                        kind: LinkKind::ToLba,
                        raw: abs,
                        resolved,
                    })
                    .with_diag(Diagnostic::info(format!(
                        "relative LBA {} from EBR at LBA {} = absolute LBA {}",
                        f0.lba_first, ebr_lba, abs
                    )));
            }

            // Entry 1: the next EBR, relative to the extended partition's start.
            let e1_at = e0_at + desc::ENTRY_SIZE;
            let mut e1 = read_desc_at(src, &desc::PART_ENTRY, e1_at, ctx);
            let f1 = EntryFacts::from_node(&e1);
            e1.label = "next EBR".into();
            e1 = e1.with_doc(
                "Entry 1 of an EBR: a pointer to the next extended boot record, at an \
                 offset relative to the start of the extended partition — not to this \
                 EBR. Zero terminates the chain.",
            );

            ebr = {
                let mut kids = ebr.children.resolved().map(|c| c.to_vec()).unwrap_or_default();
                if let Some(slot) = kids.iter_mut().find(|k| k.label == "entries") {
                    slot.kind = NodeKind::Array;
                    slot.value = Value::Composite;
                    let mut e2 = read_desc_at(src, &desc::PART_ENTRY, e1_at + desc::ENTRY_SIZE, ctx);
                    e2.label = "unused [2]".into();
                    let mut e3 =
                        read_desc_at(src, &desc::PART_ENTRY, e1_at + 2 * desc::ENTRY_SIZE, ctx);
                    e3.label = "unused [3]".into();
                    for n in [&mut e2, &mut e3] {
                        if !n.raw.iter().all(|&b| b == 0) {
                            let taken = std::mem::take(n);
                            *n = taken.with_diag(Diagnostic::warn(
                                "an EBR must leave entries 2 and 3 zero",
                            ));
                        }
                    }
                    let entries = vec![e0, e1, e2, e3];
                    let deep = entries.iter().fold(Status::Ok, |a, n| a.merge(n.deep_status()));
                    slot.status = slot.status.merge(deep);
                    slot.children = blktamper_core::Children::Resolved(entries);
                }
                ebr.with_children(kids)
            };
            out.push(ebr);

            index += 1;
            if f1.is_empty() || f1.lba_first == 0 {
                break;
            }
            match ext_start.checked_add(f1.lba_first) {
                Some(next) => ebr_lba = next,
                None => break,
            }
        }
        out
    }
}

fn type_label(t: u64) -> &'static str {
    types::MBR_TYPES.lookup(&Value::Uint(t)).map(|e| e.label).unwrap_or("unknown")
}

fn label_for_entry(i: usize, fx: &EntryFacts) -> String {
    if fx.is_empty() {
        format!("[{i}] --")
    } else {
        format!("[{i}] {:02X} {}", fx.part_type, type_label(fx.part_type))
    }
}

/// Everything a single entry can be wrong about on its own.
fn annotate_entry(mut n: Node, fx: &EntryFacts, device_sectors: u64, ss: u64) -> Node {
    if fx.is_empty() {
        // An "empty" slot with a stray status or CHS byte is a trace of something
        // that used to be here — exactly what this tool exists to surface.
        let leftover = n
            .children
            .resolved()
            .map(|c| c.iter().any(|k| !k.raw.iter().all(|&b| b == 0)))
            .unwrap_or(false);
        if leftover {
            return n.with_diag(
                Diagnostic::info("slot is unused but not zero")
                    .with_hint("leftover bytes from a previous partition table"),
            );
        }
        return n;
    }

    if fx.num_sectors == 0 {
        n = n.with_diag(Diagnostic::bad("length is zero but the slot is in use"));
    }
    match fx.end_lba() {
        None => {
            n = n.with_diag(Diagnostic::bad("lba_first + num_sectors overflows 64 bits"));
        }
        Some(end) if device_sectors > 0 && end > device_sectors => {
            n = n.with_diag(
                Diagnostic::bad(format!(
                    "extends to LBA {end} but the device has only {device_sectors} sectors \
                     ({} byte sectors)",
                    ss
                ))
                .with_hint("either the table is wrong or the sector size is"),
            );
        }
        _ => {}
    }
    if fx.status != 0x00 && fx.status != 0x80 {
        n = n.with_diag(Diagnostic::warn(format!(
            "status {:#04X} is neither 0x00 nor 0x80",
            fx.status
        )));
    }
    if fx.part_type == types::TYPE_GPT_PROTECTIVE {
        n = n.with_diag(Diagnostic::info(
            "GPT protective entry: the real partition table is the GPT, not this",
        ));
    }
    n
}

fn find_overlaps(facts: &[EntryFacts]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for i in 0..facts.len() {
        for j in i + 1..facts.len() {
            let (a, b) = (&facts[i], &facts[j]);
            if a.is_empty() || b.is_empty() || a.num_sectors == 0 || b.num_sectors == 0 {
                continue;
            }
            // Extended containers legitimately contain their logicals; comparing
            // two top-level entries is still meaningful because logicals are not
            // top-level entries.
            let (ae, be) = (a.end_lba(), b.end_lba());
            if let (Some(ae), Some(be)) = (ae, be) {
                if a.lba_first < be && b.lba_first < ae {
                    out.push((i, j));
                    out.push((j, i));
                }
            }
        }
    }
    out
}

/// A synthetic MBR sector, used by tests in this crate and by the fuzz targets.
#[doc(hidden)]
pub fn synth_mbr(entries: &[(u8, u8, u32, u32)]) -> Vec<u8> {
    let mut s = vec![0u8; 512];
    for (i, (status, ty, start, count)) in entries.iter().take(4).enumerate() {
        let o = 0x1BE + i * 16;
        s[o] = *status;
        s[o + 4] = *ty;
        s[o + 8..o + 12].copy_from_slice(&start.to_le_bytes());
        s[o + 12..o + 16].copy_from_slice(&count.to_le_bytes());
    }
    s[0x1FE] = 0x55;
    s[0x1FF] = 0xAA;
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use blktamper_core::MemSource;

    fn src_with(sector: Vec<u8>, total: usize) -> Arc<dyn BlockSource> {
        let mut data = sector;
        data.resize(total, 0);
        Arc::new(MemSource::new(data))
    }

    #[test]
    fn a_plain_mbr_scores_high_and_parses() {
        let s = src_with(synth_mbr(&[(0x80, 0x0C, 2048, 129_024)]), 64 * 1024 * 1024);
        assert!(MbrProbe.probe(&*s, 0) >= 80);
        let r = MbrProbe.open(s, 0);
        let root = r.root();
        let entries = root.find_child("entries").unwrap();
        let kids = entries.children.resolved().unwrap();
        assert_eq!(kids.len(), 4);
        assert!(kids[0].label.contains("FAT32 LBA"));
        assert_eq!(kids[1].label, "[1] --");
    }

    #[test]
    fn a_missing_boot_signature_scores_zero_but_still_opens() {
        let mut sector = synth_mbr(&[(0x80, 0x0C, 2048, 1000)]);
        sector[0x1FE] = 0x00;
        let s = src_with(sector, 1024 * 1024);
        assert_eq!(MbrProbe.probe(&*s, 0), 0);
        // Forcing the interpretation must still produce a full tree.
        let root = MbrProbe.open(s, 0).root();
        assert_eq!(root.deep_status(), Status::Bad);
        assert!(root.find_child("entries").is_some());
    }

    #[test]
    fn a_partition_past_the_end_is_flagged() {
        let s = src_with(synth_mbr(&[(0x80, 0x83, 2048, 1_000_000)]), 1024 * 1024);
        let root = MbrProbe.open(s, 0).root();
        let e = &root.find_child("entries").unwrap().children.resolved().unwrap()[0];
        assert_eq!(e.status, Status::Bad);
        assert!(e.diags.iter().any(|d| d.message.contains("only")));
    }

    #[test]
    fn overlapping_partitions_are_flagged_on_both() {
        let s = src_with(
            synth_mbr(&[(0x00, 0x83, 2048, 4096), (0x00, 0x83, 4096, 4096)]),
            64 * 1024 * 1024,
        );
        let root = MbrProbe.open(s, 0).root();
        let kids = root.find_child("entries").unwrap().children.resolved().unwrap();
        assert!(kids[0].diags.iter().any(|d| d.message.contains("overlaps")));
        assert!(kids[1].diags.iter().any(|d| d.message.contains("overlaps")));
    }

    #[test]
    fn a_protective_mbr_is_recognised_and_not_mistaken_for_a_real_one() {
        let s = src_with(synth_mbr(&[(0x00, 0xEE, 1, 131_071)]), 64 * 1024 * 1024);
        let root = MbrProbe.open(s, 0).root();
        assert!(root.diags.iter().any(|d| d.message.contains("protective MBR")));
    }

    #[test]
    fn an_unused_slot_holding_leftovers_is_surfaced() {
        // Exactly the sanitize question: the slot reads as empty, but the bytes
        // that used to describe a partition are still there.
        let mut sector = synth_mbr(&[(0x80, 0x0C, 2048, 1000)]);
        let o = 0x1BE + 16; // slot 1: type/lba/len zeroed, CHS left behind
        sector[o + 1] = 0x20;
        sector[o + 2] = 0x21;
        sector[o + 3] = 0x00;
        let s = src_with(sector, 64 * 1024 * 1024);
        let root = MbrProbe.open(s, 0).root();
        let e = &root.find_child("entries").unwrap().children.resolved().unwrap()[1];
        assert!(e.diags.iter().any(|d| d.message.contains("unused but not zero")), "{:?}", e.diags);
    }

    #[test]
    fn a_self_referential_extended_chain_terminates() {
        let mut sector = synth_mbr(&[(0x00, 0x05, 2048, 20480)]);
        let _ = &mut sector;
        let mut data = sector;
        data.resize(64 * 1024 * 1024, 0);
        // EBR at LBA 2048 that points at itself (next = 0 relative to ext start).
        let ebr = 2048 * 512;
        data[ebr + 0x1FE] = 0x55;
        data[ebr + 0x1FF] = 0xAA;
        let o = ebr + 0x1BE + 16; // entry 1 -> relative LBA 0 == ext start == itself
        data[o + 4] = 0x05;
        data[o + 8..o + 12].copy_from_slice(&0u32.to_le_bytes());
        data[o + 12..o + 16].copy_from_slice(&100u32.to_le_bytes());
        let s: Arc<dyn BlockSource> = Arc::new(MemSource::new(data));
        // Must return rather than hang.
        let root = MbrProbe.open(s, 0).root();
        assert!(root.find_child("entries").is_some());
    }

    #[test]
    fn garbage_never_panics() {
        for seed in [0u8, 1, 0x55, 0xAA, 0xFF] {
            let s: Arc<dyn BlockSource> = Arc::new(MemSource::new(vec![seed; 4096]));
            let _ = MbrProbe.probe(&*s, 0);
            let _ = MbrProbe.open(s, 0).root();
        }
    }
}
