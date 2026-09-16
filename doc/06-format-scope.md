# Format scope

## The ladder

Your ranking, with my notes. See
[ADR-004](03-decisions.md#adr-004-do-gpt-before-fat32exfat) and
[ADR-005](03-decisions.md#adr-005-three-other-things-in-your-format-ladder-are-mis-ranked)
for the arguments.

| Rank | Format | Verdict |
|---|---|---|
| 0 | MBR (+ EBR chain) | Agreed. Simplest, and it bootstraps everything. |
| 1 | FAT32, exFAT | Agreed they're needed — but see rank 2. exFAT is much bigger than it looks. |
| 2 | GPT | **Propose swapping with rank 1.** GPT is ~2 days; exFAT is ~2 weeks. |
| — | *…implementation stops here unless you say otherwise…* | |
| 3 | ext4, ext3, "UEFI" | ext3 and ext4 are one superblock parser; **ext2 (ranked 7) belongs here too**. "UEFI" is not a filesystem — the ESP is FAT32, already covered at rank 1. What did you mean? |
| 4 | LUKS | **Header viewing is cheap** — promote it. Decryption is a different project; recommend never. |
| 5 | NTFS, APFS, HFS+ | NTFS is large but extremely well documented (libyal). APFS is large and awkward. HFS+ is small and nearly dead. |
| 6 | FAT16, FAT12 | Nearly free once FAT32 exists — same BPB, different cluster width and a smaller EBPB. Arguably belongs at rank 1.5. |
| 7 | jffs2, SPIFFS, BTRFS, XFS, ZFS, ext2, F2FS, UDF | Wildly uneven. ext2 → rank 3. UDF and F2FS are moderate. BTRFS/ZFS are enormous (multi-device, COW B-trees, transaction groups) and are each a project of their own. |

## What "writing our own definitions" actually means

Yes: we write the descriptor tables. No: we don't invent them, and the transcription
is not where the work is. Three things get conflated under "definitions":

| | Who writes it | Size | Does it exist publicly? |
|---|---|---|---|
| **Layout** — name, offset, width, endianness | transcribed from published specs | ~220 lines | Yes, in at least four forms (Kaitai, ImHex, 010, libyal) |
| **Semantics** — enum tables, reserved/must-be-zero flags, cross-field checks, doc strings, link targets | us | ~300 lines of enum data + one doc line per field | **No.** Not in any machine-readable form. |
| **Traversal** — EBR chains, cluster chains, entry sets, extent trees | us | ~1000–1400 lines | Only as C/C++/Python *implementations*, not as data |

So the thing you'd be "duplicating" is row one, and it's an afternoon of typing.
Rows two and three are the product, and nothing out there gives them to you.

### What one record actually costs

The complete MBR partition entry — the whole structure, not an excerpt:

```rust
pub const MBR_PART_ENTRY: StructDesc = StructDesc {
    name: "MBR partition entry",
    size: Some(16),
    spec: "conventional; see util-linux and the Wikipedia MBR article",
    fields: &[
        f("status",      0x00, W::U8,       R::Enum(&MBR_STATUS), "0x80 = active/bootable, 0x00 = inactive"),
        f("chs_first",   0x01, W::Bytes(3), R::Chs,               "CHS of first sector; meaningless past 8 GiB"),
        f("part_type",   0x04, W::U8,       R::Enum(&MBR_TYPES),  "partition type byte"),
        f("chs_last",    0x05, W::Bytes(3), R::Chs,               "CHS of last sector; FE FF FF = overflow"),
        f("lba_first",   0x08, W::U32le,    R::Lba,               "first sector, LBA, relative to the disk"),
        f("num_sectors", 0x0C, W::U32le,    R::Dec,               "length in sectors"),
    ],
    checks: &[Check::Cross("lba_first + num_sectors <= device_sectors")],
    links:  &[LinkDesc::probe_at_lba("lba_first", "volume header")],
};
```

Six lines. That is the entire MBR partition entry, and it is simultaneously the
parser, the renderer, the editor, the filter, the copy format and the tooltip.
Multiply by ~35 structures for scopes 0–2.

### The transcription is cross-checked, not trusted

Every descriptor gets its offsets confirmed against **at least two independent
sources** — typically the primary spec (UEFI, Microsoft's exFAT document, libyal's
asciidoc) plus one of Kaitai `.ksy` or ImHex `.hexpat`. This is not busywork: I
already found that Kaitai's `gpt_partition_table.ksy` omits CRC verification
entirely and `vfat.ksy` has exactly one validation check. Single-sourcing any of
these would import their gaps.

### Typos are caught by structure, not by review

Transcribed offset tables have exactly one common failure mode: an offset or width
that's off by a few. A generic test catches essentially all of it:

```
for every StructDesc with size == Some(n):
    fields must tile [0, n) exactly
    no two fields may overlap
    any uncovered range must be a declared Gap or a RESERVED field
```

Run that over every descriptor in the crate and a mistyped width shows up as
"fields cover 15 of 16 bytes, uncovered 0x0F..0x10" the moment you add it. That
test is ~40 lines and it is worth more than any amount of proofreading.

### If the typing still bothers you

There's a cheap middle path we can take at M2: a one-off `xtask` that reads the
Kaitai `.ksy` files and emits skeleton `FieldDesc` tables with names, offsets and
widths filled in. Then we hand-enrich with enums, docs, checks and links — which is
the part that had to be written anyway.

Worth doing only if it saves more than it costs. My estimate: it does not, for four
formats. The `.ksy` parser plus the emitter is a day; typing 220 field rows is an
afternoon, and typing them is when you actually notice that `vfat.ksy` calls a field
`max_root_dir_rec` while the spec calls it `BPB_RootEntCnt`. But the option is real,
and it becomes clearly worth it if the ladder ever extends to ext4 (a ~100-field
superblock) or NTFS.

## Field inventory for scopes 0–2

Rough descriptor counts, to calibrate [ADR-002](03-decisions.md).

### MBR — ~52 descriptors

| Structure | Offset | Size | Fields |
|---|---|---|---|
| Bootstrap code | 0x000 | 440 | 1 (opaque blob; disassembly out of scope) |
| Disk signature | 0x1B8 | 4 | 1 (NT drive serial) |
| Reserved / copy-protect | 0x1BC | 2 | 1 (`0x0000`, or `0x5A5A` = copy protected) |
| Partition entry × 4 | 0x1BE | 16 each | 6 fields + 6 CHS subfields each = 48 |
| Boot signature | 0x1FE | 2 | 1 (`0x55AA`) |

Partition entry: `status`, `chs_first` (head / sector / cylinder — note the 6-bit
sector + 10-bit cylinder packing, a classic place to get it wrong), `part_type`,
`chs_last`, `lba_first`, `num_sectors`.

Traversal (Tier B): the EBR chain. An extended partition (type `0x05`/`0x0F`/`0x85`)
contains a singly-linked list of EBRs where entry 0 describes a logical partition
relative to the EBR and entry 1 points to the next EBR relative to the *extended
partition start*. Two different bases. This is the trap, it's ~60 lines, and it
needs a loop guard against a self-referential chain on a corrupt disk.

Data tables: MBR partition type bytes, ~150 entries. Transcribed facts, not code —
but see the GPL note in [ADR-001](03-decisions.md).

### GPT — ~26 descriptors + a GUID table

| Structure | Size | Fields |
|---|---|---|
| Header | 92 (of a 512 B sector) | 14 |
| Partition entry | 128 | 6 fields + ~6 attribute bits |

Header: `signature`, `revision`, `header_size`, `header_crc32`, `reserved`,
`my_lba`, `alternate_lba`, `first_usable_lba`, `last_usable_lba`, `disk_guid`,
`entries_lba`, `num_entries`, `entry_size`, `entries_crc32`.

Entry: `type_guid`, `unique_guid`, `first_lba`, `last_lba`, `attributes`
(bit 0 required, bit 1 no-block-IO, bit 2 legacy-BIOS-bootable, bits 48–63
type-specific: 60 read-only, 61 shadow-copy, 62 hidden, 63 no-automount),
`name` (72 B UTF-16LE, and it is *not* guaranteed valid — show it lossily).

Gotchas worth knowing before writing the code:

- The `header_crc32` is computed over `header_size` bytes with the CRC field itself
  zeroed. Off-by-one here is the classic GPT bug.
- `entries_crc32` covers `num_entries × entry_size` bytes, *not* the 16 KiB the
  entries usually occupy — they differ if `entry_size != 128`.
- The disk GUID is stored **mixed-endian**: first three groups little-endian, last
  two big-endian. `uuid::Uuid::from_bytes_le` vs `from_bytes` — get this wrong and
  every GUID you display is subtly scrambled.
- The backup header is at the last sector, its entry array *before* it, and its
  `my_lba`/`alternate_lba` are swapped relative to the primary. A primary-vs-backup
  diff that doesn't know this reports 2 false differences.
- The protective MBR should have exactly one `0xEE` entry covering the disk, but
  hybrid MBR/GPT setups exist in the wild and must display, not error.

Data tables: GPT partition type GUIDs, ~120 well-known entries.

### FAT32 — ~62 descriptors

| Structure | Offset | Fields |
|---|---|---|
| BPB (common to FAT12/16/32) | VBR + 0x00 | 14 |
| Extended BPB (FAT32 form) | VBR + 0x24 | 12 |
| Boot code + signature | VBR + 0x5A | 2 |
| FSInfo sector | `fs_info` LBA | 7 |
| Directory entry (8.3) | 32 B | 13 + 6 attribute bits |
| LFN entry | 32 B | 8 |

Traversal (Tier B): cluster-chain following with an EOC table and a loop guard;
cluster → byte offset arithmetic
(`data_start + (cluster - 2) × sectors_per_cluster × bytes_per_sector`); FAT#0 vs
FAT#1 divergence detection; LFN run assembly (entries precede the 8.3 entry in
*reverse* order, with an `0x40` last-entry marker and a checksum of the 8.3 name
that must match); deleted-entry handling (`0xE5` first byte, first character
destroyed).

FAT12 (rank 6) adds the 12-bit packed FAT — two entries share three bytes, and the
nibble order differs by parity. It's 30 lines and it is fiddly. FAT16 is free.

### exFAT — ~80 descriptors

This is the big one and the reason for ADR-004.

| Structure | Where | Fields |
|---|---|---|
| Main Boot Sector | sector 0 | ~22 + 4 volume-flag bits |
| Extended Boot Sectors × 8 | sectors 1–8 | 1 each + signature check |
| OEM Parameters | sector 9 | 10 × 48 B parameter slots |
| Reserved | sector 10 | 1 |
| Boot Checksum | sector 11 | 1 + the checksum algorithm over sectors 0–10 |
| Backup Boot Region | sectors 12–23 | mirror of all of the above |
| Allocation Bitmap dir entry (`0x81`) | root dir | 5 |
| Up-case Table dir entry (`0x82`) | root dir | 6 |
| Volume Label dir entry (`0x83`) | root dir | 4 |
| File dir entry (`0x85`) | any dir | ~14 + attribute bits |
| Stream Extension entry (`0xC0`) | follows `0x85` | 10 |
| File Name entry (`0xC1`) × N | follows `0xC0` | 3 |
| Volume GUID (`0xA0`), vendor ext (`0xE0`/`0xE1`), TexFAT padding (`0xA1`) | | ~8 |

Traversal (Tier B), and this is where the work is:

- **Entry sets.** A file is a `0x85` primary entry plus `secondary_count`
  secondaries: one `0xC0` stream extension plus N `0xC1` name entries. The
  `set_checksum` in the primary covers the whole set with the checksum field itself
  excluded. Presenting this as one row that expands into several 32-byte entries is
  exactly what `NodeKind::Group` and `Extent::Many` exist for.
- **Boot region checksum** over sectors 0–10, excluding three bytes
  (`volume_flags` and `percent_in_use`) — a rolling 32-bit checksum, not a CRC.
- **`NoFatChain` flag** in the stream extension: when set, the file is contiguous
  and the FAT is not consulted at all. Getting this wrong means following a chain
  that isn't there.
- **Allocation bitmap** vs FAT — exFAT tracks free space in a bitmap, so "is this
  cluster allocated" and "what's the next cluster" come from different places.
  Cross-checking the two is a genuinely useful anomaly detector.
- **Up-case table** is a compressed (run-length) table used for name hashing. The
  `name_hash` in the stream extension is computed with it, so verifying a filename
  hash requires reading and decompressing the table.

## Totals for scopes 0–2

- **~220 field descriptors** ≈ 300 lines of declarative table.
- **~270 enum entries** (MBR type bytes + GPT type GUIDs) ≈ 300 lines of data.
- **~1000–1400 lines of Tier-B traversal code**, of which roughly half is exFAT.
- Everything else — the TUI, the I/O layer, the model — is the actual project.

Which is the empirical answer to "is it simple to describe them as data": yes, the
description is small. That's also why describing them isn't the hard part.

## Effort estimate

Focused days, assuming the architecture is in place. Wide error bars.

| Milestone | Days |
|---|---|
| Model + I/O + cache + a hex-only TUI | 5–8 |
| MBR (+ EBR) | 2–3 |
| GPT (+ protective MBR, primary/backup diff) | 2–3 |
| FAT32 headers (BPB, EBPB, FSInfo) | 2–3 |
| FAT cluster chains + directory browsing + LFN | 4–6 |
| exFAT boot region + checksums | 3–4 |
| exFAT directory entry sets + bitmap + upcase | 5–7 |
| Overlay + editor + journal + commit | 4–6 |
| Test fixtures, differential tests, fuzzing | 4–6 |

## Format notes for the deferred ranks

Kept here so the ladder decisions are recorded, not because they're scheduled.

- **ext2/3/4**: one superblock (~100 fields — it is a big struct), block group
  descriptors, inodes. ext4 adds extent trees; ext2/3 use indirect block maps,
  which are *simpler*. The `s_feature_incompat` bits are what tell you which you're
  looking at. Excellent references: kernel `Documentation/filesystems/ext4/`, libyal
  `libfsext`.
- **LUKS1**: a ~592-byte header plus 8 key slots, all big-endian. **LUKS2**: a 4096-byte
  binary header (primary and secondary) plus a JSON metadata area. Displaying the
  JSON pretty-printed alongside the binary header is most of the work. Reference:
  the LUKS2 on-disk format spec, libyal `libluksde`.
- **NTFS**: boot sector → `$MFT` → file records → attribute lists → runlists. Large
  but the best-documented of the closed formats (libyal `libfsntfs`). The runlist
  decoder is the interesting part and would exercise `Extent::Many` hard.
- **BTRFS / ZFS**: multi-device, copy-on-write B-trees, transaction groups, and no
  single "header" to view. Each is a larger project than everything above combined.
  If they ever happen, they happen as separate crates.
