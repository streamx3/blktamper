# Roadmap

## Where it actually is (2026-09-16)

| Milestone | State |
|---|---|
| M0 skeleton | **done** — four crates, layering enforced by `cargo tree` |
| M1 look at bytes | **done** — file + Linux backends, block cache, hex pane, `EACCES`/`EBUSY` advice, `--sector-size` |
| M2 MBR + uniform machinery | **done** — descriptors, generic reader, field table, region tree, `z` filter, copy, EBR chain, verified against `sfdisk` images |
| M3 GPT | **done** — both headers, both entry arrays, both CRCs, primary/backup diff, ~40 type GUIDs, protective/hybrid MBR handling |
| M4 FAT32 headers | **done** — BPB, EBPB32, EBPB16, FSInfo, derived geometry, FAT mirror comparison |
| M5 FAT32 directories | **done** — cluster chains, LFN assembly with checksum, deleted entries and orphaned fragments surfaced |
| M6 writing | **partly done** — overlay, journal, arm/commit and record scrubbing for FAT and exFAT are in. Field editing, `:save`/`:load`, `:recompute` and `--undo` are not. |
| M7 exFAT | verification in progress |

The build can write, behind the three gates of [ADR-007](03-decisions.md): devices
open `O_RDONLY`, `--rw` permits arming, `:arm` opens the write handle, and `:commit`
needs the device name typed. `scripts/check.sh` verifies all of that as build
failures rather than as review habits.

The only write operation is scrubbing a recoverable record. Checksum *verification*
is implemented; `:recompute` now has an overlay to stage into but is not yet wired.


Milestones are defined by **exit criteria**, not by time. Each one should end with
something you can actually run on `/dev/sdc`.

The order below assumes [ADR-004](03-decisions.md#adr-004-do-gpt-before-fat32exfat)
(GPT before FAT). If you reject it, swap M3 and M4; nothing else changes.

---

## M0 — Skeleton

Prove the crate layering works before there's anything to layer.

- Cargo workspace with `blktamper-core`, `blktamper-io`, `blktamper-formats`, `blktamper-tui`.
- `Span`, `Extent`, `Node`, `Value`, `Repr`, `Status` defined in core.
- `BlockSource` trait + `ImageFile` backend + an in-memory `Vec<u8>` backend for tests.
- CI: `cargo build -p blktamper-core` succeeds with no `ratatui` in the dependency tree.

**Exit:** `cargo tree -p blktamper-core` shows no terminal, no async runtime, no `anyhow`.

---

## M1 — Look at bytes

A hex viewer. Not the goal, but everything else sits on it.

- Linux block device backend: open, `BLKGETSIZE64`, `BLKSSZGET`, `BLKPBSZGET`,
  mount detection via `/proc/self/mountinfo`.
- Block cache with readahead; I/O on a worker thread; UI never blocks.
- Hex pane with page/half-page/goto navigation.
- `EACCES` and `EBUSY` produce explanatory messages, not errnos.
- `--sector-size` override, shown in the title bar.

**Exit:** `sudo blktamper /dev/sdc` renders sector 0, scrolls to the end of a 57 GiB
device instantly, and survives unplugging the stick mid-scroll.

---

## M2 — MBR, and the whole uniform machinery

The first format, and the last time the UI plumbing gets written.

- `FieldDesc` / `StructDesc` types and the generic struct reader.
- Field table widget, region tree, hex highlight linking, status gutter.
- `z` filter cycle (all / hide empty / anomalies), `NodeKind::Gap` detection.
- Copy: `y`, `Y`, `y h`, `y p`, `y t`; arboard + OSC 52 + file fallback.
- MBR descriptors, partition type enum table, CHS unpacking.
- EBR chain traversal with a loop guard.
- Field detail popup.
- Golden image fixtures + generator script; first differential test vs `mbrman`.

**Exit:** open `/dev/sdc`, see all four MBR entries labelled, hide the three empty
ones with one key, select `part_type` and see its byte highlighted in hex, copy the
row as TSV and paste it somewhere.

This is the milestone that proves or disproves the whole design. If the field table
feels wrong here, it will feel wrong for every format. Budget time to throw the
widget away once.

---

## M3 — GPT, and cross-format navigation

- GPT header + entry descriptors, type-GUID table, attribute bit expansion.
- CRC32 verification with stored-vs-computed rendering.
- Backup header/entries discovery and primary-vs-backup diff view.
- Protective MBR recognition; hybrid MBR shown, not rejected.
- `FormatProbe` registry, probe scoring, `:probe` and `:as <fmt>`.
- Link following (`g`), jump stack (`Ctrl-o`/`Ctrl-i`).
- Differential test vs `gptman` and `sgdisk -p`; corrupted-CRC fixtures.

**Exit:** on a GPT test image, corrupt one byte of the header with `dd`, reopen, and
the app shows `X` on `header_crc32` with stored ≠ computed, offers a diff against the
backup, and lets you jump from a partition entry to whatever is at its first LBA.

---

## M4 — FAT32 headers

- BPB / FAT32 EBPB / FSInfo descriptors.
- Geometry derivation: FAT start, data start, cluster count, FAT type
  determination (which is defined by cluster count, not by the `fs_type` string —
  that string is documentation, not data, and the app should say so).
- Cluster ↔ LBA ↔ byte offset conversions, exposed as `:cluster N`.
- FAT #0 vs FAT #1 divergence detection.
- Differential test vs `fsck.vfat -n` and `fatfs`.

**Exit:** `/dev/sdc1`'s volume header fully labelled; jumping from the MBR entry
lands on it automatically via probing.

---

## M5 — FAT32 directories and files

The first time the tool does something no partition tool does.

- Cluster chain following with loop guard and EOC handling.
- Directory listing as a region; 8.3 entries; LFN run assembly with checksum
  verification; deleted (`0xE5`) entries shown and marked.
- `NodeKind::Group` + `Extent::Many` in anger.
- Navigate into subdirectories; jump from a directory entry to its first cluster.

**Exit:** browse to a real file on `/dev/sdc1`, expand its directory entry, see
every field, and jump to its data.

---

## M6 — Writing

Only now, and only because M0–M5 made it cheap. Ordered so that the *bounded*
operation comes before the arbitrary one: scrubbing a deleted record touches a set of
byte ranges the model has already computed, whereas field editing can touch anything.
Proving the write path on the safer operation first is worth the reordering.

1. ~~`Overlay` in the read stack~~ **done** — reads see staged edits, so the tree
   re-parses against them before anything touches the device.
2. ~~Off-device journal, `:arm`, `:commit` with the sector list and typed
   confirmation~~ **done**.
3. ~~**Scrub a deleted record**~~ **done** for FAT12/16/32 and exFAT — `neutral` and
   `zero` fills, the end-of-directory guard, whole-set staging. See
   [ADR-011](03-decisions.md) and
   [07-write-safety.md](07-write-safety.md#scrubbing-deleted-records).
4. `:save` / `:load` region dump and restore — the blunt instrument, and the one you
   actually want at 2 a.m.
5. Typed field editor with enum picker; raw hex editor.
6. `:recompute` for CRCs and mirrors, deepest-first through the cascade.
7. `--undo` replaying a journal backwards. The journal already round-trips into its
   own undo edits; only the CLI entry point is missing.

Write tests run against image files only, never a device.

**Exit:** delete a file with `mdel` on a fixture, scrub its record with `neutral`,
commit, and confirm with `mdir` that the live files are untouched and with
blktamper that the name, timestamps and first cluster are gone while the `0xE5`
tombstone remains. Then undo from the journal and verify the record is back.

---

## M7 — exFAT

- Boot region (12 sectors), extended boot sectors, OEM parameters, boot checksum.
- Backup boot region and a main-vs-backup diff.
- Directory entry sets: `0x85` + `0xC0` + `0xC1×N`, set checksum verification.
- Allocation bitmap, up-case table, `NoFatChain` handling.
- Name hash verification against the up-case table.

**Exit:** browse an exFAT volume's directory tree with entry sets presented as
single rows that expand into their constituent 32-byte entries.

---

## Beyond

In rough value-per-effort order, not committed:

1. `blktamper get <path>` — non-interactive query mode. Nearly free once `NodePath`
   exists, and it makes the whole thing scriptable.
2. LUKS1 + LUKS2 header viewing (header only, no crypto).
3. FAT12 / FAT16.
4. ext2/3/4 superblock, block group descriptors, inodes.
5. Descriptor export (`.ksy` / JSON) — closes the loop on
   [ADR-002](03-decisions.md).
6. NTFS.

## Things to decide before M2, not after

- The `FieldDesc` shape. Changing it after three formats exist is painful.
- Whether `Repr` is an enum or a trait object. (Recommend enum: it keeps
  descriptors exportable, per ADR-002.)
- Whether nodes are built eagerly per struct or streamed. (Recommend per-struct
  eager, per-array lazy.)
- The colour/status vocabulary — because changing `Status` changes every format.

---

## What the parallel review found

GPT, FAT and exFAT were each implemented by one agent and then reviewed by a second
one instructed to *refute* the first's claims rather than confirm them. That second
pass was worth more than the first, and it is worth recording what it caught.

### Defects the reviewers confirmed and fixed

| Where | Defect |
|---|---|
| `blktamper-core/src/span.rs` | **`Span::bytes` did `start * 8` unchecked.** With `overflow-checks = true` in release, any offset above 2 EiB aborts. Reachable with no hostile bytes at all: the backup GPT header sits at the device's last LBA, so a `BlockSource` reporting a large length is enough. Found independently by two reviewers. |
| `blktamper-formats/src/gpt/mod.rs` | **O(n²) diagnostic amplification.** `num_entries` was correctly clamped to 4096 as "an allocation request from an untrusted source" — and then one formatted diagnostic was emitted per overlapping *pair*. Measured at 2.44 GB RSS and 3.48 s on a crafted image. The clamp was defeated one level down. Now bounded per entry with a "and N further entries overlap, not listed" summary. |
| `blktamper-formats/src/fat/mod.rs` | **A false positive on every healthy FAT12/FAT16 volume.** A check read offset `0x24` as `fat_size_32`, but `0x24` is only `fat_size_32` on FAT32; on FAT12/16 it is the start of the EBPB16. Since the check could only fire when `fat_size_16 != 0` — i.e. only on FAT12/16 — it could never be anything *but* a false positive. |
| `blktamper-formats/src/fat/mod.rs` | **An off-by-one locked in by its own test.** The end-of-directory record was emitted as a node *and* counted among the blanks, so a 16-record cluster reported 17 records. The existing test asserted the wrong number and its comment repeated the miscount. |

### The lesson worth keeping

Three of the four are the same shape: **a bound that is enforced at one layer and
undone at the next.** `num_entries` clamped, then amplified by diagnostics.
`saturating_add` applied in `reader.rs` while `Span::bytes` still multiplied
unchecked one call deeper — the first fix looked complete and was not; writing the
test is what found the rest.

The fourth is different and worse: a test that encoded the bug. A wrong assertion
with a confident comment is harder to find than no test at all, which is why
`tests/fixtures/README.md` records ground truth read out with `xxd` and `python3`
rather than with our own parser.
