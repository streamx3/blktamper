# Research: prior art

Conducted 2026-09-16. Everything below was checked against sources, not recalled.

> Note: I could not read `https://claude.ai/cowork/cse_01C4iUrXgLnfJS4jM1dJYggx`
> (HTTP 403 — cowork sessions aren't fetchable). This research was redone from
> scratch. If that chat reached different conclusions, paste the relevant bits and
> I'll reconcile.

## 1. Is there already a tool that does this?

**In Rust: no.** Everything found is a *management* tool, not a structure viewer:

- `disktui` — TUI disk management/partitioning (create/delete partitions).
- `diskutility` — TUI format/erase/write-image, Windows-oriented.
- `flashtui` — image flasher.
- `disks-rs` (AerynOS) — superblock probing + partitioning API for an installer.
- `rust-partitions` — GPT/MBR probe and filesystem magic sniffer.

None of them show you a labelled field table, let alone let you edit one.

**Outside Rust, yes — and they're the design benchmark:**

- **WinHex / X-Ways, Active@ Disk Editor, DMDE, HxD** — Windows GUI disk editors.
  This is exactly the feature set you described, and has been for 25 years. The
  useful observation: all of them converged on the same layout — a structure
  template pane, a hex pane, and highlight-linking between them. That convergence
  is worth copying rather than re-deriving.
- **ImHex** — cross-platform GUI hex editor with a C-like pattern language
  (`.hexpat`). Its DFIR pattern set is the closest open equivalent: `DISK_PARSER.hexpat`
  detects MBR/GPT, walks extended partitions, and auto-loads `FAT32.hexpat` /
  `exFAT.hexpat` / NTFS patterns; the FAT32 pattern does FAT1/FAT2 cluster chaining
  with LFN/SFN grouping. **This proves the feature is achievable and is a good
  cross-check reference.**
- **fq** (Go) — "jq for binary formats". Decodes into a tree where every field
  carries a bit range, has a structural hex viewer and an interactive REPL, and
  explicitly models *gaps* (bit ranges no decoder claimed). **fq's data model is
  the single best prior art for the model in [04-architecture.md](04-architecture.md).**
  It is not a disk tool, but the shape is right.
- **The Sleuth Kit** (C/C++, `libtsk-rs` wrapper exists) — forensic filesystem
  analysis: `mmls`, `fsstat`, `istat`, `fls`. Reads deleted/hidden content, doesn't
  trust the OS. Very relevant to the "browse file and folder records" requirement.
- **TestDisk** — ncurses, closest existing TUI, but it is a *recovery* tool with a
  fixed workflow, not a general browser.
- **hachoir** (Python) — "view and edit a binary stream field by field". Same idea,
  generic, includes FS parsers.
- **`heh`** — Rust/ratatui terminal hex editor. Alpha, byte-level only, no structure
  awareness. Useful as a reference for the hex pane's interaction only.

**Conclusion:** the niche is genuinely empty in the Rust/TUI/Linux corner. The
feature set is well-trodden elsewhere, so there's a clear target to aim at and no
need to invent interaction patterns.

## 2. Has someone already described these formats as data?

Yes — four times over, at varying quality. This directly answers your question.

### Kaitai Struct (`.ksy`, YAML)

A declarative language compiled into parsers for ~12 languages. The gallery has
`mbr_partition_table`, `gpt_partition_table`, `vfat`, `ext2`.

I read the two that matter:

- **`gpt_partition_table.ksy`** — has `primary`/`backup` header instances, the 14
  header fields, the 6 partition-entry fields, UTF-16LE name decoding, signature
  validation. **Missing:** any CRC32 verification, protective-MBR handling, and —
  critically — *any enums*. Partition type GUIDs and the attribute bitfield are
  raw blobs.
- **`vfat.ksy`** — boot sector, BPB, FAT16 and FAT32 extended BPBs, root directory
  records with an attribute bitfield, and instances computing FAT/root-dir positions.
  **Missing:** the FAT contents and cluster-chain following, long filename (LFN)
  entries, subdirectory traversal, and exFAT entirely. No enums. Validation is one
  check on the `0x29` signature byte.

So the Kaitai specs give you *field offsets and widths*. They give you essentially
none of: enum tables, reserved-field semantics, cross-field invariants, human
documentation, or link targets. For a viewer, offsets are the cheap 40%.

**Rust support:** Kaitai gained a Rust target in v0.11 (September 2025), credited as
"decent support". It is the newest backend of twelve. The separate `kaitai` crate on
crates.io self-describes as a work in progress with a very limited feature set.
There is an NLnet-funded project specifically to improve Kaitai's Rust support —
which tells you it needed improving.

### ImHex pattern language (`.hexpat`)

Richer than Kaitai for this domain: `DISK_PARSER.hexpat` + `FAT32.hexpat` +
`exFAT.hexpat` do real traversal (EBR chains, cluster chains, LFN grouping). It is,
however, a bespoke C-like interpreted language with an interpreter written in C++
and no Rust runtime. Reusable as a **reference**, not as a dependency.

### 010 Editor binary templates

C-like templates, large community library covering MBR/GPT/FAT/NTFS/ext. The editor
is commercial; templates are mostly permissively shared. Same story: reference only.

### libyal (Joachim Metz)

`libfsext` (ext2/3/4), `libfsfat` (FAT/exFAT), `libfsntfs`, `libfsapfs`, `libfsxfs`,
`libluksde`, `libvslvm`, and ~40 more. Each ships a **working-document format
specification in asciidoc** alongside the C implementation. These are the best
free field-level format references in existence for this domain — better than the
Kaitai specs, and often better than the vendor documentation.

**This is the reuse that actually pays.** Not the code — the specs.

### Authoritative primary sources

- **exFAT**: Microsoft published the full specification openly
  (`learn.microsoft.com/windows/win32/fileio/exfat-specification`, revision 1.00).
  No reverse engineering needed.
- **GPT**: UEFI specification, chapter 5.
- **FAT**: Microsoft's FAT32 File System Specification (`fatgen103`), plus the
  ECMA-107 / ISO 9293 lineage for FAT12/16.
- **ext4**: the kernel's `Documentation/filesystems/ext4/` and the ext4 wiki disk
  layout page.
- **MBR**: no single authority; util-linux, the Wikipedia MBR page, and the
  type-code tables in `fdisk`/`sgdisk` are the practical references.

### Verdict on "describe them as data"

Yes, and it's smaller than you think — see the field counts in
[06-format-scope.md](06-format-scope.md). Scopes 0–2 are roughly **220 field descriptors** — about 300 lines of table.

But the descriptions that exist publicly describe *layout only*, and layout is the
part you'd have written in an afternoon anyway. See
[ADR-002](03-decisions.md#adr-002-describe-records-as-data-write-traversal-as-code)
for what to do about it.

## 3. Rust crates surveyed

### Partition tables

| Crate | What it is | Fit |
|---|---|---|
| `gptman` | Read/modify GPT. Structs `GPT`, `GPTHeader`, `GPTPartitionEntry`, `PartitionName(String)`. | **Wrong shape.** No byte offsets exposed. Names normalised into `String` (lossy for the non-UTF-16 junk you'll find on a damaged disk). Reserved-byte preservation unspecified. Returns `Result` — i.e. refuses. |
| `mbrman` | MBR + EBR/logical partition management. Preserves the 446-byte bootstrap. Permissive — "won't check the consistency of the partition you have created manually". | Closest to usable of the bunch, still no offsets. Good **test oracle**. |
| `gpt` | Pure-Rust GPT library. | Same shape problem. |
| `gpt-parser`, `gpt-partition-core` | Read-only, `no_std`-friendly GPT readers. | Same shape problem, smaller. |

### Filesystems

| Crate | Fit |
|---|---|
| `fatfs` / `simple-fatfs` | Embedded-oriented FAT12/16/32 *filesystem access* — open files, list dirs. Presents a POSIX-ish API, hides the on-disk layout. The opposite of what's needed for viewing, useful as an oracle. |
| `exfat-slim` | exFAT reader. Thin, young. |
| `ext4` / `ext4-view` | ext4 readers. Same shape problem. |

### Binary parsing

| Crate | Fit |
|---|---|
| `binrw` | Derive-macro parse/serialize over a stream. Good ergonomics, round-trips well. **But it parses into owned structs — the offset information is consumed and discarded.** Not zero-copy by design (operates on streams, not memory). |
| `deku` | Bit-level derive parsing over slices. Same ownership problem; error messages point at the derive. |
| `zerocopy` | Transmute-based views over `&[u8]`. Fast, genuinely zero-copy — but gives you a *typed struct*, not a *field list*. You still can't enumerate fields at runtime, which is the whole UI. |
| `scroll` | `Pread`/`Pwrite` with explicit offsets. Low-level and unopinionated. Plausible as an *internal* helper for reading primitives at offsets. |
| `nom` | Combinator parsing, stream-oriented. Overkill; these are fixed-layout records, not a grammar. |

**The common failure:** all of them produce `struct Foo { a: u32, b: u16 }`. This app
needs `[Field{"a", 0..4, U32}, Field{"b", 4..6, U16}]` — a value that can be
*iterated, filtered, labelled, and pointed back at bytes*. Deriving one from the
other requires either reflection (Rust doesn't have it) or a parallel descriptor
table — at which point the descriptor table is the real artefact and the derive is
redundant.

### Supporting crates (unambiguously reuse)

| Crate | For |
|---|---|
| `ratatui` 0.30.x (+ `ratatui-core` since the 0.30 modularisation) | TUI |
| `crossterm` | terminal backend |
| `rustix` or `nix` | `ioctl`s: `BLKSSZGET`, `BLKPBSZGET`, `BLKGETSIZE64`, `BLKFLSBUF`, `BLKRRPART` |
| `crc32fast` | GPT CRC32 |
| `uuid` | GUID parsing/formatting (GPT's mixed-endian layout is an easy thing to get wrong) |
| `arboard` (with `wayland-data-control`) | clipboard |
| `thiserror` | error enums |
| `tracing` | logging to file (never to stdout — it's a TUI) |
| `clap` | CLI |
| `libc` | `O_DIRECT`, `posix_fadvise` if needed |

## 4. Linux block-device facts that affect the design

Checked on this machine (kernel 6.8.0-138-generic):

- **`CONFIG_BLK_DEV_WRITE_MOUNTED`** — introduced in Linux 6.8 (Jan Kara, SUSE).
  When a kernel is built with it disabled, opening a *mounted* block device for
  writing fails with `-EBUSY`, and there is a `bdev_allow_write_mounted=` boot
  parameter. Rationale from the commit: writing to a mounted device's buffer cache
  "is very likely going to cause filesystem corruption" and can crash the kernel.
  This machine has `CONFIG_BLK_DEV_WRITE_MOUNTED=y`, so writes are permitted here —
  but the app must recognise `EBUSY` and explain it rather than showing a bare errno.
- **Permissions**: `/dev/sdc` is `brw-rw---- root:disk`. The current user is not in
  `disk`. So blktamper needs `sudo`, group membership, or a capability. This must be
  a first-class, explained error (R-1.5).
- **`/dev/sdc1` is currently mounted** at `/media/andrii/E807-EC4E` (label format
  `XXXX-XXXX` = a FAT/exFAT volume serial). Your actual test target is live-mounted
  right now, which is precisely the situation R-2.6 exists for.
- **Sector-granularity writes**: a buffered `pwrite()` to `/dev/sdX` at an arbitrary
  byte offset *is* allowed — the kernel does read-modify-write through the page
  cache. With `O_DIRECT` it is not: offset, length and the memory buffer must all be
  aligned to the logical block size. So "edit two bytes" is fine, but it is
  physically a whole-sector rewrite, and the page cache can hold a stale copy of the
  rest of that sector if something else has the device open. See
  [07-write-safety.md](07-write-safety.md).

## Sources

- [File Format Gallery for Kaitai Struct](https://formats.kaitai.io/)
- [kaitai-io/kaitai_struct_formats](https://github.com/kaitai-io/kaitai_struct_formats)
- [Kaitai Struct v0.11 release notes](https://kaitai.io/news/2025/09/07/kaitai-struct-v0.11-released.html)
- [NLnet: Improving and extending Kaitai Struct (Rust)](https://nlnet.nl/project/Kaitai-Rust/)
- [kaitai crate on crates.io](https://crates.io/crates/kaitai/0.1.2)
- [WerWolv/ImHex-Patterns — DISK_PARSER.hexpat](https://github.com/WerWolv/ImHex-Patterns/blob/master/patterns/DFIR/DISK_PARSER.hexpat)
- [wader/fq — jq for binary formats](https://github.com/wader/fq)
- [libyal — libfsext](https://github.com/libyal/libfsext), [libfsntfs NTFS spec](https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc)
- [exFAT File System Specification — Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/fileio/exfat-specification)
- [The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/), [forensicmatt/libtsk-rs](https://github.com/forensicmatt/libtsk-rs)
- [gptman](https://crates.io/crates/gptman) · [mbrman](https://crates.io/crates/mbrman) · [docs.rs/gptman](https://docs.rs/gptman/latest/gptman/) · [docs.rs/mbrman](https://docs.rs/mbrman/latest/mbrman/)
- [binrw](https://github.com/jam1garner/binrw) · [binrw vs deku discussion](https://github.com/jam1garner/binrw/discussions/184) · [deku](https://docs.rs/deku)
- [ratatui](https://crates.io/crates/ratatui) · [heh](https://lib.rs/crates/heh)
- [arboard](https://github.com/1Password/arboard)
- [Linux 6.8 blocking writes to mounted block devices — Phoronix](https://www.phoronix.com/news/Linux-6.8-Block-Dev-Write-Mount) · [commit ed5cc70](https://github.com/torvalds/linux/commit/ed5cc702d311c14b653323d76062b0294effa66e)
- [dloss/binary-parsing — survey of binary parsing tools](https://github.com/dloss/binary-parsing)
