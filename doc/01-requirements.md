# Requirements

Requirement IDs are stable. `MUST` / `SHOULD` / `MAY` in the RFC-2119 sense.
"Scope N" refers to the format ladder in [06-format-scope.md](06-format-scope.md).

## 0. Purpose

blktamper opens a raw block device (or an image file) and shows the on-disk structures
— partition tables, filesystem headers, directory records — as labelled, navigable
tables, with every field traceable to the exact bytes it came from. Viewing is the
product. Editing is a secondary capability that must never happen by accident.

Non-goals, explicitly:

- It is not a partitioning tool. It does not create filesystems.
- It does not repair anything automatically.
- It is not a data-recovery tool (no carving, no undelete). It may *help* you do
  recovery by hand.
- It does not mount anything, ever.

## 1. Platform

| ID | Requirement |
|---|---|
| R-1.1 | Linux is the only supported target for v1. |
| R-1.2 | All OS-specific behaviour (open, size query, sector size, mount detection, cache flush) MUST sit behind a trait so another OS can be added without touching format or UI code. |
| R-1.3 | A plain-file backend (disk image) MUST exist and MUST work on any platform the Rust toolchain supports. This is also the test harness. |
| R-1.4 | FreeBSD/NetBSD/illumos are anticipated. macOS and Windows are not planned but MUST NOT be architecturally excluded. |
| R-1.5 | The app MUST report, in-app, when it cannot open a device due to permissions, and say what to do about it (group `disk`, `sudo`, `CAP_SYS_RAWIO`). |

## 2. Device access

| ID | Requirement |
|---|---|
| R-2.1 | Open block devices (`/dev/sdc`), partitions (`/dev/sdc1`), and regular files. |
| R-2.2 | Default open mode MUST be read-only. Write access requires an explicit CLI flag *and* an in-app arming step. See [07-write-safety.md](07-write-safety.md). |
| R-2.3 | Logical and physical sector size MUST be detected (`BLKSSZGET`, `BLKPBSZGET`) and MUST be overridable by the user, because all LBA→byte arithmetic depends on it and images from 4Kn disks lie. |
| R-2.4 | Device size MUST be detected (`BLKGETSIZE64`, `fstat` for files). Reads past the end MUST be reported as a distinct state, not as zeros. |
| R-2.5 | Reads MUST be cached and MUST NOT assume the device is seekable-cheap. A 58 GiB stick must not be read linearly to display sector 0. |
| R-2.6 | The app MUST detect that a device or any of its partitions is currently mounted, display that prominently, and refuse to arm writes without an extra confirmation. |
| R-2.7 | Sparse / unreadable sectors (I/O error) MUST render as a distinct status, not crash and not be silently zero-filled. A dying disk is exactly when this tool is useful. |

## 3. Parsing model

| ID | Requirement |
|---|---|
| R-3.1 | **Parsing MUST NOT fail.** Any byte range interpreted as a structure MUST produce a complete field tree, whatever the content. Invalid data produces *diagnostics attached to fields*, never a refusal to display. |
| R-3.2 | Every displayed node MUST carry its exact provenance: absolute byte offset, bit offset, bit length. Nodes representing non-contiguous data (cluster chains, fragmented runs) MUST carry an ordered list of extents. |
| R-3.3 | Values MUST be shown both raw (as stored, hex) and decoded (enum name, timestamp, GUID, string). Neither representation may be the only one available. |
| R-3.4 | Unknown, reserved, and padding fields MUST be modelled explicitly, not omitted. A non-zero reserved field is a finding, not noise. |
| R-3.5 | Structures MUST be parsed lazily. A 128-entry GPT array, a 7 MB FAT, or a directory with 40 000 entries must not be materialised to display the first screen. |
| R-3.6 | Checksums and CRCs MUST be shown as *stored value* alongside *computed value*, with a pass/fail marker. |
| R-3.7 | The parser MUST NOT panic on any input. Enforced by fuzzing. |

## 4. Display

| ID | Requirement |
|---|---|
| R-4.1 | Every part of a supported header MUST be displayable with a human label. |
| R-4.2 | Long tables MUST support page-up/page-down and half-page scroll, plus jump-to-top/bottom. |
| R-4.3 | A hotkey MUST cycle visibility of "unpopulated" content. Three states: show all → hide empty (all-zero / all-0xFF / unused slots) → show only anomalies (failed checks, non-zero reserved, out-of-range values). |
| R-4.4 | A hex pane MUST show the bytes underlying the currently selected node, with those bytes highlighted in context. |
| R-4.5 | Different formats MUST be presented through one uniform widget set. A GPT entry and a FAT directory record look and behave the same way. |
| R-4.6 | The UI MUST remain responsive while a slow read is in flight; it MUST NOT block the event loop on I/O. |
| R-4.7 | Field documentation (what the field means, spec reference) SHOULD be available inline for supported formats. |
| R-4.8 | Colour MUST be meaningful and MUST degrade: the app MUST be usable on a 80×24 monochrome terminal. |

## 5. Navigation

| ID | Requirement |
|---|---|
| R-5.1 | A region tree MUST list everything discovered on the device (MBR, GPT primary/backup, each partition's volume header, FATs, directories) with offsets. |
| R-5.2 | Fields that reference a location MUST be followable with one key. An MBR partition entry jumps to the volume header at its starting LBA; a GPT entry likewise; a directory entry jumps to its first cluster. |
| R-5.3 | Following a link MUST push onto a jump stack with back/forward navigation. Jumping 40 GB away is disorienting without it. |
| R-5.4 | Jumping to an offset with no known structure MUST run format probing and offer whatever matches, or fall back to raw hex. |
| R-5.5 | Goto-by-absolute-offset, goto-by-LBA, and goto-by-cluster MUST all be available. |
| R-5.6 | Search by field label MUST be available within the current structure. |
| R-5.7 | The current position MUST always be expressible as a stable path string (e.g. `gpt.entries[2].first_lba`) usable for copy, bug reports, and future scripting. |

## 6. Copy

| ID | Requirement |
|---|---|
| R-6.1 | The decoded value of the selected field MUST be copyable as plain text. |
| R-6.2 | A labelled form (`label + raw + decoded + offset + size`) MUST be copyable. |
| R-6.3 | A whole table or a selected range of rows MUST be copyable as TSV so it pastes into a spreadsheet, an email, or a forum post. |
| R-6.4 | The raw bytes of the selected node MUST be copyable as a hex dump, and MUST be writable to a file. |
| R-6.5 | Copy MUST work over SSH and inside tmux. Native clipboard first, OSC 52 fallback, user-configurable command as an escape hatch, and a file under `$XDG_RUNTIME_DIR` always written so nothing is ever lost. |

## 7. Editing (deferred, but designed for now)

| ID | Requirement |
|---|---|
| R-7.1 | Edits MUST land in an in-memory overlay first. The device is untouched until an explicit commit. |
| R-7.2 | The view MUST render the overlay on top of the device and visually mark modified bytes, so you can see the consequences (including recomputed checksums) before committing. |
| R-7.3 | Editing MUST be possible at two levels: a typed field value (respecting its width/endianness/encoding), and raw bytes in the hex pane. |
| R-7.4 | Commit MUST show a byte-level diff and require explicit confirmation. |
| R-7.5 | Every committed write MUST be recorded in an undo journal stored **off the target device**, containing the offset, the original bytes and the new bytes. |
| R-7.6 | Any region MUST be dumpable to a file and restorable from a file. This is the coarse-grained backup/restore path and it MUST exist before the fine-grained one. |
| R-7.7 | Derived fields (CRC32s, checksums, mirrored copies such as the backup GPT or FAT#1) MUST NOT be silently recomputed. The app offers an explicit "recompute" / "mirror" action and shows the delta. |
| R-7.8 | The app MUST NOT refuse to write a value it believes is wrong. It warns; the user decides. |

## 8. Library separability

| ID | Requirement |
|---|---|
| R-8.1 | Core model, I/O, format parsers and TUI MUST live in separate crates in one workspace. |
| R-8.2 | No crate below the TUI may depend on `ratatui`, `crossterm`, or any terminal concept. Status and representation are semantic, not styled. |
| R-8.3 | A consumer MUST be able to depend on `blktamper-core` + one format crate and do useful work (e.g. a small "patch a GPT header" utility) without pulling in the TUI or the other formats. |
| R-8.4 | Format support MUST be feature-gated and registered through a registry, so builds can be trimmed. |
| R-8.5 | Public error types MUST be concrete enums, not `anyhow::Error`, so library consumers can match on them. |
| R-8.6 | `blktamper-core` SHOULD avoid `std`-only constructs where cheap, to keep an embedded/`no_std+alloc` port plausible. Not a hard requirement for v1. |

## 9. Quality

| ID | Requirement |
|---|---|
| R-9.1 | Golden test images MUST be generated by a committed script using standard tools (`sgdisk`, `fdisk`, `mkfs.vfat`, `mkfs.exfat`), not hand-crafted, so they are reproducible and trustworthy. |
| R-9.2 | Deliberately corrupted variants of each golden image MUST be tested — bad CRC, bad signature, truncated, overlapping partitions, non-zero reserved fields. |
| R-9.3 | Parsed output MUST be differentially tested against independent implementations (`gptman`, `mbrman`, `fatfs`, `sgdisk -p`, `fsck.*`) where they agree on a valid image. |
| R-9.4 | Every format parser MUST have a fuzz target asserting no panic and no unbounded allocation. |
| R-9.5 | Write paths MUST be tested only against image files in CI. Never against a block device. |
