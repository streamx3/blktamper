# Decisions

These are the answers to the questions you asked, plus the places where I think
you're wrong. Each is a proposal, not a fait accompli — argue back.

---

## ADR-001: Don't build on the existing filesystem/partition crates

**Status:** proposed
**Question:** "Should we use existing libraries or create our own?"

### Decision

Write our own parsing layer. Use third-party crates for *infrastructure*
(terminal, ioctls, CRC, UUID, clipboard) and for *testing*. Do not use `gptman`,
`mbrman`, `fatfs`, `ext4`, `binrw`, `deku` or Kaitai-generated code in the view path.

### Why

Your instinct — "tying them all together and making a bunch of adapters will not
take more work than writing it all from scratch" — is the right instinct, but the
reason is sharper than adapter tax. **It's a shape mismatch, not an impedance
mismatch.** Those libraries make three commitments that are each individually fatal
here:

1. **They return `Result` and refuse bad data.** `GPT::read_from()` fails on a CRC
   mismatch. But a GPT with a bad CRC is *the single most interesting thing this
   app will ever be asked to display*. R-3.1 says parsing must never fail. You
   cannot retrofit "don't fail" onto a library whose API is `Result<T, E>` — you'd
   be reimplementing the parser in the error path.

2. **They discard byte provenance.** `gptman` gives you `header.first_usable_lba:
   u64`. It does not tell you that value lives at offset 0x228, 8 bytes, little
   endian. Every single feature you care about — the hex pane highlight, the editor,
   "copy with offset", "hide empty" — is downstream of provenance. Reconstructing it
   means maintaining a parallel offset table, at which point that table is the real
   parser and the crate is dead weight.

3. **They normalise.** `gptman::PartitionName` is a `String`. A GPT partition name
   on a damaged disk is 72 bytes that may not be valid UTF-16. Normalising destroys
   exactly the evidence you opened the tool to see. Same for `fatfs`: it presents
   files and directories, deliberately hiding the cluster chain that you want to
   look at.

Put bluntly: those crates are built so a program can *use* a filesystem. This app
exists so a human can *inspect* one. Almost no code is shared between those goals.

`binrw`/`deku`/`zerocopy` fail for reason 2 only, but that's enough. All of them
produce `struct Foo { a: u32, b: u16 }`. This app needs
`[Field{"a", 0..4}, Field{"b", 4..6}]` — a value you can iterate, filter, label and
point back at bytes. Going from the struct to the field list needs reflection, which
Rust doesn't have. Going from the field list to the struct is trivial. So the field
list is the primary artefact.

### Where existing work *is* reused

| Thing | How |
|---|---|
| Format knowledge | libyal asciidoc specs, Microsoft exFAT spec, UEFI spec, Kaitai `.ksy` and ImHex `.hexpat` as cross-checks for offsets |
| Partition type tables | The *data* from `fdisk`/`sgdisk`/Wikipedia. ⚠ util-linux and gdisk are GPL-2; this repo is MIT. Transcribe the facts (type byte → name), don't copy source files. |
| Differential testing | `gptman`, `mbrman`, `fatfs`, plus `sgdisk -p`, `fdisk -l`, `fsck.vfat -n`, `dumpe2fs` as oracles on valid images |
| Image generation | `mkfs.vfat`, `mkfs.exfat`, `sgdisk`, `fdisk`, `losetup` |

This is the best of both worlds: all of the accumulated knowledge, none of the
runtime coupling, and a test suite that's stronger than anything we'd write alone.

### Cost of being wrong

Low and recoverable. If the hand-written GPT parser turns out to be a slog, we can
always add `gptman` as a *second opinion* rendered in a side pane. The architecture
permits it; the default path doesn't depend on it.

---

## ADR-002: Describe records as data, write traversal as code

**Status:** proposed
**Question:** "Will it not be simple to describe all the partition tables and FS
headers as some data format, and use them later?"

### Decision

Split every format into two tiers.

**Tier A — fixed-layout records. Described as data.**
MBR, MBR partition entry, EBR, GPT header, GPT entry, FAT BPB, FAT32 EBPB, FSInfo,
exFAT boot sector, exFAT directory entries, ext4 superblock, ext4 inode, LUKS header.
These are flat: a name, an offset, a width, an endianness, a way to render it,
a doc string, and optional checks. One line of table each.

```rust
// Illustrative — see 04-architecture.md for the real shape.
pub const MBR_PART_ENTRY: StructDesc = StructDesc {
    name: "MBR partition entry",
    size: 16,
    fields: &[
        f("status",     0x00, W::U8,       R::Enum(&MBR_STATUS),  "0x80 = active"),
        f("chs_first",  0x01, W::Bytes(3), R::Chs,                "legacy CHS of first sector"),
        f("part_type",  0x04, W::U8,       R::Enum(&MBR_TYPES),   "partition type byte"),
        f("chs_last",   0x05, W::Bytes(3), R::Chs,                "legacy CHS of last sector"),
        f("lba_first",  0x08, W::U32le,    R::Lba,                "starting LBA"),
        f("num_sectors",0x0C, W::U32le,    R::Dec,                "length in sectors"),
    ],
    checks: &[Check::Cross("lba_first + num_sectors <= device_sectors")],
    links:  &[Link::from("lba_first", LinkKind::ProbeAtLba)],
};
```

**Tier B — traversal. Written as ordinary Rust.**
Where is the backup GPT? Follow a FAT cluster chain. Walk the EBR linked list.
Group an exFAT directory entry set and verify its set checksum. Group FAT LFN runs
in reverse order. Walk an ext4 extent tree. Decide which of two mirrored FATs to
trust.

### Why split

Because the two halves have opposite economics.

- Tier A is ~80% of the *field count* and ~5% of the *thinking*. Describing it as
  data buys you the viewer, the editor, the "hide empty" filter, the TSV copy, the
  doc tooltips and round-trip writes — **for every format, for free, forever.** Not
  doing it as data means writing that UI plumbing once per format. That's the
  actual win, and it's large.
- Tier B is ~20% of the field count and ~80% of the thinking and essentially all of
  the bugs. Every declarative format I looked at handles this badly. Kaitai does it
  with `instances` and an expression language; ImHex does it by being a C-like
  programming language wearing a description-format hat. **When your data format
  needs loops, conditionals and arithmetic on previously-parsed values, you have
  written a programming language — and a worse one than Rust**, with no type
  checking, no debugger, no `cargo test`, and a compiler you also have to maintain.

So: data where data wins, code where code wins. Don't let purity push the boundary.

### Why not Kaitai / ImHex / DFDL as the runtime format

1. They describe layout, not semantics. Neither the `gpt_partition_table.ksy` nor
   the Kaitai `vfat.ksy` has a single enum. No partition-type names, no reserved-field
   semantics, no cross-field invariants, no human documentation, no link targets.
   We'd need a sidecar for all of that, and then the sidecar and the `.ksy` disagree.
2. Kaitai's Rust backend is the newest of twelve, shipped September 2025, and the
   generated code has the wrong shape anyway (owned structs, `Result`-returning).
3. Interpreting an external format at runtime adds a parser, an expression
   evaluator and a whole class of "the description file is wrong" errors, in exchange
   for an edit-without-recompile loop that you don't need — you are the only author
   and you have `cargo build`.

### But keep the door open

The descriptor is deliberately **plain data with no closures** wherever possible
(`Repr` and `Check` are enums, not `fn` pointers). That means a `blktamper-fmt-export`
tool can later emit `.ksy`, `.hexpat`, or JSON from the same tables — and a future
`blktamper` could load descriptors from a file if you ever want third-party format
plugins. Designing for that costs nothing today; implementing it today costs weeks.

### Size estimate

Scopes 0–2 (MBR + FAT32 + exFAT + GPT) are roughly **220 field descriptors**,
≈300 lines of table, plus ~1000–1400 lines of Tier-B traversal. See
[06-format-scope.md](06-format-scope.md) for the breakdown. This is a small project
that is mostly UI.

---

## ADR-003: Provenance-first data model

**Status:** proposed

### Decision

The central type is not a parsed struct. It is a lazily-expanded tree of nodes over
a byte source, where every node carries its exact extent(s) in bits, its raw bytes,
its decoded value, its validation status, and its outbound links.

Full definition in [04-architecture.md](04-architecture.md).

### Why this is the most important decision in the project

You said: *"I need viewing VERY much. I need writing somewhat."*

Take that seriously and it forces this model. Viewing means showing bytes with
labels. Editing means changing bytes behind a label. **They are the same operation
read in two directions**, and they're only the same operation if the label knows
which bytes it owns. Build the model provenance-first and the editor is a few
hundred lines on top of the viewer. Build it struct-first and the editor is a second
parser written backwards — which is how you get an editor that corrupts disks.

The same property gives you, with no extra work: the hex-pane highlight, copy-with-offset,
"jump to the bytes", "hide all-zero", gap detection (bytes no field claimed — a
genuinely useful anomaly signal, borrowed from `fq`), and the overlay diff view.

---

## ADR-004: Do GPT before FAT32/exFAT

**Status:** proposed — **this one contradicts your stated order**

### Your order

`0) MBR → 1) FAT32, exFAT → 2) GPT`, implement through 2.

### Proposed order

`MBR → GPT → FAT32 → exFAT`, still implement all four.

### Why

GPT is cheap and exFAT is not, and doing the cheap one second gets the architecture
validated weeks earlier.

- **GPT is ~20 fields, one CRC32, and an array.** It shares essentially all its
  machinery with MBR: fixed-size records, an entry array, LBA→offset arithmetic.
  It is maybe two days of work once MBR exists.
- **exFAT is a boot *region*, not a sector**: 12 sectors including an extended boot
  region, an OEM parameters sector, and a boot *checksum* sector covering the whole
  region — plus the FAT, the allocation bitmap, the up-case table, and directory
  **entry sets** where a file is a primary entry plus a stream-extension entry plus
  N filename entries, with their own set checksum. It's a week-plus, and it's the
  one place where Tier B gets genuinely intricate.

Putting GPT second buys you, before you spend that week:

1. Two formats through the same descriptor machinery — the first real proof that
   the uniform model works, and the first chance to find out it doesn't.
2. The **protective MBR ↔ GPT relationship**, which is the first *cross-format*
   link and exercises R-5.2 properly.
3. **Primary vs backup header comparison** — a diff view between two regions, which
   you'll want again for FAT#0 vs FAT#1 and for exFAT's main vs backup boot region.
4. CRC validation with stored-vs-computed display (R-3.6) on the simplest possible
   case before you meet exFAT's boot checksum.

And practically: your test device `/dev/sdc` is MBR + a FAT/exFAT partition. You
need a GPT disk to test against anyway, and making one is `sgdisk` on a loop file —
so GPT is also the format with the cheapest test fixtures.

### If you disagree

The stated order still works; it's a schedule question, not a correctness one.
Nothing in the architecture depends on it. Say the word and 08-roadmap.md flips.

---

## ADR-005: Three other things in your format ladder are mis-ranked

**Status:** informational — you may have meant something I'm not seeing

1. **"UEFI" (rank 3) is not a filesystem.** The EFI System Partition is FAT32 (or
   FAT16), so it's already covered by rank 1. If you meant something else — the
   boot-entry structures, `\EFI\BOOT\BOOTX64.EFI`, UEFI variable stores, or the
   `efivarfs` NVRAM layout — say so, because that's a different and much more
   interesting piece of work. If you meant "make sure we can browse an ESP", that
   falls out of FAT32 for free.

2. **ext2 is ranked 7 but ext3 is ranked 3.** They share a superblock. `ext2`,
   `ext3` and `ext4` are one parser with different feature-flag bits set; the
   `s_feature_compat` / `s_feature_incompat` / `s_feature_ro_compat` fields are what
   distinguish them. Doing "ext4" gets you all three superblocks immediately;
   the real extra work in ext4 is extent trees vs ext2/3's indirect block maps, and
   ext2/3's are *simpler*. Rank them together.

3. **LUKS (rank 4) is much cheaper to *view* than its rank implies.** A LUKS1
   header is a small fixed struct plus 8 key slots. A LUKS2 header is a binary
   header plus a **JSON** metadata blob — genuinely easy to display, and arguably
   the single highest value-per-line format in your whole list, because when LUKS
   goes wrong people are desperate and there is no good viewer. Note the honest
   split: *viewing* the header is easy; *decrypting* requires Argon2/PBKDF2 and
   real crypto, is a completely separate project, and should probably never be in
   scope. Consider promoting LUKS-header-view to right after GPT.

---

## ADR-006: Workspace of four crates now, split further only when it hurts

**Status:** proposed
**Question:** "I want this program to be separatable."

### Decision

Start with a Cargo workspace of four crates, with internal module boundaries drawn
where future crate splits would go:

```
blktamper-core     model, traits, descriptor types. No I/O, no UI, no format knowledge.
blktamper-io       block device + file backends, overlay, undo journal. Platform-gated.
blktamper-formats  mbr / gpt / fat / exfat modules behind cargo features, + a registry.
blktamper-tui      ratatui app + the binary.
```

### Why not one crate

Because you'd never get it apart afterwards. The specific thing that kills
separability is not module layout — it's a `Color` or a `ratatui::Span` leaking into
the model, or `anyhow` in a public signature. A crate boundary makes that a compile
error instead of a code review. That check is worth having from commit one, and it
costs an afternoon.

### Why not eight crates

Because `blktamper-fmt-mbr` as its own crate, before MBR is written, is a guess about
where the seam is. Modules inside `blktamper-formats` give the same discipline and
splitting a module into a crate later is mechanical. Split when a real consumer
appears who wants GPT without FAT — then the feature flags already work and the
split is a `Cargo.toml` edit.

### Hard rules that make it real (enforced in CI)

- `blktamper-core` may not depend on `ratatui`, `crossterm`, `tokio`, or `std::fs`.
- No crate below `blktamper-tui` may name a colour, a key, or a terminal.
- Public errors are `thiserror` enums. `anyhow` may appear in `blktamper-tui` only.
- `cargo build -p blktamper-core` and `cargo build -p blktamper-formats --no-default-features
  --features gpt` must both succeed. If they don't, the layering is broken.

### The consumer you described, concretely

> "an app that only does some limited reads/writes with partition table/FS headers"

```toml
[dependencies]
blktamper-core    = "0.1"
blktamper-io      = "0.1"
blktamper-formats = { version = "0.1", default-features = false, features = ["gpt"] }
```

…and you get: open device, parse GPT into a node tree, find the node by path
`gpt.primary.first_usable_lba`, write a new value through the overlay, commit with
journal. No terminal, no FAT code, no MBR code.

---

## ADR-007: Read-only by default, staged writes, off-device undo journal

**Status:** proposed

### Decision

Four gates between you and a corrupted disk, none of which prevent you from
corrupting it deliberately:

1. Device opened `O_RDONLY` unless `--rw` is passed on the command line.
2. `--rw` still only *permits* arming. Writing requires an in-app arm action that
   names the device.
3. All edits go to an in-memory overlay. The device is untouched until commit.
4. Commit shows a byte diff, requires confirmation, and appends the original bytes
   to a journal file stored off-device before writing.

Details and the Linux-specific hazards in [07-write-safety.md](07-write-safety.md).

### Why, given you already said you accept corruption

You accept corruption *you chose*. These gates only block corruption you *didn't*
choose — a stray keypress in a table view, or a write landing on the wrong device
because you had two sticks plugged in. None of them stop you from writing `0xFF`
over a GPT header on purpose; ADR-007 explicitly rejects any "are you sure that's a
valid value" veto (R-7.8).

The overlay is the interesting one, and it's not primarily a safety feature: it's
what makes "edit a value and watch the CRC32 turn green before you commit" possible.
That's a genuinely better editing experience than any of the Windows disk editors
offer, and it falls out of the model for free.

---

## ADR-008: Rust, not C or C++

**Status:** proposed
**Question:** "Will it make your job any easier if we switch to C/C++?"

### Decision

Stay on Rust. The architecture is not language-specific — the descriptor tables,
node tree, provenance model and overlay all port to C++23 directly — but the
*enforcement* of this project's central invariant does not.

### The honest case *for* C/C++

Not zero. Three real points:

1. **The libraries live in C.** libyal (`libfsext`, `libfsfat`, `libfsntfs`,
   `libfsapfs`, `libluksde`, …) and The Sleuth Kit are C/C++. If the plan were to
   link real implementations, C++ is where they are and Rust would need FFI.
2. **ImHex's pattern interpreter (`libpl`) is C++** and could be embedded directly.
3. **Struct casting over a buffer** — `struct mbr_entry *e = (void*)(buf + 0x1BE)` —
   is genuinely terser than descriptor tables, if that were the design.

All three collapse against decisions already made. [ADR-001](#adr-001-dont-build-on-the-existing-filesystempartition-crates)
rejected those libraries on *shape* grounds — they validate, refuse, and discard
byte provenance — and that reasoning is language-independent: `libfsfat` gives you
a filesystem API, not a field table. [ADR-002](#adr-002-describe-records-as-data-write-traversal-as-code)
rejected a runtime-interpreted pattern language. And [ADR-003](#adr-003-provenance-first-data-model)
rejected struct casting in favour of descriptor tables, so the terser C idiom never
gets used.

There is also a licensing problem. This repo is MIT. libyal is **LGPL-3.0-or-later**
(static linking triggers relinking obligations); The Sleuth Kit is
**IPL-1.0 AND CPL-1.0 AND GPL-2.0-or-later**, and CPL is GPLv3-incompatible. Linking
either is a licensing decision before it is a technical one.

### The case against, which is specific rather than general

**R-3.1 and R-3.7 are the product**: parsing must never fail and never panic on
arbitrary input. Every byte this tool reads is potentially adversarial garbage —
that is the *use case*, not an edge case.

- In Rust, an out-of-bounds read is a panic. A fuzzer finds it deterministically and
  it becomes a bug report.
- In C, it is a silent read of adjacent memory that renders as a plausible-looking
  field value. **In a forensic viewer that is strictly worse than a crash, because
  you will believe it.** The entire value proposition is "the labels are not lying
  to you."

Then the arithmetic. Offsets are `u64` across multi-TB devices, and cluster math
(`cluster_count × sectors_per_cluster × bytes_per_sector`) overflows trivially on a
corrupt header — which is exactly the input we expect. C wraps silently and you
confidently display the wrong sector. Rust offers `checked_mul`/`saturating_*`, and
this project should additionally set `overflow-checks = true` in the release
profile, trading a little speed for never silently wrapping an offset.

Secondary, but real:

- **Exhaustive `match`** on `Repr` / `Check` / `NodeKind` means adding a variant is a
  compile error everywhere it must be handled. A missing `switch` case is a runtime
  fallthrough.
- **Ownership of the node tree.** Lazy children plus a block cache plus borrowed
  slices into cached blocks is precisely where use-after-free lives. The borrow
  checker is doing real work here, not ceremony.
- **[ADR-006](#adr-006-workspace-of-four-crates-now-split-further-only-when-it-hurts)
  is unenforceable in C.** "No terminal type below the TUI layer" is a compile error
  with Cargo and a code-review convention with CMake.
- **`cargo fuzz` is an afternoon.** ASan/UBSan/libFuzzer plumbing is not, and in C
  we would spend that budget on memory bugs instead of logic bugs.

### The one thing that would change this

If the author is materially more fluent in C++, that outweighs most of the above —
on a solo project, the maintainer's fluency usually dominates. The exception is the
never-lie-on-garbage-input invariant, which is a property of the problem, not of
taste.

### The genuine fork in the road

There is a different, legitimate product hiding here: **a TUI front-end for The
Sleuth Kit**. C++, links `libtsk`, gets volume listing and file browsing across
NTFS/ext/FAT/HFS+/APFS almost for free.

It is much less work and a different tool: TSK gives you *files and volumes*, not
field-level view and edit of raw headers. No labelled GPT header, no editing, no
"show me the bytes this label came from." If that product is what's actually wanted,
C++ is the right call and most of these documents should be thrown away. It isn't
what [01-requirements.md](01-requirements.md) describes.

---

## ADR-009: What this is actually for, and what that changes

**Status:** accepted — stated by the author 2026-09-16

### Context

The tool exists to verify what [`sanitize`](https://github.com/streamx3/sanitize)
actually destroys. `sanitize` is a recursive secure-delete utility that overwrites
file contents, renames files before unlinking them, and reports honestly that on
modern filesystems it can only achieve NIST "clear", not "purge" — overwriting a
file does not reliably overwrite that file's blocks.

blktamper is the instrument that checks that claim from the other side: open the
device, look at the filesystem metadata directly, and see what survived.

### What this changes

It moves the priority from "browse a filesystem" to **"show the residue"**, and the
author was explicit about this: *"I'm not that much interested in viewing folders in
custom UI. I can do that elsewhere. I would want to have a FS table viewer for
folders and files... I want to figure out what FS entries were just deleted."*

So:

1. **The directory view is a table of records, not a file browser.** A FAT32
   directory is 32-byte entries; an exFAT directory is entry sets. Show them as what
   they are. Do not build a file manager — every OS already has one, and a file
   manager's job is precisely to hide the records we came to see.
2. **Deleted records are first-class content, not an edge case.** FAT's `0xE5`
   tombstones, orphaned long-filename fragments whose 8.3 entry is gone, exFAT
   entries whose type byte has had bit 7 cleared. These are shown by default and
   marked, never filtered out.
3. **Slack and unclaimed bytes matter.** `NodeKind::Gap` already models bytes no
   field claimed; a non-zero gap in a structure that should be zero is exactly the
   evidence being looked for. The "anomalies only" filter (`z`, third state) is the
   view that answers "did anything survive?".
4. **Unused-but-not-zero is a finding.** An MBR slot that reads as empty while still
   holding CHS bytes from a previous table gets an explicit diagnostic. Implemented
   in `mbr::annotate_entry`.
5. **Rotational vs solid-state is worth displaying.** It changes what "overwriting a
   block" even means, which is the crux of `sanitize`'s own caveat. `blktamper-io`
   reads it from sysfs.

### What it does not change

The write path stays deferred, and stays gated. Verifying a deletion tool does not
require writing anything; it requires reading very carefully.

---

## ADR-010: Answers to the open questions

**Status:** accepted — answered by the author in `09-open-questions.md`, 2026-09-16

| Question | Answer | Consequence |
|---|---|---|
| Format order (ADR-004) | Accepted | MBR → GPT → FAT32 → exFAT |
| What "UEFI" meant | The ESP, i.e. FAT32 | No separate work; covered by rank 1 |
| TUI layout | "Somewhat" — see ADR-009 | Directory view becomes a record table |
| TSV copy | "Make it and test" | `y t` emits TSV; revisit after use |
| Non-block sources | `.img` only; SSH, compressed and proprietary formats dropped | `BlockSource` may assume cheap seeking |
| MTD / SPI flash | "Little to not at all" | Out of scope; no OOB channel in `BlockSource`. Retrofit cost accepted. |
| Privileges | `sudo` is fine | No privileged helper. `open_path` explains `EACCES` and exits. |
| Name | `blktamper` | Renamed throughout, including the GitHub repository (`streamx3/blktamper`). The local working directory keeps its old name, which is independent of both and harmless. |

Two consequences worth stating plainly:

- **Dropping non-seekable sources is load-bearing.** The whole design assumes it can
  read the last sector of a device to find the backup GPT. Reversing this later
  means rewriting every reader.
- **Dropping MTD means `BlockSource` has no out-of-band channel.** Adding jffs2 or
  SPIFFS later needs spare-area access and an erase-block concept, and retrofitting
  that is a breaking change to the core trait. Accepted deliberately.

---

## ADR-011: Scrubbing recoverable records

**Status:** accepted 2026-09-16, revised the same day after the threat model was stated

### Threat model

Stated by the author: **an opponent is a technician at a competitor who gets hold of
the flash drive, and must not be able to learn business plans even from file names.**
Explicitly *not* a government, intelligence or military adversary.

That calibration decides several things below. It is why filenames are the asset, why
"looks unremarkable" matters as much as "is empty", and why physical erasure is out of
scope rather than an unmet requirement.

### Modes

Four, in decreasing thoroughness and increasing caution:

| Mode | Scope | What it leaves | Writes |
|---|---|---|---|
| **compact** *(default)* | directory | nothing: deleted records removed, survivors closed up, every vacated byte zeroed | the whole directory |
| **sweep** | directory | tombstones only where they sit between live records; the tail fully zeroed | changed records only |
| **neutral** | one record set | the deleted marker, payload zeroed | one sector |
| **zero** | one record set | nothing in that record | one sector |

**`compact` is the default** because it is the only mode that leaves no tombstone at
all, and a tombstone with a zeroed payload is exactly the "suspicious as hell" state
the threat model rules out: it says a file was deleted and scrubbed, which is more
informative to an opponent than an ordinary deletion would have been.

It is feasible because **neither FAT nor exFAT has positional back-references**.
Nothing points at "record 6 of this directory" — a subdirectory's `..` names the
parent's *cluster*, and the FAT and allocation bitmap are keyed by cluster. Survivors
can therefore move. (NTFS would be a different story: MFT references are positional.)
The order-preserving pack keeps a long-filename run adjacent to its 8.3 entry and an
exFAT entry set contiguous, and `.`/`..` stay first because they are live and already
first.

**Everything the survivors vacate is zeroed in full**, not merely marked free. A slot
marked free whose remaining 31 bytes still hold a name is the residue this exists to
remove, and both directory modes clear it — including records that were *already*
marked never-used but not erased.

### Why random fill was rejected

Offered and turned down. The reasoning is counter-intuitive enough to keep: **random
bytes are more conspicuous than zeros.** A directory cluster a formatter never used is
zeros, so noise written into one announces that somebody scrubbed there, while zeros
are indistinguishable from space that was never allocated. There is also no multi-pass
argument on 32 bytes inside one sector — one pass either landed or it did not.

### Zeroing warns, it does not refuse

An earlier revision refused `zero` when live records followed. That was wrong twice
over:

- It contradicted **R-7.8** — *"The app MUST NOT refuse to write a value it believes
  is wrong. It warns; the user decides."*
- It overstated the consequence. `0x00` in a FAT name's first byte, or an exFAT
  `entry_type`, means *stop scanning*, so zeroing ahead of live entries makes the OS
  stop seeing them — but their records and their data are byte-for-byte untouched,
  blktamper still shows them, and undo restores reachability. **Hiding is not
  destroying**, and the tool may not blur the two.

So the dialog names the affected files, states the consequence, and lets the user
proceed. It also points out that `compact` achieves the same end without hiding
anything.

### Rejected: cascading the zero

"Zero this record and everything after it" was proposed and is right only when what
follows is already deleted. Where live records are interleaved it destroys their
directory entries — names, sizes and cluster pointers gone, clusters still marked
allocated with nothing pointing at them. That turns a reversible problem into an
irreversible one. `compact` is the correct answer to the same wish.

### Markers: exhaustive when looking, conservative when writing

The author's instruction was not to let filesystem markers decide what is still there.
Adopted, with one asymmetry that has to be stated because taking it literally would
break the safety model:

- **Discovery must not trust markers.** The listers already walk past the
  end-of-directory marker and flag residue in never-used records; the scrub guards and
  the directory layout now do the same. A record past the terminator is invisible to a
  driver and just as readable on disk.
- **Destruction must trust them.** The only thing distinguishing a live record from a
  deleted one *is* that byte. Stop trusting it and there is no basis for refusing to
  scrub a live file.

Live records are therefore never touched, and a directory-wide mode reads the whole
allocated extent rather than stopping where a driver would.

### Scope: records, not file contents

**blktamper scrubs metadata. It does not overwrite file data.** That is
[`sanitize`](https://github.com/streamx3/sanitize)'s job. It is also a limit rather
than only a division of labour: the delete has already released the cluster chain, so
only a deleted file's **first** cluster is knowable from its metadata. A command
offering to "scrub the file data" while reaching one cluster would be lying.

### Scope: logical, not physical

Out of scope by decision. Whether overwriting a logical sector reaches the physical
cell is the FTL's business, and on flash it generally does not. The stated position is
that this belongs at a different layer — an encrypted container from the start, or a
destroyed device. blktamper reports what it knows (`rotational` comes from sysfs) and
promises nothing it cannot keep.

### The gap this does not close

Compaction cleans the directories it is pointed at. It does not reach:

- **Deleted directories.** Their cluster chain is released, so their contents are not
  reachable by following anything, and blktamper will not show them at all.
- **Former directory clusters.** A directory that grew and shrank leaves old records
  in clusters nothing references any more.

Both hold filenames, and both are exactly what the stated opponent would look for.
Reaching them means scanning the data area for directory-shaped clusters — carving,
which [01-requirements.md](01-requirements.md) excludes. **That exclusion is now the
limiting factor on the threat model, and it is an open decision.**

