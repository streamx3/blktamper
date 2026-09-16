# Architecture

## Crate layout

```
blktamper/                    workspace root
├─ crates/
│  ├─ blktamper-core/           model + traits + descriptor types
│  │   ├─ span.rs             Span, Extent  — bit-granular provenance
│  │   ├─ node.rs             Node, NodeKind, Children
│  │   ├─ value.rs            Value, Repr   — decode + render
│  │   ├─ desc.rs             FieldDesc, StructDesc, Check, LinkDesc
│  │   ├─ diag.rs             Diagnostic, Severity
│  │   ├─ path.rs             NodePath  ("gpt.primary.entries[3].first_lba")
│  │   ├─ probe.rs            FormatProbe, Registry
│  │   └─ source.rs           BlockSource / BlockSink traits
│  ├─ blktamper-io/             the only crate that knows about operating systems
│  │   ├─ file.rs             image files (portable)
│  │   ├─ linux/              open, BLKSSZGET/BLKPBSZGET/BLKGETSIZE64/BLKFLSBUF, mount detection
│  │   ├─ cache.rs            LRU block cache + readahead
│  │   ├─ overlay.rs          staged edits on top of a BlockSource
│  │   └─ journal.rs          off-device undo journal
│  ├─ blktamper-formats/        format knowledge; each behind a cargo feature
│  │   ├─ mbr/                feature "mbr"    (incl. EBR chain)
│  │   ├─ gpt/                feature "gpt"
│  │   ├─ fat/                feature "fat"    (FAT12/16/32, LFN)
│  │   ├─ exfat/              feature "exfat"
│  │   └─ registry.rs         registers enabled formats' probes + readers
│  └─ blktamper-tui/            ratatui app + `blktamper` binary
├─ fuzz/                      cargo-fuzz targets, one per format
├─ tests/fixtures/            generator script + xz'd sparse golden images
└─ doc/
```

Dependency direction, strictly one-way:

```
blktamper-tui ──► blktamper-formats ──► blktamper-core
     └─────────► blktamper-io ─────────────┘
```

`blktamper-formats` depends on `blktamper-core` only. It reads through the
`BlockSource` trait and has no idea whether it's talking to `/dev/sdc`, a file, or
a `Vec<u8>` in a test. That is what makes fuzzing and unit testing trivial.

---

## The core model

### Provenance

```rust
/// A contiguous run of bits on the device. Bit-granular because flag fields
/// (GPT attributes bit 60/62/63, FAT attribute bits, ext4 feature bits) need it.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Span {
    pub start_bit: u64,   // absolute, from byte 0 of the device
    pub len_bits:  u64,
}

/// Some nodes aren't contiguous: a file's data follows a cluster chain, an
/// exFAT directory entry set can straddle a cluster boundary, an LFN run is
/// stored in reverse. Those need a list.
#[derive(Clone)]
pub enum Extent {
    One(Span),
    Many(Vec<Span>),   // ordered, logical order (not necessarily ascending)
    None,              // synthetic/computed node with no bytes of its own
}
```

`Extent::Many` is the thing that most designs get wrong by adding it too late.
Adding it now costs one enum; adding it after the hex pane is written costs a
rewrite of the hex pane.

### Nodes

```rust
pub struct Node {
    pub label:    Cow<'static, str>,
    pub extent:   Extent,
    pub kind:     NodeKind,
    pub value:    Value,          // decoded
    pub repr:     Repr,           // how to render it
    pub status:   Status,         // Ok | Info | Warn | Bad | Unreadable
    pub diags:    Vec<Diagnostic>,
    pub links:    Vec<Link>,
    pub doc:      Option<&'static str>,
    pub children: Children,
}

pub enum NodeKind {
    Region,     // a whole discovered area: "GPT primary header", "Partition 1"
    Struct,     // an instance of a StructDesc
    Array,      // repeated records
    Field,      // a leaf with a value
    Group,      // logical grouping over non-contiguous parts (LFN run, entry set)
    Gap,        // bytes in the parent's range no field claimed  ← borrowed from fq
    Raw,        // uninterpreted bytes
}

pub enum Children {
    None,
    Resolved(Vec<Node>),
    /// Not expanded yet. `expand` gets the source and the parent's context.
    Lazy(Arc<dyn Expander>),
}

pub trait Expander: Send + Sync {
    fn expand(&self, src: &dyn BlockSource, ctx: &Ctx) -> Result<Vec<Node>, IoError>;
    fn hint_len(&self) -> Option<usize>;   // for scrollbar sizing without expanding
}
```

Three properties worth calling out:

- **`Children::Lazy` is mandatory, not an optimisation.** A FAT table on your 58 GiB
  stick is ~7 MB of entries. A directory can hold tens of thousands of records. The
  TUI only ever expands what's on screen plus a margin.
- **`NodeKind::Gap` is a feature.** After laying out a struct's fields, any bytes in
  range that no field claimed become a `Gap` node. On a healthy MBR there's one
  (the 446-byte bootstrap). Anywhere else, a gap is a bug in our descriptor *or*
  something interesting on the disk — both worth seeing.
- **`status` is semantic, never styled.** `Status::Bad` does not know it is red.

### Values and representation

```rust
pub enum Value {
    Unset,                       // not yet read / unreadable
    Uint(u64), Int(i64),
    Bytes(SmallVec<[u8; 16]>),
    Text(String),                // already-decoded text
    Guid([u8; 16]),
    Bool(bool),
    Composite,                   // has children instead
}

pub enum Repr {
    Hex { width: u8 },
    Dec,
    HexAndDec,
    Enum(&'static EnumTable),    // partition type byte, GPT type GUID, media descriptor
    Flags(&'static FlagTable),   // bit-per-line expansion
    Guid,                        // GPT mixed-endian layout, rendered canonically
    Chs,                         // legacy cylinder/head/sector unpacking
    Lba,                         // shows LBA and the byte offset it maps to
    Ascii { trim: bool },
    Utf16Le { lossy: true },     // always lossy; never refuse to show junk
    DosDateTime, UnixTime32, UnixTime64, NtTime, ExfatTimestamp,
    SizeBytes,                   // 120846336 → "57.6 GiB"
    Checksum { algo: ChecksumAlgo, covers: CoverSpec },
    Raw,
}
```

`Repr::Checksum` is what implements R-3.6: the renderer computes the expected value
over `covers` and shows `stored / computed`, so a bad CRC is visible without a
separate validation pass.

### Descriptors (Tier A of [ADR-002](03-decisions.md#adr-002-describe-records-as-data-write-traversal-as-code))

```rust
pub struct FieldDesc {
    pub name:   &'static str,
    pub off:    BitOff,            // offset within the struct
    pub width:  Width,
    pub repr:   Repr,
    pub doc:    &'static str,
    pub flags:  FieldFlags,        // RESERVED | MUST_BE_ZERO | DERIVED | LEGACY
    pub checks: &'static [Check],
}

pub struct StructDesc {
    pub name:   &'static str,
    pub size:   Option<u64>,       // None = variable, computed by the reader
    pub fields: &'static [FieldDesc],
    pub links:  &'static [LinkDesc],
    pub checks: &'static [Check],  // cross-field invariants
    pub spec:   &'static str,      // "UEFI 2.10 §5.3.2"
}

pub enum Check {
    Eq(Const), OneOf(&'static [Const]), Range(u64, u64),
    NonZero, Zero,
    Crc32 { covers: CoverSpec, stored: &'static str },
    Cross(&'static str),           // named invariant, resolved by the format module
}
```

Deliberately **no closures and no `fn` pointers** in `FieldDesc`. That keeps the
descriptor as plain data, which is what makes a future export to `.ksy`/`.hexpat`/JSON
possible (ADR-002, "keep the door open"). Anything needing real computation lives in
`Check::Cross` and is dispatched by name inside the format module — i.e. it's
explicitly Tier B.

### Links and navigation

```rust
pub struct Link {
    pub label: &'static str,       // "→ volume header"
    pub kind:  LinkKind,
}

pub enum LinkKind {
    ToByte(u64),
    ToLba(u64),                    // resolved with the session's sector size
    ToCluster(u64),                // resolved by the owning filesystem reader
    ToRegion(RegionId),            // e.g. primary GPT ↔ backup GPT
    ProbeAt(u64),                  // "something's here, figure out what"
}
```

`ProbeAt` is the mechanism behind your MBR-entry-to-filesystem-header jump. Following
it: convert LBA → byte offset using the session sector size, read a sector, run every
registered `FormatProbe`, pick the best-scoring match, open its reader, insert the
result into the region tree, and push the previous position onto the jump stack.

```rust
pub trait FormatProbe {
    fn id(&self) -> FormatId;
    /// Score 0..=100. Never errors, never panics. Cheap: one or two sectors.
    fn probe(&self, src: &dyn BlockSource, at: u64) -> u8;
    fn open(&self, src: &dyn BlockSource, at: u8) -> Box<dyn RegionReader>;
}

pub trait RegionReader {
    fn root(&self) -> Node;
    fn resolve(&self, path: &NodePath) -> Option<Node>;
    /// Turn a node edit into concrete byte writes. This is the *only* place a
    /// format may describe a mutation.
    fn encode(&self, path: &NodePath, v: &Value) -> Result<Vec<ByteEdit>, EncodeError>;
}
```

Scoring rather than a boolean matters: a FAT32 volume and an NTFS volume both start
with a jump instruction and an OEM name, exFAT's boot sector looks like FAT's until
byte 3, and a protective MBR looks like a real MBR. Ranked candidates with an
"interpret as…" override beats a confident wrong guess.

### Paths

```
mbr.entries[0].part_type
gpt.primary.header.crc32
gpt.backup.entries[3].first_lba
part[1].fat32.bpb.sectors_per_cluster
part[1].fat32.root/SUBDIR/FILE.TXT@0.first_cluster
```

One string that identifies any node. Used for: copy-with-context, the status bar,
the undo journal, bug reports, and eventually a non-interactive `blktamper get <path>`
mode which makes the library scriptable for free.

---

## I/O layer

```rust
pub trait BlockSource: Send + Sync {
    fn len(&self) -> u64;
    fn logical_sector_size(&self) -> u32;
    fn physical_sector_size(&self) -> u32;
    /// Never partial: fills buf or returns an error. Unreadable sectors produce
    /// ReadOutcome::Unreadable rather than zeros — a dying disk must look different
    /// from a zeroed one.
    fn read_at(&self, off: u64, buf: &mut [u8]) -> ReadOutcome;
}

pub trait BlockSink: BlockSource {
    fn write_at(&self, off: u64, data: &[u8]) -> Result<(), IoError>;
    fn flush(&self) -> Result<(), IoError>;
}
```

Stack, bottom to top:

```
LinuxBlockDevice / ImageFile        raw
  └─ BlockCache                     LRU of 64 KiB blocks, ~64 MiB budget, readahead
       └─ Overlay                   staged edits; reads return edited bytes
            └─ (parsers and UI see only this)
```

The overlay implements `BlockSource`, so **the entire parse and render path is
unaware that editing exists**. Change a byte and the CRC field recomputes on the
next render because it re-reads through the overlay. That's the whole trick, and it
is why the editor is cheap.

Threading: I/O runs on a worker thread; the UI thread never blocks (R-4.6). One
channel of requests, one of results, node expansion is async with a placeholder
"…" row while in flight.

---

## What is explicitly *not* in the model

- No `Result` from parsing. `RegionReader::root()` always returns a `Node`.
  Failure is expressed as `Status::Bad` + diagnostics on the relevant node.
- No ownership of decoded structs. Nothing holds a `Gpt` value; the tree over the
  bytes *is* the parsed form.
- No mutation outside `RegionReader::encode` → `Overlay` → explicit commit.
- No global state. A session is a value; two devices open side by side is a
  UI question, not an architecture question.

---

## What changed once it was built

The design above was written before any code. Recording where reality diverged is
more useful than quietly editing the document to look prescient.

### `blktamper-io` uses sysfs and procfs, not ioctls

The plan said `BLKSSZGET` / `BLKPBSZGET` / `BLKGETSIZE64` through `rustix` or `nix`.
The implementation reads `/sys/class/block/<name>/queue/logical_block_size` and
friends, and `/proc/self/mountinfo` for mount detection.

Better on three counts, and worth the change:

- **No `unsafe` and no `libc`.** Both `blktamper-core` and `blktamper-io` are
  `#![forbid(unsafe_code)]`, which matters for a program whose entire input is
  hostile bytes (ADR-008).
- **It is what `lsblk` does**, so it stays correct for loop devices, device-mapper
  targets and partitions — a partition has no `queue/` of its own and inherits its
  parent's, which the ioctl path hides and the sysfs path makes explicit.
- Device size comes from seeking to the end, which works on any block device and
  needs no sysfs at all.

The cost: it depends on `/sys` and `/proc` being mounted. On Linux they always are.
A FreeBSD port will need a different implementation either way.

### `Node` carries its raw bytes

The plan had provenance (`Extent`) but not the bytes themselves. Keeping
`Node::raw` means the raw column, the hex highlight, `y r` and `y h` never re-read
the device, and a node stays renderable after the source is gone. For the record
sizes in scope — 16 to 512 bytes — the duplication is not worth optimising away.

### `Node::derived` replaced a render-time computation

`Repr::Checksum` was going to compute its value while rendering. It became a
`Derived { value, matches, how }` attached at parse time instead, because:

- rendering should not do I/O or arithmetic that can fail;
- the same value is needed by the detail popup, the anomaly filter, and
  `recompute_edit_for` — computing it three times in three places invites three
  answers;
- it generalises past checksums to mirrored values (backup GPT, FAT #1), which is
  the same question asked of a different derivation.

### `RegionReader` lost `resolve` and `encode`

Both belong to the write path, which does not exist in this build. They are named in
the trait's documentation as the extension point rather than stubbed out — an
unimplemented method that returns `todo!()` is a panic waiting for a user.

### `Expander` does not take a `Ctx`

The plan passed a context alongside the source. In practice every expander captures
what it needs at construction time, which is simpler and makes the trait object
easier to store. The signature is `fn expand(&self, src: &dyn BlockSource) -> Vec<Node>`.

### The `entries` placeholder field

MBR's descriptor declares a 64-byte `entries` field covering `0x1BE..0x1FE`, and the
reader replaces that node's children with the parsed partition entries. The
alternative — leaving the range unclaimed — made the descriptor self-check report a
64-byte gap in every healthy MBR, which would have trained the eye to ignore gap
warnings. Every format with an inline array uses the same pattern.

### One real bug the design did not prevent

`common::read_desc_at` took both a read offset and a `ReadCtx`, and used the context's
`base` for provenance while reading from the offset. Every partition entry therefore
reported offset 0. It was invisible in unit tests (which pass `ReadCtx::at(0)` and
read at 0) and obvious the moment the tool was pointed at a real disk.

`read_desc_at` now overwrites `ctx.base` with the read offset, and a test asserts it.
The general lesson is in the fix's comment: *a viewer whose offsets are wrong is worse
than no viewer*, so the two parameters must not be independently settable.
