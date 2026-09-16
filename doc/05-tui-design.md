# TUI design

**This is the document to review.** Everything here is a proposal.

## Design rules

1. **Three panes, always the same three.** Regions tree (where am I), field table
   (what is here), hex (what bytes is that). Every format uses the same three.
2. **The hex pane is the proof.** Whatever row is selected, its bytes are
   highlighted in the hex pane. This is the feature that makes the tool
   trustworthy: you can always see that the label isn't lying to you.
3. **Never hide that something is there.** Filters hide *empty*, never *unknown*.
   An unparsed gap is shown as a gap.
4. **Modal-light.** Vim-ish movement because the audience already knows it, but no
   hidden modes: the status bar always states the current mode.
5. **Single-width glyphs only in layout.** No emoji, no `⚠`, no box-drawing in table
   cells. East-Asian-ambiguous characters render 1 or 2 columns depending on
   terminal and break every alignment. Status is a single ASCII glyph plus colour.
6. **80×24 must work.** Below ~100 columns the tree pane collapses to a breadcrumb.

## Main screen

```
+- blktamper - /dev/sdc - 57.7 GiB - 512/512 B - RO - sdc1 MOUNTED ---------------------------------+
| Regions                     | MBR > entries > [0]                                               |
|-----------------------------|-------------------------------------------------------------------|
| v /dev/sdc            0     |   Field                Raw                  Decoded               |
|   v MBR               0     |   status               00                   not bootable          |
|     . bootstrap       0     | + chs_first            00 82 03             h0 s2 c3              |
|     v entries       1BE     | * part_type            0C                   FAT32 LBA (CHS off)   |
|       > [0] 0C FAT32        | + chs_last             FE FF FF             h254 s63 c1023        |
|       > [1] --              |   lba_first            00 08 00 00          2048  -> 0x00100000   |
|       > [2] --              |   num_sectors          00 30 33 07          120,795,136           |
|       > [3] --              |                                                                   |
|     . signature     1FE     |                                                                   |
|   v Partition 1             | ! chs_last is the FE FF FF CHS-overflow placeholder: this         |
|     > FAT32 VBR   100000    |   partition is not representable in CHS. LBA only.                |
|     > FSInfo      100200    |                                                                   |
|     > FAT #0      104000    |                                                                   |
|     > FAT #1      52A000    |                                                                   |
|     > Root dir    950000    |                                                                   |
|-----------------------------+-------------------------------------------------------------------|
| Hex  0x000001BE..0x000001CD                                                     [2/16 selected] |
| 000001A0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|                  |
| 000001B0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00[82] |................|                  |
| 000001C0 [03 0C]FE FF FF 00 08 00  00 00 30 33 07 00 00 00  |..........03....|                  |
| 000001D0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|                  |
+-------------------------------------------------------------------------------------------------+
| NORMAL  mbr.entries[0].part_type  u8 @0x000001C2 (1 B)   filter:all   RO      ? help  : command |
+-------------------------------------------------------------------------------------------------+
```

Notes on what's shown:

- `[0] 0C FAT32` in the tree: unused MBR slots render as `--` and disappear under
  the "hide empty" filter.
- Gutter glyphs, left of the field name:
  `(space)` ok · `+` collapsible · `*` has a link to follow · `!` warning ·
  `X` failed check · `?` unknown/unreadable · `~` edited in overlay · `r` reserved.
- `lba_first` shows both the LBA and the byte offset it resolves to. That
  conversion is the single most common thing you do by hand with a calculator, so
  it's always on screen.
- The diagnostic panel under the table is only as tall as it needs to be.
- The hex pane highlights the selected field's bytes with `[ ]` brackets (colour
  in the real thing; brackets keep it readable in monochrome and in this mockup).

## GPT view, showing checksum verification

```
+- blktamper - gpt-test.img - 16.0 GiB - 512/512 B - RO ------------------------------------------------+
| Regions                     | GPT > primary > header                                                |
|-----------------------------|-----------------------------------------------------------------------|
| v gpt-test.img        0     |   Field                Raw                  Decoded                   |
|   . Protective MBR    0     |   signature            45 46 49 20 50 41..  "EFI PART"                |
|   v GPT primary     200     |   revision             00 00 01 00          1.0                       |
|     > header        200     |   header_size          5C 00 00 00          92                        |
|     > entries       400     | X header_crc32         A1 3F 22 90          stored   A13F2290         |
|   v GPT backup              |                                             computed 7C41BE05  BAD    |
|     > entries 3FFFFBE00     | r reserved             00 00 00 00          0                         |
|     > header  3FFFFFE00     |   my_lba               01 00 00 00 00 00..  1                         |
|   v Partitions              | * alternate_lba        FF FF FF 01 00 00..  33,554,431 -> 0x3FFFFFE00 |
|     > 1 EFI System          |   first_usable_lba     22 00 00 00 00 00..  34                        |
|     > 2 Linux filesystem    |   last_usable_lba      DE FF FF 01 00 00..  33,554,398                |
|     > 3 Linux LUKS          |   disk_guid            8C 3B 21 D4 ...      8c3b21d4-...-9f01         |
|                             | * entries_lba          02 00 00 00 00 00..  2 -> 0x400                |
|                             |   num_entries          80 00 00 00          128                       |
|                             |   entry_size           80 00 00 00          128                       |
|                             |   entries_crc32        4B 2E 91 00          stored   4B2E9100         |
|                             |                                             computed 4B2E9100  OK     |
|-----------------------------+-----------------------------------------------------------------------|
| X header_crc32 mismatch. The primary header differs from the backup in 3 fields.                    |
|   [d] diff primary vs backup    [r] recompute into overlay    [g] go to backup header               |
+-----------------------------------------------------------------------------------------------------+
| NORMAL  gpt.primary.header.header_crc32  u32le @0x00000210 (4 B)   filter:all   RO                  |
+-----------------------------------------------------------------------------------------------------+
```

This is the payoff of the model: `stored` vs `computed` side by side, an `X` in the
gutter, and context-sensitive actions in the diagnostic strip. No other free tool
shows you this.

## Directory browsing (FAT32)

A directory is not a special screen. It is a region whose children are records.

```
| Regions                     | part[1] > fat32 > root > DCIM > 100CANON                         |
|-----------------------------|------------------------------------------------------------------|
| v Partition 1               |   Name                 Attr    Size        First cl   Modified   |
|   v FAT32                   | + IMG_0001.JPG         ---A-   3,918,231   0x0000A31  2024-06-02 |
|     > VBR                   | + IMG_0002.JPG         ---A-   4,102,884   0x0000C0E  2024-06-02 |
|     > FSInfo                | ! _MG_0003.JPG         ---A-   3,771,002   0x0000E71  2024-06-02 |
|     > FAT #0                | + .                    ---D-           0   0x0000A2F  2024-06-02 |
|     > FAT #1                | + ..                   ---D-           0   0x0000000  2024-06-02 |
|     v root                  |                                                                  |
|       > DCIM                |                                                                  |
|         > 100CANON          | ! _MG_0003.JPG first byte is 0xE5: entry is DELETED. Name shown  |
|       . MISC                |   with first character unrecovered. Cluster chain may be reused. |
```

Expanding a record (`+`) shows the underlying 32-byte directory entry with every
field, exactly like any other struct — plus its long-filename run as a `Group`
whose extent covers the several 32-byte entries that precede it, in reverse order.

Deleted entries appear by default, marked. That is a deliberate difference from
every filesystem driver and is most of why this tool is worth building.

## Field detail popup (`Enter` or `i`)

```
     +- mbr.entries[0].part_type -------------------------------------------+
     | Offset     0x000001C2  (byte 450, LBA 0 + 450)                       |
     | Size       1 byte  (8 bits)                                          |
     | Raw        0C                                                        |
     |                                                                      |
     | hex        0x0C                 dec        12                        |
     | oct        0o014                bin        0000 1100                 |
     | ascii      '.'                  signed     12                        |
     |                                                                      |
     | Decoded    FAT32 with LBA addressing (CHS disabled)                  |
     |                                                                      |
     | Doc        Partition type byte. Non-normative: no authority defines  |
     |            these. 0x0B = FAT32 CHS, 0x0C = FAT32 LBA, 0x07 = NTFS    |
     |            or exFAT, 0xEE = GPT protective, 0x83 = Linux.            |
     | Spec       (none) - conventional, see util-linux / Wikipedia MBR     |
     |                                                                      |
     | Links      -> volume header at LBA 2048 (0x00100000)  [g]            |
     |                                                                      |
     | [y] copy value  [Y] copy labelled  [h] copy hex  [e] edit  [q] close |
     +----------------------------------------------------------------------+
```

`Repr::Enum` fields also offer a picker on edit, listing known values while still
allowing an arbitrary byte.

## Edit and commit

Editing is staged. Nothing reaches the device until commit.

```
     +- edit  mbr.entries[0].part_type ------------------------+
     | Current   0C   FAT32 LBA                                |
     | New       07_                                           |
     |                                                         |
     | Accepts: 0x07, 7, 0b111, or a name from the list below. |
     |                                                         |
     |   07  NTFS / exFAT / HPFS                               |
     |   0B  FAT32 CHS                                         |
     |   0C  FAT32 LBA                          <- current     |
     |   83  Linux                                             |
     |                                                         |
     | Effect    1 byte at 0x000001C2 changes 0C -> 07         |
     |           Sector 0 will be rewritten in full (512 B).   |
     |                                                         |
     | [Enter] stage in overlay   [Esc] cancel                 |
     +---------------------------------------------------------+
```

Staged edits show `~` in the gutter and the modified bytes are marked in the hex
pane. `:diff` lists everything staged. `:commit` is the only thing that writes:

```
     +- COMMIT to /dev/sdc -------------------------------------------+
     | Device    /dev/sdc   57.7 GiB                                  |
     | WARNING   /dev/sdc1 is mounted at /media/andrii/E807-EC4E      |
     |                                                                |
     | 2 edits, touching 1 sector:                                    |
     |                                                                |
     |   0x000001C2  1 B   0C -> 07    mbr.entries[0].part_type       |
     |   0x000001BE  1 B   00 -> 80    mbr.entries[0].status          |
     |                                                                |
     | Original bytes will be journalled to                           |
     |   ~/.local/state/blktamper/journal/2026-09-16T12-04-11-sdc.jsonl |
     |                                                                |
     | Type the device name to confirm:  ______________               |
     |                                                                |
     | [Esc] cancel                                                   |
     +----------------------------------------------------------------+
```

Typing the device name is deliberate friction, and it is the single check that
prevents writing to the wrong disk — the failure mode that actually destroys data,
as opposed to the ones you'd be doing on purpose.

## Keymap

### Movement

| Key | Action |
|---|---|
| `j` `k` / `Down` `Up` | row down / up |
| `PgDn` `PgUp` | full page |
| `Ctrl-d` `Ctrl-u` | half page |
| `Home` / `G` | first / last row |
| `h` `l` / `Left` `Right` | collapse / expand node |
| `Tab` / `Shift-Tab` | cycle pane focus (tree / table / hex) |
| `Enter` / `i` | field detail popup |

### Navigation between structures

| Key | Action |
|---|---|
| `g` | follow the selected field's link (jump to target, probing if needed) |

| `Ctrl-o` / `Ctrl-r` | jump stack back / forward |
| `:0x1BE` | goto absolute byte offset |
| `:lba 2048` | goto LBA (uses session sector size) |
| `:cluster 3` | goto cluster (in the current filesystem's context) |
| `:probe` | probe at the current offset and offer interpretations |
| `:as fat32` | force-interpret the current offset as a format |
| `/` `n` `N` | search field labels in the current structure |
| `m` `'` | set / jump to a mark (marks are named offsets, persisted per device) |

### Filtering and display

| Key | Action |
|---|---|
| `z` | cycle filter: **all** → **hide empty** → **anomalies only** |
| `Z` | toggle "show gaps" (bytes no field claimed) |
| `x` | cycle raw column: hex / dec / binary / off |
| `w` | toggle wide mode (hide tree pane, widen table) |
| `H` | toggle hex pane |
| `t` | toggle absolute vs relative offsets in the status bar |

`z`'s three states, precisely:

- **all** — everything.
- **hide empty** — hides fields whose bytes are all `0x00` or all `0xFF`, unused
  array slots, and `RESERVED` fields that are zero. Keeps a one-line
  `... 118 empty entries hidden` marker so you never forget they exist.
- **anomalies only** — shows only nodes with `Status::Warn` or worse, *plus*
  reserved/must-be-zero fields that are non-zero, *plus* gaps. This is the "find
  the corruption" view and is the reason the three-state cycle beats a boolean.

### Copy

| Key | Copies |
|---|---|
| `y` | decoded value — `FAT32 LBA` |
| `Y` | labelled — `mbr.entries[0].part_type  0x0C  FAT32 LBA  @0x000001C2 (1 B)` |
| `y h` | hex dump of the node's extent |
| `y r` | raw value as hex, no spaces — `0c` |
| `y p` | the node path — `mbr.entries[0].part_type` |
| `y t` | the whole visible table as TSV (respects the current filter) |
| `V` then `y` | line-select a range of rows, then copy as TSV |
| `:write <file>` | dump the selected node's bytes to a file |

Clipboard delivery order, per R-6.5: `arboard` (with `wayland-data-control`) →
OSC 52 escape → `--clip-cmd` if configured. Whatever happens, the text is also
written to `$XDG_RUNTIME_DIR/blktamper/last-yank`, and the status bar says which
mechanism succeeded. Copying over SSH silently failing is a bad afternoon.

### Editing

| Key | Action |
|---|---|
| `e` | edit selected field (typed, respects width/endianness/encoding) |
| `E` | edit raw bytes of the selected node in the hex pane |
| `u` / `Ctrl-r` | undo / redo a staged edit |
| `:diff` | list all staged edits |
| `:revert` | discard all staged edits |
| `:arm` | arm writing (only possible when started with `--rw`) |
| `:commit` | write staged edits to the device |
| `:save <file>` | dump the current region to a file |
| `:load <file>` | stage a region restore from a file |
| `:recompute` | recompute derived fields (CRCs, mirrors) into the overlay |

## 80×24 fallback

Tree pane collapses to a breadcrumb line; hex pane shrinks to two rows.

```
+- blktamper /dev/sdc 57.7G RO -----------------------------------------------+
| MBR > entries > [0]                                                       |
|   Field              Raw             Decoded                              |
|   status             00              not bootable                         |
| + chs_first          00 82 03        h0 s2 c3                             |
| * part_type          0C              FAT32 LBA                            |
| + chs_last           FE FF FF        h254 s63 c1023                       |
|   lba_first          00 08 00 00     2048 -> 0x00100000                   |
|   num_sectors        00 30 33 07     120,795,136                          |
|                                                                           |
|---------------------------------------------------------------------------|
| 000001C0 [03 0C]FE FF FF 00 08 00  00 00 30 33 07 00 00 00                |
+---------------------------------------------------------------------------+
| mbr.entries[0].part_type @0x1C2  all  RO                           ? help |
+---------------------------------------------------------------------------+
```

## Corrections found while implementing

Two keybindings in the draft above collided with themselves and were changed:

- **`g` could not mean both "follow link" and the first half of `gg`.** Following a
  link is the more valuable of the two and the one the requirements name (R-5.2), so
  `g` follows and `Home` goes to the top.
- **`Ctrl-i` is indistinguishable from `Tab`** at the terminal level — they are the
  same byte. Since `Tab` switches panes, the vim jump-forward pairing is unavailable.
  Jump-forward is `Ctrl-r`, which at least reads as "redo the jump".

## Things I deliberately did not do

- **No mouse-first design.** Mouse support for click-to-select and scroll, yes, but
  every action has a key. This tool gets used over SSH on a broken machine.
- **No tabs / multiple devices.** One device per process. Two disks means two
  terminals, which is also how you avoid writing to the wrong one.
- **No embedded shell or scripting language.** `blktamper get <path>` as a
  non-interactive mode later gives you scripting via the shell you already have.
- **No "repair" button.** `:recompute` stages a change and shows you the diff. The
  tool never decides what correct looks like.
