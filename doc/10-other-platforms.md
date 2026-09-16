# macOS and Windows: can this work at all?

Research conducted 2026-09-16. The question asked was narrow and practical:

> **A.** Do the interfaces exist?
> **B.** Does the OS explicitly permit their use, the way Linux does?
> **C.** Can using them cause kernel panics, file-browser crashes, or other trouble?

Short answer: **yes, yes, and mostly no — but each platform says "yes" to a
different part of what blktamper does, and the differences are large enough to
change the design rather than just the I/O backend.**

Everything below is from vendor documentation or from the source of tools that ship
this in production. Where a claim survived an adversarial check against primary
sources it is stated plainly; where it did not, it is marked.

---

## The answer in one table

| | macOS | Windows | Linux (for comparison) |
|---|---|---|---|
| **A. Interfaces exist** | Yes — `/dev/rdiskN`, `<sys/disk.h>` ioctls, DiskArbitration | Yes — `\\.\PhysicalDriveN`, `winioctl.h` | Yes — `/dev/sdX`, sysfs |
| **B. Vendor-documented and permitted** | Yes, except the boot disk, which is closed to third parties | Yes, and Microsoft names partitioning and recovery tools as intended users | Yes |
| **Privilege needed** | root (`root:operator 0640`) | Administrator — **for reading too** | root or group `disk` |
| **Read a mounted volume** | Yes | Yes | Yes |
| **Write inside a mounted filesystem** | **Yes, unguarded, via the raw node** | No — must lock or dismount the volume | Kernel-config dependent since 6.8 |
| **Write the partition table of a mounted disk** | Whole-disk open tears down the partition scheme | **Yes, explicitly allowed** | Yes |
| **C. Kernel panic** | No report found | No documented deterministic bugcheck | Documented as possible |
| **C. Browser crash** | No — but a "not readable… Initialize?" prompt | No — but stale views and a "format the disk?" prompt | N/A |
| **C. OS repairs behind you** | Automount re-probes on close | **chkdsk on the dirty bit; NTFS self-heals** | No |

The headline: **macOS is the permissive one and Windows is the strict one**, which
is the opposite of most people's expectation, and the opposite of what the platforms'
reputations suggest.

---

## macOS

### A. The interfaces

| What | How |
|---|---|
| Device nodes | `/dev/diskN` (buffered block), `/dev/rdiskN` (raw character), and `/dev/diskNsM` / `/dev/rdiskNsM` per partition |
| Open | `open(2)` with `O_RDONLY` / `O_RDWR`; `O_EXLOCK` and `O_SHLOCK` map to IOKit's exclusive/shared storage locks |
| Unbuffered I/O | `fcntl(fd, F_NOCACHE, 1)` — there is no `O_DIRECT` on macOS |
| Logical sector size | `DKIOCGETBLOCKSIZE` |
| Physical sector size | `DKIOCGETPHYSICALBLOCKSIZE` |
| Block count | `DKIOCGETBLOCKCOUNT` |
| Writable? | `DKIOCISWRITABLE` |
| Flush | `DKIOCSYNCHRONIZE` |
| Mount detection | `getfsstat(2)`, then `statfs.f_mntfromname` |
| Unmount without ejecting | `DADiskUnmount` (DiskArbitration), or `diskutil unmountDisk` |
| Keep Finder out | `DADiskClaim`, `DARegisterDiskMountApprovalCallback` |

All ioctls are in the public `<sys/disk.h>`. There is no sysfs equivalent — geometry
comes from ioctls and from the IOKit registry rather than from a filesystem.

**Alignment on the raw node is enforced, with a specific errno.** `dkreadwrite()`
rejects any raw-node I/O whose offset *or* length is not a multiple of the media
block size with `kIOReturnNotAligned`, which surfaces as **`EINVAL`**. The buffered
node has no such restriction. Three more edge behaviours worth knowing, all from the
same function: a read starting at or past end-of-media returns success with zero
bytes, a write there returns `EIO`, and a transfer spanning the end is silently
clipped short rather than failing.

**`DADiskClaim` is the one to know about.** Apple documents it as claiming a disk for
exclusive use and preventing its children from mounting, and describes the intended
use case in terms that match this program almost exactly: *"primarily useful for
doing things like volume partitioning where you want IOKit to parse your new
partition map and create new dev nodes, but you don't want other components
interacting with those new dev nodes (like the unformatted disk warning) until you've
finished writing out the new volumes."*

### B. Permitted — with one hard "no"

Nodes are `root:operator` mode `0640`. Group `operator` is macOS's counterpart to
Linux's `disk` group, but it grants **read only** — writing always needs uid 0. Apple's supported
routes to root for a distributed tool are `SMAppService` (macOS 13+) or a `.pkg`
installer. `sudo`, `authopen` and `osascript` are described by Apple as *"not
appropriate to use as API"*, and setuid-root gets *"Do not use … Ever."*

Two failure modes that must be reported differently, per Apple DTS:

- **`EACCES` (13)** — BSD permissions. You are not root, or the node says no.
- **`EPERM` (1)** — App Sandbox, TCC, or Endpoint Security. A different problem with a
  different fix.

A tool that collapses both into "permission denied" will send people chasing the
wrong layer for hours.

**The boot disk is closed.** SIP restricts raw block devices to processes carrying
`com.apple.rootless.restricted-block-devices` or
`com.apple.private.security.disk-device-access`. Both are Apple-only: `fsck_msdos`,
`mount_msdos` and `fsck_hfs` carry the first; `newfs_hfs` and `CopyHFSMeta` carry the
second. Third parties cannot obtain either. Asked how to get raw access to the boot
drive, Apple DTS answered *"Not that I'm aware of"* and recommended booting from
another device. **External and secondary disks are unaffected** — which is the case
blktamper actually cares about.

The Mac App Store is closed to this outright: App Review 2.4.5(v) forbids apps that
*"request escalation to root privileges or use setuid attributes."*

### C. What breaks — and the inverted protection that should worry you

macOS protects the *buffered* node and leaves the *raw* one open, which is backwards
from every intuition and is the single most important finding in this document:

- **`/dev/diskNsM` (block) returns `EBUSY` unconditionally** when the partition is
  mounted — even for `O_RDONLY`, via `vfs_mountedon()`.
- **`/dev/rdiskNsM` (raw) opened `O_RDWR` under a live read-write mount succeeds.**
  `DK_ADD_ACCESS(RW, RW) == RW`, so `dkopen` skips the IOKit arbitration that would
  otherwise refuse it.

So on macOS **you can write into a mounted filesystem's sectors with no guard at
all** — no `EBUSY`, no lock requirement, nothing equivalent to Windows' storage-stack
rules or Linux 6.8's `CONFIG_BLK_DEV_WRITE_MOUNTED`. The collision that Microsoft
warns "can cause corruption or system instability" is simply available.

*(This is why `dd` documentation and every forum answer tells you to
`diskutil unmountDisk` first: the OS will not do it for you.)*

Opening the **whole disk** `O_RDWR` is different — `IOMedia::handleOpen` tears down
the partition scheme above the media, or fails the open. And on close, the OS
re-probes and automounts; `etcher-sdk` waits two seconds and unmounts again to cope
with exactly this.

No credible report of a kernel panic from userspace raw writes was found on either
platform. What does break is above the kernel:

- **Finder does not crash.** But leave a disk in a state DiskArbitration cannot
  recognise and the user gets *"The disk you inserted was not readable by this
  computer"* with an **Initialize** button that opens Disk Utility. One wrong click
  reformats the evidence.
- **macOS repairs behind you, exactly as Windows does.** `diskarbitrationd` runs
  `fsck_*` before mounting any volume it has flagged `kDADiskStateRequireRepair`
  (`DAMount.c`). This is the direct counterpart of Windows' `chkdsk`-on-dirty-bit and
  it destroys the same evidence.
- Automount re-mounts on close unless you hold a `DADiskClaim`.
- **Endpoint Security can silently downgrade your handle.** An EDR client subscribed
  to `ES_EVENT_TYPE_AUTH_OPEN` responds with `es_respond_flags_result`, which lets it
  mask `FWRITE` off the open **without failing it**. The `open()` succeeds and the
  writes then fail, which will look like a blktamper bug rather than policy.

---

## Windows

### A. The interfaces

| What | How |
|---|---|
| Whole disk | `CreateFileW("\\\\.\\PhysicalDrive0", …)` |
| Volume | `CreateFileW("\\\\.\\C:", …)` — **no trailing backslash**, or it opens the filesystem instead |
| Required | `OPEN_EXISTING`; `FILE_SHARE_WRITE` when opening a volume you do not intend to lock |
| Geometry | `IOCTL_DISK_GET_DRIVE_GEOMETRY_EX` → `DISK_GEOMETRY_EX` |
| Size | `IOCTL_DISK_GET_LENGTH_INFO` → `GET_LENGTH_INFORMATION` |
| Physical sector size | `IOCTL_STORAGE_QUERY_PROPERTY` with `StorageAccessAlignmentProperty` → `STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR` |
| Which volumes live on a disk | `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` → `VOLUME_DISK_EXTENTS` / `DISK_EXTENT` |
| Lock a volume | `FSCTL_LOCK_VOLUME` / `FSCTL_UNLOCK_VOLUME` |
| Dismount | `FSCTL_DISMOUNT_VOLUME` |
| Reach the last sectors of a volume | `FSCTL_ALLOW_EXTENDED_DASD_IO` |
| Re-read the partition table | `IOCTL_DISK_UPDATE_PROPERTIES` |

No kernel driver is required. Rufus, TestDisk and HxD all do this from user mode.

### B. Permitted, and unusually explicit about it

**Administrator is required to open the handle at all — for reading as well as
writing.** `CreateFileW`'s "Physical Disks and Volumes" section states it directly.
That is stricter than Linux, where membership of group `disk` suffices for reads.

Writes are then governed by *Restricted Direct Disk Access and Volume Access in
Windows* (the public form of KB 942448), which is unusually generous to exactly this
class of tool. Through a **disk** handle, a write is allowed when:

1. **The sectors do not fall within a volume.** Microsoft's own note: *"The partition
   tables also reside in the sectors that are outside the volumes. Because these
   sectors are not under the control of any file system, there is no reason to block
   access to the sectors."*
2. The sectors fall within a mounted volume that is **locked explicitly**.
3. The volume is not mounted, or has no filesystem.

Through a **volume** handle, a write is allowed when the sectors are boot sectors,
lie outside the filesystem space, or the volume is locked — explicitly with
`FSCTL_LOCK_VOLUME`, or **implicitly by opening without `FILE_SHARE_WRITE`**.

And the compatibility section blesses our use cases by name:

> *"Partitioning programs target partition tables that reside in sectors that are
> outside the volume regions… Because access to these sectors is enabled, the
> partitioning programs are not affected."*
>
> *"Recovery programs will most likely run on volumes that the file system cannot
> mount. Because access to RAW volumes is enabled, such recovery programs are not
> affected."*

**So MBR and GPT editing works on Windows with nothing more than elevation.** It is
the FAT/exFAT directory scrubbing — writes *inside* a mounted volume — that needs a
lock.

**The hard limit:** `FSCTL_LOCK_VOLUME` and `FSCTL_DISMOUNT_VOLUME` both fail on a
system volume or one containing a page file, and *"the system volume cannot be
locked."* Scrubbing records on a live `C:` is therefore **not possible by any
supported path** — you boot from other media, exactly as you would on macOS for the
boot disk.

### C. What breaks

No documented deterministic bugcheck: Windows fails the write rather than letting it
through. Where a write *does* land under a live filesystem, Microsoft says
*"Corruption or system instability can occur"*, and bugcheck `0x24 NTFS_FILE_SYSTEM`
lists NTFS corruption among its causes — so a BSOD is a possible *consequence of
corruption*, not an immediate reaction.

Explorer does not crash. What it does is worse for a forensic tool:

- **It shows stale data.** Windows caches the partition table and filesystem metadata
  independently of your writes. Rufus, in `src/drive.c`: *"if you modify the MBR
  outside of using the Windows API, Windows still uses the cached copy it got from
  the last IOCTL, and ignores your changes until you replug the drive or issue an
  `IOCTL_DISK_UPDATE_PROPERTIES`"* — and elsewhere that the same IOCTL is
  **"*USELESS*"** short of cycling the USB port.
- **Windows repairs behind you.** NTFS self-heals online, and the volume dirty bit
  makes `chkdsk` run automatically at next boot. `chkdsk /freeorphanedchains` and the
  FAT "convert lost chains" path will alter or discard **exactly the recoverable
  remnants a forensic tool exists to show**. This is the most dangerous item on this
  page for blktamper's purpose.
- A scrubbed-to-RAW volume produces *"You need to format the disk in drive X: before
  you can use it."* — the same one-click hazard as macOS's Initialize button.

### Security software

There is **no Attack Surface Reduction rule** covering raw disk access. There is
**Controlled Folder Access**, which is an ASR capability, and its default protected
set includes *"Hard drive boot sectors"*. Modes 3 and 4 are disk-sector-only:
*"Untrusted apps are blocked from writing to disk sectors."*

Two things make this much less alarming than it sounds:

- **CFA is off by default.** Mode 0 is *"CFA is off. All apps can modify or delete
  files in protected folders and write to disk sectors."*
- Microsoft explicitly frames tools like ours as the legitimate category: *"Use Audit
  disk modification only first to confirm that no legitimate software (for example,
  **disk-imaging, backup, encryption, or partitioning tools**) writes to disk sectors
  before you switch to Block disk modification only."*

Blocked writes produce a notification and a Protection History entry — a block, not a
malware verdict. Whether adding an executable to CFA's allow-list unblocks *disk
sector* writes as opposed to protected-folder writes could not be confirmed; the
documentation covers only the folder case.

### BitLocker

Reading LBA *n* through `\\.\PhysicalDriveN` gives **ciphertext**; reading the same
LBA through `\\.\X:` on an unlocked volume gives **plaintext**. Two different answers
for the same address. A viewer that does not display which handle it is on produces
meaningless output.

---

## What this means for blktamper

### The good news

`R-1.2` already requires all OS-specific behaviour behind a trait, and
`blktamper-io` is the only crate that knows about operating systems — 200 lines of
`linux.rs` plus a portable file backend. The research does not invalidate that
design. Every Linux concept has a counterpart:

| `blktamper-io` concept | Linux | macOS | Windows |
|---|---|---|---|
| open read-only | `open(O_RDONLY)` | same, `/dev/rdiskN` | `CreateFileW(GENERIC_READ)` |
| device size | seek to end | `DKIOCGETBLOCKCOUNT` | `IOCTL_DISK_GET_LENGTH_INFO` |
| logical sector size | sysfs `logical_block_size` | `DKIOCGETBLOCKSIZE` | `IOCTL_DISK_GET_DRIVE_GEOMETRY` |
| physical sector size | sysfs `physical_block_size` | `DKIOCGETPHYSICALBLOCKSIZE` | `StorageAccessAlignmentProperty` |
| mount detection | `/proc/self/mountinfo` | `getfsstat(2)` | `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` |
| flush | `fsync` + `BLKFLSBUF` | `DKIOCSYNCHRONIZE` | `FlushFileBuffers` |

### The bad news: `BlockSink` needs a precondition step

On Linux, arming is "open `O_RDWR`". On the other two it is not:

- **Windows** needs lock-or-dismount before writing inside a volume, and the lock
  **dies with the handle** — *"A locked volume remains locked until… the handle
  closes, either directly through `CloseHandle`, or indirectly when a process
  terminates."* If blktamper crashes mid-commit, the volume unlocks and the OS
  immediately rediscovers and remounts over a half-written filesystem. Our overlay
  and journal already make that recoverable, which is fortunate rather than planned.
- **macOS** needs `DADiskUnmount` plus, ideally, a held `DADiskClaim` so nothing
  re-mounts underneath.

So `arm()` becomes platform-specific in a way that `open()` was not. The trait needs
a `prepare_for_write()` / `release()` pair, not just a writable handle.

### Three design consequences

1. **`FSCTL_ALLOW_EXTENDED_DASD_IO` is not optional.** A volume handle is short of
   the volume's end, and **the backup boot sector of a FAT/exFAT volume lives exactly
   there**. Without it, our exFAT backup-boot-region comparison silently fails at the
   last sectors.
2. **Alignment stops being advisory.** Windows raw handles require the offset, the
   length *and the buffer address* to be sector-aligned. Our read-modify-write of
   whole sectors already satisfies the first two; the third means the overlay's
   commit buffer needs an aligned allocation on Windows.
3. **`chkdsk` and Disk Utility are adversaries.** Both platforms will "repair"
   exactly the residue blktamper exists to show. The tool should warn before leaving a
   volume in a state that triggers them, and probably offer to leave the dirty bit
   alone.

---

## Distribution: what it costs to ship this

Neither platform has a raw-disk entitlement, capability or manifest privilege. On
macOS the gate is BSD permissions plus TCC; on Windows it is purely the elevated
admin token. **Signing is a distribution and user-experience gate, not an access
gate** — an unsigned binary that reaches the disk works exactly as well as a signed
one.

### macOS

| Item | Cost / consequence |
|---|---|
| Apple Developer Program | **$99/year**, no open-source or individual waiver |
| Notarization | Required in practice; `notarytool` + `stapler` |
| Stapling to a bare Mach-O | **Not possible** — a plain tarball depends on an online Gatekeeper check, which fails on the air-gapped workstations a forensic tool tends to live on. Ship a signed `.pkg` or `.dmg`. |
| Double-clicking a CLI binary in Finder | **Always blocked**, whatever you sign (Apple bug r.58097824) |
| macOS 15+ | The Control-click "Open anyway" override is **gone**; users go to System Settings → Privacy & Security. Any README saying "right-click and choose Open" is now wrong. |
| `sudo blktamper` and TCC | **Terminal becomes the responsible process.** The real instruction is "grant Terminal Full Disk Access" — which grants it to everything ever launched from Terminal. Over SSH the principal is `/usr/libexec/sshd-keygen-wrapper` instead. |
| `authopen` | `/usr/libexec/authopen` with the `sys.openfile.readwrite.<path>` right is what **Raspberry Pi Imager** ships. Apple calls it "not appropriate to use as API", but it is real, deployed prior art. |
| The "correct" pattern | `SMAppService` privileged daemon — turns a single TUI binary into a signed `.app` with a daemon, an XPC protocol and a Login Items approval step. A large tax for this shape of tool. |

### Windows

| Item | Cost / consequence |
|---|---|
| Manifest | `<requestedExecutionLevel level="requireAdministrator" />` |
| Launch behaviour | A `requireAdministrator` console app launched from a non-elevated shell returns `ERROR_ELEVATION_REQUIRED` (740) **rather than prompting**. Test cmd, PowerShell, Windows Terminal, shortcuts and CI separately. |
| Unsigned binary | "Windows protected your PC" (SmartScreen); Smart App Control blocks unknown unsigned code outright on eligible machines |
| EV certificates | **No longer bypass SmartScreen** — that was removed in 2024. Advice to buy one for instant trust is obsolete and wastes $400+/year. |
| Azure Artifact Signing | From **$9.99/month** (formerly Trusted Signing). Higher-tier pricing could not be confirmed; the Azure pricing page currently renders placeholders. |
| S mode | The binary **cannot run at all**, and switching out of S mode is one-way |

---

## Verdict

**A. Do the interfaces exist?** Yes, on both, fully documented, no kernel driver
needed.

**B. Does the OS permit their use?** Yes. Windows is *more* explicit than Linux — it
names partitioning and recovery programs as intended users and deliberately leaves
the partition-table region writable. macOS permits everything except the boot disk,
which is closed to third parties with no supported workaround.

**C. Does it cause trouble?** No kernel panics found on either. The real hazards are
not crashes but **silent destruction of the evidence by the OS itself**: Windows runs
`chkdsk` on the dirty bit, macOS runs `fsck_*` from `diskarbitrationd` before
mounting a volume it thinks needs repair, Explorer and Finder both cache stale
metadata, and both platforms offer the user a one-click reformat when a volume stops
parsing. For a tool whose entire value is showing what is actually on the disk, those
are worse than a crash would be.

### Recommendation

Both ports are viable. If one is done first, **do Windows** — the write rules are
documented precisely enough to implement against, elevation is the only access gate,
and there is no signing cost to *function*. macOS costs $99/year before a user can
run it conveniently, and its unguarded raw-node write path makes it the easier
platform to damage a disk from.

Neither should start before `BlockSink` grows the `prepare_for_write()` /
`release()` pair, because retrofitting lock-and-dismount semantics into a trait
designed around `open(O_RDWR)` is how the abstraction breaks.

**Scope note:** this is research, not a commitment. `R-1.1` still says Linux is the
only supported target for v1, and `R-1.4` still says macOS and Windows are not
planned but must not be architecturally excluded. This document exists to confirm
that the second half of `R-1.4` is satisfied — it is.

---

## What could not be confirmed

Stated so nobody builds on it:

- The **exact error code** Windows returns for a storage-stack-blocked write.
  Microsoft's article never names one and the forum thread that used to is a 404.
  **Log `GetLastError()` raw; do not branch on `ERROR_ACCESS_DENIED`.**
- Whether adding an executable to **CFA's allow-list unblocks disk-sector writes**, as
  opposed to protected-folder writes.
- Whether **TCC** gates opening `/dev/rdiskN` for a process already running as root,
  as distinct from BSD device-node permissions.
- Whether Defender's behavioural engine, outside CFA, flags an unsigned process that
  opens `\\.\PhysicalDriveN` for write. Only anecdote was found.
- Whether Explorer ever actually *crashes*, as opposed to showing stale data or
  prompting to format. No vendor statement either way.
- `kTCCServiceSystemPolicyAllFiles` / `kTCCServiceSystemPolicyRemovableVolumes` are
  real but attested only by third parties, never by Apple.
- `MOUNTMGR_DOS_DEVICE_NAME`, `IOCTL_MOUNTMGR_SET_AUTO_MOUNT` and
  `IOCTL_MOUNTMGR_QUERY_AUTO_MOUNT` are real but live in the **WDK**, not the SDK.

## Sources

Primary:

- [Restricted Direct Disk Access and Volume Access in Windows](https://learn.microsoft.com/en-us/previous-versions/windows/hardware/design/dn653576(v=vs.85)) — the public form of KB 942448
- [CreateFileW — Physical Disks and Volumes](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
- [FSCTL_LOCK_VOLUME](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_lock_volume) · [FSCTL_DISMOUNT_VOLUME](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_dismount_volume)
- [Controlled folder access](https://learn.microsoft.com/en-us/defender-endpoint/controlled-folders) — modes, defaults, and the disk-sector protection
- [Attack surface reduction rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [Disk Arbitration Programming Guide](https://developer.apple.com/library/archive/documentation/DriversKernelHardware/Conceptual/DiskArbitrationProgGuide/Introduction/Introduction.html) · [Manipulating Disks and Volumes](https://developer.apple.com/library/archive/documentation/DriversKernelHardware/Conceptual/DiskArbitrationProgGuide/ManipulatingDisks/ManipulatingDisks.html)
- [DiskArbitration.h](https://github.com/mattl/opensource.apple.com/blob/master/src/DiskArbitration/DiskArbitration-266/DiskArbitration/DiskArbitration.h) — Apple open source
- Apple Developer Forums [thread 93264](https://developer.apple.com/forums/thread/93264) — DTS on SIP and raw boot-drive access

Secondary, and valuable for what vendors understate:

- Rufus `src/drive.c` — the partition-table cache comments and the lock retry loop
- `etcher-sdk` — re-mount handling after close
- TestDisk/PhotoRec — the cross-platform device layer
- HxD documentation — stated preconditions for disk editing
