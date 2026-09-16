#!/usr/bin/env bash
# Generate golden test images. Requires: sfdisk, sgdisk, mkfs.vfat, mkfs.exfat, mtools.
# No root required: everything is done on plain files, never on a block device.
set -euo pipefail

OUT="$(cd "$(dirname "$0")" && pwd)/gen"
mkdir -p "$OUT"
rm -f "$OUT"/*.img

MiB=$((1024*1024))

say() { printf '\n== %s\n' "$*"; }

# ---------------------------------------------------------------- mbr + fat32
say "mbr-fat32.img  (64 MiB, MBR, one FAT32 partition at LBA 2048)"
IMG="$OUT/mbr-fat32.img"
truncate -s $((64*MiB)) "$IMG"
sfdisk --no-reread --no-tell-kernel "$IMG" >/dev/null <<'EOF'
label: dos
label-id: 0xdeadbeef
unit: sectors
start=2048, size=129024, type=c, bootable
EOF
# NOTE: mkfs.vfat's BLOCKS argument counts 1 KiB blocks, not sectors. Passing a
# sector count here silently creates a filesystem claiming twice the partition,
# which then overruns both the partition and the image.
mkfs.vfat -F 32 -n "BLKTAMPER" -i "1234ABCD" --offset 2048 "$IMG" $((129024 / 2)) >/dev/null
# populate, then delete, so we get live entries, LFN runs and 0xE5 tombstones
export MTOOLS_SKIP_CHECK=1
M="$IMG@@1M"
mmd     -i "$M" ::/DCIM
mmd     -i "$M" ::/a-long-directory-name
head -c 200000 /dev/urandom > /tmp/_bt_a.bin
head -c  50000 /dev/urandom > /tmp/_bt_b.bin
printf 'hello from blktamper fixture\n' > /tmp/_bt_c.txt
mcopy   -i "$M" /tmp/_bt_a.bin ::/DCIM/IMG_0001.JPG
mcopy   -i "$M" /tmp/_bt_b.bin ::/DCIM/a-very-long-file-name-for-lfn.jpeg
mcopy   -i "$M" /tmp/_bt_c.txt ::/README.TXT
mcopy   -i "$M" /tmp/_bt_c.txt ::/SECRET.TXT
mcopy   -i "$M" /tmp/_bt_b.bin ::/a-long-directory-name/deleted-payload.bin
# the sanitize use case: delete and see what survives
mdel    -i "$M" ::/SECRET.TXT
mdel    -i "$M" ::/a-long-directory-name/deleted-payload.bin
rm -f /tmp/_bt_a.bin /tmp/_bt_b.bin /tmp/_bt_c.txt
mdir    -i "$M" -/ ::/ | sed 's/^/   /'

# ------------------------------------------------------------- mbr + extended
say "mbr-extended.img  (32 MiB, primary + extended with two logicals)"
IMG="$OUT/mbr-extended.img"
truncate -s $((32*MiB)) "$IMG"
sfdisk --no-reread --no-tell-kernel "$IMG" >/dev/null <<'EOF'
label: dos
unit: sectors
start=2048,  size=8192,  type=83
start=10240, size=20480, type=5
start=12288, size=4096,  type=83
start=18432, size=4096,  type=83
EOF

# ----------------------------------------------------------------------- gpt
say "gpt-basic.img  (64 MiB, GPT, three partitions)"
IMG="$OUT/gpt-basic.img"
truncate -s $((64*MiB)) "$IMG"
sgdisk -o \
  -n 1:2048:+16M   -t 1:ef00 -c 1:"EFI System"          -u 1:11111111-2222-3333-4444-555555555555 \
  -n 2:0:+16M      -t 2:8300 -c 2:"Linux filesystem"                                              \
  -n 3:0:0         -t 3:8309 -c 3:"Linux LUKS \xe2\x98\x85"                                       \
  -U 89ABCDEF-0123-4567-89AB-CDEF01234567 "$IMG" >/dev/null
sgdisk -p "$IMG" | sed 's/^/   /'

say "gpt-badcrc.img  (same, primary header CRC32 corrupted)"
cp "$OUT/gpt-basic.img" "$OUT/gpt-badcrc.img"
printf '\xde\xad\xbe\xef' | dd of="$OUT/gpt-badcrc.img" bs=1 seek=528 conv=notrunc status=none

say "gpt-fat32.img  (64 MiB, GPT + a real FAT32 in partition 1)"
IMG="$OUT/gpt-fat32.img"
truncate -s $((64*MiB)) "$IMG"
sgdisk -o -n 1:2048:0 -t 1:0700 -c 1:"DATA" "$IMG" >/dev/null
# 1 KiB blocks, as above.
SECTORS=$(( ($(stat -c%s "$IMG")/512) - 2048 - 34 ))
mkfs.vfat -F 32 -n "GPTDATA" --offset 2048 "$IMG" $((SECTORS / 2)) >/dev/null

# --------------------------------------------------------------------- exfat
say "exfat.img  (64 MiB, bare exFAT, no partition table)"
IMG="$OUT/exfat.img"
truncate -s $((64*MiB)) "$IMG"
mkfs.exfat -L "BLKTAMPER-X" "$IMG" >/dev/null 2>&1

say "mbr-exfat.img  (96 MiB, MBR + exFAT in partition 1)"
IMG="$OUT/mbr-exfat.img"
PART="$OUT/.exfat-part.tmp"
truncate -s $((96*MiB)) "$IMG"
sfdisk --no-reread --no-tell-kernel "$IMG" >/dev/null <<'EOF'
label: dos
unit: sectors
start=2048, size=194560, type=7
EOF
truncate -s $((194560*512)) "$PART"
mkfs.exfat -L "BLKTAMPER-X" "$PART" >/dev/null 2>&1
dd if="$PART" of="$IMG" bs=512 seek=2048 conv=notrunc status=none
rm -f "$PART"

# ------------------------------------------------------------------- corrupt
say "garbage.img  (1 MiB of random bytes - the never-panic fixture)"
head -c $((1*MiB)) /dev/urandom > "$OUT/garbage.img"

say "zeros.img  (1 MiB of zeros)"
truncate -s $((1*MiB)) "$OUT/zeros.img"

say "done"
ls -la "$OUT"
