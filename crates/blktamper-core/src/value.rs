//! Decoded values and how to render them.
//!
//! `Value` is what a field decoded to; `Repr` is how it should be shown. They are
//! deliberately separate so the same `u32` can render as an LBA in one struct and a
//! cluster number in another, and so descriptors stay plain data (ADR-002).

use core::fmt;

/// A decoded field value. Always accompanied by the raw bytes it came from, so a
/// `Value` never has to be lossless on its own.
#[derive(Clone, Debug, PartialEq, Default)]
pub enum Value {
    /// Not read, unreadable, or not applicable. Renders as `??`, never as zero.
    #[default]
    Unset,
    Uint(u64),
    Int(i64),
    Bool(bool),
    Bytes(Vec<u8>),
    /// Already-decoded text. Decoding is always lossy — junk must still display.
    Text(String),
    /// 16 bytes in on-disk order; mixed-endian interpretation happens at render time.
    Guid([u8; 16]),
    /// Legacy cylinder/head/sector, already unpacked.
    Chs { head: u8, sector: u8, cylinder: u16 },
    /// A node with children rather than a scalar of its own.
    Composite,
}

impl Value {
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Uint(v) => Some(*v),
            Value::Int(v) => u64::try_from(*v).ok(),
            Value::Bool(b) => Some(*b as u64),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            Value::Guid(g) => Some(g),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    pub fn is_unset(&self) -> bool {
        matches!(self, Value::Unset)
    }

    /// True when the value carries no information: zero, empty, or all-0xFF bytes.
    /// This is what the "hide empty" filter keys off (R-4.3).
    pub fn is_blank(&self) -> bool {
        match self {
            Value::Unset => true,
            Value::Uint(0) | Value::Int(0) => true,
            Value::Bool(false) => true,
            Value::Bytes(b) => b.is_empty() || b.iter().all(|&x| x == 0) || b.iter().all(|&x| x == 0xFF),
            Value::Text(s) => s.trim().is_empty(),
            Value::Guid(g) => g.iter().all(|&x| x == 0),
            Value::Chs { head: 0, sector: 0, cylinder: 0 } => true,
            _ => false,
        }
    }
}

/// A named constant table: partition type bytes, GPT type GUIDs, media descriptors.
///
/// This is the layer that no public format description carries, and it is most of
/// what makes a viewer useful (ADR-002).
#[derive(Debug)]
pub struct EnumTable {
    pub name: &'static str,
    pub entries: &'static [EnumEntry],
}

#[derive(Debug)]
pub struct EnumEntry {
    /// Matched against `Value::as_u64` for scalars.
    pub value: u64,
    /// Matched against `Value::Guid` / `Value::Bytes` when non-empty; takes priority.
    pub bytes: &'static [u8],
    pub label: &'static str,
    pub doc: &'static str,
}

impl EnumEntry {
    pub const fn num(value: u64, label: &'static str, doc: &'static str) -> Self {
        EnumEntry { value, bytes: &[], label, doc }
    }
    pub const fn guid(bytes: &'static [u8], label: &'static str, doc: &'static str) -> Self {
        EnumEntry { value: 0, bytes, label, doc }
    }
}

impl EnumTable {
    pub fn lookup(&self, v: &Value) -> Option<&'static EnumEntry> {
        match v {
            Value::Guid(g) => self.entries.iter().find(|e| e.bytes == g.as_slice()),
            Value::Bytes(b) => self.entries.iter().find(|e| !e.bytes.is_empty() && e.bytes == b.as_slice()),
            other => other
                .as_u64()
                .and_then(|n| self.entries.iter().find(|e| e.bytes.is_empty() && e.value == n)),
        }
    }
}

/// A bitfield description. Each entry becomes a child node with a one-bit span.
#[derive(Debug)]
pub struct FlagTable {
    pub name: &'static str,
    pub bits: &'static [FlagBit],
}

#[derive(Debug)]
pub struct FlagBit {
    /// Bit index counting from the LSB of the whole field, little-endian.
    pub bit: u32,
    pub label: &'static str,
    pub doc: &'static str,
    /// When true, the bit is expected to be zero and a set bit is a finding.
    pub reserved: bool,
}

impl FlagBit {
    pub const fn new(bit: u32, label: &'static str, doc: &'static str) -> Self {
        FlagBit { bit, label, doc, reserved: false }
    }
    pub const fn reserved(bit: u32, doc: &'static str) -> Self {
        FlagBit { bit, label: "reserved", doc, reserved: true }
    }
}

/// How to render a value. Plain data — no closures, no function pointers — so the
/// descriptor tables stay exportable to an external format later (ADR-002).
#[derive(Clone, Copy, Debug)]
pub enum Repr {
    /// Hex with the field's natural width.
    Hex,
    Dec,
    /// `0x0C (12)` — the default for anything a human might want either way.
    HexDec,
    /// Look the value up in a table; unknown values still render numerically.
    Enum(&'static EnumTable),
    /// Expand into one child node per bit.
    Flags(&'static FlagTable),
    /// GPT mixed-endian layout, rendered canonically.
    Guid,
    /// Cylinder/head/sector, unpacked and annotated when it is the overflow marker.
    Chs,
    /// Show the LBA and the byte offset it maps to at the session's sector size.
    Lba,
    /// Show the cluster number and, when the filesystem geometry is known, its offset.
    Cluster,
    /// Trailing-space-trimmed ASCII, non-printables shown as dots.
    Ascii,
    /// Lossy UTF-16LE. Never refuses; invalid units become U+FFFD.
    Utf16Le,
    /// 120795136 -> "57.6 GiB"
    SizeBytes,
    /// Sector count rendered as a size once the sector size is known.
    SizeSectors,
    DosDateTime,
    DosDate,
    DosTime,
    /// exFAT timestamp: DOS date/time plus a 10ms field and a UTC offset byte.
    ExfatTime,
    /// Stored value is checked against a computed one; see `checksum::ChecksumSpec`.
    Checksum,
    /// Opaque bytes: bootstrap code, padding, unknown regions.
    Raw,
}

/// Render context — the few session facts a value needs in order to mean anything.
#[derive(Clone, Copy, Debug)]
pub struct RenderCtx {
    pub sector_size: u32,
    /// Byte offset of cluster 2, and the cluster size, when inside a filesystem.
    pub cluster_base: Option<(u64, u64)>,
    /// Device length in bytes, for range plausibility notes.
    pub device_len: u64,
}

impl Default for RenderCtx {
    fn default() -> Self {
        RenderCtx { sector_size: 512, cluster_base: None, device_len: u64::MAX }
    }
}

impl RenderCtx {
    pub fn lba_to_byte(&self, lba: u64) -> Option<u64> {
        lba.checked_mul(self.sector_size as u64)
    }

    pub fn cluster_to_byte(&self, cluster: u64) -> Option<u64> {
        let (base, size) = self.cluster_base?;
        cluster.checked_sub(2)?.checked_mul(size)?.checked_add(base)
    }
}

/// Human-readable byte count. Binary units, because every format in scope is binary.
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 7] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < UNITS.len() {
        v /= 1024.0;
        i += 1;
    }
    if v >= 100.0 {
        format!("{v:.0} {}", UNITS[i])
    } else if v >= 10.0 {
        format!("{v:.1} {}", UNITS[i])
    } else {
        format!("{v:.2} {}", UNITS[i])
    }
}

/// Group digits for readability: 120795136 -> "120,795,136".
pub fn group_digits(v: u64) -> String {
    let s = v.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Lossy UTF-16LE decode. Odd trailing byte is dropped; unpaired surrogates become
/// U+FFFD. Stops at the first NUL, which is how every format in scope pads names.
pub fn utf16le_lossy(bytes: &[u8], stop_at_nul: bool) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| !(stop_at_nul && u == 0))
        .collect();
    char::decode_utf16(units)
        .map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// Printable-ASCII rendering with dots for everything else, so byte values never
/// disappear and never become control characters in the terminal.
pub fn ascii_lossy(bytes: &[u8], trim: bool) -> String {
    let s: String = bytes
        .iter()
        .map(|&b| if (0x20..0x7f).contains(&b) { b as char } else { '.' })
        .collect();
    if trim { s.trim_end().to_string() } else { s }
}

/// GPT/Microsoft mixed-endian GUID: first three groups little-endian, last two as
/// stored. Getting this backwards silently scrambles every GUID on screen.
pub fn format_guid_mixed_endian(g: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6], g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]
    )
}

/// A hex dump line count helper used by the hex pane and by `y h` copy.
pub fn hex_bytes(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{b:02X}"));
    }
    s
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Unset => write!(f, "??"),
            Value::Uint(v) => write!(f, "{v}"),
            Value::Int(v) => write!(f, "{v}"),
            Value::Bool(b) => write!(f, "{b}"),
            Value::Bytes(b) => write!(f, "{}", hex_bytes(b)),
            Value::Text(s) => write!(f, "{s}"),
            Value::Guid(g) => write!(f, "{}", format_guid_mixed_endian(g)),
            Value::Chs { head, sector, cylinder } => write!(f, "h{head} s{sector} c{cylinder}"),
            Value::Composite => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_is_mixed_endian() {
        // sgdisk wrote disk GUID 89ABCDEF-0123-4567-89AB-CDEF01234567 to gpt-basic.img.
        // On disk that is EF CD AB 89 | 23 01 | 67 45 | 89 AB | CD EF 01 23 45 67.
        let g = [
            0xEF, 0xCD, 0xAB, 0x89, 0x23, 0x01, 0x67, 0x45, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
            0x45, 0x67,
        ];
        assert_eq!(format_guid_mixed_endian(&g), "89abcdef-0123-4567-89ab-cdef01234567");
    }

    #[test]
    fn utf16_is_lossy_not_refusing() {
        // unpaired high surrogate must render, not error
        let bytes = [0x00, 0xD8, 0x41, 0x00];
        let s = utf16le_lossy(&bytes, false);
        assert!(s.starts_with(char::REPLACEMENT_CHARACTER));
        assert!(s.ends_with('A'));
    }

    #[test]
    fn utf16_stops_at_nul_when_asked() {
        let bytes = [0x41, 0x00, 0x00, 0x00, 0x42, 0x00];
        assert_eq!(utf16le_lossy(&bytes, true), "A");
        assert_eq!(utf16le_lossy(&bytes, false), "A\0B");
    }

    #[test]
    fn blankness_covers_erased_flash() {
        assert!(Value::Bytes(vec![0xFF; 8]).is_blank());
        assert!(Value::Bytes(vec![0x00; 8]).is_blank());
        assert!(!Value::Bytes(vec![0xFF, 0x00]).is_blank());
        assert!(Value::Unset.is_blank());
    }

    #[test]
    fn sizes_and_grouping() {
        assert_eq!(group_digits(120_795_136), "120,795,136");
        assert_eq!(human_size(1023), "1023 B");
        assert_eq!(human_size(1024), "1.00 KiB");
        assert_eq!(human_size(120_795_136 * 512), "57.6 GiB");
    }

    #[test]
    fn enum_lookup_by_number_and_guid() {
        static T: EnumTable = EnumTable {
            name: "test",
            entries: &[EnumEntry::num(0x0C, "FAT32 LBA", ""), EnumEntry::guid(&[1; 16], "G", "")],
        };
        assert_eq!(T.lookup(&Value::Uint(0x0C)).unwrap().label, "FAT32 LBA");
        assert_eq!(T.lookup(&Value::Guid([1; 16])).unwrap().label, "G");
        assert!(T.lookup(&Value::Uint(0xFF)).is_none());
    }
}
