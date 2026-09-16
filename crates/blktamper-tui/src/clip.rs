//! Getting text out of the terminal and into wherever you are writing it down.
//!
//! Three mechanisms, tried in order, because no single one works everywhere:
//! the native clipboard needs a display server, OSC 52 needs terminal support but
//! travels through SSH and tmux, and a file always works. The status bar says which
//! one succeeded — a copy that silently did nothing over SSH is a bad afternoon
//! (R-6.5).

use std::io::Write;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mechanism {
    Native,
    Osc52,
    FileOnly,
}

impl Mechanism {
    pub fn label(self) -> &'static str {
        match self {
            Mechanism::Native => "clipboard",
            Mechanism::Osc52 => "clipboard (OSC 52)",
            Mechanism::FileOnly => "file only",
        }
    }
}

#[derive(Debug)]
pub struct Clipboard {
    spill: PathBuf,
    custom_cmd: Option<String>,
}

impl Default for Clipboard {
    fn default() -> Self {
        Clipboard::new()
    }
}

impl Clipboard {
    pub fn new() -> Clipboard {
        let dir = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("blktamper");
        let _ = std::fs::create_dir_all(&dir);
        Clipboard { spill: dir.join("last-yank"), custom_cmd: std::env::var("BLKTAMPER_CLIP_CMD").ok() }
    }

    /// The file the yanked text is always written to, whatever else happens.
    pub fn spill_path(&self) -> &PathBuf {
        &self.spill
    }

    pub fn copy(&mut self, text: &str) -> (Mechanism, Option<String>) {
        // Always spill first: whatever the clipboard does, the text is recoverable.
        let _ = std::fs::write(&self.spill, text);

        if let Some(cmd) = self.custom_cmd.clone() {
            if run_cmd(&cmd, text).is_ok() {
                return (Mechanism::Native, None);
            }
        }

        #[cfg(feature = "clipboard")]
        {
            match arboard::Clipboard::new().and_then(|mut c| c.set_text(text.to_string())) {
                Ok(()) => (Mechanism::Native, None),
                Err(e) => {
                    if osc52(text).is_ok() {
                        return (Mechanism::Osc52, None);
                    }
                    (Mechanism::FileOnly, Some(e.to_string()))
                }
            }
        }
        #[cfg(not(feature = "clipboard"))]
        {
            if osc52(text).is_ok() {
                return (Mechanism::Osc52, None);
            }
            (Mechanism::FileOnly, Some("built without clipboard support".into()))
        }
    }
}

fn run_cmd(cmd: &str, text: &str) -> std::io::Result<()> {
    use std::process::{Command, Stdio};
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(text.as_bytes())?;
    }
    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other("clipboard command failed"))
    }
}

/// OSC 52: the escape sequence that reaches the clipboard through SSH and tmux,
/// because the terminal emulator on the other end does the work.
fn osc52(text: &str) -> std::io::Result<()> {
    let encoded = base64(text.as_bytes());
    // tmux needs the sequence wrapped to pass it through to the outer terminal.
    let seq = if std::env::var_os("TMUX").is_some() {
        format!("\x1bPtmux;\x1b\x1b]52;c;{encoded}\x07\x1b\\")
    } else {
        format!("\x1b]52;c;{encoded}\x07")
    };
    let mut out = std::io::stdout();
    out.write_all(seq.as_bytes())?;
    out.flush()
}

/// Standard base64. Hand-rolled to avoid a dependency for forty lines.
fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_rfc_vectors() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foob"), "Zm9vYg==");
        assert_eq!(base64(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn base64_handles_high_bytes() {
        assert_eq!(base64(&[0xFF, 0xFF, 0xFF]), "////");
        assert_eq!(base64(&[0x00, 0x00, 0x00]), "AAAA");
    }

    #[test]
    fn the_spill_file_is_always_written() {
        let mut c = Clipboard::new();
        let (_, _) = c.copy("hello blktamper");
        let got = std::fs::read_to_string(c.spill_path()).unwrap();
        assert_eq!(got, "hello blktamper");
    }
}
