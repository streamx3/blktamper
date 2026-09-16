//! Format probing and region readers.
//!
//! Probing is *scored*, not boolean. A FAT32 volume and an NTFS volume both open
//! with a jump instruction and an OEM name; exFAT looks like FAT until byte 3; a
//! protective MBR looks like an MBR. Ranked candidates with an "interpret as…"
//! override beats a confident wrong guess.

use crate::node::Node;
use crate::source::BlockSource;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FormatId(pub &'static str);

impl std::fmt::Display for FormatId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// Confidence that a format is present at an offset.
///
/// * 0 — definitely not here
/// * 1..=40 — weak: a plausible byte or two
/// * 41..=79 — good: signature matched, geometry not yet checked
/// * 80..=100 — strong: signature plus self-consistent geometry
pub type Score = u8;

pub trait FormatProbe: Send + Sync {
    fn id(&self) -> FormatId;
    /// Human name for the "interpret as…" menu.
    fn name(&self) -> &'static str;
    /// Cheap: one or two sectors. Never errors, never panics.
    fn probe(&self, src: &dyn BlockSource, at: u64) -> Score;
    /// Open a reader at this offset. Called even when `probe` returned 0, because
    /// the user may force an interpretation.
    fn open(&self, src: Arc<dyn BlockSource>, at: u64) -> Box<dyn RegionReader>;
}

/// A parsed region of the device.
pub trait RegionReader: Send + Sync {
    fn id(&self) -> FormatId;
    /// The node tree. Always succeeds (R-3.1).
    fn root(&self) -> Node;
    /// Byte offset this region starts at.
    fn base(&self) -> u64;
}

#[derive(Default)]
pub struct Registry {
    probes: Vec<Arc<dyn FormatProbe>>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("formats", &self.probes.iter().map(|p| p.id().0).collect::<Vec<_>>())
            .finish()
    }
}

impl Registry {
    pub fn new() -> Registry {
        Registry::default()
    }

    pub fn register(&mut self, p: Arc<dyn FormatProbe>) -> &mut Self {
        self.probes.push(p);
        self
    }

    pub fn probes(&self) -> &[Arc<dyn FormatProbe>] {
        &self.probes
    }

    pub fn get(&self, id: FormatId) -> Option<&Arc<dyn FormatProbe>> {
        self.probes.iter().find(|p| p.id() == id)
    }

    /// Every format that scores above zero at `at`, best first.
    pub fn candidates(&self, src: &dyn BlockSource, at: u64) -> Vec<(FormatId, Score)> {
        let mut v: Vec<_> = self
            .probes
            .iter()
            .map(|p| (p.id(), p.probe(src, at)))
            .filter(|(_, s)| *s > 0)
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        v
    }

    pub fn best(&self, src: &dyn BlockSource, at: u64) -> Option<(FormatId, Score)> {
        self.candidates(src, at).into_iter().next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemSource;

    struct Fake(&'static str, Score);
    impl FormatProbe for Fake {
        fn id(&self) -> FormatId {
            FormatId(self.0)
        }
        fn name(&self) -> &'static str {
            self.0
        }
        fn probe(&self, _: &dyn BlockSource, _: u64) -> Score {
            self.1
        }
        fn open(&self, _: Arc<dyn BlockSource>, _: u64) -> Box<dyn RegionReader> {
            unimplemented!()
        }
    }

    #[test]
    fn candidates_are_ranked_and_zeros_dropped() {
        let mut r = Registry::new();
        r.register(Arc::new(Fake("weak", 10)));
        r.register(Arc::new(Fake("strong", 90)));
        r.register(Arc::new(Fake("absent", 0)));
        let src = MemSource::new(vec![0; 512]);
        let c = r.candidates(&src, 0);
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].0 .0, "strong");
        assert_eq!(r.best(&src, 0).unwrap().0 .0, "strong");
    }
}
