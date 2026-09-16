//! A block cache in front of any `BlockSource`.
//!
//! Without it, rendering one field re-reads a sector, and a 128-entry GPT array
//! becomes 128 syscalls. With it, the whole array is two reads.
//!
//! Unreadable blocks are cached as unreadable, so a dying drive is not re-poked
//! once per repaint (doc/07-write-safety.md).

use blktamper_core::{BlockSource, ReadOutcome};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// 64 KiB: large enough that a GPT entry array is one read, small enough that
/// jumping to a random offset does not pull a megabyte.
pub const BLOCK_SIZE: u64 = 64 * 1024;

/// Default budget: 64 MiB, i.e. 1024 blocks.
pub const DEFAULT_CAPACITY_BLOCKS: usize = 1024;

#[derive(Clone)]
enum Block {
    Data(Arc<Vec<u8>>),
    /// The device refused this range. Remembered so we do not retry on every frame.
    Unreadable,
}

struct Inner {
    map: HashMap<u64, Block>,
    /// Block indices in least-recently-used order.
    lru: Vec<u64>,
    capacity: usize,
    hits: u64,
    misses: u64,
}

/// Wraps a source with an LRU block cache.
pub struct CachedSource {
    inner: Arc<dyn BlockSource>,
    state: Mutex<Inner>,
}

impl std::fmt::Debug for CachedSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.state.lock().unwrap();
        f.debug_struct("CachedSource")
            .field("source", &self.inner.name())
            .field("blocks", &s.map.len())
            .field("hits", &s.hits)
            .field("misses", &s.misses)
            .finish()
    }
}

impl CachedSource {
    pub fn new(inner: Arc<dyn BlockSource>) -> CachedSource {
        CachedSource::with_capacity(inner, DEFAULT_CAPACITY_BLOCKS)
    }

    pub fn with_capacity(inner: Arc<dyn BlockSource>, capacity: usize) -> CachedSource {
        CachedSource {
            inner,
            state: Mutex::new(Inner {
                map: HashMap::new(),
                lru: Vec::new(),
                capacity: capacity.max(1),
                hits: 0,
                misses: 0,
            }),
        }
    }

    /// `(hits, misses, resident blocks)` — surfaced in the status bar when debugging.
    pub fn stats(&self) -> (u64, u64, usize) {
        let s = self.state.lock().unwrap();
        (s.hits, s.misses, s.map.len())
    }

    /// Drop everything. The hook a future `BLKFLSBUF` / re-read would use.
    pub fn invalidate(&self) {
        let mut s = self.state.lock().unwrap();
        s.map.clear();
        s.lru.clear();
    }

    fn block(&self, index: u64) -> Block {
        {
            let mut s = self.state.lock().unwrap();
            if let Some(b) = s.map.get(&index).cloned() {
                s.hits += 1;
                touch(&mut s.lru, index);
                return b;
            }
            s.misses += 1;
        }

        // Read outside the lock: a slow device must not block other readers.
        let off = index * BLOCK_SIZE;
        let mut buf = vec![0u8; BLOCK_SIZE as usize];
        let outcome = self.inner.read_at(off, &mut buf);
        let block = match outcome {
            ReadOutcome::Unreadable => Block::Unreadable,
            ReadOutcome::Short { filled } => {
                buf.truncate(filled);
                Block::Data(Arc::new(buf))
            }
            ReadOutcome::Ok => Block::Data(Arc::new(buf)),
        };

        let mut s = self.state.lock().unwrap();
        s.map.insert(index, block.clone());
        touch(&mut s.lru, index);
        while s.lru.len() > s.capacity {
            let victim = s.lru.remove(0);
            s.map.remove(&victim);
        }
        block
    }
}

fn touch(lru: &mut Vec<u64>, index: u64) {
    if let Some(pos) = lru.iter().position(|&i| i == index) {
        lru.remove(pos);
    }
    lru.push(index);
}

impl BlockSource for CachedSource {
    fn len(&self) -> u64 {
        self.inner.len()
    }

    fn logical_sector_size(&self) -> u32 {
        self.inner.logical_sector_size()
    }

    fn physical_sector_size(&self) -> u32 {
        self.inner.physical_sector_size()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> ReadOutcome {
        if buf.is_empty() {
            return ReadOutcome::Ok;
        }
        if offset >= self.len() {
            buf.fill(0);
            return ReadOutcome::Short { filled: 0 };
        }

        let mut written = 0usize;
        let mut cur = offset;
        while written < buf.len() {
            let index = cur / BLOCK_SIZE;
            let within = (cur % BLOCK_SIZE) as usize;
            match self.block(index) {
                Block::Unreadable => {
                    buf[written..].fill(0);
                    return ReadOutcome::Unreadable;
                }
                Block::Data(data) => {
                    if within >= data.len() {
                        buf[written..].fill(0);
                        return ReadOutcome::Short { filled: written };
                    }
                    let n = (data.len() - within).min(buf.len() - written);
                    buf[written..written + n].copy_from_slice(&data[within..within + n]);
                    written += n;
                    cur += n as u64;
                }
            }
        }
        ReadOutcome::Ok
    }

    fn name(&self) -> &str {
        self.inner.name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use blktamper_core::source::{FailingSource, MemSource};

    fn ramp(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn reads_match_the_underlying_source() {
        let data = ramp(300_000);
        let src = Arc::new(MemSource::new(data.clone())) as Arc<dyn BlockSource>;
        let c = CachedSource::new(src);
        for &(off, len) in &[(0u64, 10usize), (65_530, 20), (100_000, 4096), (299_990, 10)] {
            let mut got = vec![0u8; len];
            assert!(c.read_at(off, &mut got).is_ok(), "off={off}");
            assert_eq!(got, &data[off as usize..off as usize + len], "off={off}");
        }
    }

    #[test]
    fn spanning_a_block_boundary_is_stitched_correctly() {
        let data = ramp(200_000);
        let c = CachedSource::new(Arc::new(MemSource::new(data.clone())));
        let off = BLOCK_SIZE - 5;
        let mut got = vec![0u8; 10];
        assert!(c.read_at(off, &mut got).is_ok());
        assert_eq!(got, &data[off as usize..off as usize + 10]);
    }

    #[test]
    fn repeated_reads_hit_the_cache() {
        let c = CachedSource::new(Arc::new(MemSource::new(ramp(100_000))));
        let mut b = [0u8; 16];
        c.read_at(0, &mut b);
        c.read_at(32, &mut b);
        let (hits, misses, _) = c.stats();
        assert_eq!(misses, 1);
        assert!(hits >= 1);
    }

    #[test]
    fn eviction_keeps_the_cache_bounded() {
        let c = CachedSource::with_capacity(Arc::new(MemSource::new(ramp(10 * BLOCK_SIZE as usize))), 2);
        let mut b = [0u8; 4];
        for i in 0..10u64 {
            c.read_at(i * BLOCK_SIZE, &mut b);
        }
        let (_, _, resident) = c.stats();
        assert!(resident <= 2, "resident={resident}");
    }

    #[test]
    fn unreadable_is_propagated_and_not_retried() {
        let inner = FailingSource { inner: MemSource::new(ramp(200_000)), fail_from: 0 };
        let c = CachedSource::new(Arc::new(inner));
        let mut b = [0u8; 16];
        assert_eq!(c.read_at(0, &mut b), ReadOutcome::Unreadable);
        assert_eq!(c.read_at(0, &mut b), ReadOutcome::Unreadable);
        let (hits, misses, _) = c.stats();
        assert_eq!(misses, 1, "a failing sector must not be re-poked on every frame");
        assert_eq!(hits, 1);
    }

    #[test]
    fn short_source_reports_short_not_zeros() {
        let c = CachedSource::new(Arc::new(MemSource::new(ramp(100))));
        let mut b = [0u8; 200];
        assert_eq!(c.read_at(50, &mut b), ReadOutcome::Short { filled: 50 });
    }
}
