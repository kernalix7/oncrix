// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! F2FS Node Address Table (NAT).
//!
//! The NAT is the heart of F2FS's indirection layer. Every inode and indirect
//! block in F2FS has a unique **node ID** (NID). The NAT maps each NID to a
//! physical block address, so blocks can be relocated during GC without
//! updating all pointers to them.
//!
//! # On-disk layout
//!
//! The NAT occupies a dedicated area at the start of the main area. Each NAT
//! block stores 455 entries of the form:
//!
//! ```text
//! struct nat_entry {
//!     ino:       u32,   // inode number owning this node
//!     block_addr: u32,  // physical block address (0 = invalid)
//!     version:   u8,    // version counter for consistency
//! }
//! ```
//!
//! The in-memory cache accelerates lookups and tracks dirty entries for flush.
//!
//! # References
//!
//! - Linux `fs/f2fs/node.c`, `fs/f2fs/node.h` (nat_entry, NM_I)
//! - F2FS documentation: `Documentation/filesystems/f2fs.rst`

use oncrix_lib::{Error, Result};

/// Maximum number of cached NAT entries.
pub const NAT_CACHE_SIZE: usize = 2048;
/// Sentinel block address meaning "not allocated".
pub const NULL_ADDR: u32 = 0;
/// Sentinel block address meaning "inode is deleted".
pub const NEW_ADDR: u32 = u32::MAX;

/// An in-memory NAT cache entry.
#[derive(Debug, Clone, Copy)]
pub struct NatEntry {
    /// Node ID (NID) — index into the NAT.
    pub nid: u32,
    /// Owning inode number.
    pub ino: u32,
    /// Physical block address of this node block.
    pub block_addr: u32,
    /// Version counter.
    pub version: u8,
    /// Whether this entry has been modified (needs flush).
    pub dirty: bool,
}

impl NatEntry {
    /// Create a new NAT entry.
    pub fn new(nid: u32, ino: u32, block_addr: u32) -> Self {
        Self {
            nid,
            ino,
            block_addr,
            version: 0,
            dirty: false,
        }
    }

    /// Mark this entry as dirty.
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Clear the dirty flag (after flush to disk).
    pub fn clear_dirty(&mut self) {
        self.dirty = false;
    }

    /// True if the block address is allocated.
    pub fn is_allocated(&self) -> bool {
        self.block_addr != NULL_ADDR && self.block_addr != NEW_ADDR
    }
}

/// NID allocator — tracks free NIDs in a bitmap.
pub struct NidAllocator {
    /// Bitset of free NIDs (1 = free).
    bitmap: [u64; NAT_CACHE_SIZE / 64 + 1],
    /// Total NID capacity.
    capacity: u32,
    /// Next hint for free NID search.
    next_free_hint: u32,
}

impl NidAllocator {
    /// Create an allocator with `capacity` NIDs, all free.
    pub fn new(capacity: u32) -> Self {
        let words = (capacity as usize + 63) / 64;
        let mut bm = [0u64; NAT_CACHE_SIZE / 64 + 1];
        // Mark bits 0..capacity as free.
        for i in 0..words.min(bm.len()) {
            bm[i] = !0u64;
        }
        // Mask out bits beyond capacity in the last word.
        if capacity as usize % 64 != 0 {
            let tail_word = (capacity as usize / 64).min(bm.len() - 1);
            bm[tail_word] = (1u64 << (capacity as usize % 64)) - 1;
        }
        Self {
            bitmap: bm,
            capacity,
            next_free_hint: 2,
        }
    }

    /// Allocate one NID. Returns `OutOfMemory` if none available.
    pub fn alloc(&mut self) -> Result<u32> {
        let start = (self.next_free_hint as usize).min(self.capacity as usize);
        let words = (self.capacity as usize + 63) / 64;
        // Two-pass: start from hint, wrap around.
        for pass in 0..2 {
            let word_start = if pass == 0 { start / 64 } else { 0 };
            let word_end = if pass == 0 { words } else { start / 64 + 1 };
            for w in word_start..word_end.min(self.bitmap.len()) {
                if self.bitmap[w] == 0 {
                    continue;
                }
                let bit = self.bitmap[w].trailing_zeros() as usize;
                let nid = (w * 64 + bit) as u32;
                if nid >= self.capacity {
                    continue;
                }
                self.bitmap[w] &= !(1u64 << bit);
                self.next_free_hint = nid + 1;
                return Ok(nid);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Free a previously allocated NID.
    pub fn free(&mut self, nid: u32) -> Result<()> {
        if nid >= self.capacity {
            return Err(Error::InvalidArgument);
        }
        let w = (nid / 64) as usize;
        let b = (nid % 64) as usize;
        if self.bitmap[w] & (1 << b) != 0 {
            return Err(Error::InvalidArgument); // already free
        }
        self.bitmap[w] |= 1 << b;
        if nid < self.next_free_hint {
            self.next_free_hint = nid;
        }
        Ok(())
    }

    /// Check if a NID is allocated (not free).
    pub fn is_allocated(&self, nid: u32) -> bool {
        if nid >= self.capacity {
            return false;
        }
        let w = (nid / 64) as usize;
        let b = (nid % 64) as usize;
        self.bitmap[w] & (1 << b) == 0
    }
}

/// In-memory NAT cache.
pub struct NatCache {
    entries: [Option<NatEntry>; NAT_CACHE_SIZE],
    count: usize,
}

impl NatCache {
    /// Create an empty NAT cache.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; NAT_CACHE_SIZE],
            count: 0,
        }
    }

    /// Look up a NID in the cache.
    pub fn lookup(&self, nid: u32) -> Option<&NatEntry> {
        self.entries[..self.count]
            .iter()
            .filter_map(|e| e.as_ref())
            .find(|e| e.nid == nid)
    }

    /// Look up a NID (mutable).
    pub fn lookup_mut(&mut self, nid: u32) -> Option<&mut NatEntry> {
        self.entries[..self.count]
            .iter_mut()
            .filter_map(|e| e.as_mut())
            .find(|e| e.nid == nid)
    }

    /// Insert or update an entry.
    pub fn upsert(&mut self, entry: NatEntry) -> Result<()> {
        if let Some(existing) = self.lookup_mut(entry.nid) {
            *existing = entry;
            return Ok(());
        }
        if self.count >= NAT_CACHE_SIZE {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = Some(entry);
        self.count += 1;
        Ok(())
    }

    /// Evict a clean entry to make room (returns `NotFound` if none clean).
    pub fn evict_clean(&mut self) -> Result<()> {
        let pos = self.entries[..self.count]
            .iter()
            .position(|e| e.as_ref().map(|e| !e.dirty).unwrap_or(false));
        match pos {
            None => Err(Error::NotFound),
            Some(idx) => {
                self.count -= 1;
                self.entries[idx] = self.entries[self.count].take();
                Ok(())
            }
        }
    }

    /// Iterate dirty entries (need flush to disk).
    pub fn dirty_iter(&self) -> impl Iterator<Item = &NatEntry> {
        self.entries[..self.count]
            .iter()
            .filter_map(|e| e.as_ref())
            .filter(|e| e.dirty)
    }

    /// Number of cached entries.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl Default for NatCache {
    fn default() -> Self {
        Self::new()
    }
}

/// NAT manager combining the cache and NID allocator.
pub struct NatManager {
    pub cache: NatCache,
    pub alloc: NidAllocator,
}

impl NatManager {
    /// Create a NAT manager with given NID capacity.
    pub fn new(nid_capacity: u32) -> Self {
        Self {
            cache: NatCache::new(),
            alloc: NidAllocator::new(nid_capacity),
        }
    }

    /// Allocate a new NID and create a cache entry for it.
    ///
    /// `ino` is the owning inode number; `block_addr` is initially `NEW_ADDR`
    /// until the node block is actually written.
    pub fn alloc_nid(&mut self, ino: u32) -> Result<u32> {
        let nid = self.alloc.alloc()?;
        let mut entry = NatEntry::new(nid, ino, NEW_ADDR);
        entry.mark_dirty();
        self.cache.upsert(entry)?;
        Ok(nid)
    }

    /// Update the physical block address for an existing NID.
    pub fn update_block_addr(&mut self, nid: u32, block_addr: u32) -> Result<()> {
        match self.cache.lookup_mut(nid) {
            Some(entry) => {
                entry.block_addr = block_addr;
                entry.version = entry.version.wrapping_add(1);
                entry.mark_dirty();
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Free a NID — remove from cache and return to allocator.
    pub fn free_nid(&mut self, nid: u32) -> Result<()> {
        // Mark as invalid in cache.
        if let Some(entry) = self.cache.lookup_mut(nid) {
            entry.block_addr = NULL_ADDR;
            entry.mark_dirty();
        }
        self.alloc.free(nid)
    }

    /// Get the block address for `nid`, or `NotFound`.
    pub fn get_block_addr(&self, nid: u32) -> Result<u32> {
        self.cache
            .lookup(nid)
            .map(|e| e.block_addr)
            .ok_or(Error::NotFound)
    }

    /// Flush dirty NAT entries to disk via `flush_fn`.
    ///
    /// `flush_fn` receives each dirty `NatEntry` and must persist it.
    /// On success, the dirty flag is cleared.
    pub fn flush<F>(&mut self, mut flush_fn: F) -> Result<()>
    where
        F: FnMut(&NatEntry) -> Result<()>,
    {
        for entry in self.cache.entries[..self.cache.count]
            .iter_mut()
            .filter_map(|e| e.as_mut())
        {
            if entry.dirty {
                flush_fn(entry)?;
                entry.clear_dirty();
            }
        }
        Ok(())
    }
}
