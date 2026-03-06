// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Dentry cache management.
//!
//! The dentry cache (dcache) is the heart of VFS path resolution. It
//! stores in-memory representations of directory entries, caching the
//! mapping `(parent_inode, name) → child_inode`. A hot dcache means
//! that most path lookups avoid disk I/O entirely.
//!
//! # Structure
//!
//! ```text
//! DentryCache
//! ├── Hash table: (parent_ino XOR name_hash) → DentrySlot index
//! ├── LRU list: most-recently-used order for eviction
//! └── Negative entries: caches "does not exist" results
//! ```
//!
//! # Dentry states
//!
//! - **Positive**: entry exists and maps to an inode.
//! - **Negative**: entry was looked up and does not exist.
//!   Avoids repeated failed lookups (e.g., `open()` on a missing path).
//! - **Unhashed**: entry has been removed (unlink/rmdir) and will be
//!   freed when its reference count drops to zero.
//!
//! # Eviction
//!
//! When the cache is full, the least-recently-used entry is evicted,
//! provided it has no active references (use count = 0).
//!
//! # References
//!
//! Linux `fs/dcache.c`, `include/linux/dcache.h`;
//! POSIX.1-2024 path resolution semantics.

use crate::inode::InodeNumber;
use oncrix_lib::{Error, Result};

extern crate alloc;
use alloc::vec::Vec;

// ── Constants ────────────────────────────────────────────────────────────────

/// Total dentry slots in the cache.
pub const DCACHE_CAPACITY: usize = 512;

/// Maximum filename length (POSIX NAME_MAX).
pub const NAME_MAX: usize = 255;

/// Sentinel value meaning "no slot" in LRU list links.
const NO_SLOT: u16 = u16::MAX;

// ── Dentry flags ─────────────────────────────────────────────────────────────

/// Entry is a negative dentry (inode does not exist).
pub const DCACHE_NEGATIVE: u8 = 1 << 0;

/// Entry has been unhashed (pending deletion).
pub const DCACHE_UNHASHED: u8 = 1 << 1;

/// Entry is a mount point.
pub const DCACHE_MOUNTPOINT: u8 = 1 << 2;

/// Entry is a symbolic link.
pub const DCACHE_SYMLINK: u8 = 1 << 3;

// ── DentryName ───────────────────────────────────────────────────────────────

/// A fixed-size filename buffer.
#[derive(Clone, Copy)]
pub struct DentryName {
    buf: [u8; NAME_MAX],
    len: usize,
}

impl DentryName {
    /// Create from a byte slice. Returns `None` if empty or > `NAME_MAX`.
    pub fn from_bytes(s: &[u8]) -> Option<Self> {
        if s.is_empty() || s.len() > NAME_MAX {
            return None;
        }
        let mut buf = [0u8; NAME_MAX];
        buf[..s.len()].copy_from_slice(s);
        Some(Self { buf, len: s.len() })
    }

    /// Return the name as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Return the name length.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Return whether the name is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Compute a 32-bit hash of the name bytes.
    pub fn hash(&self) -> u32 {
        let mut h: u32 = 0x811c_9dc5;
        for b in self.as_bytes() {
            h = h.wrapping_mul(0x0100_0193) ^ *b as u32;
        }
        h
    }
}

impl core::fmt::Debug for DentryName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DentryName")
            .field("name", &self.as_bytes())
            .field("len", &self.len)
            .finish()
    }
}

// ── DentryEntry ──────────────────────────────────────────────────────────────

/// A single cached dentry slot.
#[derive(Debug, Clone, Copy)]
pub struct DentryEntry {
    /// Parent directory inode number.
    pub parent_ino: InodeNumber,
    /// Child inode number (meaningless for negative entries).
    pub child_ino: InodeNumber,
    /// Entry name.
    pub name: DentryName,
    /// State flags (`DCACHE_*` bitmask).
    pub flags: u8,
    /// Reference count. Entries with `use_count > 0` cannot be evicted.
    pub use_count: u32,
    /// Generation counter for ABA-prevention.
    pub generation: u32,
}

impl DentryEntry {
    /// Return `true` if this is a negative dentry.
    pub fn is_negative(&self) -> bool {
        self.flags & DCACHE_NEGATIVE != 0
    }

    /// Return `true` if this entry has been unhashed.
    pub fn is_unhashed(&self) -> bool {
        self.flags & DCACHE_UNHASHED != 0
    }

    /// Return `true` if this is a mount point.
    pub fn is_mountpoint(&self) -> bool {
        self.flags & DCACHE_MOUNTPOINT != 0
    }

    /// Return `true` if this is a valid, positive, hashed dentry.
    pub fn is_valid(&self) -> bool {
        !self.is_negative() && !self.is_unhashed()
    }

    /// Increment the use count.
    pub fn get(&mut self) {
        self.use_count = self.use_count.saturating_add(1);
    }

    /// Decrement the use count.
    pub fn put(&mut self) {
        self.use_count = self.use_count.saturating_sub(1);
    }
}

// ── LRU list ─────────────────────────────────────────────────────────────────

/// Per-slot LRU doubly-linked list node (uses slot indices, not pointers).
#[derive(Debug, Clone, Copy)]
struct LruNode {
    prev: u16,
    next: u16,
}

impl LruNode {
    const fn sentinel() -> Self {
        Self {
            prev: NO_SLOT,
            next: NO_SLOT,
        }
    }
}

// ── DentryCache ──────────────────────────────────────────────────────────────

/// Fixed-capacity dentry cache with LRU eviction.
pub struct DentryCache {
    /// Slot storage.
    slots: [Option<DentryEntry>; DCACHE_CAPACITY],
    /// Per-slot LRU list nodes.
    lru: [LruNode; DCACHE_CAPACITY],
    /// Head of the LRU list (most recently used).
    lru_head: u16,
    /// Tail of the LRU list (least recently used).
    lru_tail: u16,
    /// Number of occupied slots.
    count: usize,
    /// Global generation counter.
    generation: u32,
    /// Cache hit counter.
    pub hits: u64,
    /// Cache miss counter.
    pub misses: u64,
    /// Eviction counter.
    pub evictions: u64,
}

impl DentryCache {
    /// Create an empty dentry cache.
    pub const fn new() -> Self {
        Self {
            slots: [const { None }; DCACHE_CAPACITY],
            lru: [const { LruNode::sentinel() }; DCACHE_CAPACITY],
            lru_head: NO_SLOT,
            lru_tail: NO_SLOT,
            count: 0,
            generation: 0,
            hits: 0,
            misses: 0,
            evictions: 0,
        }
    }

    // ── Hash ─────────────────────────────────────────────────────────────────

    /// Compute the primary hash bucket for a lookup.
    fn hash_key(parent_ino: InodeNumber, name: &DentryName) -> usize {
        let h = (parent_ino.0 as u32).wrapping_add(name.hash());
        (h as usize) % DCACHE_CAPACITY
    }

    // ── LRU management ───────────────────────────────────────────────────────

    /// Move slot `idx` to the head of the LRU list (most recently used).
    fn lru_touch(&mut self, idx: u16) {
        if self.lru_head == idx {
            return;
        }
        // Remove from current position.
        let prev = self.lru[idx as usize].prev;
        let next = self.lru[idx as usize].next;
        if prev != NO_SLOT {
            self.lru[prev as usize].next = next;
        }
        if next != NO_SLOT {
            self.lru[next as usize].prev = prev;
        }
        if self.lru_tail == idx {
            self.lru_tail = prev;
        }
        // Insert at head.
        self.lru[idx as usize].prev = NO_SLOT;
        self.lru[idx as usize].next = self.lru_head;
        if self.lru_head != NO_SLOT {
            self.lru[self.lru_head as usize].prev = idx;
        }
        self.lru_head = idx;
        if self.lru_tail == NO_SLOT {
            self.lru_tail = idx;
        }
    }

    /// Add a new slot `idx` at the head of the LRU list.
    fn lru_insert_head(&mut self, idx: u16) {
        self.lru[idx as usize].prev = NO_SLOT;
        self.lru[idx as usize].next = self.lru_head;
        if self.lru_head != NO_SLOT {
            self.lru[self.lru_head as usize].prev = idx;
        }
        self.lru_head = idx;
        if self.lru_tail == NO_SLOT {
            self.lru_tail = idx;
        }
    }

    /// Remove slot `idx` from the LRU list.
    fn lru_remove(&mut self, idx: u16) {
        let prev = self.lru[idx as usize].prev;
        let next = self.lru[idx as usize].next;
        if prev != NO_SLOT {
            self.lru[prev as usize].next = next;
        } else {
            self.lru_head = next;
        }
        if next != NO_SLOT {
            self.lru[next as usize].prev = prev;
        } else {
            self.lru_tail = prev;
        }
        self.lru[idx as usize] = LruNode::sentinel();
    }

    /// Find a free slot, evicting the LRU entry if necessary.
    fn alloc_slot(&mut self) -> Result<u16> {
        // Scan for an empty slot first (fast path).
        for i in 0..DCACHE_CAPACITY {
            if self.slots[i].is_none() {
                return Ok(i as u16);
            }
        }
        // Evict from LRU tail.
        let mut candidate = self.lru_tail;
        while candidate != NO_SLOT {
            let entry = &self.slots[candidate as usize];
            let use_count = entry.as_ref().map(|e| e.use_count).unwrap_or(0);
            if use_count == 0 {
                self.lru_remove(candidate);
                self.slots[candidate as usize] = None;
                self.count -= 1;
                self.evictions += 1;
                return Ok(candidate);
            }
            candidate = self.lru[candidate as usize].prev;
        }
        Err(Error::OutOfMemory)
    }

    // ── Public API ───────────────────────────────────────────────────────────

    /// Look up `(parent_ino, name)` in the cache.
    ///
    /// Returns `Ok(Some(&DentryEntry))` on a cache hit (including
    /// negative entries), `Ok(None)` on a miss.
    pub fn lookup(&mut self, parent_ino: InodeNumber, name: &[u8]) -> Result<Option<&DentryEntry>> {
        let dname = DentryName::from_bytes(name).ok_or(Error::InvalidArgument)?;
        let start = Self::hash_key(parent_ino, &dname);

        for probe in 0..DCACHE_CAPACITY {
            let idx = (start + probe) % DCACHE_CAPACITY;
            match &self.slots[idx] {
                Some(entry) => {
                    if entry.parent_ino == parent_ino && entry.name.as_bytes() == dname.as_bytes() {
                        self.hits += 1;
                        let idx16 = idx as u16;
                        self.lru_touch(idx16);
                        return Ok(Some(
                            &self.slots[idx]
                                .as_ref()
                                .expect("slot must be Some after touch"),
                        ));
                    }
                }
                None => break,
            }
        }
        self.misses += 1;
        Ok(None)
    }

    /// Insert a positive dentry mapping `(parent_ino, name) → child_ino`.
    pub fn insert_positive(
        &mut self,
        parent_ino: InodeNumber,
        name: &[u8],
        child_ino: InodeNumber,
        flags: u8,
    ) -> Result<()> {
        let dname = DentryName::from_bytes(name).ok_or(Error::InvalidArgument)?;
        self.generation = self.generation.wrapping_add(1);
        let cur_gen = self.generation;

        let entry = DentryEntry {
            parent_ino,
            child_ino,
            name: dname,
            flags: flags & !DCACHE_NEGATIVE,
            use_count: 0,
            generation: cur_gen,
        };
        let slot_idx = self.alloc_slot()?;
        self.slots[slot_idx as usize] = Some(entry);
        self.count += 1;
        self.lru_insert_head(slot_idx);
        Ok(())
    }

    /// Insert a negative dentry for `(parent_ino, name)`.
    ///
    /// Subsequent lookups will return a negative hit, avoiding repeated
    /// disk lookups for non-existent paths.
    pub fn insert_negative(&mut self, parent_ino: InodeNumber, name: &[u8]) -> Result<()> {
        let dname = DentryName::from_bytes(name).ok_or(Error::InvalidArgument)?;
        self.generation = self.generation.wrapping_add(1);
        let cur_gen = self.generation;

        let child_ino = InodeNumber(0);
        let entry = DentryEntry {
            parent_ino,
            child_ino,
            name: dname,
            flags: DCACHE_NEGATIVE,
            use_count: 0,
            generation: cur_gen,
        };
        let slot_idx = self.alloc_slot()?;
        self.slots[slot_idx as usize] = Some(entry);
        self.count += 1;
        self.lru_insert_head(slot_idx);
        Ok(())
    }

    /// Invalidate the dentry for `(parent_ino, name)`.
    ///
    /// Marks the entry as unhashed. If it has no active references
    /// (use_count = 0), it is freed immediately.
    pub fn invalidate(&mut self, parent_ino: InodeNumber, name: &[u8]) -> Result<()> {
        let dname = DentryName::from_bytes(name).ok_or(Error::InvalidArgument)?;
        let start = Self::hash_key(parent_ino, &dname);

        for probe in 0..DCACHE_CAPACITY {
            let idx = (start + probe) % DCACHE_CAPACITY;
            let matches = self.slots[idx]
                .as_ref()
                .map(|e| e.parent_ino == parent_ino && e.name.as_bytes() == dname.as_bytes())
                .unwrap_or(false);

            if matches {
                let use_count = self.slots[idx].as_ref().map(|e| e.use_count).unwrap_or(0);
                if use_count == 0 {
                    self.lru_remove(idx as u16);
                    self.slots[idx] = None;
                    self.count -= 1;
                } else if let Some(ref mut e) = self.slots[idx] {
                    e.flags |= DCACHE_UNHASHED;
                }
                return Ok(());
            }
            if self.slots[idx].is_none() {
                break;
            }
        }
        Ok(()) // Not an error if not present.
    }

    /// Invalidate all dentries whose parent inode is `parent_ino`.
    ///
    /// Used when a directory is deleted or renamed.
    pub fn invalidate_children(&mut self, parent_ino: InodeNumber) {
        for i in 0..DCACHE_CAPACITY {
            let matches = self.slots[i]
                .as_ref()
                .map(|e| e.parent_ino == parent_ino)
                .unwrap_or(false);
            if matches {
                let use_count = self.slots[i].as_ref().map(|e| e.use_count).unwrap_or(0);
                if use_count == 0 {
                    self.lru_remove(i as u16);
                    self.slots[i] = None;
                    self.count -= 1;
                } else if let Some(ref mut e) = self.slots[i] {
                    e.flags |= DCACHE_UNHASHED;
                }
            }
        }
    }

    /// Increase the use count for `(parent_ino, name)`.
    ///
    /// Pins the entry so it will not be evicted.
    pub fn get(&mut self, parent_ino: InodeNumber, name: &[u8]) -> Result<()> {
        let dname = DentryName::from_bytes(name).ok_or(Error::InvalidArgument)?;
        let start = Self::hash_key(parent_ino, &dname);
        for probe in 0..DCACHE_CAPACITY {
            let idx = (start + probe) % DCACHE_CAPACITY;
            let matches = self.slots[idx]
                .as_ref()
                .map(|e| e.parent_ino == parent_ino && e.name.as_bytes() == dname.as_bytes())
                .unwrap_or(false);
            if matches {
                if let Some(ref mut e) = self.slots[idx] {
                    e.get();
                }
                return Ok(());
            }
            if self.slots[idx].is_none() {
                break;
            }
        }
        Err(Error::NotFound)
    }

    /// Decrease the use count for `(parent_ino, name)`.
    ///
    /// If the entry is unhashed and the use count drops to 0, it is freed.
    pub fn put(&mut self, parent_ino: InodeNumber, name: &[u8]) -> Result<()> {
        let dname = DentryName::from_bytes(name).ok_or(Error::InvalidArgument)?;
        let start = Self::hash_key(parent_ino, &dname);
        for probe in 0..DCACHE_CAPACITY {
            let idx = (start + probe) % DCACHE_CAPACITY;
            let matches = self.slots[idx]
                .as_ref()
                .map(|e| e.parent_ino == parent_ino && e.name.as_bytes() == dname.as_bytes())
                .unwrap_or(false);
            if matches {
                let (should_free, unhashed) = self.slots[idx]
                    .as_ref()
                    .map(|e| {
                        let new_count = e.use_count.saturating_sub(1);
                        (
                            new_count == 0 && (e.flags & DCACHE_UNHASHED != 0),
                            e.flags & DCACHE_UNHASHED != 0,
                        )
                    })
                    .unwrap_or((false, false));

                if should_free {
                    self.lru_remove(idx as u16);
                    self.slots[idx] = None;
                    self.count -= 1;
                } else if let Some(ref mut e) = self.slots[idx] {
                    e.put();
                    let _ = unhashed;
                }
                return Ok(());
            }
            if self.slots[idx].is_none() {
                break;
            }
        }
        Err(Error::NotFound)
    }

    // ── Statistics ───────────────────────────────────────────────────────────

    /// Return the number of occupied cache slots.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Return cache capacity.
    pub fn capacity(&self) -> usize {
        DCACHE_CAPACITY
    }

    /// Return `true` if the cache is full.
    pub fn is_full(&self) -> bool {
        self.count >= DCACHE_CAPACITY
    }

    /// Return cache statistics.
    pub fn stats(&self) -> DcacheStats {
        let mut negative = 0usize;
        let mut pinned = 0usize;
        let mut mountpoints = 0usize;
        for slot in self.slots.iter().flatten() {
            if slot.is_negative() {
                negative += 1;
            }
            if slot.use_count > 0 {
                pinned += 1;
            }
            if slot.is_mountpoint() {
                mountpoints += 1;
            }
        }
        DcacheStats {
            total: self.count,
            negative,
            pinned,
            mountpoints,
            hits: self.hits,
            misses: self.misses,
            evictions: self.evictions,
        }
    }

    /// Shrink the cache by evicting up to `target_free` unreferenced entries.
    ///
    /// Entries are evicted from the LRU tail. Returns the number of
    /// entries evicted.
    pub fn shrink(&mut self, target_free: usize) -> usize {
        let mut freed = 0usize;
        while freed < target_free {
            let candidate = self.lru_tail;
            if candidate == NO_SLOT {
                break;
            }
            let use_count = self.slots[candidate as usize]
                .as_ref()
                .map(|e| e.use_count)
                .unwrap_or(1);
            if use_count > 0 {
                // Walk backward; if the tail is pinned, try the next one.
                let prev = self.lru[candidate as usize].prev;
                if prev == NO_SLOT {
                    break;
                }
                // Move pinned tail to head to avoid repeated failures.
                self.lru_touch(candidate);
                continue;
            }
            self.lru_remove(candidate);
            self.slots[candidate as usize] = None;
            self.count -= 1;
            self.evictions += 1;
            freed += 1;
        }
        freed
    }
}

impl Default for DentryCache {
    fn default() -> Self {
        Self::new()
    }
}

// ── DcacheStats ──────────────────────────────────────────────────────────────

/// Snapshot of dentry cache statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct DcacheStats {
    /// Total entries (positive + negative).
    pub total: usize,
    /// Negative dentry count.
    pub negative: usize,
    /// Pinned entries (use_count > 0).
    pub pinned: usize,
    /// Mount point entries.
    pub mountpoints: usize,
    /// Total cache hits since boot.
    pub hits: u64,
    /// Total cache misses since boot.
    pub misses: u64,
    /// Total evictions since boot.
    pub evictions: u64,
}

impl DcacheStats {
    /// Return the hit rate as a percentage (0–100), or 0 if no lookups.
    pub fn hit_rate_pct(&self) -> u64 {
        let total = self.hits + self.misses;
        if total == 0 {
            return 0;
        }
        self.hits * 100 / total
    }
}

// ── Linux-named dentry API ────────────────────────────────────────────────────
//
// These functions mirror the Linux dcache API from fs/dcache.c.
// They are thin wrappers around DentryCache that use the canonical names
// expected by callers that know the Linux VFS interface.

/// Allocate and initialise a new dentry for `(parent_ino, name, child_ino)`.
///
/// Mirrors `d_alloc()`. The new entry is positive and inserted into the
/// cache at the head of the LRU list. Returns `Err(InvalidArgument)` if
/// `name` is empty or exceeds `NAME_MAX`, `Err(OutOfMemory)` if the cache
/// is full and no evictable slot exists.
pub fn d_alloc(
    cache: &mut DentryCache,
    parent_ino: InodeNumber,
    name: &[u8],
    child_ino: InodeNumber,
) -> Result<()> {
    cache.insert_positive(parent_ino, name, child_ino, 0)
}

/// Look up `(parent_ino, name)` in the dentry cache.
///
/// Mirrors `d_lookup()`. Returns `Ok(Some(&DentryEntry))` on any hit
/// (positive or negative), `Ok(None)` on a miss.
pub fn d_lookup<'a>(
    cache: &'a mut DentryCache,
    parent_ino: InodeNumber,
    name: &[u8],
) -> Result<Option<&'a DentryEntry>> {
    cache.lookup(parent_ino, name)
}

/// Add a positive dentry to the cache after a successful filesystem lookup.
///
/// Mirrors `d_add()`: combines alloc + install. If the entry is already
/// present as positive (race with another lookup), the existing entry is
/// left in place.  A negative entry at the same slot is replaced.
pub fn d_add(
    cache: &mut DentryCache,
    parent_ino: InodeNumber,
    name: &[u8],
    child_ino: InodeNumber,
) -> Result<()> {
    // Snapshot current state to avoid borrow conflicts.
    let state = cache
        .lookup(parent_ino, name)?
        .map(|e| (e.is_negative(), e.child_ino));
    match state {
        Some((false, _existing_ino)) => Ok(()), // positive hit — leave in place
        Some((true, _)) => {
            // Replace negative with positive.
            cache.invalidate(parent_ino, name)?;
            cache.insert_positive(parent_ino, name, child_ino, 0)
        }
        None => cache.insert_positive(parent_ino, name, child_ino, 0),
    }
}

/// Delete (invalidate) a dentry from the cache.
///
/// Mirrors `d_delete()`. The entry is marked unhashed; if its use count is
/// already zero it is freed immediately.
pub fn d_delete(cache: &mut DentryCache, parent_ino: InodeNumber, name: &[u8]) -> Result<()> {
    cache.invalidate(parent_ino, name)
}

/// Mark a dentry as a negative entry after a failed filesystem lookup.
///
/// Mirrors `d_add()` with a NULL inode (negative variant).
pub fn d_add_negative(cache: &mut DentryCache, parent_ino: InodeNumber, name: &[u8]) -> Result<()> {
    // Remove any stale entry first.
    let _ = cache.invalidate(parent_ino, name);
    cache.insert_negative(parent_ino, name)
}

/// Drop a reference to a dentry.
///
/// Mirrors `dput()`. Decrements use count; if the entry is unhashed and
/// the count reaches 0, the slot is freed immediately.
pub fn dput(cache: &mut DentryCache, parent_ino: InodeNumber, name: &[u8]) -> Result<()> {
    cache.put(parent_ino, name)
}

/// Acquire a reference to a dentry (prevent eviction).
///
/// Mirrors `dget()`.
pub fn dget(cache: &mut DentryCache, parent_ino: InodeNumber, name: &[u8]) -> Result<()> {
    cache.get(parent_ino, name)
}

/// Prune negative dentries from the cache under memory pressure.
///
/// Removes up to `max` negative, unreferenced entries from the LRU tail.
/// Returns the number of entries pruned.
pub fn prune_negative_dentries(cache: &mut DentryCache, max: usize) -> usize {
    // Snapshot candidate (parent_ino, name) pairs to avoid mid-loop borrows.
    let mut candidates: [(InodeNumber, [u8; NAME_MAX], usize); 64] =
        [(InodeNumber(0), [0u8; NAME_MAX], 0); 64];
    let mut count = 0usize;

    for slot in cache.slots.iter().flatten() {
        if count >= max.min(64) {
            break;
        }
        if slot.is_negative() && slot.use_count == 0 {
            let name_len = slot.name.len();
            let mut name_buf = [0u8; NAME_MAX];
            name_buf[..name_len].copy_from_slice(slot.name.as_bytes());
            candidates[count] = (slot.parent_ino, name_buf, name_len);
            count += 1;
        }
    }

    let mut pruned = 0usize;
    for (parent_ino, name_buf, name_len) in candidates.iter().take(count) {
        if cache
            .invalidate(*parent_ino, &name_buf[..*name_len])
            .is_ok()
        {
            pruned += 1;
        }
    }
    pruned
}

// ── Per-superblock dentry list ────────────────────────────────────────────────

/// Maximum dentries tracked per superblock.
const MAX_SB_DENTRIES: usize = 512;

/// A reference to a dentry registered with a superblock.
#[derive(Debug, Clone, Copy)]
pub struct SbDentryRef {
    /// Parent inode number.
    pub parent_ino: InodeNumber,
    /// Child inode number (0 for negative entries).
    pub child_ino: InodeNumber,
    /// Name length.
    pub name_len: usize,
    /// Name bytes.
    pub name_buf: [u8; NAME_MAX],
}

impl SbDentryRef {
    /// Create a new superblock dentry reference. Returns `None` if name is
    /// invalid.
    pub fn new(parent_ino: InodeNumber, child_ino: InodeNumber, name: &[u8]) -> Option<Self> {
        if name.is_empty() || name.len() > NAME_MAX {
            return None;
        }
        let mut name_buf = [0u8; NAME_MAX];
        name_buf[..name.len()].copy_from_slice(name);
        Some(Self {
            parent_ino,
            child_ino,
            name_len: name.len(),
            name_buf,
        })
    }

    /// Return the name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name_buf[..self.name_len]
    }
}

/// Per-superblock list of dentries.
///
/// Allows the VFS to iterate all dentries belonging to a specific
/// superblock, e.g., during unmount or filesystem invalidation.
///
/// Mirrors Linux's `super_block.s_dentry_lru` and `s_nr_dentry_unused`.
pub struct SbDentryList {
    /// Superblock identifier.
    pub sb_id: u64,
    entries: [Option<SbDentryRef>; MAX_SB_DENTRIES],
    count: usize,
}

impl SbDentryList {
    /// Create a new per-superblock dentry list.
    pub fn new(sb_id: u64) -> Self {
        Self {
            sb_id,
            entries: core::array::from_fn(|_| None),
            count: 0,
        }
    }

    /// Register a dentry with this superblock.
    pub fn add(
        &mut self,
        parent_ino: InodeNumber,
        child_ino: InodeNumber,
        name: &[u8],
    ) -> Result<()> {
        if self.count >= MAX_SB_DENTRIES {
            return Err(Error::OutOfMemory);
        }
        let dref = SbDentryRef::new(parent_ino, child_ino, name).ok_or(Error::InvalidArgument)?;
        for slot in &mut self.entries {
            if slot.is_none() {
                *slot = Some(dref);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a dentry registration by parent inode + name.
    pub fn remove(&mut self, parent_ino: InodeNumber, name: &[u8]) {
        for slot in &mut self.entries {
            let matches = slot
                .as_ref()
                .map(|d| d.parent_ino == parent_ino && d.name() == name)
                .unwrap_or(false);
            if matches {
                *slot = None;
                self.count -= 1;
                return;
            }
        }
    }

    /// Iterate all registered dentries.
    pub fn iter(&self) -> impl Iterator<Item = &SbDentryRef> {
        self.entries.iter().flatten()
    }

    /// Number of registered dentries.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if the list is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Invalidate all dentries for this superblock in the global cache.
    ///
    /// Called during unmount. After this call the list is empty.
    pub fn invalidate_all(&mut self, cache: &mut DentryCache) {
        for slot in &mut self.entries {
            // Capture (parent_ino, name) before clearing the slot.
            let info = slot.as_ref().map(|d| {
                let mut nb = [0u8; NAME_MAX];
                nb[..d.name_len].copy_from_slice(&d.name_buf[..d.name_len]);
                (d.parent_ino, nb, d.name_len)
            });
            *slot = None;
            if let Some((parent_ino, name_buf, name_len)) = info {
                let _ = cache.invalidate(parent_ino, &name_buf[..name_len]);
            }
        }
        self.count = 0;
    }

    /// Shrink up to `target` unreferenced dentries.
    ///
    /// Invalidates dentries with `use_count == 0` from the cache and
    /// removes them from this list. Returns the number freed.
    pub fn shrink(&mut self, cache: &mut DentryCache, target: usize) -> usize {
        let mut freed = 0usize;
        for slot in &mut self.entries {
            if freed >= target {
                break;
            }
            // Snapshot info without holding ref across the mutable cache call.
            let info = slot.as_ref().map(|d| {
                let mut nb = [0u8; NAME_MAX];
                nb[..d.name_len].copy_from_slice(&d.name_buf[..d.name_len]);
                (d.parent_ino, nb, d.name_len)
            });
            if let Some((parent_ino, name_buf, name_len)) = info {
                let name = &name_buf[..name_len];
                let use_count = cache
                    .lookup(parent_ino, name)
                    .ok()
                    .flatten()
                    .map(|e| e.use_count)
                    .unwrap_or(0);
                if use_count == 0 {
                    let _ = cache.invalidate(parent_ino, name);
                    *slot = None;
                    self.count -= 1;
                    freed += 1;
                }
            }
        }
        freed
    }
}

// ── Dcache shrink callback ────────────────────────────────────────────────────

/// Result of a dcache shrink operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct ShrinkResult {
    /// Dentries freed by this shrink call.
    pub freed: usize,
    /// Dentries remaining after shrink.
    pub remaining: usize,
    /// Dentries that could not be freed (pinned / use_count > 0).
    pub skipped: usize,
}

/// Dcache memory-pressure shrink callback.
///
/// Mirrors Linux's `dcache_shrinker` (`shrink_dcache_sb()` /
/// `shrink_dcache_memory()`).
///
/// # Arguments
///
/// - `cache`: the global dentry cache
/// - `sb_list`: optional per-superblock list to restrict scope (`None` = global)
/// - `nr_to_scan`: number of entries to attempt to free
///
/// Returns a `ShrinkResult` describing what happened.
pub fn dcache_shrink(
    cache: &mut DentryCache,
    sb_list: Option<&mut SbDentryList>,
    nr_to_scan: usize,
) -> ShrinkResult {
    let freed;

    if let Some(sb) = sb_list {
        freed = sb.shrink(cache, nr_to_scan);
    } else {
        freed = cache.shrink(nr_to_scan);
    }

    let remaining = cache.count();
    let skipped = nr_to_scan.saturating_sub(freed);

    ShrinkResult {
        freed,
        remaining,
        skipped,
    }
}

/// Estimate the number of freeable dentries (for shrinker registration).
///
/// Returns the count of unreferenced entries (use_count == 0).
pub fn dcache_count_freeable(cache: &DentryCache) -> usize {
    cache
        .slots
        .iter()
        .flatten()
        .filter(|e| e.use_count == 0)
        .count()
}

// ── Dentry rename helper ──────────────────────────────────────────────────────

/// Rename a cached dentry from `(old_parent, old_name)` to `(new_parent, new_name)`.
///
/// Mirrors the dcache side of `d_move()`. Invalidates the old entry and
/// inserts a new positive entry at the new location. Returns `Err(NotFound)`
/// if the old entry is not in the cache.
pub fn d_move(
    cache: &mut DentryCache,
    old_parent: InodeNumber,
    old_name: &[u8],
    new_parent: InodeNumber,
    new_name: &[u8],
) -> Result<()> {
    // Snapshot child inode and flags before invalidation.
    let (child_ino, flags) = {
        let entry = cache.lookup(old_parent, old_name)?.ok_or(Error::NotFound)?;
        (
            entry.child_ino,
            entry.flags & !(DCACHE_UNHASHED | DCACHE_NEGATIVE),
        )
    };
    cache.invalidate(old_parent, old_name)?;
    // Remove any existing entry at the target path.
    let _ = cache.invalidate(new_parent, new_name);
    cache.insert_positive(new_parent, new_name, child_ino, flags)
}

// ── Reverse alias lookup ──────────────────────────────────────────────────────

/// Collect all dentries in the cache whose child inode is `child_ino`.
///
/// Used for reverse path construction (e.g., `/proc/self/fd` readlinks).
/// Returns a `Vec` of `(parent_ino, name_bytes)` pairs for valid entries.
pub fn d_find_aliases(
    cache: &DentryCache,
    child_ino: InodeNumber,
) -> Vec<(InodeNumber, alloc::vec::Vec<u8>)> {
    let mut result = Vec::new();
    for slot in cache.slots.iter().flatten() {
        if slot.child_ino == child_ino && slot.is_valid() {
            result.push((slot.parent_ino, slot.name.as_bytes().to_vec()));
        }
    }
    result
}

/// Return the number of negative dentries in the cache.
pub fn dcache_negative_count(cache: &DentryCache) -> usize {
    cache
        .slots
        .iter()
        .flatten()
        .filter(|e| e.is_negative())
        .count()
}

/// Return the number of pinned (use_count > 0) dentries in the cache.
pub fn dcache_pinned_count(cache: &DentryCache) -> usize {
    cache
        .slots
        .iter()
        .flatten()
        .filter(|e| e.use_count > 0)
        .count()
}
