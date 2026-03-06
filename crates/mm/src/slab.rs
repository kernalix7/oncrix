// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Slab allocator for fixed-size kernel objects.
//!
//! Provides O(1) allocation and deallocation of fixed-size objects.
//! Each `SlabCache` manages objects of a single size, using a free-list
//! within a pre-allocated memory pool.
//!
//! This is the kernel's primary allocator for frequently created/destroyed
//! objects (PCBs, file descriptors, IPC endpoints, etc.), eliminating
//! fragmentation from the general-purpose heap for these hot paths.
//!
//! Design inspired by Bonwick's slab allocator (SunOS 5.4) and
//! Linux `mm/slub.c`.
//!
//! Reference: `.kernelORG/` — `mm/slub.rst`, `mm/slab_common.c`.

use core::ptr;

use oncrix_lib::{Error, Result};

/// Maximum number of slab caches in the system.
const MAX_CACHES: usize = 16;

/// Maximum number of slabs per cache.
const MAX_SLABS_PER_CACHE: usize = 8;

/// Slab size in bytes (4 KiB — one page).
const SLAB_SIZE: usize = 4096;

/// Minimum object size (must fit a free-list pointer).
const MIN_OBJECT_SIZE: usize = core::mem::size_of::<usize>();

/// A single slab — a page-sized block of memory divided into
/// equal-sized objects.
#[derive(Debug)]
pub struct Slab {
    /// Base address of the slab memory.
    base: *mut u8,
    /// Head of the per-slab free list (embedded in free objects).
    free_head: *mut u8,
    /// Number of objects currently allocated from this slab.
    in_use: usize,
    /// Total number of objects that fit in this slab.
    capacity: usize,
}

impl Slab {
    /// Initialize a slab over the given memory region.
    ///
    /// # Safety
    ///
    /// - `base` must point to a valid, writable, `SLAB_SIZE`-byte region.
    /// - `obj_size` must be >= `MIN_OBJECT_SIZE` and a multiple of
    ///   `MIN_OBJECT_SIZE`.
    pub unsafe fn init(base: *mut u8, obj_size: usize) -> Self {
        let capacity = SLAB_SIZE / obj_size;

        // Build the free list by writing next-pointers into each free slot.
        for i in 0..capacity {
            let slot = unsafe { base.add(i * obj_size) };
            let next = if i + 1 < capacity {
                unsafe { base.add((i + 1) * obj_size) }
            } else {
                ptr::null_mut()
            };
            // SAFETY: slot is within the slab region and properly aligned
            // for a pointer write (obj_size >= size_of::<usize>()).
            unsafe {
                (slot as *mut *mut u8).write(next);
            }
        }

        Self {
            base,
            free_head: base,
            in_use: 0,
            capacity,
        }
    }

    /// Allocate one object from this slab.
    ///
    /// Returns `None` if the slab is full.
    pub fn alloc(&mut self) -> Option<*mut u8> {
        if self.free_head.is_null() {
            return None;
        }
        let obj = self.free_head;
        // SAFETY: free_head points into our slab region and contains
        // a valid next pointer (or null for the last free slot).
        self.free_head = unsafe { (obj as *const *mut u8).read() };
        self.in_use += 1;
        Some(obj)
    }

    /// Free an object back to this slab.
    ///
    /// # Safety
    ///
    /// - `ptr` must have been allocated from this slab via [`alloc`](Self::alloc).
    /// - `ptr` must not be freed more than once (no double-free).
    pub unsafe fn free(&mut self, ptr: *mut u8) {
        // Write the current free_head into the freed slot.
        // SAFETY: ptr was allocated from this slab, so it has room
        // for a pointer and is properly aligned.
        unsafe {
            (ptr as *mut *mut u8).write(self.free_head);
        }
        self.free_head = ptr;
        self.in_use = self.in_use.saturating_sub(1);
    }

    /// Check if this slab has free objects.
    pub fn has_free(&self) -> bool {
        !self.free_head.is_null()
    }

    /// Check if this slab is completely empty (no objects in use).
    pub fn is_empty(&self) -> bool {
        self.in_use == 0
    }

    /// Check if `ptr` belongs to this slab.
    pub fn contains(&self, ptr: *mut u8) -> bool {
        let base = self.base as usize;
        let addr = ptr as usize;
        addr >= base && addr < base + SLAB_SIZE
    }

    /// Number of objects currently in use.
    pub fn in_use(&self) -> usize {
        self.in_use
    }

    /// Total capacity of this slab.
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

/// A slab cache — manages slabs for objects of a single fixed size.
///
/// Each cache holds up to `MAX_SLABS_PER_CACHE` slabs. When all
/// existing slabs are full and `grow()` is called, a new slab is
/// added (the caller must provide the backing memory).
pub struct SlabCache {
    /// Cache name (for diagnostics).
    name: [u8; 32],
    /// Name length.
    name_len: usize,
    /// Object size (aligned to `MIN_OBJECT_SIZE`).
    obj_size: usize,
    /// Slabs owned by this cache.
    slabs: [Option<Slab>; MAX_SLABS_PER_CACHE],
    /// Number of active slabs.
    slab_count: usize,
    /// Total allocations (for diagnostics).
    total_allocs: u64,
    /// Total frees (for diagnostics).
    total_frees: u64,
}

impl SlabCache {
    /// Create a new slab cache for objects of `obj_size` bytes.
    ///
    /// `obj_size` is rounded up to a multiple of pointer size.
    /// Returns `Err` if `obj_size` is zero or larger than `SLAB_SIZE`.
    pub fn new(name: &[u8], obj_size: usize) -> Result<Self> {
        if obj_size == 0 || obj_size > SLAB_SIZE {
            return Err(Error::InvalidArgument);
        }

        // Round up to pointer alignment.
        let aligned_size = align_up(obj_size, MIN_OBJECT_SIZE);

        let mut name_buf = [0u8; 32];
        let copy_len = name.len().min(32);
        name_buf[..copy_len].copy_from_slice(&name[..copy_len]);

        const NONE_SLAB: Option<Slab> = None;
        Ok(Self {
            name: name_buf,
            name_len: copy_len,
            obj_size: aligned_size,
            slabs: [NONE_SLAB; MAX_SLABS_PER_CACHE],
            slab_count: 0,
            total_allocs: 0,
            total_frees: 0,
        })
    }

    /// Add a new slab backed by the given memory page.
    ///
    /// # Safety
    ///
    /// - `page` must point to a valid, writable, `SLAB_SIZE`-byte region.
    /// - The memory must remain valid for the lifetime of this cache.
    pub unsafe fn grow(&mut self, page: *mut u8) -> Result<()> {
        if self.slab_count >= MAX_SLABS_PER_CACHE {
            return Err(Error::OutOfMemory);
        }

        // SAFETY: Caller guarantees the memory is valid.
        let slab = unsafe { Slab::init(page, self.obj_size) };

        for slot in self.slabs.iter_mut() {
            if slot.is_none() {
                *slot = Some(slab);
                self.slab_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Allocate one object from the cache.
    ///
    /// Searches existing slabs for a free slot. Returns `Err` if all
    /// slabs are full (caller should `grow()` and retry).
    pub fn alloc(&mut self) -> Result<*mut u8> {
        for slab in self.slabs.iter_mut().flatten() {
            if slab.has_free() {
                if let Some(ptr) = slab.alloc() {
                    self.total_allocs += 1;
                    return Ok(ptr);
                }
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Free an object back to its slab.
    ///
    /// # Safety
    ///
    /// - `ptr` must have been allocated from this cache via [`alloc`](Self::alloc).
    /// - `ptr` must not be freed more than once.
    pub unsafe fn free(&mut self, ptr: *mut u8) -> Result<()> {
        for slab in self.slabs.iter_mut().flatten() {
            if slab.contains(ptr) {
                // SAFETY: Caller guarantees ptr was allocated from this cache.
                unsafe { slab.free(ptr) };
                self.total_frees += 1;
                return Ok(());
            }
        }
        Err(Error::InvalidArgument)
    }

    /// Shrink the cache by releasing completely empty slabs.
    ///
    /// Returns the base addresses of freed slabs so the caller can
    /// return the pages to the frame allocator.
    pub fn shrink(&mut self) -> ShrinkResult {
        let mut result = ShrinkResult::new();
        for slot in self.slabs.iter_mut() {
            if let Some(slab) = slot {
                if slab.is_empty() {
                    if result.count < MAX_SLABS_PER_CACHE {
                        result.pages[result.count] = slab.base;
                        result.count += 1;
                    }
                    *slot = None;
                    self.slab_count = self.slab_count.saturating_sub(1);
                }
            }
        }
        result
    }

    /// Object size for this cache.
    pub fn obj_size(&self) -> usize {
        self.obj_size
    }

    /// Number of active slabs.
    pub fn slab_count(&self) -> usize {
        self.slab_count
    }

    /// Cache name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Total number of objects currently allocated.
    pub fn total_in_use(&self) -> usize {
        self.slabs
            .iter()
            .filter_map(|s| s.as_ref())
            .map(|s| s.in_use())
            .sum()
    }

    /// Total capacity across all slabs.
    pub fn total_capacity(&self) -> usize {
        self.slabs
            .iter()
            .filter_map(|s| s.as_ref())
            .map(|s| s.capacity())
            .sum()
    }

    /// Diagnostic statistics: (total_allocs, total_frees).
    pub fn stats(&self) -> (u64, u64) {
        (self.total_allocs, self.total_frees)
    }
}

impl core::fmt::Debug for SlabCache {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let name = core::str::from_utf8(self.name()).unwrap_or("<invalid>");
        f.debug_struct("SlabCache")
            .field("name", &name)
            .field("obj_size", &self.obj_size)
            .field("slabs", &self.slab_count)
            .field("in_use", &self.total_in_use())
            .field("capacity", &self.total_capacity())
            .finish()
    }
}

/// Result of a cache shrink operation.
pub struct ShrinkResult {
    /// Base addresses of freed slab pages.
    pub pages: [*mut u8; MAX_SLABS_PER_CACHE],
    /// Number of freed pages.
    pub count: usize,
}

impl ShrinkResult {
    fn new() -> Self {
        Self {
            pages: [ptr::null_mut(); MAX_SLABS_PER_CACHE],
            count: 0,
        }
    }
}

/// Global slab cache registry.
///
/// Manages all named slab caches in the kernel. Typical caches:
/// - `"pcb"` — process control blocks
/// - `"fd"` — file descriptors
/// - `"ipc_msg"` — IPC messages
/// - `"vma"` — virtual memory area descriptors
pub struct SlabRegistry {
    /// Named caches.
    caches: [Option<SlabCache>; MAX_CACHES],
    /// Number of active caches.
    count: usize,
}

impl Default for SlabRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SlabRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const NONE_CACHE: Option<SlabCache> = None;
        Self {
            caches: [NONE_CACHE; MAX_CACHES],
            count: 0,
        }
    }

    /// Create a new named slab cache.
    ///
    /// Returns the cache index on success.
    pub fn create_cache(&mut self, name: &[u8], obj_size: usize) -> Result<usize> {
        if self.count >= MAX_CACHES {
            return Err(Error::OutOfMemory);
        }

        let cache = SlabCache::new(name, obj_size)?;

        for (i, slot) in self.caches.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(cache);
                self.count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Look up a cache by index.
    pub fn get(&self, index: usize) -> Option<&SlabCache> {
        self.caches.get(index)?.as_ref()
    }

    /// Look up a cache by index (mutable).
    pub fn get_mut(&mut self, index: usize) -> Option<&mut SlabCache> {
        self.caches.get_mut(index)?.as_mut()
    }

    /// Find a cache by name.
    pub fn find_by_name(&self, name: &[u8]) -> Option<usize> {
        for (i, slot) in self.caches.iter().enumerate() {
            if let Some(cache) = slot {
                if cache.name() == name {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Remove a cache by index.
    ///
    /// Returns `Err` if the cache still has objects in use.
    pub fn destroy_cache(&mut self, index: usize) -> Result<()> {
        let cache = self
            .caches
            .get(index)
            .and_then(|c| c.as_ref())
            .ok_or(Error::InvalidArgument)?;

        if cache.total_in_use() > 0 {
            return Err(Error::Busy);
        }

        self.caches[index] = None;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Number of active caches.
    pub fn count(&self) -> usize {
        self.count
    }
}

impl core::fmt::Debug for SlabRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SlabRegistry")
            .field("active_caches", &self.count)
            .field("capacity", &MAX_CACHES)
            .finish()
    }
}

/// Align `value` up to the next multiple of `align`.
///
/// `align` must be a power of two.
const fn align_up(value: usize, align: usize) -> usize {
    let mask = align - 1;
    (value + mask) & !mask
}
