// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-process memory descriptor (`mm_struct` equivalent).
//!
//! Each process in the ONCRIX kernel has an associated memory descriptor
//! that tracks its virtual address space layout, page table root, VM
//! accounting, and resource limits. This module implements the core
//! memory descriptor type and a table for managing all active descriptors.
//!
//! # Design
//!
//! The memory descriptor is the kernel's per-process record of:
//! - **Page table root** (`pgd_phys`): physical address of the PML4.
//! - **Address space layout**: mmap base, stack, brk (heap) bounds.
//! - **VM accounting**: total, locked, pinned, data, exec, stack pages.
//! - **Resource limits**: max mappings, max stack size, brk region.
//! - **Reference counting**: use count (threads) + mm count (kernel refs).
//!
//! Fork creates a new `MmStruct` via `dup_mm`, which copies the layout
//! and accounting but gives the child a fresh page table root (CoW
//! mappings are set up by the page table layer).
//!
//! # Subsystems
//!
//! - [`MmFlags`] — per-mm bitflags (dumpable, ASLR, uprobes)
//! - [`MmUsers`] — reference counting (use_count + mm_count)
//! - [`MmLimits`] — resource limits (max maps, stack, brk region)
//! - [`MmStruct`] — the core per-process memory descriptor
//! - [`MmTable`] — system-wide table of all active mm descriptors
//! - [`MmStats`] — aggregate statistics
//!
//! Reference: Linux `include/linux/mm_types.h` (`struct mm_struct`),
//! `kernel/fork.c` (`dup_mmap`, `copy_mm`).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of mm descriptors in the system.
const MAX_MM_ENTRIES: usize = 256;

/// Standard page size in bytes (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Default task size (user address space limit): 128 TiB.
const DEFAULT_TASK_SIZE: u64 = 0x0000_7FFF_FFFF_F000;

/// Default mmap base address (with ASLR this would be randomized).
const DEFAULT_MMAP_BASE: u64 = 0x0000_7F00_0000_0000;

/// Default maximum number of memory mappings per process.
const DEFAULT_MAX_MAP_COUNT: u32 = 65536;

/// Default maximum stack size in bytes (8 MiB).
const DEFAULT_MAX_STACK_SIZE: u64 = 8 * 1024 * 1024;

/// Invalid mm_id sentinel.
const INVALID_MM_ID: u32 = u32::MAX;

// -------------------------------------------------------------------
// MmFlags
// -------------------------------------------------------------------

/// Per-mm flags controlling process memory behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MmFlags(u32);

impl MmFlags {
    /// Process core dump is allowed.
    pub const DUMPABLE: Self = Self(1 << 0);

    /// Virtual address space layout randomization is enabled.
    pub const RANDOMIZE_VA: Self = Self(1 << 1);

    /// User-space probes (uprobes) are registered on this mm.
    pub const HAS_UPROBES: Self = Self(1 << 2);

    /// Memory is being torn down (exit_mm in progress).
    pub const TEARING_DOWN: Self = Self(1 << 3);

    /// OOM reaper is allowed to reap this mm.
    pub const OOM_REAPABLE: Self = Self(1 << 4);

    /// This mm has had its page tables duplicated (post-fork).
    pub const FORKED: Self = Self(1 << 5);

    /// KASAN shadow memory is enabled.
    pub const KASAN_ENABLED: Self = Self(1 << 6);

    /// Memory descriptor has been locked (mlock_all).
    pub const LOCKED: Self = Self(1 << 7);

    /// No flags set.
    pub const NONE: Self = Self(0);

    /// Create flags from a raw `u32` value.
    pub const fn from_raw(v: u32) -> Self {
        Self(v)
    }

    /// Return the raw `u32` representation.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Check whether `other` flags are all present in `self`.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Combine two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Remove specific flags.
    pub const fn difference(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Whether no flags are set.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

// -------------------------------------------------------------------
// MmUsers
// -------------------------------------------------------------------

/// Reference counting for a memory descriptor.
///
/// - `use_count`: number of threads sharing this mm (decremented on
///   thread exit; when it reaches zero, the address space is torn down).
/// - `mm_count`: number of kernel references to this mm (including
///   one for `use_count > 0`). When `mm_count` reaches zero, the
///   `MmStruct` itself can be freed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmUsers {
    /// Number of threads using this mm.
    pub use_count: u32,
    /// Number of kernel references.
    pub mm_count: u32,
}

impl MmUsers {
    /// Create a new reference counter with one user and one kernel ref.
    pub const fn new() -> Self {
        Self {
            use_count: 1,
            mm_count: 1,
        }
    }

    /// Create an empty (zero-ref) counter.
    pub const fn empty() -> Self {
        Self {
            use_count: 0,
            mm_count: 0,
        }
    }

    /// Increment the use count.
    pub fn get(&mut self) {
        self.use_count = self.use_count.saturating_add(1);
    }

    /// Decrement the use count.
    ///
    /// Returns `true` if the use count has reached zero (tear down).
    pub fn put(&mut self) -> bool {
        self.use_count = self.use_count.saturating_sub(1);
        self.use_count == 0
    }

    /// Increment the mm kernel reference count.
    pub fn grab(&mut self) {
        self.mm_count = self.mm_count.saturating_add(1);
    }

    /// Decrement the mm kernel reference count.
    ///
    /// Returns `true` if the mm_count has reached zero (can free).
    pub fn drop_ref(&mut self) -> bool {
        self.mm_count = self.mm_count.saturating_sub(1);
        self.mm_count == 0
    }

    /// Whether the mm is still in use by at least one thread.
    pub const fn in_use(&self) -> bool {
        self.use_count > 0
    }

    /// Whether there are any kernel references remaining.
    pub const fn has_refs(&self) -> bool {
        self.mm_count > 0
    }
}

impl Default for MmUsers {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MmLimits
// -------------------------------------------------------------------

/// Per-process memory resource limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmLimits {
    /// Maximum number of memory mappings (VMAs).
    pub max_map_count: u32,
    /// Maximum stack size in bytes.
    pub max_stack_size: u64,
    /// Start of the brk (heap) region.
    pub brk_start: u64,
    /// Current end of the brk region.
    pub brk_end: u64,
    /// Maximum brk size in bytes (0 = unlimited).
    pub max_brk_size: u64,
    /// Maximum locked memory in bytes.
    pub max_locked_bytes: u64,
    /// Maximum address space size in bytes (0 = task_size).
    pub max_as_bytes: u64,
}

impl MmLimits {
    /// Create default limits.
    pub const fn new() -> Self {
        Self {
            max_map_count: DEFAULT_MAX_MAP_COUNT,
            max_stack_size: DEFAULT_MAX_STACK_SIZE,
            brk_start: 0,
            brk_end: 0,
            max_brk_size: 0,
            max_locked_bytes: 64 * 1024 * 1024, // 64 MiB
            max_as_bytes: 0,
        }
    }

    /// Current brk region size in bytes.
    pub const fn brk_size(&self) -> u64 {
        if self.brk_end > self.brk_start {
            self.brk_end - self.brk_start
        } else {
            0
        }
    }

    /// Current brk region size in pages.
    pub const fn brk_pages(&self) -> u64 {
        self.brk_size() / PAGE_SIZE
    }

    /// Whether the brk limit has been reached.
    pub const fn brk_at_limit(&self) -> bool {
        if self.max_brk_size == 0 {
            return false; // unlimited
        }
        self.brk_size() >= self.max_brk_size
    }

    /// Attempt to extend the brk region by `delta` bytes.
    ///
    /// Returns the new brk end on success.
    pub fn extend_brk(&mut self, delta: u64) -> Result<u64> {
        let new_end = self.brk_end.checked_add(delta).ok_or(Error::OutOfMemory)?;
        if self.max_brk_size > 0 {
            let new_size = new_end.saturating_sub(self.brk_start);
            if new_size > self.max_brk_size {
                return Err(Error::OutOfMemory);
            }
        }
        self.brk_end = new_end;
        Ok(new_end)
    }
}

impl Default for MmLimits {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MmStruct
// -------------------------------------------------------------------

/// Per-process memory descriptor.
///
/// Tracks the virtual address space layout, page table root, VM
/// accounting counters, and resource limits for a single process.
#[derive(Debug, Clone, Copy)]
pub struct MmStruct {
    /// Unique mm identifier (index into MmTable).
    pub mm_id: u32,
    /// Physical address of the PML4 (page global directory).
    pub pgd_phys: u64,
    /// Base address for mmap allocations.
    pub mmap_base: u64,
    /// Maximum user-space virtual address.
    pub task_size: u64,
    /// Total pages mapped in the virtual address space.
    pub total_vm: u64,
    /// Pages locked in memory (mlock).
    pub locked_vm: u64,
    /// Pages pinned for DMA or similar.
    pub pinned_vm: u64,
    /// Pages used for data segments.
    pub data_vm: u64,
    /// Pages used for executable segments.
    pub exec_vm: u64,
    /// Pages used for the stack.
    pub stack_vm: u64,
    /// Reference counters.
    pub users: MmUsers,
    /// Per-mm flags.
    pub flags: MmFlags,
    /// Resource limits.
    pub limits: MmLimits,
    /// Number of VMAs (memory mappings).
    pub map_count: u32,
    /// Owning process ID.
    pub owner_pid: u32,
    /// Start address of the code segment.
    pub start_code: u64,
    /// End address of the code segment.
    pub end_code: u64,
    /// Start address of the data segment.
    pub start_data: u64,
    /// End address of the data segment.
    pub end_data: u64,
    /// Start address of the stack.
    pub start_stack: u64,
    /// Start address of command-line arguments.
    pub arg_start: u64,
    /// End address of command-line arguments.
    pub arg_end: u64,
    /// Start address of environment variables.
    pub env_start: u64,
    /// End address of environment variables.
    pub env_end: u64,
    /// Whether this slot is in use.
    active: bool,
}

impl MmStruct {
    /// Create an empty (unused) mm descriptor.
    const fn empty() -> Self {
        Self {
            mm_id: INVALID_MM_ID,
            pgd_phys: 0,
            mmap_base: DEFAULT_MMAP_BASE,
            task_size: DEFAULT_TASK_SIZE,
            total_vm: 0,
            locked_vm: 0,
            pinned_vm: 0,
            data_vm: 0,
            exec_vm: 0,
            stack_vm: 0,
            users: MmUsers::empty(),
            flags: MmFlags::NONE,
            limits: MmLimits::new(),
            map_count: 0,
            owner_pid: 0,
            start_code: 0,
            end_code: 0,
            start_data: 0,
            end_data: 0,
            start_stack: 0,
            arg_start: 0,
            arg_end: 0,
            env_start: 0,
            env_end: 0,
            active: false,
        }
    }

    /// Whether this mm descriptor is active (in use).
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Total resident virtual memory in bytes.
    pub const fn total_vm_bytes(&self) -> u64 {
        self.total_vm * PAGE_SIZE
    }

    /// Locked memory in bytes.
    pub const fn locked_bytes(&self) -> u64 {
        self.locked_vm * PAGE_SIZE
    }

    /// Pinned memory in bytes.
    pub const fn pinned_bytes(&self) -> u64 {
        self.pinned_vm * PAGE_SIZE
    }

    /// Code segment size in bytes.
    pub const fn code_size(&self) -> u64 {
        if self.end_code > self.start_code {
            self.end_code - self.start_code
        } else {
            0
        }
    }

    /// Data segment size in bytes.
    pub const fn data_size(&self) -> u64 {
        if self.end_data > self.start_data {
            self.end_data - self.start_data
        } else {
            0
        }
    }

    /// Whether ASLR is enabled for this process.
    pub const fn is_randomized(&self) -> bool {
        self.flags.contains(MmFlags::RANDOMIZE_VA)
    }

    /// Whether the process core is dumpable.
    pub const fn is_dumpable(&self) -> bool {
        self.flags.contains(MmFlags::DUMPABLE)
    }

    /// Whether the mm is being torn down.
    pub const fn is_tearing_down(&self) -> bool {
        self.flags.contains(MmFlags::TEARING_DOWN)
    }

    /// Increment VM accounting by `pages` for total_vm.
    pub fn account_vm(&mut self, pages: u64) -> Result<()> {
        self.total_vm = self.total_vm.checked_add(pages).ok_or(Error::OutOfMemory)?;
        Ok(())
    }

    /// Decrement VM accounting by `pages` for total_vm.
    pub fn unaccount_vm(&mut self, pages: u64) {
        self.total_vm = self.total_vm.saturating_sub(pages);
    }

    /// Lock `pages` in memory, respecting the limit.
    pub fn lock_vm(&mut self, pages: u64) -> Result<()> {
        let new_locked = self
            .locked_vm
            .checked_add(pages)
            .ok_or(Error::OutOfMemory)?;
        let limit_pages = self.limits.max_locked_bytes / PAGE_SIZE;
        if limit_pages > 0 && new_locked > limit_pages {
            return Err(Error::OutOfMemory);
        }
        self.locked_vm = new_locked;
        Ok(())
    }

    /// Unlock `pages` from memory.
    pub fn unlock_vm(&mut self, pages: u64) {
        self.locked_vm = self.locked_vm.saturating_sub(pages);
    }

    /// Pin `pages` for DMA.
    pub fn pin_vm(&mut self, pages: u64) -> Result<()> {
        self.pinned_vm = self
            .pinned_vm
            .checked_add(pages)
            .ok_or(Error::OutOfMemory)?;
        Ok(())
    }

    /// Unpin `pages`.
    pub fn unpin_vm(&mut self, pages: u64) {
        self.pinned_vm = self.pinned_vm.saturating_sub(pages);
    }
}

// -------------------------------------------------------------------
// MmStats
// -------------------------------------------------------------------

/// Aggregate mm subsystem statistics.
#[derive(Debug, Clone, Copy, Default)]
pub struct MmStats {
    /// Total mm descriptors allocated since boot.
    pub total_allocated: u64,
    /// Total mm descriptors freed since boot.
    pub total_freed: u64,
    /// Currently active mm descriptors.
    pub current_active: u64,
    /// Peak number of active mm descriptors.
    pub peak_active: u64,
    /// Total fork (dup_mm) operations.
    pub total_forks: u64,
    /// Total exit_mm operations.
    pub total_exits: u64,
    /// Total pages across all active mms.
    pub total_vm_pages: u64,
    /// Total locked pages across all active mms.
    pub total_locked_pages: u64,
}

impl MmStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_allocated: 0,
            total_freed: 0,
            current_active: 0,
            peak_active: 0,
            total_forks: 0,
            total_exits: 0,
            total_vm_pages: 0,
            total_locked_pages: 0,
        }
    }
}

// -------------------------------------------------------------------
// MmTable
// -------------------------------------------------------------------

/// System-wide table of all memory descriptors.
///
/// Manages allocation, deallocation, lookup, and fork (duplication)
/// of per-process mm descriptors.
pub struct MmTable {
    /// The descriptor table.
    entries: [MmStruct; MAX_MM_ENTRIES],
    /// Number of active entries.
    active_count: usize,
    /// Next mm_id to try for allocation (simple sequential scan).
    next_id: u32,
    /// Aggregate statistics.
    stats: MmStats,
    /// Whether the table has been initialized.
    initialized: bool,
}

impl MmTable {
    /// Create a new uninitialized mm table.
    pub fn new() -> Self {
        Self {
            entries: [const { MmStruct::empty() }; MAX_MM_ENTRIES],
            active_count: 0,
            next_id: 0,
            stats: MmStats::new(),
            initialized: false,
        }
    }

    /// Initialize the mm table.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.initialized = true;
        Ok(())
    }

    /// Whether the table is initialized.
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Current statistics.
    pub const fn stats(&self) -> &MmStats {
        &self.stats
    }

    /// Number of active mm descriptors.
    pub const fn active_count(&self) -> usize {
        self.active_count
    }

    /// Allocate a new mm descriptor for a process.
    ///
    /// Returns the mm_id of the new descriptor.
    pub fn alloc_mm(&mut self, owner_pid: u32, pgd_phys: u64) -> Result<u32> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }
        if self.active_count >= MAX_MM_ENTRIES {
            return Err(Error::OutOfMemory);
        }

        // Find a free slot starting from next_id.
        let start = self.next_id as usize;
        let mut slot = None;
        for offset in 0..MAX_MM_ENTRIES {
            let idx = (start + offset) % MAX_MM_ENTRIES;
            if !self.entries[idx].active {
                slot = Some(idx);
                break;
            }
        }

        let idx = match slot {
            Some(s) => s,
            None => return Err(Error::OutOfMemory),
        };

        let mm_id = idx as u32;
        self.entries[idx] = MmStruct {
            mm_id,
            pgd_phys,
            mmap_base: DEFAULT_MMAP_BASE,
            task_size: DEFAULT_TASK_SIZE,
            total_vm: 0,
            locked_vm: 0,
            pinned_vm: 0,
            data_vm: 0,
            exec_vm: 0,
            stack_vm: 0,
            users: MmUsers::new(),
            flags: MmFlags::DUMPABLE.union(MmFlags::RANDOMIZE_VA),
            limits: MmLimits::new(),
            map_count: 0,
            owner_pid,
            start_code: 0,
            end_code: 0,
            start_data: 0,
            end_data: 0,
            start_stack: 0,
            arg_start: 0,
            arg_end: 0,
            env_start: 0,
            env_end: 0,
            active: true,
        };

        self.active_count += 1;
        self.next_id = ((idx + 1) % MAX_MM_ENTRIES) as u32;
        self.stats.total_allocated += 1;
        self.stats.current_active = self.active_count as u64;
        if self.stats.current_active > self.stats.peak_active {
            self.stats.peak_active = self.stats.current_active;
        }

        Ok(mm_id)
    }

    /// Free an mm descriptor.
    ///
    /// The mm must have no remaining users or kernel references.
    pub fn free_mm(&mut self, mm_id: u32) -> Result<()> {
        let idx = mm_id as usize;
        if idx >= MAX_MM_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        if !self.entries[idx].active {
            return Err(Error::NotFound);
        }
        if self.entries[idx].users.in_use() || self.entries[idx].users.has_refs() {
            return Err(Error::Busy);
        }

        self.entries[idx] = MmStruct::empty();
        self.active_count = self.active_count.saturating_sub(1);
        self.stats.total_freed += 1;
        self.stats.current_active = self.active_count as u64;

        Ok(())
    }

    /// Get a reference to an mm descriptor by id.
    pub fn get_mm(&self, mm_id: u32) -> Result<&MmStruct> {
        let idx = mm_id as usize;
        if idx >= MAX_MM_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        if !self.entries[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&self.entries[idx])
    }

    /// Get a mutable reference to an mm descriptor by id.
    pub fn get_mm_mut(&mut self, mm_id: u32) -> Result<&mut MmStruct> {
        let idx = mm_id as usize;
        if idx >= MAX_MM_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        if !self.entries[idx].active {
            return Err(Error::NotFound);
        }
        Ok(&mut self.entries[idx])
    }

    /// Increment the use count for an mm (new thread sharing it).
    pub fn get_mm_users(&mut self, mm_id: u32) -> Result<()> {
        let mm = self.get_mm_mut(mm_id)?;
        mm.users.get();
        Ok(())
    }

    /// Decrement the use count for an mm (thread exiting).
    ///
    /// Returns `true` if the use count reached zero (tear down needed).
    pub fn put_mm_users(&mut self, mm_id: u32) -> Result<bool> {
        let idx = mm_id as usize;
        if idx >= MAX_MM_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        if !self.entries[idx].active {
            return Err(Error::NotFound);
        }
        Ok(self.entries[idx].users.put())
    }

    /// Duplicate an mm descriptor (fork).
    ///
    /// Creates a new mm with the same layout and accounting as the
    /// source, but with a new pgd_phys (the caller is responsible for
    /// setting up CoW page tables).
    pub fn dup_mm(&mut self, src_mm_id: u32, new_owner_pid: u32, new_pgd_phys: u64) -> Result<u32> {
        // Read source fields first.
        let idx = src_mm_id as usize;
        if idx >= MAX_MM_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        if !self.entries[idx].active {
            return Err(Error::NotFound);
        }

        let src = self.entries[idx];

        // Allocate a new mm.
        let new_id = self.alloc_mm(new_owner_pid, new_pgd_phys)?;
        let new_idx = new_id as usize;

        // Copy layout and accounting from source.
        self.entries[new_idx].mmap_base = src.mmap_base;
        self.entries[new_idx].task_size = src.task_size;
        self.entries[new_idx].total_vm = src.total_vm;
        self.entries[new_idx].locked_vm = src.locked_vm;
        self.entries[new_idx].pinned_vm = 0; // pinned pages are not inherited
        self.entries[new_idx].data_vm = src.data_vm;
        self.entries[new_idx].exec_vm = src.exec_vm;
        self.entries[new_idx].stack_vm = src.stack_vm;
        self.entries[new_idx].flags = src.flags.union(MmFlags::FORKED);
        self.entries[new_idx].limits = src.limits;
        self.entries[new_idx].map_count = src.map_count;
        self.entries[new_idx].start_code = src.start_code;
        self.entries[new_idx].end_code = src.end_code;
        self.entries[new_idx].start_data = src.start_data;
        self.entries[new_idx].end_data = src.end_data;
        self.entries[new_idx].start_stack = src.start_stack;
        self.entries[new_idx].arg_start = src.arg_start;
        self.entries[new_idx].arg_end = src.arg_end;
        self.entries[new_idx].env_start = src.env_start;
        self.entries[new_idx].env_end = src.env_end;

        self.stats.total_forks += 1;

        Ok(new_id)
    }

    /// Handle process exit: decrement use count and mark for teardown.
    ///
    /// If this was the last thread, marks the mm as tearing down and
    /// decrements the kernel reference. Returns `true` if the mm can
    /// be freed immediately.
    pub fn exit_mm(&mut self, mm_id: u32) -> Result<bool> {
        let idx = mm_id as usize;
        if idx >= MAX_MM_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        if !self.entries[idx].active {
            return Err(Error::NotFound);
        }

        let last_user = self.entries[idx].users.put();
        if last_user {
            // Last thread: mark as tearing down.
            self.entries[idx].flags = self.entries[idx].flags.union(MmFlags::TEARING_DOWN);

            // Drop the kernel reference that was held for use_count > 0.
            let can_free = self.entries[idx].users.drop_ref();
            self.stats.total_exits += 1;

            if can_free {
                self.entries[idx] = MmStruct::empty();
                self.active_count = self.active_count.saturating_sub(1);
                self.stats.total_freed += 1;
                self.stats.current_active = self.active_count as u64;
            }

            return Ok(can_free);
        }

        Ok(false)
    }

    /// Refresh aggregate VM statistics from all active mms.
    pub fn refresh_stats(&mut self) {
        let mut total_vm: u64 = 0;
        let mut total_locked: u64 = 0;
        for entry in &self.entries {
            if entry.active {
                total_vm += entry.total_vm;
                total_locked += entry.locked_vm;
            }
        }
        self.stats.total_vm_pages = total_vm;
        self.stats.total_locked_pages = total_locked;
    }

    /// Find an mm by owner PID.
    pub fn find_by_pid(&self, pid: u32) -> Result<&MmStruct> {
        for entry in &self.entries {
            if entry.active && entry.owner_pid == pid {
                return Ok(entry);
            }
        }
        Err(Error::NotFound)
    }

    /// Count mms owned by a specific PID (for debugging).
    pub fn count_by_pid(&self, pid: u32) -> usize {
        let mut count = 0;
        for entry in &self.entries {
            if entry.active && entry.owner_pid == pid {
                count += 1;
            }
        }
        count
    }
}

impl Default for MmTable {
    fn default() -> Self {
        Self::new()
    }
}
