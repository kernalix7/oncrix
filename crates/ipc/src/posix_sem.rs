// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX semaphore implementation.
//!
//! Provides both unnamed and named semaphores following POSIX.1-2024
//! (`sem_init`, `sem_destroy`, `sem_open`, `sem_close`, `sem_unlink`,
//! `sem_wait`, `sem_trywait`, `sem_timedwait`, `sem_post`, `sem_getvalue`).
//!
//! Unnamed semaphores are initialized in-place and may be shared between
//! threads (pshared == 0) or processes (pshared != 0).  Named semaphores
//! live in a global registry and are reference-counted.
//!
//! # Limits
//!
//! | Limit | Value |
//! |-------|-------|
//! | `SEM_VALUE_MAX` | 2^31 - 1 |
//! | `SEM_NSEMS_MAX` | 256 |
//! | `SEM_NAME_MAX` | 64 bytes (including leading `/`) |
//!
//! # POSIX conformance
//!
//! This implementation follows IEEE Std 1003.1-2024.  The kernel-internal
//! representation does **not** expose a raw `sem_t` to user space; instead,
//! semaphore handles (small integer descriptors) are returned and looked up
//! through the registry.  This is an intentional deviation that simplifies
//! the kernel/user boundary.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants (POSIX limits)
// -------------------------------------------------------------------

/// Maximum value a semaphore counter may reach (POSIX `SEM_VALUE_MAX`).
///
/// POSIX requires this to be at least 32767.  We use 2^31 - 1 which
/// matches Linux.
pub const SEM_VALUE_MAX: u32 = 0x7FFF_FFFF;

/// Maximum number of semaphores system-wide (`SEM_NSEMS_MAX`).
const SEM_NSEMS_MAX: usize = 256;

/// Maximum length of a named semaphore name (including leading `/`).
const SEM_NAME_MAX: usize = 64;

/// Maximum number of named semaphore entries in the registry.
const SEM_NAMED_MAX: usize = 128;

/// Maximum number of per-process open handles to named semaphores.
const SEM_HANDLE_MAX: usize = 64;

// -------------------------------------------------------------------
// Open flags (subset of O_* relevant to sem_open)
// -------------------------------------------------------------------

/// Flags for [`sem_open`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemOpenFlags(u32);

impl SemOpenFlags {
    /// No flags.
    pub const NONE: Self = Self(0);
    /// Create the semaphore if it does not exist.
    pub const O_CREAT: Self = Self(1 << 0);
    /// Fail if the semaphore already exists (requires `O_CREAT`).
    pub const O_EXCL: Self = Self(1 << 1);

    /// Create from raw bits.
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Return raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Test whether a specific flag is set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }
}

// -------------------------------------------------------------------
// Mode (permissions)
// -------------------------------------------------------------------

/// Semaphore permission mode (mirrors POSIX `mode_t` subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemMode(u32);

impl SemMode {
    /// Default mode: owner rw, group r, other r (0644).
    pub const DEFAULT: Self = Self(0o644);

    /// Create from raw mode bits.
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw & 0o7777)
    }

    /// Return raw mode bits.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

// -------------------------------------------------------------------
// Timespec (for sem_timedwait / sem_clockwait)
// -------------------------------------------------------------------

/// Absolute timeout specification (POSIX `struct timespec`).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemTimespec {
    /// Seconds.
    pub tv_sec: i64,
    /// Nanoseconds (0..999_999_999).
    pub tv_nsec: i64,
}

impl SemTimespec {
    /// A zero timespec.
    pub const ZERO: Self = Self {
        tv_sec: 0,
        tv_nsec: 0,
    };

    /// Validate that the timespec values are in range.
    pub const fn is_valid(&self) -> bool {
        self.tv_sec >= 0 && self.tv_nsec >= 0 && self.tv_nsec < 1_000_000_000
    }
}

// -------------------------------------------------------------------
// SemaphoreState — shared between unnamed and named semaphores
// -------------------------------------------------------------------

/// Internal state of a single semaphore.
///
/// The `value` field is the counting semaphore counter.
/// `waiter_count` tracks how many threads/processes are blocked in
/// `sem_wait` — this is informational and used for `sem_getvalue`
/// when the counter is zero (POSIX allows returning a negative value
/// whose magnitude is the waiter count, or zero).
#[derive(Debug)]
struct SemaphoreState {
    /// Current counter value (0..=SEM_VALUE_MAX).
    value: u32,
    /// Number of threads blocked in sem_wait.
    waiter_count: u32,
    /// True if this semaphore slot is in use.
    active: bool,
    /// True if shared between processes (pshared != 0).
    process_shared: bool,
    /// Owner PID (the process that created the semaphore).
    owner_pid: u64,
    /// Generation counter to detect use-after-destroy.
    generation: u64,
}

impl SemaphoreState {
    const fn new() -> Self {
        Self {
            value: 0,
            waiter_count: 0,
            active: false,
            process_shared: false,
            owner_pid: 0,
            generation: 0,
        }
    }
}

// -------------------------------------------------------------------
// NamedSemEntry — registry entry for named semaphores
// -------------------------------------------------------------------

/// A named semaphore registry entry.
///
/// Named semaphores are identified by a `/`-prefixed name.  Multiple
/// processes can open the same named semaphore; the registry tracks
/// the reference count.
#[derive(Debug)]
struct NamedSemEntry {
    /// Name buffer (NUL-padded).
    name: [u8; SEM_NAME_MAX],
    /// Actual length of the name (not counting NUL).
    name_len: usize,
    /// Index into `SemRegistry.slots` for the underlying semaphore.
    sem_index: usize,
    /// Number of open handles (from all processes).
    ref_count: u32,
    /// True if `sem_unlink` has been called but handles remain.
    unlinked: bool,
    /// True if this registry entry is occupied.
    active: bool,
    /// Permission mode.
    mode: SemMode,
    /// Owner UID.
    owner_uid: u32,
    /// Owner GID.
    owner_gid: u32,
    /// Generation for handle validation.
    generation: u64,
}

impl NamedSemEntry {
    const fn new() -> Self {
        Self {
            name: [0u8; SEM_NAME_MAX],
            name_len: 0,
            sem_index: 0,
            ref_count: 0,
            unlinked: false,
            active: false,
            mode: SemMode::DEFAULT,
            owner_uid: 0,
            owner_gid: 0,
            generation: 0,
        }
    }
}

// -------------------------------------------------------------------
// SemHandle — per-process open descriptor
// -------------------------------------------------------------------

/// A per-process handle to a named semaphore.
///
/// Returned by `sem_open`, invalidated by `sem_close`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemHandle {
    /// Handle descriptor (index into handle table).
    pub descriptor: u32,
    /// Generation stamp for validation.
    generation: u64,
}

/// Per-process handle slot.
#[derive(Debug)]
struct HandleSlot {
    /// Index into `SemRegistry.named` array.
    named_index: usize,
    /// Generation of the named entry at open time.
    named_gen: u64,
    /// True if this handle slot is in use.
    active: bool,
    /// Handle generation.
    generation: u64,
}

impl HandleSlot {
    const fn new() -> Self {
        Self {
            named_index: 0,
            named_gen: 0,
            active: false,
            generation: 0,
        }
    }
}

// -------------------------------------------------------------------
// SemRegistry — the main semaphore registry
// -------------------------------------------------------------------

/// Global semaphore registry.
///
/// Contains both unnamed semaphore slots and named semaphore entries.
/// Fixed-size, no heap allocation.
pub struct SemRegistry {
    /// Unnamed + named semaphore state slots.
    slots: [SemaphoreState; SEM_NSEMS_MAX],
    /// Named semaphore name→slot mapping.
    named: [NamedSemEntry; SEM_NAMED_MAX],
    /// Per-process handle table (simplified: single process for now).
    handles: [HandleSlot; SEM_HANDLE_MAX],
    /// Next generation counter for semaphore slots.
    next_slot_gen: u64,
    /// Next generation counter for named entries.
    next_named_gen: u64,
    /// Next generation counter for handles.
    next_handle_gen: u64,
}

impl SemRegistry {
    /// Create a new, empty registry.
    pub const fn new() -> Self {
        Self {
            slots: [const { SemaphoreState::new() }; SEM_NSEMS_MAX],
            named: [const { NamedSemEntry::new() }; SEM_NAMED_MAX],
            handles: [const { HandleSlot::new() }; SEM_HANDLE_MAX],
            next_slot_gen: 1,
            next_named_gen: 1,
            next_handle_gen: 1,
        }
    }

    // ---------------------------------------------------------------
    // Internal helpers
    // ---------------------------------------------------------------

    /// Allocate a free semaphore slot, returning its index.
    fn alloc_slot(&mut self) -> Result<usize> {
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if !slot.active {
                slot.active = true;
                slot.generation = self.next_slot_gen;
                self.next_slot_gen += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a named entry by name.
    fn find_named(&self, name: &[u8]) -> Option<usize> {
        for (i, entry) in self.named.iter().enumerate() {
            if entry.active
                && !entry.unlinked
                && entry.name_len == name.len()
                && entry.name[..name.len()] == *name
            {
                return Some(i);
            }
        }
        None
    }

    /// Allocate a free named entry slot.
    fn alloc_named(&mut self) -> Result<usize> {
        for (i, entry) in self.named.iter_mut().enumerate() {
            if !entry.active {
                entry.active = true;
                entry.generation = self.next_named_gen;
                self.next_named_gen += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Allocate a free handle slot.
    fn alloc_handle(&mut self) -> Result<usize> {
        for (i, h) in self.handles.iter_mut().enumerate() {
            if !h.active {
                h.active = true;
                h.generation = self.next_handle_gen;
                self.next_handle_gen += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Validate a handle and return (named_index, sem_slot_index).
    fn resolve_handle(&self, handle: SemHandle) -> Result<(usize, usize)> {
        let idx = handle.descriptor as usize;
        if idx >= SEM_HANDLE_MAX {
            return Err(Error::InvalidArgument);
        }
        let h = &self.handles[idx];
        if !h.active || h.generation != handle.generation {
            return Err(Error::InvalidArgument);
        }
        let ni = h.named_index;
        if ni >= SEM_NAMED_MAX || !self.named[ni].active {
            return Err(Error::NotFound);
        }
        if self.named[ni].generation != h.named_gen {
            return Err(Error::NotFound);
        }
        let si = self.named[ni].sem_index;
        Ok((ni, si))
    }

    /// Validate a semaphore name per POSIX rules.
    ///
    /// The name must begin with `/`, be at most `SEM_NAME_MAX` bytes,
    /// and not be just `/`.
    fn validate_name(name: &[u8]) -> Result<()> {
        if name.is_empty() || name.len() > SEM_NAME_MAX {
            return Err(Error::InvalidArgument);
        }
        if name[0] != b'/' {
            return Err(Error::InvalidArgument);
        }
        if name.len() == 1 {
            // Just "/" is not a valid semaphore name.
            return Err(Error::InvalidArgument);
        }
        // No embedded NUL bytes.
        if name.iter().any(|&b| b == 0) {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Release a semaphore slot and potentially the named entry.
    fn release_named_entry(&mut self, ni: usize) {
        let entry = &mut self.named[ni];
        if entry.ref_count == 0 && entry.unlinked {
            let si = entry.sem_index;
            entry.active = false;
            entry.name_len = 0;
            // Also release the underlying slot.
            if si < SEM_NSEMS_MAX {
                self.slots[si].active = false;
            }
        }
    }

    // ---------------------------------------------------------------
    // Unnamed semaphore API (POSIX sem_init / sem_destroy)
    // ---------------------------------------------------------------

    /// Initialize an unnamed semaphore.
    ///
    /// Returns a semaphore slot index that the caller uses as an opaque
    /// handle for subsequent operations.
    ///
    /// # Arguments
    ///
    /// * `pshared` — if non-zero the semaphore may be shared between
    ///   processes.
    /// * `value` — initial counter value (must be <= `SEM_VALUE_MAX`).
    /// * `pid` — PID of the creating process.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — value exceeds `SEM_VALUE_MAX`.
    /// * `OutOfMemory` — no free semaphore slots.
    pub fn sem_init(&mut self, pshared: i32, value: u32, pid: u64) -> Result<usize> {
        if value > SEM_VALUE_MAX {
            return Err(Error::InvalidArgument);
        }

        let idx = self.alloc_slot()?;
        let slot = &mut self.slots[idx];
        slot.value = value;
        slot.waiter_count = 0;
        slot.process_shared = pshared != 0;
        slot.owner_pid = pid;
        Ok(idx)
    }

    /// Destroy an unnamed semaphore.
    ///
    /// The semaphore must not have any waiters.  Destroying a semaphore
    /// that other threads are waiting on is undefined behavior per POSIX;
    /// we return `Busy` instead.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — `sem_id` is out of range or not active.
    /// * `Busy` — threads are blocked on this semaphore.
    pub fn sem_destroy(&mut self, sem_id: usize) -> Result<()> {
        if sem_id >= SEM_NSEMS_MAX {
            return Err(Error::InvalidArgument);
        }
        let slot = &self.slots[sem_id];
        if !slot.active {
            return Err(Error::InvalidArgument);
        }
        if slot.waiter_count > 0 {
            return Err(Error::Busy);
        }
        self.slots[sem_id].active = false;
        Ok(())
    }

    // ---------------------------------------------------------------
    // Named semaphore API (POSIX sem_open / sem_close / sem_unlink)
    // ---------------------------------------------------------------

    /// Open (or create) a named semaphore.
    ///
    /// # Arguments
    ///
    /// * `name` — semaphore name (must begin with `/`).
    /// * `flags` — `O_CREAT` and/or `O_EXCL`.
    /// * `mode` — permission mode (used only when creating).
    /// * `value` — initial value (used only when creating).
    /// * `uid` — effective UID of the calling process.
    /// * `gid` — effective GID of the calling process.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — bad name or value > `SEM_VALUE_MAX`.
    /// * `AlreadyExists` — `O_CREAT | O_EXCL` and semaphore exists.
    /// * `NotFound` — no `O_CREAT` and semaphore does not exist.
    /// * `OutOfMemory` — no free registry slots or handle slots.
    pub fn sem_open(
        &mut self,
        name: &[u8],
        flags: SemOpenFlags,
        mode: SemMode,
        value: u32,
        uid: u32,
        gid: u32,
    ) -> Result<SemHandle> {
        Self::validate_name(name)?;

        let existing = self.find_named(name);

        if let Some(ni) = existing {
            // Semaphore exists.
            if flags.contains(SemOpenFlags::O_CREAT) && flags.contains(SemOpenFlags::O_EXCL) {
                return Err(Error::AlreadyExists);
            }
            // Open an existing semaphore — allocate a handle.
            let hi = self.alloc_handle()?;
            let cur_gen = self.named[ni].generation;
            self.handles[hi].named_index = ni;
            self.handles[hi].named_gen = cur_gen;
            self.named[ni].ref_count += 1;
            return Ok(SemHandle {
                descriptor: hi as u32,
                generation: self.handles[hi].generation,
            });
        }

        // Semaphore does not exist.
        if !flags.contains(SemOpenFlags::O_CREAT) {
            return Err(Error::NotFound);
        }

        if value > SEM_VALUE_MAX {
            return Err(Error::InvalidArgument);
        }

        // Allocate underlying semaphore slot.
        let si = self.alloc_slot()?;
        self.slots[si].value = value;
        self.slots[si].waiter_count = 0;
        self.slots[si].process_shared = true; // named are always shared
        self.slots[si].owner_pid = uid as u64;

        // Allocate named entry.
        let ni = match self.alloc_named() {
            Ok(idx) => idx,
            Err(e) => {
                // Roll back slot allocation.
                self.slots[si].active = false;
                return Err(e);
            }
        };
        let entry = &mut self.named[ni];
        let copy_len = name.len().min(SEM_NAME_MAX);
        entry.name[..copy_len].copy_from_slice(&name[..copy_len]);
        entry.name_len = copy_len;
        entry.sem_index = si;
        entry.ref_count = 1;
        entry.unlinked = false;
        entry.mode = mode;
        entry.owner_uid = uid;
        entry.owner_gid = gid;

        // Allocate process handle.
        let hi = match self.alloc_handle() {
            Ok(idx) => idx,
            Err(e) => {
                // Roll back named + slot allocation.
                self.named[ni].active = false;
                self.slots[si].active = false;
                return Err(e);
            }
        };
        self.handles[hi].named_index = ni;
        self.handles[hi].named_gen = self.named[ni].generation;

        Ok(SemHandle {
            descriptor: hi as u32,
            generation: self.handles[hi].generation,
        })
    }

    /// Close a named semaphore handle.
    ///
    /// Decrements the reference count.  If the semaphore was unlinked
    /// and this was the last reference, the underlying resources are freed.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — invalid handle.
    pub fn sem_close(&mut self, handle: SemHandle) -> Result<()> {
        let (ni, _si) = self.resolve_handle(handle)?;

        // Invalidate the handle slot.
        let hi = handle.descriptor as usize;
        self.handles[hi].active = false;

        // Decrement reference count.
        let entry = &mut self.named[ni];
        entry.ref_count = entry.ref_count.saturating_sub(1);

        // If unlinked and no more references, free everything.
        self.release_named_entry(ni);
        Ok(())
    }

    /// Remove a named semaphore from the namespace.
    ///
    /// The name is immediately removed so that subsequent `sem_open`
    /// calls with the same name will create a new semaphore.  The
    /// underlying resources are freed when the last handle is closed.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — bad name.
    /// * `NotFound` — no semaphore with this name exists.
    pub fn sem_unlink(&mut self, name: &[u8]) -> Result<()> {
        Self::validate_name(name)?;

        let ni = self.find_named(name).ok_or(Error::NotFound)?;
        self.named[ni].unlinked = true;

        // If no handles remain, free immediately.
        self.release_named_entry(ni);
        Ok(())
    }

    // ---------------------------------------------------------------
    // Semaphore operations (shared between named and unnamed)
    // ---------------------------------------------------------------

    /// Lock (decrement) a semaphore.
    ///
    /// If the counter is positive it is decremented and the call returns
    /// immediately.  If the counter is zero, this is a blocking call.
    /// In this stub implementation we return `WouldBlock` instead of
    /// actually blocking (the real kernel would enqueue the caller on
    /// a wait queue and schedule).
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — bad `sem_id`.
    /// * `WouldBlock` — counter is zero (stub: would block).
    /// * `Interrupted` — a signal was delivered.
    pub fn sem_wait(&mut self, sem_id: usize) -> Result<()> {
        let slot = self.get_slot_mut(sem_id)?;
        if slot.value > 0 {
            slot.value -= 1;
            Ok(())
        } else {
            // In a real kernel we would enqueue on the wait queue.
            // Increment waiter count for sem_getvalue reporting.
            slot.waiter_count += 1;
            Err(Error::WouldBlock)
        }
    }

    /// Try to lock a semaphore without blocking.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — bad `sem_id`.
    /// * `WouldBlock` — counter is zero (EAGAIN).
    pub fn sem_trywait(&mut self, sem_id: usize) -> Result<()> {
        let slot = self.get_slot_mut(sem_id)?;
        if slot.value > 0 {
            slot.value -= 1;
            Ok(())
        } else {
            Err(Error::WouldBlock)
        }
    }

    /// Timed wait on a semaphore.
    ///
    /// Like `sem_wait` but with an absolute timeout.  In this stub we
    /// only check whether the counter is positive (immediate success) or
    /// validate the timeout and return `WouldBlock`.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — bad `sem_id` or invalid `abstime`.
    /// * `WouldBlock` — counter is zero and timeout applies.
    pub fn sem_timedwait(&mut self, sem_id: usize, abstime: &SemTimespec) -> Result<()> {
        if !abstime.is_valid() {
            return Err(Error::InvalidArgument);
        }
        let slot = self.get_slot_mut(sem_id)?;
        if slot.value > 0 {
            slot.value -= 1;
            Ok(())
        } else {
            slot.waiter_count += 1;
            Err(Error::WouldBlock)
        }
    }

    /// Unlock (increment) a semaphore.
    ///
    /// If threads are waiting, one is woken (in the real kernel).
    /// The counter must not exceed `SEM_VALUE_MAX`.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — bad `sem_id`.
    /// * `InvalidArgument` — counter would overflow `SEM_VALUE_MAX`.
    pub fn sem_post(&mut self, sem_id: usize) -> Result<()> {
        let slot = self.get_slot_mut(sem_id)?;
        if slot.waiter_count > 0 {
            // Wake one waiter (in real kernel: dequeue from wait queue
            // and make runnable).  The counter stays the same because
            // the woken thread "consumes" the post.
            slot.waiter_count -= 1;
            Ok(())
        } else if slot.value >= SEM_VALUE_MAX {
            Err(Error::InvalidArgument)
        } else {
            slot.value += 1;
            Ok(())
        }
    }

    /// Get the current value of a semaphore.
    ///
    /// POSIX allows two behaviors when threads are blocked:
    /// - Return zero, or
    /// - Return a negative value whose magnitude is the waiter count.
    ///
    /// We return a negative waiter count to give maximum information.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — bad `sem_id`.
    pub fn sem_getvalue(&self, sem_id: usize) -> Result<i32> {
        let slot = self.get_slot(sem_id)?;
        if slot.waiter_count > 0 {
            // Negative = number of blocked waiters.
            Ok(-(slot.waiter_count as i32))
        } else {
            Ok(slot.value as i32)
        }
    }

    // ---------------------------------------------------------------
    // Named semaphore operations via handle
    // ---------------------------------------------------------------

    /// Lock a named semaphore by handle.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — invalid handle or bad slot.
    /// * `WouldBlock` — counter is zero.
    pub fn sem_wait_named(&mut self, handle: SemHandle) -> Result<()> {
        let (_ni, si) = self.resolve_handle(handle)?;
        self.sem_wait(si)
    }

    /// Try-lock a named semaphore by handle.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — invalid handle.
    /// * `WouldBlock` — counter is zero.
    pub fn sem_trywait_named(&mut self, handle: SemHandle) -> Result<()> {
        let (_ni, si) = self.resolve_handle(handle)?;
        self.sem_trywait(si)
    }

    /// Timed-wait on a named semaphore by handle.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — invalid handle or bad timeout.
    /// * `WouldBlock` — counter is zero.
    pub fn sem_timedwait_named(&mut self, handle: SemHandle, abstime: &SemTimespec) -> Result<()> {
        let (_ni, si) = self.resolve_handle(handle)?;
        self.sem_timedwait(si, abstime)
    }

    /// Post (unlock) a named semaphore by handle.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — invalid handle or overflow.
    pub fn sem_post_named(&mut self, handle: SemHandle) -> Result<()> {
        let (_ni, si) = self.resolve_handle(handle)?;
        self.sem_post(si)
    }

    /// Get the value of a named semaphore by handle.
    ///
    /// # Errors
    ///
    /// * `InvalidArgument` — invalid handle.
    pub fn sem_getvalue_named(&self, handle: SemHandle) -> Result<i32> {
        let (_ni, si) = self.resolve_handle(handle)?;
        self.sem_getvalue(si)
    }

    // ---------------------------------------------------------------
    // Query / administrative helpers
    // ---------------------------------------------------------------

    /// Count how many semaphore slots are in use.
    pub fn active_count(&self) -> usize {
        self.slots.iter().filter(|s| s.active).count()
    }

    /// Count how many named semaphores are registered.
    pub fn named_count(&self) -> usize {
        self.named
            .iter()
            .filter(|e| e.active && !e.unlinked)
            .count()
    }

    /// Check whether a named semaphore exists (not unlinked).
    pub fn name_exists(&self, name: &[u8]) -> bool {
        self.find_named(name).is_some()
    }

    /// Get the reference count for a named semaphore.
    ///
    /// # Errors
    ///
    /// * `NotFound` — no semaphore with this name.
    pub fn name_ref_count(&self, name: &[u8]) -> Result<u32> {
        let ni = self.find_named(name).ok_or(Error::NotFound)?;
        Ok(self.named[ni].ref_count)
    }

    /// Unregister a process: close all handles owned by the given PID.
    ///
    /// Called during process exit to prevent resource leaks.
    pub fn cleanup_process(&mut self, _pid: u64) {
        // In a full implementation we would track which PID owns each
        // handle.  For now, this is a no-op placeholder that the
        // process-exit path can call.
    }

    // ---------------------------------------------------------------
    // Private slot accessors
    // ---------------------------------------------------------------

    /// Get an active slot by index (shared ref).
    fn get_slot(&self, sem_id: usize) -> Result<&SemaphoreState> {
        if sem_id >= SEM_NSEMS_MAX {
            return Err(Error::InvalidArgument);
        }
        let slot = &self.slots[sem_id];
        if !slot.active {
            return Err(Error::InvalidArgument);
        }
        Ok(slot)
    }

    /// Get an active slot by index (mutable ref).
    fn get_slot_mut(&mut self, sem_id: usize) -> Result<&mut SemaphoreState> {
        if sem_id >= SEM_NSEMS_MAX {
            return Err(Error::InvalidArgument);
        }
        let slot = &mut self.slots[sem_id];
        if !slot.active {
            return Err(Error::InvalidArgument);
        }
        Ok(slot)
    }
}

// -------------------------------------------------------------------
// Module-level tests
// -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unnamed_init_and_destroy() {
        let mut reg = SemRegistry::new();
        let id = reg.sem_init(0, 5, 100).unwrap();
        assert_eq!(reg.sem_getvalue(id).unwrap(), 5);
        assert!(reg.sem_destroy(id).is_ok());
        // After destroy, slot is invalid.
        assert!(reg.sem_getvalue(id).is_err());
    }

    #[test]
    fn test_unnamed_value_max_overflow() {
        let mut reg = SemRegistry::new();
        assert!(reg.sem_init(0, SEM_VALUE_MAX + 1, 1).is_err());
    }

    #[test]
    fn test_sem_wait_and_post() {
        let mut reg = SemRegistry::new();
        let id = reg.sem_init(0, 2, 100).unwrap();

        // Two successful waits.
        assert!(reg.sem_wait(id).is_ok());
        assert_eq!(reg.sem_getvalue(id).unwrap(), 1);
        assert!(reg.sem_wait(id).is_ok());
        assert_eq!(reg.sem_getvalue(id).unwrap(), 0);

        // Third wait would block.
        assert_eq!(reg.sem_wait(id), Err(Error::WouldBlock));

        // Post wakes a waiter (waiter_count was incremented).
        assert!(reg.sem_post(id).is_ok());
        // After waking the waiter, value is still 0.
        assert_eq!(reg.sem_getvalue(id).unwrap(), 0);
    }

    #[test]
    fn test_sem_trywait_eagain() {
        let mut reg = SemRegistry::new();
        let id = reg.sem_init(0, 0, 100).unwrap();
        assert_eq!(reg.sem_trywait(id), Err(Error::WouldBlock));
    }

    #[test]
    fn test_sem_post_overflow() {
        let mut reg = SemRegistry::new();
        let id = reg.sem_init(0, SEM_VALUE_MAX, 100).unwrap();
        assert_eq!(reg.sem_post(id), Err(Error::InvalidArgument));
    }

    #[test]
    fn test_sem_getvalue_negative_waiters() {
        let mut reg = SemRegistry::new();
        let id = reg.sem_init(0, 0, 100).unwrap();
        // Simulate 3 blocked waiters.
        let _ = reg.sem_wait(id);
        let _ = reg.sem_wait(id);
        let _ = reg.sem_wait(id);
        assert_eq!(reg.sem_getvalue(id).unwrap(), -3);
    }

    #[test]
    fn test_named_create_and_open() {
        let mut reg = SemRegistry::new();
        let h1 = reg
            .sem_open(
                b"/test_sem",
                SemOpenFlags::O_CREAT,
                SemMode::DEFAULT,
                1,
                0,
                0,
            )
            .unwrap();

        // Opening again gives a different handle.
        let h2 = reg
            .sem_open(b"/test_sem", SemOpenFlags::NONE, SemMode::DEFAULT, 0, 0, 0)
            .unwrap();
        assert_ne!(h1.descriptor, h2.descriptor);
        assert_eq!(reg.name_ref_count(b"/test_sem").unwrap(), 2);
    }

    #[test]
    fn test_named_excl() {
        let mut reg = SemRegistry::new();
        let _h = reg
            .sem_open(
                b"/excl_sem",
                SemOpenFlags::O_CREAT,
                SemMode::DEFAULT,
                0,
                0,
                0,
            )
            .unwrap();

        // O_CREAT | O_EXCL must fail.
        let flags =
            SemOpenFlags::from_raw(SemOpenFlags::O_CREAT.bits() | SemOpenFlags::O_EXCL.bits());
        assert_eq!(
            reg.sem_open(b"/excl_sem", flags, SemMode::DEFAULT, 0, 0, 0),
            Err(Error::AlreadyExists)
        );
    }

    #[test]
    fn test_named_not_found() {
        let mut reg = SemRegistry::new();
        assert_eq!(
            reg.sem_open(
                b"/no_such_sem",
                SemOpenFlags::NONE,
                SemMode::DEFAULT,
                0,
                0,
                0,
            ),
            Err(Error::NotFound)
        );
    }

    #[test]
    fn test_sem_unlink_and_deferred_free() {
        let mut reg = SemRegistry::new();
        let h = reg
            .sem_open(
                b"/unlink_sem",
                SemOpenFlags::O_CREAT,
                SemMode::DEFAULT,
                3,
                0,
                0,
            )
            .unwrap();

        // Unlink: name disappears but resources persist.
        assert!(reg.sem_unlink(b"/unlink_sem").is_ok());
        assert!(!reg.name_exists(b"/unlink_sem"));

        // Handle still works.
        assert_eq!(reg.sem_getvalue_named(h).unwrap(), 3);

        // Close last handle: resources freed.
        assert!(reg.sem_close(h).is_ok());
    }

    #[test]
    fn test_named_operations_via_handle() {
        let mut reg = SemRegistry::new();
        let h = reg
            .sem_open(b"/op_sem", SemOpenFlags::O_CREAT, SemMode::DEFAULT, 2, 0, 0)
            .unwrap();

        assert!(reg.sem_wait_named(h).is_ok());
        assert_eq!(reg.sem_getvalue_named(h).unwrap(), 1);

        assert!(reg.sem_post_named(h).is_ok());
        assert_eq!(reg.sem_getvalue_named(h).unwrap(), 2);

        assert!(reg.sem_trywait_named(h).is_ok());
        assert_eq!(reg.sem_getvalue_named(h).unwrap(), 1);

        assert!(reg.sem_close(h).is_ok());
    }

    #[test]
    fn test_timedwait_invalid_timespec() {
        let mut reg = SemRegistry::new();
        let id = reg.sem_init(0, 1, 100).unwrap();

        let bad_ts = SemTimespec {
            tv_sec: -1,
            tv_nsec: 0,
        };
        assert_eq!(reg.sem_timedwait(id, &bad_ts), Err(Error::InvalidArgument));

        let bad_ns = SemTimespec {
            tv_sec: 0,
            tv_nsec: 2_000_000_000,
        };
        assert_eq!(reg.sem_timedwait(id, &bad_ns), Err(Error::InvalidArgument));
    }

    #[test]
    fn test_name_validation() {
        // No leading slash.
        assert!(SemRegistry::validate_name(b"bad").is_err());
        // Just slash.
        assert!(SemRegistry::validate_name(b"/").is_err());
        // Empty.
        assert!(SemRegistry::validate_name(b"").is_err());
        // Good name.
        assert!(SemRegistry::validate_name(b"/good").is_ok());
    }

    #[test]
    fn test_destroy_with_waiters_fails() {
        let mut reg = SemRegistry::new();
        let id = reg.sem_init(0, 0, 100).unwrap();
        let _ = reg.sem_wait(id); // increments waiter_count
        assert_eq!(reg.sem_destroy(id), Err(Error::Busy));
    }

    #[test]
    fn test_active_count() {
        let mut reg = SemRegistry::new();
        assert_eq!(reg.active_count(), 0);
        let _ = reg.sem_init(0, 1, 100).unwrap();
        let _ = reg.sem_init(0, 2, 100).unwrap();
        assert_eq!(reg.active_count(), 2);
    }

    #[test]
    fn test_sem_open_flags_contains() {
        let flags =
            SemOpenFlags::from_raw(SemOpenFlags::O_CREAT.bits() | SemOpenFlags::O_EXCL.bits());
        assert!(flags.contains(SemOpenFlags::O_CREAT));
        assert!(flags.contains(SemOpenFlags::O_EXCL));
        assert!(!SemOpenFlags::NONE.contains(SemOpenFlags::O_CREAT));
    }

    #[test]
    fn test_process_shared_flag() {
        let mut reg = SemRegistry::new();
        let id_private = reg.sem_init(0, 1, 100).unwrap();
        let id_shared = reg.sem_init(1, 1, 100).unwrap();

        // Private semaphore.
        assert!(!reg.slots[id_private].process_shared);
        // Shared semaphore.
        assert!(reg.slots[id_shared].process_shared);
    }
}
