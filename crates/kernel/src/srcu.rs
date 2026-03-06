// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Sleepable Read-Copy-Update (SRCU) synchronization primitive.
//!
//! SRCU extends classic RCU by allowing readers to sleep inside
//! critical sections. This is useful for I/O-bound read paths
//! (filesystem lookups, network configuration reads) where the
//! reader may block on disk or network operations.
//!
//! Unlike traditional RCU, SRCU uses per-domain lock counts and
//! explicit generation tracking to detect grace periods. Each
//! SRCU domain is independent — a grace period in one domain does
//! not affect others.
//!
//! # Design
//!
//! Each [`SrcuStruct`] maintains:
//! - Per-CPU lock counts (split into two alternating counters)
//! - A generation counter that flips between 0 and 1
//! - A callback queue for deferred work after grace periods
//!
//! Readers call [`srcu_read_lock`] / [`srcu_read_unlock`] which
//! increment/decrement the per-CPU counter for the current
//! generation. Writers call [`synchronize_srcu`] which flips the
//! generation and waits for all readers in the old generation to
//! complete.
//!
//! # Usage
//!
//! ```ignore
//! let mut srcu = SrcuStruct::new();
//! srcu.init(4)?; // 4 CPUs
//!
//! // Reader path (may sleep):
//! let idx = srcu_read_lock(&mut srcu, 0)?;
//! // ... read shared data, may sleep ...
//! srcu_read_unlock(&mut srcu, 0, idx)?;
//!
//! // Writer path:
//! // ... update shared data ...
//! synchronize_srcu(&mut srcu)?; // wait for readers
//! // ... free old data ...
//! ```
//!
//! Reference: Linux `kernel/rcu/srcutree.c`,
//! `include/linux/srcu.h`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of CPUs supported.
const MAX_CPUS: usize = 64;

/// Number of lock count slots per CPU (two alternating generations).
const NR_SLOTS: usize = 2;

/// Maximum number of SRCU domains.
const MAX_SRCU_DOMAINS: usize = 32;

/// Maximum number of pending callbacks per domain.
const MAX_CALLBACKS: usize = 64;

/// Maximum name length for an SRCU domain.
const MAX_NAME_LEN: usize = 32;

/// Maximum iterations for grace period polling.
const MAX_GP_POLL_ITERS: u64 = 1_000_000;

// ── SrcuData ──────────────────────────────────────────────────────

/// Per-CPU SRCU data.
///
/// Each CPU maintains two lock counts — one for each generation
/// slot. When a grace period flips the generation index, readers
/// already in their critical section continue using the old slot.
/// New readers use the new slot. The grace period completes when
/// the old slot's lock count reaches zero.
#[derive(Debug, Clone, Copy)]
pub struct SrcuData {
    /// Lock counts for each slot (two alternating generations).
    /// `lock_count[idx]` tracks readers in generation `idx`.
    pub lock_count: [u64; NR_SLOTS],
    /// Unlock counts for each slot. The number of active readers
    /// in slot `i` is `lock_count[i] - unlock_count[i]`.
    pub unlock_count: [u64; NR_SLOTS],
    /// Whether this per-CPU data is initialised.
    pub active: bool,
}

impl SrcuData {
    /// Creates uninitialised per-CPU data.
    const fn new() -> Self {
        Self {
            lock_count: [0; NR_SLOTS],
            unlock_count: [0; NR_SLOTS],
            active: false,
        }
    }

    /// Returns the number of active readers in a given slot.
    pub const fn readers_active(&self, slot: usize) -> u64 {
        if slot < NR_SLOTS {
            self.lock_count[slot] - self.unlock_count[slot]
        } else {
            0
        }
    }

    /// Returns the total number of active readers across both
    /// slots.
    pub const fn total_readers(&self) -> u64 {
        (self.lock_count[0] - self.unlock_count[0]) + (self.lock_count[1] - self.unlock_count[1])
    }
}

impl Default for SrcuData {
    fn default() -> Self {
        Self::new()
    }
}

// ── SrcuCallback ─────────────────────────────────────────────────

/// A deferred callback to invoke after an SRCU grace period.
///
/// Callbacks are queued by [`call_srcu`] and executed once the
/// grace period they were registered in has completed.
#[derive(Debug, Clone, Copy)]
pub struct SrcuCallback {
    /// Unique callback identifier.
    pub id: u64,
    /// Grace period sequence number this callback is waiting for.
    pub gp_seq: u64,
    /// User-provided tag for identifying the callback.
    pub tag: u64,
    /// Whether this callback slot is in use.
    pub pending: bool,
    /// Whether this callback has been invoked.
    pub completed: bool,
}

impl SrcuCallback {
    /// Creates an empty callback slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            gp_seq: 0,
            tag: 0,
            pending: false,
            completed: false,
        }
    }
}

impl Default for SrcuCallback {
    fn default() -> Self {
        Self::empty()
    }
}

// ── SrcuGpState ──────────────────────────────────────────────────

/// Grace period state for an SRCU domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrcuGpState {
    /// No grace period in progress.
    Idle,
    /// Grace period started, waiting for readers to drain.
    WaitingForReaders,
    /// Grace period complete, callbacks ready to run.
    Completed,
}

impl Default for SrcuGpState {
    fn default() -> Self {
        Self::Idle
    }
}

// ── SrcuStruct ───────────────────────────────────────────────────

/// A single SRCU synchronization domain.
///
/// Each domain is independent — grace periods, callbacks, and
/// reader tracking are all per-domain. Multiple subsystems can
/// use separate SRCU domains without interfering with each other.
pub struct SrcuStruct {
    /// Domain name for debugging.
    pub name: [u8; MAX_NAME_LEN],
    /// Name length.
    pub name_len: usize,
    /// Per-CPU SRCU data.
    data: [SrcuData; MAX_CPUS],
    /// Number of online CPUs.
    nr_cpus: usize,
    /// Current generation index (0 or 1).
    srcu_idx: usize,
    /// Grace period sequence counter (monotonically increasing).
    srcu_gp_seq: u64,
    /// Completed grace period sequence number.
    srcu_gp_seq_completed: u64,
    /// Grace period state.
    gp_state: SrcuGpState,
    /// Pending callbacks.
    callbacks: [SrcuCallback; MAX_CALLBACKS],
    /// Number of pending callbacks.
    callback_count: usize,
    /// Next callback ID.
    next_cb_id: u64,
    /// Whether this domain is initialised.
    initialised: bool,
}

impl SrcuStruct {
    /// Creates a new uninitialised SRCU domain.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            data: [SrcuData::new(); MAX_CPUS],
            nr_cpus: 0,
            srcu_idx: 0,
            srcu_gp_seq: 0,
            srcu_gp_seq_completed: 0,
            gp_state: SrcuGpState::Idle,
            callbacks: [SrcuCallback::empty(); MAX_CALLBACKS],
            callback_count: 0,
            next_cb_id: 1,
            initialised: false,
        }
    }

    /// Initialises the SRCU domain for `nr_cpus` processors.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if `nr_cpus` is 0 or
    /// exceeds [`MAX_CPUS`].
    pub fn init(&mut self, nr_cpus: usize) -> Result<()> {
        if nr_cpus == 0 || nr_cpus > MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        self.data = [SrcuData::new(); MAX_CPUS];
        for d in &mut self.data[..nr_cpus] {
            d.active = true;
        }
        self.nr_cpus = nr_cpus;
        self.srcu_idx = 0;
        self.srcu_gp_seq = 0;
        self.srcu_gp_seq_completed = 0;
        self.gp_state = SrcuGpState::Idle;
        self.callbacks = [SrcuCallback::empty(); MAX_CALLBACKS];
        self.callback_count = 0;
        self.next_cb_id = 1;
        self.initialised = true;

        Ok(())
    }

    /// Sets the domain name.
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    /// Returns the name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Returns the current generation index (0 or 1).
    pub const fn srcu_idx(&self) -> usize {
        self.srcu_idx
    }

    /// Returns the current grace period sequence number.
    pub const fn gp_seq(&self) -> u64 {
        self.srcu_gp_seq
    }

    /// Returns the last completed grace period sequence number.
    pub const fn gp_seq_completed(&self) -> u64 {
        self.srcu_gp_seq_completed
    }

    /// Returns the grace period state.
    pub const fn gp_state(&self) -> SrcuGpState {
        self.gp_state
    }

    /// Returns whether this domain is initialised.
    pub const fn is_initialised(&self) -> bool {
        self.initialised
    }

    /// Returns the number of online CPUs.
    pub const fn nr_cpus(&self) -> usize {
        self.nr_cpus
    }

    /// Returns a reference to per-CPU data.
    ///
    /// # Errors
    ///
    /// Returns `Error::InvalidArgument` if `cpu_id` is out of
    /// range.
    pub fn cpu_data(&self, cpu_id: usize) -> Result<&SrcuData> {
        if cpu_id >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.data[cpu_id])
    }

    /// Returns the total number of active readers across all CPUs
    /// in a given slot.
    pub fn readers_active_in_slot(&self, slot: usize) -> u64 {
        let mut total = 0u64;
        for d in &self.data[..self.nr_cpus] {
            if d.active {
                total = total.saturating_add(d.readers_active(slot));
            }
        }
        total
    }

    /// Returns the total number of active readers across all CPUs
    /// and both slots.
    pub fn total_readers(&self) -> u64 {
        let mut total = 0u64;
        for d in &self.data[..self.nr_cpus] {
            if d.active {
                total = total.saturating_add(d.total_readers());
            }
        }
        total
    }

    /// Returns the number of pending callbacks.
    pub const fn pending_callbacks(&self) -> usize {
        self.callback_count
    }

    /// Returns the number of completed (ready to invoke) callbacks.
    pub fn completed_callbacks(&self) -> usize {
        self.callbacks[..self.callback_count]
            .iter()
            .filter(|cb| cb.pending && cb.completed)
            .count()
    }

    /// Advances completed callbacks — marks callbacks as completed
    /// if their grace period has finished.
    pub fn advance_callbacks(&mut self) {
        for cb in &mut self.callbacks {
            if cb.pending && !cb.completed && cb.gp_seq <= self.srcu_gp_seq_completed {
                cb.completed = true;
            }
        }
    }

    /// Removes and returns the ID of the next completed callback,
    /// or `None` if there are no completed callbacks.
    pub fn drain_one_callback(&mut self) -> Option<(u64, u64)> {
        // Find the first completed callback.
        let pos = self.callbacks[..self.callback_count]
            .iter()
            .position(|cb| cb.pending && cb.completed)?;

        let id = self.callbacks[pos].id;
        let tag = self.callbacks[pos].tag;

        // Swap-remove.
        self.callback_count -= 1;
        if pos < self.callback_count {
            self.callbacks[pos] = self.callbacks[self.callback_count];
        }
        self.callbacks[self.callback_count] = SrcuCallback::empty();

        Some((id, tag))
    }
}

impl Default for SrcuStruct {
    fn default() -> Self {
        Self::new()
    }
}

// ── Public API ─────────────────────────────────────────────────────

/// Enters an SRCU read-side critical section.
///
/// Returns the generation index that must be passed to
/// [`srcu_read_unlock`]. The caller may sleep while holding this
/// lock.
///
/// # Errors
///
/// - `Error::InvalidArgument` — `cpu_id` out of range or domain
///   not initialised.
pub fn srcu_read_lock(srcu: &mut SrcuStruct, cpu_id: usize) -> Result<usize> {
    if !srcu.initialised {
        return Err(Error::InvalidArgument);
    }
    if cpu_id >= srcu.nr_cpus {
        return Err(Error::InvalidArgument);
    }

    let idx = srcu.srcu_idx;
    srcu.data[cpu_id].lock_count[idx] = srcu.data[cpu_id].lock_count[idx].saturating_add(1);

    Ok(idx)
}

/// Exits an SRCU read-side critical section.
///
/// `idx` is the value returned by [`srcu_read_lock`].
///
/// # Errors
///
/// - `Error::InvalidArgument` — `cpu_id` out of range, invalid
///   `idx`, or domain not initialised.
pub fn srcu_read_unlock(srcu: &mut SrcuStruct, cpu_id: usize, idx: usize) -> Result<()> {
    if !srcu.initialised {
        return Err(Error::InvalidArgument);
    }
    if cpu_id >= srcu.nr_cpus {
        return Err(Error::InvalidArgument);
    }
    if idx >= NR_SLOTS {
        return Err(Error::InvalidArgument);
    }

    srcu.data[cpu_id].unlock_count[idx] = srcu.data[cpu_id].unlock_count[idx].saturating_add(1);

    Ok(())
}

/// Starts an SRCU grace period.
///
/// Flips the generation index so new readers use the new slot,
/// then the caller polls [`srcu_gp_complete`] to check if all
/// old-generation readers have finished.
///
/// # Errors
///
/// - `Error::InvalidArgument` — domain not initialised.
/// - `Error::Busy` — a grace period is already in progress.
pub fn start_srcu_gp(srcu: &mut SrcuStruct) -> Result<u64> {
    if !srcu.initialised {
        return Err(Error::InvalidArgument);
    }
    if srcu.gp_state == SrcuGpState::WaitingForReaders {
        return Err(Error::Busy);
    }

    // Flip the generation index.
    let old_idx = srcu.srcu_idx;
    srcu.srcu_idx = 1 - old_idx;
    srcu.srcu_gp_seq = srcu.srcu_gp_seq.saturating_add(1);
    srcu.gp_state = SrcuGpState::WaitingForReaders;

    Ok(srcu.srcu_gp_seq)
}

/// Checks whether the current SRCU grace period is complete.
///
/// A grace period is complete when there are no active readers
/// in the old generation slot (the one before the flip).
///
/// Returns `true` if the grace period has completed.
///
/// # Errors
///
/// Returns `Error::InvalidArgument` if the domain is not
/// initialised.
pub fn srcu_gp_complete(srcu: &mut SrcuStruct) -> Result<bool> {
    if !srcu.initialised {
        return Err(Error::InvalidArgument);
    }

    if srcu.gp_state != SrcuGpState::WaitingForReaders {
        return Ok(true);
    }

    // The old slot is the opposite of the current index.
    let old_idx = 1 - srcu.srcu_idx;
    let active = srcu.readers_active_in_slot(old_idx);

    if active == 0 {
        srcu.srcu_gp_seq_completed = srcu.srcu_gp_seq;
        srcu.gp_state = SrcuGpState::Completed;
        srcu.advance_callbacks();
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Waits for all pre-existing SRCU readers to complete.
///
/// This is a synchronous grace period — it starts a new grace
/// period and polls until all old readers have finished.
///
/// # Errors
///
/// - `Error::InvalidArgument` — domain not initialised.
/// - `Error::Busy` — a grace period is already in progress.
/// - `Error::WouldBlock` — grace period did not complete within
///   the maximum poll iterations.
pub fn synchronize_srcu(srcu: &mut SrcuStruct) -> Result<()> {
    if !srcu.initialised {
        return Err(Error::InvalidArgument);
    }

    // If no readers exist, no need for a grace period.
    if srcu.total_readers() == 0 {
        srcu.srcu_gp_seq = srcu.srcu_gp_seq.saturating_add(1);
        srcu.srcu_gp_seq_completed = srcu.srcu_gp_seq;
        srcu.advance_callbacks();
        return Ok(());
    }

    // Start a grace period.
    start_srcu_gp(srcu)?;

    // Poll for completion.
    for _ in 0..MAX_GP_POLL_ITERS {
        if srcu_gp_complete(srcu)? {
            srcu.gp_state = SrcuGpState::Idle;
            return Ok(());
        }
    }

    // Grace period did not complete in time.
    Err(Error::WouldBlock)
}

/// Queues a callback to be invoked after the next SRCU grace
/// period completes.
///
/// The callback is identified by a `tag` value that the caller
/// can use to match callbacks when draining. Returns the
/// callback ID.
///
/// # Errors
///
/// - `Error::InvalidArgument` — domain not initialised.
/// - `Error::OutOfMemory` — callback queue is full.
pub fn call_srcu(srcu: &mut SrcuStruct, tag: u64) -> Result<u64> {
    if !srcu.initialised {
        return Err(Error::InvalidArgument);
    }
    if srcu.callback_count >= MAX_CALLBACKS {
        return Err(Error::OutOfMemory);
    }

    let id = srcu.next_cb_id;
    srcu.next_cb_id += 1;

    // The callback waits for the *next* grace period to complete.
    let wait_seq = srcu.srcu_gp_seq.saturating_add(1);

    srcu.callbacks[srcu.callback_count] = SrcuCallback {
        id,
        gp_seq: wait_seq,
        tag,
        pending: true,
        completed: false,
    };
    srcu.callback_count += 1;

    Ok(id)
}

// ── SrcuDomainRegistry ──────────────────────────────────────────

/// System-wide registry of SRCU domains.
///
/// Manages creation, lookup, and lifecycle of SRCU
/// synchronization domains.
pub struct SrcuDomainRegistry {
    /// Domain slots.
    domains: [Option<SrcuStruct>; MAX_SRCU_DOMAINS],
    /// Number of active domains.
    count: usize,
    /// Next domain ID seed.
    next_seed: u64,
}

impl SrcuDomainRegistry {
    /// Creates an empty domain registry.
    pub const fn new() -> Self {
        // Cannot use [None; N] for non-Copy types, use explicit
        // array construction.
        Self {
            domains: [
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                None, None, None, None,
            ],
            count: 0,
            next_seed: 1,
        }
    }

    /// Creates a new SRCU domain and returns its index.
    ///
    /// # Errors
    ///
    /// - `Error::InvalidArgument` — name is empty or `nr_cpus`
    ///   is zero/too large.
    /// - `Error::OutOfMemory` — no free domain slots.
    pub fn create(&mut self, name: &[u8], nr_cpus: usize) -> Result<usize> {
        if name.is_empty() {
            return Err(Error::InvalidArgument);
        }

        let slot_idx = self
            .domains
            .iter()
            .position(|d| d.is_none())
            .ok_or(Error::OutOfMemory)?;

        let mut domain = SrcuStruct::new();
        domain.init(nr_cpus)?;
        domain.set_name(name);
        self.next_seed += 1;

        self.domains[slot_idx] = Some(domain);
        self.count += 1;

        Ok(slot_idx)
    }

    /// Removes a domain by index.
    ///
    /// # Errors
    ///
    /// - `Error::InvalidArgument` — index out of range.
    /// - `Error::NotFound` — no domain at that index.
    /// - `Error::Busy` — domain has active readers or pending
    ///   callbacks.
    pub fn remove(&mut self, idx: usize) -> Result<()> {
        if idx >= MAX_SRCU_DOMAINS {
            return Err(Error::InvalidArgument);
        }

        let domain = self.domains[idx].as_ref().ok_or(Error::NotFound)?;

        if domain.total_readers() > 0 || domain.pending_callbacks() > 0 {
            return Err(Error::Busy);
        }

        self.domains[idx] = None;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Returns a reference to a domain by index.
    ///
    /// # Errors
    ///
    /// - `Error::InvalidArgument` — index out of range.
    /// - `Error::NotFound` — no domain at that index.
    pub fn get(&self, idx: usize) -> Result<&SrcuStruct> {
        if idx >= MAX_SRCU_DOMAINS {
            return Err(Error::InvalidArgument);
        }
        self.domains[idx].as_ref().ok_or(Error::NotFound)
    }

    /// Returns a mutable reference to a domain by index.
    ///
    /// # Errors
    ///
    /// - `Error::InvalidArgument` — index out of range.
    /// - `Error::NotFound` — no domain at that index.
    pub fn get_mut(&mut self, idx: usize) -> Result<&mut SrcuStruct> {
        if idx >= MAX_SRCU_DOMAINS {
            return Err(Error::InvalidArgument);
        }
        self.domains[idx].as_mut().ok_or(Error::NotFound)
    }

    /// Returns the number of active domains.
    pub const fn count(&self) -> usize {
        self.count
    }
}

impl Default for SrcuDomainRegistry {
    fn default() -> Self {
        Self::new()
    }
}
