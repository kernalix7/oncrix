// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! User-space probes (uprobes).
//!
//! Uprobes allow dynamic tracing of user-space functions by inserting
//! breakpoint instructions at specified offsets within an executable
//! or shared library. When the breakpoint fires, the kernel captures
//! register state, generates a trace event, and resumes execution.
//!
//! # Architecture
//!
//! ```text
//!   User space                    Kernel
//! ┌──────────────┐          ┌───────────────────┐
//! │ ELF binary   │          │ UprobeManager      │
//! │ ┌──────────┐ │  trap    │ ┌───────────────┐ │
//! │ │ 0xCC (BP)│─┼────────►│ │ UprobeEntry   │ │
//! │ └──────────┘ │          │ │  path+offset   │ │
//! └──────────────┘          │ │  handler logic │ │
//!                           │ └───────────────┘ │
//!   single-step             │ UretprobeTrampoline│
//!   ◄──────────────────────│  (return probes)   │
//! └──────────────┘          └───────────────────┘
//! ```
//!
//! # Reference
//!
//! Linux `kernel/events/uprobes.c`, `include/linux/uprobes.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum number of registered uprobes.
const MAX_UPROBES: usize = 512;

/// Maximum path length for the probed binary.
const MAX_PATH_LEN: usize = 256;

/// Maximum number of active return probe trampolines.
const MAX_RETURN_INSTANCES: usize = 64;

/// Breakpoint instruction byte on x86_64 (INT3).
const _BREAKPOINT_INSN: u8 = 0xCC;

/// Maximum saved instruction bytes for single-stepping.
const MAX_INSN_SIZE: usize = 16;

/// Maximum number of events in the per-uprobe ring.
const MAX_EVENTS_PER_PROBE: usize = 256;

/// Reference counter offset indicating no reference counter.
const _REF_CTR_OFFSET_NONE: u64 = 0;

// ======================================================================
// Uprobe state
// ======================================================================

/// State of a single uprobe entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UprobeState {
    /// Registered but not yet inserted.
    Registered,
    /// Breakpoint inserted, actively probing.
    Active,
    /// Temporarily disabled.
    Disabled,
    /// Being removed.
    Removing,
}

/// Type of uprobe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UprobeType {
    /// Standard uprobe (fires on function entry).
    Entry,
    /// Return probe (fires on function return).
    Return,
}

// ======================================================================
// Uprobe event
// ======================================================================

/// An event generated when a uprobe fires.
#[derive(Debug, Clone, Copy)]
pub struct UprobeEvent {
    /// Timestamp in nanoseconds.
    timestamp_ns: u64,
    /// PID of the process that hit the probe.
    pid: u32,
    /// TID of the thread.
    tid: u32,
    /// Instruction pointer at probe site.
    ip: u64,
    /// Stack pointer at probe hit.
    sp: u64,
    /// Return address (valid for return probes).
    ret_addr: u64,
    /// CPU on which the event occurred.
    cpu: u32,
    /// The uprobe entry ID that generated this event.
    uprobe_id: u32,
    /// Whether this is a return event.
    is_return: bool,
}

impl UprobeEvent {
    /// Creates an empty event.
    pub const fn new() -> Self {
        Self {
            timestamp_ns: 0,
            pid: 0,
            tid: 0,
            ip: 0,
            sp: 0,
            ret_addr: 0,
            cpu: 0,
            uprobe_id: 0,
            is_return: false,
        }
    }

    /// Returns the timestamp.
    pub fn timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }

    /// Returns the PID.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Returns the TID.
    pub fn tid(&self) -> u32 {
        self.tid
    }

    /// Returns the instruction pointer.
    pub fn ip(&self) -> u64 {
        self.ip
    }

    /// Returns the uprobe ID.
    pub fn uprobe_id(&self) -> u32 {
        self.uprobe_id
    }
}

// ======================================================================
// Saved instruction (for single-stepping)
// ======================================================================

/// Saved original instruction bytes before breakpoint insertion.
#[derive(Debug, Clone, Copy)]
pub struct SavedInsn {
    /// The original bytes replaced by the breakpoint.
    bytes: [u8; MAX_INSN_SIZE],
    /// Number of valid bytes.
    len: u8,
}

impl SavedInsn {
    /// Creates an empty saved instruction.
    pub const fn new() -> Self {
        Self {
            bytes: [0u8; MAX_INSN_SIZE],
            len: 0,
        }
    }

    /// Saves instruction bytes.
    pub fn save(&mut self, insn: &[u8]) -> Result<()> {
        if insn.len() > MAX_INSN_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.bytes[..insn.len()].copy_from_slice(insn);
        self.len = insn.len() as u8;
        Ok(())
    }

    /// Returns the saved bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

// ======================================================================
// Return probe trampoline
// ======================================================================

/// Tracks a single return probe instance (one per in-flight call).
#[derive(Debug, Clone, Copy)]
pub struct ReturnInstance {
    /// Original return address (to restore after probing).
    orig_ret_addr: u64,
    /// The uprobe entry ID this return instance belongs to.
    uprobe_id: u32,
    /// TID of the thread.
    tid: u32,
    /// Whether this slot is in use.
    active: bool,
}

impl ReturnInstance {
    /// Creates an inactive return instance.
    pub const fn new() -> Self {
        Self {
            orig_ret_addr: 0,
            uprobe_id: 0,
            tid: 0,
            active: false,
        }
    }
}

/// Manages return probe trampolines.
pub struct UretprobeTrampoline {
    /// Active return instances.
    instances: [ReturnInstance; MAX_RETURN_INSTANCES],
    /// Number of active instances.
    count: usize,
}

impl UretprobeTrampoline {
    /// Creates a new trampoline manager.
    pub const fn new() -> Self {
        Self {
            instances: [const { ReturnInstance::new() }; MAX_RETURN_INSTANCES],
            count: 0,
        }
    }

    /// Pushes a return instance for tracking.
    pub fn push(&mut self, uprobe_id: u32, tid: u32, orig_ret_addr: u64) -> Result<()> {
        let slot = self
            .instances
            .iter()
            .position(|inst| !inst.active)
            .ok_or(Error::OutOfMemory)?;
        self.instances[slot].orig_ret_addr = orig_ret_addr;
        self.instances[slot].uprobe_id = uprobe_id;
        self.instances[slot].tid = tid;
        self.instances[slot].active = true;
        self.count += 1;
        Ok(())
    }

    /// Pops a return instance for the given thread, returning the
    /// original return address.
    pub fn pop(&mut self, tid: u32) -> Result<u64> {
        // Search from the end (most recent) for LIFO ordering.
        for i in (0..MAX_RETURN_INSTANCES).rev() {
            if self.instances[i].active && self.instances[i].tid == tid {
                let addr = self.instances[i].orig_ret_addr;
                self.instances[i].active = false;
                self.count -= 1;
                return Ok(addr);
            }
        }
        Err(Error::NotFound)
    }

    /// Returns the number of active return instances.
    pub fn count(&self) -> usize {
        self.count
    }
}

// ======================================================================
// Uprobe entry
// ======================================================================

/// A single registered uprobe.
pub struct UprobeEntry {
    /// Path to the probed binary.
    path: [u8; MAX_PATH_LEN],
    /// Length of the path.
    path_len: usize,
    /// File offset within the binary (from ELF symbol + section).
    file_offset: u64,
    /// Optional reference counter offset in the binary.
    ref_ctr_offset: u64,
    /// Unique uprobe ID.
    uprobe_id: u32,
    /// Probe type (entry or return).
    probe_type: UprobeType,
    /// Current state.
    state: UprobeState,
    /// Saved original instruction at the probe site.
    saved_insn: SavedInsn,
    /// Hit counter.
    hit_count: u64,
    /// Number of tasks currently referencing this probe.
    ref_count: u32,
    /// Event ring buffer for this probe.
    events: [UprobeEvent; MAX_EVENTS_PER_PROBE],
    /// Event ring head.
    event_head: usize,
    /// Number of events recorded.
    event_count: usize,
}

impl UprobeEntry {
    /// Creates a new empty uprobe entry.
    pub const fn new() -> Self {
        Self {
            path: [0u8; MAX_PATH_LEN],
            path_len: 0,
            file_offset: 0,
            ref_ctr_offset: 0,
            uprobe_id: 0,
            probe_type: UprobeType::Entry,
            state: UprobeState::Registered,
            saved_insn: SavedInsn::new(),
            hit_count: 0,
            ref_count: 0,
            events: [const { UprobeEvent::new() }; MAX_EVENTS_PER_PROBE],
            event_head: 0,
            event_count: 0,
        }
    }

    /// Returns the binary path.
    pub fn path(&self) -> &[u8] {
        &self.path[..self.path_len]
    }

    /// Returns the file offset.
    pub fn file_offset(&self) -> u64 {
        self.file_offset
    }

    /// Returns the reference counter offset.
    pub fn ref_ctr_offset(&self) -> u64 {
        self.ref_ctr_offset
    }

    /// Returns the uprobe ID.
    pub fn uprobe_id(&self) -> u32 {
        self.uprobe_id
    }

    /// Returns the probe type.
    pub fn probe_type(&self) -> UprobeType {
        self.probe_type
    }

    /// Returns the current state.
    pub fn state(&self) -> UprobeState {
        self.state
    }

    /// Returns the hit count.
    pub fn hit_count(&self) -> u64 {
        self.hit_count
    }

    /// Increments the reference count.
    pub fn inc_ref(&mut self) {
        self.ref_count = self.ref_count.saturating_add(1);
    }

    /// Decrements the reference count.
    pub fn dec_ref(&mut self) {
        self.ref_count = self.ref_count.saturating_sub(1);
    }

    /// Records an event for this probe.
    pub fn record_event(&mut self, event: UprobeEvent) {
        self.events[self.event_head] = event;
        self.event_head = (self.event_head + 1) % MAX_EVENTS_PER_PROBE;
        if self.event_count < MAX_EVENTS_PER_PROBE {
            self.event_count += 1;
        }
        self.hit_count = self.hit_count.saturating_add(1);
    }

    /// Returns the number of recorded events.
    pub fn event_count(&self) -> usize {
        self.event_count
    }

    /// Reads an event by logical index (0 = oldest).
    pub fn read_event(&self, index: usize) -> Option<&UprobeEvent> {
        if index >= self.event_count {
            return None;
        }
        let start = if self.event_count < MAX_EVENTS_PER_PROBE {
            0
        } else {
            self.event_head
        };
        let actual = (start + index) % MAX_EVENTS_PER_PROBE;
        Some(&self.events[actual])
    }
}

// ======================================================================
// Uprobe manager
// ======================================================================

/// Manages all registered uprobes.
pub struct UprobeManager {
    /// Registered uprobe entries.
    entries: [UprobeEntry; MAX_UPROBES],
    /// Which slots are occupied.
    occupied: [bool; MAX_UPROBES],
    /// Number of registered uprobes.
    count: usize,
    /// Next uprobe ID to assign.
    next_id: u32,
    /// Return probe trampoline manager.
    trampoline: UretprobeTrampoline,
    /// Global enable/disable flag.
    enabled: bool,
}

impl UprobeManager {
    /// Creates a new empty uprobe manager.
    pub const fn new() -> Self {
        Self {
            entries: [const { UprobeEntry::new() }; MAX_UPROBES],
            occupied: [false; MAX_UPROBES],
            count: 0,
            next_id: 1,
            trampoline: UretprobeTrampoline::new(),
            enabled: true,
        }
    }

    /// Returns the number of registered uprobes.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Returns whether uprobes are globally enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Sets the global enable flag.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Returns a reference to the trampoline manager.
    pub fn trampoline(&self) -> &UretprobeTrampoline {
        &self.trampoline
    }

    /// Registers a new uprobe.
    pub fn register(
        &mut self,
        path: &[u8],
        file_offset: u64,
        ref_ctr_offset: u64,
        probe_type: UprobeType,
    ) -> Result<u32> {
        if path.is_empty() || path.len() > MAX_PATH_LEN {
            return Err(Error::InvalidArgument);
        }
        // Check for duplicate (same path + offset).
        for i in 0..MAX_UPROBES {
            if self.occupied[i]
                && self.entries[i].file_offset == file_offset
                && self.entries[i].path_len == path.len()
                && self.entries[i].path[..path.len()] == *path
            {
                return Err(Error::AlreadyExists);
            }
        }
        let slot = self.find_free_slot()?;
        let uprobe_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        self.entries[slot].path[..path.len()].copy_from_slice(path);
        self.entries[slot].path_len = path.len();
        self.entries[slot].file_offset = file_offset;
        self.entries[slot].ref_ctr_offset = ref_ctr_offset;
        self.entries[slot].uprobe_id = uprobe_id;
        self.entries[slot].probe_type = probe_type;
        self.entries[slot].state = UprobeState::Registered;
        self.entries[slot].hit_count = 0;
        self.entries[slot].ref_count = 0;
        self.entries[slot].event_head = 0;
        self.entries[slot].event_count = 0;
        self.occupied[slot] = true;
        self.count += 1;
        Ok(uprobe_id)
    }

    /// Unregisters a uprobe by ID.
    pub fn unregister(&mut self, uprobe_id: u32) -> Result<()> {
        let slot = self.find_by_id(uprobe_id)?;
        if self.entries[slot].ref_count > 0 {
            return Err(Error::Busy);
        }
        self.entries[slot].state = UprobeState::Removing;
        self.occupied[slot] = false;
        self.count -= 1;
        Ok(())
    }

    /// Activates a uprobe (inserts breakpoint).
    pub fn activate(&mut self, uprobe_id: u32) -> Result<()> {
        let slot = self.find_by_id(uprobe_id)?;
        if self.entries[slot].state != UprobeState::Registered
            && self.entries[slot].state != UprobeState::Disabled
        {
            return Err(Error::InvalidArgument);
        }
        self.entries[slot].state = UprobeState::Active;
        Ok(())
    }

    /// Disables a uprobe.
    pub fn disable(&mut self, uprobe_id: u32) -> Result<()> {
        let slot = self.find_by_id(uprobe_id)?;
        if self.entries[slot].state != UprobeState::Active {
            return Err(Error::InvalidArgument);
        }
        self.entries[slot].state = UprobeState::Disabled;
        Ok(())
    }

    /// Processes a uprobe hit.
    pub fn process_hit(
        &mut self,
        uprobe_id: u32,
        timestamp_ns: u64,
        pid: u32,
        tid: u32,
        ip: u64,
        sp: u64,
    ) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        let slot = self.find_by_id(uprobe_id)?;
        if self.entries[slot].state != UprobeState::Active {
            return Err(Error::InvalidArgument);
        }
        let is_return = self.entries[slot].probe_type == UprobeType::Return;
        let mut event = UprobeEvent::new();
        event.timestamp_ns = timestamp_ns;
        event.pid = pid;
        event.tid = tid;
        event.ip = ip;
        event.sp = sp;
        event.cpu = 0; // Would come from current CPU.
        event.uprobe_id = uprobe_id;
        event.is_return = is_return;
        self.entries[slot].record_event(event);
        Ok(())
    }

    /// Handles a return probe hit.
    pub fn process_return_hit(
        &mut self,
        tid: u32,
        timestamp_ns: u64,
        pid: u32,
        ip: u64,
        sp: u64,
    ) -> Result<u64> {
        let orig_ret = self.trampoline.pop(tid)?;
        // Find the uprobe for this return instance — search by
        // matching return type.
        for i in 0..MAX_UPROBES {
            if self.occupied[i]
                && self.entries[i].probe_type == UprobeType::Return
                && self.entries[i].state == UprobeState::Active
            {
                let mut event = UprobeEvent::new();
                event.timestamp_ns = timestamp_ns;
                event.pid = pid;
                event.tid = tid;
                event.ip = ip;
                event.sp = sp;
                event.ret_addr = orig_ret;
                event.uprobe_id = self.entries[i].uprobe_id;
                event.is_return = true;
                self.entries[i].record_event(event);
                break;
            }
        }
        Ok(orig_ret)
    }

    /// Sets up a return probe by hijacking the return address.
    pub fn setup_return_probe(
        &mut self,
        uprobe_id: u32,
        tid: u32,
        orig_ret_addr: u64,
    ) -> Result<()> {
        let slot = self.find_by_id(uprobe_id)?;
        if self.entries[slot].probe_type != UprobeType::Return {
            return Err(Error::InvalidArgument);
        }
        self.trampoline.push(uprobe_id, tid, orig_ret_addr)
    }

    /// Saves the instruction bytes at a probe site.
    pub fn save_insn(&mut self, uprobe_id: u32, insn: &[u8]) -> Result<()> {
        let slot = self.find_by_id(uprobe_id)?;
        self.entries[slot].saved_insn.save(insn)
    }

    /// Finds a free slot.
    fn find_free_slot(&self) -> Result<usize> {
        self.occupied
            .iter()
            .position(|&o| !o)
            .ok_or(Error::OutOfMemory)
    }

    /// Finds slot by uprobe ID.
    fn find_by_id(&self, uprobe_id: u32) -> Result<usize> {
        for i in 0..MAX_UPROBES {
            if self.occupied[i] && self.entries[i].uprobe_id == uprobe_id {
                return Ok(i);
            }
        }
        Err(Error::NotFound)
    }
}
