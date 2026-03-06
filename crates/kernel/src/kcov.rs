// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel code coverage collection (kcov).
//!
//! Provides per-task coverage data collection, recording program
//! counter (PC) addresses or comparison operands executed during
//! a task's lifetime. User space enables coverage on a task, then
//! reads the shared coverage buffer to determine which code paths
//! were exercised.
//!
//! # Architecture
//!
//! ```text
//!  task_enable_kcov()──► KcovInstance::enable()
//!        │
//!        ▼
//!  instrumented code ──► kcov_trace_pc(pc)
//!        │                  or kcov_trace_cmp(type, arg1, arg2, pc)
//!        ▼
//!  KcovArea::record_pc() / record_cmp()
//!        │
//!        ▼
//!  task_disable_kcov()──► KcovInstance::disable()
//!        │
//!        ▼
//!  user reads KcovArea buffer via shared mapping
//! ```
//!
//! # Modes
//!
//! - **TracePC**: Records the PC of each executed basic block.
//! - **TraceCmp**: Records comparison operands (type, arg1, arg2,
//!   pc) for fuzzer-driven coverage guidance.
//!
//! Reference: Linux `kernel/kcov.c`,
//! `include/linux/kcov.h`.

use oncrix_lib::{Error, Result};

/// Maximum number of PC entries in a single coverage area.
///
/// Sized to fit in a single 4 KiB shared page when each entry
/// is 8 bytes (512 * 8 = 4096).
const KCOV_AREA_SIZE: usize = 512;

/// Maximum number of comparison operand records.
///
/// Each record is 4 u64 values (type, arg1, arg2, pc), so 128
/// records = 4096 bytes.
const KCOV_CMP_SIZE: usize = 128;

/// Maximum number of kcov instances (one per task).
const MAX_KCOV_INSTANCES: usize = 32;

// -------------------------------------------------------------------
// KcovMode
// -------------------------------------------------------------------

/// Operating mode for a kcov instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[derive(Default)]
pub enum KcovMode {
    /// Coverage collection is disabled.
    #[default]
    Disabled = 0,
    /// Record program counter addresses of executed basic blocks.
    TracePC = 1,
    /// Record comparison operands for guided fuzzing.
    TraceCmp = 2,
}

// -------------------------------------------------------------------
// CmpRecord
// -------------------------------------------------------------------

/// A single comparison operand record captured in TraceCmp mode.
#[derive(Debug, Clone, Copy, Default)]
pub struct CmpRecord {
    /// Comparison type encoding (size | is_const flag).
    ///
    /// Bits 0-1: operand size (0=u8, 1=u16, 2=u32, 3=u64).
    /// Bit 2: 1 if one operand is a compile-time constant.
    pub cmp_type: u64,
    /// First comparison operand.
    pub arg1: u64,
    /// Second comparison operand.
    pub arg2: u64,
    /// Program counter of the comparison instruction.
    pub pc: u64,
}

// -------------------------------------------------------------------
// KcovArea
// -------------------------------------------------------------------

/// Shared coverage buffer for a single task.
///
/// In TracePC mode, the `pcs` array records unique PC addresses.
/// In TraceCmp mode, the `cmps` array records comparison operand
/// tuples. The first entry in `pcs` (index 0) serves as a write
/// cursor, following the Linux kcov convention.
pub struct KcovArea {
    /// PC trace buffer. Index 0 is the write cursor.
    pcs: [u64; KCOV_AREA_SIZE],
    /// Comparison operand buffer.
    cmps: [CmpRecord; KCOV_CMP_SIZE],
    /// Number of valid PC entries (excluding the cursor slot).
    pc_count: usize,
    /// Number of valid comparison records.
    cmp_count: usize,
}

impl Default for KcovArea {
    fn default() -> Self {
        Self::new()
    }
}

impl KcovArea {
    /// Create an empty coverage area.
    pub const fn new() -> Self {
        Self {
            pcs: [0u64; KCOV_AREA_SIZE],
            cmps: [CmpRecord {
                cmp_type: 0,
                arg1: 0,
                arg2: 0,
                pc: 0,
            }; KCOV_CMP_SIZE],
            pc_count: 0,
            cmp_count: 0,
        }
    }

    /// Record a program counter address in TracePC mode.
    ///
    /// Returns `true` if the PC was recorded, `false` if the
    /// buffer is full.
    pub fn record_pc(&mut self, pc: u64) -> bool {
        // Slot 0 is the cursor; usable slots are 1..KCOV_AREA_SIZE.
        if self.pc_count >= KCOV_AREA_SIZE - 1 {
            return false;
        }
        self.pc_count += 1;
        self.pcs[self.pc_count] = pc;
        // Update cursor at index 0.
        self.pcs[0] = self.pc_count as u64;
        true
    }

    /// Record a comparison operand tuple in TraceCmp mode.
    ///
    /// Returns `true` if the record was stored, `false` if the
    /// buffer is full.
    pub fn record_cmp(&mut self, cmp_type: u64, arg1: u64, arg2: u64, pc: u64) -> bool {
        if self.cmp_count >= KCOV_CMP_SIZE {
            return false;
        }
        self.cmps[self.cmp_count] = CmpRecord {
            cmp_type,
            arg1,
            arg2,
            pc,
        };
        self.cmp_count += 1;
        true
    }

    /// Reset the coverage area, clearing all collected data.
    pub fn reset(&mut self) {
        self.pcs = [0u64; KCOV_AREA_SIZE];
        self.cmps = [CmpRecord {
            cmp_type: 0,
            arg1: 0,
            arg2: 0,
            pc: 0,
        }; KCOV_CMP_SIZE];
        self.pc_count = 0;
        self.cmp_count = 0;
    }

    /// Number of PC entries currently recorded.
    pub fn pc_count(&self) -> usize {
        self.pc_count
    }

    /// Number of comparison records currently stored.
    pub fn cmp_count(&self) -> usize {
        self.cmp_count
    }

    /// Read the PC at the given index (1-based, following the
    /// cursor convention).
    ///
    /// Returns `None` if `index` is out of range.
    pub fn read_pc(&self, index: usize) -> Option<u64> {
        if index == 0 || index > self.pc_count {
            return None;
        }
        Some(self.pcs[index])
    }

    /// Read the comparison record at the given index.
    ///
    /// Returns `None` if `index` is out of range.
    pub fn read_cmp(&self, index: usize) -> Option<&CmpRecord> {
        if index >= self.cmp_count {
            return None;
        }
        Some(&self.cmps[index])
    }

    /// Raw read of the cursor value at index 0.
    pub fn cursor(&self) -> u64 {
        self.pcs[0]
    }

    /// Check whether the PC buffer is full.
    pub fn pc_full(&self) -> bool {
        self.pc_count >= KCOV_AREA_SIZE - 1
    }

    /// Check whether the comparison buffer is full.
    pub fn cmp_full(&self) -> bool {
        self.cmp_count >= KCOV_CMP_SIZE
    }
}

impl core::fmt::Debug for KcovArea {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KcovArea")
            .field("pc_count", &self.pc_count)
            .field("cmp_count", &self.cmp_count)
            .field("pc_capacity", &(KCOV_AREA_SIZE - 1))
            .field("cmp_capacity", &KCOV_CMP_SIZE)
            .finish()
    }
}

// -------------------------------------------------------------------
// KcovInstance
// -------------------------------------------------------------------

/// Per-task kcov instance managing coverage collection state.
///
/// Each instance owns a [`KcovArea`] and tracks the collection
/// mode, owning task, and hit/overflow statistics.
pub struct KcovInstance {
    /// Coverage data buffer.
    area: KcovArea,
    /// Current collection mode.
    mode: KcovMode,
    /// Task ID that owns this instance.
    task_id: u64,
    /// Whether this instance slot is in use.
    active: bool,
    /// Unique instance identifier.
    id: u32,
    /// Total number of trace points recorded.
    total_hits: u64,
    /// Number of trace points dropped due to full buffers.
    overflows: u64,
}

impl Default for KcovInstance {
    fn default() -> Self {
        Self {
            area: KcovArea::new(),
            mode: KcovMode::Disabled,
            task_id: 0,
            active: false,
            id: 0,
            total_hits: 0,
            overflows: 0,
        }
    }
}

impl KcovInstance {
    /// Create a new inactive kcov instance.
    pub const fn new() -> Self {
        Self {
            area: KcovArea::new(),
            mode: KcovMode::Disabled,
            task_id: 0,
            active: false,
            id: 0,
            total_hits: 0,
            overflows: 0,
        }
    }

    /// Enable coverage collection in the specified mode.
    ///
    /// Resets the coverage area before starting.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `mode` is
    ///   [`KcovMode::Disabled`].
    /// - [`Error::Busy`] if collection is already active.
    pub fn enable(&mut self, mode: KcovMode) -> Result<()> {
        if mode == KcovMode::Disabled {
            return Err(Error::InvalidArgument);
        }
        if self.mode != KcovMode::Disabled {
            return Err(Error::Busy);
        }
        self.area.reset();
        self.mode = mode;
        self.total_hits = 0;
        self.overflows = 0;
        Ok(())
    }

    /// Disable coverage collection, returning to
    /// [`KcovMode::Disabled`].
    ///
    /// The coverage data remains in the area for reading until
    /// the next `enable()` call.
    pub fn disable(&mut self) {
        self.mode = KcovMode::Disabled;
    }

    /// Current collection mode.
    pub fn mode(&self) -> KcovMode {
        self.mode
    }

    /// Task ID that owns this instance.
    pub fn task_id(&self) -> u64 {
        self.task_id
    }

    /// Unique instance identifier.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Total trace points recorded since last enable.
    pub fn total_hits(&self) -> u64 {
        self.total_hits
    }

    /// Trace points dropped due to buffer overflow.
    pub fn overflows(&self) -> u64 {
        self.overflows
    }

    /// Reference to the underlying coverage area.
    pub fn area(&self) -> &KcovArea {
        &self.area
    }

    /// Record a PC trace point.
    ///
    /// Only records if the instance is in [`KcovMode::TracePC`]
    /// mode. Returns `true` if the PC was recorded.
    pub fn trace_pc(&mut self, pc: u64) -> bool {
        if self.mode != KcovMode::TracePC {
            return false;
        }
        self.total_hits += 1;
        if self.area.record_pc(pc) {
            true
        } else {
            self.overflows += 1;
            false
        }
    }

    /// Record a comparison operand trace point.
    ///
    /// Only records if the instance is in
    /// [`KcovMode::TraceCmp`] mode. Returns `true` if the
    /// record was stored.
    pub fn trace_cmp(&mut self, cmp_type: u64, arg1: u64, arg2: u64, pc: u64) -> bool {
        if self.mode != KcovMode::TraceCmp {
            return false;
        }
        self.total_hits += 1;
        if self.area.record_cmp(cmp_type, arg1, arg2, pc) {
            true
        } else {
            self.overflows += 1;
            false
        }
    }
}

impl core::fmt::Debug for KcovInstance {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KcovInstance")
            .field("id", &self.id)
            .field("task_id", &self.task_id)
            .field("mode", &self.mode)
            .field("active", &self.active)
            .field("total_hits", &self.total_hits)
            .field("overflows", &self.overflows)
            .field("area", &self.area)
            .finish()
    }
}

// -------------------------------------------------------------------
// KcovStats
// -------------------------------------------------------------------

/// Aggregate statistics for a kcov instance.
#[derive(Debug, Clone, Copy, Default)]
pub struct KcovStats {
    /// Current collection mode.
    pub mode: KcovMode,
    /// Number of PC entries collected.
    pub pc_count: usize,
    /// Number of comparison records collected.
    pub cmp_count: usize,
    /// Total trace points since last enable.
    pub total_hits: u64,
    /// Trace points lost to buffer overflow.
    pub overflows: u64,
}

// -------------------------------------------------------------------
// KcovRegistry
// -------------------------------------------------------------------

/// Central registry managing all kcov instances.
///
/// Supports up to [`MAX_KCOV_INSTANCES`] concurrent coverage
/// sessions, each bound to a single task.
pub struct KcovRegistry {
    /// Pool of kcov instances.
    instances: [KcovInstance; MAX_KCOV_INSTANCES],
    /// Next unique instance identifier.
    next_id: u32,
    /// Number of active instances.
    active_count: usize,
}

impl Default for KcovRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl KcovRegistry {
    /// Create an empty kcov registry.
    pub const fn new() -> Self {
        const INIT: KcovInstance = KcovInstance::new();
        Self {
            instances: [INIT; MAX_KCOV_INSTANCES],
            next_id: 1,
            active_count: 0,
        }
    }

    /// Allocate a new kcov instance for the given task.
    ///
    /// Returns the instance identifier on success.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the registry is full.
    /// - [`Error::AlreadyExists`] if the task already has an
    ///   instance.
    pub fn alloc(&mut self, task_id: u64) -> Result<u32> {
        // Reject duplicate task registrations.
        let dup = self
            .instances
            .iter()
            .any(|inst| inst.active && inst.task_id == task_id);
        if dup {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .instances
            .iter_mut()
            .find(|inst| !inst.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        *slot = KcovInstance::new();
        slot.task_id = task_id;
        slot.active = true;
        slot.id = id;
        self.active_count += 1;
        Ok(id)
    }

    /// Release the kcov instance with the given `id`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no active instance has this `id`.
    pub fn free(&mut self, id: u32) -> Result<()> {
        let slot = self
            .instances
            .iter_mut()
            .find(|inst| inst.active && inst.id == id)
            .ok_or(Error::NotFound)?;

        slot.active = false;
        slot.mode = KcovMode::Disabled;
        self.active_count = self.active_count.saturating_sub(1);
        Ok(())
    }

    /// Release the kcov instance owned by `task_id`.
    ///
    /// Called during task teardown to clean up coverage state.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no active instance belongs to
    ///   this task.
    pub fn free_by_task(&mut self, task_id: u64) -> Result<()> {
        let slot = self
            .instances
            .iter_mut()
            .find(|inst| inst.active && inst.task_id == task_id)
            .ok_or(Error::NotFound)?;

        slot.active = false;
        slot.mode = KcovMode::Disabled;
        self.active_count = self.active_count.saturating_sub(1);
        Ok(())
    }

    /// Enable coverage collection on the instance with `id`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no active instance has this `id`.
    /// - [`Error::InvalidArgument`] if `mode` is `Disabled`.
    /// - [`Error::Busy`] if the instance is already collecting.
    pub fn enable(&mut self, id: u32, mode: KcovMode) -> Result<()> {
        let inst = self
            .instances
            .iter_mut()
            .find(|inst| inst.active && inst.id == id)
            .ok_or(Error::NotFound)?;
        inst.enable(mode)
    }

    /// Disable coverage collection on the instance with `id`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no active instance has this `id`.
    pub fn disable(&mut self, id: u32) -> Result<()> {
        let inst = self
            .instances
            .iter_mut()
            .find(|inst| inst.active && inst.id == id)
            .ok_or(Error::NotFound)?;
        inst.disable();
        Ok(())
    }

    /// Record a PC trace point for the given task.
    ///
    /// Looks up the instance by `task_id` and records the PC
    /// if the instance is in TracePC mode. Returns `true` if
    /// recorded.
    pub fn trace_pc(&mut self, task_id: u64, pc: u64) -> bool {
        let inst = self
            .instances
            .iter_mut()
            .find(|inst| inst.active && inst.task_id == task_id);
        match inst {
            Some(i) => i.trace_pc(pc),
            None => false,
        }
    }

    /// Record a comparison operand trace point for the given
    /// task.
    ///
    /// Looks up the instance by `task_id` and records the
    /// comparison if the instance is in TraceCmp mode. Returns
    /// `true` if recorded.
    pub fn trace_cmp(
        &mut self,
        task_id: u64,
        cmp_type: u64,
        arg1: u64,
        arg2: u64,
        pc: u64,
    ) -> bool {
        let inst = self
            .instances
            .iter_mut()
            .find(|inst| inst.active && inst.task_id == task_id);
        match inst {
            Some(i) => i.trace_cmp(cmp_type, arg1, arg2, pc),
            None => false,
        }
    }

    /// Retrieve statistics for the instance with `id`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no active instance has this `id`.
    pub fn stats(&self, id: u32) -> Result<KcovStats> {
        let inst = self
            .instances
            .iter()
            .find(|inst| inst.active && inst.id == id)
            .ok_or(Error::NotFound)?;
        Ok(KcovStats {
            mode: inst.mode,
            pc_count: inst.area.pc_count(),
            cmp_count: inst.area.cmp_count(),
            total_hits: inst.total_hits,
            overflows: inst.overflows,
        })
    }

    /// Look up the instance for a given task and return a
    /// reference to its coverage area.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no active instance belongs to
    ///   this task.
    pub fn area_for_task(&self, task_id: u64) -> Result<&KcovArea> {
        let inst = self
            .instances
            .iter()
            .find(|inst| inst.active && inst.task_id == task_id)
            .ok_or(Error::NotFound)?;
        Ok(&inst.area)
    }

    /// Number of active kcov instances.
    pub fn active_count(&self) -> usize {
        self.active_count
    }

    /// Total capacity of the registry.
    pub fn capacity(&self) -> usize {
        MAX_KCOV_INSTANCES
    }

    /// Check whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.active_count == 0
    }
}

impl core::fmt::Debug for KcovRegistry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KcovRegistry")
            .field("active_count", &self.active_count)
            .field("capacity", &MAX_KCOV_INSTANCES)
            .field("next_id", &self.next_id)
            .finish()
    }
}
