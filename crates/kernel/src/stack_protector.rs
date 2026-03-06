// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Stack canary and guard page protection.
//!
//! Provides stack overflow detection via two complementary mechanisms:
//!
//! 1. **Stack canaries**: A random value placed between the stack frame
//!    and the return address. Checked on function return; corruption
//!    indicates a buffer overflow (potential exploit). Modeled after
//!    GCC's `-fstack-protector`.
//!
//! 2. **Guard pages**: An unmapped page placed at the bottom of each
//!    kernel/user thread stack. Any write to the guard page triggers a
//!    page fault, catching stack overflow before it corrupts adjacent
//!    memory.
//!
//! # Architecture
//!
//! ```text
//! ┌────────────────────────────┐  ← Stack top (highest address)
//! │  Stack frames (grows down) │
//! │  ┌──────────────────────┐  │
//! │  │  local variables     │  │
//! │  │  canary value        │  │  ← checked on function return
//! │  │  saved RBP / RA      │  │
//! │  └──────────────────────┘  │
//! │          ...               │
//! │                            │
//! ├────────────────────────────┤  ← Stack bottom
//! │  GUARD PAGE (unmapped)     │  ← page fault on overflow
//! └────────────────────────────┘
//! ```
//!
//! # Canary Format
//!
//! The canary is a 64-bit value with the following structure:
//! - Bits 63..8: random value (from kernel entropy pool)
//! - Bits  7..0: null byte (0x00) — terminates string copies
//!
//! # Reference
//!
//! Linux `include/linux/stackprotector.h`,
//! `arch/x86/include/asm/stackprotector.h`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum number of thread stacks tracked.
const MAX_STACKS: usize = 512;

/// Default stack size in bytes (16 KiB for kernel threads).
const DEFAULT_STACK_SIZE: usize = 16384;

/// Guard page size (one 4K page).
const GUARD_PAGE_SIZE: usize = 4096;

/// Canary null terminator mask (low byte = 0).
const CANARY_NULL_MASK: u64 = 0xFFFF_FFFF_FFFF_FF00;

/// Maximum violation log entries.
const MAX_VIOLATIONS: usize = 64;

/// Magic value used to detect uninitialised canary slots.
const CANARY_UNINIT: u64 = 0xDEAD_BEEF_DEAD_BEEF;

// ======================================================================
// CanaryValue — the stack canary
// ======================================================================

/// A stack canary value.
///
/// Contains a randomised 64-bit value with a null low byte to
/// inhibit string-copy-based overwrites.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanaryValue {
    /// The canary value (low byte always 0).
    value: u64,
}

impl CanaryValue {
    /// Create a new canary from a random seed.
    ///
    /// The low byte is forced to zero to act as a string terminator.
    pub const fn from_seed(seed: u64) -> Self {
        Self {
            value: seed & CANARY_NULL_MASK,
        }
    }

    /// Create a canary with the uninitialised sentinel.
    const fn uninit() -> Self {
        Self {
            value: CANARY_UNINIT,
        }
    }

    /// Get the raw canary value.
    pub fn raw(&self) -> u64 {
        self.value
    }

    /// Check whether this canary has been initialised.
    pub fn is_initialized(&self) -> bool {
        self.value != CANARY_UNINIT
    }

    /// Verify that the canary matches the expected value.
    pub fn verify(&self, expected: &CanaryValue) -> bool {
        self.value == expected.value
    }
}

// ======================================================================
// GuardPage — metadata about a stack's guard page
// ======================================================================

/// Metadata for a guard page at the bottom of a thread stack.
#[derive(Debug, Clone, Copy)]
pub struct GuardPage {
    /// Virtual address of the guard page.
    pub vaddr: u64,
    /// Size of the guard region in bytes (usually one page).
    pub size: usize,
    /// Whether the guard page is currently mapped as inaccessible.
    pub active: bool,
    /// Thread/task ID owning this guard page.
    pub owner_tid: u64,
}

impl GuardPage {
    /// Create an inactive guard page descriptor.
    const fn empty() -> Self {
        Self {
            vaddr: 0,
            size: 0,
            active: false,
            owner_tid: 0,
        }
    }

    /// Create a guard page for the given stack region.
    pub const fn new(vaddr: u64, size: usize, owner_tid: u64) -> Self {
        Self {
            vaddr,
            size,
            active: true,
            owner_tid,
        }
    }
}

// ======================================================================
// StackCheckConfig — configuration knobs
// ======================================================================

/// Configuration for stack protection behaviour.
#[derive(Debug, Clone, Copy)]
pub struct StackCheckConfig {
    /// Enable stack canaries.
    pub canary_enabled: bool,
    /// Enable guard pages.
    pub guard_page_enabled: bool,
    /// Log violations before panic.
    pub log_violations: bool,
    /// Panic on canary corruption (vs. kill offending task only).
    pub panic_on_corruption: bool,
    /// Guard page size in bytes.
    pub guard_size: usize,
    /// How often (in ticks) to run background canary audits.
    pub audit_interval_ticks: u64,
}

impl StackCheckConfig {
    /// Default configuration with all protections enabled.
    pub const fn new() -> Self {
        Self {
            canary_enabled: true,
            guard_page_enabled: true,
            log_violations: true,
            panic_on_corruption: true,
            guard_size: GUARD_PAGE_SIZE,
            audit_interval_ticks: 1000,
        }
    }
}

// ======================================================================
// ViolationType — kind of stack violation detected
// ======================================================================

/// The type of stack violation that was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViolationType {
    /// Stack canary was corrupted.
    CanaryCorruption,
    /// Access to the guard page was detected (page fault).
    GuardPageFault,
    /// Stack pointer went below the guard page.
    StackUnderflow,
    /// Stack pointer exceeds the stack top.
    StackOverflow,
}

// ======================================================================
// ViolationRecord — log entry for a stack violation
// ======================================================================

/// A recorded stack violation event.
#[derive(Debug, Clone, Copy)]
pub struct ViolationRecord {
    /// Type of violation.
    pub kind: ViolationType,
    /// Thread/task ID of the offender.
    pub tid: u64,
    /// Instruction pointer at the time of violation.
    pub rip: u64,
    /// Stack pointer at the time of violation.
    pub rsp: u64,
    /// Expected canary value (for canary violations).
    pub expected_canary: u64,
    /// Actual canary value found.
    pub actual_canary: u64,
    /// Monotonic tick when the violation occurred.
    pub timestamp: u64,
    /// Whether this entry is valid.
    pub valid: bool,
}

impl ViolationRecord {
    /// Create an empty (invalid) record.
    const fn empty() -> Self {
        Self {
            kind: ViolationType::CanaryCorruption,
            tid: 0,
            rip: 0,
            rsp: 0,
            expected_canary: 0,
            actual_canary: 0,
            timestamp: 0,
            valid: false,
        }
    }
}

// ======================================================================
// StackEntry — per-thread stack tracking
// ======================================================================

/// Per-thread stack metadata tracked by the protector.
#[derive(Debug, Clone, Copy)]
struct StackEntry {
    /// Thread/task ID.
    tid: u64,
    /// Stack base address (lowest usable address, above guard page).
    stack_base: u64,
    /// Stack top address (highest address).
    stack_top: u64,
    /// Stack size in bytes (excluding guard page).
    stack_size: usize,
    /// The expected canary value for this thread.
    canary: CanaryValue,
    /// Guard page descriptor.
    guard: GuardPage,
    /// Whether this slot is in use.
    active: bool,
}

impl StackEntry {
    /// Create an empty (inactive) entry.
    const fn empty() -> Self {
        Self {
            tid: 0,
            stack_base: 0,
            stack_top: 0,
            stack_size: 0,
            canary: CanaryValue::uninit(),
            guard: GuardPage::empty(),
            active: false,
        }
    }
}

// ======================================================================
// StackProtectorStats — aggregate statistics
// ======================================================================

/// Aggregate statistics for the stack protector subsystem.
#[derive(Debug, Clone, Copy)]
pub struct StackProtectorStats {
    /// Total stacks currently tracked.
    pub active_stacks: u32,
    /// Total canary checks performed.
    pub canary_checks: u64,
    /// Total canary violations detected.
    pub canary_violations: u64,
    /// Total guard page faults handled.
    pub guard_faults: u64,
    /// Total background audit passes.
    pub audit_passes: u64,
    /// Violation log entries written.
    pub log_entries: u32,
}

impl StackProtectorStats {
    /// Create zeroed statistics.
    const fn new() -> Self {
        Self {
            active_stacks: 0,
            canary_checks: 0,
            canary_violations: 0,
            guard_faults: 0,
            audit_passes: 0,
            log_entries: 0,
        }
    }
}

// ======================================================================
// StackGuard — top-level stack protector
// ======================================================================

/// Top-level stack protector managing canaries and guard pages for
/// all tracked thread stacks.
pub struct StackGuard {
    /// Per-thread stack entries.
    entries: [StackEntry; MAX_STACKS],
    /// Number of active entries.
    num_entries: usize,
    /// Configuration.
    config: StackCheckConfig,
    /// Violation log (circular buffer).
    violations: [ViolationRecord; MAX_VIOLATIONS],
    /// Next write index in the violation log.
    violation_head: usize,
    /// Statistics.
    stats: StackProtectorStats,
    /// Master canary seed (from entropy pool).
    master_seed: u64,
    /// Current monotonic tick.
    current_tick: u64,
    /// Tick at which the last audit ran.
    last_audit_tick: u64,
}

impl StackGuard {
    /// Create a new stack protector.
    pub const fn new() -> Self {
        Self {
            entries: [const { StackEntry::empty() }; MAX_STACKS],
            num_entries: 0,
            config: StackCheckConfig::new(),
            violations: [const { ViolationRecord::empty() }; MAX_VIOLATIONS],
            violation_head: 0,
            stats: StackProtectorStats::new(),
            master_seed: 0,
            current_tick: 0,
            last_audit_tick: 0,
        }
    }

    /// Initialise the stack protector with a random seed.
    pub fn init(&mut self, seed: u64, config: StackCheckConfig) {
        self.master_seed = seed;
        self.config = config;
    }

    /// Generate a per-thread canary from the master seed and TID.
    fn generate_canary(&self, tid: u64) -> CanaryValue {
        // Simple hash: XOR + rotate.  In a real kernel this would
        // use a cryptographic PRNG.
        let mixed = self.master_seed ^ tid.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let rotated = mixed.rotate_left(13) ^ mixed.rotate_right(7);
        CanaryValue::from_seed(rotated)
    }

    /// Initialise a canary for a new thread stack.
    ///
    /// Registers the stack region and returns the canary value that
    /// must be written at the stack frame boundary.
    pub fn init_canary(
        &mut self,
        tid: u64,
        stack_base: u64,
        stack_size: usize,
    ) -> Result<CanaryValue> {
        if !self.config.canary_enabled {
            return Ok(CanaryValue::from_seed(0));
        }
        if self.num_entries >= MAX_STACKS {
            return Err(Error::OutOfMemory);
        }
        if stack_size < GUARD_PAGE_SIZE + 1 {
            return Err(Error::InvalidArgument);
        }

        let canary = self.generate_canary(tid);
        let stack_top = stack_base + stack_size as u64;

        // Find a free slot.
        let slot_idx = self
            .entries
            .iter()
            .position(|e| !e.active)
            .ok_or(Error::OutOfMemory)?;

        self.entries[slot_idx] = StackEntry {
            tid,
            stack_base,
            stack_top,
            stack_size,
            canary,
            guard: GuardPage::empty(),
            active: true,
        };
        self.num_entries += 1;
        self.stats.active_stacks += 1;

        Ok(canary)
    }

    /// Verify the canary for a thread.
    ///
    /// Returns `Ok(true)` if the canary matches, `Ok(false)` if it
    /// was corrupted, or an error if the TID is not tracked.
    pub fn verify_canary(&mut self, tid: u64, actual_value: u64) -> Result<bool> {
        if !self.config.canary_enabled {
            return Ok(true);
        }

        self.stats.canary_checks += 1;

        let entry = self
            .entries
            .iter()
            .find(|e| e.active && e.tid == tid)
            .ok_or(Error::NotFound)?;

        let expected = entry.canary;
        let actual = CanaryValue::from_seed(actual_value);

        if expected.verify(&actual) {
            Ok(true)
        } else {
            self.stats.canary_violations += 1;
            if self.config.log_violations {
                self.log_violation(ViolationRecord {
                    kind: ViolationType::CanaryCorruption,
                    tid,
                    rip: 0,
                    rsp: 0,
                    expected_canary: expected.raw(),
                    actual_canary: actual.raw(),
                    timestamp: self.current_tick,
                    valid: true,
                });
            }
            Ok(false)
        }
    }

    /// Set up a guard page at the bottom of a thread's stack.
    pub fn setup_guard_page(&mut self, tid: u64) -> Result<GuardPage> {
        if !self.config.guard_page_enabled {
            return Ok(GuardPage::empty());
        }

        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.active && e.tid == tid)
            .ok_or(Error::NotFound)?;

        // Guard page sits immediately below the usable stack base.
        let guard_vaddr = entry
            .stack_base
            .saturating_sub(self.config.guard_size as u64);
        let guard = GuardPage::new(guard_vaddr, self.config.guard_size, tid);
        entry.guard = guard;

        // In a real implementation, we would call into the page table
        // code to unmap (or mark no-access) the guard page region.

        Ok(guard)
    }

    /// Handle a stack overflow event (guard page fault or canary
    /// corruption detected by hardware).
    pub fn on_stack_overflow(&mut self, tid: u64, rip: u64, rsp: u64) -> Result<ViolationType> {
        self.stats.guard_faults += 1;

        // Determine the type of violation.
        let kind = if let Some(entry) = self.entries.iter().find(|e| e.active && e.tid == tid) {
            if entry.guard.active
                && rsp >= entry.guard.vaddr
                && rsp < entry.guard.vaddr + entry.guard.size as u64
            {
                ViolationType::GuardPageFault
            } else if rsp < entry.stack_base {
                ViolationType::StackUnderflow
            } else {
                ViolationType::StackOverflow
            }
        } else {
            ViolationType::StackOverflow
        };

        if self.config.log_violations {
            self.log_violation(ViolationRecord {
                kind,
                tid,
                rip,
                rsp,
                expected_canary: 0,
                actual_canary: 0,
                timestamp: self.current_tick,
                valid: true,
            });
        }

        Ok(kind)
    }

    /// Remove tracking for a thread that has exited.
    pub fn remove_stack(&mut self, tid: u64) -> Result<()> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.active && e.tid == tid)
            .ok_or(Error::NotFound)?;

        entry.active = false;
        entry.canary = CanaryValue::uninit();
        entry.guard = GuardPage::empty();

        if self.num_entries > 0 {
            self.num_entries -= 1;
        }
        if self.stats.active_stacks > 0 {
            self.stats.active_stacks -= 1;
        }

        Ok(())
    }

    /// Run a background audit of all tracked canaries.
    ///
    /// In a real kernel, this would read the actual canary value from
    /// each thread's stack frame. Here we validate internal state
    /// consistency. Returns the number of stacks audited.
    pub fn audit(&mut self) -> u32 {
        self.stats.audit_passes += 1;
        self.last_audit_tick = self.current_tick;

        let mut audited = 0u32;
        for entry in &self.entries {
            if entry.active && entry.canary.is_initialized() {
                audited += 1;
            }
        }
        audited
    }

    /// Check whether a background audit is due.
    pub fn audit_due(&self) -> bool {
        self.current_tick.saturating_sub(self.last_audit_tick) >= self.config.audit_interval_ticks
    }

    /// Set the current monotonic tick.
    pub fn set_tick(&mut self, tick: u64) {
        self.current_tick = tick;
    }

    /// Get the stack protector statistics.
    pub fn stats(&self) -> &StackProtectorStats {
        &self.stats
    }

    /// Get the current configuration.
    pub fn config(&self) -> &StackCheckConfig {
        &self.config
    }

    /// Get the number of violation log entries.
    pub fn violation_count(&self) -> u32 {
        self.stats.log_entries
    }

    /// Read a violation record by index.
    pub fn get_violation(&self, index: usize) -> Result<&ViolationRecord> {
        if index >= MAX_VIOLATIONS {
            return Err(Error::InvalidArgument);
        }
        let record = &self.violations[index];
        if !record.valid {
            return Err(Error::NotFound);
        }
        Ok(record)
    }

    /// Log a violation record into the circular buffer.
    fn log_violation(&mut self, record: ViolationRecord) {
        self.violations[self.violation_head] = record;
        self.violation_head = (self.violation_head + 1) % MAX_VIOLATIONS;
        self.stats.log_entries += 1;
    }

    /// Lookup the canary value for a given thread ID.
    pub fn get_canary(&self, tid: u64) -> Result<CanaryValue> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.active && e.tid == tid)
            .ok_or(Error::NotFound)?;
        Ok(entry.canary)
    }

    /// Check whether a thread has a guard page configured.
    pub fn has_guard_page(&self, tid: u64) -> bool {
        self.entries
            .iter()
            .any(|e| e.active && e.tid == tid && e.guard.active)
    }
}
