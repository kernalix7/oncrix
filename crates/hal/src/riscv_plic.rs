// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RISC-V Platform-Level Interrupt Controller (PLIC) driver.
//!
//! The PLIC is the RISC-V standard interrupt controller for external
//! (global) interrupts. It arbitrates among multiple interrupt sources
//! and delivers one interrupt at a time to each hart context.
//!
//! # PLIC Memory Map (base = PLIC_BASE)
//!
//! | Offset          | Description                          |
//! |-----------------|--------------------------------------|
//! | 0x000000        | Source 0 priority (reserved)         |
//! | 0x000004 + 4*n  | Source n priority (1..1023)          |
//! | 0x001000        | Pending bits (32 regs, 1 bit/source) |
//! | 0x002000 + 0x80*C| Enable bits for context C           |
//! | 0x200000 + 0x1000*C | Context C threshold + claim/complete |
//!
//! # Context Layout (per hart)
//!
//! Each hart has 2 contexts: M-mode (2*hart) and S-mode (2*hart+1).
//!
//! Reference: RISC-V PLIC Specification v1.0.0.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of PLIC interrupt sources.
pub const PLIC_MAX_SOURCES: usize = 1024;
/// Maximum number of PLIC contexts (harts × 2 privilege modes).
pub const PLIC_MAX_CONTEXTS: usize = 15872;

// ---------------------------------------------------------------------------
// PLIC Register Offsets
// ---------------------------------------------------------------------------

/// Source priority registers base (4 bytes per source).
const PLIC_PRIORITY_BASE: u64 = 0x000000;
/// Pending bits registers base (1 bit per source, 32 sources per u32).
const PLIC_PENDING_BASE: u64 = 0x001000;
/// Enable bits base (0x80 bytes per context).
const PLIC_ENABLE_BASE: u64 = 0x002000;
/// Per-context register area base (0x1000 bytes per context).
const PLIC_CONTEXT_BASE: u64 = 0x200000;

/// Within context area: threshold register offset.
const CTX_THRESHOLD: u64 = 0x000;
/// Within context area: claim/complete register offset.
const CTX_CLAIM: u64 = 0x004;

// ---------------------------------------------------------------------------
// PLIC instance
// ---------------------------------------------------------------------------

/// RISC-V PLIC hardware instance.
pub struct RiscvPlic {
    /// MMIO base address of the PLIC.
    base: u64,
    /// Number of interrupt sources (1-based, source 0 is reserved).
    num_sources: usize,
    /// Number of contexts.
    num_contexts: usize,
    /// Whether this PLIC is initialized.
    initialized: bool,
}

impl RiscvPlic {
    /// Creates a new PLIC instance.
    ///
    /// `num_sources` — number of interrupt sources (max 1023).
    /// `num_contexts` — number of contexts (harts × 2 modes).
    pub const fn new(base: u64, num_sources: usize, num_contexts: usize) -> Self {
        let ns = if num_sources > PLIC_MAX_SOURCES - 1 {
            PLIC_MAX_SOURCES - 1
        } else {
            num_sources
        };
        let nc = if num_contexts > PLIC_MAX_CONTEXTS {
            PLIC_MAX_CONTEXTS
        } else {
            num_contexts
        };
        Self {
            base,
            num_sources: ns,
            num_contexts: nc,
            initialized: false,
        }
    }

    /// Initializes the PLIC.
    ///
    /// Sets all source priorities to 0 (disabled) and all context thresholds
    /// to 0 (accept all).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the base address is zero.
    pub fn init(&mut self) -> Result<()> {
        if self.base == 0 {
            return Err(Error::InvalidArgument);
        }
        // Disable all sources (priority 0 = disabled).
        for src in 1..=self.num_sources {
            self.set_priority(src as u32, 0);
        }
        // Set all context thresholds to 0 (accept all priorities).
        for ctx in 0..self.num_contexts {
            self.set_threshold(ctx as u32, 0);
        }
        self.initialized = true;
        Ok(())
    }

    /// Sets the priority of interrupt source `src` (1..=num_sources).
    ///
    /// Priority 0 disables the source; priority 7 is highest.
    pub fn set_priority(&self, src: u32, priority: u32) {
        let offset = PLIC_PRIORITY_BASE + src as u64 * 4;
        self.write32(offset, priority & 0x7);
    }

    /// Returns the priority of source `src`.
    pub fn get_priority(&self, src: u32) -> u32 {
        self.read32(PLIC_PRIORITY_BASE + src as u64 * 4)
    }

    /// Returns `true` if source `src` has a pending interrupt.
    pub fn is_pending(&self, src: u32) -> bool {
        let reg_idx = src / 32;
        let bit = src % 32;
        let val = self.read32(PLIC_PENDING_BASE + reg_idx as u64 * 4);
        val & (1 << bit) != 0
    }

    /// Enables interrupt source `src` for context `ctx`.
    pub fn enable_source(&self, ctx: u32, src: u32) {
        let enable_offset = PLIC_ENABLE_BASE + ctx as u64 * 0x80 + (src / 32) as u64 * 4;
        let val = self.read32(enable_offset);
        self.write32(enable_offset, val | (1 << (src % 32)));
    }

    /// Disables interrupt source `src` for context `ctx`.
    pub fn disable_source(&self, ctx: u32, src: u32) {
        let enable_offset = PLIC_ENABLE_BASE + ctx as u64 * 0x80 + (src / 32) as u64 * 4;
        let val = self.read32(enable_offset);
        self.write32(enable_offset, val & !(1 << (src % 32)));
    }

    /// Sets the priority threshold for context `ctx`.
    ///
    /// Only interrupts with priority > threshold are forwarded.
    pub fn set_threshold(&self, ctx: u32, threshold: u32) {
        let offset = PLIC_CONTEXT_BASE + ctx as u64 * 0x1000 + CTX_THRESHOLD;
        self.write32(offset, threshold & 0x7);
    }

    /// Returns the priority threshold for context `ctx`.
    pub fn get_threshold(&self, ctx: u32) -> u32 {
        self.read32(PLIC_CONTEXT_BASE + ctx as u64 * 0x1000 + CTX_THRESHOLD)
    }

    /// Claims the highest-priority pending interrupt for context `ctx`.
    ///
    /// Returns 0 if no interrupt is pending (spurious).
    /// The returned source ID must be passed to [`complete`](Self::complete)
    /// after handling the interrupt.
    pub fn claim(&self, ctx: u32) -> u32 {
        self.read32(PLIC_CONTEXT_BASE + ctx as u64 * 0x1000 + CTX_CLAIM)
    }

    /// Signals completion of interrupt source `src` for context `ctx`.
    ///
    /// Must be called after the interrupt handler has finished.
    pub fn complete(&self, ctx: u32, src: u32) {
        self.write32(PLIC_CONTEXT_BASE + ctx as u64 * 0x1000 + CTX_CLAIM, src);
    }

    /// Returns the MMIO base address.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Returns the number of interrupt sources.
    pub fn num_sources(&self) -> usize {
        self.num_sources
    }

    /// Returns the number of contexts.
    pub fn num_contexts(&self) -> usize {
        self.num_contexts
    }

    /// Returns `true` if the PLIC is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // -----------------------------------------------------------------------
    // Private MMIO helpers
    // -----------------------------------------------------------------------

    fn read32(&self, offset: u64) -> u32 {
        let addr = (self.base + offset) as *const u32;
        // SAFETY: offset is within the PLIC MMIO region, volatile read required
        // to prevent compiler from eliding the hardware register access.
        unsafe { core::ptr::read_volatile(addr) }
    }

    fn write32(&self, offset: u64, val: u32) {
        let addr = (self.base + offset) as *mut u32;
        // SAFETY: offset is within the PLIC MMIO region, volatile write ensures
        // the hardware sees the update immediately.
        unsafe { core::ptr::write_volatile(addr, val) }
    }
}

impl Default for RiscvPlic {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

// ---------------------------------------------------------------------------
// Convenience helpers
// ---------------------------------------------------------------------------

/// Returns the context index for a given hart and privilege mode.
///
/// M-mode: context = hart * 2.
/// S-mode: context = hart * 2 + 1.
pub const fn plic_context(hart: u32, smode: bool) -> u32 {
    hart * 2 + if smode { 1 } else { 0 }
}

/// Initializes a PLIC and enables a single source for the given hart's S-mode context.
///
/// # Errors
///
/// Propagates errors from [`RiscvPlic::init`].
pub fn init_plic_source(
    base: u64,
    num_sources: usize,
    num_harts: usize,
    source: u32,
    priority: u32,
) -> Result<RiscvPlic> {
    let mut plic = RiscvPlic::new(base, num_sources, num_harts * 2);
    plic.init()?;
    plic.set_priority(source, priority);
    for hart in 0..num_harts {
        let ctx = plic_context(hart as u32, true);
        plic.enable_source(ctx, source);
    }
    Ok(plic)
}
