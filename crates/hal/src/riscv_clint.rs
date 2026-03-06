// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! RISC-V Core Local Interruptor (CLINT) timer and IPI driver.
//!
//! The CLINT provides per-hart machine timer (MTIMER) and machine software
//! interrupt (MSIP) functionality. It is specified in the SiFive E31/E51
//! CoreIP manuals and widely adopted in RISC-V SoCs.
//!
//! # CLINT Memory Map (base = CLINT_BASE)
//!
//! | Offset            | Description                        |
//! |-------------------|------------------------------------|
//! | 0x0000 + 4*hart   | MSIP register for hart (4 bytes)   |
//! | 0x4000 + 8*hart   | MTIMECMP for hart (8 bytes)        |
//! | 0xBFF8            | MTIME (shared 64-bit counter)      |
//!
//! Writing 1 to MSIP[hart] sends a machine software interrupt (IPI) to
//! that hart. Writing 0 clears it.
//!
//! The MTIMER fires a machine timer interrupt (MTI) when MTIME >= MTIMECMP.
//!
//! Reference: SiFive E31/E51 CoreIP Manual, RISC-V Privileged ISA Spec.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of CLINT instances.
pub const MAX_CLINT_INSTANCES: usize = 2;
/// Maximum number of harts supported by a single CLINT.
pub const CLINT_MAX_HARTS: usize = 4095;

// ---------------------------------------------------------------------------
// CLINT Register Offsets
// ---------------------------------------------------------------------------

/// MSIP registers base (4 bytes per hart).
const CLINT_MSIP_BASE: u64 = 0x0000;
/// MTIMECMP registers base (8 bytes per hart).
const CLINT_MTIMECMP_BASE: u64 = 0x4000;
/// MTIME counter register (shared, 8 bytes).
const CLINT_MTIME: u64 = 0xBFF8;

// ---------------------------------------------------------------------------
// CLINT instance
// ---------------------------------------------------------------------------

/// RISC-V CLINT hardware instance.
pub struct RiscvClint {
    /// MMIO base address.
    base: u64,
    /// Number of harts this CLINT serves.
    num_harts: usize,
    /// Whether this CLINT is initialized.
    initialized: bool,
}

impl RiscvClint {
    /// Creates a new CLINT instance.
    pub const fn new(base: u64, num_harts: usize) -> Self {
        let nh = if num_harts > CLINT_MAX_HARTS {
            CLINT_MAX_HARTS
        } else {
            num_harts
        };
        Self {
            base,
            num_harts: nh,
            initialized: false,
        }
    }

    /// Initializes the CLINT.
    ///
    /// Clears all MSIP bits (no pending IPIs) and sets MTIMECMP to
    /// `u64::MAX` for all harts (timer disabled).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the base address is zero.
    pub fn init(&mut self) -> Result<()> {
        if self.base == 0 {
            return Err(Error::InvalidArgument);
        }
        // Clear all MSIP bits.
        for hart in 0..self.num_harts {
            self.clear_msip(hart as u32);
        }
        // Disable all timers.
        for hart in 0..self.num_harts {
            self.write_mtimecmp(hart as u32, u64::MAX);
        }
        self.initialized = true;
        Ok(())
    }

    /// Reads the global MTIME counter.
    pub fn read_mtime(&self) -> u64 {
        self.read64(CLINT_MTIME)
    }

    /// Reads the MTIMECMP value for a given hart.
    pub fn read_mtimecmp(&self, hart: u32) -> u64 {
        let offset = CLINT_MTIMECMP_BASE + hart as u64 * 8;
        self.read64(offset)
    }

    /// Writes a new MTIMECMP value for a given hart.
    ///
    /// The timer interrupt fires when `MTIME >= MTIMECMP`.
    /// Set to `u64::MAX` to disable.
    pub fn write_mtimecmp(&self, hart: u32, cmp: u64) {
        let offset = CLINT_MTIMECMP_BASE + hart as u64 * 8;
        // Write low word first to avoid spurious interrupts on 32-bit access.
        self.write32(offset, 0xFFFF_FFFF);
        self.write32(offset + 4, (cmp >> 32) as u32);
        self.write32(offset, (cmp & 0xFFFF_FFFF) as u32);
    }

    /// Programs the timer to fire after `delay_ticks` ticks from now.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `hart >= num_harts`.
    pub fn set_timer_delay(&self, hart: u32, delay_ticks: u64) -> Result<()> {
        if hart as usize >= self.num_harts {
            return Err(Error::InvalidArgument);
        }
        let now = self.read_mtime();
        let cmp = now.saturating_add(delay_ticks);
        self.write_mtimecmp(hart, cmp);
        Ok(())
    }

    /// Disables the timer for a given hart (sets MTIMECMP = u64::MAX).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `hart >= num_harts`.
    pub fn disable_timer(&self, hart: u32) -> Result<()> {
        if hart as usize >= self.num_harts {
            return Err(Error::InvalidArgument);
        }
        self.write_mtimecmp(hart, u64::MAX);
        Ok(())
    }

    /// Sends an inter-processor interrupt (IPI) to `hart` via MSIP.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `hart >= num_harts`.
    pub fn send_ipi(&self, hart: u32) -> Result<()> {
        if hart as usize >= self.num_harts {
            return Err(Error::InvalidArgument);
        }
        self.write32(CLINT_MSIP_BASE + hart as u64 * 4, 1);
        Ok(())
    }

    /// Clears the MSIP (software interrupt) for a given hart.
    pub fn clear_msip(&self, hart: u32) {
        self.write32(CLINT_MSIP_BASE + hart as u64 * 4, 0);
    }

    /// Returns `true` if a software interrupt is pending for `hart`.
    pub fn is_msip_pending(&self, hart: u32) -> bool {
        self.read32(CLINT_MSIP_BASE + hart as u64 * 4) & 1 != 0
    }

    /// Returns the MMIO base address.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// Returns the number of harts.
    pub fn num_harts(&self) -> usize {
        self.num_harts
    }

    /// Returns `true` if the CLINT is initialized.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    // -----------------------------------------------------------------------
    // Private MMIO helpers
    // -----------------------------------------------------------------------

    fn read32(&self, offset: u64) -> u32 {
        let addr = (self.base + offset) as *const u32;
        // SAFETY: offset is within the CLINT MMIO region, volatile read prevents
        // compiler from reordering or eliding the hardware register access.
        unsafe { core::ptr::read_volatile(addr) }
    }

    fn write32(&self, offset: u64, val: u32) {
        let addr = (self.base + offset) as *mut u32;
        // SAFETY: offset is within the CLINT MMIO region, volatile write ensures
        // the hardware sees the update immediately.
        unsafe { core::ptr::write_volatile(addr, val) }
    }

    fn read64(&self, offset: u64) -> u64 {
        // Read as two 32-bit words to avoid issues on 32-bit implementations.
        let lo = self.read32(offset) as u64;
        let hi = self.read32(offset + 4) as u64;
        lo | (hi << 32)
    }
}

impl Default for RiscvClint {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

// ---------------------------------------------------------------------------
// Convenience helpers
// ---------------------------------------------------------------------------

/// Initializes a CLINT instance with the given base and number of harts.
///
/// # Errors
///
/// Propagates errors from [`RiscvClint::init`].
pub fn init_clint(base: u64, num_harts: usize) -> Result<RiscvClint> {
    let mut clint = RiscvClint::new(base, num_harts);
    clint.init()?;
    Ok(clint)
}

/// Global CLINT registry.
pub struct ClintRegistry {
    instances: [RiscvClint; MAX_CLINT_INSTANCES],
    count: usize,
}

impl ClintRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            instances: [const { RiscvClint::new(0, 0) }; MAX_CLINT_INSTANCES],
            count: 0,
        }
    }

    /// Registers a CLINT instance.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, base: u64, num_harts: usize) -> Result<usize> {
        if self.count >= MAX_CLINT_INSTANCES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.instances[idx] = RiscvClint::new(base, num_harts);
        self.count += 1;
        Ok(idx)
    }

    /// Returns a reference to the instance at `index`.
    pub fn get(&self, index: usize) -> Option<&RiscvClint> {
        if index < self.count {
            Some(&self.instances[index])
        } else {
            None
        }
    }

    /// Returns a mutable reference to the instance at `index`.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut RiscvClint> {
        if index < self.count {
            Some(&mut self.instances[index])
        } else {
            None
        }
    }

    /// Returns the number of registered instances.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no instances are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for ClintRegistry {
    fn default() -> Self {
        Self::new()
    }
}
