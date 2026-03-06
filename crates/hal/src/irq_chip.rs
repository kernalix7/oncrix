// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IRQ chip abstraction layer.
//!
//! Defines the [`IrqChip`] trait for interrupt controller hardware
//! backends and the [`IrqDesc`] interrupt descriptor that binds a
//! hardware IRQ to a chip + handler. This enables chained interrupt
//! handling for complex hierarchies (e.g., GPIO expanders hanging off
//! an I/O APIC line).
//!
//! # Hierarchy
//!
//! ```text
//! CPU ← APIC ← I/O APIC ← GPIO controller ← GPIO pin interrupt
//! ```
//!
//! Each level is an [`IrqChip`]. The GPIO chip's parent chip is the
//! I/O APIC chip. When the GPIO chip's parent IRQ fires, it reads
//! its interrupt status register and calls the appropriate handler
//! for the triggering pin.
//!
//! Reference: Linux kernel irqchip framework (Documentation/core-api/irq/)

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of IRQs in the descriptor table.
const MAX_IRQS: usize = 256;

/// Maximum IRQ chip name length.
const CHIP_NAME_LEN: usize = 24;

/// IRQ flags: edge-triggered.
pub const IRQ_TYPE_EDGE_RISING: u32 = 0x0001;
/// IRQ flags: edge-triggered falling.
pub const IRQ_TYPE_EDGE_FALLING: u32 = 0x0002;
/// IRQ flags: both edges.
pub const IRQ_TYPE_EDGE_BOTH: u32 = IRQ_TYPE_EDGE_RISING | IRQ_TYPE_EDGE_FALLING;
/// IRQ flags: level high.
pub const IRQ_TYPE_LEVEL_HIGH: u32 = 0x0004;
/// IRQ flags: level low.
pub const IRQ_TYPE_LEVEL_LOW: u32 = 0x0008;
/// IRQ flag: shared (multiple handlers on same IRQ line).
pub const IRQ_FLAG_SHARED: u32 = 0x0080;
/// IRQ flag: disabled.
pub const IRQ_FLAG_DISABLED: u32 = 0x0100;
/// IRQ flag: no auto-enable after request.
pub const IRQ_FLAG_NOAUTOEN: u32 = 0x0200;

// ── IrqReturn ────────────────────────────────────────────────────────────────

/// Return value from an interrupt handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrqReturn {
    /// The handler did not service this interrupt (for shared IRQs).
    None,
    /// The interrupt was handled successfully.
    Handled,
    /// The handler requests the kernel to wake a thread handler.
    WakeThread,
}

// ── IrqTrigger ───────────────────────────────────────────────────────────────

/// Interrupt trigger type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrqTrigger {
    /// Edge-triggered on rising edge.
    EdgeRising,
    /// Edge-triggered on falling edge.
    EdgeFalling,
    /// Edge-triggered on both edges.
    EdgeBoth,
    /// Level-triggered, active high.
    LevelHigh,
    /// Level-triggered, active low.
    LevelLow,
}

impl IrqTrigger {
    /// Convert from IRQ type flags.
    pub fn from_flags(flags: u32) -> Option<Self> {
        match flags & 0x0F {
            x if x == IRQ_TYPE_EDGE_RISING => Some(Self::EdgeRising),
            x if x == IRQ_TYPE_EDGE_FALLING => Some(Self::EdgeFalling),
            x if x == IRQ_TYPE_EDGE_BOTH => Some(Self::EdgeBoth),
            x if x == IRQ_TYPE_LEVEL_HIGH => Some(Self::LevelHigh),
            x if x == IRQ_TYPE_LEVEL_LOW => Some(Self::LevelLow),
            _ => None,
        }
    }

    /// Convert to IRQ type flags.
    pub fn to_flags(self) -> u32 {
        match self {
            Self::EdgeRising => IRQ_TYPE_EDGE_RISING,
            Self::EdgeFalling => IRQ_TYPE_EDGE_FALLING,
            Self::EdgeBoth => IRQ_TYPE_EDGE_BOTH,
            Self::LevelHigh => IRQ_TYPE_LEVEL_HIGH,
            Self::LevelLow => IRQ_TYPE_LEVEL_LOW,
        }
    }

    /// Return whether this is an edge-triggered interrupt.
    pub fn is_edge(self) -> bool {
        matches!(self, Self::EdgeRising | Self::EdgeFalling | Self::EdgeBoth)
    }
}

// ── IrqChip trait ────────────────────────────────────────────────────────────

/// Hardware IRQ chip interface.
///
/// Implemented by each interrupt controller (APIC, I/O APIC, GPIO
/// expander, etc.). The kernel calls these methods from interrupt
/// context to manage individual IRQ lines.
pub trait IrqChip {
    /// Return the chip name for diagnostics.
    fn name(&self) -> &str;

    /// Acknowledge an interrupt after it fires (needed for edge-triggered).
    ///
    /// For level-triggered IRQs this is typically a no-op (unmask instead).
    fn ack(&self, hwirq: u32);

    /// Mask (disable) the specified hardware IRQ line.
    fn mask(&self, hwirq: u32);

    /// Unmask (enable) the specified hardware IRQ line.
    fn unmask(&self, hwirq: u32);

    /// Set the trigger type for the given hardware IRQ.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the trigger type is not
    /// supported by this chip.
    fn set_type(&self, hwirq: u32, trigger: IrqTrigger) -> Result<()>;

    /// Enable the hardware IRQ line (unmask + arm for first use).
    ///
    /// Default: calls `unmask`.
    fn enable(&self, hwirq: u32) {
        self.unmask(hwirq);
    }

    /// Disable the hardware IRQ line.
    ///
    /// Default: calls `mask`.
    fn disable(&self, hwirq: u32) {
        self.mask(hwirq);
    }

    /// Optional: set CPU affinity for the IRQ.
    ///
    /// Default: no-op (not all chips support this).
    fn set_affinity(&self, _hwirq: u32, _cpu_mask: u64) -> Result<()> {
        Err(Error::NotImplemented)
    }

    /// Optional: handle a chained interrupt (called by parent chip handler).
    ///
    /// For GPIO expanders: reads status, dispatches to child handlers.
    fn handle_chained_irq(&self, _hwirq: u32) {}
}

// ── IrqHandler ───────────────────────────────────────────────────────────────

/// Interrupt handler function signature.
pub type IrqHandler = fn(irq: u32, data: usize) -> IrqReturn;

// ── IrqDesc ──────────────────────────────────────────────────────────────────

/// An interrupt descriptor binding a hardware IRQ to a chip and handler.
#[derive(Clone, Copy)]
pub struct IrqDesc {
    /// Global Linux-style IRQ number (virtual).
    pub irq: u32,
    /// Hardware IRQ number within the parent chip.
    pub hwirq: u32,
    /// IRQ trigger type flags.
    pub trigger_flags: u32,
    /// IRQ state flags (DISABLED, SHARED, etc.).
    pub state_flags: u32,
    /// Optional handler function.
    pub handler: Option<IrqHandler>,
    /// Per-handler data (e.g., pointer to device struct as usize).
    pub handler_data: usize,
    /// Interrupt count for diagnostics.
    pub count: u64,
    /// Spurious count (handler returned None).
    pub spurious_count: u64,
    /// Whether this descriptor is occupied.
    pub valid: bool,
    /// IRQ name for /proc/interrupts equivalent.
    pub name: [u8; CHIP_NAME_LEN],
    pub name_len: usize,
}

impl IrqDesc {
    /// Create a new IRQ descriptor.
    pub fn new(
        irq: u32,
        hwirq: u32,
        trigger_flags: u32,
        name: &[u8],
        handler: Option<IrqHandler>,
        handler_data: usize,
    ) -> Self {
        let mut name_buf = [0u8; CHIP_NAME_LEN];
        let len = name.len().min(CHIP_NAME_LEN);
        name_buf[..len].copy_from_slice(&name[..len]);
        Self {
            irq,
            hwirq,
            trigger_flags,
            state_flags: 0,
            handler,
            handler_data,
            count: 0,
            spurious_count: 0,
            valid: true,
            name: name_buf,
            name_len: len,
        }
    }

    /// Return whether this IRQ is currently masked.
    pub fn is_disabled(&self) -> bool {
        self.state_flags & IRQ_FLAG_DISABLED != 0
    }

    /// Return the name as bytes.
    pub fn name_str(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Dispatch the interrupt handler and update statistics.
    pub fn dispatch(&mut self) -> IrqReturn {
        let ret = match self.handler {
            Some(h) => h(self.irq, self.handler_data),
            None => IrqReturn::None,
        };
        self.count = self.count.saturating_add(1);
        if ret == IrqReturn::None {
            self.spurious_count = self.spurious_count.saturating_add(1);
        }
        ret
    }
}

// ── SimpleIrqChip ─────────────────────────────────────────────────────────────

/// A simple no-op IRQ chip for platform devices that manage their own
/// interrupt acknowledgement (e.g., MMIO-based GPIO controllers).
pub struct SimpleIrqChip {
    /// Chip name.
    name_buf: [u8; CHIP_NAME_LEN],
    name_len: usize,
    /// MMIO base of the interrupt controller.
    base: u64,
    /// Mask register offset.
    mask_offset: u32,
    /// Clear/ACK register offset.
    ack_offset: u32,
    /// Number of IRQ lines managed.
    num_irqs: u32,
}

impl SimpleIrqChip {
    /// Create a new simple IRQ chip.
    pub fn new(name: &[u8], base: u64, mask_offset: u32, ack_offset: u32, num_irqs: u32) -> Self {
        let mut name_buf = [0u8; CHIP_NAME_LEN];
        let len = name.len().min(CHIP_NAME_LEN);
        name_buf[..len].copy_from_slice(&name[..len]);
        Self {
            name_buf,
            name_len: len,
            base,
            mask_offset,
            ack_offset,
            num_irqs,
        }
    }

    fn read32(&self, offset: u32) -> u32 {
        // SAFETY: MMIO register access within mapped controller region.
        unsafe { core::ptr::read_volatile((self.base + offset as u64) as *const u32) }
    }

    fn write32(&self, offset: u32, value: u32) {
        // SAFETY: MMIO register access within mapped controller region.
        unsafe { core::ptr::write_volatile((self.base + offset as u64) as *mut u32, value) }
    }
}

impl IrqChip for SimpleIrqChip {
    fn name(&self) -> &str {
        // SAFETY: name_buf is filled with valid ASCII from new().
        core::str::from_utf8(&self.name_buf[..self.name_len]).unwrap_or("unknown")
    }

    fn ack(&self, hwirq: u32) {
        if hwirq < self.num_irqs {
            self.write32(self.ack_offset, 1 << hwirq);
        }
    }

    fn mask(&self, hwirq: u32) {
        if hwirq < self.num_irqs {
            let cur = self.read32(self.mask_offset);
            self.write32(self.mask_offset, cur | (1 << hwirq));
        }
    }

    fn unmask(&self, hwirq: u32) {
        if hwirq < self.num_irqs {
            let cur = self.read32(self.mask_offset);
            self.write32(self.mask_offset, cur & !(1 << hwirq));
        }
    }

    fn set_type(&self, hwirq: u32, _trigger: IrqTrigger) -> Result<()> {
        if hwirq >= self.num_irqs {
            return Err(Error::InvalidArgument);
        }
        // Simple chips typically support only one trigger type.
        Ok(())
    }
}

// ── IrqDomain ────────────────────────────────────────────────────────────────

/// IRQ domain: maps hardware IRQ numbers to global IRQ descriptors.
///
/// Tracks the mapping between the chip's hardware IRQ space and the
/// global virtual IRQ number space used by the descriptor table.
pub struct IrqDomain {
    /// Base global IRQ number for this domain.
    pub irq_base: u32,
    /// Number of IRQs in this domain.
    pub size: u32,
    /// Hardware IRQ base (offset from chip's IRQ 0).
    pub hwirq_base: u32,
    /// Domain name.
    pub name: [u8; CHIP_NAME_LEN],
    pub name_len: usize,
}

impl IrqDomain {
    /// Create a new IRQ domain.
    pub fn new(name: &[u8], irq_base: u32, hwirq_base: u32, size: u32) -> Self {
        let mut name_buf = [0u8; CHIP_NAME_LEN];
        let len = name.len().min(CHIP_NAME_LEN);
        name_buf[..len].copy_from_slice(&name[..len]);
        Self {
            irq_base,
            size,
            hwirq_base,
            name: name_buf,
            name_len: len,
        }
    }

    /// Translate a hardware IRQ to a global IRQ number.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `hwirq` is out of range.
    pub fn hwirq_to_irq(&self, hwirq: u32) -> Result<u32> {
        if hwirq < self.hwirq_base || hwirq >= self.hwirq_base + self.size {
            return Err(Error::InvalidArgument);
        }
        Ok(self.irq_base + (hwirq - self.hwirq_base))
    }

    /// Translate a global IRQ number to a hardware IRQ.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `irq` is out of range.
    pub fn irq_to_hwirq(&self, irq: u32) -> Result<u32> {
        if irq < self.irq_base || irq >= self.irq_base + self.size {
            return Err(Error::InvalidArgument);
        }
        Ok(self.hwirq_base + (irq - self.irq_base))
    }

    /// Return whether the given global IRQ belongs to this domain.
    pub fn contains_irq(&self, irq: u32) -> bool {
        irq >= self.irq_base && irq < self.irq_base + self.size
    }
}

// ── IrqTable ─────────────────────────────────────────────────────────────────

/// Global IRQ descriptor table.
pub struct IrqTable {
    /// IRQ descriptors indexed by global IRQ number.
    descs: [Option<IrqDesc>; MAX_IRQS],
    /// Number of registered IRQs.
    count: u32,
}

impl IrqTable {
    /// Create an empty IRQ table.
    pub const fn new() -> Self {
        Self {
            descs: [const { None }; MAX_IRQS],
            count: 0,
        }
    }

    /// Register an IRQ descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::AlreadyExists`] if the IRQ is already registered,
    /// or [`Error::InvalidArgument`] if `irq >= MAX_IRQS`.
    pub fn register(&mut self, desc: IrqDesc) -> Result<()> {
        let irq = desc.irq as usize;
        if irq >= MAX_IRQS {
            return Err(Error::InvalidArgument);
        }
        if self.descs[irq].is_some() {
            return Err(Error::AlreadyExists);
        }
        self.descs[irq] = Some(desc);
        self.count += 1;
        Ok(())
    }

    /// Unregister an IRQ descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the IRQ is not registered.
    pub fn unregister(&mut self, irq: u32) -> Result<()> {
        let irq_idx = irq as usize;
        if irq_idx >= MAX_IRQS || self.descs[irq_idx].is_none() {
            return Err(Error::NotFound);
        }
        self.descs[irq_idx] = None;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Dispatch an interrupt by global IRQ number.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the IRQ has no descriptor.
    pub fn dispatch(&mut self, irq: u32) -> Result<IrqReturn> {
        let irq_idx = irq as usize;
        let desc = self
            .descs
            .get_mut(irq_idx)
            .and_then(|d| d.as_mut())
            .ok_or(Error::NotFound)?;
        Ok(desc.dispatch())
    }

    /// Return a reference to an IRQ descriptor.
    pub fn get(&self, irq: u32) -> Option<&IrqDesc> {
        self.descs.get(irq as usize)?.as_ref()
    }

    /// Return the number of registered IRQs.
    pub fn count(&self) -> u32 {
        self.count
    }
}

impl Default for IrqTable {
    fn default() -> Self {
        Self::new()
    }
}
