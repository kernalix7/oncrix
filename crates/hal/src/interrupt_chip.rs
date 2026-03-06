// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Generic interrupt controller abstraction layer.
//!
//! Provides a platform-agnostic interface for managing hardware interrupt
//! controllers. Concrete controllers (PIC, APIC, GIC) implement the
//! [`IrqChipOps`] trait and are registered as domains via
//! [`InterruptChipSubsystem`].
//!
//! # Architecture
//!
//! ```text
//! Hardware IRQ line
//!       │
//!       ▼
//! IrqDomain  (maps hw_irq → IrqDesc)
//!       │
//!       ▼
//! IrqDesc    (logical IRQ, type, handler index, chip ID)
//!       │
//!       ▼
//! IrqChipOps (enable / disable / ack / eoi / set_type / set_affinity)
//! ```
//!
//! Reference: Linux kernel `include/linux/irq.h` and `kernel/irq/` subsystem.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum IRQ descriptors per domain.
const MAX_IRQS_PER_DOMAIN: usize = 256;

/// Maximum number of IRQ domains managed by the subsystem.
const MAX_DOMAINS: usize = 4;

/// Maximum registered IRQ handler slots.
const MAX_HANDLERS: usize = 256;

/// Sentinel value meaning "no handler assigned".
const NO_HANDLER: u16 = u16::MAX;

// ---------------------------------------------------------------------------
// IrqType
// ---------------------------------------------------------------------------

/// Hardware trigger type for an IRQ line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrqType {
    /// Level-sensitive interrupt (asserted while condition holds).
    Level,
    /// Edge-sensitive interrupt (fires on signal transition).
    Edge,
    /// Both edges trigger an interrupt.
    Both,
}

impl Default for IrqType {
    fn default() -> Self {
        Self::Level
    }
}

// ---------------------------------------------------------------------------
// IrqChipOps
// ---------------------------------------------------------------------------

/// Operations that a concrete interrupt controller chip must provide.
///
/// All methods receive the hardware IRQ number (`hw_irq`) relevant to
/// the chip, which may differ from the kernel-visible logical IRQ number.
pub trait IrqChipOps {
    /// Enable delivery of hardware IRQ `hw_irq`.
    fn enable(&mut self, hw_irq: u32) -> Result<()>;

    /// Disable delivery of hardware IRQ `hw_irq`.
    fn disable(&mut self, hw_irq: u32) -> Result<()>;

    /// Mask (suppress) `hw_irq` at the controller level.
    fn mask(&mut self, hw_irq: u32) -> Result<()>;

    /// Unmask `hw_irq` at the controller level.
    fn unmask(&mut self, hw_irq: u32) -> Result<()>;

    /// Acknowledge an edge-triggered interrupt (before handler runs).
    fn ack(&mut self, hw_irq: u32) -> Result<()>;

    /// Signal end-of-interrupt (after handler has completed).
    fn eoi(&mut self, hw_irq: u32) -> Result<()>;

    /// Configure the trigger type (Level / Edge / Both) for `hw_irq`.
    fn set_type(&mut self, hw_irq: u32, irq_type: IrqType) -> Result<()>;

    /// Set the CPU affinity mask for `hw_irq` (bitmask of target CPUs).
    fn set_affinity(&mut self, hw_irq: u32, cpu_mask: u64) -> Result<()>;
}

// ---------------------------------------------------------------------------
// IrqDesc
// ---------------------------------------------------------------------------

/// Descriptor for a single logical IRQ.
#[derive(Debug, Clone, Copy)]
pub struct IrqDesc {
    /// Logical (kernel-visible) IRQ number.
    pub irq_num: u32,
    /// Hardware IRQ number in the originating chip.
    pub hw_irq: u32,
    /// Identifier of the chip domain that owns this IRQ.
    pub chip_id: u8,
    /// Trigger type of this IRQ.
    pub irq_type: IrqType,
    /// Index into the handler table (`NO_HANDLER` if unregistered).
    pub handler_idx: u16,
    /// Human-readable name (up to 16 bytes, zero-terminated).
    pub name: [u8; 16],
    /// Whether the IRQ is currently enabled at the controller.
    pub enabled: bool,
    /// Whether the IRQ is currently masked.
    pub masked: bool,
}

impl IrqDesc {
    /// Create a new descriptor with default values.
    pub const fn new(irq_num: u32, hw_irq: u32, chip_id: u8) -> Self {
        Self {
            irq_num,
            hw_irq,
            chip_id,
            irq_type: IrqType::Level,
            handler_idx: NO_HANDLER,
            name: [0u8; 16],
            enabled: false,
            masked: true,
        }
    }

    /// Set the descriptor name from a byte slice (truncated to 15 bytes).
    pub fn set_name(&mut self, name: &[u8]) {
        let copy_len = name.len().min(15);
        self.name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.name[copy_len] = 0;
    }

    /// Return whether a handler is registered for this IRQ.
    pub fn has_handler(&self) -> bool {
        self.handler_idx != NO_HANDLER
    }
}

impl Default for IrqDesc {
    fn default() -> Self {
        Self::new(0, 0, 0)
    }
}

// ---------------------------------------------------------------------------
// IrqDomain
// ---------------------------------------------------------------------------

/// An IRQ domain maps hardware IRQ numbers from one controller to
/// logical kernel IRQ numbers.
pub struct IrqDomain {
    /// First logical IRQ number in this domain.
    pub base_irq: u32,
    /// Number of IRQs in this domain.
    pub size: u32,
    /// Domain name (up to 16 bytes, zero-terminated).
    pub name: [u8; 16],
    /// Chip identifier (index into the subsystem's chip table).
    pub chip_id: u8,
    /// Whether this domain slot is in use.
    pub valid: bool,
    /// IRQ descriptors indexed by `hw_irq - base_hw_irq`.
    irq_descs: [IrqDesc; MAX_IRQS_PER_DOMAIN],
    /// Number of IRQs actually mapped in this domain.
    mapped_count: usize,
}

impl IrqDomain {
    /// Create an empty domain.
    pub const fn new() -> Self {
        Self {
            base_irq: 0,
            size: 0,
            name: [0u8; 16],
            chip_id: 0,
            valid: false,
            irq_descs: [const { IrqDesc::new(0, 0, 0) }; MAX_IRQS_PER_DOMAIN],
            mapped_count: 0,
        }
    }

    /// Return the number of IRQs mapped in this domain.
    pub fn mapped_count(&self) -> usize {
        self.mapped_count
    }

    /// Look up an `IrqDesc` by logical IRQ number.
    pub fn find_by_irq(&self, irq_num: u32) -> Option<&IrqDesc> {
        self.irq_descs[..self.mapped_count]
            .iter()
            .find(|d| d.irq_num == irq_num)
    }

    /// Mutable lookup by logical IRQ number.
    fn find_by_irq_mut(&mut self, irq_num: u32) -> Option<&mut IrqDesc> {
        let count = self.mapped_count;
        self.irq_descs[..count]
            .iter_mut()
            .find(|d| d.irq_num == irq_num)
    }

    /// Map a new hardware IRQ to a logical IRQ within this domain.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the domain is full, or
    /// [`Error::AlreadyExists`] if `irq_num` is already mapped.
    fn map_irq(&mut self, irq_num: u32, hw_irq: u32, chip_id: u8) -> Result<()> {
        if self.mapped_count >= MAX_IRQS_PER_DOMAIN {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate logical IRQ.
        if self.find_by_irq(irq_num).is_some() {
            return Err(Error::AlreadyExists);
        }
        let desc = IrqDesc::new(irq_num, hw_irq, chip_id);
        self.irq_descs[self.mapped_count] = desc;
        self.mapped_count += 1;
        Ok(())
    }
}

impl Default for IrqDomain {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// IrqChipStats
// ---------------------------------------------------------------------------

/// Aggregate statistics for the interrupt chip subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct IrqChipStats {
    /// Total IRQs handled (dispatched to a handler).
    pub total_handled: u64,
    /// Spurious interrupts (no descriptor or no handler found).
    pub spurious: u64,
    /// Number of `mask` operations performed.
    pub masked: u64,
    /// Number of `unmask` operations performed.
    pub unmasked: u64,
}

impl IrqChipStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_handled: 0,
            spurious: 0,
            masked: 0,
            unmasked: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Handler table entry
// ---------------------------------------------------------------------------

/// A registered IRQ handler function pointer.
type IrqHandlerFn = fn(irq_num: u32);

/// Entry in the handler table.
#[derive(Clone, Copy)]
struct HandlerEntry {
    handler: IrqHandlerFn,
    valid: bool,
}

impl HandlerEntry {
    const fn new() -> Self {
        Self {
            handler: default_handler,
            valid: false,
        }
    }
}

/// Default no-op handler used to fill uninitialised slots.
fn default_handler(_irq: u32) {}

// ---------------------------------------------------------------------------
// InterruptChipSubsystem
// ---------------------------------------------------------------------------

/// Manages multiple IRQ domains and dispatches interrupts to handlers.
pub struct InterruptChipSubsystem {
    domains: [IrqDomain; MAX_DOMAINS],
    domain_count: usize,
    handlers: [HandlerEntry; MAX_HANDLERS],
    stats: IrqChipStats,
}

impl InterruptChipSubsystem {
    /// Create an empty subsystem.
    pub const fn new() -> Self {
        Self {
            domains: [const { IrqDomain::new() }; MAX_DOMAINS],
            domain_count: 0,
            handlers: [const { HandlerEntry::new() }; MAX_HANDLERS],
            stats: IrqChipStats::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Domain management
    // -----------------------------------------------------------------------

    /// Register a new IRQ domain.
    ///
    /// Returns the domain ID (index) on success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the maximum domain count is reached,
    /// or [`Error::InvalidArgument`] if `size` is zero.
    pub fn register_domain(
        &mut self,
        base_irq: u32,
        size: u32,
        chip_id: u8,
        name: &[u8],
    ) -> Result<usize> {
        if self.domain_count >= MAX_DOMAINS {
            return Err(Error::OutOfMemory);
        }
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        let id = self.domain_count;
        self.domains[id].base_irq = base_irq;
        self.domains[id].size = size;
        self.domains[id].chip_id = chip_id;
        self.domains[id].valid = true;
        let copy_len = name.len().min(15);
        self.domains[id].name[..copy_len].copy_from_slice(&name[..copy_len]);
        self.domains[id].name[copy_len] = 0;
        self.domain_count += 1;
        Ok(id)
    }

    /// Map a hardware IRQ to a logical IRQ within a domain.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `domain_id` is out of range or
    /// the domain is not valid. Propagates errors from the domain map operation.
    pub fn map_irq(&mut self, domain_id: usize, irq_num: u32, hw_irq: u32) -> Result<()> {
        if domain_id >= self.domain_count || !self.domains[domain_id].valid {
            return Err(Error::InvalidArgument);
        }
        let chip_id = self.domains[domain_id].chip_id;
        self.domains[domain_id].map_irq(irq_num, hw_irq, chip_id)
    }

    // -----------------------------------------------------------------------
    // Handler registration
    // -----------------------------------------------------------------------

    /// Register a handler function for a logical IRQ.
    ///
    /// Associates `handler` with `irq_num` by writing its index into the
    /// matching `IrqDesc` in any registered domain.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `irq_num` is not mapped in any domain,
    /// or [`Error::OutOfMemory`] if the handler table is full.
    pub fn request_irq(&mut self, irq_num: u32, handler: IrqHandlerFn) -> Result<()> {
        // Find a free handler slot.
        let handler_idx = self
            .handlers
            .iter()
            .position(|h| !h.valid)
            .ok_or(Error::OutOfMemory)?;

        // Find the IRQ descriptor in all domains.
        let domain_idx = (0..self.domain_count)
            .find(|&d| self.domains[d].find_by_irq(irq_num).is_some())
            .ok_or(Error::NotFound)?;

        // Write the handler index into the descriptor — borrow ends after this block.
        {
            let desc = self.domains[domain_idx]
                .find_by_irq_mut(irq_num)
                .ok_or(Error::NotFound)?;
            desc.handler_idx = handler_idx as u16;
        }

        // Store the handler (borrow of self.handlers, separate from self.domains).
        self.handlers[handler_idx] = HandlerEntry {
            handler,
            valid: true,
        };

        Ok(())
    }

    /// Unregister the handler for a logical IRQ.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `irq_num` is not mapped.
    pub fn free_irq(&mut self, irq_num: u32) -> Result<()> {
        let domain_idx = (0..self.domain_count)
            .find(|&d| self.domains[d].find_by_irq(irq_num).is_some())
            .ok_or(Error::NotFound)?;

        // Extract the handler index and clear it; borrow ends after this block.
        let handler_idx = {
            let desc = self.domains[domain_idx]
                .find_by_irq_mut(irq_num)
                .ok_or(Error::NotFound)?;
            let idx = desc.handler_idx;
            desc.handler_idx = NO_HANDLER;
            idx
        };

        if (handler_idx as usize) < MAX_HANDLERS {
            self.handlers[handler_idx as usize].valid = false;
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Interrupt dispatch
    // -----------------------------------------------------------------------

    /// Handle an interrupt for logical IRQ `irq_num`.
    ///
    /// Looks up the descriptor, calls the registered handler, and updates
    /// statistics. Spurious interrupts (no handler) are counted but do not
    /// return an error.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `irq_num` does not exist in any domain.
    pub fn handle_irq(&mut self, irq_num: u32) -> Result<()> {
        // Find which domain owns this IRQ.
        let domain_idx = (0..self.domain_count)
            .find(|&d| self.domains[d].find_by_irq(irq_num).is_some())
            .ok_or(Error::NotFound)?;

        // Extract handler_idx; immutable borrow ends at end of this block.
        let handler_idx = self.domains[domain_idx]
            .find_by_irq(irq_num)
            .ok_or(Error::NotFound)?
            .handler_idx;

        if handler_idx == NO_HANDLER || (handler_idx as usize) >= MAX_HANDLERS {
            self.stats.spurious = self.stats.spurious.saturating_add(1);
            return Ok(());
        }

        let handler_entry = self.handlers[handler_idx as usize];
        if !handler_entry.valid {
            self.stats.spurious = self.stats.spurious.saturating_add(1);
            return Ok(());
        }

        (handler_entry.handler)(irq_num);
        self.stats.total_handled = self.stats.total_handled.saturating_add(1);

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Chip operations forwarding
    // -----------------------------------------------------------------------

    /// Return the hardware IRQ number for a given logical IRQ.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `irq_num` is not mapped.
    pub fn hw_irq_for(&self, irq_num: u32) -> Result<u32> {
        for d in 0..self.domain_count {
            if let Some(desc) = self.domains[d].find_by_irq(irq_num) {
                return Ok(desc.hw_irq);
            }
        }
        Err(Error::NotFound)
    }

    /// Mark a logical IRQ as masked in its descriptor (bookkeeping only).
    ///
    /// Callers are responsible for issuing the actual chip `mask` call.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `irq_num` is not mapped.
    pub fn mark_masked(&mut self, irq_num: u32) -> Result<()> {
        let domain_idx = (0..self.domain_count)
            .find(|&d| self.domains[d].find_by_irq(irq_num).is_some())
            .ok_or(Error::NotFound)?;
        self.domains[domain_idx]
            .find_by_irq_mut(irq_num)
            .ok_or(Error::NotFound)?
            .masked = true;
        self.stats.masked = self.stats.masked.saturating_add(1);
        Ok(())
    }

    /// Mark a logical IRQ as unmasked in its descriptor (bookkeeping only).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `irq_num` is not mapped.
    pub fn mark_unmasked(&mut self, irq_num: u32) -> Result<()> {
        let domain_idx = (0..self.domain_count)
            .find(|&d| self.domains[d].find_by_irq(irq_num).is_some())
            .ok_or(Error::NotFound)?;
        self.domains[domain_idx]
            .find_by_irq_mut(irq_num)
            .ok_or(Error::NotFound)?
            .masked = false;
        self.stats.unmasked = self.stats.unmasked.saturating_add(1);
        Ok(())
    }

    /// Mark a logical IRQ as enabled in its descriptor (bookkeeping only).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `irq_num` is not mapped.
    pub fn mark_enabled(&mut self, irq_num: u32, enabled: bool) -> Result<()> {
        let domain_idx = (0..self.domain_count)
            .find(|&d| self.domains[d].find_by_irq(irq_num).is_some())
            .ok_or(Error::NotFound)?;
        self.domains[domain_idx]
            .find_by_irq_mut(irq_num)
            .ok_or(Error::NotFound)?
            .enabled = enabled;
        Ok(())
    }

    /// Return a snapshot of the aggregate statistics.
    pub fn stats(&self) -> IrqChipStats {
        self.stats
    }

    /// Return the number of registered domains.
    pub fn domain_count(&self) -> usize {
        self.domain_count
    }

    /// Return a reference to a domain by ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `domain_id` is out of range.
    pub fn domain(&self, domain_id: usize) -> Result<&IrqDomain> {
        if domain_id >= self.domain_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.domains[domain_id])
    }
}

impl Default for InterruptChipSubsystem {
    fn default() -> Self {
        Self::new()
    }
}
