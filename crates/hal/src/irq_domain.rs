// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IRQ domain mapping subsystem.
//!
//! An IRQ domain translates hardware interrupt specifiers (HW IRQ numbers)
//! into Linux-style virtual IRQ numbers (virqs) that the kernel can use
//! uniformly regardless of the underlying interrupt controller topology.
//! This mirrors the Linux `irqdomain` framework described in
//! `Documentation/core-api/irq/irq-domain.rst`.
//!
//! # Concepts
//!
//! - **HW IRQ** — the interrupt number as the hardware controller sees it
//!   (e.g., APIC vector, GSI, MSI data value).
//! - **virq** — virtual IRQ number allocated by this domain; used by
//!   kernel subsystems and device drivers.
//! - **IRQ domain** — maps a contiguous or sparse set of HW IRQs to virqs.
//! - **IRQ domain operations** — per-domain callbacks for activating,
//!   deactivating, masking and unmasking hardware interrupts.
//!
//! # Domain Types
//!
//! | Type       | Description                                     |
//! |------------|-------------------------------------------------|
//! | Linear     | Direct-mapped array (HW → virq), fast O(1)     |
//! | Tree       | Radix-tree style sparse mapping                |
//! | Legacy     | Fixed 1:1 mapping for ISA/legacy IRQs (0..15)  |
//! | Hierarchy  | Domain stacking (e.g., MSI → IOAPIC → APIC)    |
//!
//! # Usage
//!
//! ```ignore
//! let mut domain = IrqDomain::new_linear("i8042", 16, &PS2_OPS);
//! domain.create_mapping(1, 1)?;   // HW IRQ 1 → virq 1
//! let virq = domain.virq_of(1)?;
//! ```
//!
//! Reference: Linux kernel `include/linux/irqdomain.h`,
//! `kernel/irq/irqdomain.c`.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of IRQ domains in the system.
pub const MAX_DOMAINS: usize = 32;

/// Maximum virqs tracked per domain (for linear domains).
pub const MAX_VIRQS_PER_DOMAIN: usize = 256;

/// Maximum total virq allocations across all domains.
pub const MAX_VIRQS_TOTAL: usize = 1024;

/// Invalid / unallocated virq sentinel.
pub const VIRQ_INVALID: u32 = u32::MAX;

/// First virq number available for allocation.
const VIRQ_BASE: u32 = 1;

// ---------------------------------------------------------------------------
// IRQ trigger and polarity
// ---------------------------------------------------------------------------

/// IRQ trigger type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TriggerType {
    /// Rising-edge triggered.
    #[default]
    EdgeRising,
    /// Falling-edge triggered.
    EdgeFalling,
    /// Both edges triggered.
    EdgeBoth,
    /// Active-high level triggered.
    LevelHigh,
    /// Active-low level triggered.
    LevelLow,
}

/// IRQ flow type combining trigger mode and level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IrqFlowType {
    /// Trigger mode for this IRQ.
    pub trigger: TriggerType,
    /// Whether the interrupt is shared among multiple devices.
    pub shared: bool,
    /// Whether this interrupt requires an EOI sequence.
    pub needs_eoi: bool,
}

// ---------------------------------------------------------------------------
// IRQ descriptor
// ---------------------------------------------------------------------------

/// Per-virq descriptor maintained by the domain subsystem.
#[derive(Debug, Clone, Copy)]
pub struct IrqDesc {
    /// Virtual IRQ number.
    pub virq: u32,
    /// Hardware IRQ number in the owning domain.
    pub hwirq: u32,
    /// Flow type configuration.
    pub flow: IrqFlowType,
    /// IRQ is currently active (enabled at hardware level).
    pub active: bool,
    /// IRQ is masked (temporarily disabled).
    pub masked: bool,
    /// Domain index that owns this virq.
    pub domain_idx: usize,
    /// Name tag for debugging.
    pub name: [u8; 16],
}

impl IrqDesc {
    /// Creates a new `IrqDesc` for a virq/hwirq pair in the given domain.
    pub const fn new(virq: u32, hwirq: u32, domain_idx: usize) -> Self {
        Self {
            virq,
            hwirq,
            flow: IrqFlowType {
                trigger: TriggerType::EdgeRising,
                shared: false,
                needs_eoi: false,
            },
            active: false,
            masked: false,
            domain_idx,
            name: [0u8; 16],
        }
    }

    /// Sets the 15-character (max) name for this IRQ descriptor.
    pub fn set_name(&mut self, s: &[u8]) {
        let len = s.len().min(15);
        self.name[..len].copy_from_slice(&s[..len]);
        self.name[len] = 0;
    }
}

// ---------------------------------------------------------------------------
// Domain operations trait
// ---------------------------------------------------------------------------

/// Callbacks that each IRQ domain implementation must provide.
pub trait IrqDomainOps {
    /// Translates a HW IRQ specifier into a virq flow configuration.
    ///
    /// Called when a new mapping is created. The implementation should
    /// configure the hardware IRQ and return the appropriate flow type.
    fn map(&self, hwirq: u32, virq: u32) -> Result<IrqFlowType>;

    /// Unmaps a previously mapped HW IRQ / virq pair.
    fn unmap(&self, hwirq: u32, virq: u32);

    /// Activates (unmasks) a HW IRQ.
    fn activate(&self, hwirq: u32) -> Result<()>;

    /// Deactivates (masks) a HW IRQ.
    fn deactivate(&self, hwirq: u32);

    /// Sends end-of-interrupt to the hardware.
    fn eoi(&self, hwirq: u32);
}

// ---------------------------------------------------------------------------
// No-op domain operations (placeholder)
// ---------------------------------------------------------------------------

/// A no-op implementation of [`IrqDomainOps`] for domains that do not
/// need hardware callbacks (e.g., virtual/test domains).
pub struct NoopDomainOps;

impl IrqDomainOps for NoopDomainOps {
    fn map(&self, _hwirq: u32, _virq: u32) -> Result<IrqFlowType> {
        Ok(IrqFlowType::default())
    }

    fn unmap(&self, _hwirq: u32, _virq: u32) {}

    fn activate(&self, _hwirq: u32) -> Result<()> {
        Ok(())
    }

    fn deactivate(&self, _hwirq: u32) {}

    fn eoi(&self, _hwirq: u32) {}
}

// ---------------------------------------------------------------------------
// Domain type
// ---------------------------------------------------------------------------

/// Classification of an IRQ domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainType {
    /// Direct linear mapping: HW IRQ index = virq index.
    Linear,
    /// Legacy ISA domain: fixed mapping for IRQs 0–15.
    Legacy,
    /// Hierarchy: this domain is chained to a parent domain.
    Hierarchy,
}

// ---------------------------------------------------------------------------
// IrqDomain
// ---------------------------------------------------------------------------

/// An IRQ domain maps hardware interrupt numbers to virqs.
pub struct IrqDomain {
    /// Human-readable name for debugging.
    pub name: [u8; 32],
    /// Domain type.
    pub domain_type: DomainType,
    /// Parent domain index in the global registry (used for hierarchy).
    pub parent_idx: Option<usize>,
    /// Number of hardware IRQs in this domain.
    pub hwirq_max: u32,
    /// Linear map: `hwirq_to_virq[hw] = virq` (VIRQ_INVALID if unmapped).
    hwirq_to_virq: [u32; MAX_VIRQS_PER_DOMAIN],
    /// Reverse map: `virq_to_hwirq[virq - virq_base] = hwirq`.
    virq_to_hwirq: [u32; MAX_VIRQS_PER_DOMAIN],
    /// Base virq number allocated to this domain.
    virq_base: u32,
    /// Number of virqs allocated in this domain.
    virq_count: u32,
    /// Whether the domain has been initialised.
    pub initialized: bool,
}

impl IrqDomain {
    /// Creates a new linear IRQ domain.
    ///
    /// `hwirq_max` is the number of hardware IRQ lines in this controller.
    /// `virq_base` is the first virq number allocated to this domain.
    pub const fn new_linear(hwirq_max: u32, virq_base: u32) -> Self {
        Self {
            name: [0u8; 32],
            domain_type: DomainType::Linear,
            parent_idx: None,
            hwirq_max,
            hwirq_to_virq: [VIRQ_INVALID; MAX_VIRQS_PER_DOMAIN],
            virq_to_hwirq: [VIRQ_INVALID; MAX_VIRQS_PER_DOMAIN],
            virq_base,
            virq_count: 0,
            initialized: false,
        }
    }

    /// Creates a legacy ISA IRQ domain covering HW IRQs 0–15.
    pub const fn new_legacy(virq_base: u32) -> Self {
        let mut d = Self::new_linear(16, virq_base);
        d.domain_type = DomainType::Legacy;
        d
    }

    /// Sets the domain name (up to 31 bytes).
    pub fn set_name(&mut self, s: &[u8]) {
        let len = s.len().min(31);
        self.name[..len].copy_from_slice(&s[..len]);
        self.name[len] = 0;
    }

    /// Initialises the domain, pre-mapping all HW IRQs in a legacy domain.
    pub fn init<O: IrqDomainOps>(&mut self, ops: &O) -> Result<()> {
        if self.domain_type == DomainType::Legacy {
            for hw in 0..self.hwirq_max {
                let virq = self.virq_base + hw;
                let flow = ops.map(hw, virq)?;
                self.insert_mapping(hw, virq, flow)?;
            }
        }
        self.initialized = true;
        Ok(())
    }

    /// Creates a mapping from `hwirq` to a new virq.
    ///
    /// The virq is calculated as `virq_base + hwirq` for linear domains.
    /// Returns the allocated virq.
    pub fn create_mapping<O: IrqDomainOps>(&mut self, hwirq: u32, ops: &O) -> Result<u32> {
        if hwirq >= self.hwirq_max {
            return Err(Error::InvalidArgument);
        }
        // Check if already mapped.
        let existing = self.hwirq_to_virq[hwirq as usize];
        if existing != VIRQ_INVALID {
            return Ok(existing);
        }
        let virq = self.virq_base + hwirq;
        let flow = ops.map(hwirq, virq)?;
        self.insert_mapping(hwirq, virq, flow)?;
        Ok(virq)
    }

    /// Removes the mapping for `hwirq`.
    pub fn dispose_mapping<O: IrqDomainOps>(&mut self, hwirq: u32, ops: &O) {
        if hwirq >= self.hwirq_max as u32 {
            return;
        }
        let virq = self.hwirq_to_virq[hwirq as usize];
        if virq == VIRQ_INVALID {
            return;
        }
        ops.unmap(hwirq, virq);
        self.hwirq_to_virq[hwirq as usize] = VIRQ_INVALID;
        let off = (virq - self.virq_base) as usize;
        if off < MAX_VIRQS_PER_DOMAIN {
            self.virq_to_hwirq[off] = VIRQ_INVALID;
        }
        if self.virq_count > 0 {
            self.virq_count -= 1;
        }
    }

    /// Returns the virq for `hwirq`, or `VIRQ_INVALID` if not mapped.
    pub fn virq_of(&self, hwirq: u32) -> u32 {
        if hwirq >= self.hwirq_max {
            return VIRQ_INVALID;
        }
        self.hwirq_to_virq[hwirq as usize]
    }

    /// Returns the hwirq for `virq`, or `VIRQ_INVALID` if not mapped.
    pub fn hwirq_of(&self, virq: u32) -> u32 {
        if virq < self.virq_base {
            return VIRQ_INVALID;
        }
        let off = (virq - self.virq_base) as usize;
        if off >= MAX_VIRQS_PER_DOMAIN {
            return VIRQ_INVALID;
        }
        self.virq_to_hwirq[off]
    }

    /// Returns the number of active mappings.
    pub fn mapping_count(&self) -> u32 {
        self.virq_count
    }

    /// Activates the hardware IRQ corresponding to `virq`.
    pub fn activate_irq<O: IrqDomainOps>(&self, virq: u32, ops: &O) -> Result<()> {
        let hwirq = self.hwirq_of(virq);
        if hwirq == VIRQ_INVALID {
            return Err(Error::NotFound);
        }
        ops.activate(hwirq)
    }

    /// Deactivates the hardware IRQ corresponding to `virq`.
    pub fn deactivate_irq<O: IrqDomainOps>(&self, virq: u32, ops: &O) {
        let hwirq = self.hwirq_of(virq);
        if hwirq != VIRQ_INVALID {
            ops.deactivate(hwirq);
        }
    }

    /// Sends EOI for `virq`.
    pub fn eoi<O: IrqDomainOps>(&self, virq: u32, ops: &O) {
        let hwirq = self.hwirq_of(virq);
        if hwirq != VIRQ_INVALID {
            ops.eoi(hwirq);
        }
    }

    // -----------------------------------------------------------------------
    // Private
    // -----------------------------------------------------------------------

    fn insert_mapping(&mut self, hwirq: u32, virq: u32, _flow: IrqFlowType) -> Result<()> {
        if hwirq as usize >= MAX_VIRQS_PER_DOMAIN {
            return Err(Error::InvalidArgument);
        }
        let off = (virq - self.virq_base) as usize;
        if off >= MAX_VIRQS_PER_DOMAIN {
            return Err(Error::InvalidArgument);
        }
        self.hwirq_to_virq[hwirq as usize] = virq;
        self.virq_to_hwirq[off] = hwirq;
        self.virq_count += 1;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Global IRQ domain registry
// ---------------------------------------------------------------------------

/// Global registry of all active IRQ domains.
pub struct IrqDomainRegistry {
    domains: [IrqDomain; MAX_DOMAINS],
    count: usize,
    /// Next virq base to assign to new domains.
    next_virq: u32,
}

impl IrqDomainRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            domains: [const { IrqDomain::new_linear(0, 0) }; MAX_DOMAINS],
            count: 0,
            next_virq: VIRQ_BASE,
        }
    }

    /// Allocates virq space and registers a new linear domain.
    ///
    /// Returns the domain index. The domain is not yet initialised;
    /// call `get_mut(idx).init(ops)` to activate mappings.
    pub fn add_linear_domain<O: IrqDomainOps>(
        &mut self,
        hwirq_max: u32,
        name: &[u8],
        ops: &O,
    ) -> Result<usize> {
        if self.count >= MAX_DOMAINS {
            return Err(Error::OutOfMemory);
        }
        if hwirq_max as usize > MAX_VIRQS_PER_DOMAIN {
            return Err(Error::InvalidArgument);
        }
        let virq_base = self.next_virq;
        let mut domain = IrqDomain::new_linear(hwirq_max, virq_base);
        domain.set_name(name);
        domain.init(ops)?;
        let idx = self.count;
        self.domains[idx] = domain;
        self.count += 1;
        self.next_virq = virq_base + hwirq_max;
        Ok(idx)
    }

    /// Registers a pre-built legacy ISA domain.
    pub fn add_legacy_domain<O: IrqDomainOps>(&mut self, name: &[u8], ops: &O) -> Result<usize> {
        if self.count >= MAX_DOMAINS {
            return Err(Error::OutOfMemory);
        }
        let virq_base = self.next_virq;
        let mut domain = IrqDomain::new_legacy(virq_base);
        domain.set_name(name);
        domain.init(ops)?;
        let idx = self.count;
        self.domains[idx] = domain;
        self.count += 1;
        self.next_virq = virq_base + 16;
        Ok(idx)
    }

    /// Looks up the domain that owns the given virq.
    pub fn domain_for_virq(&self, virq: u32) -> Option<usize> {
        for i in 0..self.count {
            let d = &self.domains[i];
            if virq >= d.virq_base && virq < d.virq_base + d.hwirq_max {
                return Some(i);
            }
        }
        None
    }

    /// Resolves a virq to its hardware IRQ number.
    pub fn resolve_virq(&self, virq: u32) -> Option<(usize, u32)> {
        let domain_idx = self.domain_for_virq(virq)?;
        let hwirq = self.domains[domain_idx].hwirq_of(virq);
        if hwirq == VIRQ_INVALID {
            return None;
        }
        Some((domain_idx, hwirq))
    }

    /// Returns an immutable reference to the domain at `index`.
    pub fn get(&self, index: usize) -> Option<&IrqDomain> {
        if index < self.count {
            Some(&self.domains[index])
        } else {
            None
        }
    }

    /// Returns a mutable reference to the domain at `index`.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut IrqDomain> {
        if index < self.count {
            Some(&mut self.domains[index])
        } else {
            None
        }
    }

    /// Returns the number of registered domains.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no domains are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the next available virq base.
    pub fn next_free_virq(&self) -> u32 {
        self.next_virq
    }
}

impl Default for IrqDomainRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Convenience: create and map a single ISA/legacy IRQ
// ---------------------------------------------------------------------------

/// Allocates a linear domain with `hwirq_max` entries and returns it.
///
/// Shorthand for creating simple single-controller domains.
pub fn alloc_linear_domain(hwirq_max: u32, virq_base: u32) -> IrqDomain {
    IrqDomain::new_linear(hwirq_max, virq_base)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct TestOps;
    impl IrqDomainOps for TestOps {
        fn map(&self, _hw: u32, _v: u32) -> Result<IrqFlowType> {
            Ok(IrqFlowType::default())
        }
        fn unmap(&self, _hw: u32, _v: u32) {}
        fn activate(&self, _hw: u32) -> Result<()> {
            Ok(())
        }
        fn deactivate(&self, _hw: u32) {}
        fn eoi(&self, _hw: u32) {}
    }

    #[test]
    fn linear_domain_mapping() {
        let mut d = IrqDomain::new_linear(16, 1);
        let ops = TestOps;
        d.init(&ops).unwrap();
        let virq = d.create_mapping(3, &ops).unwrap();
        assert_eq!(virq, 4); // virq_base(1) + hwirq(3)
        assert_eq!(d.virq_of(3), 4);
        assert_eq!(d.hwirq_of(4), 3);
    }

    #[test]
    fn domain_invalid_hwirq() {
        let mut d = IrqDomain::new_linear(8, 1);
        let ops = TestOps;
        d.init(&ops).unwrap();
        assert!(d.create_mapping(8, &ops).is_err());
    }

    #[test]
    fn dispose_mapping() {
        let mut d = IrqDomain::new_linear(16, 1);
        let ops = TestOps;
        d.init(&ops).unwrap();
        d.create_mapping(0, &ops).unwrap();
        assert_eq!(d.mapping_count(), 1);
        d.dispose_mapping(0, &ops);
        assert_eq!(d.virq_of(0), VIRQ_INVALID);
    }

    #[test]
    fn registry_empty() {
        let reg = IrqDomainRegistry::new();
        assert!(reg.is_empty());
    }

    #[test]
    fn registry_add_linear() {
        let mut reg = IrqDomainRegistry::new();
        let ops = TestOps;
        let idx = reg.add_linear_domain(16, b"test", &ops).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(reg.len(), 1);
    }
}
