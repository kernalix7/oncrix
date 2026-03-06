// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Local APIC and I/O APIC management for x86_64.
//!
//! The Advanced Programmable Interrupt Controller (APIC) system
//! consists of per-CPU Local APICs and one or more I/O APICs that
//! route device interrupts. This module provides:
//!
//! - **Local APIC** — end-of-interrupt, IPI delivery, timer setup,
//!   spurious vector configuration, and APIC ID reading.
//! - **I/O APIC** — redirection table management for routing device
//!   IRQs to specific CPUs/vectors.
//! - **APIC mode detection** — xAPIC vs x2APIC selection.
//!
//! # Architecture
//!
//! ```text
//! ┌────────────┐    ┌────────────┐
//! │  Device     │────│  I/O APIC  │──── interrupt bus
//! └────────────┘    └────────────┘          │
//!                                    ┌──────▼──────┐
//!                                    │ Local APIC  │ (per CPU)
//!                                    └─────────────┘
//! ```
//!
//! The Local APIC is accessed via MMIO at a platform-specific base
//! address (typically `0xFEE00000`). The I/O APIC is also MMIO-mapped
//! (typically at `0xFEC00000`).
//!
//! Reference: Intel SDM Volume 3A, Chapter 10 — APIC.

use oncrix_lib::{Error, Result};

// ── Local APIC register offsets ─────────────────────────────────

/// Local APIC register offsets (aligned to 16-byte boundaries).
pub mod local_reg {
    /// APIC ID Register (read/write).
    pub const ID: u32 = 0x020;
    /// APIC Version Register (read-only).
    pub const VERSION: u32 = 0x030;
    /// Task Priority Register (read/write).
    pub const TPR: u32 = 0x080;
    /// Arbitration Priority Register (read-only).
    pub const APR: u32 = 0x090;
    /// Processor Priority Register (read-only).
    pub const PPR: u32 = 0x0A0;
    /// EOI Register (write-only).
    pub const EOI: u32 = 0x0B0;
    /// Remote Read Register (read-only).
    pub const RRD: u32 = 0x0C0;
    /// Logical Destination Register (read/write).
    pub const LDR: u32 = 0x0D0;
    /// Destination Format Register (read/write).
    pub const DFR: u32 = 0x0E0;
    /// Spurious Interrupt Vector Register (read/write).
    pub const SVR: u32 = 0x0F0;
    /// In-Service Register (ISR) base, 256 bits across 8 regs.
    pub const ISR_BASE: u32 = 0x100;
    /// Trigger Mode Register (TMR) base.
    pub const TMR_BASE: u32 = 0x180;
    /// Interrupt Request Register (IRR) base.
    pub const IRR_BASE: u32 = 0x200;
    /// Error Status Register (read-only).
    pub const ESR: u32 = 0x280;
    /// LVT CMCI Register.
    pub const LVT_CMCI: u32 = 0x2F0;
    /// Interrupt Command Register Low (read/write).
    pub const ICR_LOW: u32 = 0x300;
    /// Interrupt Command Register High (read/write).
    pub const ICR_HIGH: u32 = 0x310;
    /// LVT Timer Register (read/write).
    pub const LVT_TIMER: u32 = 0x320;
    /// LVT Thermal Sensor Register.
    pub const LVT_THERMAL: u32 = 0x330;
    /// LVT Performance Monitoring Counter Register.
    pub const LVT_PERF: u32 = 0x340;
    /// LVT LINT0 Register.
    pub const LVT_LINT0: u32 = 0x350;
    /// LVT LINT1 Register.
    pub const LVT_LINT1: u32 = 0x360;
    /// LVT Error Register.
    pub const LVT_ERROR: u32 = 0x370;
    /// Timer Initial Count Register.
    pub const TIMER_INIT_COUNT: u32 = 0x380;
    /// Timer Current Count Register (read-only).
    pub const TIMER_CURRENT: u32 = 0x390;
    /// Timer Divide Configuration Register.
    pub const TIMER_DIVIDE: u32 = 0x3E0;
}

// ── I/O APIC register offsets ───────────────────────────────────

/// I/O APIC indirect register offsets.
pub mod io_reg {
    /// I/O APIC ID Register (index 0x00).
    pub const ID: u32 = 0x00;
    /// I/O APIC Version Register (index 0x01).
    pub const VERSION: u32 = 0x01;
    /// I/O APIC Arbitration ID (index 0x02).
    pub const ARB_ID: u32 = 0x02;

    /// Compute the low 32 bits redirection table register index.
    pub const fn redirection_low(irq: u8) -> u32 {
        0x10 + (irq as u32) * 2
    }

    /// Compute the high 32 bits redirection table register index.
    pub const fn redirection_high(irq: u8) -> u32 {
        0x10 + (irq as u32) * 2 + 1
    }
}

// ── I/O APIC MMIO register addresses ───────────────────────────

/// I/O APIC register select (IOREGSEL) — offset 0x00 from base.
const IOAPIC_REGSEL: u32 = 0x00;

/// I/O APIC data window (IOWIN) — offset 0x10 from base.
const IOAPIC_WIN: u32 = 0x10;

// ── Local APIC bit constants ────────────────────────────────────

/// Spurious Vector Register: APIC Software Enable bit.
const SVR_ENABLE: u32 = 1 << 8;

/// ICR delivery mode: Fixed.
const ICR_FIXED: u32 = 0 << 8;

/// ICR delivery mode: NMI.
const ICR_NMI: u32 = 4 << 8;

/// ICR delivery mode: INIT.
const ICR_INIT: u32 = 5 << 8;

/// ICR delivery mode: Start-Up.
const ICR_STARTUP: u32 = 6 << 8;

/// ICR destination mode: Physical.
const ICR_DEST_PHYSICAL: u32 = 0 << 11;

/// ICR destination mode: Logical.
const _ICR_DEST_LOGICAL: u32 = 1 << 11;

/// ICR level: Assert.
const ICR_LEVEL_ASSERT: u32 = 1 << 14;

/// ICR level: De-assert.
const _ICR_LEVEL_DEASSERT: u32 = 0 << 14;

/// ICR trigger mode: Edge.
const ICR_TRIGGER_EDGE: u32 = 0 << 15;

/// ICR trigger mode: Level.
const _ICR_TRIGGER_LEVEL: u32 = 1 << 15;

/// ICR delivery status: Send Pending.
const ICR_SEND_PENDING: u32 = 1 << 12;

/// ICR shorthand: No shorthand.
const ICR_NO_SHORTHAND: u32 = 0 << 18;

/// ICR shorthand: Self.
const ICR_SELF: u32 = 1 << 18;

/// ICR shorthand: All including self.
const ICR_ALL_INCLUDING_SELF: u32 = 2 << 18;

/// ICR shorthand: All excluding self.
const ICR_ALL_EXCLUDING_SELF: u32 = 3 << 18;

/// LVT mask bit — when set, the interrupt is masked.
const LVT_MASKED: u32 = 1 << 16;

/// LVT timer mode: One-shot.
const LVT_TIMER_ONESHOT: u32 = 0 << 17;

/// LVT timer mode: Periodic.
const LVT_TIMER_PERIODIC: u32 = 1 << 17;

/// LVT timer mode: TSC-Deadline.
const _LVT_TIMER_TSCDEADLINE: u32 = 2 << 17;

/// Timer divide value 16.
const TIMER_DIVIDE_16: u32 = 0x03;

/// Default APIC base physical address for xAPIC mode.
pub const DEFAULT_LOCAL_APIC_BASE: u64 = 0xFEE0_0000;

/// Default I/O APIC base physical address.
pub const DEFAULT_IOAPIC_BASE: u64 = 0xFEC0_0000;

/// Maximum number of I/O APIC redirection entries we support.
const MAX_IOAPIC_ENTRIES: usize = 24;

/// Maximum I/O APICs tracked.
const MAX_IOAPICS: usize = 4;

/// Maximum number of IRQ route entries.
const MAX_IRQ_ROUTES: usize = 256;

// ── APIC Mode ───────────────────────────────────────────────────

/// Detected or configured APIC operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ApicMode {
    /// APIC not yet initialised.
    #[default]
    Disabled,
    /// Classic xAPIC mode (MMIO-based).
    XApic,
    /// Extended x2APIC mode (MSR-based).
    X2Apic,
}

// ── IPI Destination ─────────────────────────────────────────────

/// IPI destination shorthand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpiDestination {
    /// Send to a specific APIC ID.
    Physical(u8),
    /// Send to self.
    ToSelf,
    /// Broadcast to all CPUs including self.
    AllIncludingSelf,
    /// Broadcast to all CPUs excluding self.
    AllExcludingSelf,
}

// ── IPI Type ────────────────────────────────────────────────────

/// Type of inter-processor interrupt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpiType {
    /// Fixed vector delivery.
    Fixed(u8),
    /// Non-maskable interrupt.
    Nmi,
    /// INIT signal (for AP startup sequence).
    Init,
    /// Startup IPI with vector page number.
    Startup(u8),
}

// ── Trigger / Polarity ──────────────────────────────────────────

/// I/O APIC interrupt trigger mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TriggerMode {
    /// Edge-triggered.
    #[default]
    Edge,
    /// Level-triggered.
    Level,
}

/// I/O APIC interrupt polarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Polarity {
    /// Active high.
    #[default]
    ActiveHigh,
    /// Active low.
    ActiveLow,
}

// ── IRQ Route ───────────────────────────────────────────────────

/// An IRQ routing entry mapping a source IRQ to an APIC vector.
#[derive(Debug, Clone, Copy)]
pub struct IrqRoute {
    /// Source IRQ number (e.g., ISA IRQ 0-15 or PCI IRQ).
    pub source_irq: u8,
    /// I/O APIC index in the system.
    pub ioapic_index: u8,
    /// I/O APIC input pin.
    pub ioapic_pin: u8,
    /// Destination APIC vector.
    pub vector: u8,
    /// Destination APIC ID.
    pub dest_apic_id: u8,
    /// Trigger mode.
    pub trigger: TriggerMode,
    /// Polarity.
    pub polarity: Polarity,
    /// Whether this route is active.
    pub active: bool,
}

impl IrqRoute {
    /// Create an empty, inactive route.
    pub const fn empty() -> Self {
        Self {
            source_irq: 0,
            ioapic_index: 0,
            ioapic_pin: 0,
            vector: 0,
            dest_apic_id: 0,
            trigger: TriggerMode::Edge,
            polarity: Polarity::ActiveHigh,
            active: false,
        }
    }
}

// ── Local APIC ──────────────────────────────────────────────────

/// Local APIC controller.
///
/// Provides access to the per-CPU Local APIC through MMIO registers.
/// Must be initialised with the MMIO base address (typically
/// `0xFEE00000` from ACPI MADT or MSR `0x1B`).
pub struct LocalApic {
    /// MMIO base virtual address.
    base: u64,
    /// Current operating mode.
    mode: ApicMode,
    /// This CPU's APIC ID.
    apic_id: u8,
    /// Whether the APIC has been initialised.
    initialised: bool,
}

impl LocalApic {
    /// Create an uninitialised Local APIC handle.
    pub const fn new() -> Self {
        Self {
            base: 0,
            mode: ApicMode::Disabled,
            apic_id: 0,
            initialised: false,
        }
    }

    /// Initialise the Local APIC at the given MMIO base address.
    ///
    /// Reads the APIC ID, enables the APIC via the Spurious Vector
    /// Register, and sets the task priority to accept all interrupts.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `base` is zero.
    /// Returns [`Error::IoError`] if the APIC version register
    /// reads an invalid value.
    pub fn init(&mut self, base: u64, spurious_vector: u8) -> Result<()> {
        if base == 0 {
            return Err(Error::InvalidArgument);
        }

        self.base = base;
        self.mode = ApicMode::XApic;

        // Read the APIC ID.
        let id_reg = self.read_reg(local_reg::ID);
        self.apic_id = (id_reg >> 24) as u8;

        // Verify version register is sane (bits 7:0 = version,
        // typically 0x10-0x20 for modern APICs).
        let version = self.read_reg(local_reg::VERSION);
        let ver_num = version & 0xFF;
        if ver_num == 0 || ver_num > 0xFF {
            return Err(Error::IoError);
        }

        // Set task priority to 0 (accept all interrupts).
        self.write_reg(local_reg::TPR, 0);

        // Enable the APIC and set the spurious vector.
        let svr = SVR_ENABLE | u32::from(spurious_vector);
        self.write_reg(local_reg::SVR, svr);

        // Mask all LVT entries initially.
        self.write_reg(local_reg::LVT_TIMER, LVT_MASKED);
        self.write_reg(local_reg::LVT_LINT0, LVT_MASKED);
        self.write_reg(local_reg::LVT_LINT1, LVT_MASKED);
        self.write_reg(local_reg::LVT_ERROR, LVT_MASKED);
        self.write_reg(local_reg::LVT_PERF, LVT_MASKED);
        self.write_reg(local_reg::LVT_THERMAL, LVT_MASKED);

        self.initialised = true;
        Ok(())
    }

    // ── Register access ─────────────────────────────────────

    /// Read a 32-bit Local APIC register.
    fn read_reg(&self, offset: u32) -> u32 {
        // SAFETY: Local APIC MMIO region is mapped into kernel
        // virtual address space. Offsets are well-known register
        // addresses from the Intel SDM.
        unsafe {
            let addr = (self.base + u64::from(offset)) as *const u32;
            core::ptr::read_volatile(addr)
        }
    }

    /// Write a 32-bit Local APIC register.
    fn write_reg(&self, offset: u32, value: u32) {
        // SAFETY: Local APIC MMIO region is mapped into kernel
        // virtual address space. Offsets are well-known register
        // addresses from the Intel SDM.
        unsafe {
            let addr = (self.base + u64::from(offset)) as *mut u32;
            core::ptr::write_volatile(addr, value);
        }
    }

    // ── Core operations ─────────────────────────────────────

    /// Send End-Of-Interrupt to the Local APIC.
    ///
    /// Must be called at the end of every interrupt handler to
    /// acknowledge the interrupt and allow further interrupts.
    pub fn eoi(&self) {
        self.write_reg(local_reg::EOI, 0);
    }

    /// Read this CPU's APIC ID.
    pub fn read_id(&self) -> u8 {
        self.apic_id
    }

    /// Return the current APIC operating mode.
    pub fn mode(&self) -> ApicMode {
        self.mode
    }

    /// Return whether the APIC has been initialised.
    pub fn is_initialised(&self) -> bool {
        self.initialised
    }

    /// Read the APIC version register.
    pub fn version(&self) -> u32 {
        self.read_reg(local_reg::VERSION)
    }

    /// Return the maximum LVT entry count from the version register.
    pub fn max_lvt_entries(&self) -> u8 {
        let ver = self.read_reg(local_reg::VERSION);
        ((ver >> 16) & 0xFF) as u8
    }

    /// Set the task priority register.
    ///
    /// Lower values accept more interrupt priorities.
    pub fn set_task_priority(&self, priority: u8) {
        self.write_reg(local_reg::TPR, u32::from(priority));
    }

    /// Read the error status register.
    ///
    /// Write 0 first (required by hardware) then read.
    pub fn read_error_status(&self) -> u32 {
        self.write_reg(local_reg::ESR, 0);
        self.read_reg(local_reg::ESR)
    }

    // ── Inter-Processor Interrupts ──────────────────────────

    /// Send an inter-processor interrupt (IPI).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if a previous IPI send is still
    /// pending after polling.
    pub fn send_ipi(&self, dest: IpiDestination, ipi_type: IpiType) -> Result<()> {
        // Wait for previous IPI to complete.
        let mut timeout = 100_000u32;
        while self.read_reg(local_reg::ICR_LOW) & ICR_SEND_PENDING != 0 {
            timeout = timeout.checked_sub(1).ok_or(Error::Busy)?;
        }

        // Build the ICR value.
        let (delivery, vector_bits) = match ipi_type {
            IpiType::Fixed(v) => (ICR_FIXED, u32::from(v)),
            IpiType::Nmi => (ICR_NMI, 0),
            IpiType::Init => (ICR_INIT, 0),
            IpiType::Startup(page) => (ICR_STARTUP, u32::from(page)),
        };

        let (shorthand, dest_id) = match dest {
            IpiDestination::Physical(id) => (ICR_NO_SHORTHAND, id),
            IpiDestination::ToSelf => (ICR_SELF, 0),
            IpiDestination::AllIncludingSelf => (ICR_ALL_INCLUDING_SELF, 0),
            IpiDestination::AllExcludingSelf => (ICR_ALL_EXCLUDING_SELF, 0),
        };

        let trigger = match ipi_type {
            IpiType::Init => ICR_TRIGGER_EDGE | ICR_LEVEL_ASSERT,
            _ => ICR_TRIGGER_EDGE,
        };

        // Write high dword first (destination APIC ID).
        let icr_high = u32::from(dest_id) << 24;
        self.write_reg(local_reg::ICR_HIGH, icr_high);

        // Write low dword to trigger the send.
        let icr_low = vector_bits | delivery | ICR_DEST_PHYSICAL | trigger | shorthand;
        self.write_reg(local_reg::ICR_LOW, icr_low);

        Ok(())
    }

    // ── Timer configuration ─────────────────────────────────

    /// Configure the Local APIC timer in one-shot mode.
    ///
    /// The timer will fire a single interrupt on `vector` after
    /// `initial_count` ticks at the configured divider rate.
    pub fn setup_timer_oneshot(&self, vector: u8, initial_count: u32) {
        self.write_reg(local_reg::TIMER_DIVIDE, TIMER_DIVIDE_16);
        let lvt = LVT_TIMER_ONESHOT | u32::from(vector);
        self.write_reg(local_reg::LVT_TIMER, lvt);
        self.write_reg(local_reg::TIMER_INIT_COUNT, initial_count);
    }

    /// Configure the Local APIC timer in periodic mode.
    ///
    /// The timer will fire interrupts on `vector` every
    /// `initial_count` ticks.
    pub fn setup_timer_periodic(&self, vector: u8, initial_count: u32) {
        self.write_reg(local_reg::TIMER_DIVIDE, TIMER_DIVIDE_16);
        let lvt = LVT_TIMER_PERIODIC | u32::from(vector);
        self.write_reg(local_reg::LVT_TIMER, lvt);
        self.write_reg(local_reg::TIMER_INIT_COUNT, initial_count);
    }

    /// Stop the Local APIC timer by masking it.
    pub fn stop_timer(&self) {
        self.write_reg(local_reg::LVT_TIMER, LVT_MASKED);
        self.write_reg(local_reg::TIMER_INIT_COUNT, 0);
    }

    /// Read the current timer count value.
    pub fn read_timer_current(&self) -> u32 {
        self.read_reg(local_reg::TIMER_CURRENT)
    }

    /// Set the timer divide configuration.
    pub fn set_timer_divide(&self, divide: u32) {
        self.write_reg(local_reg::TIMER_DIVIDE, divide);
    }

    // ── LVT configuration ───────────────────────────────────

    /// Configure LVT LINT0 entry.
    pub fn configure_lint0(&self, vector: u8, masked: bool) {
        let mut val = u32::from(vector);
        if masked {
            val |= LVT_MASKED;
        }
        self.write_reg(local_reg::LVT_LINT0, val);
    }

    /// Configure LVT LINT1 entry.
    pub fn configure_lint1(&self, vector: u8, masked: bool) {
        let mut val = u32::from(vector);
        if masked {
            val |= LVT_MASKED;
        }
        self.write_reg(local_reg::LVT_LINT1, val);
    }

    /// Configure LVT Error entry.
    pub fn configure_error_lvt(&self, vector: u8) {
        self.write_reg(local_reg::LVT_ERROR, u32::from(vector));
    }

    /// Return the MMIO base address.
    pub fn base_address(&self) -> u64 {
        self.base
    }
}

impl Default for LocalApic {
    fn default() -> Self {
        Self::new()
    }
}

// ── I/O APIC ────────────────────────────────────────────────────

/// I/O APIC controller.
///
/// Provides access to the I/O APIC through its indirect register
/// interface (IOREGSEL + IOWIN). Each I/O APIC has 24 redirection
/// table entries that map device IRQs to APIC vectors.
pub struct IoApic {
    /// MMIO base virtual address.
    base: u64,
    /// I/O APIC ID read from hardware.
    id: u8,
    /// Number of redirection entries (from version register).
    max_entries: u8,
    /// Hardware version.
    version: u8,
    /// Whether this I/O APIC has been initialised.
    initialised: bool,
}

impl IoApic {
    /// Create an uninitialised I/O APIC handle.
    pub const fn new() -> Self {
        Self {
            base: 0,
            id: 0,
            max_entries: 0,
            version: 0,
            initialised: false,
        }
    }

    /// Initialise the I/O APIC at the given MMIO base address.
    ///
    /// Reads the I/O APIC ID and version, determines the number
    /// of redirection entries, and masks all entries.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `base` is zero.
    pub fn init(&mut self, base: u64) -> Result<()> {
        if base == 0 {
            return Err(Error::InvalidArgument);
        }

        self.base = base;

        // Read ID register.
        let id_raw = self.read_indirect(io_reg::ID);
        self.id = ((id_raw >> 24) & 0x0F) as u8;

        // Read version register.
        let ver_raw = self.read_indirect(io_reg::VERSION);
        self.version = (ver_raw & 0xFF) as u8;
        self.max_entries = (((ver_raw >> 16) & 0xFF) as u8).saturating_add(1);

        // Mask all redirection entries.
        let entry_count = self.max_entries.min(MAX_IOAPIC_ENTRIES as u8);
        for pin in 0..entry_count {
            self.mask_irq(pin);
        }

        self.initialised = true;
        Ok(())
    }

    // ── Indirect register access ────────────────────────────

    /// Read a 32-bit I/O APIC register via the indirect interface.
    fn read_indirect(&self, index: u32) -> u32 {
        // SAFETY: I/O APIC MMIO region is mapped. The IOREGSEL
        // and IOWIN registers are at offsets 0x00 and 0x10.
        unsafe {
            let sel = (self.base + u64::from(IOAPIC_REGSEL)) as *mut u32;
            let win = (self.base + u64::from(IOAPIC_WIN)) as *const u32;
            core::ptr::write_volatile(sel, index);
            core::ptr::read_volatile(win)
        }
    }

    /// Write a 32-bit I/O APIC register via the indirect interface.
    fn write_indirect(&self, index: u32, value: u32) {
        // SAFETY: I/O APIC MMIO region is mapped. The IOREGSEL
        // and IOWIN registers are at offsets 0x00 and 0x10.
        unsafe {
            let sel = (self.base + u64::from(IOAPIC_REGSEL)) as *mut u32;
            let win = (self.base + u64::from(IOAPIC_WIN)) as *mut u32;
            core::ptr::write_volatile(sel, index);
            core::ptr::write_volatile(win, value);
        }
    }

    // ── Core operations ─────────────────────────────────────

    /// Read the I/O APIC ID.
    pub fn read_id(&self) -> u8 {
        self.id
    }

    /// Return the I/O APIC version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Return the maximum number of redirection table entries.
    pub fn max_entries(&self) -> u8 {
        self.max_entries
    }

    /// Return whether the I/O APIC has been initialised.
    pub fn is_initialised(&self) -> bool {
        self.initialised
    }

    // ── Redirection table ───────────────────────────────────

    /// Set a redirection table entry for a given IRQ pin.
    ///
    /// Routes the I/O APIC input pin to the specified vector on
    /// the destination APIC.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `pin` exceeds the
    /// number of available redirection entries.
    pub fn set_route(
        &self,
        pin: u8,
        vector: u8,
        dest_apic_id: u8,
        trigger: TriggerMode,
        polarity: Polarity,
    ) -> Result<()> {
        if pin >= self.max_entries {
            return Err(Error::InvalidArgument);
        }

        // Build the 64-bit redirection entry.
        let mut low: u32 = u32::from(vector);

        // Delivery mode: Fixed (000).
        // Destination mode: Physical (bit 11 = 0).

        if polarity == Polarity::ActiveLow {
            low |= 1 << 13;
        }
        if trigger == TriggerMode::Level {
            low |= 1 << 15;
        }

        let high: u32 = u32::from(dest_apic_id) << 24;

        self.write_indirect(io_reg::redirection_low(pin), low);
        self.write_indirect(io_reg::redirection_high(pin), high);

        Ok(())
    }

    /// Read a redirection table entry.
    ///
    /// Returns (low_dword, high_dword).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `pin` is out of range.
    pub fn read_route(&self, pin: u8) -> Result<(u32, u32)> {
        if pin >= self.max_entries {
            return Err(Error::InvalidArgument);
        }
        let low = self.read_indirect(io_reg::redirection_low(pin));
        let high = self.read_indirect(io_reg::redirection_high(pin));
        Ok((low, high))
    }

    /// Mask (disable) an I/O APIC IRQ input pin.
    pub fn mask_irq(&self, pin: u8) {
        if pin >= self.max_entries {
            return;
        }
        let low = self.read_indirect(io_reg::redirection_low(pin));
        self.write_indirect(io_reg::redirection_low(pin), low | LVT_MASKED);
    }

    /// Unmask (enable) an I/O APIC IRQ input pin.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `pin` is out of range.
    pub fn unmask_irq(&self, pin: u8) -> Result<()> {
        if pin >= self.max_entries {
            return Err(Error::InvalidArgument);
        }
        let low = self.read_indirect(io_reg::redirection_low(pin));
        self.write_indirect(io_reg::redirection_low(pin), low & !LVT_MASKED);
        Ok(())
    }

    /// Return the MMIO base address.
    pub fn base_address(&self) -> u64 {
        self.base
    }
}

impl Default for IoApic {
    fn default() -> Self {
        Self::new()
    }
}

// ── IRQ Route Table ─────────────────────────────────────────────

/// System-wide IRQ routing table.
///
/// Maintains a mapping from source IRQ numbers to I/O APIC
/// redirection entries. Used during ACPI MADT parsing to build
/// the complete interrupt routing picture.
pub struct IrqRouteTable {
    /// Route entries.
    routes: [IrqRoute; MAX_IRQ_ROUTES],
    /// Number of active routes.
    count: usize,
}

impl IrqRouteTable {
    /// Create an empty routing table.
    pub const fn new() -> Self {
        Self {
            routes: [const { IrqRoute::empty() }; MAX_IRQ_ROUTES],
            count: 0,
        }
    }

    /// Add an IRQ route.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the table is full.
    pub fn add_route(&mut self, route: IrqRoute) -> Result<()> {
        if self.count >= MAX_IRQ_ROUTES {
            return Err(Error::OutOfMemory);
        }
        self.routes[self.count] = route;
        self.count += 1;
        Ok(())
    }

    /// Find a route by source IRQ number.
    pub fn find_by_source(&self, source_irq: u8) -> Option<&IrqRoute> {
        let mut i = 0;
        while i < self.count {
            if self.routes[i].active && self.routes[i].source_irq == source_irq {
                return Some(&self.routes[i]);
            }
            i += 1;
        }
        None
    }

    /// Return the number of active routes.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return a reference to a route by index.
    pub fn get(&self, index: usize) -> Option<&IrqRoute> {
        if index < self.count {
            Some(&self.routes[index])
        } else {
            None
        }
    }
}

impl Default for IrqRouteTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── I/O APIC Registry ──────────────────────────────────────────

/// Registry tracking all I/O APICs in the system.
pub struct IoApicRegistry {
    /// I/O APIC instances.
    entries: [Option<IoApic>; MAX_IOAPICS],
    /// Number of registered I/O APICs.
    count: usize,
}

impl IoApicRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const NONE: Option<IoApic> = None;
        Self {
            entries: [NONE; MAX_IOAPICS],
            count: 0,
        }
    }

    /// Register an initialised I/O APIC.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, ioapic: IoApic) -> Result<()> {
        if self.count >= MAX_IOAPICS {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = Some(ioapic);
        self.count += 1;
        Ok(())
    }

    /// Return a reference to an I/O APIC by index.
    pub fn get(&self, index: usize) -> Option<&IoApic> {
        if index < self.count {
            self.entries[index].as_ref()
        } else {
            None
        }
    }

    /// Return a mutable reference to an I/O APIC by index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut IoApic> {
        if index < self.count {
            self.entries[index].as_mut()
        } else {
            None
        }
    }

    /// Return the number of registered I/O APICs.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for IoApicRegistry {
    fn default() -> Self {
        Self::new()
    }
}
