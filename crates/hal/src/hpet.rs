// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! HPET (High Precision Event Timer) driver.
//!
//! The HPET provides a high-resolution monotonic counter and up to 32
//! comparator timers. It is described by an ACPI table with signature
//! `"HPET"` and accessed through memory-mapped I/O registers.
//!
//! This driver supports:
//! - Parsing the ACPI HPET table to discover the base address and
//!   timer period.
//! - Reading the main counter for high-precision timekeeping.
//! - Configuring individual timers in one-shot or periodic mode.
//! - Converting counter values to nanoseconds.
//!
//! The HPET specification guarantees a counter period of at most
//! 100 nanoseconds (≥ 10 MHz) and is commonly used to calibrate
//! other timers (e.g., the Local APIC timer).

use oncrix_lib::{Error, Result};

use crate::acpi::{SdtHeader, validate_sdt_checksum};
use crate::timer::Timer;

// ── ACPI HPET table signature ────────────────────────────────

/// ACPI HPET table signature: `"HPET"`.
const HPET_SIGNATURE: [u8; 4] = *b"HPET";

/// Minimum ACPI HPET table size (SDT header + HPET-specific fields).
///
/// The HPET table contains at least: SDT header (36 bytes) +
/// event timer block ID (4) + base address GAS (12) + HPET number
/// (1) + min tick (2) + page protection (1) = 56 bytes.
const HPET_TABLE_MIN_SIZE: usize = 56;

// ── Register offsets ─────────────────────────────────────────

/// HPET MMIO register offsets per the IA-PC HPET specification.
pub mod reg {
    /// General Capabilities and ID Register (read-only, 64-bit).
    pub const GENERAL_CAP_ID: u64 = 0x000;
    /// General Configuration Register (read-write, 64-bit).
    pub const GENERAL_CONFIG: u64 = 0x010;
    /// General Interrupt Status Register (read-write-clear, 64-bit).
    pub const GENERAL_INT_STATUS: u64 = 0x020;
    /// Main Counter Value Register (read-write, 64-bit).
    pub const MAIN_COUNTER: u64 = 0x0F0;

    /// Timer N Configuration and Capability Register (64-bit).
    ///
    /// Timer registers are spaced 0x20 bytes apart starting at 0x100.
    pub const fn timer_config(n: u8) -> u64 {
        0x100 + 0x20 * n as u64
    }

    /// Timer N Comparator Value Register (64-bit).
    pub const fn timer_comparator(n: u8) -> u64 {
        0x108 + 0x20 * n as u64
    }

    /// Timer N FSB Interrupt Route Register (64-bit).
    pub const fn timer_fsb_route(n: u8) -> u64 {
        0x110 + 0x20 * n as u64
    }
}

// ── Capability register bit fields ──────────────────────────

/// Bit mask for the counter clock period (bits 63:32) in the
/// General Capabilities register. The period is in femtoseconds.
const CAP_PERIOD_MASK: u64 = 0xFFFF_FFFF_0000_0000;

/// Shift to extract the counter clock period.
const CAP_PERIOD_SHIFT: u32 = 32;

/// Bit mask for the number of timers minus one (bits 12:8).
const CAP_NUM_TIMERS_MASK: u64 = 0x0000_0000_0000_1F00;

/// Shift to extract the number of timers field.
const CAP_NUM_TIMERS_SHIFT: u32 = 8;

/// Bit 13: COUNT_SIZE_CAP — 1 if the main counter is 64-bit.
const CAP_64BIT: u64 = 1 << 13;

/// Bit 15: LEG_ROUTE_CAP — 1 if legacy replacement route is
/// supported (timer 0 → IRQ0, timer 1 → IRQ8).
const CAP_LEGACY_ROUTE: u64 = 1 << 15;

/// Bit mask for the revision ID (bits 7:0).
const CAP_REVISION_MASK: u64 = 0xFF;

// ── General Configuration register bits ─────────────────────

/// Bit 0: ENABLE_CNF — overall HPET enable.
const CFG_ENABLE: u64 = 1;

/// Bit 1: LEG_RT_CNF — enable legacy replacement routing.
const CFG_LEGACY_ROUTE: u64 = 1 << 1;

// ── Timer Configuration register bits ───────────────────────

/// Bit 1: Tn_INT_TYPE_CNF — 0 = edge, 1 = level triggered.
const TIMER_LEVEL_TRIGGERED: u64 = 1 << 1;

/// Bit 2: Tn_INT_ENB_CNF — enable interrupt generation.
const TIMER_INT_ENABLE: u64 = 1 << 2;

/// Bit 3: Tn_TYPE_CNF — 0 = one-shot, 1 = periodic.
const TIMER_PERIODIC: u64 = 1 << 3;

/// Bit 4: Tn_PER_INT_CAP — 1 if periodic mode is supported
/// (read-only capability).
const TIMER_PERIODIC_CAP: u64 = 1 << 4;

/// Bit 5: Tn_SIZE_CAP — 1 if 64-bit comparator (read-only).
const TIMER_64BIT_CAP: u64 = 1 << 5;

/// Bit 6: Tn_VAL_SET_CNF — set to allow writing the accumulator
/// value for periodic mode.
const TIMER_VAL_SET: u64 = 1 << 6;

/// Bit 14: Tn_FSB_EN_CNF — enable FSB interrupt delivery.
const TIMER_FSB_ENABLE: u64 = 1 << 14;

/// Bit 15: Tn_FSB_INT_DEL_CAP — FSB interrupt delivery capable
/// (read-only).
const TIMER_FSB_CAP: u64 = 1 << 15;

/// Bits 13:9 — Tn_INT_ROUTE_CNF: I/O APIC routing for this timer.
const TIMER_ROUTE_SHIFT: u32 = 9;

/// Mask for the routing field (5 bits).
const TIMER_ROUTE_MASK: u64 = 0x1F << 9;

/// Bits 63:32 — Tn_INT_ROUTE_CAP: bitmask of allowed I/O APIC
/// interrupt routing lines (read-only).
const TIMER_ROUTE_CAP_SHIFT: u32 = 32;

/// Maximum number of HPET timers we support.
const MAX_TIMERS: usize = 8;

/// Femtoseconds per nanosecond.
const FEMTOS_PER_NANO: u64 = 1_000_000;

/// Maximum allowed period in femtoseconds (100 ns = 10^8 fs).
/// The HPET spec mandates the period must not exceed this value.
const MAX_PERIOD_FS: u64 = 100_000_000;

// ── HpetCapabilities ────────────────────────────────────────

/// Parsed capabilities from the HPET General Capabilities register.
#[derive(Debug, Clone, Copy)]
pub struct HpetCapabilities {
    /// Counter tick period in femtoseconds (10^-15 s).
    pub period_fs: u32,
    /// Number of timers present (1-based count, not the raw
    /// `NUM_TIM_CAP` field which is N-1).
    pub num_timers: u8,
    /// Whether the main counter is 64-bit capable.
    pub is_64bit: bool,
    /// Whether legacy replacement routing is supported.
    pub legacy_route_capable: bool,
    /// Hardware revision ID.
    pub revision: u8,
}

impl HpetCapabilities {
    /// Parse capabilities from the raw 64-bit register value.
    pub fn from_raw(raw: u64) -> Self {
        let period_fs = ((raw & CAP_PERIOD_MASK) >> CAP_PERIOD_SHIFT) as u32;
        let num_timers_minus_one = ((raw & CAP_NUM_TIMERS_MASK) >> CAP_NUM_TIMERS_SHIFT) as u8;
        Self {
            period_fs,
            num_timers: num_timers_minus_one.saturating_add(1),
            is_64bit: raw & CAP_64BIT != 0,
            legacy_route_capable: raw & CAP_LEGACY_ROUTE != 0,
            revision: (raw & CAP_REVISION_MASK) as u8,
        }
    }

    /// Compute the counter frequency in Hz from the period.
    ///
    /// Returns 0 if the period is zero (invalid hardware).
    pub fn frequency_hz(&self) -> u64 {
        if self.period_fs == 0 {
            return 0;
        }
        // freq = 10^15 / period_fs
        1_000_000_000_000_000 / self.period_fs as u64
    }
}

// ── HpetInfo (ACPI table) ───────────────────────────────────

/// Information parsed from the ACPI HPET description table.
#[derive(Debug, Clone, Copy)]
pub struct HpetInfo {
    /// Physical base address of the HPET register block.
    pub base_address: u64,
    /// Counter tick period in femtoseconds (from the ACPI table's
    /// event timer block ID, bits 63:32 of the capabilities).
    pub min_tick: u16,
    /// HPET sequence number (for systems with multiple HPETs).
    pub hpet_number: u8,
    /// Hardware revision from the event timer block ID.
    pub revision: u8,
    /// Number of comparators minus one (from event timer block ID).
    pub num_timers_minus_one: u8,
    /// Whether the main counter is 64-bit (bit 13 of block ID).
    pub counter_64bit: bool,
    /// Whether legacy IRQ replacement is supported (bit 15).
    pub legacy_capable: bool,
    /// PCI vendor ID from the event timer block ID.
    pub vendor_id: u16,
}

/// Parse an ACPI HPET description table.
///
/// The `data` slice must include the full SDT header and at least
/// 56 bytes total. The base address is extracted from the Generic
/// Address Structure at offset 44.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the table is too short,
/// the signature does not match, or the checksum fails.
pub fn parse_hpet_table(data: &[u8]) -> Result<HpetInfo> {
    if data.len() < HPET_TABLE_MIN_SIZE {
        return Err(Error::InvalidArgument);
    }

    // SAFETY: data.len() >= SDT_HEADER_SIZE verified
    // (HPET_TABLE_MIN_SIZE > SDT_HEADER_SIZE).
    let header = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const SdtHeader) };

    if header.signature != HPET_SIGNATURE {
        return Err(Error::InvalidArgument);
    }

    let length = header.length as usize;
    if !validate_sdt_checksum(data, length.min(data.len())) {
        return Err(Error::InvalidArgument);
    }

    // Event Timer Block ID at offset 36 (u32).
    // SAFETY: offset 36 + 4 = 40 <= HPET_TABLE_MIN_SIZE.
    let block_id = unsafe { core::ptr::read_unaligned(data.as_ptr().add(36) as *const u32) };

    // Base address: Generic Address Structure at offset 40.
    // The GAS is 12 bytes; the 64-bit address is at GAS offset 4.
    // SAFETY: offset 44 + 8 = 52 <= HPET_TABLE_MIN_SIZE.
    let base_address = unsafe { core::ptr::read_unaligned(data.as_ptr().add(44) as *const u64) };

    // HPET number (u8) at offset 52.
    let hpet_number = data[52];

    // Minimum tick (u16) at offset 53.
    // SAFETY: offset 53 + 2 = 55 <= HPET_TABLE_MIN_SIZE.
    let min_tick = unsafe { core::ptr::read_unaligned(data.as_ptr().add(53) as *const u16) };

    let revision = (block_id & 0xFF) as u8;
    let num_timers_minus_one = ((block_id >> 8) & 0x1F) as u8;
    let counter_64bit = block_id & (1 << 13) != 0;
    let legacy_capable = block_id & (1 << 15) != 0;
    let vendor_id = (block_id >> 16) as u16;

    if base_address == 0 {
        return Err(Error::InvalidArgument);
    }

    Ok(HpetInfo {
        base_address,
        min_tick,
        hpet_number,
        revision,
        num_timers_minus_one,
        counter_64bit,
        legacy_capable,
        vendor_id,
    })
}

// ── HpetTimer ───────────────────────────────────────────────

/// Trigger mode for an HPET timer comparator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerMode {
    /// Edge-triggered interrupt.
    Edge,
    /// Level-triggered interrupt.
    Level,
}

/// Timer firing mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerMode {
    /// Fire once when the main counter reaches the comparator.
    OneShot,
    /// Fire periodically at a fixed interval.
    Periodic,
}

/// Configuration and state for a single HPET timer comparator.
#[derive(Debug, Clone, Copy)]
pub struct HpetTimer {
    /// Timer index (0-based).
    pub index: u8,
    /// Whether periodic mode is supported (hardware capability).
    pub periodic_capable: bool,
    /// Whether the comparator is 64-bit capable.
    pub is_64bit: bool,
    /// Whether FSB interrupt delivery is supported.
    pub fsb_capable: bool,
    /// Bitmask of allowed I/O APIC interrupt routing lines.
    pub route_capabilities: u32,
}

impl HpetTimer {
    /// Parse a timer's capabilities from its raw configuration
    /// register value.
    pub fn from_config_reg(index: u8, raw: u64) -> Self {
        Self {
            index,
            periodic_capable: raw & TIMER_PERIODIC_CAP != 0,
            is_64bit: raw & TIMER_64BIT_CAP != 0,
            fsb_capable: raw & TIMER_FSB_CAP != 0,
            route_capabilities: (raw >> TIMER_ROUTE_CAP_SHIFT) as u32,
        }
    }
}

// ── Hpet (main driver) ─────────────────────────────────────

/// HPET driver.
///
/// Provides access to the HPET main counter and timer comparators
/// through memory-mapped I/O. Must be initialised with the base
/// address from the ACPI HPET table.
pub struct Hpet {
    /// MMIO base virtual address of the HPET register block.
    base: u64,
    /// Parsed hardware capabilities.
    capabilities: HpetCapabilities,
    /// Per-timer capability snapshots.
    timers: [Option<HpetTimer>; MAX_TIMERS],
    /// Number of timers discovered.
    timer_count: u8,
    /// Whether the HPET is currently enabled.
    enabled: bool,
}

impl Hpet {
    /// Create a new, uninitialised HPET driver.
    ///
    /// Use [`Hpet::init`] to read hardware capabilities and prepare
    /// the HPET for use.
    pub const fn new() -> Self {
        Self {
            base: 0,
            capabilities: HpetCapabilities {
                period_fs: 0,
                num_timers: 0,
                is_64bit: false,
                legacy_route_capable: false,
                revision: 0,
            },
            timers: [None; MAX_TIMERS],
            timer_count: 0,
            enabled: false,
        }
    }

    /// Initialise the HPET from the ACPI-provided base address.
    ///
    /// Reads the capabilities register, discovers timers, and leaves
    /// the HPET in a disabled state (call [`Hpet::enable`] to start
    /// the main counter).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `base` is zero, or
    /// [`Error::IoError`] if the capabilities register reports an
    /// invalid period (zero or exceeding 100 ns).
    pub fn init(&mut self, base: u64) -> Result<()> {
        if base == 0 {
            return Err(Error::InvalidArgument);
        }

        self.base = base;

        // Read capabilities.
        let cap_raw = self.read64(reg::GENERAL_CAP_ID);
        self.capabilities = HpetCapabilities::from_raw(cap_raw);

        // Validate period.
        if self.capabilities.period_fs == 0 || self.capabilities.period_fs as u64 > MAX_PERIOD_FS {
            return Err(Error::IoError);
        }

        // Disable the HPET before configuring timers.
        self.disable();

        // Reset the main counter.
        self.write64(reg::MAIN_COUNTER, 0);

        // Discover individual timer capabilities.
        let n = self.capabilities.num_timers.min(MAX_TIMERS as u8);
        self.timer_count = n;

        for i in 0..n {
            let cfg = self.read64(reg::timer_config(i));
            self.timers[i as usize] = Some(HpetTimer::from_config_reg(i, cfg));

            // Disable the timer and clear any pending interrupt.
            self.write64(
                reg::timer_config(i),
                cfg & !(TIMER_INT_ENABLE | TIMER_PERIODIC),
            );
        }

        Ok(())
    }

    /// Initialise the HPET from a parsed [`HpetInfo`] structure.
    ///
    /// Convenience wrapper around [`Hpet::init`] that extracts the
    /// base address from the ACPI table info.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Hpet::init`].
    pub fn init_from_acpi(&mut self, info: &HpetInfo) -> Result<()> {
        self.init(info.base_address)
    }

    // ── Register access ─────────────────────────────────────

    /// Read a 64-bit HPET register.
    fn read64(&self, offset: u64) -> u64 {
        // SAFETY: HPET MMIO region is mapped in kernel space.
        // Reads from well-known register offsets within the 1 KiB
        // HPET register block.
        unsafe {
            let addr = (self.base + offset) as *const u64;
            core::ptr::read_volatile(addr)
        }
    }

    /// Write a 64-bit HPET register.
    fn write64(&self, offset: u64, value: u64) {
        // SAFETY: HPET MMIO region is mapped in kernel space.
        // Writes to well-known register offsets within the 1 KiB
        // HPET register block.
        unsafe {
            let addr = (self.base + offset) as *mut u64;
            core::ptr::write_volatile(addr, value);
        }
    }

    // ── Enable / Disable ────────────────────────────────────

    /// Enable the HPET main counter.
    ///
    /// Sets the ENABLE_CNF bit in the General Configuration
    /// register. The main counter begins incrementing.
    pub fn enable(&mut self) {
        let cfg = self.read64(reg::GENERAL_CONFIG);
        self.write64(reg::GENERAL_CONFIG, cfg | CFG_ENABLE);
        self.enabled = true;
    }

    /// Disable the HPET main counter.
    ///
    /// Clears the ENABLE_CNF bit. The main counter stops and all
    /// timer interrupts are suppressed.
    pub fn disable(&mut self) {
        let cfg = self.read64(reg::GENERAL_CONFIG);
        self.write64(reg::GENERAL_CONFIG, cfg & !CFG_ENABLE);
        self.enabled = false;
    }

    /// Enable legacy replacement routing (IRQ0 for timer 0,
    /// IRQ8 for timer 1).
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotImplemented`] if the hardware does not
    /// support legacy replacement routing.
    pub fn enable_legacy_route(&mut self) -> Result<()> {
        if !self.capabilities.legacy_route_capable {
            return Err(Error::NotImplemented);
        }
        let cfg = self.read64(reg::GENERAL_CONFIG);
        self.write64(reg::GENERAL_CONFIG, cfg | CFG_LEGACY_ROUTE);
        Ok(())
    }

    /// Disable legacy replacement routing.
    pub fn disable_legacy_route(&mut self) {
        let cfg = self.read64(reg::GENERAL_CONFIG);
        self.write64(reg::GENERAL_CONFIG, cfg & !CFG_LEGACY_ROUTE);
    }

    /// Return whether the HPET is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    // ── Main counter ────────────────────────────────────────

    /// Read the current main counter value.
    pub fn read_counter(&self) -> u64 {
        self.read64(reg::MAIN_COUNTER)
    }

    /// Reset the main counter to zero.
    ///
    /// The HPET must be disabled before resetting the counter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the HPET is currently enabled.
    pub fn reset_counter(&mut self) -> Result<()> {
        if self.enabled {
            return Err(Error::Busy);
        }
        self.write64(reg::MAIN_COUNTER, 0);
        Ok(())
    }

    // ── Nanosecond conversion ───────────────────────────────

    /// Convert a counter delta (ticks) to nanoseconds.
    ///
    /// Uses the period from the capabilities register. Returns 0
    /// if the period is invalid (zero). This method uses the HPET
    /// period directly for higher precision than the `Timer` trait
    /// default.
    pub fn counter_to_nanos(&self, ticks: u64) -> u64 {
        let period = self.capabilities.period_fs as u64;
        if period == 0 {
            return 0;
        }
        // nanos = ticks * period_fs / 10^6
        let fs = (ticks as u128).saturating_mul(period as u128);
        (fs / FEMTOS_PER_NANO as u128) as u64
    }

    /// Convert nanoseconds to counter ticks.
    ///
    /// Returns 0 if the period is invalid (zero). This method uses
    /// the HPET period directly for higher precision than the
    /// `Timer` trait default.
    pub fn nanos_to_counter(&self, nanos: u64) -> u64 {
        let period = self.capabilities.period_fs as u64;
        if period == 0 {
            return 0;
        }
        // ticks = nanos * 10^6 / period_fs
        let fs = (nanos as u128).saturating_mul(FEMTOS_PER_NANO as u128);
        (fs / period as u128) as u64
    }

    // ── Capabilities ────────────────────────────────────────

    /// Return the parsed hardware capabilities.
    pub fn capabilities(&self) -> &HpetCapabilities {
        &self.capabilities
    }

    /// Return the number of timer comparators.
    pub fn timer_count(&self) -> u8 {
        self.timer_count
    }

    /// Return the capabilities of a specific timer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of
    /// range.
    pub fn timer_info(&self, index: u8) -> Result<&HpetTimer> {
        self.timers
            .get(index as usize)
            .and_then(|t| t.as_ref())
            .ok_or(Error::InvalidArgument)
    }

    // ── Timer configuration ─────────────────────────────────

    /// Configure and arm an HPET timer comparator.
    ///
    /// Sets the comparator value, trigger mode, firing mode, and
    /// I/O APIC interrupt routing. The timer is enabled upon return.
    ///
    /// For periodic mode, `comparator_value` sets the interval in
    /// HPET ticks between successive interrupts.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `index` is out of range or
    ///   the requested `irq_route` is not in the timer's allowed
    ///   routing mask.
    /// - [`Error::NotImplemented`] if periodic mode is requested
    ///   but the timer does not support it.
    pub fn configure_timer(
        &mut self,
        index: u8,
        mode: TimerMode,
        trigger: TriggerMode,
        irq_route: u8,
        comparator_value: u64,
    ) -> Result<()> {
        let timer = self
            .timers
            .get(index as usize)
            .and_then(|t| t.as_ref())
            .ok_or(Error::InvalidArgument)?;

        // Verify periodic capability.
        if mode == TimerMode::Periodic && !timer.periodic_capable {
            return Err(Error::NotImplemented);
        }

        // Verify interrupt route is allowed.
        if irq_route >= 32 || timer.route_capabilities & (1 << irq_route) == 0 {
            return Err(Error::InvalidArgument);
        }

        // Build the configuration register value.
        let mut cfg: u64 = 0;

        // Interrupt enable.
        cfg |= TIMER_INT_ENABLE;

        // Trigger mode.
        if trigger == TriggerMode::Level {
            cfg |= TIMER_LEVEL_TRIGGERED;
        }

        // Timer mode.
        if mode == TimerMode::Periodic {
            cfg |= TIMER_PERIODIC | TIMER_VAL_SET;
        }

        // I/O APIC route.
        cfg &= !TIMER_ROUTE_MASK;
        cfg |= (irq_route as u64) << TIMER_ROUTE_SHIFT;

        self.write64(reg::timer_config(index), cfg);
        self.write64(reg::timer_comparator(index), comparator_value);

        Ok(())
    }

    /// Disable a timer comparator (mask its interrupt).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of
    /// range.
    pub fn disable_timer(&mut self, index: u8) -> Result<()> {
        if index >= self.timer_count {
            return Err(Error::InvalidArgument);
        }
        let cfg = self.read64(reg::timer_config(index));
        self.write64(reg::timer_config(index), cfg & !TIMER_INT_ENABLE);
        Ok(())
    }

    /// Enable FSB (Front Side Bus / MSI) interrupt delivery for
    /// a timer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of
    /// range, or [`Error::NotImplemented`] if the timer does not
    /// support FSB delivery.
    pub fn enable_timer_fsb(&mut self, index: u8, fsb_value: u32, fsb_address: u32) -> Result<()> {
        let timer = self
            .timers
            .get(index as usize)
            .and_then(|t| t.as_ref())
            .ok_or(Error::InvalidArgument)?;

        if !timer.fsb_capable {
            return Err(Error::NotImplemented);
        }

        // Write the FSB route register (address in upper 32 bits,
        // value in lower 32 bits).
        let fsb_reg = ((fsb_address as u64) << 32) | fsb_value as u64;
        self.write64(reg::timer_fsb_route(index), fsb_reg);

        // Enable FSB delivery in the timer config.
        let cfg = self.read64(reg::timer_config(index));
        self.write64(reg::timer_config(index), cfg | TIMER_FSB_ENABLE);

        Ok(())
    }

    /// Clear the interrupt status bit for a timer.
    ///
    /// Required for level-triggered timers to re-arm.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `index` is out of
    /// range.
    pub fn clear_interrupt_status(&mut self, index: u8) -> Result<()> {
        if index >= self.timer_count {
            return Err(Error::InvalidArgument);
        }
        // Writing 1 to a bit in the interrupt status register
        // clears that timer's interrupt.
        self.write64(reg::GENERAL_INT_STATUS, 1u64 << index);
        Ok(())
    }

    /// Read the raw interrupt status register.
    pub fn interrupt_status(&self) -> u64 {
        self.read64(reg::GENERAL_INT_STATUS)
    }

    /// Return the MMIO base address.
    pub fn base_address(&self) -> u64 {
        self.base
    }
}

impl Default for Hpet {
    fn default() -> Self {
        Self::new()
    }
}

impl Timer for Hpet {
    fn frequency_hz(&self) -> u64 {
        self.capabilities.frequency_hz()
    }

    fn current_ticks(&self) -> u64 {
        self.read_counter()
    }

    fn set_oneshot(&mut self, ticks: u64) -> Result<()> {
        if self.timer_count == 0 {
            return Err(Error::NotImplemented);
        }

        // Use timer 0 for the Timer trait's one-shot mode.
        // Compute the absolute comparator value = counter + ticks.
        let target = self.read_counter().wrapping_add(ticks);

        // Read existing config to preserve the route, then set
        // one-shot + interrupt enable.
        let cfg = self.read64(reg::timer_config(0));
        let preserved_route = cfg & TIMER_ROUTE_MASK;

        let new_cfg = TIMER_INT_ENABLE | preserved_route;
        self.write64(reg::timer_config(0), new_cfg);
        self.write64(reg::timer_comparator(0), target);

        Ok(())
    }

    fn set_periodic(&mut self, ticks: u64) -> Result<()> {
        if self.timer_count == 0 {
            return Err(Error::NotImplemented);
        }

        let timer = self.timers[0].as_ref().ok_or(Error::NotImplemented)?;

        if !timer.periodic_capable {
            return Err(Error::NotImplemented);
        }

        // Read existing config to preserve the route.
        let cfg = self.read64(reg::timer_config(0));
        let preserved_route = cfg & TIMER_ROUTE_MASK;

        let new_cfg = TIMER_INT_ENABLE | TIMER_PERIODIC | TIMER_VAL_SET | preserved_route;
        self.write64(reg::timer_config(0), new_cfg);
        self.write64(reg::timer_comparator(0), ticks);

        Ok(())
    }

    fn stop(&mut self) -> Result<()> {
        if self.timer_count == 0 {
            return Ok(());
        }
        self.disable_timer(0)
    }
}
