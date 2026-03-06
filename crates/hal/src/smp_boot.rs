// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SMP bootstrap protocol for Application Processors (APs).
//!
//! Implements the INIT-SIPI-SIPI sequence to bring APs online,
//! manages per-AP stack allocation, tracks which CPUs are online,
//! and provides the trampoline page setup for 16-bit real-mode
//! AP startup code.
//!
//! # Boot sequence
//!
//! 1. BSP allocates a trampoline page below 1 MiB.
//! 2. BSP copies the 16-bit AP startup stub into the trampoline.
//! 3. BSP sends INIT IPI, waits 10 ms, then two SIPI IPIs to each AP.
//! 4. Each AP executes the trampoline, switches to protected/long mode,
//!    and sets its bit in `AP_ONLINE_MASK`.
//! 5. BSP polls until all expected APs are online.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────────────

/// Maximum number of CPUs (BSP + APs) this driver supports.
pub const MAX_CPUS: usize = 64;

/// Stack size per AP in bytes (16 KiB).
pub const AP_STACK_SIZE: usize = 16 * 1024;

/// Physical address of the trampoline page (must be below 1 MiB,
/// aligned to 4 KiB; 0x8000 is conventional).
pub const TRAMPOLINE_PHYS: u64 = 0x0000_8000;

/// APIC register offset: Interrupt Command Register low (32-bit).
const APIC_ICR_LOW: u64 = 0x300;

/// APIC register offset: Interrupt Command Register high (32-bit).
const APIC_ICR_HIGH: u64 = 0x310;

/// APIC ID register offset.
const APIC_ID_REG: u64 = 0x020;

/// ICR delivery mode: INIT (bits 10:8 = 101).
const ICR_DELIVERY_INIT: u32 = 0x0000_0500;

/// ICR delivery mode: Start-Up (SIPI) (bits 10:8 = 110).
const ICR_DELIVERY_SIPI: u32 = 0x0000_0600;

/// ICR level: Assert.
const ICR_LEVEL_ASSERT: u32 = 1 << 14;

/// ICR trigger mode: Level.
const ICR_TRIGGER_LEVEL: u32 = 1 << 15;

/// ICR destination shorthand: No shorthand (single CPU).
const ICR_DEST_NO_SHORTHAND: u32 = 0x0000_0000;

/// ICR destination shorthand: All excluding self.
const ICR_DEST_ALL_EX_SELF: u32 = 0x000C_0000;

/// Delivery status bit in ICR low: 1 = send pending.
const ICR_SEND_PENDING: u32 = 1 << 12;

/// Timeout iterations waiting for ICR delivery status to clear.
const ICR_SEND_TIMEOUT: u32 = 100_000;

// ── SmpBootState ─────────────────────────────────────────────────────────────

/// Per-CPU SMP boot state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmpBootState {
    /// CPU slot is unused / not present.
    Absent,
    /// CPU has been identified but not yet started.
    Identified,
    /// INIT IPI sent; waiting for AP to execute trampoline.
    InitSent,
    /// SIPI sent; AP is executing early startup code.
    SipiSent,
    /// AP has completed startup and is online.
    Online,
    /// AP startup failed or timed out.
    Failed,
}

// ── CpuInfo ──────────────────────────────────────────────────────────────────

/// Per-CPU descriptor tracked by the SMP boot driver.
#[derive(Debug, Clone, Copy)]
pub struct CpuInfo {
    /// x2APIC / xAPIC ID of this CPU.
    pub apic_id: u32,
    /// Logical CPU index (0 = BSP).
    pub cpu_id: u8,
    /// Current boot state.
    pub state: SmpBootState,
    /// Base virtual address of this AP's stack (0 = not allocated).
    pub stack_base: u64,
}

impl CpuInfo {
    /// Create a new, absent CPU entry.
    pub const fn new() -> Self {
        Self {
            apic_id: 0,
            cpu_id: 0,
            state: SmpBootState::Absent,
            stack_base: 0,
        }
    }
}

impl Default for CpuInfo {
    fn default() -> Self {
        Self::new()
    }
}

// ── SmpBoot ──────────────────────────────────────────────────────────────────

/// SMP bootstrap driver.
///
/// Manages the AP bring-up sequence, per-AP stack memory, and the
/// online CPU bitmask.
pub struct SmpBoot {
    /// Virtual address of the local APIC MMIO region.
    apic_base: u64,
    /// Per-CPU descriptors.
    cpus: [CpuInfo; MAX_CPUS],
    /// Number of CPUs registered (including BSP at index 0).
    cpu_count: usize,
    /// Bitmask of CPUs that have reported online (bit N = CPU N).
    online_mask: u64,
    /// Physical address of the trampoline page.
    trampoline_phys: u64,
}

impl SmpBoot {
    /// Create a new, uninitialised SMP boot driver.
    pub const fn new() -> Self {
        Self {
            apic_base: 0,
            cpus: [const { CpuInfo::new() }; MAX_CPUS],
            cpu_count: 0,
            online_mask: 0,
            trampoline_phys: TRAMPOLINE_PHYS,
        }
    }

    /// Initialise the SMP boot driver.
    ///
    /// `apic_virt_base` is the virtual address of the local APIC MMIO
    /// region (typically mapped at the physical address from IA32_APIC_BASE
    /// MSR with offset 0xFEE0_0000).
    ///
    /// Registers the BSP as CPU 0 and marks it online.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `apic_virt_base` is zero.
    pub fn init(&mut self, apic_virt_base: u64) -> Result<()> {
        if apic_virt_base == 0 {
            return Err(Error::InvalidArgument);
        }
        self.apic_base = apic_virt_base;

        // Read BSP APIC ID.
        let bsp_apic_id = self.read_apic32(APIC_ID_REG) >> 24;

        self.cpus[0] = CpuInfo {
            apic_id: bsp_apic_id,
            cpu_id: 0,
            state: SmpBootState::Online,
            stack_base: 0,
        };
        self.cpu_count = 1;
        self.online_mask = 1;

        Ok(())
    }

    /// Register an AP by its APIC ID.
    ///
    /// `stack_base` is the virtual base address of the AP's pre-allocated
    /// stack region (`AP_STACK_SIZE` bytes).
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no CPU slots remain.
    pub fn register_ap(&mut self, apic_id: u32, stack_base: u64) -> Result<u8> {
        if self.cpu_count >= MAX_CPUS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.cpu_count;
        self.cpus[idx] = CpuInfo {
            apic_id,
            cpu_id: idx as u8,
            state: SmpBootState::Identified,
            stack_base,
        };
        self.cpu_count += 1;
        Ok(idx as u8)
    }

    /// Set up the trampoline page for AP startup.
    ///
    /// Writes a minimal 16-bit real-mode stub at `trampoline_virt` that
    /// initialises segment registers and jumps to the 32/64-bit kernel
    /// entry point `entry_phys`.
    ///
    /// The stub layout (8 bytes):
    /// ```text
    /// [0] cli
    /// [1] xor ax, ax
    /// [3] mov ds, ax
    /// [5] jmp far entry_phys
    /// ```
    ///
    /// In a real implementation the stub would be a proper 16-bit→64-bit
    /// bootstrap; here we write a recognizable sentinel pattern.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `trampoline_virt` is zero.
    pub fn setup_trampoline(&mut self, trampoline_virt: u64, entry_phys: u64) -> Result<()> {
        if trampoline_virt == 0 {
            return Err(Error::InvalidArgument);
        }
        self.trampoline_phys = trampoline_virt; // store for later IPI use

        // Write a minimal real-mode stub: CLI + NOP sled + entry address.
        // SAFETY: Caller guarantees trampoline_virt is a valid, writable
        // mapping of the page at TRAMPOLINE_PHYS (<1 MiB).
        unsafe {
            let p = trampoline_virt as *mut u8;
            p.write_volatile(0xFA); // CLI
            p.add(1).write_volatile(0x90); // NOP
            p.add(2).write_volatile(0x90); // NOP
            p.add(3).write_volatile(0x90); // NOP
            // Store entry_phys as a 64-bit little-endian value at offset 4.
            let entry_ptr = p.add(4) as *mut u64;
            entry_ptr.write_volatile(entry_phys);
        }

        Ok(())
    }

    /// Boot a single AP by sending the INIT-SIPI-SIPI sequence.
    ///
    /// The SIPI vector encodes the trampoline page number
    /// (`trampoline_phys >> 12`, must fit in 8 bits).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `cpu_id` is out of range or
    ///   the AP is not in `Identified` state.
    /// - [`Error::Busy`] if the APIC ICR does not clear the send-pending
    ///   bit within the timeout.
    pub fn boot_ap(&mut self, cpu_id: u8) -> Result<()> {
        let idx = cpu_id as usize;
        if idx == 0 || idx >= self.cpu_count {
            return Err(Error::InvalidArgument);
        }
        if self.cpus[idx].state != SmpBootState::Identified {
            return Err(Error::InvalidArgument);
        }

        let apic_id = self.cpus[idx].apic_id;
        let vector = ((self.trampoline_phys >> 12) & 0xFF) as u32;

        // Send INIT IPI.
        self.send_ipi(
            apic_id,
            ICR_DELIVERY_INIT | ICR_LEVEL_ASSERT | ICR_TRIGGER_LEVEL,
            0,
        )?;
        self.cpus[idx].state = SmpBootState::InitSent;

        // Deassert INIT.
        self.send_ipi(apic_id, ICR_DELIVERY_INIT | ICR_TRIGGER_LEVEL, 0)?;

        // Send first SIPI.
        self.send_ipi(apic_id, ICR_DELIVERY_SIPI | vector, 0)?;
        // Send second SIPI (required by MP spec).
        self.send_ipi(apic_id, ICR_DELIVERY_SIPI | vector, 0)?;
        self.cpus[idx].state = SmpBootState::SipiSent;

        Ok(())
    }

    /// Boot all registered APs in sequence.
    ///
    /// # Errors
    ///
    /// Propagates the first error from [`SmpBoot::boot_ap`].
    pub fn boot_all_aps(&mut self) -> Result<()> {
        let count = self.cpu_count;
        for i in 1..count {
            self.boot_ap(i as u8)?;
        }
        Ok(())
    }

    /// Mark a CPU as online (called by the AP itself after startup).
    ///
    /// Sets the corresponding bit in `online_mask` and updates the
    /// CPU state to `Online`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of range.
    pub fn mark_online(&mut self, cpu_id: u8) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= self.cpu_count {
            return Err(Error::InvalidArgument);
        }
        self.cpus[idx].state = SmpBootState::Online;
        if cpu_id < 64 {
            self.online_mask |= 1u64 << cpu_id;
        }
        Ok(())
    }

    /// Mark a CPU as failed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of range.
    pub fn mark_failed(&mut self, cpu_id: u8) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= self.cpu_count {
            return Err(Error::InvalidArgument);
        }
        self.cpus[idx].state = SmpBootState::Failed;
        Ok(())
    }

    /// Return the bitmask of online CPUs.
    pub fn online_mask(&self) -> u64 {
        self.online_mask
    }

    /// Return the total number of registered CPUs.
    pub fn cpu_count(&self) -> usize {
        self.cpu_count
    }

    /// Return a reference to the `CpuInfo` for the given CPU ID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `cpu_id` is out of range.
    pub fn cpu_info(&self, cpu_id: u8) -> Result<&CpuInfo> {
        let idx = cpu_id as usize;
        if idx >= self.cpu_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.cpus[idx])
    }

    /// Return whether the specified CPU is online.
    pub fn is_online(&self, cpu_id: u8) -> bool {
        if cpu_id >= 64 {
            return false;
        }
        self.online_mask & (1u64 << cpu_id) != 0
    }

    /// Return the number of CPUs currently online.
    pub fn online_count(&self) -> usize {
        self.online_mask.count_ones() as usize
    }

    // ── APIC helpers ─────────────────────────────────────────────────────────

    /// Read a 32-bit xAPIC register.
    fn read_apic32(&self, offset: u64) -> u32 {
        // SAFETY: apic_base is set during init() to a valid MMIO mapping.
        // Offset is a known xAPIC register within the 4 KiB APIC page.
        unsafe {
            let addr = (self.apic_base + offset) as *const u32;
            core::ptr::read_volatile(addr)
        }
    }

    /// Write a 32-bit xAPIC register.
    fn write_apic32(&self, offset: u64, value: u32) {
        // SAFETY: apic_base is set during init() to a valid MMIO mapping.
        // Offset is a known xAPIC register within the 4 KiB APIC page.
        unsafe {
            let addr = (self.apic_base + offset) as *mut u32;
            core::ptr::write_volatile(addr, value);
        }
    }

    /// Send an IPI via the xAPIC ICR.
    ///
    /// Writes `dest_id` to ICR_HIGH, then `icr_low` to ICR_LOW.
    /// Waits for the send-pending bit to clear.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the send-pending bit does not clear.
    fn send_ipi(&self, dest_apic_id: u32, icr_low: u32, _flags: u32) -> Result<()> {
        // Wait for any previous IPI to finish.
        self.wait_icr_idle()?;

        // Write destination APIC ID into ICR high (bits 31:24).
        self.write_apic32(APIC_ICR_HIGH, dest_apic_id << 24);

        // Write the ICR low to trigger the IPI.
        self.write_apic32(APIC_ICR_LOW, ICR_DEST_NO_SHORTHAND | icr_low);

        // Wait for delivery.
        self.wait_icr_idle()
    }

    /// Poll until the ICR send-pending bit clears.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] on timeout.
    fn wait_icr_idle(&self) -> Result<()> {
        for _ in 0..ICR_SEND_TIMEOUT {
            if self.read_apic32(APIC_ICR_LOW) & ICR_SEND_PENDING == 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Send an IPI to all CPUs excluding self (broadcast).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the ICR does not become idle.
    pub fn send_broadcast_ipi(&self, vector: u8) -> Result<()> {
        self.wait_icr_idle()?;
        self.write_apic32(APIC_ICR_LOW, ICR_DEST_ALL_EX_SELF | vector as u32);
        self.wait_icr_idle()
    }
}

impl Default for SmpBoot {
    fn default() -> Self {
        Self::new()
    }
}
