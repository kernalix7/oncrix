// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Symmetric Multiprocessing (SMP) boot for x86_64.
//!
//! Implements the AP (Application Processor) startup sequence using
//! the INIT-SIPI-SIPI protocol. The BSP (Bootstrap Processor) sends
//! INIT and STARTUP IPIs to each AP via the Local APIC's Interrupt
//! Command Register (ICR).
//!
//! Each AP boots in real mode at the SIPI vector address, transitions
//! through protected mode to long mode, then enters the kernel's AP
//! entry point.
//!
//! Reference: Intel SDM Vol. 3A §8.4 "Multiple-Processor (MP)
//! Initialization", Linux `arch/x86/kernel/smpboot.c`.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering};
use oncrix_hal::arch::x86_64::apic::APIC_BASE;

/// Maximum number of CPUs supported.
pub const MAX_CPUS: usize = 64;

/// Per-CPU data structure.
///
/// Each CPU has its own instance, indexed by CPU index.
/// This holds CPU-local state needed by the scheduler,
/// interrupt handlers, and other subsystems.
#[derive(Debug, Clone, Copy)]
pub struct PerCpuData {
    /// APIC ID of this CPU.
    pub apic_id: u8,
    /// Whether this CPU has completed initialization.
    pub online: bool,
    /// CPU index (0 = BSP, 1..N = APs in boot order).
    pub cpu_index: u32,
    /// Current idle state (for power management).
    pub idle: bool,
}

impl PerCpuData {
    /// Create uninitialized per-CPU data.
    const fn empty() -> Self {
        Self {
            apic_id: 0,
            online: false,
            cpu_index: 0,
            idle: true,
        }
    }
}

/// Wrapper for global per-CPU data.
///
/// SAFETY: During early boot, only the BSP accesses PER_CPU. After
/// SMP boot, each CPU only writes to its own slot. Cross-CPU reads
/// happen only after writes are complete (sequenced by INIT-SIPI).
struct PerCpuArray(UnsafeCell<[PerCpuData; MAX_CPUS]>);

// SAFETY: Access is controlled by the SMP boot protocol — BSP writes
// during single-threaded boot, APs write only their own slots.
unsafe impl Sync for PerCpuArray {}

static PER_CPU: PerCpuArray = PerCpuArray(UnsafeCell::new({
    const EMPTY: PerCpuData = PerCpuData::empty();
    [EMPTY; MAX_CPUS]
}));

/// Number of CPUs that have come online.
static CPUS_ONLINE: AtomicU32 = AtomicU32::new(0);

/// Local APIC ICR (Interrupt Command Register) offsets.
mod icr {
    /// ICR low 32 bits — offset 0x300.
    pub const ICR_LO: u32 = 0x300;
    /// ICR high 32 bits (destination) — offset 0x310.
    pub const ICR_HI: u32 = 0x310;

    /// Delivery mode: INIT.
    pub const INIT: u32 = 0b101 << 8;
    /// Delivery mode: STARTUP (SIPI).
    pub const STARTUP: u32 = 0b110 << 8;

    /// Level assert (bit 14).
    pub const LEVEL_ASSERT: u32 = 1 << 14;
    /// Level de-assert (bit 14 clear, bit 15 set for trigger mode).
    pub const LEVEL_DEASSERT: u32 = 0;
    /// Trigger mode: level (bit 15).
    pub const TRIGGER_LEVEL: u32 = 1 << 15;
}

/// Write to a Local APIC register.
///
/// # Safety
///
/// Caller must ensure the APIC is mapped at `APIC_BASE`.
unsafe fn apic_write(offset: u32, value: u32) {
    let addr = (APIC_BASE + offset as u64) as *mut u32;
    // SAFETY: APIC MMIO is identity-mapped during boot.
    unsafe {
        core::ptr::write_volatile(addr, value);
    }
}

/// Read from a Local APIC register.
///
/// # Safety
///
/// Caller must ensure the APIC is mapped at `APIC_BASE`.
unsafe fn apic_read(offset: u32) -> u32 {
    let addr = (APIC_BASE + offset as u64) as *const u32;
    // SAFETY: APIC MMIO is identity-mapped during boot.
    unsafe { core::ptr::read_volatile(addr) }
}

/// Wait for the ICR delivery status to clear (delivery complete).
///
/// # Safety
///
/// Caller must ensure APIC is accessible.
unsafe fn wait_icr_idle() {
    // Bit 12 of ICR_LO = delivery status (0 = idle, 1 = pending).
    loop {
        // SAFETY: Reading a well-known APIC register.
        if unsafe { apic_read(icr::ICR_LO) } & (1 << 12) == 0 {
            break;
        }
        core::hint::spin_loop();
    }
}

/// Send an INIT IPI to a specific APIC ID.
///
/// # Safety
///
/// Must only be called by the BSP during early boot.
unsafe fn send_init_ipi(apic_id: u8) {
    // SAFETY: BSP APIC access during controlled SMP boot sequence.
    unsafe {
        apic_write(icr::ICR_HI, (apic_id as u32) << 24);
        apic_write(
            icr::ICR_LO,
            icr::INIT | icr::LEVEL_ASSERT | icr::TRIGGER_LEVEL,
        );
        wait_icr_idle();

        // De-assert INIT.
        apic_write(icr::ICR_HI, (apic_id as u32) << 24);
        apic_write(
            icr::ICR_LO,
            icr::INIT | icr::LEVEL_DEASSERT | icr::TRIGGER_LEVEL,
        );
        wait_icr_idle();
    }
}

/// Send a STARTUP IPI (SIPI) to a specific APIC ID.
///
/// `vector_page` is the physical page number (0-255) where the AP
/// trampoline code is located. The AP starts executing at
/// `vector_page * 0x1000` in real mode.
///
/// # Safety
///
/// Must only be called by the BSP during controlled SMP boot.
/// The trampoline page must contain valid real-mode boot code.
unsafe fn send_sipi(apic_id: u8, vector_page: u8) {
    // SAFETY: BSP APIC access during controlled SMP boot sequence.
    unsafe {
        apic_write(icr::ICR_HI, (apic_id as u32) << 24);
        apic_write(icr::ICR_LO, icr::STARTUP | vector_page as u32);
        wait_icr_idle();
    }
}

/// Delay loop (approximate microseconds).
///
/// Uses a busy loop calibrated to ~1 µs per iteration on modern
/// CPUs. This is intentionally imprecise — only used during the
/// INIT-SIPI-SIPI timing requirements.
fn delay_us(us: u64) {
    let iterations = us * 100;
    for _ in 0..iterations {
        core::hint::spin_loop();
    }
}

/// Boot a single Application Processor.
///
/// Sends the INIT-SIPI-SIPI sequence per Intel SDM §8.4.4.1:
/// 1. Send INIT IPI
/// 2. Wait 10ms
/// 3. Send SIPI
/// 4. Wait 200µs
/// 5. Send SIPI (retry)
/// 6. Wait 200µs
///
/// # Safety
///
/// Must be called by the BSP. The trampoline page must be set up
/// with valid AP boot code before calling this function.
pub unsafe fn boot_ap(apic_id: u8, trampoline_page: u8) {
    // SAFETY: Controlled SMP boot sequence called by BSP.
    unsafe {
        send_init_ipi(apic_id);
        delay_us(10_000);
        send_sipi(apic_id, trampoline_page);
        delay_us(200);
        send_sipi(apic_id, trampoline_page);
        delay_us(200);
    }
}

/// Get a raw pointer to a per-CPU slot.
fn per_cpu_ptr(index: usize) -> *mut PerCpuData {
    // SAFETY: Index is bounds-checked by callers.
    let arr_ptr = PER_CPU.0.get() as *mut PerCpuData;
    // SAFETY: Pointer arithmetic within the array.
    unsafe { arr_ptr.add(index) }
}

/// Initialize the BSP's per-CPU data.
///
/// Must be called once during early boot before starting APs.
pub fn init_bsp(bsp_apic_id: u8) {
    // SAFETY: Single-threaded during early boot, no APs running yet.
    unsafe {
        per_cpu_ptr(0).write(PerCpuData {
            apic_id: bsp_apic_id,
            online: true,
            cpu_index: 0,
            idle: false,
        });
    }
    CPUS_ONLINE.store(1, Ordering::Release);
}

/// Boot all Application Processors found in the MADT.
///
/// `local_apics` is the array of Local APIC entries from ACPI MADT.
/// `bsp_apic_id` is the BSP's APIC ID (skip it when booting APs).
/// `trampoline_page` is the physical page number for the AP boot code.
///
/// Returns the number of APs successfully booted.
///
/// # Safety
///
/// Must be called by the BSP after setting up the trampoline code.
pub unsafe fn boot_all_aps(
    local_apics: &[oncrix_hal::acpi::MadtLocalApic],
    bsp_apic_id: u8,
    trampoline_page: u8,
) -> u32 {
    let mut ap_count = 0u32;

    for lapic in local_apics {
        if lapic.apic_id == bsp_apic_id {
            continue;
        }

        // Skip disabled CPUs (flag bit 0 = enabled).
        if lapic.flags & 0x1 == 0 && lapic.flags & 0x2 == 0 {
            continue;
        }

        let cpu_idx = ap_count as usize + 1;
        if cpu_idx >= MAX_CPUS {
            break;
        }

        // SAFETY: No APs are running yet; we're the only writer.
        unsafe {
            per_cpu_ptr(cpu_idx).write(PerCpuData {
                apic_id: lapic.apic_id,
                online: false,
                cpu_index: cpu_idx as u32,
                idle: true,
            });
        }

        // SAFETY: Controlled SMP boot sequence.
        unsafe {
            boot_ap(lapic.apic_id, trampoline_page);
        }

        ap_count += 1;
    }

    CPUS_ONLINE.store(1 + ap_count, Ordering::Release);
    ap_count
}

/// Mark an AP as online (called by AP entry code).
///
/// # Safety
///
/// Must be called exactly once by each AP after initialization.
pub unsafe fn ap_mark_online(apic_id: u8) {
    for i in 0..MAX_CPUS {
        // SAFETY: Each AP writes only to its own slot, identified by
        // apic_id match. Reads of other slots are safe because the
        // BSP has already written them before sending the SIPI.
        let ptr = per_cpu_ptr(i);
        unsafe {
            if (*ptr).apic_id == apic_id && !(*ptr).online {
                (*ptr).online = true;
                return;
            }
        }
    }
}

/// Get the number of online CPUs.
pub fn online_cpus() -> u32 {
    CPUS_ONLINE.load(Ordering::Acquire)
}

/// Get per-CPU data for a given CPU index.
///
/// # Safety
///
/// The caller must ensure `cpu_index < MAX_CPUS` and the CPU
/// has been initialized.
pub unsafe fn get_per_cpu(cpu_index: usize) -> PerCpuData {
    // SAFETY: Caller ensures valid index and initialized state.
    unsafe { per_cpu_ptr(cpu_index).read() }
}

/// Get the current CPU's APIC ID (reads from the Local APIC).
pub fn current_apic_id() -> u8 {
    // SAFETY: Reading APIC ID register; APIC is always mapped.
    unsafe { (apic_read(0x020) >> 24) as u8 }
}
