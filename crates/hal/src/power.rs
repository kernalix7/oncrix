// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ACPI power management (shutdown, reboot, sleep).
//!
//! Provides FADT parsing, ACPI PM timer access, and system
//! power-state transitions (S5 shutdown, keyboard/ACPI/triple-fault
//! reboot). All port I/O is x86_64-specific and gated accordingly.

use oncrix_lib::{Error, Result};

use crate::acpi::{SdtHeader, validate_sdt_checksum};

// ── Port I/O helpers ──────────────────────────────────────────

/// Read a byte from an I/O port.
///
/// Wraps the x86_64 `in` instruction for 8-bit port reads.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: Ring-0 I/O port access. The caller is responsible
    // for ensuring the port address is valid.
    unsafe {
        core::arch::asm!(
            "in al, dx",
            out("al") value,
            in("dx") port,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}

/// Write a byte to an I/O port.
///
/// Wraps the x86_64 `out` instruction for 8-bit port writes.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn outb(port: u16, value: u8) {
    // SAFETY: Ring-0 I/O port access. The caller is responsible
    // for ensuring the port address and value are valid.
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") port,
            in("al") value,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Read a 16-bit word from an I/O port.
///
/// Wraps the x86_64 `in` instruction for 16-bit port reads.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn inw(port: u16) -> u16 {
    let value: u16;
    // SAFETY: Ring-0 I/O port access. The caller is responsible
    // for ensuring the port address is valid.
    unsafe {
        core::arch::asm!(
            "in ax, dx",
            out("ax") value,
            in("dx") port,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}

/// Write a 16-bit word to an I/O port.
///
/// Wraps the x86_64 `out` instruction for 16-bit port writes.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn outw(port: u16, value: u16) {
    // SAFETY: Ring-0 I/O port access. The caller is responsible
    // for ensuring the port address and value are valid.
    unsafe {
        core::arch::asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") value,
            options(nomem, nostack, preserves_flags),
        );
    }
}

/// Read a 32-bit doubleword from an I/O port.
///
/// Wraps the x86_64 `in` instruction for 32-bit port reads.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn inl(port: u16) -> u32 {
    let value: u32;
    // SAFETY: Ring-0 I/O port access. The caller is responsible
    // for ensuring the port address is valid.
    unsafe {
        core::arch::asm!(
            "in eax, dx",
            out("eax") value,
            in("dx") port,
            options(nomem, nostack, preserves_flags),
        );
    }
    value
}

/// Write a 32-bit doubleword to an I/O port.
///
/// Wraps the x86_64 `out` instruction for 32-bit port writes.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn outl(port: u16, value: u32) {
    // SAFETY: Ring-0 I/O port access. The caller is responsible
    // for ensuring the port address and value are valid.
    unsafe {
        core::arch::asm!(
            "out dx, eax",
            in("dx") port,
            in("eax") value,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// ── Power state / reset enums ─────────────────────────────────

/// ACPI system power states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerState {
    /// S0 — Working (fully running).
    S0Working,
    /// S1 — Standby (CPU caches flushed, CPU stopped).
    S1Standby,
    /// S3 — Suspend to RAM (context saved in memory).
    S3Suspend,
    /// S4 — Hibernate (context saved to disk).
    S4Hibernate,
    /// S5 — Soft-off (mechanical off, except wake logic).
    S5SoftOff,
}

/// System reset method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetMethod {
    /// Send 0xFE to the PS/2 keyboard controller (port 0x64).
    Keyboard,
    /// Write the FADT reset value to the ACPI RESET_REG.
    AcpiReset,
    /// Load a null IDT and trigger an interrupt (triple fault).
    TripleFault,
}

// ── FADT ──────────────────────────────────────────────────────

/// FADT signature: `"FACP"`.
const FADT_SIGNATURE: [u8; 4] = *b"FACP";

/// Partial ACPI FADT — power-management-relevant fields only.
///
/// Field offsets follow the ACPI 6.5 specification, Table 5-33.
#[derive(Debug, Clone, Copy)]
pub struct AcpiFadt {
    /// Port address of the SMI command port.
    pub smi_cmd: u32,
    /// Value to write to `smi_cmd` to enable ACPI mode.
    pub acpi_enable: u8,
    /// Value to write to `smi_cmd` to disable ACPI mode.
    pub acpi_disable: u8,
    /// PM1a Event Block I/O port.
    pub pm1a_evt_blk: u32,
    /// PM1b Event Block I/O port (0 if unsupported).
    pub pm1b_evt_blk: u32,
    /// PM1a Control Block I/O port.
    pub pm1a_cnt_blk: u32,
    /// PM1b Control Block I/O port (0 if unsupported).
    pub pm1b_cnt_blk: u32,
    /// Length in bytes of PM1 event registers.
    pub pm1_evt_len: u8,
    /// Length in bytes of PM1 control registers.
    pub pm1_cnt_len: u8,
    /// PM timer I/O port base address.
    pub pm_tmr_blk: u32,
    /// PM timer length (4 = 24-bit, can also be 32-bit).
    pub pm_tmr_len: u8,
    /// FADT flags (bit 8: TMR_VAL_EXT — 32-bit timer).
    pub flags: u32,
    /// Physical address of the ACPI reset register.
    pub reset_reg_addr: u64,
    /// Value to write to the reset register.
    pub reset_value: u8,
    /// SLP_TYPa value for S5 (soft-off).
    pub slp_typa_s5: u8,
    /// SLP_TYPb value for S5 (soft-off).
    pub slp_typb_s5: u8,
}

/// Minimum FADT size needed to extract power-management fields.
///
/// We need up to offset 129 (reset value) at minimum, but the
/// SLP_TYP values come from the DSDT \_S5 object. For simplicity
/// we require at least 129 bytes of FADT data and default the
/// SLP_TYP fields to 0 (caller can override from DSDT parsing).
const FADT_MIN_SIZE: usize = 129;

/// Parse an ACPI FADT (Fixed ACPI Description Table).
///
/// Extracts power-management fields from raw table bytes.
/// The `data` slice must include the full SDT header.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if the data is too short,
/// the signature does not match, or the checksum fails.
pub fn parse_fadt(data: &[u8]) -> Result<AcpiFadt> {
    if data.len() < FADT_MIN_SIZE {
        return Err(Error::InvalidArgument);
    }

    // SAFETY: data.len() >= SDT_HEADER_SIZE verified (FADT_MIN_SIZE > SDT_HEADER_SIZE).
    let header = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const SdtHeader) };

    if header.signature != FADT_SIGNATURE {
        return Err(Error::InvalidArgument);
    }

    let length = header.length as usize;
    if !validate_sdt_checksum(data, length.min(data.len())) {
        return Err(Error::InvalidArgument);
    }

    // Helper: read an unaligned value at a byte offset.
    // SAFETY (per call-site): bounds are checked against data.len()
    // which was verified >= FADT_MIN_SIZE above. All offsets used
    // below are < FADT_MIN_SIZE.
    let r32 = |off: usize| -> u32 {
        // SAFETY: off + 4 <= FADT_MIN_SIZE <= data.len().
        unsafe { core::ptr::read_unaligned(data.as_ptr().add(off) as *const u32) }
    };

    let r8 = |off: usize| -> u8 { data[off] };

    // FADT field offsets (ACPI spec Table 5-33):
    //  36: FIRMWARE_CTRL (u32)     48: SMI_CMD (u32)
    //  52: ACPI_ENABLE (u8)        53: ACPI_DISABLE (u8)
    //  56: PM1a_EVT_BLK (u32)     60: PM1b_EVT_BLK (u32)
    //  64: PM1a_CNT_BLK (u32)     68: PM1b_CNT_BLK (u32)
    //  76: PM_TMR_BLK (u32)
    //  88: PM1_EVT_LEN (u8)       89: PM1_CNT_LEN (u8)
    //  91: PM_TMR_LEN (u8)
    // 112: FLAGS (u32)
    // 116: RESET_REG (12-byte GAS — address at offset 4 of GAS)
    // 128: RESET_VALUE (u8)

    let reset_reg_addr = if data.len() >= 128 {
        // SAFETY: 120 + 8 = 128 <= data.len().
        unsafe { core::ptr::read_unaligned(data.as_ptr().add(120) as *const u64) }
    } else {
        0
    };

    Ok(AcpiFadt {
        smi_cmd: r32(48),
        acpi_enable: r8(52),
        acpi_disable: r8(53),
        pm1a_evt_blk: r32(56),
        pm1b_evt_blk: r32(60),
        pm1a_cnt_blk: r32(64),
        pm1b_cnt_blk: r32(68),
        pm_tmr_blk: r32(76),
        pm1_evt_len: r8(88),
        pm1_cnt_len: r8(89),
        pm_tmr_len: r8(91),
        flags: r32(112),
        reset_reg_addr,
        reset_value: r8(128),
        // SLP_TYP values must be extracted from DSDT \_S5 object.
        // Default to 0; the caller should override after DSDT parsing.
        slp_typa_s5: 0,
        slp_typb_s5: 0,
    })
}

// ── PM Timer ──────────────────────────────────────────────────

/// PM timer frequency: 3.579545 MHz (ACPI-defined).
const PM_TIMER_FREQ_HZ: u64 = 3_579_545;

/// Mask for a 24-bit PM timer.
const PM_TIMER_MASK_24: u32 = 0x00FF_FFFF;

/// Mask for a 32-bit PM timer.
const PM_TIMER_MASK_32: u32 = 0xFFFF_FFFF;

/// ACPI PM Timer for precision microsecond-level timing.
///
/// The PM timer ticks at exactly 3.579545 MHz and is available
/// on all ACPI-compliant systems. It is either 24-bit or 32-bit
/// wide, depending on the FADT `TMR_VAL_EXT` flag (bit 8).
#[derive(Debug, Clone, Copy)]
pub struct AcpiPmTimer {
    /// I/O port for the PM timer.
    pub port: u16,
    /// Whether the timer is 32-bit (vs. 24-bit).
    pub is_32bit: bool,
}

impl AcpiPmTimer {
    /// Create a PM timer from FADT fields.
    ///
    /// Returns `None` if the FADT does not advertise a PM timer
    /// (pm_tmr_blk == 0 or pm_tmr_len < 4).
    pub fn from_fadt(fadt: &AcpiFadt) -> Option<Self> {
        if fadt.pm_tmr_blk == 0 || fadt.pm_tmr_len < 4 {
            return None;
        }
        // FADT flags bit 8: TMR_VAL_EXT (1 = 32-bit timer).
        let is_32bit = fadt.flags & (1 << 8) != 0;
        Some(Self {
            port: fadt.pm_tmr_blk as u16,
            is_32bit,
        })
    }

    /// Read the current PM timer tick count.
    #[cfg(target_arch = "x86_64")]
    pub fn read(&self) -> u32 {
        let raw = inl(self.port);
        if self.is_32bit {
            raw
        } else {
            raw & PM_TIMER_MASK_24
        }
    }

    /// Compute elapsed microseconds between two timer readings.
    ///
    /// Handles wrap-around for both 24-bit and 32-bit timers.
    pub fn elapsed_us(&self, start: u32, end: u32) -> u64 {
        let mask = if self.is_32bit {
            PM_TIMER_MASK_32 as u64
        } else {
            PM_TIMER_MASK_24 as u64
        };
        let ticks = ((end as u64).wrapping_sub(start as u64)) & mask;
        // microseconds = ticks * 1_000_000 / PM_TIMER_FREQ_HZ
        ticks.saturating_mul(1_000_000) / PM_TIMER_FREQ_HZ
    }
}

// ── Power Manager ─────────────────────────────────────────────

/// SLP_EN bit position in PM1_CNT register (bit 13).
const SLP_EN_BIT: u16 = 1 << 13;

/// ACPI power manager.
///
/// Manages system power state transitions using FADT data. Must
/// be initialised with valid FADT table bytes before use.
#[derive(Debug)]
pub struct PowerManager {
    /// Parsed FADT (None if not yet initialised).
    pub fadt: Option<AcpiFadt>,
    /// Whether ACPI SCI mode is enabled.
    pub acpi_enabled: bool,
}

impl Default for PowerManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PowerManager {
    /// Create an uninitialised power manager.
    pub const fn new() -> Self {
        Self {
            fadt: None,
            acpi_enabled: false,
        }
    }

    /// Initialise the power manager from raw FADT table bytes.
    ///
    /// Parses the FADT and enables ACPI mode if the system is
    /// still in legacy mode (SMI_CMD != 0 and ACPI not yet on).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if FADT parsing fails.
    #[cfg(target_arch = "x86_64")]
    pub fn init(fadt_data: &[u8]) -> Result<Self> {
        let fadt = parse_fadt(fadt_data)?;
        let mut mgr = Self {
            fadt: Some(fadt),
            acpi_enabled: false,
        };

        // Enable ACPI mode if needed (SMI_CMD != 0 means the
        // platform supports the legacy-to-ACPI transition).
        if fadt.smi_cmd != 0 && fadt.acpi_enable != 0 {
            // Check PM1a_CNT_BLK bit 0 (SCI_EN).
            let pm1a = inw(fadt.pm1a_cnt_blk as u16);
            if pm1a & 1 == 0 {
                // Not yet in ACPI mode — send ACPI_ENABLE.
                outb(fadt.smi_cmd as u16, fadt.acpi_enable);

                // Spin-wait until SCI_EN is set (bounded).
                let mut retries: u32 = 1_000_000;
                while retries > 0 {
                    let val = inw(fadt.pm1a_cnt_blk as u16);
                    if val & 1 != 0 {
                        break;
                    }
                    retries = retries.saturating_sub(1);
                }
                if retries == 0 {
                    return Err(Error::IoError);
                }
            }
            mgr.acpi_enabled = true;
        } else {
            // ACPI mode already active or no SMI_CMD.
            mgr.acpi_enabled = true;
        }

        Ok(mgr)
    }

    /// Set the SLP_TYP values for S5 (soft-off).
    ///
    /// These are normally extracted from the DSDT \_S5 object.
    /// Call this after DSDT parsing to enable proper shutdown.
    pub fn set_s5_slp_typ(&mut self, slp_typa: u8, slp_typb: u8) {
        if let Some(ref mut fadt) = self.fadt {
            fadt.slp_typa_s5 = slp_typa;
            fadt.slp_typb_s5 = slp_typb;
        }
    }

    /// Return the current system power state.
    ///
    /// Since the kernel is running, this always returns
    /// [`PowerState::S0Working`]. Other states can only be
    /// observed transiently during sleep/shutdown transitions.
    pub fn get_power_state(&self) -> PowerState {
        PowerState::S0Working
    }

    /// Perform an ACPI S5 soft-off shutdown. Does not return.
    ///
    /// Writes `(SLP_TYPa << 10) | SLP_EN` to PM1a_CNT_BLK,
    /// and the same with SLP_TYPb to PM1b_CNT_BLK if present.
    ///
    /// # Panics
    ///
    /// Halts the CPU in a loop if the shutdown command does not
    /// take effect (should never happen on compliant hardware).
    #[cfg(target_arch = "x86_64")]
    pub fn shutdown(&self) -> ! {
        if let Some(ref fadt) = self.fadt {
            let val_a: u16 = (u16::from(fadt.slp_typa_s5) << 10) | SLP_EN_BIT;

            outw(fadt.pm1a_cnt_blk as u16, val_a);

            // If PM1b_CNT_BLK is present, write there too.
            if fadt.pm1b_cnt_blk != 0 {
                let val_b: u16 = (u16::from(fadt.slp_typb_s5) << 10) | SLP_EN_BIT;
                outw(fadt.pm1b_cnt_blk as u16, val_b);
            }
        }

        // If shutdown did not take effect, halt forever.
        halt_loop()
    }

    /// Reboot the system using the specified method.
    ///
    /// Does not return on success. Falls through to a halt loop
    /// if the chosen method fails.
    #[cfg(target_arch = "x86_64")]
    pub fn reboot(&self, method: ResetMethod) -> ! {
        match method {
            ResetMethod::Keyboard => {
                // Send 0xFE to PS/2 keyboard controller command
                // port to pulse the CPU reset line.
                outb(0x64, 0xFE);
            }
            ResetMethod::AcpiReset => {
                if let Some(ref fadt) = self.fadt {
                    if fadt.reset_reg_addr != 0 {
                        // Write reset value to the I/O port specified
                        // by the FADT RESET_REG Generic Address.
                        outb(fadt.reset_reg_addr as u16, fadt.reset_value);
                    }
                }
            }
            ResetMethod::TripleFault => {
                // Load a null IDT (limit=0, base=0) and trigger
                // an interrupt, causing a triple fault -> reset.
                // SAFETY: Deliberately crashing the CPU to reset.
                unsafe {
                    core::arch::asm!(
                        "lidt [{}]",
                        "int3",
                        in(reg) &NULL_IDT_DESC as *const _,
                        options(noreturn),
                    );
                }
            }
        }

        // If the reset method did not take effect, halt.
        halt_loop()
    }
}

/// Null IDT descriptor for triple-fault reboot.
#[cfg(target_arch = "x86_64")]
#[repr(C, packed)]
struct IdtDescriptor {
    /// Limit (0 = empty IDT).
    limit: u16,
    /// Base address (0).
    base: u64,
}

/// A zero-filled IDT descriptor that causes a triple fault when
/// loaded and any interrupt fires.
#[cfg(target_arch = "x86_64")]
static NULL_IDT_DESC: IdtDescriptor = IdtDescriptor { limit: 0, base: 0 };

/// Halt the CPU in an infinite loop (cli + hlt).
#[cfg(target_arch = "x86_64")]
fn halt_loop() -> ! {
    loop {
        // SAFETY: Disabling interrupts and halting is the intended
        // final action after a failed shutdown/reboot attempt.
        unsafe {
            core::arch::asm!("cli", "hlt", options(nomem, nostack),);
        }
    }
}
