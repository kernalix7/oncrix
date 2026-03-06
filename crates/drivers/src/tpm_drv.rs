// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Trusted Platform Module (TPM) 2.0 driver (TIS/MMIO interface).
//!
//! Implements the TPM 2.0 PC Client Platform Firmware Profile's
//! TPM Interface Specification (TIS) for communication via MMIO.
//!
//! Key operations:
//! - Locality management and access request/grant
//! - Command transmission via the data FIFO
//! - Response reception and status polling
//! - PCR extend operations
//!
//! Reference: TCG PC Client Platform TPM Profile Specification v1.04 (TPM2);
//! TCG TPM 2.0 Part 3 — Commands (TCG-TSS-ESYS).

use oncrix_lib::{Error, Result};

// ── TIS MMIO Base and Locality Offsets ────────────────────────────────────

/// TIS MMIO base (platform-defined; typically 0xFED40000 on x86).
pub const TIS_BASE: usize = 0xFED40000;
/// Size of each locality's register window.
pub const TIS_LOCALITY_SIZE: usize = 0x1000;

/// Return the MMIO base for the given locality (0-4).
pub fn locality_base(base: usize, locality: u8) -> usize {
    base + (locality as usize) * TIS_LOCALITY_SIZE
}

// ── TIS Register Offsets (within a locality window) ───────────────────────

/// TPM Access register (R/W).
pub const TPM_ACCESS: u32 = 0x000;
/// TPM Interrupt Enable register.
pub const TPM_INT_ENABLE: u32 = 0x008;
/// TPM Interrupt Vector.
pub const TPM_INT_VECTOR: u32 = 0x00C;
/// TPM Interrupt Status.
pub const TPM_INT_STATUS: u32 = 0x010;
/// TPM FIFO Interface Capability.
pub const TPM_INTF_CAPS: u32 = 0x014;
/// TPM Status register (R/W).
pub const TPM_STS: u32 = 0x018;
/// TPM Data FIFO (R/W).
pub const TPM_DATA_FIFO: u32 = 0x024;
/// TPM Interface ID (TIS 1.3+).
pub const TPM_INTF_ID: u32 = 0x030;
/// TPM DID/VID.
pub const TPM_DID_VID: u32 = 0xF00;
/// TPM Revision ID.
pub const TPM_RID: u32 = 0xF04;

// ── TPM Access Register Bits ───────────────────────────────────────────────

/// tpmEstablished — indicates TPM_ESTABLISHMENT is set.
pub const ACCESS_ESTABLISHMENT: u8 = 1 << 0;
/// requestUse — locality is requesting access.
pub const ACCESS_REQUEST_USE: u8 = 1 << 1;
/// pendingRequest — another locality is pending.
pub const ACCESS_PENDING_REQ: u8 = 1 << 2;
/// Seize — forcibly take access (higher locality).
pub const ACCESS_SEIZE: u8 = 1 << 3;
/// beenSeized — this locality was seized.
pub const ACCESS_BEEN_SEIZED: u8 = 1 << 4;
/// activeLocality — this locality is active.
pub const ACCESS_ACTIVE: u8 = 1 << 5;
/// Valid bit.
pub const ACCESS_VALID: u8 = 1 << 7;

// ── TPM Status Register Bits ───────────────────────────────────────────────

/// responseRetry — resubmit last command.
pub const STS_RESPONSE_RETRY: u32 = 1 << 1;
/// selfTestDone — self-test complete.
pub const STS_SELF_TEST_DONE: u32 = 1 << 2;
/// Expect — TPM expects more data.
pub const STS_EXPECT: u32 = 1 << 3;
/// dataAvail — response data available.
pub const STS_DATA_AVAIL: u32 = 1 << 4;
/// Go — execute command.
pub const STS_GO: u32 = 1 << 5;
/// commandReady — TPM is ready for a new command.
pub const STS_COMMAND_READY: u32 = 1 << 6;
/// stsValid — STS register is valid.
pub const STS_VALID: u32 = 1 << 7;
/// burstCount field (bits 8-23).
pub const STS_BURST_COUNT_SHIFT: u32 = 8;
pub const STS_BURST_COUNT_MASK: u32 = 0xFFFF;

/// Maximum TPM command/response buffer size.
pub const TPM_MAX_CMD_LEN: usize = 4096;
/// Command header size (tag + size + code).
pub const TPM_HEADER_LEN: usize = 10;

// ── MMIO helpers ───────────────────────────────────────────────────────────

#[inline]
unsafe fn read8(base: usize, offset: u32) -> u8 {
    // SAFETY: caller guarantees base+offset is valid TIS MMIO.
    unsafe { core::ptr::read_volatile((base + offset as usize) as *const u8) }
}

#[inline]
unsafe fn write8(base: usize, offset: u32, val: u8) {
    // SAFETY: caller guarantees base+offset is valid TIS MMIO.
    unsafe { core::ptr::write_volatile((base + offset as usize) as *mut u8, val) }
}

#[inline]
unsafe fn read32(base: usize, offset: u32) -> u32 {
    // SAFETY: caller guarantees base+offset is valid TIS MMIO.
    unsafe { core::ptr::read_volatile((base + offset as usize) as *const u32) }
}

#[inline]
unsafe fn write32(base: usize, offset: u32, val: u32) {
    // SAFETY: caller guarantees base+offset is valid TIS MMIO.
    unsafe { core::ptr::write_volatile((base + offset as usize) as *mut u32, val) }
}

// ── TPM Driver ─────────────────────────────────────────────────────────────

/// TPM 2.0 TIS driver.
pub struct Tpm {
    /// TIS MMIO base address.
    mmio_base: usize,
    /// Active locality (0-4).
    locality: u8,
    /// VID and DID read at init.
    vid: u16,
    did: u16,
}

impl Tpm {
    /// Create a new TPM driver.
    ///
    /// # Safety
    /// `mmio_base` must be the TIS MMIO base address (e.g., 0xFED40000),
    /// mapped with device memory attributes and accessible by the kernel.
    pub unsafe fn new(mmio_base: usize, locality: u8) -> Self {
        Self {
            mmio_base,
            locality,
            vid: 0,
            did: 0,
        }
    }

    /// Return the locality MMIO base.
    fn loc_base(&self) -> usize {
        locality_base(self.mmio_base, self.locality)
    }

    /// Request access to the TPM locality.
    pub fn request_locality(&self) -> Result<()> {
        let base = self.loc_base();
        // SAFETY: TPM_ACCESS register in locality window.
        unsafe { write8(base, TPM_ACCESS, ACCESS_REQUEST_USE) }
        for _ in 0..1_000_000 {
            let a = unsafe { read8(base, TPM_ACCESS) };
            if a & ACCESS_ACTIVE != 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Release the active locality.
    pub fn release_locality(&self) {
        let base = self.loc_base();
        // SAFETY: writing ACCESS_ACTIVE clears the locality in TIS.
        unsafe { write8(base, TPM_ACCESS, ACCESS_ACTIVE) }
    }

    /// Poll until TPM status matches expected bits.
    fn wait_status(&self, mask: u32, expected: u32) -> Result<()> {
        let base = self.loc_base();
        for _ in 0..1_000_000 {
            let sts = unsafe { read32(base, TPM_STS) };
            if sts & STS_VALID != 0 && (sts & mask) == expected {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Put the TPM into command-ready state.
    fn set_command_ready(&self) -> Result<()> {
        let base = self.loc_base();
        // Writing STS_COMMAND_READY transitions to commandReady.
        // SAFETY: TPM_STS write to set command-ready state.
        unsafe { write32(base, TPM_STS, STS_COMMAND_READY) }
        self.wait_status(STS_COMMAND_READY, STS_COMMAND_READY)
    }

    /// Write a command buffer to the TPM FIFO.
    fn write_command(&self, cmd: &[u8]) -> Result<()> {
        let base = self.loc_base();
        for &byte in cmd {
            // Wait until TPM expects more data.
            self.wait_status(STS_EXPECT, STS_EXPECT)?;
            // SAFETY: TPM_DATA_FIFO write.
            unsafe { write8(base, TPM_DATA_FIFO, byte) }
        }
        Ok(())
    }

    /// Start command execution.
    fn execute(&self) {
        let base = self.loc_base();
        // SAFETY: STS_GO triggers command execution.
        unsafe { write32(base, TPM_STS, STS_GO) }
    }

    /// Read the response from the TPM FIFO into `buf`.
    fn read_response(&self, buf: &mut [u8]) -> Result<usize> {
        let base = self.loc_base();
        self.wait_status(STS_DATA_AVAIL, STS_DATA_AVAIL)?;
        let mut n = 0;
        while n < buf.len() {
            let sts = unsafe { read32(base, TPM_STS) };
            if sts & STS_VALID == 0 {
                return Err(Error::IoError);
            }
            if sts & STS_DATA_AVAIL == 0 {
                break;
            }
            buf[n] = unsafe { read8(base, TPM_DATA_FIFO) };
            n += 1;
        }
        Ok(n)
    }

    /// Initialize the TPM: request locality and read VID/DID.
    pub fn init(&mut self) -> Result<()> {
        self.request_locality()?;
        let base = self.loc_base();
        // SAFETY: TPM_DID_VID is a read-only identification register.
        let did_vid = unsafe { read32(base, TPM_DID_VID) };
        self.vid = did_vid as u16;
        self.did = (did_vid >> 16) as u16;
        Ok(())
    }

    /// Transmit a TPM command and receive the response.
    pub fn transmit(&self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize> {
        if cmd.len() < TPM_HEADER_LEN || rsp.len() < TPM_HEADER_LEN {
            return Err(Error::InvalidArgument);
        }
        self.set_command_ready()?;
        self.write_command(cmd)?;
        self.execute();
        self.read_response(rsp)
    }

    /// Return the TPM Vendor ID.
    pub fn vendor_id(&self) -> u16 {
        self.vid
    }

    /// Return the TPM Device ID.
    pub fn device_id(&self) -> u16 {
        self.did
    }

    /// Return the active locality.
    pub fn locality(&self) -> u8 {
        self.locality
    }

    /// Read the TPM status register.
    pub fn status(&self) -> u32 {
        let base = self.loc_base();
        // SAFETY: TPM_STS read.
        unsafe { read32(base, TPM_STS) }
    }
}
