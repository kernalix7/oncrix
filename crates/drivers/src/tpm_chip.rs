// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! TPM (Trusted Platform Module) chip driver.
//!
//! Implements the chip registration layer, command transmit/receive via the
//! TPM Interface Specification (TIS) MMIO FIFO, TPM2 command builders for
//! common operations, locality management, and timeout handling.
//!
//! # Supported TPM2 commands
//!
//! | Command | Builder function |
//! |---|---|
//! | `TPM2_CC_PCR_Read` | [`build_pcr_read`] |
//! | `TPM2_CC_PCR_Extend` | [`build_pcr_extend`] |
//! | `TPM2_CC_GetRandom` | [`build_get_random`] |
//! | `TPM2_CC_GetCapability` | [`build_get_capability`] |
//!
//! # Chip registration
//!
//! [`TpmChip`] encapsulates TIS MMIO state and is managed by
//! [`TpmChipRegistry`], which assigns sequential chip indices.
//!
//! Reference: Linux `drivers/char/tpm/tpm-chip.c`,
//!            TCG PC Client Platform TPM Profile Specification v1.05.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// TIS MMIO constants
// ---------------------------------------------------------------------------

/// Default TIS MMIO base address (x86 ACPI TCPA/TPM2 table value).
pub const TIS_BASE: u64 = 0xFED4_0000;
/// Size of each locality's register window.
pub const TIS_LOCALITY_SIZE: u64 = 0x1000;

/// TPM Access register.
pub const REG_ACCESS: u32 = 0x000;
/// TPM Status register.
pub const REG_STS: u32 = 0x018;
/// TPM Data FIFO register.
pub const REG_FIFO: u32 = 0x024;
/// TPM DID/VID register.
pub const REG_DID_VID: u32 = 0xF00;

/// Access: requestUse.
pub const ACCESS_REQUEST: u8 = 1 << 1;
/// Access: activeLocality.
pub const ACCESS_ACTIVE: u8 = 1 << 5;

/// STS: commandReady.
pub const STS_CMD_READY: u32 = 1 << 6;
/// STS: stsValid.
pub const STS_VALID: u32 = 1 << 7;
/// STS: dataAvail.
pub const STS_DATA_AVAIL: u32 = 1 << 4;
/// STS: Expect.
pub const STS_EXPECT: u32 = 1 << 3;
/// STS: Go.
pub const STS_GO: u32 = 1 << 5;

// ---------------------------------------------------------------------------
// TPM2 command codes
// ---------------------------------------------------------------------------

/// TPM2_CC_GetCapability.
pub const CC_GET_CAPABILITY: u32 = 0x017A;
/// TPM2_CC_GetRandom.
pub const CC_GET_RANDOM: u32 = 0x017B;
/// TPM2_CC_PCR_Read.
pub const CC_PCR_READ: u32 = 0x017E;
/// TPM2_CC_PCR_Extend.
pub const CC_PCR_EXTEND: u32 = 0x0182;

/// TPM_ST_NO_SESSIONS session tag.
pub const TAG_NO_SESSIONS: u16 = 0x8001;

/// SHA-256 algorithm ID.
pub const ALG_SHA256: u16 = 0x000B;
/// SHA-256 digest size in bytes.
pub const SHA256_DIGEST_LEN: usize = 32;

/// Maximum TPM command/response buffer length.
pub const TPM_BUF_LEN: usize = 4096;
/// TPM command header: tag(2) + size(4) + code(4) = 10 bytes.
pub const TPM_HEADER_LEN: usize = 10;

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

#[inline]
unsafe fn rd8(base: u64, off: u32) -> u8 {
    // SAFETY: caller guarantees base+off is a valid TIS MMIO address.
    unsafe { core::ptr::read_volatile((base + u64::from(off)) as *const u8) }
}

#[inline]
unsafe fn wr8(base: u64, off: u32, val: u8) {
    // SAFETY: caller guarantees base+off is a valid TIS MMIO address.
    unsafe { core::ptr::write_volatile((base + u64::from(off)) as *mut u8, val) }
}

#[inline]
unsafe fn rd32(base: u64, off: u32) -> u32 {
    // SAFETY: caller guarantees base+off is a valid TIS MMIO address.
    unsafe { core::ptr::read_volatile((base + u64::from(off)) as *const u32) }
}

#[inline]
unsafe fn wr32(base: u64, off: u32, val: u32) {
    // SAFETY: caller guarantees base+off is a valid TIS MMIO address.
    unsafe { core::ptr::write_volatile((base + u64::from(off)) as *mut u32, val) }
}

// ---------------------------------------------------------------------------
// TPM2 command builders
// ---------------------------------------------------------------------------

/// Writes a big-endian u16 into `buf` at `pos`.
fn put_u16_be(buf: &mut [u8], pos: usize, val: u16) {
    buf[pos] = (val >> 8) as u8;
    buf[pos + 1] = val as u8;
}

/// Writes a big-endian u32 into `buf` at `pos`.
fn put_u32_be(buf: &mut [u8], pos: usize, val: u32) {
    buf[pos] = (val >> 24) as u8;
    buf[pos + 1] = (val >> 16) as u8;
    buf[pos + 2] = (val >> 8) as u8;
    buf[pos + 3] = val as u8;
}

/// Fills the common 10-byte TPM2 command header.
fn write_header(buf: &mut [u8], tag: u16, size: u32, code: u32) {
    put_u16_be(buf, 0, tag);
    put_u32_be(buf, 2, size);
    put_u32_be(buf, 6, code);
}

/// Builds a `TPM2_CC_PCR_Read` command for PCR `index` using SHA-256.
///
/// Returns the number of bytes written into `buf`, or an error if `buf`
/// is too small.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `buf` is shorter than required.
pub fn build_pcr_read(buf: &mut [u8], pcr_index: u32) -> Result<usize> {
    // Header(10) + TPML_PCR_SELECTION: count(4) + alg(2) + sizeofSelect(1)
    // + pcrSelect[3] = 20 bytes total.
    const CMD_LEN: usize = 20;
    if buf.len() < CMD_LEN {
        return Err(Error::InvalidArgument);
    }
    write_header(buf, TAG_NO_SESSIONS, CMD_LEN as u32, CC_PCR_READ);
    // TPML_PCR_SELECTION.count = 1
    put_u32_be(buf, 10, 1);
    // TPMS_PCR_SELECTION.hash = SHA-256
    put_u16_be(buf, 14, ALG_SHA256);
    // sizeofSelect = 3
    buf[16] = 3;
    // PCR select bitmap (3 bytes, bit = pcr_index)
    buf[17] = 0;
    buf[18] = 0;
    buf[19] = 0;
    if pcr_index < 24 {
        buf[17 + (pcr_index / 8) as usize] = 1 << (pcr_index % 8);
    }
    Ok(CMD_LEN)
}

/// Builds a `TPM2_CC_PCR_Extend` command for PCR `index` with a SHA-256 digest.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `digest` is not 32 bytes or `buf`
/// is too small.
pub fn build_pcr_extend(buf: &mut [u8], pcr_index: u32, digest: &[u8]) -> Result<usize> {
    if digest.len() != SHA256_DIGEST_LEN {
        return Err(Error::InvalidArgument);
    }
    // Header(10) + PCR handle(4) + sessions header(9) +
    // TPML_DIGEST_VALUES: count(4) + alg(2) + digest(32) = 61 bytes.
    const CMD_LEN: usize = 61;
    if buf.len() < CMD_LEN {
        return Err(Error::InvalidArgument);
    }
    write_header(buf, TAG_NO_SESSIONS, CMD_LEN as u32, CC_PCR_EXTEND);
    // PCR handle = TPM_HR_PCR | pcr_index (0x01000000 | index)
    put_u32_be(buf, 10, 0x0100_0000 | pcr_index);
    // Authorisation (empty password session, 9 bytes).
    put_u32_be(buf, 14, 9); // authorizationSize
    put_u32_be(buf, 18, 0x4000_0009); // TPM_RS_PW
    buf[22] = 0;
    buf[23] = 0; // nonceCaller size = 0
    buf[24] = 0; // sessionAttributes = 0
    buf[25] = 0;
    buf[26] = 0; // auth size = 0
    // TPML_DIGEST_VALUES.count = 1
    put_u32_be(buf, 27, 1);
    // TPMT_HA.hashAlg = SHA-256
    put_u16_be(buf, 31, ALG_SHA256);
    // digest bytes
    buf[33..33 + SHA256_DIGEST_LEN].copy_from_slice(digest);
    Ok(CMD_LEN)
}

/// Builds a `TPM2_CC_GetRandom` command requesting `num_bytes` of randomness.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `buf` is too small.
pub fn build_get_random(buf: &mut [u8], num_bytes: u16) -> Result<usize> {
    const CMD_LEN: usize = 12;
    if buf.len() < CMD_LEN {
        return Err(Error::InvalidArgument);
    }
    write_header(buf, TAG_NO_SESSIONS, CMD_LEN as u32, CC_GET_RANDOM);
    put_u16_be(buf, 10, num_bytes);
    Ok(CMD_LEN)
}

/// Builds a `TPM2_CC_GetCapability` command.
///
/// `capability` is a TPM_CAP_* constant; `property` and `count` select the
/// range of properties to return.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `buf` is too small.
pub fn build_get_capability(
    buf: &mut [u8],
    capability: u32,
    property: u32,
    count: u32,
) -> Result<usize> {
    const CMD_LEN: usize = 22;
    if buf.len() < CMD_LEN {
        return Err(Error::InvalidArgument);
    }
    write_header(buf, TAG_NO_SESSIONS, CMD_LEN as u32, CC_GET_CAPABILITY);
    put_u32_be(buf, 10, capability);
    put_u32_be(buf, 14, property);
    put_u32_be(buf, 18, count);
    Ok(CMD_LEN)
}

// ---------------------------------------------------------------------------
// TpmChip
// ---------------------------------------------------------------------------

/// A TPM chip instance bound to a TIS MMIO window.
pub struct TpmChip {
    /// TIS MMIO base address.
    mmio_base: u64,
    /// Active locality (0-4).
    locality: u8,
    /// Vendor ID read at init.
    pub vendor_id: u16,
    /// Device ID read at init.
    pub device_id: u16,
    /// Chip index assigned by the registry.
    pub chip_idx: u8,
    /// Whether this chip is initialised and operational.
    pub ready: bool,
}

impl TpmChip {
    /// Creates a new chip descriptor.
    ///
    /// # Safety
    ///
    /// `mmio_base` must be the TIS MMIO base address, mapped with device
    /// memory attributes and accessible at kernel privilege level.
    pub const unsafe fn new(mmio_base: u64, locality: u8) -> Self {
        Self {
            mmio_base,
            locality,
            vendor_id: 0,
            device_id: 0,
            chip_idx: 0,
            ready: false,
        }
    }

    fn loc_base(&self) -> u64 {
        self.mmio_base + u64::from(self.locality) * TIS_LOCALITY_SIZE
    }

    /// Requests access to the configured locality.
    ///
    /// Polls up to 1,000,000 iterations for the active flag.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the locality cannot be granted.
    pub fn request_locality(&self) -> Result<()> {
        let base = self.loc_base();
        // SAFETY: base is a valid TIS locality window.
        unsafe { wr8(base, REG_ACCESS, ACCESS_REQUEST) }
        for _ in 0..1_000_000 {
            let a = unsafe { rd8(base, REG_ACCESS) };
            if a & ACCESS_ACTIVE != 0 {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Releases the active locality.
    pub fn release_locality(&self) {
        let base = self.loc_base();
        // SAFETY: writing ACCESS_ACTIVE clears the locality in TIS.
        unsafe { wr8(base, REG_ACCESS, ACCESS_ACTIVE) }
    }

    /// Polls the STS register until `(sts & mask) == expected`.
    fn wait_sts(&self, mask: u32, expected: u32) -> Result<()> {
        let base = self.loc_base();
        for _ in 0..1_000_000 {
            // SAFETY: REG_STS is a valid TIS register.
            let sts = unsafe { rd32(base, REG_STS) };
            if sts & STS_VALID != 0 && (sts & mask) == expected {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }

    /// Transitions the chip to command-ready state.
    fn set_cmd_ready(&self) -> Result<()> {
        let base = self.loc_base();
        // SAFETY: STS write transitions chip state.
        unsafe { wr32(base, REG_STS, STS_CMD_READY) }
        self.wait_sts(STS_CMD_READY, STS_CMD_READY)
    }

    /// Writes `cmd` to the TPM FIFO.
    fn write_fifo(&self, cmd: &[u8]) -> Result<()> {
        let base = self.loc_base();
        for &b in cmd {
            self.wait_sts(STS_EXPECT, STS_EXPECT)?;
            // SAFETY: REG_FIFO byte write.
            unsafe { wr8(base, REG_FIFO, b) }
        }
        Ok(())
    }

    /// Reads the response from the TPM FIFO into `rsp`.
    fn read_fifo(&self, rsp: &mut [u8]) -> Result<usize> {
        let base = self.loc_base();
        self.wait_sts(STS_DATA_AVAIL, STS_DATA_AVAIL)?;
        let mut n = 0;
        while n < rsp.len() {
            // SAFETY: REG_STS read.
            let sts = unsafe { rd32(base, REG_STS) };
            if sts & STS_VALID == 0 {
                return Err(Error::IoError);
            }
            if sts & STS_DATA_AVAIL == 0 {
                break;
            }
            // SAFETY: REG_FIFO byte read.
            rsp[n] = unsafe { rd8(base, REG_FIFO) };
            n += 1;
        }
        Ok(n)
    }

    /// Initialises the chip: requests locality and reads VID/DID.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if the locality cannot be granted.
    pub fn init(&mut self) -> Result<()> {
        self.request_locality()?;
        let base = self.loc_base();
        // SAFETY: REG_DID_VID is a read-only identification register.
        let did_vid = unsafe { rd32(base, REG_DID_VID) };
        self.vendor_id = did_vid as u16;
        self.device_id = (did_vid >> 16) as u16;
        self.ready = true;
        Ok(())
    }

    /// Transmits `cmd` and receives the response into `rsp`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if either buffer is shorter than
    /// [`TPM_HEADER_LEN`], or propagates FIFO/status errors.
    pub fn transmit(&self, cmd: &[u8], rsp: &mut [u8]) -> Result<usize> {
        if cmd.len() < TPM_HEADER_LEN || rsp.len() < TPM_HEADER_LEN {
            return Err(Error::InvalidArgument);
        }
        self.set_cmd_ready()?;
        self.write_fifo(cmd)?;
        let base = self.loc_base();
        // SAFETY: STS_GO triggers command execution.
        unsafe { wr32(base, REG_STS, STS_GO) }
        self.read_fifo(rsp)
    }

    /// Returns the active locality.
    pub fn locality(&self) -> u8 {
        self.locality
    }
}

// ---------------------------------------------------------------------------
// TpmChipRegistry
// ---------------------------------------------------------------------------

/// Maximum chips in the global registry.
const MAX_CHIPS: usize = 4;

/// Global TPM chip registry.
///
/// Assigns sequential chip indices and allows lookup by index.
pub struct TpmChipRegistry {
    chips: [Option<TpmChip>; MAX_CHIPS],
    count: usize,
}

impl TpmChipRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            chips: [const { None }; MAX_CHIPS],
            count: 0,
        }
    }

    /// Registers a chip, assigning it a chip index.
    ///
    /// Returns the assigned index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, mut chip: TpmChip) -> Result<usize> {
        if self.count >= MAX_CHIPS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        chip.chip_idx = idx as u8;
        self.chips[idx] = Some(chip);
        self.count += 1;
        Ok(idx)
    }

    /// Unregisters a chip by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if `idx` is invalid.
    pub fn unregister(&mut self, idx: usize) -> Result<()> {
        if idx >= self.count || self.chips[idx].is_none() {
            return Err(Error::NotFound);
        }
        if let Some(chip) = &self.chips[idx] {
            chip.release_locality();
        }
        self.chips[idx] = None;
        Ok(())
    }

    /// Returns a reference to the chip at `idx`.
    pub fn get(&self, idx: usize) -> Option<&TpmChip> {
        if idx < self.count {
            self.chips[idx].as_ref()
        } else {
            None
        }
    }

    /// Returns a mutable reference to the chip at `idx`.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut TpmChip> {
        if idx < self.count {
            self.chips[idx].as_mut()
        } else {
            None
        }
    }

    /// Returns the number of registered chips.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no chips are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

impl Default for TpmChipRegistry {
    fn default() -> Self {
        Self::new()
    }
}
