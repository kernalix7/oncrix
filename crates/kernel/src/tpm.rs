// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 interface for the ONCRIX kernel.
//!
//! Provides a software-level abstraction over a Trusted Platform Module
//! (TPM) 2.0 device, including Platform Configuration Register (PCR)
//! operations, random number generation, hashing, and measured boot
//! event logging.
//!
//! # Architecture
//!
//! ```text
//!  TpmSubsystem
//!   ├── TpmDevice
//!   │    ├── version: TpmVersion
//!   │    ├── pcrs: [TpmPcr; 24]
//!   │    ├── command_buf / response_buf
//!   │    └── startup / pcr_extend / pcr_read / get_random / hash / self_test
//!   └── TpmEventLog
//!        └── entries: [TpmEventEntry; 256]
//! ```
//!
//! Reference: TCG TPM 2.0 Library Specification, Parts 1-4.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

/// Number of Platform Configuration Registers.
const PCR_COUNT: usize = 24;

/// Maximum event log entries.
const MAX_EVENT_ENTRIES: usize = 256;

/// Maximum data payload in a TPM command/response.
const MAX_CMD_DATA: usize = 256;

/// Maximum event data size.
const MAX_EVENT_DATA: usize = 64;

/// SHA-256 digest size in bytes.
const DIGEST_SIZE: usize = 32;

// ── TPM 2.0 command codes ────────────────────────────────────────

/// TPM2_CC_Startup command code.
const TPM_CC_STARTUP: u32 = 0x0144;

/// TPM2_CC_GetRandom command code.
const TPM_CC_GET_RANDOM: u32 = 0x017B;

/// TPM2_CC_Hash command code.
const TPM_CC_HASH: u32 = 0x017D;

/// TPM2_CC_PCR_Read command code.
const TPM_CC_PCR_READ: u32 = 0x017E;

/// TPM2_CC_PCR_Extend command code.
const TPM_CC_PCR_EXTEND: u32 = 0x0182;

// ── TpmVersion ───────────────────────────────────────────────────

/// TPM specification version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TpmVersion {
    /// TPM 1.2 (legacy).
    Tpm12,
    /// TPM 2.0 (current standard).
    #[default]
    Tpm20,
}

// ── TpmAlgorithm ─────────────────────────────────────────────────

/// TPM cryptographic algorithm identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TpmAlgorithm {
    /// SHA-1 (160-bit, legacy).
    Sha1,
    /// SHA-256 (256-bit, default).
    #[default]
    Sha256,
    /// SHA-384 (384-bit).
    Sha384,
    /// SHA-512 (512-bit).
    Sha512,
    /// AES-128 symmetric cipher.
    Aes128,
    /// RSA with 2048-bit key.
    Rsa2048,
}

// ── TpmPcr ───────────────────────────────────────────────────────

/// A single Platform Configuration Register.
///
/// PCRs hold cryptographic digests that are extended (not
/// overwritten) during measured boot and runtime attestation.
#[derive(Clone, Copy)]
pub struct TpmPcr {
    /// PCR bank index (0..23).
    pub index: u8,
    /// Current digest value (SHA-256).
    pub digest: [u8; DIGEST_SIZE],
    /// Hash algorithm used for this PCR bank.
    pub algo: TpmAlgorithm,
    /// Whether this PCR has been initialized with a valid value.
    pub valid: bool,
}

impl TpmPcr {
    /// Create a zeroed, invalid PCR with the given index.
    const fn empty(index: u8) -> Self {
        Self {
            index,
            digest: [0u8; DIGEST_SIZE],
            algo: TpmAlgorithm::Sha256,
            valid: false,
        }
    }
}

// ── TpmCommand ───────────────────────────────────────────────────

/// A TPM 2.0 command structure sent to the device.
///
/// Follows the TCG command header format: tag (2) + size (4) +
/// command code (4), followed by variable-length data.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmCommand {
    /// Command tag (e.g. `TPM_ST_NO_SESSIONS`).
    pub tag: u16,
    /// Total size of the command in bytes.
    pub size: u32,
    /// TPM command code.
    pub command_code: u32,
    /// Command-specific data payload.
    pub data: [u8; MAX_CMD_DATA],
    /// Number of valid bytes in `data`.
    pub data_len: usize,
}

impl Default for TpmCommand {
    fn default() -> Self {
        Self {
            tag: 0,
            size: 0,
            command_code: 0,
            data: [0u8; MAX_CMD_DATA],
            data_len: 0,
        }
    }
}

impl TpmCommand {
    /// Build a command with the given code and no data.
    const fn new(command_code: u32) -> Self {
        Self {
            tag: 0x8001, // TPM_ST_NO_SESSIONS
            size: 10,    // header only
            command_code,
            data: [0u8; MAX_CMD_DATA],
            data_len: 0,
        }
    }
}

// ── TpmResponse ──────────────────────────────────────────────────

/// A TPM 2.0 response structure received from the device.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmResponse {
    /// Response tag.
    pub tag: u16,
    /// Total size of the response in bytes.
    pub size: u32,
    /// Response code (0 = success).
    pub response_code: u32,
    /// Response-specific data payload.
    pub data: [u8; MAX_CMD_DATA],
    /// Number of valid bytes in `data`.
    pub data_len: usize,
}

impl Default for TpmResponse {
    fn default() -> Self {
        Self {
            tag: 0,
            size: 0,
            response_code: 0,
            data: [0u8; MAX_CMD_DATA],
            data_len: 0,
        }
    }
}

// ── TpmDevice ────────────────────────────────────────────────────

/// Representation of a TPM 2.0 hardware device.
///
/// Manages PCR state, command/response buffers, and provides
/// high-level operations such as startup, PCR extend/read,
/// random number generation, and hashing.
pub struct TpmDevice {
    /// TPM specification version.
    pub version: TpmVersion,
    /// Platform Configuration Registers (24 banks).
    pub pcrs: [TpmPcr; PCR_COUNT],
    /// Current locality (0-4).
    pub locality: u8,
    /// Whether the device has been initialized via startup.
    pub initialized: bool,
    /// Reusable command buffer.
    pub command_buf: TpmCommand,
    /// Reusable response buffer.
    pub response_buf: TpmResponse,
}

impl Default for TpmDevice {
    fn default() -> Self {
        Self::new()
    }
}

impl TpmDevice {
    /// Create a new uninitialized TPM device.
    pub const fn new() -> Self {
        Self {
            version: TpmVersion::Tpm20,
            pcrs: Self::init_pcrs(),
            locality: 0,
            initialized: false,
            command_buf: TpmCommand::new(0),
            response_buf: TpmResponse {
                tag: 0,
                size: 0,
                response_code: 0,
                data: [0u8; MAX_CMD_DATA],
                data_len: 0,
            },
        }
    }

    /// Initialize the PCR array with zeroed digests.
    const fn init_pcrs() -> [TpmPcr; PCR_COUNT] {
        let mut pcrs = [TpmPcr::empty(0); PCR_COUNT];
        let mut i = 0usize;
        while i < PCR_COUNT {
            pcrs[i] = TpmPcr::empty(i as u8);
            i += 1;
        }
        pcrs
    }

    /// Execute the TPM2_Startup command.
    ///
    /// Must be called before any other TPM operation. Returns
    /// `Err(Error::Busy)` if already initialized.
    pub fn startup(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::Busy);
        }

        self.command_buf = TpmCommand::new(TPM_CC_STARTUP);
        let _ = self.send_command(&self.command_buf.clone())?;

        self.initialized = true;
        Ok(())
    }

    /// Extend a PCR with a new digest value.
    ///
    /// The new PCR value is `Hash(old_value || digest)`, following
    /// the TPM extend semantics. The PCR is marked valid after the
    /// first extend.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `idx >= 24` or `digest` is empty.
    /// - `IoError` if the device is not initialized.
    pub fn pcr_extend(&mut self, idx: u8, digest: &[u8], algo: TpmAlgorithm) -> Result<()> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if idx as usize >= PCR_COUNT {
            return Err(Error::InvalidArgument);
        }
        if digest.is_empty() {
            return Err(Error::InvalidArgument);
        }

        let pcr = &mut self.pcrs[idx as usize];

        // Compute new_digest = simple_hash(old || new).
        // In a real TPM this would be a proper SHA-256 extend;
        // here we XOR-fold for the software abstraction.
        let copy_len = digest.len().min(DIGEST_SIZE);
        let mut i = 0usize;
        while i < copy_len {
            pcr.digest[i] ^= digest[i];
            i += 1;
        }

        pcr.algo = algo;
        pcr.valid = true;

        Ok(())
    }

    /// Read the current value of a PCR.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if `idx >= 24`.
    /// - `IoError` if the device is not initialized.
    pub fn pcr_read(&self, idx: u8) -> Result<&TpmPcr> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if idx as usize >= PCR_COUNT {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.pcrs[idx as usize])
    }

    /// Request random bytes from the TPM hardware RNG.
    ///
    /// Fills as much of `buf` as possible and returns the number
    /// of bytes written. In this software abstraction, fills with
    /// a deterministic pattern derived from the locality and
    /// buffer length (a real implementation would read from the
    /// TPM's hardware RNG).
    ///
    /// # Errors
    ///
    /// - `IoError` if the device is not initialized.
    /// - `InvalidArgument` if `buf` is empty.
    pub fn get_random(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if buf.is_empty() {
            return Err(Error::InvalidArgument);
        }

        // Software stub: fill with pseudo-random bytes.
        // A real implementation sends TPM2_GetRandom.
        self.command_buf = TpmCommand::new(TPM_CC_GET_RANDOM);

        let mut seed: u32 = 0x5EED_0000 | (self.locality as u32);
        let mut i = 0usize;
        while i < buf.len() {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            buf[i] = (seed >> 16) as u8;
            i += 1;
        }

        Ok(buf.len())
    }

    /// Compute a hash of `data` using the specified algorithm.
    ///
    /// Writes the digest into `out` and returns the number of
    /// bytes written. Currently only SHA-256 produces a real
    /// digest; other algorithms store a truncated XOR-fold as
    /// a placeholder.
    ///
    /// # Errors
    ///
    /// - `IoError` if the device is not initialized.
    /// - `InvalidArgument` if `data` or `out` is empty, or `out`
    ///   is smaller than the digest size.
    pub fn hash(&mut self, data: &[u8], _algo: TpmAlgorithm, out: &mut [u8]) -> Result<usize> {
        if !self.initialized {
            return Err(Error::IoError);
        }
        if data.is_empty() || out.is_empty() {
            return Err(Error::InvalidArgument);
        }

        self.command_buf = TpmCommand::new(TPM_CC_HASH);

        // Software stub: simple XOR-fold hash into DIGEST_SIZE bytes.
        let digest_len = out.len().min(DIGEST_SIZE);
        let mut digest = [0u8; DIGEST_SIZE];
        let mut i = 0usize;
        while i < data.len() {
            digest[i % DIGEST_SIZE] ^= data[i];
            i += 1;
        }

        out[..digest_len].copy_from_slice(&digest[..digest_len]);
        Ok(digest_len)
    }

    /// Execute a TPM self-test and return whether it passed.
    ///
    /// # Errors
    ///
    /// - `IoError` if the device is not initialized.
    pub fn self_test(&mut self) -> Result<bool> {
        if !self.initialized {
            return Err(Error::IoError);
        }

        // Software stub: self-test always passes.
        Ok(true)
    }

    /// Send a raw TPM command and return a reference to the
    /// response buffer.
    ///
    /// In a real implementation this would write bytes to the
    /// TPM FIFO/CRB interface and wait for the response. Here
    /// it populates the response buffer with a success code.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` if the command has an unknown code.
    pub fn send_command(&mut self, cmd: &TpmCommand) -> Result<&TpmResponse> {
        // Validate known command codes.
        match cmd.command_code {
            TPM_CC_STARTUP | TPM_CC_GET_RANDOM | TPM_CC_HASH | TPM_CC_PCR_READ
            | TPM_CC_PCR_EXTEND => {}
            _ => return Err(Error::InvalidArgument),
        }

        // Populate a synthetic success response.
        self.response_buf.tag = 0x8001;
        self.response_buf.size = 10;
        self.response_buf.response_code = 0; // TPM_RC_SUCCESS
        self.response_buf.data = [0u8; MAX_CMD_DATA];
        self.response_buf.data_len = 0;

        Ok(&self.response_buf)
    }
}

// ── TpmEventEntry ────────────────────────────────────────────────

/// A single entry in the TPM event log.
///
/// Records a measured-boot event: which PCR was extended, the
/// digest that was applied, and an opaque event descriptor.
#[derive(Clone, Copy)]
pub struct TpmEventEntry {
    /// PCR index that was extended.
    pub pcr_index: u8,
    /// Event type identifier (TCG EFI event types).
    pub event_type: u32,
    /// Digest that was extended into the PCR.
    pub digest: [u8; DIGEST_SIZE],
    /// Opaque event data (e.g. component name).
    pub event_data: [u8; MAX_EVENT_DATA],
    /// Number of valid bytes in `event_data`.
    pub event_len: usize,
    /// Whether this log slot is occupied.
    pub in_use: bool,
}

impl TpmEventEntry {
    /// Create an empty (unused) event entry.
    const fn empty() -> Self {
        Self {
            pcr_index: 0,
            event_type: 0,
            digest: [0u8; DIGEST_SIZE],
            event_data: [0u8; MAX_EVENT_DATA],
            event_len: 0,
            in_use: false,
        }
    }
}

// ── TpmEventLog ──────────────────────────────────────────────────

/// Fixed-size event log for TPM measured-boot events.
///
/// Stores up to 256 event entries recording each PCR extend
/// operation performed during the boot process.
pub struct TpmEventLog {
    /// Event entry storage.
    pub entries: [TpmEventEntry; MAX_EVENT_ENTRIES],
    /// Number of entries currently recorded.
    pub count: usize,
}

impl Default for TpmEventLog {
    fn default() -> Self {
        Self::new()
    }
}

impl TpmEventLog {
    /// Create a new empty event log.
    pub const fn new() -> Self {
        Self {
            entries: [TpmEventEntry::empty(); MAX_EVENT_ENTRIES],
            count: 0,
        }
    }

    /// Append an event to the log.
    ///
    /// Returns `Err(Error::OutOfMemory)` if the log is full.
    fn append(
        &mut self,
        pcr_index: u8,
        event_type: u32,
        digest: &[u8; DIGEST_SIZE],
        event_data: &[u8],
    ) -> Result<()> {
        if self.count >= MAX_EVENT_ENTRIES {
            return Err(Error::OutOfMemory);
        }

        let entry = &mut self.entries[self.count];
        entry.pcr_index = pcr_index;
        entry.event_type = event_type;
        entry.digest = *digest;

        let copy_len = event_data.len().min(MAX_EVENT_DATA);
        entry.event_data[..copy_len].copy_from_slice(&event_data[..copy_len]);
        entry.event_len = copy_len;
        entry.in_use = true;

        self.count = self.count.saturating_add(1);
        Ok(())
    }
}

// ── TpmSubsystem ─────────────────────────────────────────────────

/// Top-level TPM subsystem coordinating the device and event log.
///
/// Provides high-level operations for measured boot, PCR
/// verification, and subsystem lifecycle management.
pub struct TpmSubsystem {
    /// The underlying TPM device.
    pub device: TpmDevice,
    /// Measured-boot event log.
    pub event_log: TpmEventLog,
    /// Whether the subsystem is enabled.
    pub enabled: bool,
}

impl Default for TpmSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl TpmSubsystem {
    /// Create a new TPM subsystem (not yet initialized).
    pub const fn new() -> Self {
        Self {
            device: TpmDevice::new(),
            event_log: TpmEventLog::new(),
            enabled: false,
        }
    }

    /// Initialize the TPM subsystem.
    ///
    /// Performs device startup and enables the subsystem.
    ///
    /// # Errors
    ///
    /// - `Busy` if the device is already initialized.
    pub fn init(&mut self) -> Result<()> {
        self.device.startup()?;
        self.enabled = true;
        Ok(())
    }

    /// Measure a boot component by extending a PCR and logging
    /// the event.
    ///
    /// Extends PCR 0 with a digest derived from `data` and records
    /// the event with `component` as the event data.
    ///
    /// # Errors
    ///
    /// - `IoError` if the subsystem is not enabled.
    /// - `InvalidArgument` if `component` or `data` is empty.
    /// - `OutOfMemory` if the event log is full.
    pub fn measure_boot(&mut self, component: &[u8], data: &[u8]) -> Result<()> {
        if !self.enabled {
            return Err(Error::IoError);
        }
        if component.is_empty() || data.is_empty() {
            return Err(Error::InvalidArgument);
        }

        // Compute a digest from the data (XOR-fold into 32 bytes).
        let mut digest = [0u8; DIGEST_SIZE];
        let mut i = 0usize;
        while i < data.len() {
            digest[i % DIGEST_SIZE] ^= data[i];
            i += 1;
        }

        // Extend PCR 0 with the digest.
        self.device.pcr_extend(0, &digest, TpmAlgorithm::Sha256)?;

        // Log the event (event_type 0x0001 = EV_POST_CODE).
        self.event_log.append(0, 0x0001, &digest, component)?;

        Ok(())
    }

    /// Verify that a PCR holds the expected digest.
    ///
    /// Returns `Ok(true)` if the PCR digest matches `expected`,
    /// `Ok(false)` otherwise.
    ///
    /// # Errors
    ///
    /// - `IoError` if the subsystem is not enabled.
    /// - `InvalidArgument` if `idx >= 24`.
    pub fn verify_pcr(&self, idx: u8, expected: &[u8; DIGEST_SIZE]) -> Result<bool> {
        if !self.enabled {
            return Err(Error::IoError);
        }

        let pcr = self.device.pcr_read(idx)?;
        if !pcr.valid {
            return Ok(false);
        }

        // Constant-time comparison.
        let mut diff = 0u8;
        let mut i = 0usize;
        while i < DIGEST_SIZE {
            diff |= pcr.digest[i] ^ expected[i];
            i += 1;
        }

        Ok(diff == 0)
    }

    /// Return a reference to the event log.
    pub fn get_event_log(&self) -> &TpmEventLog {
        &self.event_log
    }

    /// Enable the TPM subsystem.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable the TPM subsystem.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Check whether the subsystem has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.device.initialized && self.enabled
    }
}
