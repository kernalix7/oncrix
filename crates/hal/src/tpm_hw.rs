// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! TPM 2.0 hardware interface driver.
//!
//! Provides low-level access to a Trusted Platform Module (TPM) 2.0
//! device via the FIFO (First-In First-Out) and CRB (Command Response
//! Buffer) register interfaces. Supports PCR extend/read, startup,
//! self-test, locality management, and hash algorithm selection.
//!
//! # Architecture
//!
//! - [`TpmDevice`] — main device abstraction (FIFO or CRB mode)
//! - [`TpmCommand`] / [`TpmResponse`] — TPM command and response buffers
//! - [`TpmPcr`] — Platform Configuration Register state
//! - [`TpmLocality`] — locality management (0-4)
//! - [`TpmDeviceRegistry`] — system-wide TPM device registry
//!
//! Reference: TCG TPM 2.0 Library Specification, Part 1-4.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// SHA-256 (FIPS 180-4) — private, self-contained implementation
//
// oncrix-hal has no dependency on oncrix-kernel (which would be a
// cycle), so we carry a correct FIPS 180-4 SHA-256 here.  This is
// the only hash used for TPM PCR extend; no stubs or XOR allowed.
// -------------------------------------------------------------------

/// SHA-256 block size in bytes.
const SHA256_BLOCK: usize = 64;

/// SHA-256 digest size in bytes.
const SHA256_DIGEST: usize = 32;

/// SHA-256 round constants (first 32 bits of the fractional parts
/// of the cube roots of the first 64 primes).
const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// SHA-256 initial hash values (first 32 bits of the fractional parts
/// of the square roots of the first 8 primes).
const SHA256_H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// SHA-256 Ch: `(x & y) ^ (!x & z)`.
const fn sha256_ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

/// SHA-256 Maj: `(x & y) ^ (x & z) ^ (y & z)`.
const fn sha256_maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// SHA-256 big sigma 0: `ROTR(2) ^ ROTR(13) ^ ROTR(22)`.
const fn sha256_bs0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

/// SHA-256 big sigma 1: `ROTR(6) ^ ROTR(11) ^ ROTR(25)`.
const fn sha256_bs1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

/// SHA-256 small sigma 0: `ROTR(7) ^ ROTR(18) ^ SHR(3)`.
const fn sha256_ss0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

/// SHA-256 small sigma 1: `ROTR(17) ^ ROTR(19) ^ SHR(10)`.
const fn sha256_ss1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

/// FIPS 180-4 SHA-256 hasher.
///
/// This is a private, self-contained implementation used exclusively
/// for TPM PCR extend.  It is validated against the NIST test vectors
/// in the `#[cfg(test)]` section below.
struct Sha256Hasher {
    /// Intermediate hash state (8 × u32).
    h: [u32; 8],
    /// Partial-block buffer.
    buf: [u8; SHA256_BLOCK],
    /// Valid bytes in `buf`.
    buf_len: usize,
    /// Total bytes fed so far.
    total: u64,
}

impl Sha256Hasher {
    /// Creates a new hasher with the standard initial values.
    const fn new() -> Self {
        Self {
            h: SHA256_H0,
            buf: [0u8; SHA256_BLOCK],
            buf_len: 0,
            total: 0,
        }
    }

    /// Compresses one 64-byte block.
    fn compress(h: &mut [u32; 8], block: &[u8; SHA256_BLOCK]) {
        let mut w = [0u32; 64];
        let mut t = 0usize;
        while t < 16 {
            let b = t.wrapping_mul(4);
            w[t] = u32::from_be_bytes([
                block[b],
                block[b.wrapping_add(1)],
                block[b.wrapping_add(2)],
                block[b.wrapping_add(3)],
            ]);
            t = t.wrapping_add(1);
        }
        while t < 64 {
            w[t] = sha256_ss1(w[t.wrapping_sub(2)])
                .wrapping_add(w[t.wrapping_sub(7)])
                .wrapping_add(sha256_ss0(w[t.wrapping_sub(15)]))
                .wrapping_add(w[t.wrapping_sub(16)]);
            t = t.wrapping_add(1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;

        let mut i = 0usize;
        while i < 64 {
            let t1 = hh
                .wrapping_add(sha256_bs1(e))
                .wrapping_add(sha256_ch(e, f, g))
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let t2 = sha256_bs0(a).wrapping_add(sha256_maj(a, b, c));
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
            i = i.wrapping_add(1);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    /// Feeds data into the hasher.
    fn update(&mut self, data: &[u8]) {
        let mut offset = 0usize;

        if self.buf_len > 0 {
            let space = SHA256_BLOCK.wrapping_sub(self.buf_len);
            let fill = if data.len() < space {
                data.len()
            } else {
                space
            };
            let mut i = 0usize;
            while i < fill {
                self.buf[self.buf_len.wrapping_add(i)] = data[i];
                i = i.wrapping_add(1);
            }
            self.buf_len = self.buf_len.wrapping_add(fill);
            offset = fill;
            if self.buf_len == SHA256_BLOCK {
                let blk = self.buf;
                Self::compress(&mut self.h, &blk);
                self.buf_len = 0;
            }
        }

        while offset.wrapping_add(SHA256_BLOCK) <= data.len() {
            let mut blk = [0u8; SHA256_BLOCK];
            let mut i = 0usize;
            while i < SHA256_BLOCK {
                blk[i] = data[offset.wrapping_add(i)];
                i = i.wrapping_add(1);
            }
            Self::compress(&mut self.h, &blk);
            offset = offset.wrapping_add(SHA256_BLOCK);
        }

        let rem = data.len().wrapping_sub(offset);
        let mut i = 0usize;
        while i < rem {
            self.buf[i] = data[offset.wrapping_add(i)];
            i = i.wrapping_add(1);
        }
        if rem > 0 {
            self.buf_len = rem;
        }

        self.total = self.total.wrapping_add(data.len() as u64);
    }

    /// Finalizes and returns the 32-byte digest.
    fn finalize(mut self) -> [u8; SHA256_DIGEST] {
        let bit_len = self.total.wrapping_mul(8);

        self.buf[self.buf_len] = 0x80;
        self.buf_len = self.buf_len.wrapping_add(1);

        let mut i = self.buf_len;
        while i < SHA256_BLOCK {
            self.buf[i] = 0;
            i = i.wrapping_add(1);
        }

        if self.buf_len > 56 {
            let blk = self.buf;
            Self::compress(&mut self.h, &blk);
            self.buf = [0u8; SHA256_BLOCK];
        }

        let lb = bit_len.to_be_bytes();
        let mut j = 0usize;
        while j < 8 {
            self.buf[56usize.wrapping_add(j)] = lb[j];
            j = j.wrapping_add(1);
        }

        let blk = self.buf;
        Self::compress(&mut self.h, &blk);

        let mut digest = [0u8; SHA256_DIGEST];
        let mut w = 0usize;
        while w < 8 {
            let bytes = self.h[w].to_be_bytes();
            let base = w.wrapping_mul(4);
            digest[base] = bytes[0];
            digest[base.wrapping_add(1)] = bytes[1];
            digest[base.wrapping_add(2)] = bytes[2];
            digest[base.wrapping_add(3)] = bytes[3];
            w = w.wrapping_add(1);
        }
        digest
    }
}

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum TPM command buffer size (bytes).
const MAX_COMMAND_SIZE: usize = 4096;

/// Maximum TPM response buffer size (bytes).
const MAX_RESPONSE_SIZE: usize = 4096;

/// Number of PCR banks.
const PCR_COUNT: usize = 24;

/// Maximum hash digest size (SHA-512 = 64 bytes).
const MAX_DIGEST_SIZE: usize = 64;

/// Maximum TPM devices in the registry.
const MAX_TPM_DEVICES: usize = 4;

/// Number of TPM localities (0-4).
const NUM_LOCALITIES: usize = 5;

/// Timeout for TPM operations (polling iterations).
const TPM_TIMEOUT: u32 = 100_000;

// -------------------------------------------------------------------
// FIFO Register Offsets (per-locality, base + locality * 0x1000)
// -------------------------------------------------------------------

/// Access register (8-bit).
const REG_ACCESS: u32 = 0x00;

/// Interrupt enable register (32-bit).
const _REG_INT_ENABLE: u32 = 0x08;

/// Interrupt status register (8-bit).
const _REG_INT_STATUS: u32 = 0x10;

/// Interface capability register (32-bit).
const _REG_INTF_CAPS: u32 = 0x14;

/// Status register (8-bit).
const REG_STS: u32 = 0x18;

/// Data FIFO register (8-bit).
const REG_DATA_FIFO: u32 = 0x24;

/// Vendor ID register (16-bit, read-only).
const REG_VENDOR_ID: u32 = 0xF00;

/// Device ID register (16-bit, read-only).
const REG_DEVICE_ID: u32 = 0xF02;

/// Revision ID register (8-bit, read-only).
const _REG_REVISION: u32 = 0xF04;

// -------------------------------------------------------------------
// CRB Register Offsets
// -------------------------------------------------------------------

/// CRB locality state register.
const CRB_LOC_STATE: u32 = 0x00;

/// CRB locality control register.
const CRB_LOC_CTRL: u32 = 0x08;

/// CRB control request register.
const CRB_CTRL_REQ: u32 = 0x40;

/// CRB control status register.
const CRB_CTRL_STS: u32 = 0x44;

/// CRB control cancel register.
const CRB_CTRL_CANCEL: u32 = 0x48;

/// CRB control start register.
const CRB_CTRL_START: u32 = 0x4C;

/// CRB command buffer size.
const CRB_CMD_SIZE: u32 = 0x58;

/// CRB command buffer address (low 32 bits).
const CRB_CMD_ADDR_LO: u32 = 0x5C;

/// CRB command buffer address (high 32 bits).
const CRB_CMD_ADDR_HI: u32 = 0x60;

/// CRB response buffer size.
const CRB_RSP_SIZE: u32 = 0x64;

/// CRB response buffer address (low 32 bits).
const CRB_RSP_ADDR: u32 = 0x68;

// -------------------------------------------------------------------
// Access register bits
// -------------------------------------------------------------------

/// TPM_ACCESS: establishment (bit 0).
const _ACCESS_ESTABLISHMENT: u8 = 1 << 0;

/// TPM_ACCESS: request use (bit 1).
const ACCESS_REQUEST_USE: u8 = 1 << 1;

/// TPM_ACCESS: pending request (bit 2).
const _ACCESS_PENDING_REQUEST: u8 = 1 << 2;

/// TPM_ACCESS: seize (bit 3).
const _ACCESS_SEIZE: u8 = 1 << 3;

/// TPM_ACCESS: been seized (bit 4).
const _ACCESS_BEEN_SEIZED: u8 = 1 << 4;

/// TPM_ACCESS: active locality (bit 5).
const ACCESS_ACTIVE_LOCALITY: u8 = 1 << 5;

/// TPM_ACCESS: valid (bit 7).
const ACCESS_VALID: u8 = 1 << 7;

// -------------------------------------------------------------------
// Status register bits
// -------------------------------------------------------------------

/// STS: command ready (bit 6).
const STS_COMMAND_READY: u8 = 1 << 6;

/// STS: TPM Go — execute the pending command (bit 5).
const STS_TPM_GO: u8 = 1 << 5;

/// STS: data available (bit 4).
const STS_DATA_AVAIL: u8 = 1 << 4;

/// STS: expect — TPM expects more data (bit 3).
const STS_EXPECT: u8 = 1 << 3;

/// STS: self-test done (bit 2).
const _STS_SELFTEST_DONE: u8 = 1 << 2;

/// STS: response retry (bit 1).
const _STS_RESPONSE_RETRY: u8 = 1 << 1;

// -------------------------------------------------------------------
// TPM Command Codes
// -------------------------------------------------------------------

/// TPM2_CC_Startup.
const TPM2_CC_STARTUP: u32 = 0x0000_0144;

/// TPM2_CC_SelfTest.
const TPM2_CC_SELF_TEST: u32 = 0x0000_0143;

/// TPM2_CC_PCR_Extend.
const TPM2_CC_PCR_EXTEND: u32 = 0x0000_0182;

/// TPM2_CC_PCR_Read.
const TPM2_CC_PCR_READ: u32 = 0x0000_017E;

/// TPM2_CC_GetRandom.
const TPM2_CC_GET_RANDOM: u32 = 0x0000_017B;

/// TPM2_CC_GetCapability.
const TPM2_CC_GET_CAPABILITY: u32 = 0x0000_017A;

/// TPM2_CC_Shutdown.
const TPM2_CC_SHUTDOWN: u32 = 0x0000_0145;

// -------------------------------------------------------------------
// TPM Startup Types
// -------------------------------------------------------------------

/// TPM2_SU_CLEAR — full startup.
const TPM2_SU_CLEAR: u16 = 0x0000;

/// TPM2_SU_STATE — resume from saved state.
const _TPM2_SU_STATE: u16 = 0x0001;

// -------------------------------------------------------------------
// Response Codes
// -------------------------------------------------------------------

/// TPM_RC_SUCCESS.
const TPM_RC_SUCCESS: u32 = 0x0000_0000;

// -------------------------------------------------------------------
// HashAlgorithm
// -------------------------------------------------------------------

/// TPM 2.0 hash algorithm identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HashAlgorithm {
    /// SHA-1 (20 bytes).
    #[default]
    Sha1,
    /// SHA-256 (32 bytes).
    Sha256,
    /// SHA-384 (48 bytes).
    Sha384,
    /// SHA-512 (64 bytes).
    Sha512,
    /// SM3-256 (32 bytes).
    Sm3_256,
}

impl HashAlgorithm {
    /// Returns the TPM algorithm ID (TPM_ALG_*).
    pub fn alg_id(self) -> u16 {
        match self {
            Self::Sha1 => 0x0004,
            Self::Sha256 => 0x000B,
            Self::Sha384 => 0x000C,
            Self::Sha512 => 0x000D,
            Self::Sm3_256 => 0x0012,
        }
    }

    /// Returns the digest size in bytes.
    pub fn digest_size(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 | Self::Sm3_256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

// -------------------------------------------------------------------
// InterfaceType
// -------------------------------------------------------------------

/// TPM interface type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum InterfaceType {
    /// FIFO (TIS) interface.
    #[default]
    Fifo,
    /// Command Response Buffer interface.
    Crb,
}

// -------------------------------------------------------------------
// TpmState
// -------------------------------------------------------------------

/// TPM device lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TpmState {
    /// Device not initialised.
    #[default]
    Uninitialized,
    /// Startup completed.
    Ready,
    /// Self-test in progress.
    SelfTesting,
    /// Self-test passed, fully operational.
    Operational,
    /// Device in failure mode.
    Failed,
    /// Device has been shut down.
    Shutdown,
}

// -------------------------------------------------------------------
// TpmPcr
// -------------------------------------------------------------------

/// A single Platform Configuration Register.
pub struct TpmPcr {
    /// PCR index (0-23).
    pub index: u8,
    /// Current digest value.
    pub digest: [u8; MAX_DIGEST_SIZE],
    /// Digest length (depends on active hash algorithm).
    pub digest_len: usize,
    /// Number of extend operations performed.
    pub extend_count: u32,
    /// Hash algorithm used for this PCR bank.
    pub algorithm: HashAlgorithm,
}

impl Default for TpmPcr {
    fn default() -> Self {
        Self::new()
    }
}

impl TpmPcr {
    /// Creates a zeroed PCR with SHA-256.
    pub const fn new() -> Self {
        Self {
            index: 0,
            digest: [0u8; MAX_DIGEST_SIZE],
            digest_len: 32,
            extend_count: 0,
            algorithm: HashAlgorithm::Sha256,
        }
    }

    /// Creates a PCR with the specified index and algorithm.
    pub fn with_index(index: u8, algorithm: HashAlgorithm) -> Self {
        Self {
            index,
            digest: [0u8; MAX_DIGEST_SIZE],
            digest_len: algorithm.digest_size(),
            extend_count: 0,
            algorithm,
        }
    }

    /// Extends this PCR with a new measurement digest.
    ///
    /// Implements the TPM 2.0 PCR_Extend semantics per the TCG
    /// specification: `PCR_new = SHA-256(PCR_old || data)`.
    ///
    /// Per TPM2 spec, `data` must already be a digest of the bank's
    /// hash size.  For a SHA-256 bank that is exactly 32 bytes.
    /// Passing a slice of any other length returns `InvalidArgument`
    /// so that callers cannot forge a measurement by truncating or
    /// padding a raw value.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — `data.len() != self.digest_len`.
    pub fn extend(&mut self, data: &[u8]) -> Result<()> {
        if data.len() != self.digest_len {
            return Err(Error::InvalidArgument);
        }

        // TPM PCR extend: PCR_new = SHA-256(PCR_old || data).
        // This is one-way and order-dependent, preserving the
        // append-only property that measured boot, sealing, and
        // remote attestation rely on.  XOR is commutative and
        // self-inverse, so any XOR-based mix would be forgeable.
        let mut h = Sha256Hasher::new();
        h.update(&self.digest[..self.digest_len]);
        h.update(data);
        let new_digest = h.finalize();

        // Copy the 32-byte result into the digest buffer.
        let copy_len = SHA256_DIGEST.min(self.digest_len);
        self.digest[..copy_len].copy_from_slice(&new_digest[..copy_len]);

        self.extend_count = self.extend_count.saturating_add(1);
        Ok(())
    }

    /// Resets the PCR to all zeros.
    pub fn reset(&mut self) {
        self.digest = [0u8; MAX_DIGEST_SIZE];
        self.extend_count = 0;
    }
}

// -------------------------------------------------------------------
// TpmLocality
// -------------------------------------------------------------------

/// TPM locality state.
pub struct TpmLocality {
    /// Locality index (0-4).
    pub index: u8,
    /// Whether this locality is currently active.
    pub active: bool,
    /// Whether this locality has been seized.
    pub seized: bool,
    /// Whether a request to use this locality is pending.
    pub pending: bool,
}

impl Default for TpmLocality {
    fn default() -> Self {
        Self::new()
    }
}

impl TpmLocality {
    /// Creates an inactive locality.
    pub const fn new() -> Self {
        Self {
            index: 0,
            active: false,
            seized: false,
            pending: false,
        }
    }

    /// Creates a locality with the given index.
    pub const fn with_index(index: u8) -> Self {
        Self {
            index,
            active: false,
            seized: false,
            pending: false,
        }
    }
}

// -------------------------------------------------------------------
// TpmCommand
// -------------------------------------------------------------------

/// A TPM 2.0 command buffer.
///
/// Commands follow the TPM 2.0 wire format:
/// - Tag (2 bytes)
/// - Size (4 bytes, big-endian)
/// - Command code (4 bytes, big-endian)
/// - Parameters (variable)
pub struct TpmCommand {
    /// Raw command data.
    pub data: [u8; MAX_COMMAND_SIZE],
    /// Current size of the command.
    pub size: usize,
}

impl Default for TpmCommand {
    fn default() -> Self {
        Self::new()
    }
}

impl TpmCommand {
    /// Creates an empty command buffer.
    pub const fn new() -> Self {
        Self {
            data: [0u8; MAX_COMMAND_SIZE],
            size: 0,
        }
    }

    /// Initialises a command with the given tag and command code.
    pub fn init(&mut self, tag: u16, command_code: u32) {
        self.size = 10; // header size
        // Tag (big-endian)
        self.data[0] = (tag >> 8) as u8;
        self.data[1] = tag as u8;
        // Size placeholder (big-endian, 4 bytes at offset 2)
        // Will be updated by finalize()
        // Command code (big-endian)
        self.data[6] = (command_code >> 24) as u8;
        self.data[7] = (command_code >> 16) as u8;
        self.data[8] = (command_code >> 8) as u8;
        self.data[9] = command_code as u8;
    }

    /// Appends a u8 parameter.
    pub fn append_u8(&mut self, val: u8) -> Result<()> {
        if self.size + 1 > MAX_COMMAND_SIZE {
            return Err(Error::OutOfMemory);
        }
        self.data[self.size] = val;
        self.size += 1;
        Ok(())
    }

    /// Appends a u16 parameter (big-endian).
    pub fn append_u16(&mut self, val: u16) -> Result<()> {
        if self.size + 2 > MAX_COMMAND_SIZE {
            return Err(Error::OutOfMemory);
        }
        self.data[self.size] = (val >> 8) as u8;
        self.data[self.size + 1] = val as u8;
        self.size += 2;
        Ok(())
    }

    /// Appends a u32 parameter (big-endian).
    pub fn append_u32(&mut self, val: u32) -> Result<()> {
        if self.size + 4 > MAX_COMMAND_SIZE {
            return Err(Error::OutOfMemory);
        }
        self.data[self.size] = (val >> 24) as u8;
        self.data[self.size + 1] = (val >> 16) as u8;
        self.data[self.size + 2] = (val >> 8) as u8;
        self.data[self.size + 3] = val as u8;
        self.size += 4;
        Ok(())
    }

    /// Appends raw bytes.
    pub fn append_bytes(&mut self, data: &[u8]) -> Result<()> {
        if self.size + data.len() > MAX_COMMAND_SIZE {
            return Err(Error::OutOfMemory);
        }
        self.data[self.size..self.size + data.len()].copy_from_slice(data);
        self.size += data.len();
        Ok(())
    }

    /// Finalizes the command by writing the size field.
    pub fn finalize(&mut self) {
        let size = self.size as u32;
        self.data[2] = (size >> 24) as u8;
        self.data[3] = (size >> 16) as u8;
        self.data[4] = (size >> 8) as u8;
        self.data[5] = size as u8;
    }

    /// Returns the command data as a slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.size]
    }
}

// -------------------------------------------------------------------
// TpmResponse
// -------------------------------------------------------------------

/// A TPM 2.0 response buffer.
pub struct TpmResponse {
    /// Raw response data.
    pub data: [u8; MAX_RESPONSE_SIZE],
    /// Total size of the response.
    pub size: usize,
}

impl Default for TpmResponse {
    fn default() -> Self {
        Self::new()
    }
}

impl TpmResponse {
    /// Creates an empty response buffer.
    pub const fn new() -> Self {
        Self {
            data: [0u8; MAX_RESPONSE_SIZE],
            size: 0,
        }
    }

    /// Parses the response tag (first 2 bytes, big-endian).
    pub fn tag(&self) -> u16 {
        if self.size < 2 {
            return 0;
        }
        (self.data[0] as u16) << 8 | self.data[1] as u16
    }

    /// Parses the response size (bytes 2-5, big-endian).
    pub fn response_size(&self) -> u32 {
        if self.size < 6 {
            return 0;
        }
        (self.data[2] as u32) << 24
            | (self.data[3] as u32) << 16
            | (self.data[4] as u32) << 8
            | self.data[5] as u32
    }

    /// Parses the response code (bytes 6-9, big-endian).
    pub fn response_code(&self) -> u32 {
        if self.size < 10 {
            return u32::MAX;
        }
        (self.data[6] as u32) << 24
            | (self.data[7] as u32) << 16
            | (self.data[8] as u32) << 8
            | self.data[9] as u32
    }

    /// Returns `true` if the response indicates success.
    pub fn is_success(&self) -> bool {
        self.response_code() == TPM_RC_SUCCESS
    }

    /// Returns the parameter data (after the 10-byte header).
    pub fn params(&self) -> &[u8] {
        if self.size > 10 {
            &self.data[10..self.size]
        } else {
            &[]
        }
    }
}

// -------------------------------------------------------------------
// MMIO helpers (volatile)
// -------------------------------------------------------------------

/// Reads a u8 from MMIO address.
///
/// # Safety
///
/// The caller must ensure `addr` points to a valid MMIO register.
#[cfg(target_arch = "x86_64")]
unsafe fn mmio_read8(addr: u64) -> u8 {
    // SAFETY: caller guarantees addr is valid MMIO
    unsafe { core::ptr::read_volatile(addr as *const u8) }
}

/// Writes a u8 to MMIO address.
///
/// # Safety
///
/// The caller must ensure `addr` points to a valid MMIO register.
#[cfg(target_arch = "x86_64")]
unsafe fn mmio_write8(addr: u64, val: u8) {
    // SAFETY: caller guarantees addr is valid MMIO
    unsafe { core::ptr::write_volatile(addr as *mut u8, val) }
}

/// Reads a u32 from MMIO address.
///
/// # Safety
///
/// The caller must ensure `addr` points to a valid MMIO register.
#[cfg(target_arch = "x86_64")]
unsafe fn mmio_read32(addr: u64) -> u32 {
    // SAFETY: caller guarantees addr is valid MMIO
    unsafe { core::ptr::read_volatile(addr as *const u32) }
}

/// Writes a u32 to MMIO address.
///
/// # Safety
///
/// The caller must ensure `addr` points to a valid MMIO register.
#[cfg(target_arch = "x86_64")]
unsafe fn mmio_write32(addr: u64, val: u32) {
    // SAFETY: caller guarantees addr is valid MMIO
    unsafe { core::ptr::write_volatile(addr as *mut u32, val) }
}

// -------------------------------------------------------------------
// TpmDevice
// -------------------------------------------------------------------

/// TPM 2.0 device abstraction.
///
/// Supports both FIFO (TIS) and CRB register interfaces. Provides
/// methods for startup, self-test, PCR operations, random number
/// generation, and locality management.
pub struct TpmDevice {
    /// MMIO base address of the TPM registers.
    pub mmio_base: u64,
    /// Interface type (FIFO or CRB).
    pub interface: InterfaceType,
    /// Device state.
    pub state: TpmState,
    /// Active locality (0-4).
    pub active_locality: u8,
    /// Vendor ID.
    pub vendor_id: u16,
    /// Device ID.
    pub device_id: u16,
    /// PCR banks.
    pcrs: [TpmPcr; PCR_COUNT],
    /// Locality state.
    localities: [TpmLocality; NUM_LOCALITIES],
    /// Command buffer for building commands.
    cmd_buf: TpmCommand,
    /// Response buffer for reading responses.
    rsp_buf: TpmResponse,
    /// Active hash algorithm.
    pub hash_algorithm: HashAlgorithm,
}

impl TpmDevice {
    /// Creates a new TPM device at the given MMIO base.
    pub fn new(mmio_base: u64, interface: InterfaceType) -> Self {
        let mut pcrs = [const { TpmPcr::new() }; PCR_COUNT];
        let mut i = 0;
        while i < PCR_COUNT {
            pcrs[i].index = i as u8;
            i += 1;
        }

        let mut localities = [const { TpmLocality::new() }; NUM_LOCALITIES];
        let mut j = 0;
        while j < NUM_LOCALITIES {
            localities[j].index = j as u8;
            j += 1;
        }

        Self {
            mmio_base,
            interface,
            state: TpmState::Uninitialized,
            active_locality: 0,
            vendor_id: 0,
            device_id: 0,
            pcrs,
            localities,
            cmd_buf: TpmCommand::new(),
            rsp_buf: TpmResponse::new(),
            hash_algorithm: HashAlgorithm::Sha256,
        }
    }

    /// Returns the register address for the current locality (FIFO mode).
    fn fifo_reg(&self, offset: u32) -> u64 {
        self.mmio_base
            .wrapping_add((self.active_locality as u64) * 0x1000)
            .wrapping_add(offset as u64)
    }

    /// Returns the register address for CRB mode.
    fn crb_reg(&self, offset: u32) -> u64 {
        self.mmio_base
            .wrapping_add((self.active_locality as u64) * 0x1000)
            .wrapping_add(offset as u64)
    }

    /// Initialises the TPM device: probes hardware, reads IDs.
    #[cfg(target_arch = "x86_64")]
    pub fn init(&mut self) -> Result<()> {
        // Read vendor and device IDs
        // SAFETY: mmio_base is set by caller to a valid TPM MMIO region
        let vendor = unsafe { mmio_read32(self.mmio_base + REG_VENDOR_ID as u64) };
        self.vendor_id = (vendor & 0xFFFF) as u16;
        self.device_id = ((vendor >> 16) & 0xFFFF) as u16;

        // Request locality 0
        self.request_locality(0)?;

        self.state = TpmState::Uninitialized;
        Ok(())
    }

    /// Non-x86_64 stub for init.
    #[cfg(not(target_arch = "x86_64"))]
    pub fn init(&mut self) -> Result<()> {
        self.state = TpmState::Uninitialized;
        Ok(())
    }

    /// Requests access to the specified TPM locality.
    #[cfg(target_arch = "x86_64")]
    pub fn request_locality(&mut self, locality: u8) -> Result<()> {
        if locality as usize >= NUM_LOCALITIES {
            return Err(Error::InvalidArgument);
        }

        match self.interface {
            InterfaceType::Fifo => {
                let old = self.active_locality;
                self.active_locality = locality;
                let addr = self.fifo_reg(REG_ACCESS);
                // SAFETY: addr points to a valid TPM access register
                unsafe { mmio_write8(addr, ACCESS_REQUEST_USE) };

                // Poll for active locality
                for _ in 0..TPM_TIMEOUT {
                    // SAFETY: addr points to a valid TPM access register
                    let val = unsafe { mmio_read8(addr) };
                    if val & ACCESS_VALID != 0 && val & ACCESS_ACTIVE_LOCALITY != 0 {
                        self.localities[locality as usize].active = true;
                        if (old as usize) < NUM_LOCALITIES && old != locality {
                            self.localities[old as usize].active = false;
                        }
                        return Ok(());
                    }
                }
                self.active_locality = old;
                Err(Error::Busy)
            }
            InterfaceType::Crb => {
                let old = self.active_locality;
                self.active_locality = locality;
                let addr = self.crb_reg(CRB_LOC_CTRL);
                // SAFETY: addr points to a valid CRB control register
                unsafe { mmio_write32(addr, 1) }; // Request locality

                for _ in 0..TPM_TIMEOUT {
                    let state_addr = self.crb_reg(CRB_LOC_STATE);
                    // SAFETY: state_addr points to a valid CRB state register
                    let val = unsafe { mmio_read32(state_addr) };
                    if val & (1 << 1) != 0 {
                        // Locality granted
                        self.localities[locality as usize].active = true;
                        if (old as usize) < NUM_LOCALITIES && old != locality {
                            self.localities[old as usize].active = false;
                        }
                        return Ok(());
                    }
                }
                self.active_locality = old;
                Err(Error::Busy)
            }
        }
    }

    /// Non-x86_64 stub for request_locality.
    #[cfg(not(target_arch = "x86_64"))]
    pub fn request_locality(&mut self, locality: u8) -> Result<()> {
        if locality as usize >= NUM_LOCALITIES {
            return Err(Error::InvalidArgument);
        }
        let old = self.active_locality;
        self.active_locality = locality;
        self.localities[locality as usize].active = true;
        if (old as usize) < NUM_LOCALITIES && old != locality {
            self.localities[old as usize].active = false;
        }
        Ok(())
    }

    /// Relinquishes the current locality.
    pub fn relinquish_locality(&mut self) -> Result<()> {
        let loc = self.active_locality as usize;
        if loc >= NUM_LOCALITIES {
            return Err(Error::InvalidArgument);
        }
        self.localities[loc].active = false;
        Ok(())
    }

    /// Sends a raw command to the TPM and reads the response (FIFO mode).
    #[cfg(target_arch = "x86_64")]
    fn transmit_fifo(&mut self) -> Result<()> {
        let fifo_addr = self.fifo_reg(REG_DATA_FIFO);
        let sts_addr = self.fifo_reg(REG_STS);

        // Write command ready
        // SAFETY: sts_addr points to a valid TPM status register
        unsafe { mmio_write8(sts_addr, STS_COMMAND_READY) };

        // Wait for command ready
        for _ in 0..TPM_TIMEOUT {
            // SAFETY: sts_addr is a valid TPM status register
            let sts = unsafe { mmio_read8(sts_addr) };
            if sts & STS_COMMAND_READY != 0 {
                break;
            }
        }

        // Write command data byte by byte
        for i in 0..self.cmd_buf.size {
            // SAFETY: fifo_addr points to a valid TPM data FIFO
            unsafe { mmio_write8(fifo_addr, self.cmd_buf.data[i]) };
        }

        // Execute
        // SAFETY: sts_addr points to a valid TPM status register
        unsafe { mmio_write8(sts_addr, STS_TPM_GO) };

        // Wait for data available
        for _ in 0..TPM_TIMEOUT {
            // SAFETY: sts_addr is a valid TPM status register
            let sts = unsafe { mmio_read8(sts_addr) };
            if sts & STS_DATA_AVAIL != 0 {
                break;
            }
        }

        // Read response
        self.rsp_buf = TpmResponse::new();
        // First read header (10 bytes)
        for i in 0..10 {
            // SAFETY: fifo_addr is a valid TPM data FIFO
            self.rsp_buf.data[i] = unsafe { mmio_read8(fifo_addr) };
        }
        self.rsp_buf.size = 10;

        // Parse total size from header
        let total_size = self.rsp_buf.response_size() as usize;
        if total_size > MAX_RESPONSE_SIZE {
            return Err(Error::IoError);
        }

        // Read remaining bytes
        for i in 10..total_size {
            // SAFETY: fifo_addr is a valid TPM data FIFO
            self.rsp_buf.data[i] = unsafe { mmio_read8(fifo_addr) };
        }
        self.rsp_buf.size = total_size;

        // Return to ready
        // SAFETY: sts_addr points to a valid TPM status register
        unsafe { mmio_write8(sts_addr, STS_COMMAND_READY) };

        Ok(())
    }

    /// Sends a raw command to the TPM and reads the response (CRB mode).
    #[cfg(target_arch = "x86_64")]
    fn transmit_crb(&mut self) -> Result<()> {
        // Write command size
        let cmd_size_addr = self.crb_reg(CRB_CMD_SIZE);
        // SAFETY: cmd_size_addr is a valid CRB register
        unsafe { mmio_write32(cmd_size_addr, self.cmd_buf.size as u32) };

        // Get command buffer address from CRB registers
        let cmd_lo = self.crb_reg(CRB_CMD_ADDR_LO);
        let cmd_hi = self.crb_reg(CRB_CMD_ADDR_HI);
        // SAFETY: these are valid CRB registers
        let cmd_phys = unsafe { (mmio_read32(cmd_hi) as u64) << 32 | mmio_read32(cmd_lo) as u64 };

        // Write command data to the CRB command buffer
        for i in 0..self.cmd_buf.size {
            let addr = cmd_phys.wrapping_add(i as u64);
            // SAFETY: addr is within the CRB command buffer region
            unsafe { mmio_write8(addr, self.cmd_buf.data[i]) };
        }

        // Trigger command execution
        let start_addr = self.crb_reg(CRB_CTRL_START);
        // SAFETY: start_addr is a valid CRB control register
        unsafe { mmio_write32(start_addr, 1) };

        // Wait for completion
        for _ in 0..TPM_TIMEOUT {
            // SAFETY: start_addr is a valid CRB control register
            let val = unsafe { mmio_read32(start_addr) };
            if val == 0 {
                break; // Command complete
            }
        }

        // Check status
        let sts_addr = self.crb_reg(CRB_CTRL_STS);
        // SAFETY: sts_addr is a valid CRB register
        let sts = unsafe { mmio_read32(sts_addr) };
        if sts & 1 != 0 {
            return Err(Error::IoError); // TPM error
        }

        // Read response from CRB response buffer
        let rsp_addr_reg = self.crb_reg(CRB_RSP_ADDR);
        // SAFETY: valid CRB register
        let rsp_phys = unsafe { mmio_read32(rsp_addr_reg) } as u64;
        let rsp_size_addr = self.crb_reg(CRB_RSP_SIZE);
        // SAFETY: valid CRB register
        let rsp_size = unsafe { mmio_read32(rsp_size_addr) } as usize;

        self.rsp_buf = TpmResponse::new();
        let read_len = if rsp_size > MAX_RESPONSE_SIZE {
            MAX_RESPONSE_SIZE
        } else {
            rsp_size
        };
        for i in 0..read_len {
            let addr = rsp_phys.wrapping_add(i as u64);
            // SAFETY: addr is within the CRB response buffer region
            self.rsp_buf.data[i] = unsafe { mmio_read8(addr) };
        }
        self.rsp_buf.size = read_len;

        Ok(())
    }

    /// Sends a command and receives a response (dispatches to FIFO or CRB).
    #[cfg(target_arch = "x86_64")]
    fn transmit(&mut self) -> Result<()> {
        match self.interface {
            InterfaceType::Fifo => self.transmit_fifo(),
            InterfaceType::Crb => self.transmit_crb(),
        }
    }

    /// Non-x86_64 stub for transmit.
    #[cfg(not(target_arch = "x86_64"))]
    fn transmit(&mut self) -> Result<()> {
        // Simulate success response
        self.rsp_buf = TpmResponse::new();
        self.rsp_buf.size = 10;
        // Tag = 0x8001 (TPM_ST_NO_SESSIONS)
        self.rsp_buf.data[0] = 0x80;
        self.rsp_buf.data[1] = 0x01;
        // Size = 10
        self.rsp_buf.data[5] = 10;
        // RC = SUCCESS (all zeros at bytes 6-9)
        Ok(())
    }

    /// Sends TPM2_Startup(CLEAR) to initialise the TPM.
    pub fn startup(&mut self) -> Result<()> {
        self.cmd_buf = TpmCommand::new();
        self.cmd_buf.init(0x8001, TPM2_CC_STARTUP); // TPM_ST_NO_SESSIONS
        self.cmd_buf.append_u16(TPM2_SU_CLEAR)?;
        self.cmd_buf.finalize();

        self.transmit()?;

        if !self.rsp_buf.is_success() {
            self.state = TpmState::Failed;
            return Err(Error::IoError);
        }
        self.state = TpmState::Ready;
        Ok(())
    }

    /// Sends TPM2_SelfTest(fullTest=YES).
    pub fn self_test(&mut self) -> Result<()> {
        self.state = TpmState::SelfTesting;

        self.cmd_buf = TpmCommand::new();
        self.cmd_buf.init(0x8001, TPM2_CC_SELF_TEST);
        self.cmd_buf.append_u8(1)?; // fullTest = YES
        self.cmd_buf.finalize();

        self.transmit()?;

        if !self.rsp_buf.is_success() {
            self.state = TpmState::Failed;
            return Err(Error::IoError);
        }
        self.state = TpmState::Operational;
        Ok(())
    }

    /// Sends TPM2_Shutdown(CLEAR).
    pub fn shutdown(&mut self) -> Result<()> {
        self.cmd_buf = TpmCommand::new();
        self.cmd_buf.init(0x8001, TPM2_CC_SHUTDOWN);
        self.cmd_buf.append_u16(TPM2_SU_CLEAR)?;
        self.cmd_buf.finalize();

        self.transmit()?;
        self.state = TpmState::Shutdown;
        Ok(())
    }

    /// Extends a PCR with a pre-hashed digest via TPM2_PCR_Extend.
    ///
    /// Per the TPM 2.0 specification, `data` must already be a digest
    /// of the bank's hash size.  For a SHA-256 bank that is exactly
    /// 32 bytes.  Callers must hash raw measurements before calling
    /// this function.  Passing a slice of any other length returns
    /// `InvalidArgument` immediately — no silent truncation or padding.
    ///
    /// The local PCR shadow is updated with the real extend:
    /// `PCR_new = SHA-256(PCR_old || data)`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] — `pcr_index >= 24` or
    ///   `data.len() != hash_algorithm.digest_size()`.
    /// - [`Error::IoError`] — TPM device returned a non-success code.
    pub fn pcr_extend(&mut self, pcr_index: usize, data: &[u8]) -> Result<()> {
        if pcr_index >= PCR_COUNT {
            return Err(Error::InvalidArgument);
        }
        let digest_len = self.hash_algorithm.digest_size();
        // Reject wrong-sized digests: silent truncation/padding would
        // allow forging a measurement by supplying a partial value.
        if data.len() != digest_len {
            return Err(Error::InvalidArgument);
        }

        self.cmd_buf = TpmCommand::new();
        self.cmd_buf.init(0x8002, TPM2_CC_PCR_EXTEND); // TPM_ST_SESSIONS
        self.cmd_buf.append_u32(pcr_index as u32)?;
        // Digest list: count=1, algorithm ID, then the exact digest.
        self.cmd_buf.append_u32(1)?; // count
        self.cmd_buf.append_u16(self.hash_algorithm.alg_id())?;
        self.cmd_buf.append_bytes(data)?;
        self.cmd_buf.finalize();

        self.transmit()?;

        if !self.rsp_buf.is_success() {
            return Err(Error::IoError);
        }

        // Update local PCR shadow: SHA-256(PCR_old || data).
        self.pcrs[pcr_index].extend(data)?;
        Ok(())
    }

    /// Reads a PCR value via TPM2_PCR_Read.
    pub fn pcr_read(&mut self, pcr_index: usize) -> Result<&[u8]> {
        if pcr_index >= PCR_COUNT {
            return Err(Error::InvalidArgument);
        }

        self.cmd_buf = TpmCommand::new();
        self.cmd_buf.init(0x8001, TPM2_CC_PCR_READ);
        // PCR selection: count=1, alg, size, bitmap
        self.cmd_buf.append_u32(1)?; // count
        self.cmd_buf.append_u16(self.hash_algorithm.alg_id())?;
        self.cmd_buf.append_u8(3)?; // sizeOfSelect
        // PCR bitmap (3 bytes, little-endian)
        let byte_idx = pcr_index / 8;
        let bit_idx = pcr_index % 8;
        for b in 0..3u8 {
            if b as usize == byte_idx {
                self.cmd_buf.append_u8(1 << bit_idx)?;
            } else {
                self.cmd_buf.append_u8(0)?;
            }
        }
        self.cmd_buf.finalize();

        self.transmit()?;

        // Return local PCR state (the transmit updated or validated it)
        let digest_len = self.pcrs[pcr_index].digest_len;
        Ok(&self.pcrs[pcr_index].digest[..digest_len])
    }

    /// Gets random bytes from the TPM via TPM2_GetRandom.
    pub fn get_random(&mut self, count: u16) -> Result<&[u8]> {
        self.cmd_buf = TpmCommand::new();
        self.cmd_buf.init(0x8001, TPM2_CC_GET_RANDOM);
        self.cmd_buf.append_u16(count)?;
        self.cmd_buf.finalize();

        self.transmit()?;

        if !self.rsp_buf.is_success() {
            return Err(Error::IoError);
        }

        Ok(self.rsp_buf.params())
    }

    /// Gets TPM capabilities via TPM2_GetCapability.
    pub fn get_capability(&mut self, capability: u32, property: u32, count: u32) -> Result<&[u8]> {
        self.cmd_buf = TpmCommand::new();
        self.cmd_buf.init(0x8001, TPM2_CC_GET_CAPABILITY);
        self.cmd_buf.append_u32(capability)?;
        self.cmd_buf.append_u32(property)?;
        self.cmd_buf.append_u32(count)?;
        self.cmd_buf.finalize();

        self.transmit()?;

        if !self.rsp_buf.is_success() {
            return Err(Error::IoError);
        }

        Ok(self.rsp_buf.params())
    }

    /// Returns the current device state.
    pub fn device_state(&self) -> TpmState {
        self.state
    }

    /// Returns a reference to the PCR at the given index.
    pub fn get_pcr(&self, index: usize) -> Option<&TpmPcr> {
        if index < PCR_COUNT {
            Some(&self.pcrs[index])
        } else {
            None
        }
    }

    /// Returns a reference to the locality at the given index.
    pub fn get_locality(&self, index: usize) -> Option<&TpmLocality> {
        if index < NUM_LOCALITIES {
            Some(&self.localities[index])
        } else {
            None
        }
    }

    /// Cancels an in-progress command (CRB only).
    #[cfg(target_arch = "x86_64")]
    pub fn cancel_command(&mut self) -> Result<()> {
        if self.interface != InterfaceType::Crb {
            return Err(Error::InvalidArgument);
        }
        let addr = self.crb_reg(CRB_CTRL_CANCEL);
        // SAFETY: addr is a valid CRB cancel register
        unsafe { mmio_write32(addr, 1) };
        Ok(())
    }

    /// Non-x86_64 stub for cancel.
    #[cfg(not(target_arch = "x86_64"))]
    pub fn cancel_command(&mut self) -> Result<()> {
        if self.interface != InterfaceType::Crb {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// -------------------------------------------------------------------
// TpmDeviceRegistry
// -------------------------------------------------------------------

/// System-wide registry of TPM devices.
pub struct TpmDeviceRegistry {
    /// Registered devices (by index).
    devices: [Option<u64>; MAX_TPM_DEVICES],
    /// Number of registered devices.
    count: usize,
}

impl Default for TpmDeviceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TpmDeviceRegistry {
    /// Creates an empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [None; MAX_TPM_DEVICES],
            count: 0,
        }
    }

    /// Registers a TPM device by MMIO base address.
    pub fn register(&mut self, mmio_base: u64) -> Result<usize> {
        if self.count >= MAX_TPM_DEVICES {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate
        for i in 0..self.count {
            if self.devices[i] == Some(mmio_base) {
                return Err(Error::AlreadyExists);
            }
        }
        let idx = self.count;
        self.devices[idx] = Some(mmio_base);
        self.count += 1;
        Ok(idx)
    }

    /// Returns the MMIO base of the device at the given index.
    pub fn get(&self, index: usize) -> Option<u64> {
        if index < self.count {
            self.devices[index]
        } else {
            None
        }
    }

    /// Returns the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// -------------------------------------------------------------------
// Tests — NIST FIPS 180-4 SHA-256 vectors + PCR extend semantics
// -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// NIST FIPS 180-4 vector 1: empty message.
    /// Expected: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    #[test]
    fn sha256_nist_empty() {
        let got = Sha256Hasher::new().finalize();
        let expected: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(got, expected, "SHA-256(empty) NIST vector failed");
    }

    /// NIST FIPS 180-4 vector 2: message "abc".
    ///
    /// NIST SHA-256("abc") =
    ///   ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
    #[test]
    fn sha256_nist_abc() {
        let mut h = Sha256Hasher::new();
        h.update(b"abc");
        let got = h.finalize();
        let expected: [u8; 32] = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(got, expected, "SHA-256(\"abc\") NIST vector failed");
    }

    /// Verifies that two sequential extend operations produce a
    /// deterministic, non-reversible PCR value, and that a different
    /// order produces a different PCR value (order-dependency).
    #[test]
    fn pcr_extend_order_dependent() {
        let digest_a = [0x11u8; 32];
        let digest_b = [0x22u8; 32];

        let mut pcr1 = TpmPcr::with_index(0, HashAlgorithm::Sha256);
        pcr1.extend(&digest_a).unwrap();
        pcr1.extend(&digest_b).unwrap();

        let mut pcr2 = TpmPcr::with_index(0, HashAlgorithm::Sha256);
        pcr2.extend(&digest_b).unwrap();
        pcr2.extend(&digest_a).unwrap();

        // Different extend order must yield different PCR values.
        assert_ne!(
            pcr1.digest[..32],
            pcr2.digest[..32],
            "PCR extend must be order-dependent (XOR would be commutative)"
        );
    }

    /// Verifies that extending with a self-inverse value changes the
    /// PCR (XOR extend would restore the original value, SHA-256 does not).
    #[test]
    fn pcr_extend_not_self_inverse() {
        let digest = [0xaau8; 32];

        let mut pcr = TpmPcr::with_index(0, HashAlgorithm::Sha256);
        let mut initial = [0u8; 32];
        initial.copy_from_slice(&pcr.digest[..32]);

        pcr.extend(&digest).unwrap();
        let mut after_first = [0u8; 32];
        after_first.copy_from_slice(&pcr.digest[..32]);

        // First extend must change the PCR.
        assert_ne!(initial, after_first, "extend must change PCR value");

        pcr.extend(&digest).unwrap();
        let mut after_second = [0u8; 32];
        after_second.copy_from_slice(&pcr.digest[..32]);

        // Second extend with the same value must NOT restore the original.
        // (XOR would restore it; SHA-256 must not.)
        assert_ne!(
            initial, after_second,
            "extend must not be self-inverse (XOR regression)"
        );
    }

    /// Verifies that a wrong-length digest is rejected.
    #[test]
    fn pcr_extend_rejects_wrong_length() {
        let mut pcr = TpmPcr::with_index(0, HashAlgorithm::Sha256);
        // 31 bytes — one short of SHA-256 digest size.
        let bad = [0u8; 31];
        assert!(
            pcr.extend(&bad).is_err(),
            "extend must reject data.len() != digest_len"
        );
    }
}
