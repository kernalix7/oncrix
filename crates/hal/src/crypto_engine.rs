// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hardware crypto engine abstraction.
//!
//! Many SoCs include dedicated hardware accelerators for cryptographic
//! operations (AES, SHA, RSA/ECC, RNG). This module provides a HAL-level
//! interface to submit jobs to such an engine and poll for completion.
//!
//! Concrete platform code implements [`CryptoEngine`] and registers the
//! engine with the kernel's crypto subsystem.

use oncrix_lib::{Error, Result};

/// Maximum key size supported (bytes).
pub const CRYPTO_MAX_KEY_BYTES: usize = 64;
/// Maximum digest size supported (bytes).
pub const CRYPTO_MAX_DIGEST_BYTES: usize = 64;
/// Maximum number of pending jobs in the engine queue.
pub const CRYPTO_MAX_JOBS: usize = 16;

/// Symmetric cipher algorithm selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherAlg {
    /// AES-128 in CBC mode.
    Aes128Cbc,
    /// AES-256 in CBC mode.
    Aes256Cbc,
    /// AES-128 in GCM mode (AEAD).
    Aes128Gcm,
    /// AES-256 in GCM mode (AEAD).
    Aes256Gcm,
    /// ChaCha20-Poly1305 (AEAD).
    ChaCha20Poly1305,
}

/// Hash algorithm selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    /// SHA-256.
    Sha256,
    /// SHA-384.
    Sha384,
    /// SHA-512.
    Sha512,
    /// SHA3-256.
    Sha3_256,
}

/// Crypto operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoOp {
    /// Symmetric encryption.
    Encrypt(CipherAlg),
    /// Symmetric decryption.
    Decrypt(CipherAlg),
    /// Compute a message digest.
    Hash(HashAlg),
    /// Compute an HMAC.
    Hmac(HashAlg),
    /// Generate random bytes.
    Random,
}

/// Job status returned after completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobStatus {
    /// Job completed successfully.
    Done,
    /// Job is still in-flight.
    Pending,
    /// Engine reported a hardware error.
    HwError,
}

/// A single crypto job descriptor.
#[derive(Debug, Clone, Copy)]
pub struct CryptoJob {
    /// Unique job identifier (assigned by the engine).
    pub id: u32,
    /// Operation to perform.
    pub op: CryptoOp,
    /// Input data physical address.
    pub src_paddr: u64,
    /// Input data length in bytes.
    pub src_len: usize,
    /// Output buffer physical address.
    pub dst_paddr: u64,
    /// Output buffer length in bytes.
    pub dst_len: usize,
    /// Key physical address (for cipher/HMAC ops).
    pub key_paddr: u64,
    /// Key length in bytes.
    pub key_len: usize,
    /// Job completion status.
    pub status: JobStatus,
}

impl CryptoJob {
    /// Creates a new unsubmitted job.
    pub const fn new(op: CryptoOp) -> Self {
        Self {
            id: 0,
            op,
            src_paddr: 0,
            src_len: 0,
            dst_paddr: 0,
            dst_len: 0,
            key_paddr: 0,
            key_len: 0,
            status: JobStatus::Pending,
        }
    }
}

/// Hardware capability flags.
#[derive(Debug, Clone, Copy, Default)]
pub struct CryptoCapabilities {
    /// Engine supports AES acceleration.
    pub aes: bool,
    /// Engine supports SHA acceleration.
    pub sha: bool,
    /// Engine supports HMAC acceleration.
    pub hmac: bool,
    /// Engine includes a hardware RNG.
    pub rng: bool,
    /// Engine supports scatter-gather DMA.
    pub scatter_gather: bool,
}

/// Hardware crypto engine register offsets (generic layout).
struct Regs;

impl Regs {
    const CTRL: usize = 0x00;
    const STATUS: usize = 0x04;
    const SRC_ADDR_LO: usize = 0x10;
    const SRC_ADDR_HI: usize = 0x14;
    const SRC_LEN: usize = 0x18;
    const DST_ADDR_LO: usize = 0x20;
    const DST_ADDR_HI: usize = 0x24;
    const DST_LEN: usize = 0x28;
    const KEY_ADDR_LO: usize = 0x30;
    const KEY_LEN: usize = 0x34;
    const JOB_ID: usize = 0x38;
    const INTR_CLR: usize = 0x3C;

    // CTRL bits
    const CTRL_START: u32 = 1 << 0;
    const CTRL_RESET: u32 = 1 << 1;
    // STATUS bits
    const STATUS_BUSY: u32 = 1 << 0;
    const STATUS_DONE: u32 = 1 << 1;
    const STATUS_ERR: u32 = 1 << 2;
}

/// Hardware crypto engine.
pub struct CryptoEngineHw {
    /// MMIO base address.
    base: usize,
    /// Engine capabilities.
    caps: CryptoCapabilities,
    /// Next job ID to assign.
    next_id: u32,
    /// Pending job queue.
    jobs: [Option<CryptoJob>; CRYPTO_MAX_JOBS],
}

impl CryptoEngineHw {
    /// Creates a new crypto engine handle.
    ///
    /// # Arguments
    ///
    /// * `base` — MMIO base address (must be mapped).
    /// * `caps` — Hardware capability flags.
    pub const fn new(base: usize, caps: CryptoCapabilities) -> Self {
        Self {
            base,
            caps,
            next_id: 1,
            jobs: [const { None }; CRYPTO_MAX_JOBS],
        }
    }

    /// Resets and initialises the engine.
    pub fn init(&mut self) -> Result<()> {
        self.mmio_write32(Regs::CTRL, Regs::CTRL_RESET);
        // In real hardware a delay or polling loop would follow.
        self.mmio_write32(Regs::CTRL, 0);
        Ok(())
    }

    /// Returns the engine's hardware capabilities.
    pub fn capabilities(&self) -> CryptoCapabilities {
        self.caps
    }

    /// Submits a job to the engine.
    ///
    /// Returns the assigned job ID on success, or [`Error::Busy`] if the
    /// job queue is full.
    pub fn submit(&mut self, job: CryptoJob) -> Result<u32> {
        self.validate_job(&job)?;
        let slot = self.find_empty_slot().ok_or(Error::Busy)?;
        // Check engine is not busy.
        let status = self.mmio_read32(Regs::STATUS);
        if (status & Regs::STATUS_BUSY) != 0 {
            return Err(Error::Busy);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let mut j = job;
        j.id = id;
        j.status = JobStatus::Pending;
        self.jobs[slot] = Some(j);
        // Program hardware registers.
        self.mmio_write32(Regs::SRC_ADDR_LO, j.src_paddr as u32);
        self.mmio_write32(Regs::SRC_ADDR_HI, (j.src_paddr >> 32) as u32);
        self.mmio_write32(Regs::SRC_LEN, j.src_len as u32);
        self.mmio_write32(Regs::DST_ADDR_LO, j.dst_paddr as u32);
        self.mmio_write32(Regs::DST_ADDR_HI, (j.dst_paddr >> 32) as u32);
        self.mmio_write32(Regs::DST_LEN, j.dst_len as u32);
        if j.key_len > 0 {
            self.mmio_write32(Regs::KEY_ADDR_LO, j.key_paddr as u32);
            self.mmio_write32(Regs::KEY_LEN, j.key_len as u32);
        }
        self.mmio_write32(Regs::JOB_ID, id);
        self.mmio_write32(Regs::CTRL, Regs::CTRL_START | self.op_code(j.op));
        Ok(id)
    }

    /// Polls the engine for job completion.
    ///
    /// Returns `Some(id)` of the completed job, or `None` if still in-flight.
    pub fn poll(&mut self) -> Option<u32> {
        let status = self.mmio_read32(Regs::STATUS);
        if (status & (Regs::STATUS_DONE | Regs::STATUS_ERR)) == 0 {
            return None;
        }
        let completed_id = self.mmio_read32(Regs::JOB_ID);
        self.mmio_write32(Regs::INTR_CLR, 0xFF);
        // Update job status.
        for slot in self.jobs.iter_mut() {
            if let Some(j) = slot {
                if j.id == completed_id {
                    j.status = if (status & Regs::STATUS_ERR) != 0 {
                        JobStatus::HwError
                    } else {
                        JobStatus::Done
                    };
                    return Some(completed_id);
                }
            }
        }
        None
    }

    /// Returns the status of a previously submitted job.
    pub fn job_status(&self, id: u32) -> Option<JobStatus> {
        for slot in &self.jobs {
            if let Some(j) = slot {
                if j.id == id {
                    return Some(j.status);
                }
            }
        }
        None
    }

    // ---- private helpers ----

    fn find_empty_slot(&self) -> Option<usize> {
        self.jobs.iter().position(|s| s.is_none())
    }

    fn validate_job(&self, job: &CryptoJob) -> Result<()> {
        match job.op {
            CryptoOp::Encrypt(_) | CryptoOp::Decrypt(_) => {
                if !self.caps.aes {
                    return Err(Error::NotImplemented);
                }
                if job.key_len == 0 || job.key_len > CRYPTO_MAX_KEY_BYTES {
                    return Err(Error::InvalidArgument);
                }
            }
            CryptoOp::Hash(_) => {
                if !self.caps.sha {
                    return Err(Error::NotImplemented);
                }
            }
            CryptoOp::Hmac(_) => {
                if !self.caps.hmac {
                    return Err(Error::NotImplemented);
                }
            }
            CryptoOp::Random => {
                if !self.caps.rng {
                    return Err(Error::NotImplemented);
                }
            }
        }
        Ok(())
    }

    fn op_code(&self, op: CryptoOp) -> u32 {
        match op {
            CryptoOp::Encrypt(CipherAlg::Aes128Cbc) => 0x0100,
            CryptoOp::Encrypt(CipherAlg::Aes256Cbc) => 0x0200,
            CryptoOp::Encrypt(CipherAlg::Aes128Gcm) => 0x0300,
            CryptoOp::Encrypt(CipherAlg::Aes256Gcm) => 0x0400,
            CryptoOp::Encrypt(CipherAlg::ChaCha20Poly1305) => 0x0500,
            CryptoOp::Decrypt(alg) => self.op_code(CryptoOp::Encrypt(alg)) | 0x8000,
            CryptoOp::Hash(HashAlg::Sha256) => 0x1000,
            CryptoOp::Hash(HashAlg::Sha384) => 0x1100,
            CryptoOp::Hash(HashAlg::Sha512) => 0x1200,
            CryptoOp::Hash(HashAlg::Sha3_256) => 0x1300,
            CryptoOp::Hmac(alg) => self.op_code(CryptoOp::Hash(alg)) | 0x4000,
            CryptoOp::Random => 0x2000,
        }
    }

    fn mmio_read32(&self, offset: usize) -> u32 {
        let ptr = (self.base + offset) as *const u32;
        // SAFETY: base is a valid mapped MMIO region; volatile prevents caching.
        unsafe { core::ptr::read_volatile(ptr) }
    }

    fn mmio_write32(&self, offset: usize, value: u32) {
        let ptr = (self.base + offset) as *mut u32;
        // SAFETY: base is a valid mapped MMIO region; volatile prevents caching.
        unsafe { core::ptr::write_volatile(ptr, value) }
    }
}
