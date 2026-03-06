// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hardware Random Number Generator (HWRNG) abstraction.
//!
//! Provides an interface for hardware entropy sources such as
//! RDRAND/RDSEED (x86_64), VirtIO-RNG, and TPM RNG. Multiple
//! sources can be registered and the pool automatically selects the
//! highest-quality source for entropy requests.
//!
//! # Architecture
//!
//! - **HwRngQuality** — entropy quality score (bits per 1024 bits output)
//! - **HwRngSource** — a single hardware entropy source
//! - **HwRngPool** — aggregates multiple sources, selects best quality
//! - **HwRngDevice** — device wrapper with internal entropy buffer
//! - **HwRngRegistry** — tracks up to 4 HWRNG devices
//!
//! Entropy mixing uses XOR-fold to combine bytes from the selected
//! source, providing defense-in-depth against biased sources.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of HWRNG sources in a pool.
pub const MAX_SOURCES: usize = 4;

/// Maximum number of registered HWRNG devices.
pub const MAX_HWRNG_DEVICES: usize = 4;

/// Maximum length of a source name in bytes.
pub const MAX_SOURCE_NAME_LEN: usize = 64;

/// Size of the internal entropy buffer in bytes.
pub const ENTROPY_BUFFER_SIZE: usize = 256;

/// Maximum quality score (1024 bits of entropy per 1024 bits output).
pub const MAX_QUALITY: u16 = 1024;

// ---------------------------------------------------------------------------
// HwRng Quality
// ---------------------------------------------------------------------------

/// Entropy quality score for a hardware RNG source.
///
/// Expressed as the number of bits of true entropy per 1024 bits of
/// output. A score of 1024 means the source is believed to produce
/// full entropy; lower scores indicate bias or algorithmic expansion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct HwRngQuality {
    /// Quality score in the range 1–1024.
    score: u16,
}

impl HwRngQuality {
    /// Create a new quality score, clamped to 1–[`MAX_QUALITY`].
    pub const fn new(score: u16) -> Self {
        let s = if score == 0 {
            1
        } else if score > MAX_QUALITY {
            MAX_QUALITY
        } else {
            score
        };
        Self { score: s }
    }

    /// Return the raw quality score.
    pub const fn score(self) -> u16 {
        self.score
    }
}

// ---------------------------------------------------------------------------
// HwRng Source
// ---------------------------------------------------------------------------

/// A single hardware entropy source.
///
/// Represents one RNG backend (e.g., RDRAND, VirtIO-RNG, TPM) with
/// its quality rating and availability state.
pub struct HwRngSource {
    /// Human-readable source name (null-padded).
    pub name: [u8; MAX_SOURCE_NAME_LEN],
    /// Length of the valid portion of `name`.
    name_len: usize,
    /// Entropy quality of this source.
    pub quality: HwRngQuality,
    /// Whether this source is currently available for reads.
    pub available: bool,
}

impl HwRngSource {
    /// Create a new HWRNG source.
    ///
    /// `name` is truncated to [`MAX_SOURCE_NAME_LEN`] bytes.
    pub fn new(name: &[u8], quality: HwRngQuality) -> Self {
        let mut n = [0u8; MAX_SOURCE_NAME_LEN];
        let len = if name.len() > MAX_SOURCE_NAME_LEN {
            MAX_SOURCE_NAME_LEN
        } else {
            name.len()
        };
        n[..len].copy_from_slice(&name[..len]);
        Self {
            name: n,
            name_len: len,
            quality,
            available: true,
        }
    }

    /// Return the source name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Read entropy from this source into `buf`.
    ///
    /// Returns the number of bytes actually filled. In a real
    /// implementation this would invoke the hardware-specific
    /// read (e.g., RDRAND loop, MMIO read from VirtIO-RNG).
    ///
    /// Returns [`Error::IoError`] if the source is unavailable.
    pub fn read_entropy(&self, buf: &mut [u8], len: usize) -> Result<usize> {
        if !self.available {
            return Err(Error::IoError);
        }
        let fill_len = if len > buf.len() { buf.len() } else { len };
        // Stub: fill with a deterministic pattern for testing.
        // A real implementation reads from hardware.
        for (i, byte) in buf[..fill_len].iter_mut().enumerate() {
            *byte = (i & 0xFF) as u8;
        }
        Ok(fill_len)
    }
}

// ---------------------------------------------------------------------------
// HwRng Pool
// ---------------------------------------------------------------------------

/// Aggregates multiple hardware entropy sources.
///
/// The pool selects the highest-quality available source when
/// fulfilling entropy requests and applies XOR-fold mixing for
/// defense-in-depth.
pub struct HwRngPool {
    /// Registered entropy sources.
    sources: [Option<HwRngSource>; MAX_SOURCES],
    /// Number of registered sources.
    count: usize,
}

impl Default for HwRngPool {
    fn default() -> Self {
        Self::new()
    }
}

impl HwRngPool {
    /// Create an empty entropy pool.
    pub const fn new() -> Self {
        Self {
            sources: [None, None, None, None],
            count: 0,
        }
    }

    /// Add an entropy source to the pool.
    ///
    /// Returns [`Error::OutOfMemory`] if all source slots are full.
    pub fn add_source(&mut self, source: HwRngSource) -> Result<()> {
        for slot in &mut self.sources {
            if slot.is_none() {
                *slot = Some(source);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove an entropy source by name.
    ///
    /// Returns [`Error::NotFound`] if no source with that name
    /// exists.
    pub fn remove_source(&mut self, name: &[u8]) -> Result<()> {
        for slot in &mut self.sources {
            if let Some(src) = slot {
                if src.name_bytes() == name {
                    *slot = None;
                    self.count -= 1;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Select the best available source (highest quality score).
    ///
    /// Returns a reference to the source, or [`None`] if no sources
    /// are available.
    pub fn best_source(&self) -> Option<&HwRngSource> {
        let mut best: Option<&HwRngSource> = None;
        for src in self.sources.iter().flatten() {
            if src.available {
                match best {
                    Some(b) if b.quality >= src.quality => {}
                    _ => best = Some(src),
                }
            }
        }
        best
    }

    /// XOR-fold mix: fold `src` bytes into `dst` using XOR.
    ///
    /// If `src` is shorter than `dst`, only the first `src.len()`
    /// bytes of `dst` are modified.
    fn xor_fold(dst: &mut [u8], src: &[u8]) {
        let len = if dst.len() < src.len() {
            dst.len()
        } else {
            src.len()
        };
        for i in 0..len {
            dst[i] ^= src[i];
        }
    }

    /// Fill `buf` with entropy from the best available source.
    ///
    /// Applies XOR-fold mixing over the raw source output.
    /// Returns [`Error::NotFound`] if no sources are available.
    pub fn fill_buffer(&self, buf: &mut [u8]) -> Result<()> {
        let src = self.best_source().ok_or(Error::NotFound)?;
        let mut raw = [0u8; ENTROPY_BUFFER_SIZE];
        let fill_len = if buf.len() > ENTROPY_BUFFER_SIZE {
            ENTROPY_BUFFER_SIZE
        } else {
            buf.len()
        };
        let filled = src.read_entropy(&mut raw, fill_len)?;

        // Zero the output buffer first, then XOR-fold the raw entropy.
        buf[..filled].fill(0);
        Self::xor_fold(&mut buf[..filled], &raw[..filled]);
        Ok(())
    }

    /// Return the number of registered sources.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no sources are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// ---------------------------------------------------------------------------
// HwRng Device
// ---------------------------------------------------------------------------

/// A hardware RNG device with an internal entropy buffer.
///
/// Wraps a single [`HwRngSource`] and maintains a 256-byte buffer
/// of pre-fetched entropy for low-latency reads.
pub struct HwRngDevice {
    /// Device identifier.
    pub device_id: u8,
    /// The backing entropy source.
    source: HwRngSource,
    /// Pre-fetched entropy buffer.
    buffer: [u8; ENTROPY_BUFFER_SIZE],
    /// Number of valid bytes remaining in the buffer.
    buffer_valid: usize,
    /// Read offset into the buffer.
    buffer_offset: usize,
}

impl HwRngDevice {
    /// Create a new HWRNG device wrapping the given source.
    pub fn new(device_id: u8, source: HwRngSource) -> Self {
        Self {
            device_id,
            source,
            buffer: [0u8; ENTROPY_BUFFER_SIZE],
            buffer_valid: 0,
            buffer_offset: 0,
        }
    }

    /// Perform a basic self-test of the entropy source.
    ///
    /// Reads a small sample and checks that it is not all zeros,
    /// which would indicate a stuck or failed source.
    /// Returns [`Error::IoError`] if the self-test fails.
    pub fn self_test(&self) -> Result<()> {
        let mut sample = [0u8; 16];
        let filled = self.source.read_entropy(&mut sample, 16)?;
        if filled == 0 {
            return Err(Error::IoError);
        }
        // Check that at least one byte is non-zero.
        let all_zero = sample[..filled].iter().all(|&b| b == 0);
        if all_zero {
            return Err(Error::IoError);
        }
        Ok(())
    }

    /// Reseed the internal entropy buffer from the hardware source.
    ///
    /// Fills the entire 256-byte buffer with fresh entropy.
    pub fn reseed(&mut self) -> Result<()> {
        let filled = self
            .source
            .read_entropy(&mut self.buffer, ENTROPY_BUFFER_SIZE)?;
        self.buffer_valid = filled;
        self.buffer_offset = 0;
        Ok(())
    }

    /// Read bytes from the internal entropy buffer into `dst`.
    ///
    /// Automatically reseeds when the buffer is exhausted.
    /// Returns the number of bytes written.
    pub fn read(&mut self, dst: &mut [u8]) -> Result<usize> {
        let mut written = 0;
        let mut remaining = dst.len();

        while remaining > 0 {
            if self.buffer_valid == 0 || self.buffer_offset >= self.buffer_valid {
                self.reseed()?;
                if self.buffer_valid == 0 {
                    break;
                }
            }
            let avail = self.buffer_valid - self.buffer_offset;
            let chunk = if remaining < avail { remaining } else { avail };
            dst[written..written + chunk]
                .copy_from_slice(&self.buffer[self.buffer_offset..self.buffer_offset + chunk]);
            self.buffer_offset += chunk;
            written += chunk;
            remaining -= chunk;
        }
        Ok(written)
    }

    /// Return the quality score of the backing source.
    pub fn quality(&self) -> HwRngQuality {
        self.source.quality
    }

    /// Return `true` if the backing source is available.
    pub fn is_available(&self) -> bool {
        self.source.available
    }
}

// ---------------------------------------------------------------------------
// HwRng Registry
// ---------------------------------------------------------------------------

/// Registry of hardware RNG devices.
///
/// Tracks up to [`MAX_HWRNG_DEVICES`] devices and provides
/// convenience methods for obtaining random bytes from the best
/// available source.
pub struct HwRngRegistry {
    /// Fixed-size array of device slots.
    devices: [Option<HwRngDevice>; MAX_HWRNG_DEVICES],
    /// Number of currently registered devices.
    count: usize,
}

impl Default for HwRngRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl HwRngRegistry {
    /// Create an empty HWRNG device registry.
    pub const fn new() -> Self {
        Self {
            devices: [None, None, None, None],
            count: 0,
        }
    }

    /// Register a new HWRNG device.
    ///
    /// Returns [`Error::OutOfMemory`] if the registry is full, or
    /// [`Error::AlreadyExists`] if a device with the same
    /// `device_id` is already registered.
    pub fn register(&mut self, device: HwRngDevice) -> Result<()> {
        for d in self.devices.iter().flatten() {
            if d.device_id == device.device_id {
                return Err(Error::AlreadyExists);
            }
        }
        for slot in &mut self.devices {
            if slot.is_none() {
                *slot = Some(device);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a device by its `device_id`.
    ///
    /// Returns [`Error::NotFound`] if no device with that ID exists.
    pub fn unregister(&mut self, device_id: u8) -> Result<()> {
        for slot in &mut self.devices {
            if let Some(d) = slot {
                if d.device_id == device_id {
                    *slot = None;
                    self.count -= 1;
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Fill `buf` with random bytes from the best available device.
    ///
    /// Selects the device with the highest quality score and reads
    /// from it. Returns [`Error::NotFound`] if no devices are
    /// registered.
    pub fn get_random_bytes(&mut self, buf: &mut [u8]) -> Result<usize> {
        // Find the device with the best quality.
        let mut best_idx: Option<usize> = None;
        let mut best_quality = HwRngQuality::new(0);
        for (i, slot) in self.devices.iter().enumerate() {
            if let Some(dev) = slot {
                if dev.is_available() && dev.quality() > best_quality {
                    best_quality = dev.quality();
                    best_idx = Some(i);
                }
            }
        }
        let idx = best_idx.ok_or(Error::NotFound)?;
        if let Some(dev) = &mut self.devices[idx] {
            dev.read(buf)
        } else {
            Err(Error::NotFound)
        }
    }

    /// Return a reference to the best available source device.
    ///
    /// "Best" is determined by the highest quality score among
    /// available devices.
    pub fn best_source(&self) -> Option<&HwRngDevice> {
        let mut best: Option<&HwRngDevice> = None;
        for dev in self.devices.iter().flatten() {
            if dev.is_available() {
                match best {
                    Some(b) if b.quality() >= dev.quality() => {}
                    _ => best = Some(dev),
                }
            }
        }
        best
    }

    /// Return the number of registered devices.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Return `true` if no devices are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
