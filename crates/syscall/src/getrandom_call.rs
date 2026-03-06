// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getrandom(2)` syscall handler — cryptographic random number generation.
//!
//! Provides the `getrandom` syscall compatible with Linux 3.17+ and
//! POSIX.1-2024.  The syscall fills a caller-supplied buffer with random
//! bytes drawn from the kernel entropy pool.
//!
//! # Flags
//!
//! - `GRND_NONBLOCK` (1) — return `WouldBlock` instead of blocking when the
//!   pool has not yet been seeded.
//! - `GRND_RANDOM`   (2) — draw from the blocking `/dev/random` pool rather
//!   than the unlimited `/dev/urandom` pool.
//! - `GRND_INSECURE` (4) — return bytes even when the pool is not yet seeded
//!   (useful for testing; not cryptographically safe).
//!
//! # Pool model
//!
//! Two logical pools are maintained:
//! - **urandom pool** — always returns bytes; may be low-quality until seeded.
//! - **random pool**  — blocks (or returns `WouldBlock`) until the pool has
//!   accumulated sufficient entropy.
//!
//! Entropy is added via [`add_entropy`].  The pool uses a simple XOR+rotate
//! mixing strategy.  In a production kernel this would be ChaCha20 or a
//! hardware RNG; the model here is intentionally simple for the purpose of
//! establishing the syscall interface.
//!
//! # POSIX reference
//!
//! `.TheOpenGroup/susv5-html/functions/` — getrandom is a Linux extension
//! adopted by several BSDs; POSIX.1-2024 does not mandate it but permits it.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of the internal entropy pool in bytes.
pub const ENTROPY_POOL_SIZE: usize = 256;

/// Minimum entropy mix iterations before the pool is considered seeded.
const SEEDED_THRESHOLD: u64 = 4;

/// Maximum number of bytes that can be requested per `getrandom` call.
pub const GETRANDOM_MAX_BYTES: usize = 33_554_432; // 32 MiB

/// Syscall number for `getrandom` (x86_64 Linux ABI).
pub const SYS_GETRANDOM: u64 = 318;

// ---------------------------------------------------------------------------
// GetrandomFlags
// ---------------------------------------------------------------------------

/// Flags for the `getrandom` syscall.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GetrandomFlag {
    /// Do not block; return `WouldBlock` if pool is not yet seeded.
    GrndNonblock = 1,
    /// Use the blocking `/dev/random` pool.
    GrndRandom = 2,
    /// Return bytes even when pool is not seeded (insecure).
    GrndInsecure = 4,
}

/// Validated set of `getrandom` flags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GetrandomFlags(u32);

impl GetrandomFlags {
    /// Raw value for `GRND_NONBLOCK`.
    pub const GRND_NONBLOCK: u32 = 1;
    /// Raw value for `GRND_RANDOM`.
    pub const GRND_RANDOM: u32 = 2;
    /// Raw value for `GRND_INSECURE`.
    pub const GRND_INSECURE: u32 = 4;

    /// Mask of all valid flag bits.
    const VALID_MASK: u32 = Self::GRND_NONBLOCK | Self::GRND_RANDOM | Self::GRND_INSECURE;

    /// Parse and validate flags from a raw `u32`.
    ///
    /// Returns `InvalidArgument` if unknown bits are set or if mutually
    /// exclusive `GRND_RANDOM` and `GRND_INSECURE` are both set.
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw & !Self::VALID_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        // GRND_RANDOM and GRND_INSECURE are mutually exclusive.
        if raw & Self::GRND_RANDOM != 0 && raw & Self::GRND_INSECURE != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Return the raw bits.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether `GRND_NONBLOCK` is set.
    pub const fn is_nonblock(self) -> bool {
        self.0 & Self::GRND_NONBLOCK != 0
    }

    /// Whether `GRND_RANDOM` is set.
    pub const fn is_random(self) -> bool {
        self.0 & Self::GRND_RANDOM != 0
    }

    /// Whether `GRND_INSECURE` is set.
    pub const fn is_insecure(self) -> bool {
        self.0 & Self::GRND_INSECURE != 0
    }
}

// ---------------------------------------------------------------------------
// EntropyPool
// ---------------------------------------------------------------------------

/// Raw entropy pool with XOR+rotate mixing.
///
/// Not cryptographically strong — used to model the entropy accumulation
/// interface.  A real implementation would use ChaCha20 or a hardware TRNG.
#[derive(Debug)]
pub struct EntropyPool {
    /// Raw entropy bytes.
    pool: [u8; ENTROPY_POOL_SIZE],
    /// Number of times entropy has been mixed in.
    pub mix_count: u64,
    /// Whether the pool has accumulated enough entropy to be considered ready.
    pub ready: bool,
}

impl EntropyPool {
    /// Create an empty, un-seeded entropy pool.
    pub const fn new() -> Self {
        Self {
            pool: [0u8; ENTROPY_POOL_SIZE],
            mix_count: 0,
            ready: false,
        }
    }

    /// Mix `data[..len]` into the pool using XOR and left-rotation.
    ///
    /// Each input byte is XORed into the pool at an offset derived from
    /// `mix_count`, then rotated by 3 bits so repeated inputs produce
    /// different pool states.
    pub fn mix(&mut self, data: &[u8]) {
        let len = data.len().min(ENTROPY_POOL_SIZE);
        for (i, byte) in data[..len].iter().enumerate() {
            let idx = ((self.mix_count as usize).wrapping_add(i)) % ENTROPY_POOL_SIZE;
            self.pool[idx] ^= byte.rotate_left(3);
        }
        self.mix_count = self.mix_count.wrapping_add(1);
        if self.mix_count >= SEEDED_THRESHOLD {
            self.ready = true;
        }
    }

    /// Fill `out` with bytes derived from the pool.
    ///
    /// Uses a simple counter-mode extraction: each output byte is the
    /// pool byte at the current position XORed with the output index.
    pub fn extract(&self, out: &mut [u8], offset: u64) {
        for (i, byte) in out.iter_mut().enumerate() {
            let idx = (offset as usize).wrapping_add(i) % ENTROPY_POOL_SIZE;
            *byte = self.pool[idx] ^ (i as u8);
        }
    }

    /// Return `true` if the pool has been seeded.
    pub const fn is_ready(&self) -> bool {
        self.ready
    }
}

impl Default for EntropyPool {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// GetrandomState
// ---------------------------------------------------------------------------

/// Per-system `getrandom` state.
///
/// Maintains two logical pools:
/// - `urandom_pool` — always available; equivalent to `/dev/urandom`.
/// - `random_pool`  — blocks until seeded; equivalent to `/dev/random`.
#[derive(Debug)]
pub struct GetrandomState {
    /// The urandom pool (always available after any entropy is added).
    urandom_pool: EntropyPool,
    /// The random pool (blocks until `random_ready` is set).
    random_pool: EntropyPool,
    /// Counter tracking total bytes extracted (used as extraction offset).
    extract_counter: u64,
    /// Whether the system has been initially seeded (urandom ready).
    pub seeded: bool,
    /// Whether the blocking random pool is ready.
    pub urandom_ready: bool,
}

impl GetrandomState {
    /// Create a new, un-seeded state.
    pub const fn new() -> Self {
        Self {
            urandom_pool: EntropyPool::new(),
            random_pool: EntropyPool::new(),
            extract_counter: 0,
            seeded: false,
            urandom_ready: false,
        }
    }

    /// Return a reference to the urandom pool.
    pub const fn urandom_pool(&self) -> &EntropyPool {
        &self.urandom_pool
    }

    /// Return a reference to the random pool.
    pub const fn random_pool(&self) -> &EntropyPool {
        &self.random_pool
    }

    /// Return the current extraction counter.
    pub const fn extract_counter(&self) -> u64 {
        self.extract_counter
    }
}

impl Default for GetrandomState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// GetrandomStats
// ---------------------------------------------------------------------------

/// Accumulated statistics for the `getrandom` subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct GetrandomStats {
    /// Total number of `getrandom` calls.
    pub total_calls: u64,
    /// Total bytes of random data generated.
    pub bytes_generated: u64,
    /// Number of times the call blocked (pool not yet ready).
    pub blocks: u64,
    /// Number of `GRND_NONBLOCK` calls that returned `WouldBlock`.
    pub nonblock_fails: u64,
}

impl GetrandomStats {
    /// Create a zeroed stats record.
    pub const fn new() -> Self {
        Self {
            total_calls: 0,
            bytes_generated: 0,
            blocks: 0,
            nonblock_fails: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// add_entropy
// ---------------------------------------------------------------------------

/// Add external entropy to the `GetrandomState` pools.
///
/// Both pools receive the entropy.  Once the urandom pool has been mixed
/// enough times, `seeded` and `urandom_ready` are set.
///
/// # Arguments
///
/// * `state` — mutable reference to the system entropy state.
/// * `data`  — entropy source bytes.
pub fn add_entropy(state: &mut GetrandomState, data: &[u8]) {
    state.urandom_pool.mix(data);
    state.random_pool.mix(data);

    if state.urandom_pool.is_ready() {
        state.seeded = true;
        state.urandom_ready = true;
    }
}

// ---------------------------------------------------------------------------
// do_getrandom
// ---------------------------------------------------------------------------

/// Core handler for the `getrandom(2)` syscall.
///
/// Fills `buf[..buf_len]` with random bytes from the appropriate pool,
/// subject to flag-controlled blocking/non-blocking semantics.
///
/// # Arguments
///
/// * `state`   — Mutable reference to the system getrandom state.
/// * `stats`   — Mutable statistics accumulator.
/// * `buf`     — Destination buffer (must be at least `buf_len` bytes long).
/// * `buf_len` — Number of bytes requested.
/// * `flags`   — Raw `getrandom` flags (`GRND_NONBLOCK`, `GRND_RANDOM`,
///               `GRND_INSECURE`).
///
/// # Returns
///
/// Number of bytes written into `buf` on success.
///
/// # Errors
///
/// * `InvalidArgument` — Unknown flags, mutually exclusive flags set, or
///   `buf_len` exceeds `GETRANDOM_MAX_BYTES`.
/// * `WouldBlock`      — `GRND_NONBLOCK` set and pool is not yet seeded.
///
/// # Blocking semantics
///
/// If the pool is not yet seeded and neither `GRND_NONBLOCK` nor
/// `GRND_INSECURE` is set, in a real kernel the call would sleep until the
/// pool is seeded.  In this implementation `WouldBlock` is returned to model
/// the would-block condition (the caller is responsible for retrying).
pub fn do_getrandom(
    state: &mut GetrandomState,
    stats: &mut GetrandomStats,
    buf: &mut [u8],
    buf_len: usize,
    flags: u32,
) -> Result<usize> {
    let flags = GetrandomFlags::from_raw(flags)?;

    if buf_len == 0 {
        return Ok(0);
    }
    if buf_len > GETRANDOM_MAX_BYTES {
        return Err(Error::InvalidArgument);
    }
    if buf.len() < buf_len {
        return Err(Error::InvalidArgument);
    }

    stats.total_calls += 1;

    // Determine which pool to use and whether it is ready.
    let use_random_pool = flags.is_random();
    let pool_ready = if use_random_pool {
        state.random_pool.is_ready()
    } else {
        state.urandom_pool.is_ready()
    };

    // Blocking / non-blocking logic.
    if !pool_ready && !flags.is_insecure() {
        if flags.is_nonblock() {
            stats.nonblock_fails += 1;
            return Err(Error::WouldBlock);
        }
        // Simulate blocking: in a real kernel we would sleep here.
        // Model it as a would-block return so the caller can inject
        // entropy and retry.
        stats.blocks += 1;
        return Err(Error::WouldBlock);
    }

    // Extract bytes from the chosen pool.
    let counter = state.extract_counter;
    let out = &mut buf[..buf_len];
    if use_random_pool {
        state.random_pool.extract(out, counter);
    } else {
        state.urandom_pool.extract(out, counter);
    }

    state.extract_counter = state.extract_counter.wrapping_add(buf_len as u64);
    stats.bytes_generated += buf_len as u64;

    Ok(buf_len)
}

// ---------------------------------------------------------------------------
// Syscall entry point (raw register values)
// ---------------------------------------------------------------------------

/// Process a raw `getrandom` syscall.
///
/// # Arguments
///
/// * `state`    — Mutable entropy state.
/// * `stats`    — Mutable statistics.
/// * `buf`      — Destination buffer.
/// * `buf_len`  — Raw `count` argument from registers.
/// * `flags`    — Raw `flags` argument from registers.
pub fn sys_getrandom(
    state: &mut GetrandomState,
    stats: &mut GetrandomStats,
    buf: &mut [u8],
    buf_len: u64,
    flags: u64,
) -> Result<usize> {
    let len = usize::try_from(buf_len).map_err(|_| Error::InvalidArgument)?;
    let flags_u32 = u32::try_from(flags).map_err(|_| Error::InvalidArgument)?;
    do_getrandom(state, stats, buf, len, flags_u32)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded_state() -> GetrandomState {
        let mut s = GetrandomState::new();
        let entropy = [0xABu8; 32];
        // Mix enough times to cross the seeded threshold.
        for _ in 0..SEEDED_THRESHOLD {
            add_entropy(&mut s, &entropy);
        }
        s
    }

    #[test]
    fn test_flags_valid() {
        assert!(GetrandomFlags::from_raw(0).is_ok());
        assert!(GetrandomFlags::from_raw(GetrandomFlags::GRND_NONBLOCK).is_ok());
        assert!(GetrandomFlags::from_raw(GetrandomFlags::GRND_RANDOM).is_ok());
        assert!(GetrandomFlags::from_raw(GetrandomFlags::GRND_INSECURE).is_ok());
    }

    #[test]
    fn test_flags_invalid_bits() {
        assert_eq!(GetrandomFlags::from_raw(0x08), Err(Error::InvalidArgument));
    }

    #[test]
    fn test_flags_mutually_exclusive() {
        let both = GetrandomFlags::GRND_RANDOM | GetrandomFlags::GRND_INSECURE;
        assert_eq!(GetrandomFlags::from_raw(both), Err(Error::InvalidArgument));
    }

    #[test]
    fn test_add_entropy_seeded() {
        let mut s = GetrandomState::new();
        assert!(!s.seeded);
        let data = [0x42u8; 16];
        for _ in 0..SEEDED_THRESHOLD {
            add_entropy(&mut s, &data);
        }
        assert!(s.seeded);
        assert!(s.urandom_ready);
    }

    #[test]
    fn test_getrandom_unset_nonblock_returns_wouldblock() {
        let mut s = GetrandomState::new();
        let mut stats = GetrandomStats::new();
        let mut buf = [0u8; 32];
        let result = do_getrandom(
            &mut s,
            &mut stats,
            &mut buf,
            32,
            GetrandomFlags::GRND_NONBLOCK,
        );
        assert_eq!(result, Err(Error::WouldBlock));
        assert_eq!(stats.nonblock_fails, 1);
    }

    #[test]
    fn test_getrandom_unseeded_blocks() {
        let mut s = GetrandomState::new();
        let mut stats = GetrandomStats::new();
        let mut buf = [0u8; 32];
        // Neither nonblock nor insecure — should model a block.
        let result = do_getrandom(&mut s, &mut stats, &mut buf, 32, 0);
        assert_eq!(result, Err(Error::WouldBlock));
        assert_eq!(stats.blocks, 1);
    }

    #[test]
    fn test_getrandom_insecure_unseeded_succeeds() {
        let mut s = GetrandomState::new();
        let mut stats = GetrandomStats::new();
        let mut buf = [0u8; 32];
        let n = do_getrandom(
            &mut s,
            &mut stats,
            &mut buf,
            32,
            GetrandomFlags::GRND_INSECURE,
        )
        .unwrap();
        assert_eq!(n, 32);
        assert_eq!(stats.bytes_generated, 32);
    }

    #[test]
    fn test_getrandom_seeded_success() {
        let mut s = seeded_state();
        let mut stats = GetrandomStats::new();
        let mut buf = [0u8; 64];
        let n = do_getrandom(&mut s, &mut stats, &mut buf, 64, 0).unwrap();
        assert_eq!(n, 64);
        assert_eq!(stats.bytes_generated, 64);
        assert_eq!(stats.total_calls, 1);
    }

    #[test]
    fn test_getrandom_zero_len() {
        let mut s = seeded_state();
        let mut stats = GetrandomStats::new();
        let mut buf = [0u8; 4];
        let n = do_getrandom(&mut s, &mut stats, &mut buf, 0, 0).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn test_getrandom_buf_too_small() {
        let mut s = seeded_state();
        let mut stats = GetrandomStats::new();
        let mut buf = [0u8; 4];
        // Requesting more bytes than buf holds.
        let result = do_getrandom(&mut s, &mut stats, &mut buf, 16, 0);
        assert_eq!(result, Err(Error::InvalidArgument));
    }

    #[test]
    fn test_getrandom_random_pool() {
        let mut s = seeded_state();
        let mut stats = GetrandomStats::new();
        let mut buf = [0u8; 32];
        let n = do_getrandom(
            &mut s,
            &mut stats,
            &mut buf,
            32,
            GetrandomFlags::GRND_RANDOM,
        )
        .unwrap();
        assert_eq!(n, 32);
    }

    #[test]
    fn test_getrandom_counter_advances() {
        let mut s = seeded_state();
        let mut stats = GetrandomStats::new();
        let mut buf1 = [0u8; 8];
        let mut buf2 = [0u8; 8];
        do_getrandom(&mut s, &mut stats, &mut buf1, 8, 0).unwrap();
        do_getrandom(&mut s, &mut stats, &mut buf2, 8, 0).unwrap();
        // Counter should have advanced by 8 after first call, making outputs differ.
        assert_ne!(buf1, buf2);
    }

    #[test]
    fn test_entropy_pool_mix_ready() {
        let mut pool = EntropyPool::new();
        assert!(!pool.is_ready());
        for _ in 0..SEEDED_THRESHOLD {
            pool.mix(&[1u8, 2, 3, 4]);
        }
        assert!(pool.is_ready());
    }

    #[test]
    fn test_entropy_pool_extract_differs_by_offset() {
        let mut pool = EntropyPool::new();
        pool.mix(&[0xFF; ENTROPY_POOL_SIZE]);
        pool.mix(&[0xAA; ENTROPY_POOL_SIZE]);
        pool.mix(&[0x55; ENTROPY_POOL_SIZE]);
        pool.mix(&[0x11; ENTROPY_POOL_SIZE]);

        let mut out1 = [0u8; 16];
        let mut out2 = [0u8; 16];
        pool.extract(&mut out1, 0);
        pool.extract(&mut out2, 16);
        assert_ne!(out1, out2);
    }

    #[test]
    fn test_sys_getrandom() {
        let mut s = seeded_state();
        let mut stats = GetrandomStats::new();
        let mut buf = [0u8; 16];
        let n = sys_getrandom(&mut s, &mut stats, &mut buf, 16, 0).unwrap();
        assert_eq!(n, 16);
    }

    #[test]
    fn test_stats_accumulate() {
        let mut s = seeded_state();
        let mut stats = GetrandomStats::new();
        let mut buf = [0u8; 32];
        do_getrandom(&mut s, &mut stats, &mut buf, 32, 0).unwrap();
        do_getrandom(&mut s, &mut stats, &mut buf, 32, 0).unwrap();
        assert_eq!(stats.total_calls, 2);
        assert_eq!(stats.bytes_generated, 64);
    }
}
