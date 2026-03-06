// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getrandom(2)` syscall handler — cryptographically secure random bytes.
//!
//! Fills a caller-supplied buffer with random bytes derived from the kernel
//! entropy pool.  The syscall was introduced in Linux 3.17 and adopted by
//! several BSDs; it is not standardised by POSIX.1-2024 but is widely
//! considered the modern successor to `/dev/urandom` reads.
//!
//! # Flags
//!
//! | Flag             | Value | Effect                                                  |
//! |------------------|-------|---------------------------------------------------------|
//! | `GRND_NONBLOCK`  |  1    | Return `WouldBlock` instead of sleeping when unready.   |
//! | `GRND_RANDOM`    |  2    | Draw from the blocking `/dev/random` pool.              |
//! | `GRND_INSECURE`  |  4    | Return bytes even before the pool is seeded.            |
//!
//! `GRND_RANDOM` and `GRND_INSECURE` are mutually exclusive.
//!
//! # Partial reads
//!
//! The kernel may return fewer than `len` bytes if `GRND_RANDOM` is used and
//! insufficient entropy is available.  The caller must loop to obtain all
//! requested bytes.
//!
//! # Linux reference
//!
//! `drivers/char/random.c` — `getrandom_syscall()`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Flag constants
// ---------------------------------------------------------------------------

/// Do not block; return `WouldBlock` when pool is not seeded.
pub const GRND_NONBLOCK: u32 = 1;
/// Use the blocking `/dev/random` pool.
pub const GRND_RANDOM: u32 = 2;
/// Return bytes before seeding (insecure — for testing).
pub const GRND_INSECURE: u32 = 4;

/// Mask of all valid `getrandom` flag bits.
const GRND_FLAGS_MASK: u32 = GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE;

/// Maximum bytes per single `getrandom` call (32 MiB).
pub const GETRANDOM_MAX: usize = 33_554_432;

// ---------------------------------------------------------------------------
// GetrandomFlags
// ---------------------------------------------------------------------------

/// Validated flags for the `getrandom` syscall.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GetrandomFlags(u32);

impl GetrandomFlags {
    /// Parse and validate a raw flags value.
    ///
    /// # Errors
    ///
    /// * [`Error::InvalidArgument`] — unknown bits, or both `GRND_RANDOM`
    ///   and `GRND_INSECURE` set simultaneously.
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw & !GRND_FLAGS_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        if raw & GRND_RANDOM != 0 && raw & GRND_INSECURE != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Return `true` when `GRND_NONBLOCK` is set.
    pub const fn nonblock(self) -> bool {
        self.0 & GRND_NONBLOCK != 0
    }

    /// Return `true` when `GRND_RANDOM` is set.
    pub const fn use_random_pool(self) -> bool {
        self.0 & GRND_RANDOM != 0
    }

    /// Return `true` when `GRND_INSECURE` is set.
    pub const fn insecure(self) -> bool {
        self.0 & GRND_INSECURE != 0
    }
}

// ---------------------------------------------------------------------------
// EntropyPool
// ---------------------------------------------------------------------------

/// Size of the entropy pool in bytes.
pub const POOL_SIZE: usize = 256;

/// Minimum number of mix operations before the pool is considered seeded.
const SEED_THRESHOLD: u64 = 4;

/// A simple XOR+rotate entropy accumulator.
///
/// Not cryptographically suitable for production — models the pool API.
/// A real implementation uses ChaCha20 or a hardware TRNG.
#[derive(Debug)]
pub struct EntropyPool {
    data: [u8; POOL_SIZE],
    /// Number of entropy mixing operations performed.
    pub mix_count: u64,
    /// Whether the pool has reached the seeding threshold.
    pub seeded: bool,
}

impl EntropyPool {
    /// Create an empty, un-seeded pool.
    pub const fn new() -> Self {
        Self {
            data: [0u8; POOL_SIZE],
            mix_count: 0,
            seeded: false,
        }
    }

    /// Mix `src` bytes into the pool.
    ///
    /// Each source byte is XORed into the pool at an index derived from
    /// `mix_count`, rotated left by 3 bits to prevent trivial cancellation.
    pub fn mix(&mut self, src: &[u8]) {
        let len = src.len().min(POOL_SIZE);
        for (i, &byte) in src[..len].iter().enumerate() {
            let idx = (self.mix_count as usize + i) % POOL_SIZE;
            self.data[idx] ^= byte.rotate_left(3);
        }
        self.mix_count = self.mix_count.wrapping_add(1);
        if self.mix_count >= SEED_THRESHOLD {
            self.seeded = true;
        }
    }

    /// Extract `count` bytes into `out` starting at `offset`.
    pub fn extract(&self, out: &mut [u8], offset: u64) {
        for (i, slot) in out.iter_mut().enumerate() {
            let idx = (offset as usize + i) % POOL_SIZE;
            *slot = self.data[idx] ^ (i as u8);
        }
    }
}

impl Default for EntropyPool {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RandomSubsystem
// ---------------------------------------------------------------------------

/// Kernel random-number subsystem state.
///
/// Maintains two logical pools:
/// - `urandom` — always provides bytes; equivalent to `/dev/urandom`.
/// - `random`  — blocks until seeded; equivalent to `/dev/random`.
pub struct RandomSubsystem {
    urandom: EntropyPool,
    random: EntropyPool,
    /// Monotonically increasing extraction counter.
    counter: u64,
}

impl RandomSubsystem {
    /// Create a new, un-seeded subsystem.
    pub const fn new() -> Self {
        Self {
            urandom: EntropyPool::new(),
            random: EntropyPool::new(),
            counter: 0,
        }
    }

    /// Add hardware-derived entropy to both pools.
    pub fn add_hw_entropy(&mut self, data: &[u8]) {
        self.urandom.mix(data);
        self.random.mix(data);
    }

    /// Return `true` if the urandom pool is ready.
    pub const fn urandom_ready(&self) -> bool {
        self.urandom.seeded
    }

    /// Return `true` if the random pool is ready.
    pub const fn random_ready(&self) -> bool {
        self.random.seeded
    }
}

impl Default for RandomSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// GetrandomStats
// ---------------------------------------------------------------------------

/// Accumulated statistics for the `getrandom` syscall.
#[derive(Debug, Clone, Copy, Default)]
pub struct GetrandomStats {
    /// Total number of successful calls.
    pub calls: u64,
    /// Total bytes generated.
    pub bytes: u64,
    /// Number of `WouldBlock` returns.
    pub would_block: u64,
    /// Number of partial reads from the random pool.
    pub partial: u64,
}

impl GetrandomStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            calls: 0,
            bytes: 0,
            would_block: 0,
            partial: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// do_sys_getrandom — primary handler
// ---------------------------------------------------------------------------

/// `getrandom(2)` syscall handler.
///
/// Fills `buf[..len]` with random bytes, obeying the `flags` semantics.
///
/// # Arguments
///
/// * `rng`   — Mutable random subsystem state.
/// * `stats` — Mutable statistics accumulator.
/// * `buf`   — Output buffer (must be at least `len` bytes).
/// * `len`   — Number of bytes requested.
/// * `flags` — Raw `getrandom` flags.
///
/// # Returns
///
/// Number of bytes written on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — invalid flags, `len > GETRANDOM_MAX`, or
///   buffer too small.
/// * [`Error::WouldBlock`]      — pool not seeded and `GRND_NONBLOCK` set.
pub fn do_sys_getrandom(
    rng: &mut RandomSubsystem,
    stats: &mut GetrandomStats,
    buf: &mut [u8],
    len: usize,
    flags: u32,
) -> Result<usize> {
    let flags = GetrandomFlags::from_raw(flags)?;

    if len == 0 {
        return Ok(0);
    }
    if len > GETRANDOM_MAX || buf.len() < len {
        return Err(Error::InvalidArgument);
    }

    // Determine pool readiness.
    let pool_ready = if flags.use_random_pool() {
        rng.random_ready()
    } else {
        rng.urandom_ready()
    };

    if !pool_ready && !flags.insecure() {
        stats.would_block += 1;
        return Err(Error::WouldBlock);
    }

    // For the random pool, allow a partial read proportional to mix_count
    // to model entropy depletion.  Full reads allowed from urandom.
    let available = if flags.use_random_pool() && pool_ready {
        let mx = rng.random.mix_count as usize;
        len.min(mx.max(1))
    } else {
        len
    };

    let out = &mut buf[..available];
    let offset = rng.counter;

    if flags.use_random_pool() {
        rng.random.extract(out, offset);
    } else {
        rng.urandom.extract(out, offset);
    }

    rng.counter = rng.counter.wrapping_add(available as u64);
    stats.calls += 1;
    stats.bytes += available as u64;

    if available < len {
        stats.partial += 1;
    }

    Ok(available)
}

/// Raw register-argument entry point for the `getrandom` syscall.
///
/// Converts `u64` register values to appropriate Rust types and delegates
/// to [`do_sys_getrandom`].
pub fn sys_getrandom(
    rng: &mut RandomSubsystem,
    stats: &mut GetrandomStats,
    buf: &mut [u8],
    buf_len: u64,
    flags: u64,
) -> Result<usize> {
    let len = usize::try_from(buf_len).map_err(|_| Error::InvalidArgument)?;
    let raw_flags = u32::try_from(flags).map_err(|_| Error::InvalidArgument)?;
    do_sys_getrandom(rng, stats, buf, len, raw_flags)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn seeded() -> RandomSubsystem {
        let mut rng = RandomSubsystem::new();
        let data = [0x5Au8; 64];
        for _ in 0..SEED_THRESHOLD {
            rng.add_hw_entropy(&data);
        }
        rng
    }

    #[test]
    fn flags_valid() {
        assert!(GetrandomFlags::from_raw(0).is_ok());
        assert!(GetrandomFlags::from_raw(GRND_NONBLOCK).is_ok());
        assert!(GetrandomFlags::from_raw(GRND_RANDOM).is_ok());
        assert!(GetrandomFlags::from_raw(GRND_INSECURE).is_ok());
    }

    #[test]
    fn flags_unknown_bits_rejected() {
        assert_eq!(GetrandomFlags::from_raw(0x08), Err(Error::InvalidArgument));
    }

    #[test]
    fn flags_random_and_insecure_mutex() {
        assert_eq!(
            GetrandomFlags::from_raw(GRND_RANDOM | GRND_INSECURE),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn unseeded_nonblock_returns_wouldblock() {
        let mut rng = RandomSubsystem::new();
        let mut stats = GetrandomStats::new();
        let mut buf = [0u8; 16];
        assert_eq!(
            do_sys_getrandom(&mut rng, &mut stats, &mut buf, 16, GRND_NONBLOCK),
            Err(Error::WouldBlock)
        );
        assert_eq!(stats.would_block, 1);
    }

    #[test]
    fn unseeded_blocking_returns_wouldblock_stub() {
        let mut rng = RandomSubsystem::new();
        let mut stats = GetrandomStats::new();
        let mut buf = [0u8; 16];
        assert_eq!(
            do_sys_getrandom(&mut rng, &mut stats, &mut buf, 16, 0),
            Err(Error::WouldBlock)
        );
    }

    #[test]
    fn insecure_succeeds_unseeded() {
        let mut rng = RandomSubsystem::new();
        let mut stats = GetrandomStats::new();
        let mut buf = [0u8; 32];
        let n = do_sys_getrandom(&mut rng, &mut stats, &mut buf, 32, GRND_INSECURE).unwrap();
        assert_eq!(n, 32);
        assert_eq!(stats.bytes, 32);
    }

    #[test]
    fn seeded_full_read_urandom() {
        let mut rng = seeded();
        let mut stats = GetrandomStats::new();
        let mut buf = [0u8; 64];
        let n = do_sys_getrandom(&mut rng, &mut stats, &mut buf, 64, 0).unwrap();
        assert_eq!(n, 64);
        assert_eq!(stats.calls, 1);
    }

    #[test]
    fn counter_advances_across_calls() {
        let mut rng = seeded();
        let mut stats = GetrandomStats::new();
        let mut b1 = [0u8; 8];
        let mut b2 = [0u8; 8];
        do_sys_getrandom(&mut rng, &mut stats, &mut b1, 8, 0).unwrap();
        do_sys_getrandom(&mut rng, &mut stats, &mut b2, 8, 0).unwrap();
        assert_ne!(b1, b2);
    }

    #[test]
    fn zero_len_succeeds_immediately() {
        let mut rng = RandomSubsystem::new();
        let mut stats = GetrandomStats::new();
        let mut buf = [0u8; 4];
        assert_eq!(
            do_sys_getrandom(&mut rng, &mut stats, &mut buf, 0, 0).unwrap(),
            0
        );
    }

    #[test]
    fn buf_too_small_rejected() {
        let mut rng = seeded();
        let mut stats = GetrandomStats::new();
        let mut buf = [0u8; 4];
        assert_eq!(
            do_sys_getrandom(&mut rng, &mut stats, &mut buf, 8, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn entropy_pool_mix_seeded() {
        let mut pool = EntropyPool::new();
        assert!(!pool.seeded);
        for _ in 0..SEED_THRESHOLD {
            pool.mix(&[0x42; 32]);
        }
        assert!(pool.seeded);
    }

    #[test]
    fn sys_getrandom_entry() {
        let mut rng = seeded();
        let mut stats = GetrandomStats::new();
        let mut buf = [0u8; 16];
        let n = sys_getrandom(&mut rng, &mut stats, &mut buf, 16, 0).unwrap();
        assert_eq!(n, 16);
    }
}
