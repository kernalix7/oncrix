// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel random number generator (/dev/random, /dev/urandom).
//!
//! Provides a cryptographically-inspired PRNG based on a simplified
//! ChaCha20 quarter-round construction, fed by an entropy pool that
//! collects timing jitter from interrupts, disk I/O, and keyboard
//! input.
//!
//! # Design
//!
//! - [`EntropyPool`]: 256-byte ring buffer that accumulates raw
//!   entropy via XOR mixing.
//! - [`ChaCha20State`]: Simplified ChaCha20-based PRNG that converts
//!   pooled entropy into uniform random bytes.
//! - [`KernelRng`]: Top-level RNG combining the pool and PRNG,
//!   exposing `/dev/random` (blocking) and `/dev/urandom`
//!   (non-blocking) semantics.
//!
//! # `getrandom(2)` support
//!
//! The `SYS_GETRANDOM` (318) syscall uses [`GRND_NONBLOCK`] and
//! [`GRND_RANDOM`] flags to select behavior.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

/// `getrandom(2)` syscall number (Linux x86_64 ABI).
pub const SYS_GETRANDOM: u64 = 318;

/// `getrandom` flag: return `EAGAIN` instead of blocking.
pub const GRND_NONBLOCK: u32 = 1;

/// `getrandom` flag: use `/dev/random` (blocking) pool.
pub const GRND_RANDOM: u32 = 2;

/// Maximum tracked entropy in bits.
const MAX_ENTROPY_BITS: u32 = 2048;

/// Minimum entropy (bits) required before `/dev/random` unblocks.
const MIN_RESEED_ENTROPY: u32 = 256;

/// Size of the entropy pool in bytes.
const POOL_SIZE: usize = 256;

/// ChaCha20 block size in bytes.
const CHACHA_BLOCK_SIZE: usize = 64;

// ── Entropy mixing helpers ───────────────────────────────────────

/// Mix a `u64` value into the entropy pool via XOR at `*pos`.
///
/// Advances `*pos` by 8, wrapping around the 256-byte pool.
pub fn mix_u64(pool: &mut [u8], pos: &mut usize, val: u64) {
    let bytes = val.to_le_bytes();
    for &b in &bytes {
        pool[*pos % pool.len()] ^= b;
        *pos = (*pos).wrapping_add(1) % pool.len();
    }
}

/// Fold a 256-byte pool into 32 bytes by XOR-ing 8 chunks.
///
/// This is a simple hash: the pool is split into 8 consecutive
/// 32-byte blocks which are XOR-reduced into a single 32-byte
/// digest.
pub fn hash_pool(pool: &[u8; POOL_SIZE]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0usize;
    while i < POOL_SIZE {
        let mut j = 0usize;
        while j < 32 {
            out[j] ^= pool[i.wrapping_add(j)];
            j = j.wrapping_add(1);
        }
        i = i.wrapping_add(32);
    }
    out
}

// ── EntropyPool ──────────────────────────────────────────────────

/// Raw entropy accumulator.
///
/// Collects entropy by XOR-mixing incoming data bytes into a
/// 256-byte ring buffer. Tracks an estimated number of entropy
/// bits available.
pub struct EntropyPool {
    /// The 256-byte mixing buffer.
    pool: [u8; POOL_SIZE],
    /// Current write position in the ring buffer.
    write_pos: usize,
    /// Estimated bits of entropy accumulated (capped at
    /// [`MAX_ENTROPY_BITS`]).
    entropy_bits: u32,
}

impl Default for EntropyPool {
    fn default() -> Self {
        Self::new()
    }
}

impl EntropyPool {
    /// Create a new, zeroed entropy pool.
    pub const fn new() -> Self {
        Self {
            pool: [0u8; POOL_SIZE],
            write_pos: 0,
            entropy_bits: 0,
        }
    }

    /// Mix `data` into the pool and credit `estimated_bits` of
    /// entropy (capped at [`MAX_ENTROPY_BITS`]).
    pub fn add_entropy(&mut self, data: &[u8], estimated_bits: u32) {
        for &b in data {
            self.pool[self.write_pos] ^= b;
            self.write_pos = self.write_pos.wrapping_add(1) % POOL_SIZE;
        }
        self.entropy_bits = self.entropy_bits.saturating_add(estimated_bits);
        if self.entropy_bits > MAX_ENTROPY_BITS {
            self.entropy_bits = MAX_ENTROPY_BITS;
        }
    }

    /// Return the estimated number of entropy bits available.
    pub fn available_entropy(&self) -> u32 {
        self.entropy_bits
    }
}

// ── ChaCha20State ────────────────────────────────────────────────

/// Simplified ChaCha20 quarter-round based PRNG.
///
/// Implements the ChaCha20 state initialization, quarter-round
/// operation, and block generation as described in RFC 8439.
pub struct ChaCha20State {
    /// The 16-word (512-bit) ChaCha20 state.
    state: [u32; 16],
}

impl Default for ChaCha20State {
    fn default() -> Self {
        Self::new()
    }
}

impl ChaCha20State {
    /// Create a new, zeroed ChaCha20 state.
    pub const fn new() -> Self {
        Self { state: [0u32; 16] }
    }

    /// Initialize the state per ChaCha20 spec.
    ///
    /// - Words 0..3: "expand 32-byte k" constant
    /// - Words 4..11: 256-bit `seed` (key)
    /// - Word 12: block counter (starts at 0)
    /// - Words 13..15: 96-bit `nonce`
    pub fn init(&mut self, seed: &[u8; 32], nonce: &[u8; 12]) {
        // "expand 32-byte k"
        self.state[0] = 0x6170_7865;
        self.state[1] = 0x3320_646e;
        self.state[2] = 0x7962_2d32;
        self.state[3] = 0x6b20_6574;

        // Key (seed) — 8 little-endian u32s.
        let mut i = 0usize;
        while i < 8 {
            let base = i.wrapping_mul(4);
            self.state[4usize.wrapping_add(i)] = u32::from_le_bytes([
                seed[base],
                seed[base.wrapping_add(1)],
                seed[base.wrapping_add(2)],
                seed[base.wrapping_add(3)],
            ]);
            i = i.wrapping_add(1);
        }

        // Block counter.
        self.state[12] = 0;

        // Nonce — 3 little-endian u32s.
        let mut j = 0usize;
        while j < 3 {
            let base = j.wrapping_mul(4);
            self.state[13usize.wrapping_add(j)] = u32::from_le_bytes([
                nonce[base],
                nonce[base.wrapping_add(1)],
                nonce[base.wrapping_add(2)],
                nonce[base.wrapping_add(3)],
            ]);
            j = j.wrapping_add(1);
        }
    }

    /// ChaCha20 quarter-round on indices `a`, `b`, `c`, `d`.
    fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(16);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(12);

        state[a] = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d] = state[d].rotate_left(8);

        state[c] = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b] = state[b].rotate_left(7);
    }

    /// Generate one 64-byte block of ChaCha20 output.
    ///
    /// Performs 20 rounds (10 double-rounds of column + diagonal
    /// quarter-rounds), then adds the original state and
    /// increments the block counter.
    pub fn block(&mut self) -> [u8; CHACHA_BLOCK_SIZE] {
        let mut working = self.state;

        // 20 rounds = 10 double-rounds.
        let mut round = 0u32;
        while round < 10 {
            // Column rounds.
            Self::quarter_round(&mut working, 0, 4, 8, 12);
            Self::quarter_round(&mut working, 1, 5, 9, 13);
            Self::quarter_round(&mut working, 2, 6, 10, 14);
            Self::quarter_round(&mut working, 3, 7, 11, 15);
            // Diagonal rounds.
            Self::quarter_round(&mut working, 0, 5, 10, 15);
            Self::quarter_round(&mut working, 1, 6, 11, 12);
            Self::quarter_round(&mut working, 2, 7, 8, 13);
            Self::quarter_round(&mut working, 3, 4, 9, 14);
            round = round.wrapping_add(1);
        }

        // Add original state.
        let mut i = 0usize;
        while i < 16 {
            working[i] = working[i].wrapping_add(self.state[i]);
            i = i.wrapping_add(1);
        }

        // Serialize to bytes.
        let mut out = [0u8; CHACHA_BLOCK_SIZE];
        let mut w = 0usize;
        while w < 16 {
            let bytes = working[w].to_le_bytes();
            let base = w.wrapping_mul(4);
            out[base] = bytes[0];
            out[base.wrapping_add(1)] = bytes[1];
            out[base.wrapping_add(2)] = bytes[2];
            out[base.wrapping_add(3)] = bytes[3];
            w = w.wrapping_add(1);
        }

        // Increment block counter.
        self.state[12] = self.state[12].wrapping_add(1);

        out
    }

    /// Fill `out` with PRNG output, rekeying after each block.
    ///
    /// After producing each 64-byte block, the first 32 bytes of
    /// the output are used to re-seed the key (forward secrecy).
    pub fn generate(&mut self, out: &mut [u8]) {
        let mut offset = 0usize;
        while offset < out.len() {
            let block = self.block();
            let remaining = out.len().wrapping_sub(offset);
            let copy_len = if remaining < CHACHA_BLOCK_SIZE {
                remaining
            } else {
                CHACHA_BLOCK_SIZE
            };

            let mut i = 0usize;
            while i < copy_len {
                out[offset.wrapping_add(i)] = block[i];
                i = i.wrapping_add(1);
            }
            offset = offset.wrapping_add(copy_len);

            // Rekey: use first 32 bytes of block as new key.
            let mut new_key = [0u8; 32];
            let mut k = 0usize;
            while k < 32 {
                new_key[k] = block[k];
                k = k.wrapping_add(1);
            }
            // Extract nonce from bytes 32..44 of block.
            let mut new_nonce = [0u8; 12];
            let mut n = 0usize;
            while n < 12 {
                new_nonce[n] = block[32usize.wrapping_add(n)];
                n = n.wrapping_add(1);
            }
            self.init(&new_key, &new_nonce);
        }
    }
}

// ── KernelRng ────────────────────────────────────────────────────

/// Top-level kernel random number generator.
///
/// Combines an [`EntropyPool`] for raw entropy collection with a
/// [`ChaCha20State`] PRNG for output generation. Supports both
/// blocking (`/dev/random`) and non-blocking (`/dev/urandom`)
/// interfaces.
pub struct KernelRng {
    /// Raw entropy pool.
    pool: EntropyPool,
    /// ChaCha20-based PRNG.
    chacha: ChaCha20State,
    /// Whether the PRNG has been seeded at least once.
    initialized: bool,
    /// Number of times the PRNG has been reseeded.
    reseed_count: u64,
}

impl Default for KernelRng {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelRng {
    /// Create a new, unseeded kernel RNG.
    pub const fn new() -> Self {
        Self {
            pool: EntropyPool::new(),
            chacha: ChaCha20State::new(),
            initialized: false,
            reseed_count: 0,
        }
    }

    /// Mix interrupt timing entropy into the pool.
    ///
    /// Call this from every IRQ handler to accumulate timing jitter.
    /// Each IRQ contributes an estimated 1 bit of entropy.
    pub fn add_interrupt_entropy(&mut self, irq: u8, timestamp: u64) {
        let mixed = timestamp ^ (irq as u64).wrapping_shl(56);
        let bytes = mixed.to_le_bytes();
        self.pool.add_entropy(&bytes, 1);
    }

    /// Mix disk I/O timing entropy into the pool.
    ///
    /// Call this on each disk operation completion. Each event
    /// contributes an estimated 2 bits of entropy.
    pub fn add_disk_entropy(&mut self, sector: u64, timestamp: u64) {
        let mixed = timestamp ^ sector.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let bytes = mixed.to_le_bytes();
        self.pool.add_entropy(&bytes, 2);
    }

    /// Mix keyboard input timing entropy into the pool.
    ///
    /// Call this on each key event. Each keystroke contributes an
    /// estimated 4 bits of entropy due to human timing variability.
    pub fn add_input_entropy(&mut self, scancode: u8, timestamp: u64) {
        let mixed = timestamp ^ (scancode as u64).wrapping_shl(48);
        let bytes = mixed.to_le_bytes();
        self.pool.add_entropy(&bytes, 4);
    }

    /// Reseed the ChaCha20 PRNG from the entropy pool.
    ///
    /// Extracts a 32-byte hash of the pool as the new key and
    /// constructs a 12-byte nonce from the reseed counter. Resets
    /// the pool entropy estimate to zero.
    pub fn reseed(&mut self) {
        let seed = hash_pool(&self.pool.pool);

        // Construct nonce from reseed counter + first pool bytes.
        let counter_bytes = self.reseed_count.to_le_bytes();
        let mut nonce = [0u8; 12];
        let mut i = 0usize;
        while i < 8 {
            nonce[i] = counter_bytes[i];
            i = i.wrapping_add(1);
        }
        // Fill remaining 4 bytes from pool head.
        nonce[8] = self.pool.pool[0];
        nonce[9] = self.pool.pool[1];
        nonce[10] = self.pool.pool[2];
        nonce[11] = self.pool.pool[3];

        self.chacha.init(&seed, &nonce);
        self.reseed_count = self.reseed_count.wrapping_add(1);
        self.pool.entropy_bits = 0;
        self.initialized = true;
    }

    /// Fill `buf` with random bytes from `/dev/random`.
    ///
    /// Requires at least [`MIN_RESEED_ENTROPY`] bits of entropy in
    /// the pool before producing output. Returns
    /// [`Error::WouldBlock`] if insufficient entropy is available
    /// (the caller should retry later).
    pub fn get_random_bytes(&mut self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.pool.available_entropy() < MIN_RESEED_ENTROPY {
            return Err(Error::WouldBlock);
        }
        self.reseed();
        self.chacha.generate(buf);
        Ok(buf.len())
    }

    /// Fill `buf` with random bytes from `/dev/urandom`.
    ///
    /// Always succeeds. If the PRNG has never been seeded, it
    /// performs a best-effort reseed from whatever entropy is
    /// available. Output quality depends on the amount of entropy
    /// that has been collected.
    pub fn get_urandom_bytes(&mut self, buf: &mut [u8]) -> usize {
        if buf.is_empty() {
            return 0;
        }
        // Reseed if we have gathered enough entropy, or if we
        // have never been initialized.
        if !self.initialized || self.pool.available_entropy() >= MIN_RESEED_ENTROPY {
            self.reseed();
        }
        self.chacha.generate(buf);
        buf.len()
    }

    /// Return a random `u32`.
    pub fn get_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.get_urandom_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    /// Return a random `u64`.
    pub fn get_u64(&mut self) -> u64 {
        let mut buf = [0u8; 8];
        self.get_urandom_bytes(&mut buf);
        u64::from_le_bytes(buf)
    }
}
