// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel random number generator (ChaCha20-based).
//!
//! Provides cryptographically secure random bytes using a ChaCha20
//! stream cipher seeded from an entropy pool. Entropy is collected
//! from hardware events (interrupts, jitter) and mixed into the
//! pool using XOR-shift mixing.
//!
//! # Architecture
//!
//! ```text
//! RandomSubsystem
//! ├── entropy_pool: EntropyPool
//! │   ├── input_pool: [u32; POOL_WORDS]
//! │   └── entropy_count (credits)
//! ├── chacha_state: ChaChaState
//! │   ├── key: [u32; 8]
//! │   ├── counter: u64
//! │   └── nonce: [u32; 3]
//! └── stats: RandomStats
//!
//! Entropy flow:
//!   Hardware event → add_entropy(data) → mix into pool
//!   get_random_bytes() → if seeded: ChaCha20 output
//!                      → if not seeded: Err(WouldBlock)
//! ```
//!
//! # Entropy Credits
//!
//! Each entropy contribution is assigned a credit value (in bits).
//! The pool is considered "seeded" when it has accumulated at least
//! 256 bits of entropy credit.
//!
//! # Reference
//!
//! Linux `drivers/char/random.c`, `include/linux/random.h`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────

/// Entropy pool size in 32-bit words.
const POOL_WORDS: usize = 128;

/// Minimum entropy credits (bits) to consider the pool seeded.
const SEED_THRESHOLD: u32 = 256;

/// Maximum entropy credits.
const MAX_ENTROPY_CREDITS: u32 = POOL_WORDS as u32 * 32;

/// ChaCha20 block size in bytes.
const CHACHA_BLOCK_SIZE: usize = 64;

/// ChaCha20 key size in 32-bit words.
const CHACHA_KEY_WORDS: usize = 8;

/// ChaCha20 rounds.
const CHACHA_ROUNDS: u32 = 20;

/// Output buffer size for buffered random bytes.
const OUTPUT_BUFFER_SIZE: usize = 256;

/// Maximum single request size.
const MAX_REQUEST_SIZE: usize = 1024;

// ── ChaChaState ─────────────────────────────────────────────

/// ChaCha20 stream cipher state.
#[derive(Debug, Clone, Copy)]
struct ChaChaState {
    /// Key (256 bits = 8 × u32).
    key: [u32; CHACHA_KEY_WORDS],
    /// Block counter.
    counter: u64,
    /// Nonce (96 bits = 3 × u32).
    nonce: [u32; 3],
    /// Whether the state has been seeded.
    seeded: bool,
    /// Generation counter (incremented on reseed).
    generation: u64,
}

impl ChaChaState {
    /// Create an unseeded state.
    const fn new() -> Self {
        Self {
            key: [0; CHACHA_KEY_WORDS],
            counter: 0,
            nonce: [0; 3],
            seeded: false,
            generation: 0,
        }
    }

    /// Seed the ChaCha state from the entropy pool.
    fn seed(&mut self, pool: &[u32; POOL_WORDS]) {
        // Use the first 8 words of the pool as the key.
        self.key.copy_from_slice(&pool[..CHACHA_KEY_WORDS]);
        // Use the next 3 words as the nonce.
        self.nonce.copy_from_slice(&pool[8..11]);
        self.counter = 0;
        self.seeded = true;
        self.generation += 1;
    }

    /// Generate a ChaCha20 block (64 bytes = 16 × u32).
    fn generate_block(&mut self) -> [u32; 16] {
        let mut state = [0u32; 16];

        // ChaCha20 constant: "expand 32-byte k"
        state[0] = 0x6170_7865;
        state[1] = 0x3320_646e;
        state[2] = 0x7962_2d32;
        state[3] = 0x6b20_6574;

        // Key.
        state[4..12].copy_from_slice(&self.key);

        // Counter.
        state[12] = self.counter as u32;
        state[13] = (self.counter >> 32) as u32;

        // Nonce.
        state[14] = self.nonce[0];
        state[15] = self.nonce[1];

        let mut working = state;

        // 20 rounds (10 double-rounds).
        let mut round = 0u32;
        while round < CHACHA_ROUNDS {
            // Column round.
            chacha_quarter_round(&mut working, 0, 4, 8, 12);
            chacha_quarter_round(&mut working, 1, 5, 9, 13);
            chacha_quarter_round(&mut working, 2, 6, 10, 14);
            chacha_quarter_round(&mut working, 3, 7, 11, 15);
            // Diagonal round.
            chacha_quarter_round(&mut working, 0, 5, 10, 15);
            chacha_quarter_round(&mut working, 1, 6, 11, 12);
            chacha_quarter_round(&mut working, 2, 7, 8, 13);
            chacha_quarter_round(&mut working, 3, 4, 9, 14);
            round += 2;
        }

        // Add original state.
        for (i, val) in working.iter_mut().enumerate() {
            *val = val.wrapping_add(state[i]);
        }

        self.counter += 1;
        working
    }
}

/// ChaCha20 quarter round.
fn chacha_quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = s[d].rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = s[b].rotate_left(7);
}

// ── EntropyPool ─────────────────────────────────────────────

/// Entropy input mixing pool.
struct EntropyPool {
    /// Pool data.
    pool: [u32; POOL_WORDS],
    /// Input position for mixing.
    input_pos: usize,
    /// Entropy credits in bits.
    entropy_count: u32,
    /// Total entropy samples added.
    samples_added: u64,
}

impl EntropyPool {
    /// Create an empty pool.
    const fn new() -> Self {
        Self {
            pool: [0; POOL_WORDS],
            input_pos: 0,
            entropy_count: 0,
            samples_added: 0,
        }
    }

    /// Mix entropy into the pool using XOR-shift.
    fn add_entropy(&mut self, data: u64, credit_bits: u32) {
        let lo = data as u32;
        let hi = (data >> 32) as u32;

        // XOR-shift mixing.
        let pos = self.input_pos;
        self.pool[pos] ^= lo;
        self.pool[(pos + 3) % POOL_WORDS] ^= hi;
        self.pool[(pos + 7) % POOL_WORDS] ^= lo.rotate_left(13) ^ hi.rotate_right(7);

        self.input_pos = (pos + 1) % POOL_WORDS;
        self.entropy_count = self
            .entropy_count
            .saturating_add(credit_bits)
            .min(MAX_ENTROPY_CREDITS);
        self.samples_added += 1;
    }

    /// Whether the pool has enough entropy to seed.
    fn is_ready(&self) -> bool {
        self.entropy_count >= SEED_THRESHOLD
    }

    /// Debit entropy credits after seeding.
    fn debit(&mut self, bits: u32) {
        self.entropy_count = self.entropy_count.saturating_sub(bits);
    }
}

// ── RandomStats ─────────────────────────────────────────────

/// Statistics for the random subsystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct RandomStats {
    /// Total entropy samples added.
    pub samples_added: u64,
    /// Current entropy credit (bits).
    pub entropy_bits: u32,
    /// Whether the CRNG is seeded.
    pub seeded: bool,
    /// Total bytes generated.
    pub bytes_generated: u64,
    /// Total get_random_u32 calls.
    pub u32_calls: u64,
    /// Total get_random_u64 calls.
    pub u64_calls: u64,
    /// Total get_random_bytes calls.
    pub bytes_calls: u64,
    /// Number of reseeds.
    pub reseeds: u64,
    /// Requests blocked (not yet seeded).
    pub blocked_requests: u64,
}

// ── RandomSubsystem ─────────────────────────────────────────

/// Kernel random number generator subsystem.
pub struct RandomSubsystem {
    /// Entropy pool.
    pool: EntropyPool,
    /// ChaCha20 state.
    chacha: ChaChaState,
    /// Output buffer.
    output_buf: [u8; OUTPUT_BUFFER_SIZE],
    /// Bytes remaining in output buffer.
    output_remaining: usize,
    /// Output buffer read position.
    output_pos: usize,
    /// Statistics.
    stats: RandomStats,
    /// Whether initialized.
    initialized: bool,
}

impl RandomSubsystem {
    /// Create a new random subsystem.
    pub const fn new() -> Self {
        Self {
            pool: EntropyPool::new(),
            chacha: ChaChaState::new(),
            output_buf: [0u8; OUTPUT_BUFFER_SIZE],
            output_remaining: 0,
            output_pos: 0,
            stats: RandomStats {
                samples_added: 0,
                entropy_bits: 0,
                seeded: false,
                bytes_generated: 0,
                u32_calls: 0,
                u64_calls: 0,
                bytes_calls: 0,
                reseeds: 0,
                blocked_requests: 0,
            },
            initialized: false,
        }
    }

    /// Initialize.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.initialized = true;
        Ok(())
    }

    /// Add entropy to the pool.
    pub fn add_entropy(&mut self, data: u64, credit_bits: u32) {
        self.pool.add_entropy(data, credit_bits);
        self.stats.samples_added = self.pool.samples_added;
        self.stats.entropy_bits = self.pool.entropy_count;

        // Auto-seed if we have enough entropy.
        if self.pool.is_ready() && !self.chacha.seeded {
            self.reseed();
        }
    }

    /// Add interrupt timing entropy.
    pub fn add_interrupt_entropy(&mut self, irq: u32, timestamp_ns: u64) {
        let data = (irq as u64) ^ timestamp_ns;
        // Interrupt timing gives ~1 bit of entropy.
        self.add_entropy(data, 1);
    }

    /// Add device event entropy.
    pub fn add_device_entropy(&mut self, event_type: u32, event_data: u64) {
        let data = (event_type as u64).wrapping_mul(0x517c_c1b7_2722_0a95) ^ event_data;
        self.add_entropy(data, 2);
    }

    /// Force a reseed of the CRNG from the pool.
    pub fn reseed(&mut self) {
        self.chacha.seed(&self.pool.pool);
        self.pool.debit(SEED_THRESHOLD);
        self.output_remaining = 0;
        self.stats.seeded = true;
        self.stats.reseeds += 1;
    }

    /// Get random bytes.
    pub fn get_random_bytes(&mut self, out: &mut [u8]) -> Result<()> {
        if out.len() > MAX_REQUEST_SIZE {
            return Err(Error::InvalidArgument);
        }
        if !self.chacha.seeded {
            self.stats.blocked_requests += 1;
            return Err(Error::WouldBlock);
        }

        self.stats.bytes_calls += 1;
        let mut filled = 0;

        while filled < out.len() {
            if self.output_remaining == 0 {
                self.refill_buffer();
            }
            let copy_len = (out.len() - filled).min(self.output_remaining);
            out[filled..filled + copy_len]
                .copy_from_slice(&self.output_buf[self.output_pos..self.output_pos + copy_len]);
            filled += copy_len;
            self.output_pos += copy_len;
            self.output_remaining -= copy_len;
        }

        self.stats.bytes_generated += out.len() as u64;
        Ok(())
    }

    /// Get a random u32.
    pub fn get_random_u32(&mut self) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.get_random_bytes(&mut buf)?;
        self.stats.u32_calls += 1;
        Ok(u32::from_le_bytes(buf))
    }

    /// Get a random u64.
    pub fn get_random_u64(&mut self) -> Result<u64> {
        let mut buf = [0u8; 8];
        self.get_random_bytes(&mut buf)?;
        self.stats.u64_calls += 1;
        Ok(u64::from_le_bytes(buf))
    }

    /// Whether the CRNG is seeded.
    pub fn is_seeded(&self) -> bool {
        self.chacha.seeded
    }

    /// Current entropy credits.
    pub fn entropy_bits(&self) -> u32 {
        self.pool.entropy_count
    }

    /// Statistics.
    pub fn stats(&self) -> &RandomStats {
        &self.stats
    }

    // ── Internal ────────────────────────────────────────────

    /// Refill the output buffer from ChaCha20.
    fn refill_buffer(&mut self) {
        let mut pos = 0;
        while pos < OUTPUT_BUFFER_SIZE {
            let block = self.chacha.generate_block();
            for word in &block {
                let bytes = word.to_le_bytes();
                let remaining = OUTPUT_BUFFER_SIZE - pos;
                let copy_len = remaining.min(4);
                self.output_buf[pos..pos + copy_len].copy_from_slice(&bytes[..copy_len]);
                pos += copy_len;
                if pos >= OUTPUT_BUFFER_SIZE {
                    break;
                }
            }
        }
        self.output_pos = 0;
        self.output_remaining = OUTPUT_BUFFER_SIZE;
    }
}

impl Default for RandomSubsystem {
    fn default() -> Self {
        Self::new()
    }
}
