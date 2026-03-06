// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel cryptographic primitives.
//!
//! Provides fundamental cryptographic building blocks for the ONCRIX
//! kernel: SHA-256 hashing, HMAC-SHA256 message authentication, and
//! AES-128 block cipher with CBC and CTR modes of operation.
//!
//! All implementations are constant-time where security-critical and
//! operate in `#![no_std]` with zero external dependencies.

use oncrix_lib::{Error, Result};

// ── SHA-256 Constants ───────────────────────────────────────────

/// SHA-256 round constants (first 32 bits of the fractional parts
/// of the cube roots of the first 64 primes).
const K: [u32; 64] = [
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

/// SHA-256 initial hash values (first 32 bits of the fractional
/// parts of the square roots of the first 8 primes).
const H_INIT: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// SHA-256 block size in bytes.
const SHA256_BLOCK_SIZE: usize = 64;

/// SHA-256 digest size in bytes.
const SHA256_DIGEST_SIZE: usize = 32;

// ── SHA-256 helper functions ────────────────────────────────────

/// SHA-256 Ch function: `(x & y) ^ (!x & z)`.
const fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

/// SHA-256 Maj function: `(x & y) ^ (x & z) ^ (y & z)`.
const fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// SHA-256 big sigma 0: `ROTR(2) ^ ROTR(13) ^ ROTR(22)`.
const fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

/// SHA-256 big sigma 1: `ROTR(6) ^ ROTR(11) ^ ROTR(25)`.
const fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

/// SHA-256 small sigma 0: `ROTR(7) ^ ROTR(18) ^ SHR(3)`.
const fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

/// SHA-256 small sigma 1: `ROTR(17) ^ ROTR(19) ^ SHR(10)`.
const fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

// ── Sha256State ─────────────────────────────────────────────────

/// Internal state for the SHA-256 hash computation.
///
/// Holds the 8-word (256-bit) intermediate hash, a 64-byte block
/// buffer for partial input, and the total message length in bytes.
pub struct Sha256State {
    /// Intermediate hash value (8 × u32 words).
    h: [u32; 8],
    /// Block buffer for accumulating partial 64-byte blocks.
    block: [u8; SHA256_BLOCK_SIZE],
    /// Number of valid bytes currently in `block`.
    block_len: usize,
    /// Total number of bytes processed so far.
    total_len: u64,
}

impl Default for Sha256State {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256State {
    /// Create a new SHA-256 state initialized to the standard
    /// initial hash values.
    pub const fn new() -> Self {
        Self {
            h: H_INIT,
            block: [0u8; SHA256_BLOCK_SIZE],
            block_len: 0,
            total_len: 0,
        }
    }
}

// ── Sha256 ──────────────────────────────────────────────────────

/// SHA-256 cryptographic hash function (FIPS 180-4).
///
/// Produces a 256-bit (32-byte) message digest.
///
/// # Usage
///
/// ```ignore
/// let mut hasher = Sha256::new();
/// hasher.update(b"hello");
/// let digest = hasher.finalize();
/// ```
pub struct Sha256 {
    /// Internal hash state.
    state: Sha256State,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// Create a new SHA-256 hasher with standard initial values.
    pub const fn new() -> Self {
        Self {
            state: Sha256State::new(),
        }
    }

    /// Process a single 64-byte block through the SHA-256
    /// compression function.
    fn compress(h: &mut [u32; 8], block: &[u8; SHA256_BLOCK_SIZE]) {
        // Prepare message schedule W[0..63].
        let mut w = [0u32; 64];
        let mut t = 0usize;
        while t < 16 {
            let base = t.wrapping_mul(4);
            w[t] = u32::from_be_bytes([
                block[base],
                block[base.wrapping_add(1)],
                block[base.wrapping_add(2)],
                block[base.wrapping_add(3)],
            ]);
            t = t.wrapping_add(1);
        }
        while t < 64 {
            w[t] = small_sigma1(w[t.wrapping_sub(2)])
                .wrapping_add(w[t.wrapping_sub(7)])
                .wrapping_add(small_sigma0(w[t.wrapping_sub(15)]))
                .wrapping_add(w[t.wrapping_sub(16)]);
            t = t.wrapping_add(1);
        }

        // Initialize working variables.
        let mut a = h[0];
        let mut b = h[1];
        let mut c = h[2];
        let mut d = h[3];
        let mut e = h[4];
        let mut f = h[5];
        let mut g = h[6];
        let mut hh = h[7];

        // 64 rounds.
        let mut i = 0usize;
        while i < 64 {
            let t1 = hh
                .wrapping_add(big_sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
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

        // Add compressed chunk to current hash value.
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    /// Feed `data` into the hasher.
    ///
    /// Can be called multiple times to process data incrementally.
    pub fn update(&mut self, data: &[u8]) {
        let st = &mut self.state;
        let mut offset = 0usize;

        // If we have buffered data, fill the block first.
        if st.block_len > 0 {
            let space = SHA256_BLOCK_SIZE.wrapping_sub(st.block_len);
            let fill = if data.len() < space {
                data.len()
            } else {
                space
            };
            let mut i = 0usize;
            while i < fill {
                st.block[st.block_len.wrapping_add(i)] = data[i];
                i = i.wrapping_add(1);
            }
            st.block_len = st.block_len.wrapping_add(fill);
            offset = fill;

            if st.block_len == SHA256_BLOCK_SIZE {
                let block = st.block;
                Self::compress(&mut st.h, &block);
                st.block_len = 0;
            }
        }

        // Process full blocks directly from input.
        while offset.wrapping_add(SHA256_BLOCK_SIZE) <= data.len() {
            let mut block = [0u8; SHA256_BLOCK_SIZE];
            let mut i = 0usize;
            while i < SHA256_BLOCK_SIZE {
                block[i] = data[offset.wrapping_add(i)];
                i = i.wrapping_add(1);
            }
            Self::compress(&mut st.h, &block);
            offset = offset.wrapping_add(SHA256_BLOCK_SIZE);
        }

        // Buffer remaining bytes.
        let remaining = data.len().wrapping_sub(offset);
        if remaining > 0 {
            let mut i = 0usize;
            while i < remaining {
                st.block[i] = data[offset.wrapping_add(i)];
                i = i.wrapping_add(1);
            }
            st.block_len = remaining;
        }

        st.total_len = st.total_len.wrapping_add(data.len() as u64);
    }

    /// Finalize the hash and return the 32-byte SHA-256 digest.
    ///
    /// Consumes the hasher. After calling this, the hasher state is
    /// left in an unspecified state.
    pub fn finalize(mut self) -> [u8; SHA256_DIGEST_SIZE] {
        let st = &mut self.state;
        let bit_len = st.total_len.wrapping_mul(8);

        // Append the 0x80 padding byte.
        st.block[st.block_len] = 0x80;
        st.block_len = st.block_len.wrapping_add(1);

        // Zero-fill remaining block space.
        let mut i = st.block_len;
        while i < SHA256_BLOCK_SIZE {
            st.block[i] = 0;
            i = i.wrapping_add(1);
        }

        // If not enough room for the 8-byte length, compress and
        // start a new block.
        if st.block_len > 56 {
            let block = st.block;
            Self::compress(&mut st.h, &block);
            st.block = [0u8; SHA256_BLOCK_SIZE];
        }

        // Append message length in bits as big-endian u64.
        let len_bytes = bit_len.to_be_bytes();
        let mut j = 0usize;
        while j < 8 {
            st.block[56usize.wrapping_add(j)] = len_bytes[j];
            j = j.wrapping_add(1);
        }

        let block = st.block;
        Self::compress(&mut st.h, &block);

        // Serialize hash words to big-endian bytes.
        let mut digest = [0u8; SHA256_DIGEST_SIZE];
        let mut w = 0usize;
        while w < 8 {
            let bytes = st.h[w].to_be_bytes();
            let base = w.wrapping_mul(4);
            digest[base] = bytes[0];
            digest[base.wrapping_add(1)] = bytes[1];
            digest[base.wrapping_add(2)] = bytes[2];
            digest[base.wrapping_add(3)] = bytes[3];
            w = w.wrapping_add(1);
        }
        digest
    }

    /// Convenience: hash `data` in one shot and return the digest.
    pub fn digest(data: &[u8]) -> [u8; SHA256_DIGEST_SIZE] {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }
}

// ── HMAC-SHA256 ─────────────────────────────────────────────────

/// HMAC-SHA256 message authentication code (RFC 2104).
///
/// Computes a keyed hash using SHA-256 as the underlying hash
/// function, producing a 32-byte authentication tag.
///
/// # Usage
///
/// ```ignore
/// let mut mac = Hmac256::new(b"secret-key");
/// mac.update(b"message");
/// let tag = mac.finalize();
/// ```
pub struct Hmac256 {
    /// Inner SHA-256 hasher (initialized with ipad-XORed key).
    inner: Sha256,
    /// Outer key block (key XORed with opad).
    outer_key_block: [u8; SHA256_BLOCK_SIZE],
}

impl Hmac256 {
    /// Create a new HMAC-SHA256 instance with the given `key`.
    ///
    /// If the key is longer than 64 bytes, it is first hashed with
    /// SHA-256. If shorter, it is zero-padded to 64 bytes.
    pub fn new(key: &[u8]) -> Self {
        // Normalize key to exactly 64 bytes.
        let mut key_block = [0u8; SHA256_BLOCK_SIZE];
        if key.len() > SHA256_BLOCK_SIZE {
            let hashed = Sha256::digest(key);
            let mut i = 0usize;
            while i < SHA256_DIGEST_SIZE {
                key_block[i] = hashed[i];
                i = i.wrapping_add(1);
            }
        } else {
            let mut i = 0usize;
            while i < key.len() {
                key_block[i] = key[i];
                i = i.wrapping_add(1);
            }
        }

        // Compute ipad and opad key blocks.
        let mut ipad_block = [0u8; SHA256_BLOCK_SIZE];
        let mut opad_block = [0u8; SHA256_BLOCK_SIZE];
        let mut i = 0usize;
        while i < SHA256_BLOCK_SIZE {
            ipad_block[i] = key_block[i] ^ 0x36;
            opad_block[i] = key_block[i] ^ 0x5c;
            i = i.wrapping_add(1);
        }

        // Initialize inner hasher with ipad block.
        let mut inner = Sha256::new();
        inner.update(&ipad_block);

        Self {
            inner,
            outer_key_block: opad_block,
        }
    }

    /// Feed `data` into the HMAC computation.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize and return the 32-byte HMAC-SHA256 tag.
    pub fn finalize(self) -> [u8; SHA256_DIGEST_SIZE] {
        let inner_hash = self.inner.finalize();
        let mut outer = Sha256::new();
        outer.update(&self.outer_key_block);
        outer.update(&inner_hash);
        outer.finalize()
    }
}

// ── AES-128 Constants ───────────────────────────────────────────

/// AES block size in bytes.
const AES_BLOCK_SIZE: usize = 16;

/// Number of AES-128 rounds.
const AES128_ROUNDS: usize = 10;

/// Number of 32-bit words in an AES-128 key.
const AES128_NK: usize = 4;

/// AES S-box substitution table.
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// AES inverse S-box substitution table.
const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// AES round constants for key expansion.
const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

// ── AES GF(2^8) helpers ─────────────────────────────────────────

/// Multiply by 2 in GF(2^8) with irreducible polynomial 0x11b.
const fn gf_mul2(x: u8) -> u8 {
    let shifted = (x as u16) << 1;
    let reduced = shifted ^ (((shifted >> 8) & 1) * 0x1b);
    reduced as u8
}

/// Multiply by 3 in GF(2^8): `gf_mul2(x) ^ x`.
const fn gf_mul3(x: u8) -> u8 {
    gf_mul2(x) ^ x
}

/// Multiply by 9 in GF(2^8).
const fn gf_mul9(x: u8) -> u8 {
    gf_mul2(gf_mul2(gf_mul2(x))) ^ x
}

/// Multiply by 11 in GF(2^8).
const fn gf_mul11(x: u8) -> u8 {
    gf_mul2(gf_mul2(gf_mul2(x)) ^ x) ^ x
}

/// Multiply by 13 in GF(2^8).
const fn gf_mul13(x: u8) -> u8 {
    gf_mul2(gf_mul2(gf_mul2(x) ^ x)) ^ x
}

/// Multiply by 14 in GF(2^8).
const fn gf_mul14(x: u8) -> u8 {
    gf_mul2(gf_mul2(gf_mul2(x) ^ x) ^ x)
}

// ── AesKey ──────────────────────────────────────────────────────

/// Expanded AES-128 key schedule.
///
/// Contains 11 round keys (initial + 10 rounds), each 16 bytes,
/// derived from the original 128-bit key via the AES key expansion
/// algorithm.
pub struct AesKey {
    /// 11 round keys × 16 bytes = 176 bytes total.
    round_keys: [[u8; AES_BLOCK_SIZE]; AES128_ROUNDS + 1],
}

impl AesKey {
    /// Expand a 16-byte AES-128 key into the full key schedule.
    pub fn new(key: &[u8; AES_BLOCK_SIZE]) -> Self {
        let mut w = [0u32; 4 * (AES128_ROUNDS + 1)];

        // Copy original key into first Nk words.
        let mut i = 0usize;
        while i < AES128_NK {
            let base = i.wrapping_mul(4);
            w[i] = u32::from_be_bytes([
                key[base],
                key[base.wrapping_add(1)],
                key[base.wrapping_add(2)],
                key[base.wrapping_add(3)],
            ]);
            i = i.wrapping_add(1);
        }

        // Key expansion.
        i = AES128_NK;
        while i < 4 * (AES128_ROUNDS + 1) {
            let mut temp = w[i.wrapping_sub(1)];
            if i % AES128_NK == 0 {
                // RotWord + SubWord + Rcon
                temp =
                    Self::sub_word(Self::rot_word(temp)) ^ ((RCON[i / AES128_NK - 1] as u32) << 24);
            }
            w[i] = w[i.wrapping_sub(AES128_NK)] ^ temp;
            i = i.wrapping_add(1);
        }

        // Pack words into round key arrays.
        let mut round_keys = [[0u8; AES_BLOCK_SIZE]; AES128_ROUNDS + 1];
        let mut r = 0usize;
        while r <= AES128_ROUNDS {
            let wi = r.wrapping_mul(4);
            let mut j = 0usize;
            while j < 4 {
                let bytes = w[wi.wrapping_add(j)].to_be_bytes();
                let base = j.wrapping_mul(4);
                round_keys[r][base] = bytes[0];
                round_keys[r][base.wrapping_add(1)] = bytes[1];
                round_keys[r][base.wrapping_add(2)] = bytes[2];
                round_keys[r][base.wrapping_add(3)] = bytes[3];
                j = j.wrapping_add(1);
            }
            r = r.wrapping_add(1);
        }

        Self { round_keys }
    }

    /// Rotate a 32-bit word left by 8 bits.
    const fn rot_word(w: u32) -> u32 {
        w.rotate_left(8)
    }

    /// Apply the S-box to each byte of a 32-bit word.
    fn sub_word(w: u32) -> u32 {
        let b = w.to_be_bytes();
        u32::from_be_bytes([
            SBOX[b[0] as usize],
            SBOX[b[1] as usize],
            SBOX[b[2] as usize],
            SBOX[b[3] as usize],
        ])
    }
}

// ── Aes128 ──────────────────────────────────────────────────────

/// AES-128 block cipher (FIPS 197).
///
/// Encrypts and decrypts individual 16-byte blocks using a 128-bit
/// key with 10 rounds.
pub struct Aes128 {
    /// Expanded key schedule.
    key: AesKey,
}

impl Aes128 {
    /// Create a new AES-128 cipher from a 16-byte key.
    pub fn new(key: &[u8; AES_BLOCK_SIZE]) -> Self {
        Self {
            key: AesKey::new(key),
        }
    }

    /// Encrypt a single 16-byte block in place.
    pub fn encrypt_block(&self, block: &mut [u8; AES_BLOCK_SIZE]) {
        // Initial AddRoundKey.
        Self::add_round_key(block, &self.key.round_keys[0]);

        // Rounds 1..9: SubBytes, ShiftRows, MixColumns,
        // AddRoundKey.
        let mut round = 1usize;
        while round < AES128_ROUNDS {
            Self::sub_bytes(block);
            Self::shift_rows(block);
            Self::mix_columns(block);
            Self::add_round_key(block, &self.key.round_keys[round]);
            round = round.wrapping_add(1);
        }

        // Final round (no MixColumns).
        Self::sub_bytes(block);
        Self::shift_rows(block);
        Self::add_round_key(block, &self.key.round_keys[AES128_ROUNDS]);
    }

    /// Decrypt a single 16-byte block in place.
    pub fn decrypt_block(&self, block: &mut [u8; AES_BLOCK_SIZE]) {
        // Initial AddRoundKey with last round key.
        Self::add_round_key(block, &self.key.round_keys[AES128_ROUNDS]);

        // Rounds 9..1: InvShiftRows, InvSubBytes,
        // AddRoundKey, InvMixColumns.
        let mut round = AES128_ROUNDS.wrapping_sub(1);
        while round >= 1 {
            Self::inv_shift_rows(block);
            Self::inv_sub_bytes(block);
            Self::add_round_key(block, &self.key.round_keys[round]);
            Self::inv_mix_columns(block);
            round = round.wrapping_sub(1);
        }

        // Final round (no InvMixColumns).
        Self::inv_shift_rows(block);
        Self::inv_sub_bytes(block);
        Self::add_round_key(block, &self.key.round_keys[0]);
    }

    /// XOR a 16-byte round key into the state block.
    fn add_round_key(block: &mut [u8; AES_BLOCK_SIZE], rk: &[u8; AES_BLOCK_SIZE]) {
        let mut i = 0usize;
        while i < AES_BLOCK_SIZE {
            block[i] ^= rk[i];
            i = i.wrapping_add(1);
        }
    }

    /// Apply S-box substitution to every byte.
    fn sub_bytes(block: &mut [u8; AES_BLOCK_SIZE]) {
        let mut i = 0usize;
        while i < AES_BLOCK_SIZE {
            block[i] = SBOX[block[i] as usize];
            i = i.wrapping_add(1);
        }
    }

    /// Apply inverse S-box substitution to every byte.
    fn inv_sub_bytes(block: &mut [u8; AES_BLOCK_SIZE]) {
        let mut i = 0usize;
        while i < AES_BLOCK_SIZE {
            block[i] = INV_SBOX[block[i] as usize];
            i = i.wrapping_add(1);
        }
    }

    /// ShiftRows: cyclically shift rows of the state matrix.
    ///
    /// State is in column-major order:
    /// `[s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, sA, sB, sC,
    ///   sD, sE, sF]`
    /// maps to:
    /// ```text
    /// s0 s4 s8 sC
    /// s1 s5 s9 sD
    /// s2 s6 sA sE
    /// s3 s7 sB sF
    /// ```
    fn shift_rows(s: &mut [u8; AES_BLOCK_SIZE]) {
        // Row 1: shift left by 1.
        let t = s[1];
        s[1] = s[5];
        s[5] = s[9];
        s[9] = s[13];
        s[13] = t;

        // Row 2: shift left by 2.
        let t0 = s[2];
        let t1 = s[6];
        s[2] = s[10];
        s[6] = s[14];
        s[10] = t0;
        s[14] = t1;

        // Row 3: shift left by 3 (= right by 1).
        let t = s[15];
        s[15] = s[11];
        s[11] = s[7];
        s[7] = s[3];
        s[3] = t;
    }

    /// Inverse ShiftRows.
    fn inv_shift_rows(s: &mut [u8; AES_BLOCK_SIZE]) {
        // Row 1: shift right by 1.
        let t = s[13];
        s[13] = s[9];
        s[9] = s[5];
        s[5] = s[1];
        s[1] = t;

        // Row 2: shift right by 2.
        let t0 = s[2];
        let t1 = s[6];
        s[2] = s[10];
        s[6] = s[14];
        s[10] = t0;
        s[14] = t1;

        // Row 3: shift right by 3 (= left by 1).
        let t = s[3];
        s[3] = s[7];
        s[7] = s[11];
        s[11] = s[15];
        s[15] = t;
    }

    /// MixColumns: multiply each column by the MDS matrix in
    /// GF(2^8).
    fn mix_columns(s: &mut [u8; AES_BLOCK_SIZE]) {
        let mut col = 0usize;
        while col < 4 {
            let base = col.wrapping_mul(4);
            let a0 = s[base];
            let a1 = s[base.wrapping_add(1)];
            let a2 = s[base.wrapping_add(2)];
            let a3 = s[base.wrapping_add(3)];

            s[base] = gf_mul2(a0) ^ gf_mul3(a1) ^ a2 ^ a3;
            s[base.wrapping_add(1)] = a0 ^ gf_mul2(a1) ^ gf_mul3(a2) ^ a3;
            s[base.wrapping_add(2)] = a0 ^ a1 ^ gf_mul2(a2) ^ gf_mul3(a3);
            s[base.wrapping_add(3)] = gf_mul3(a0) ^ a1 ^ a2 ^ gf_mul2(a3);
            col = col.wrapping_add(1);
        }
    }

    /// Inverse MixColumns.
    fn inv_mix_columns(s: &mut [u8; AES_BLOCK_SIZE]) {
        let mut col = 0usize;
        while col < 4 {
            let base = col.wrapping_mul(4);
            let a0 = s[base];
            let a1 = s[base.wrapping_add(1)];
            let a2 = s[base.wrapping_add(2)];
            let a3 = s[base.wrapping_add(3)];

            s[base] = gf_mul14(a0) ^ gf_mul11(a1) ^ gf_mul13(a2) ^ gf_mul9(a3);
            s[base.wrapping_add(1)] = gf_mul9(a0) ^ gf_mul14(a1) ^ gf_mul11(a2) ^ gf_mul13(a3);
            s[base.wrapping_add(2)] = gf_mul13(a0) ^ gf_mul9(a1) ^ gf_mul14(a2) ^ gf_mul11(a3);
            s[base.wrapping_add(3)] = gf_mul11(a0) ^ gf_mul13(a1) ^ gf_mul9(a2) ^ gf_mul14(a3);
            col = col.wrapping_add(1);
        }
    }
}

// ── CipherMode ──────────────────────────────────────────────────

/// Block cipher mode of operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherMode {
    /// Electronic Codebook: each block encrypted independently.
    Ecb,
    /// Cipher Block Chaining: each plaintext block XORed with
    /// the previous ciphertext block before encryption.
    Cbc,
    /// Counter mode: turns a block cipher into a stream cipher
    /// using an incrementing counter.
    Ctr,
}

// ── AesCbc ──────────────────────────────────────────────────────

/// AES-128 in CBC (Cipher Block Chaining) mode.
///
/// Requires input length to be a multiple of 16 bytes. The caller
/// is responsible for applying PKCS#7 or other padding before
/// encryption and removing it after decryption.
pub struct AesCbc {
    /// Underlying AES-128 block cipher.
    cipher: Aes128,
}

impl AesCbc {
    /// Create a new AES-128-CBC instance with the given key.
    pub fn new(key: &[u8; AES_BLOCK_SIZE]) -> Self {
        Self {
            cipher: Aes128::new(key),
        }
    }

    /// Encrypt `data` in place using CBC mode with the given `iv`.
    ///
    /// `data` length must be a multiple of 16. Returns
    /// `Err(InvalidArgument)` otherwise.
    pub fn encrypt(&self, iv: &[u8; AES_BLOCK_SIZE], data: &mut [u8]) -> Result<()> {
        if data.len() % AES_BLOCK_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if data.is_empty() {
            return Ok(());
        }

        let num_blocks = data.len() / AES_BLOCK_SIZE;

        // First block: XOR with IV.
        let mut prev = *iv;
        let mut blk_idx = 0usize;
        while blk_idx < num_blocks {
            let offset = blk_idx.wrapping_mul(AES_BLOCK_SIZE);

            // Copy block out, XOR with previous ciphertext.
            let mut block = [0u8; AES_BLOCK_SIZE];
            let mut i = 0usize;
            while i < AES_BLOCK_SIZE {
                block[i] = data[offset.wrapping_add(i)] ^ prev[i];
                i = i.wrapping_add(1);
            }

            self.cipher.encrypt_block(&mut block);

            // Write ciphertext back and save as prev.
            let mut i = 0usize;
            while i < AES_BLOCK_SIZE {
                data[offset.wrapping_add(i)] = block[i];
                prev[i] = block[i];
                i = i.wrapping_add(1);
            }

            blk_idx = blk_idx.wrapping_add(1);
        }

        Ok(())
    }

    /// Decrypt `data` in place using CBC mode with the given `iv`.
    ///
    /// `data` length must be a multiple of 16. Returns
    /// `Err(InvalidArgument)` otherwise.
    pub fn decrypt(&self, iv: &[u8; AES_BLOCK_SIZE], data: &mut [u8]) -> Result<()> {
        if data.len() % AES_BLOCK_SIZE != 0 {
            return Err(Error::InvalidArgument);
        }
        if data.is_empty() {
            return Ok(());
        }

        let num_blocks = data.len() / AES_BLOCK_SIZE;

        let mut prev = *iv;
        let mut blk_idx = 0usize;
        while blk_idx < num_blocks {
            let offset = blk_idx.wrapping_mul(AES_BLOCK_SIZE);

            // Save ciphertext for next round's XOR.
            let mut ciphertext = [0u8; AES_BLOCK_SIZE];
            let mut i = 0usize;
            while i < AES_BLOCK_SIZE {
                ciphertext[i] = data[offset.wrapping_add(i)];
                i = i.wrapping_add(1);
            }

            // Decrypt block.
            let mut block = ciphertext;
            self.cipher.decrypt_block(&mut block);

            // XOR with previous ciphertext (or IV).
            let mut i = 0usize;
            while i < AES_BLOCK_SIZE {
                data[offset.wrapping_add(i)] = block[i] ^ prev[i];
                i = i.wrapping_add(1);
            }

            prev = ciphertext;
            blk_idx = blk_idx.wrapping_add(1);
        }

        Ok(())
    }
}

// ── AesCtr ──────────────────────────────────────────────────────

/// AES-128 in CTR (Counter) mode.
///
/// Turns the block cipher into a stream cipher by encrypting
/// successive counter values and XORing the keystream with the
/// plaintext. Works on arbitrary-length data (no padding needed).
///
/// The 16-byte counter block is formed as:
/// `nonce (12 bytes) || counter (4 bytes big-endian)`.
pub struct AesCtr {
    /// Underlying AES-128 block cipher.
    cipher: Aes128,
}

impl AesCtr {
    /// Create a new AES-128-CTR instance with the given key.
    pub fn new(key: &[u8; AES_BLOCK_SIZE]) -> Self {
        Self {
            cipher: Aes128::new(key),
        }
    }

    /// Encrypt or decrypt `data` in place using CTR mode.
    ///
    /// `nonce` is a 12-byte value; `counter` is the initial 32-bit
    /// block counter. Encryption and decryption are the same
    /// operation in CTR mode.
    pub fn apply(&self, nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
        if data.is_empty() {
            return;
        }

        let mut ctr = counter;
        let mut offset = 0usize;

        while offset < data.len() {
            // Build counter block: nonce || counter (BE).
            let mut ctr_block = [0u8; AES_BLOCK_SIZE];
            let mut i = 0usize;
            while i < 12 {
                ctr_block[i] = nonce[i];
                i = i.wrapping_add(1);
            }
            let ctr_bytes = ctr.to_be_bytes();
            ctr_block[12] = ctr_bytes[0];
            ctr_block[13] = ctr_bytes[1];
            ctr_block[14] = ctr_bytes[2];
            ctr_block[15] = ctr_bytes[3];

            // Encrypt counter block to produce keystream.
            self.cipher.encrypt_block(&mut ctr_block);

            // XOR keystream with data.
            let remaining = data.len().wrapping_sub(offset);
            let chunk = if remaining < AES_BLOCK_SIZE {
                remaining
            } else {
                AES_BLOCK_SIZE
            };

            let mut i = 0usize;
            while i < chunk {
                data[offset.wrapping_add(i)] ^= ctr_block[i];
                i = i.wrapping_add(1);
            }

            ctr = ctr.wrapping_add(1);
            offset = offset.wrapping_add(AES_BLOCK_SIZE);
        }
    }

    /// Encrypt `data` in place (alias for [`Self::apply`]).
    pub fn encrypt(&self, nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
        self.apply(nonce, counter, data);
    }

    /// Decrypt `data` in place (alias for [`Self::apply`]).
    pub fn decrypt(&self, nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
        self.apply(nonce, counter, data);
    }
}

// ── Utility functions ───────────────────────────────────────────

/// Compare two byte slices in constant time.
///
/// Returns `true` if and only if `a` and `b` have the same length
/// and identical contents. Timing does not depend on the position
/// of the first differing byte.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    let mut i = 0usize;
    while i < a.len() {
        diff |= a[i] ^ b[i];
        i = i.wrapping_add(1);
    }
    diff == 0
}

/// XOR `src` bytes into `dst` in place.
///
/// Only processes `min(dst.len(), src.len())` bytes, leaving any
/// trailing bytes in `dst` unchanged.
pub fn xor_bytes(dst: &mut [u8], src: &[u8]) {
    let len = if dst.len() < src.len() {
        dst.len()
    } else {
        src.len()
    };
    let mut i = 0usize;
    while i < len {
        dst[i] ^= src[i];
        i = i.wrapping_add(1);
    }
}
