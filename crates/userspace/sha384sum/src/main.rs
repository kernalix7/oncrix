// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/sha384sum` — SHA-384 (FIPS 180-4) file digest utility.
//!
//! Forms:
//!   * `sha384sum [FILE...]` — for each FILE print `HEX_HASH  FILENAME\n`
//!     (two spaces). With no operand or with a `-` operand, read stdin and
//!     render the filename as `-`.
//!   * `sha384sum -c FILE` — read FILE as a list of `HEX_HASH  PATH` lines
//!     and verify each PATH. Prints `PATH: OK` or `PATH: FAILED` to stdout
//!     and exits 1 if any check fails.
//!
//! Algorithm: original Rust implementation of SHA-384 as defined by
//! FIPS PUB 180-4 §5.3.4 and §6.5 (US Department of Commerce / NIST,
//! public-domain). SHA-384 shares SHA-512's round constants, message
//! schedule, compression function, and 128-byte block + 128-bit length
//! padding; it differs only in the initial hash value H(0) and in
//! truncating the final state to the first six 64-bit words (48 bytes /
//! 96 hex chars). No GPL or otherwise licensed reference source was
//! consulted; constants and formulas come from the specification text
//! directly.
//!
//! POSIX reference: this is a GNU coreutils utility, not a POSIX one — it
//! mirrors the `sha384sum(1)` behaviour described by GNU coreutils.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// `_start` is naked so the Rust prologue does not allocate a local frame
/// before we capture `argc`/`argv` from the SysV-AMD64 initial stack.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym sha384sum_main,
    );
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// I/O chunk size for the streaming hash loop.
const CHUNK: usize = 4096;

/// Maximum number of FILE operands accepted on the command line.
const MAX_FILES: usize = 16;

/// Standard file descriptors.
const STDIN: i32 = 0;
const STDOUT: i32 = 1;
const STDERR: i32 = 2;

/// SHA-384 digest length in bytes / hex chars.
/// SHA-384 is the first 6 of the 8 final 64-bit words (FIPS 180-4 §6.5).
const DIGEST_BYTES: usize = 48;
const HEX_CHARS: usize = 96;

/// SHA-384 block size in bytes (identical to SHA-512).
const BLOCK_BYTES: usize = 128;

// ---------------------------------------------------------------------------
// SHA-384 core (FIPS 180-4 §5.3.4 + §6.5)
// ---------------------------------------------------------------------------

/// Initial hash value H(0) — FIPS 180-4 §5.3.4. These are the first 64 bits
/// of the fractional parts of the square roots of the 9th through 16th
/// primes; they differ from the SHA-512 IV so a SHA-384 digest of an empty
/// string is distinct from a truncated SHA-512 digest of the same input.
const H0: [u64; 8] = [
    0xcbbb_9d5d_c105_9ed8,
    0x629a_292a_367c_d507,
    0x9159_015a_3070_dd17,
    0x152f_ecd8_f70e_5939,
    0x6733_2667_ffc0_0b31,
    0x8eb4_4a87_6858_1511,
    0xdb0c_2e0d_64f9_8fa7,
    0x47b5_481d_befa_4fa4,
];

/// Round constants K — first 64 bits of the fractional parts of the cube
/// roots of the first 80 primes (FIPS 180-4 § 4.2.3). Shared with SHA-512.
const K: [u64; 80] = [
    0x428a_2f98_d728_ae22,
    0x7137_4491_23ef_65cd,
    0xb5c0_fbcf_ec4d_3b2f,
    0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538,
    0x59f1_11f1_b605_d019,
    0x923f_82a4_af19_4f9b,
    0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242,
    0x1283_5b01_4570_6fbe,
    0x2431_85be_4ee4_b28c,
    0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f,
    0x80de_b1fe_3b16_96b1,
    0x9bdc_06a7_25c7_1235,
    0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2,
    0xefbe_4786_384f_25e3,
    0x0fc1_9dc6_8b8c_d5b5,
    0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275,
    0x4a74_84aa_6ea6_e483,
    0x5cb0_a9dc_bd41_fbd4,
    0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab,
    0xa831_c66d_2db4_3210,
    0xb003_27c8_98fb_213f,
    0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2,
    0xd5a7_9147_930a_a725,
    0x06ca_6351_e003_826f,
    0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc,
    0x2e1b_2138_5c26_c926,
    0x4d2c_6dfc_5ac4_2aed,
    0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de,
    0x766a_0abb_3c77_b2a8,
    0x81c2_c92e_47ed_aee6,
    0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364,
    0xa81a_664b_bc42_3001,
    0xc24b_8b70_d0f8_9791,
    0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218,
    0xd699_0624_5565_a910,
    0xf40e_3585_5771_202a,
    0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8,
    0x1e37_6c08_5141_ab53,
    0x2748_774c_df8e_eb99,
    0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63,
    0x4ed8_aa4a_e341_8acb,
    0x5b9c_ca4f_7763_e373,
    0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc,
    0x78a5_636f_4317_2f60,
    0x84c8_7814_a1f0_ab72,
    0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28,
    0xa450_6ceb_de82_bde9,
    0xbef9_a3f7_b2c6_7915,
    0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c,
    0xd186_b8c7_21c0_c207,
    0xeada_7dd6_cde0_eb1e,
    0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba,
    0x0a63_7dc5_a2c8_98a6,
    0x113f_9804_bef9_0dae,
    0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84,
    0x32ca_ab7b_40c7_2493,
    0x3c9e_be0a_15c9_bebc,
    0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6,
    0x597f_299c_fc65_7e2a,
    0x5fcb_6fab_3ad6_faec,
    0x6c44_198c_4a47_5817,
];

/// Streaming SHA-384 state. Feed bytes via [`Sha384::update`] and call
/// [`Sha384::finish`] to obtain the 48-byte digest.
struct Sha384 {
    /// Current chaining variables H0..H7.
    h: [u64; 8],
    /// Partial 128-byte block being accumulated.
    block: [u8; BLOCK_BYTES],
    /// Number of valid bytes in `block`.
    block_len: usize,
    /// Total number of *bytes* hashed so far. The 128-bit length field
    /// appended in finalisation is this value times eight (in bits). We
    /// only track the low 64 bits because the kernel cannot deliver more
    /// than 2^64 bytes from a single fd; the high half is always zero.
    total_bytes: u64,
}

impl Sha384 {
    /// Construct a new SHA-384 hasher in its initial state.
    fn new() -> Self {
        Self {
            h: H0,
            block: [0u8; BLOCK_BYTES],
            block_len: 0,
            total_bytes: 0,
        }
    }

    /// Absorb `data` into the hasher, processing any 128-byte blocks that
    /// complete during the call.
    fn update(&mut self, data: &[u8]) {
        let mut i = 0;
        while i < data.len() {
            let space = BLOCK_BYTES - self.block_len;
            let take = if data.len() - i < space {
                data.len() - i
            } else {
                space
            };
            // Copy `take` bytes into the partial block.
            let mut j = 0;
            while j < take {
                self.block[self.block_len + j] = data[i + j];
                j += 1;
            }
            self.block_len += take;
            i += take;
            if self.block_len == BLOCK_BYTES {
                let blk = self.block;
                self.compress(&blk);
                self.block_len = 0;
            }
        }
        self.total_bytes = self.total_bytes.wrapping_add(data.len() as u64);
    }

    /// Apply the SHA-384/512 compression function to one 128-byte block.
    ///
    /// Implements FIPS 180-4 § 6.4.2 step-for-step: message schedule
    /// expansion `W[0..80]`, then 80 mixing rounds using the working
    /// variables `a..h`, then add the result back into the chaining
    /// variables. The compression function is identical to SHA-512; only
    /// the IV and the final truncation distinguish SHA-384.
    fn compress(&mut self, block: &[u8; BLOCK_BYTES]) {
        let mut w = [0u64; 80];
        let mut t = 0;
        while t < 16 {
            let off = t * 8;
            w[t] = (block[off] as u64) << 56
                | (block[off + 1] as u64) << 48
                | (block[off + 2] as u64) << 40
                | (block[off + 3] as u64) << 32
                | (block[off + 4] as u64) << 24
                | (block[off + 5] as u64) << 16
                | (block[off + 6] as u64) << 8
                | (block[off + 7] as u64);
            t += 1;
        }
        while t < 80 {
            let s0 = w[t - 15].rotate_right(1) ^ w[t - 15].rotate_right(8) ^ (w[t - 15] >> 7);
            let s1 = w[t - 2].rotate_right(19) ^ w[t - 2].rotate_right(61) ^ (w[t - 2] >> 6);
            w[t] = w[t - 16]
                .wrapping_add(s0)
                .wrapping_add(w[t - 7])
                .wrapping_add(s1);
            t += 1;
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];

        let mut i = 0;
        while i < 80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
            i += 1;
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }

    /// Append SHA-384 padding (a single `0x80` byte, zero pad to length 112
    /// mod 128, then the 128-bit big-endian message length in bits) and emit
    /// the 48-byte digest (first 6 of the 8 chaining variables, per FIPS
    /// 180-4 §6.5). Consumes the hasher state.
    fn finish(mut self) -> [u8; DIGEST_BYTES] {
        let bit_len = self.total_bytes.wrapping_mul(8);

        // Append 0x80.
        self.block[self.block_len] = 0x80;
        self.block_len += 1;

        // If there isn't room for the 16-byte length, flush this block first.
        if self.block_len > 112 {
            let mut i = self.block_len;
            while i < BLOCK_BYTES {
                self.block[i] = 0;
                i += 1;
            }
            let blk = self.block;
            self.compress(&blk);
            self.block_len = 0;
        }
        // Zero-pad up to byte 112.
        let mut i = self.block_len;
        while i < 112 {
            self.block[i] = 0;
            i += 1;
        }
        // 128-bit big-endian length in bits. High 64 bits are always zero
        // because `total_bytes` cannot exceed 2^61 bytes (× 8 = 2^64 bits).
        let mut j = 0;
        while j < 8 {
            self.block[112 + j] = 0;
            j += 1;
        }
        let mut j = 0;
        while j < 8 {
            self.block[120 + j] = (bit_len >> (56 - j * 8)) as u8;
            j += 1;
        }
        let blk = self.block;
        self.compress(&blk);

        // Serialise H[0..6] big-endian (truncation per FIPS 180-4 §6.5).
        let mut out = [0u8; DIGEST_BYTES];
        let mut k = 0;
        while k < 6 {
            let v = self.h[k];
            out[k * 8] = (v >> 56) as u8;
            out[k * 8 + 1] = (v >> 48) as u8;
            out[k * 8 + 2] = (v >> 40) as u8;
            out[k * 8 + 3] = (v >> 32) as u8;
            out[k * 8 + 4] = (v >> 24) as u8;
            out[k * 8 + 5] = (v >> 16) as u8;
            out[k * 8 + 6] = (v >> 8) as u8;
            out[k * 8 + 7] = v as u8;
            k += 1;
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

extern "C" fn sha384sum_main(argc: usize, argv: *const *const u8) -> ! {
    let mut files: [*const u8; MAX_FILES] = [core::ptr::null(); MAX_FILES];
    let mut nfiles: usize = 0;
    let mut check_mode = false;

    let mut i = 1;
    while i < argc {
        // SAFETY: argv has at least `argc` valid pointers from execve.
        let ptr = unsafe { argv.add(i).read() };
        if ptr.is_null() {
            break;
        }
        // SAFETY: argv entries are null-terminated.
        let first = unsafe { ptr.read() };
        let second = unsafe { ptr.add(1).read() };
        if first == b'-' && second == b'c' && unsafe { ptr.add(2).read() } == 0 {
            check_mode = true;
        } else {
            if nfiles >= MAX_FILES {
                write_all(STDERR, b"sha384sum: too many file arguments\n");
                libc::exit(1);
            }
            files[nfiles] = ptr;
            nfiles += 1;
        }
        i += 1;
    }

    if check_mode {
        // `-c` requires exactly one file (a checksum list). Anything else is
        // an error in our subset.
        if nfiles == 0 {
            write_all(STDERR, b"sha384sum: -c requires a checksum file\n");
            libc::exit(1);
        }
        let mut any_fail = false;
        let mut k = 0;
        while k < nfiles {
            if !check_file(files[k]) {
                any_fail = true;
            }
            k += 1;
        }
        libc::exit(if any_fail { 1 } else { 0 });
    }

    let mut exit_code: i32 = 0;
    if nfiles == 0 {
        if !hash_fd_emit(STDIN, b"-") {
            exit_code = 1;
        }
    } else {
        let mut k = 0;
        while k < nfiles {
            if !hash_operand(files[k]) {
                exit_code = 1;
            }
            k += 1;
        }
    }
    libc::exit(exit_code)
}

// ---------------------------------------------------------------------------
// Per-operand drivers
// ---------------------------------------------------------------------------

/// Hash one command-line operand and emit `HEX  NAME\n`. Returns `false` if
/// the operand could not be opened or read.
fn hash_operand(path: *const u8) -> bool {
    // SAFETY: path is a null-terminated argv pointer.
    let first = unsafe { path.read() };
    let second = unsafe { path.add(1).read() };

    if first == b'-' && second == 0 {
        return hash_fd_emit(STDIN, b"-");
    }

    // SAFETY: path is null-terminated.
    let fd = unsafe { libc::open(path, libc::O_RDONLY, 0) };
    if fd < 0 {
        write_all(STDERR, b"sha384sum: cannot open ");
        write_cstr(STDERR, path);
        write_all(STDERR, b"\n");
        return false;
    }
    let fd = fd as i32;
    let ok = hash_fd_emit_cstr(fd, path);
    libc::close(fd);
    ok
}

/// Hash `fd`, then write `HEX  NAME\n` using a static byte slice as the
/// rendered filename (used for stdin's `-`).
fn hash_fd_emit(fd: i32, name: &[u8]) -> bool {
    match hash_fd(fd, name) {
        Some(digest) => {
            emit_hex(&digest);
            write_all(STDOUT, b"  ");
            write_all(STDOUT, name);
            write_all(STDOUT, b"\n");
            true
        }
        None => false,
    }
}

/// Hash `fd`, then write `HEX  NAME\n` using a null-terminated C string for
/// the filename (used for regular file operands).
fn hash_fd_emit_cstr(fd: i32, name: *const u8) -> bool {
    match hash_fd(fd, b"<file>") {
        Some(digest) => {
            emit_hex(&digest);
            write_all(STDOUT, b"  ");
            write_cstr(STDOUT, name);
            write_all(STDOUT, b"\n");
            true
        }
        None => false,
    }
}

/// Stream `fd` through SHA-384 and return the digest. `err_label` is only
/// used for the `read error on …` diagnostic.
fn hash_fd(fd: i32, err_label: &[u8]) -> Option<[u8; DIGEST_BYTES]> {
    let mut hasher = Sha384::new();
    let mut buf = [0u8; CHUNK];
    loop {
        // SAFETY: buf is a stack array valid for CHUNK writable bytes.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr(), buf.len()) };
        if n == 0 {
            break;
        }
        if n < 0 {
            write_all(STDERR, b"sha384sum: read error on ");
            write_all(STDERR, err_label);
            write_all(STDERR, b"\n");
            return None;
        }
        hasher.update(&buf[..n as usize]);
    }
    Some(hasher.finish())
}

// ---------------------------------------------------------------------------
// `-c` check-mode driver
// ---------------------------------------------------------------------------

/// Maximum supported PATH length in a check-list entry.
const MAX_PATH: usize = 256;

/// Verify all `HEX_HASH  PATH` lines in `list_path`. Returns `false` if any
/// line failed (mismatched digest, missing file, malformed line).
fn check_file(list_path: *const u8) -> bool {
    // SAFETY: list_path is a null-terminated argv pointer.
    let fd = unsafe { libc::open(list_path, libc::O_RDONLY, 0) };
    if fd < 0 {
        write_all(STDERR, b"sha384sum: cannot open ");
        write_cstr(STDERR, list_path);
        write_all(STDERR, b"\n");
        return false;
    }
    let fd = fd as i32;

    // Read the whole list. CHUNK at a time, accumulate into line buffer.
    let mut line = [0u8; HEX_CHARS + 2 + MAX_PATH + 1];
    let mut line_len: usize = 0;
    let mut buf = [0u8; CHUNK];
    let mut any_fail = false;

    loop {
        // SAFETY: buf is valid for CHUNK writable bytes.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr(), buf.len()) };
        if n == 0 {
            break;
        }
        if n < 0 {
            write_all(STDERR, b"sha384sum: read error on check list\n");
            libc::close(fd);
            return false;
        }
        let got = n as usize;
        let mut k = 0;
        while k < got {
            let c = buf[k];
            if c == b'\n' {
                if !process_check_line(&line[..line_len]) {
                    any_fail = true;
                }
                line_len = 0;
            } else if line_len < line.len() {
                line[line_len] = c;
                line_len += 1;
            } else {
                // Over-long line: skip the rest of it.
                line_len = line.len();
            }
            k += 1;
        }
    }
    libc::close(fd);
    // Handle trailing line without newline.
    if line_len > 0 && !process_check_line(&line[..line_len]) {
        any_fail = true;
    }
    !any_fail
}

/// Process one `HEX_HASH  PATH` check-list line: parse, re-hash the path,
/// compare, print verdict. Returns `false` on any failure (parse error,
/// I/O error, or digest mismatch).
fn process_check_line(line: &[u8]) -> bool {
    // Skip blank / comment lines silently.
    if line.is_empty() {
        return true;
    }
    if line[0] == b'#' {
        return true;
    }
    // Need at least 96 hex chars + two spaces + one path char.
    if line.len() < HEX_CHARS + 3 {
        write_all(STDERR, b"sha384sum: malformed check line\n");
        return false;
    }
    // Parse the expected digest.
    let mut expected = [0u8; DIGEST_BYTES];
    let mut i = 0;
    while i < DIGEST_BYTES {
        let hi = hex_nibble(line[i * 2]);
        let lo = hex_nibble(line[i * 2 + 1]);
        match (hi, lo) {
            (Some(h), Some(l)) => expected[i] = (h << 4) | l,
            _ => {
                write_all(STDERR, b"sha384sum: malformed check line\n");
                return false;
            }
        }
        i += 1;
    }
    // Two-space separator.
    if line[HEX_CHARS] != b' ' || line[HEX_CHARS + 1] != b' ' {
        write_all(STDERR, b"sha384sum: malformed check line\n");
        return false;
    }
    // Path portion — copy out to a NUL-terminated buffer.
    let path_bytes = &line[HEX_CHARS + 2..];
    if path_bytes.len() > MAX_PATH {
        write_all(STDERR, b"sha384sum: path too long in check line\n");
        return false;
    }
    let mut path_buf = [0u8; MAX_PATH + 1];
    let mut p = 0;
    while p < path_bytes.len() {
        path_buf[p] = path_bytes[p];
        p += 1;
    }
    path_buf[path_bytes.len()] = 0;

    // SAFETY: path_buf is null-terminated.
    let fd = unsafe { libc::open(path_buf.as_ptr(), libc::O_RDONLY, 0) };
    if fd < 0 {
        write_all(STDOUT, path_bytes);
        write_all(STDOUT, b": FAILED open or read\n");
        return false;
    }
    let fd = fd as i32;
    let digest = hash_fd(fd, path_bytes);
    libc::close(fd);
    let Some(actual) = digest else {
        write_all(STDOUT, path_bytes);
        write_all(STDOUT, b": FAILED open or read\n");
        return false;
    };

    if ct_eq(&actual, &expected) {
        write_all(STDOUT, path_bytes);
        write_all(STDOUT, b": OK\n");
        true
    } else {
        write_all(STDOUT, path_bytes);
        write_all(STDOUT, b": FAILED\n");
        false
    }
}

/// Constant-time equality for two 48-byte digests. Not strictly required by
/// the spec but avoids leaking timing information through the verdict path.
fn ct_eq(a: &[u8; DIGEST_BYTES], b: &[u8; DIGEST_BYTES]) -> bool {
    let mut diff: u8 = 0;
    let mut i = 0;
    while i < DIGEST_BYTES {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    diff == 0
}

/// Decode a single ASCII hex nibble (0-9, a-f, A-F) or return `None`.
fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

/// Write the digest as 96 lowercase hex characters.
fn emit_hex(digest: &[u8; DIGEST_BYTES]) {
    const TAB: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; HEX_CHARS];
    let mut i = 0;
    while i < DIGEST_BYTES {
        out[i * 2] = TAB[(digest[i] >> 4) as usize];
        out[i * 2 + 1] = TAB[(digest[i] & 0x0f) as usize];
        i += 1;
    }
    write_all(STDOUT, &out);
}

/// Write a null-terminated C string to `fd` (no NUL written).
fn write_cstr(fd: i32, s: *const u8) {
    if s.is_null() {
        return;
    }
    let len = c_strlen(s);
    let mut pos: usize = 0;
    while pos < len {
        // SAFETY: s is null-terminated for at least `len` bytes; pos < len
        // ensures we read inside that span.
        let n = unsafe { libc::write(fd, s.add(pos), len - pos) };
        if n <= 0 {
            return;
        }
        pos += n as usize;
    }
}

/// Length of a null-terminated C string. Caller guarantees termination.
fn c_strlen(s: *const u8) -> usize {
    let mut n: usize = 0;
    // SAFETY: caller guarantees the string is null-terminated.
    while unsafe { s.add(n).read() } != 0 {
        n += 1;
    }
    n
}

/// Write the entire slice or stop on error.
fn write_all(fd: i32, buf: &[u8]) {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: buf slice is valid for buf.len() bytes.
        let n = unsafe { libc::write(fd, buf[pos..].as_ptr(), buf.len() - pos) };
        if n <= 0 {
            return;
        }
        pos += n as usize;
    }
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(STDERR, b"sha384sum: panic\n");
    libc::exit(1)
}
