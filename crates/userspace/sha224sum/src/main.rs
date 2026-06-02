// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/sha224sum` — SHA-224 (FIPS 180-4) file digest utility.
//!
//! Forms:
//!   * `sha224sum [FILE...]` — for each FILE print `HEX_HASH  FILENAME\n`
//!     (two spaces). With no operand or with a `-` operand, read stdin and
//!     render the filename as `-`.
//!   * `sha224sum -c FILE` — read FILE as a list of `HEX_HASH  PATH` lines
//!     and verify each PATH. Prints `PATH: OK` or `PATH: FAILED` to stdout
//!     and exits 1 if any check fails.
//!
//! Algorithm: original Rust implementation of SHA-224 as defined by
//! FIPS PUB 180-4 (US Department of Commerce / NIST, public-domain). The
//! compression function is identical to SHA-256 (§ 6.2.2 / § 6.3); only the
//! initial hash value (§ 5.3.2) differs, and the digest is truncated to the
//! first seven 32-bit words (28 bytes / 56 hex chars). No GPL or otherwise
//! licensed reference source was consulted.
//!
//! POSIX reference: this is a GNU coreutils utility, not a POSIX one — it
//! mirrors the `sha224sum(1)` behaviour described by GNU coreutils.

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
        main = sym sha224sum_main,
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

/// SHA-224 digest length in bytes / hex chars (FIPS 180-4 § 6.3 — the first
/// seven 32-bit words of the SHA-256 chaining state).
const DIGEST_BYTES: usize = 28;
const HEX_CHARS: usize = 56;

// ---------------------------------------------------------------------------
// SHA-224 core (FIPS 180-4)
// ---------------------------------------------------------------------------

/// Initial hash value H(0) for SHA-224 — second 32 bits of the fractional
/// parts of the square roots of the 9th through 16th primes (FIPS 180-4
/// § 5.3.2).
const H0: [u32; 8] = [
    0xc105_9ed8,
    0x367c_d507,
    0x3070_dd17,
    0xf70e_5939,
    0xffc0_0b31,
    0x6858_1511,
    0x64f9_8fa7,
    0xbefa_4fa4,
];

/// Round constants K — first 32 bits of the fractional parts of the cube
/// roots of the first 64 primes (FIPS 180-4 § 4.2.2). Identical to the
/// SHA-256 schedule constants since SHA-224 shares the same compression
/// function (§ 6.3).
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

/// Streaming SHA-224 state. Feed bytes via [`Sha224::update`] and call
/// [`Sha224::finish`] to obtain the 28-byte digest.
struct Sha224 {
    /// Current chaining variables H0..H7 (only H0..H6 contribute to the
    /// final digest, but the compression function still uses all eight).
    h: [u32; 8],
    /// Partial 64-byte block being accumulated.
    block: [u8; 64],
    /// Number of valid bytes in `block`.
    block_len: usize,
    /// Total number of *bytes* hashed so far. The length field appended in
    /// finalisation is this value times eight (in bits).
    total_bytes: u64,
}

impl Sha224 {
    /// Construct a new SHA-224 hasher in its initial state.
    fn new() -> Self {
        Self {
            h: H0,
            block: [0u8; 64],
            block_len: 0,
            total_bytes: 0,
        }
    }

    /// Absorb `data` into the hasher, processing any 64-byte blocks that
    /// complete during the call.
    fn update(&mut self, data: &[u8]) {
        let mut i = 0;
        while i < data.len() {
            let space = 64 - self.block_len;
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
            if self.block_len == 64 {
                let blk = self.block;
                self.compress(&blk);
                self.block_len = 0;
            }
        }
        self.total_bytes = self.total_bytes.wrapping_add(data.len() as u64);
    }

    /// Apply the SHA-256/SHA-224 compression function to one 64-byte block
    /// (FIPS 180-4 § 6.2.2, reused unchanged for SHA-224 per § 6.3).
    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        let mut t = 0;
        while t < 16 {
            let off = t * 4;
            w[t] = (block[off] as u32) << 24
                | (block[off + 1] as u32) << 16
                | (block[off + 2] as u32) << 8
                | (block[off + 3] as u32);
            t += 1;
        }
        while t < 64 {
            let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
            let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
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
        while i < 64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
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

    /// Append SHA-256 padding (a single `0x80` byte, zero pad to length 56
    /// mod 64, then the 64-bit big-endian message length in bits) and emit
    /// the 28-byte SHA-224 digest. Per FIPS 180-4 § 6.3 the digest is the
    /// big-endian serialisation of H[0..7] — the eighth word is discarded.
    fn finish(mut self) -> [u8; DIGEST_BYTES] {
        let bit_len = self.total_bytes.wrapping_mul(8);

        // Append 0x80.
        self.block[self.block_len] = 0x80;
        self.block_len += 1;

        // If there isn't room for the 8-byte length, flush this block first.
        if self.block_len > 56 {
            let mut i = self.block_len;
            while i < 64 {
                self.block[i] = 0;
                i += 1;
            }
            let blk = self.block;
            self.compress(&blk);
            self.block_len = 0;
        }
        // Zero-pad up to byte 56.
        let mut i = self.block_len;
        while i < 56 {
            self.block[i] = 0;
            i += 1;
        }
        // 64-bit big-endian length in bits.
        let mut j = 0;
        while j < 8 {
            self.block[56 + j] = (bit_len >> (56 - j * 8)) as u8;
            j += 1;
        }
        let blk = self.block;
        self.compress(&blk);

        // Serialise H[0..7] big-endian — first seven 32-bit words only.
        let mut out = [0u8; DIGEST_BYTES];
        let mut k = 0;
        while k < 7 {
            let v = self.h[k];
            out[k * 4] = (v >> 24) as u8;
            out[k * 4 + 1] = (v >> 16) as u8;
            out[k * 4 + 2] = (v >> 8) as u8;
            out[k * 4 + 3] = v as u8;
            k += 1;
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

extern "C" fn sha224sum_main(argc: usize, argv: *const *const u8) -> ! {
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
                write_all(STDERR, b"sha224sum: too many file arguments\n");
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
            write_all(STDERR, b"sha224sum: -c requires a checksum file\n");
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
        write_all(STDERR, b"sha224sum: cannot open ");
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

/// Stream `fd` through SHA-224 and return the digest. `err_label` is only
/// used for the `read error on …` diagnostic.
fn hash_fd(fd: i32, err_label: &[u8]) -> Option<[u8; DIGEST_BYTES]> {
    let mut hasher = Sha224::new();
    let mut buf = [0u8; CHUNK];
    loop {
        // SAFETY: buf is a stack array valid for CHUNK writable bytes.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr(), buf.len()) };
        if n == 0 {
            break;
        }
        if n < 0 {
            write_all(STDERR, b"sha224sum: read error on ");
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
        write_all(STDERR, b"sha224sum: cannot open ");
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
            write_all(STDERR, b"sha224sum: read error on check list\n");
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
    // Need at least 56 hex chars + two spaces + one path char.
    if line.len() < HEX_CHARS + 3 {
        write_all(STDERR, b"sha224sum: malformed check line\n");
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
                write_all(STDERR, b"sha224sum: malformed check line\n");
                return false;
            }
        }
        i += 1;
    }
    // Two-space separator.
    if line[HEX_CHARS] != b' ' || line[HEX_CHARS + 1] != b' ' {
        write_all(STDERR, b"sha224sum: malformed check line\n");
        return false;
    }
    // Path portion — copy out to a NUL-terminated buffer.
    let path_bytes = &line[HEX_CHARS + 2..];
    if path_bytes.len() > MAX_PATH {
        write_all(STDERR, b"sha224sum: path too long in check line\n");
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

/// Constant-time equality for two 28-byte digests. Not strictly required by
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

/// Write the digest as 56 lowercase hex characters.
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
    write_all(STDERR, b"sha224sum: panic\n");
    libc::exit(1)
}
