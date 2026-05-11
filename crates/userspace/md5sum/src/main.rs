// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/md5sum` — print or check MD5 (RFC 1321) message digests.
//!
//! Forms:
//!   * `md5sum [FILE...]` — for each FILE print `HEX_HASH  FILENAME\n`
//!     (two spaces between hash and filename). With no operands or with a
//!     `-` operand, read from stdin; the filename column is rendered as `-`.
//!   * `md5sum -c FILE` — read FILE as a list of `HEX_HASH  PATH` lines
//!     and verify each PATH's digest. Per-PATH `PATH: OK` or `PATH: FAILED`
//!     is written to stdout; exit status is 1 if any mismatch occurred.
//!
//! Algorithm: MD5 per RFC 1321, implemented from the public RFC pseudocode.
//! No external reference source (GPL or RSA) was consulted; this is an
//! original Rust transcription of the specification.
//!
//! Exit status:
//!   * 0 — every operand processed successfully and (in check mode) every
//!     line verified.
//!   * 1 — one or more operands could not be opened or read, or one or
//!     more checksums failed verification.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// `_start` is a naked function so the Rust prologue does not allocate a
/// local stack frame before argc/argv are captured. The kernel's
/// `sys_execve` lays out the System V AMD64 initial stack at
/// `RSP = 0x5FF000` with `[rsp] = argc` and `[rsp+8..] = argv`.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym md5sum_main,
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

/// MD5 block size in bytes.
const BLOCK_SIZE: usize = 64;

/// MD5 digest size in bytes.
const DIGEST_SIZE: usize = 16;

// ---------------------------------------------------------------------------
// MD5 core (RFC 1321)
// ---------------------------------------------------------------------------

/// MD5 per-round shift amounts. Index 0..16 = round 1, 16..32 = round 2,
/// 32..48 = round 3, 48..64 = round 4. From RFC 1321 section 3.4.
const SHIFTS: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9,
    14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15,
    21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

/// Per-round additive constants. `K[i] = floor(2^32 * abs(sin(i + 1)))` in
/// radians, as defined in RFC 1321 section 3.4.
const K: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

/// Streaming MD5 hasher.
///
/// Input is consumed in 64-byte blocks; partial input is held in `buffer`
/// until enough bytes accumulate. Call `finalize` once after the last
/// `update` to obtain the 16-byte digest.
struct Md5 {
    /// Running state words A, B, C, D.
    state: [u32; 4],
    /// Total length of all bytes consumed so far.
    len: u64,
    /// Partial-block scratch (0..BLOCK_SIZE bytes pending).
    buffer: [u8; BLOCK_SIZE],
    /// Valid bytes currently in `buffer`.
    fill: usize,
}

impl Md5 {
    /// Initial state values from RFC 1321 section 3.3.
    const fn new() -> Self {
        Self {
            state: [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476],
            len: 0,
            buffer: [0u8; BLOCK_SIZE],
            fill: 0,
        }
    }

    /// Absorb `data` into the running hash.
    fn update(&mut self, data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        let mut idx = 0;

        // First, top up any partial block left over from a previous call.
        if self.fill > 0 {
            let need = BLOCK_SIZE - self.fill;
            let take = if data.len() < need { data.len() } else { need };
            let mut j = 0;
            while j < take {
                self.buffer[self.fill + j] = data[idx + j];
                j += 1;
            }
            self.fill += take;
            idx += take;
            if self.fill == BLOCK_SIZE {
                let block = self.buffer;
                self.compress(&block);
                self.fill = 0;
            }
        }

        // Then process whole blocks straight from the input slice.
        while data.len() - idx >= BLOCK_SIZE {
            let mut block = [0u8; BLOCK_SIZE];
            let mut j = 0;
            while j < BLOCK_SIZE {
                block[j] = data[idx + j];
                j += 1;
            }
            self.compress(&block);
            idx += BLOCK_SIZE;
        }

        // Stash whatever tail is left for the next call or for finalize.
        while idx < data.len() {
            self.buffer[self.fill] = data[idx];
            self.fill += 1;
            idx += 1;
        }
    }

    /// Apply the standard MD5 padding and emit the 128-bit digest as
    /// little-endian bytes (A | B | C | D, each 4 bytes LE).
    fn finalize(mut self) -> [u8; DIGEST_SIZE] {
        // Capture total bit-length before padding mutates `len`.
        let bit_len = self.len.wrapping_mul(8);

        // RFC 1321 padding: append 0x80, then zeros until length mod 64 == 56,
        // then 8 bytes of little-endian bit length.
        self.update(&[0x80u8]);

        // Pad with zeros until `fill` reaches 56, possibly straddling a block
        // boundary (in which case `compress` runs and `fill` resets to 0).
        let zeros = [0u8; BLOCK_SIZE];
        let pad_len = if self.fill <= 56 {
            56 - self.fill
        } else {
            (BLOCK_SIZE - self.fill) + 56
        };
        self.update(&zeros[..pad_len]);
        debug_assert!(self.fill == 56);

        let len_bytes = bit_len.to_le_bytes();
        self.update(&len_bytes);
        debug_assert!(self.fill == 0);

        let mut out = [0u8; DIGEST_SIZE];
        let mut i = 0;
        while i < 4 {
            let word = self.state[i].to_le_bytes();
            out[i * 4] = word[0];
            out[i * 4 + 1] = word[1];
            out[i * 4 + 2] = word[2];
            out[i * 4 + 3] = word[3];
            i += 1;
        }
        out
    }

    /// Compress one 64-byte block into the running state. Implements the
    /// four-round MD5 transform from RFC 1321 section 3.4.
    fn compress(&mut self, block: &[u8; BLOCK_SIZE]) {
        // Decode 16 little-endian 32-bit words from the block.
        let mut m = [0u32; 16];
        let mut i = 0;
        while i < 16 {
            m[i] = u32::from_le_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
            i += 1;
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];

        let mut i: usize = 0;
        while i < 64 {
            let (f, g) = if i < 16 {
                // Round 1: F(b,c,d) = (b AND c) OR ((NOT b) AND d); g = i.
                ((b & c) | (!b & d), i)
            } else if i < 32 {
                // Round 2: G(b,c,d) = (d AND b) OR ((NOT d) AND c); g = (5i + 1) mod 16.
                ((d & b) | (!d & c), (5 * i + 1) % 16)
            } else if i < 48 {
                // Round 3: H(b,c,d) = b XOR c XOR d; g = (3i + 5) mod 16.
                (b ^ c ^ d, (3 * i + 5) % 16)
            } else {
                // Round 4: I(b,c,d) = c XOR (b OR (NOT d)); g = (7i) mod 16.
                (c ^ (b | !d), (7 * i) % 16)
            };

            let temp = d;
            d = c;
            c = b;
            let sum = a
                .wrapping_add(f)
                .wrapping_add(K[i])
                .wrapping_add(m[g]);
            b = b.wrapping_add(sum.rotate_left(SHIFTS[i]));
            a = temp;

            i += 1;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

extern "C" fn md5sum_main(argc: usize, argv: *const *const u8) -> ! {
    let mut files: [*const u8; MAX_FILES] = [core::ptr::null(); MAX_FILES];
    let mut nfiles: usize = 0;
    let mut check_mode = false;

    // Argument parse: `-c` enables check mode; every other operand is a
    // file (or `-` for stdin).
    let mut i = 1;
    while i < argc {
        // SAFETY: argv has at least `argc` valid pointers from execve.
        let ptr = unsafe { argv.add(i).read() };
        if ptr.is_null() {
            break;
        }
        // SAFETY: argv pointers are null-terminated C strings.
        let first = unsafe { ptr.read() };
        // SAFETY: same as above; reading the byte after the first is safe
        // because the string is at least nul-terminated.
        let second = unsafe { ptr.add(1).read() };
        if first == b'-' && second == b'c' {
            // SAFETY: the third byte is either nul or another option char.
            let third = unsafe { ptr.add(2).read() };
            if third == 0 {
                check_mode = true;
                i += 1;
                continue;
            }
        }
        if nfiles >= MAX_FILES {
            write_all(STDERR, b"md5sum: too many file arguments\n");
            libc::exit(1);
        }
        files[nfiles] = ptr;
        nfiles += 1;
        i += 1;
    }

    let mut exit_code: i32 = 0;

    if check_mode {
        if nfiles == 0 {
            write_all(STDERR, b"md5sum: -c requires a file argument\n");
            libc::exit(1);
        }
        let mut k = 0;
        while k < nfiles {
            if !check_file(files[k]) {
                exit_code = 1;
            }
            k += 1;
        }
    } else if nfiles == 0 {
        // No operands — hash stdin, render filename as `-`.
        match hash_fd(STDIN, b"-") {
            Some(digest) => emit_line(&digest, b"-"),
            None => exit_code = 1,
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

/// Process one operand for the normal (non-check) form: open it (or
/// attach to stdin for `-`), hash it, emit one output line. Returns
/// `true` on success.
fn hash_operand(path: *const u8) -> bool {
    // SAFETY: path is a null-terminated argv pointer.
    let first = unsafe { path.read() };
    // SAFETY: same as above.
    let second = unsafe { path.add(1).read() };

    if first == b'-' && second == 0 {
        return match hash_fd(STDIN, b"-") {
            Some(digest) => {
                emit_line(&digest, b"-");
                true
            }
            None => false,
        };
    }

    // SAFETY: path is a null-terminated argv pointer.
    let fd = unsafe { libc::open(path, libc::O_RDONLY, 0) };
    if fd < 0 {
        write_all(STDERR, b"md5sum: cannot open ");
        write_cstr(STDERR, path);
        write_all(STDERR, b"\n");
        return false;
    }
    let fd = fd as i32;
    let res = hash_fd(fd, b"<file>");
    libc::close(fd);
    match res {
        Some(digest) => {
            emit_line(&digest, b"");
            // We deferred filename emission so we could include the
            // original argv-supplied path verbatim:
            write_cstr(STDOUT, path);
            write_all(STDOUT, b"\n");
            true
        }
        None => {
            write_all(STDERR, b"md5sum: read error on ");
            write_cstr(STDERR, path);
            write_all(STDERR, b"\n");
            false
        }
    }
}

/// Stream all bytes from `fd` through MD5 and return the digest. Returns
/// `None` on read error. `err_label` is used for the diagnostic when
/// `fd` is anonymous (e.g. stdin).
fn hash_fd(fd: i32, err_label: &[u8]) -> Option<[u8; DIGEST_SIZE]> {
    let mut buf = [0u8; CHUNK];
    let mut hasher = Md5::new();

    loop {
        // SAFETY: buf is a stack array valid for CHUNK writable bytes.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr(), buf.len()) };
        if n == 0 {
            break;
        }
        if n < 0 {
            // Caller decides how to format the diagnostic for named files;
            // for unnamed input (stdin) we emit it here.
            if fd == STDIN {
                write_all(STDERR, b"md5sum: read error on ");
                write_all(STDERR, err_label);
                write_all(STDERR, b"\n");
            }
            return None;
        }
        hasher.update(&buf[..n as usize]);
    }

    Some(hasher.finalize())
}

/// Emit `HEX  FILENAME` when called with a non-empty filename, or just
/// `HEX  ` (trailing two-spaces) when the caller intends to write the
/// filename itself afterwards.
fn emit_line(digest: &[u8; DIGEST_SIZE], filename: &[u8]) {
    write_hex(STDOUT, digest);
    write_all(STDOUT, b"  ");
    if !filename.is_empty() {
        write_all(STDOUT, filename);
        write_all(STDOUT, b"\n");
    }
}

// ---------------------------------------------------------------------------
// Check mode (`-c`)
// ---------------------------------------------------------------------------

/// Verify every `HEX  PATH` line in `list_path`. Returns `true` if all
/// lines verified, `false` if any failed or if the list file couldn't be
/// opened/read.
fn check_file(list_path: *const u8) -> bool {
    // SAFETY: list_path is a null-terminated argv pointer.
    let fd = unsafe { libc::open(list_path, libc::O_RDONLY, 0) };
    if fd < 0 {
        write_all(STDERR, b"md5sum: cannot open ");
        write_cstr(STDERR, list_path);
        write_all(STDERR, b"\n");
        return false;
    }
    let fd = fd as i32;

    // Slurp the list into a bounded stack buffer. For our subset this is
    // sufficient: check files are tiny by construction (one short line
    // per checksummed file).
    const LIST_MAX: usize = 16 * 1024;
    let mut buf = [0u8; LIST_MAX];
    let mut filled = 0;
    loop {
        if filled == buf.len() {
            write_all(STDERR, b"md5sum: check file too large\n");
            libc::close(fd);
            return false;
        }
        // SAFETY: buf has buf.len()-filled writable bytes from offset `filled`.
        let n = unsafe { libc::read(fd, buf[filled..].as_mut_ptr(), buf.len() - filled) };
        if n == 0 {
            break;
        }
        if n < 0 {
            write_all(STDERR, b"md5sum: read error on ");
            write_cstr(STDERR, list_path);
            write_all(STDERR, b"\n");
            libc::close(fd);
            return false;
        }
        filled += n as usize;
    }
    libc::close(fd);

    let mut all_ok = true;
    let mut start = 0;
    while start < filled {
        // Find end of line.
        let mut end = start;
        while end < filled && buf[end] != b'\n' {
            end += 1;
        }
        let line = &buf[start..end];
        start = end + 1;

        if line.is_empty() {
            continue;
        }
        if !verify_line(line) {
            all_ok = false;
        }
    }
    all_ok
}

/// Verify one `HEX  PATH` line. Writes `PATH: OK` or `PATH: FAILED` to
/// stdout. Returns `true` iff the line verified.
fn verify_line(line: &[u8]) -> bool {
    // Expect: 32 hex chars, two spaces, then the path. Any deviation is
    // treated as a malformed line (reported and counted as a failure).
    if line.len() < 32 + 2 + 1 {
        write_all(STDOUT, b"md5sum: malformed check line\n");
        return false;
    }

    let mut expected = [0u8; DIGEST_SIZE];
    let mut i = 0;
    while i < DIGEST_SIZE {
        let hi = hex_nibble(line[i * 2]);
        let lo = hex_nibble(line[i * 2 + 1]);
        match (hi, lo) {
            (Some(h), Some(l)) => expected[i] = (h << 4) | l,
            _ => {
                write_all(STDOUT, b"md5sum: malformed check line\n");
                return false;
            }
        }
        i += 1;
    }
    if line[32] != b' ' || line[33] != b' ' {
        write_all(STDOUT, b"md5sum: malformed check line\n");
        return false;
    }

    let path = &line[34..];
    // Path must be null-terminated for libc::open. Copy into a stack
    // buffer with a trailing NUL.
    const PATH_MAX: usize = 512;
    if path.is_empty() || path.len() >= PATH_MAX {
        write_all(STDOUT, b"md5sum: malformed check line\n");
        return false;
    }
    let mut cpath = [0u8; PATH_MAX];
    let mut j = 0;
    while j < path.len() {
        cpath[j] = path[j];
        j += 1;
    }
    cpath[path.len()] = 0;

    // SAFETY: cpath is null-terminated within PATH_MAX bytes.
    let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY, 0) };
    if fd < 0 {
        write_all(STDOUT, path);
        write_all(STDOUT, b": FAILED open or read\n");
        return false;
    }
    let fd = fd as i32;
    let got = hash_fd(fd, path);
    libc::close(fd);

    match got {
        Some(digest) if digest == expected => {
            write_all(STDOUT, path);
            write_all(STDOUT, b": OK\n");
            true
        }
        Some(_) => {
            write_all(STDOUT, path);
            write_all(STDOUT, b": FAILED\n");
            false
        }
        None => {
            write_all(STDOUT, path);
            write_all(STDOUT, b": FAILED open or read\n");
            false
        }
    }
}

/// Decode a single hex digit. Returns `None` on non-hex input.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

/// Write a 16-byte digest as 32 lowercase hex characters.
fn write_hex(fd: i32, digest: &[u8; DIGEST_SIZE]) {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = [0u8; DIGEST_SIZE * 2];
    let mut i = 0;
    while i < DIGEST_SIZE {
        out[i * 2] = TABLE[(digest[i] >> 4) as usize];
        out[i * 2 + 1] = TABLE[(digest[i] & 0x0f) as usize];
        i += 1;
    }
    write_all(fd, &out);
}

/// Write a null-terminated C string to `fd` (the NUL is not written).
fn write_cstr(fd: i32, s: *const u8) {
    if s.is_null() {
        return;
    }
    let len = c_strlen(s);
    let mut pos: usize = 0;
    while pos < len {
        // SAFETY: s is null-terminated for at least `len` bytes; pos < len
        // keeps the read inside that span.
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

/// Write the entire slice or stop on error. Used for diagnostics and
/// short output lines where partial-write recovery is unnecessary.
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
    write_all(STDERR, b"md5sum: panic\n");
    libc::exit(1)
}
