// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/od` — POSIX.1-2024 octal/hex/decimal/char dump.
//!
//! Reads bytes from stdin (or up to four named files) and prints them in
//! the requested radix one 16-byte block per line. Each line begins with
//! a file-offset address followed by the formatted bytes/words.
//!
//! Body formats:
//!   * `-o` — unsigned octal 16-bit words (default)
//!   * `-x` — unsigned hex 16-bit words
//!   * `-d` — unsigned decimal 16-bit words
//!   * `-b` — unsigned octal bytes
//!   * `-c` — named/escaped characters
//!
//! Address radix:
//!   * `-Ao` — octal (default)
//!   * `-Ad` — decimal
//!   * `-Ax` — hex
//!   * `-An` — none
//!
//! Implementation is heap-free: a single 16-byte block is held in a stack
//! buffer between reads, and format dispatch is a static enum match (no
//! closures, no boxed trait objects).
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/od.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// `_start` is naked so the Rust prologue does not shift `[rsp]` away from
/// argc before we capture argc/argv — see `cat`/`wc` for the same pattern.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym od_main,
    );
}

// ---------------------------------------------------------------------------
// Format dispatch
// ---------------------------------------------------------------------------

/// Output body format selected via `-o`/`-x`/`-d`/`-b`/`-c`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Body {
    /// `-o` — unsigned octal 16-bit words.
    OctalWord,
    /// `-x` — unsigned hex 16-bit words.
    HexWord,
    /// `-d` — unsigned decimal 16-bit words.
    DecimalWord,
    /// `-b` — unsigned octal bytes.
    OctalByte,
    /// `-c` — named/escaped characters.
    NamedChar,
}

/// Address radix selected via `-A?`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Addr {
    /// `-Ao` — octal (POSIX default).
    Octal,
    /// `-Ad` — decimal.
    Decimal,
    /// `-Ax` — hexadecimal.
    Hex,
    /// `-An` — no address printed.
    None,
}

const BLOCK: usize = 16;
const READ_CHUNK: usize = 4096;
/// POSIX limits operands; the task spec caps at 4.
const MAX_FILES: usize = 4;

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

extern "C" fn od_main(argc: usize, argv: *const *const u8) -> ! {
    let mut body = Body::OctalWord;
    let mut addr = Addr::Octal;
    let mut files: [*const u8; MAX_FILES] = [core::ptr::null(); MAX_FILES];
    let mut nfiles = 0usize;

    let mut idx = 1usize;
    let mut after_dd = false;
    while idx < argc {
        // SAFETY: idx < argc; argv has `argc` valid (possibly null) entries.
        let arg = unsafe { cstr_at(argv, idx) };
        idx += 1;

        if !after_dd && arg == b"--" {
            after_dd = true;
            continue;
        }

        if !after_dd && !arg.is_empty() && arg[0] == b'-' && arg != b"-" {
            // Option processing.
            match arg {
                b"-o" => body = Body::OctalWord,
                b"-x" => body = Body::HexWord,
                b"-d" => body = Body::DecimalWord,
                b"-b" => body = Body::OctalByte,
                b"-c" => body = Body::NamedChar,
                b"-A" => {
                    if idx >= argc {
                        fail(b"od: -A needs RADIX\n");
                    }
                    // SAFETY: idx < argc.
                    let r = unsafe { cstr_at(argv, idx) };
                    idx += 1;
                    addr = parse_addr(r);
                }
                _ if arg.len() >= 2 && &arg[..2] == b"-A" => {
                    addr = parse_addr(&arg[2..]);
                }
                _ => fail(b"od: unknown option\n"),
            }
            continue;
        }

        // File operand (or `-` for stdin).
        if nfiles >= MAX_FILES {
            fail(b"od: too many file operands (max 4)\n");
        }
        files[nfiles] = if arg == b"-" {
            core::ptr::null()
        } else {
            // SAFETY: argv[idx-1] is a null-terminated argv string.
            unsafe { *argv.add(idx - 1) }
        };
        nfiles += 1;
    }

    let mut state = DumpState::new(body, addr);
    let mut exit_code: i32 = 0;

    if nfiles == 0 {
        if !dump_fd(0, &mut state) {
            exit_code = 1;
        }
    } else {
        for file in files.iter().take(nfiles) {
            if file.is_null() {
                if !dump_fd(0, &mut state) {
                    exit_code = 1;
                }
                continue;
            }
            // SAFETY: pointer originates from argv, null-terminated.
            let fd = unsafe { libc::open(*file, libc::O_RDONLY, 0) };
            if fd < 0 {
                write_all(2, b"od: cannot open file\n");
                exit_code = 1;
                continue;
            }
            if !dump_fd(fd as i32, &mut state) {
                exit_code = 1;
            }
            libc::close(fd as i32);
        }
    }

    state.flush();
    libc::exit(exit_code)
}

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

/// Parse the argument to `-A` (one of `o`, `d`, `x`, `n`).
fn parse_addr(spec: &[u8]) -> Addr {
    match spec {
        b"o" => Addr::Octal,
        b"d" => Addr::Decimal,
        b"x" => Addr::Hex,
        b"n" => Addr::None,
        _ => fail(b"od: -A radix must be one of o/d/x/n\n"),
    }
}

// ---------------------------------------------------------------------------
// Dump state machine
// ---------------------------------------------------------------------------

/// Holds the streaming dump state across reads/files: the current
/// 16-byte block being assembled and the running file offset (which
/// becomes the address printed on each line).
struct DumpState {
    body: Body,
    addr: Addr,
    /// Bytes accumulated for the current line (0..BLOCK).
    block: [u8; BLOCK],
    /// Number of valid bytes currently in `block`.
    have: usize,
    /// Address (byte offset) of the *first* byte in `block`.
    line_addr: u64,
}

impl DumpState {
    /// Construct a fresh state with no accumulated bytes.
    const fn new(body: Body, addr: Addr) -> Self {
        Self {
            body,
            addr,
            block: [0u8; BLOCK],
            have: 0,
            line_addr: 0,
        }
    }

    /// Feed `chunk` into the state, emitting full 16-byte lines as they
    /// complete. Any tail under 16 bytes is held until the next call or
    /// until `flush()`.
    fn feed(&mut self, chunk: &[u8]) {
        let mut i = 0usize;
        while i < chunk.len() {
            let take = (BLOCK - self.have).min(chunk.len() - i);
            self.block[self.have..self.have + take].copy_from_slice(&chunk[i..i + take]);
            self.have += take;
            i += take;
            if self.have == BLOCK {
                emit_line(self.body, self.addr, self.line_addr, &self.block);
                self.line_addr = self.line_addr.wrapping_add(BLOCK as u64);
                self.have = 0;
            }
        }
    }

    /// Emit any tail line plus the trailing address marker (POSIX).
    fn flush(&mut self) {
        if self.have > 0 {
            // Zero-pad the unused tail bytes so word formats have full
            // 16-bit values to render (matches GNU coreutils behavior).
            for slot in &mut self.block[self.have..] {
                *slot = 0;
            }
            emit_partial_line(self.body, self.addr, self.line_addr, &self.block, self.have);
            self.line_addr = self.line_addr.wrapping_add(self.have as u64);
            self.have = 0;
        }
        // POSIX: the final line is the address of the last byte + 1.
        write_address(self.addr, self.line_addr);
        write_all(1, b"\n");
    }
}

/// Read all bytes from `fd` and feed them into `state`. Returns `true`
/// on clean EOF, `false` if a read error occurred.
fn dump_fd(fd: i32, state: &mut DumpState) -> bool {
    let mut buf = [0u8; READ_CHUNK];
    loop {
        // SAFETY: buf is valid writable storage of READ_CHUNK bytes.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr(), READ_CHUNK) };
        if n == 0 {
            return true;
        }
        if n < 0 {
            write_all(2, b"od: read error\n");
            return false;
        }
        state.feed(&buf[..n as usize]);
    }
}

// ---------------------------------------------------------------------------
// Line emission
// ---------------------------------------------------------------------------

/// Emit one complete 16-byte line: address followed by the formatted body.
fn emit_line(body: Body, addr: Addr, line_addr: u64, block: &[u8; BLOCK]) {
    write_address(addr, line_addr);
    write_body(body, block, BLOCK);
    write_all(1, b"\n");
}

/// Emit a short trailing line (`have` bytes valid, rest of `block`
/// zero-padded for word formats).
fn emit_partial_line(body: Body, addr: Addr, line_addr: u64, block: &[u8; BLOCK], have: usize) {
    write_address(addr, line_addr);
    write_body(body, block, have);
    write_all(1, b"\n");
}

/// Print the line address using the configured radix and width.
fn write_address(addr: Addr, value: u64) {
    match addr {
        Addr::Octal => {
            write_radix_padded(value, 8, 7);
        }
        Addr::Decimal => {
            write_radix_padded(value, 10, 7);
        }
        Addr::Hex => {
            write_radix_padded(value, 16, 6);
        }
        Addr::None => {
            // No address printed.
        }
    }
}

/// Dispatch to the body printer for the chosen format.
fn write_body(body: Body, block: &[u8; BLOCK], have: usize) {
    match body {
        Body::OctalWord => write_word_body(block, have, 8, 6),
        Body::HexWord => write_word_body(block, have, 16, 4),
        Body::DecimalWord => write_word_body(block, have, 10, 5),
        Body::OctalByte => write_byte_octal(block, have),
        Body::NamedChar => write_named_char(block, have),
    }
}

/// Print the block as 8 little-endian 16-bit words, each in the chosen
/// radix at the given fixed width.  Word slots beyond `have` (rounded
/// up to whole words) are skipped entirely so a partial line stays
/// shorter than a full one.
fn write_word_body(block: &[u8; BLOCK], have: usize, radix: u32, width: usize) {
    // Round `have` up to the next even byte so a stray odd byte still
    // produces a (zero-padded) word per POSIX rendering convention.
    let words = have.div_ceil(2);
    let mut i = 0usize;
    while i < words {
        write_all(1, b" ");
        let lo = block[i * 2] as u16;
        let hi = block[i * 2 + 1] as u16;
        let word = lo | (hi << 8);
        write_radix_padded(word as u64, radix, width);
        i += 1;
    }
}

/// Print the block as up to 16 octal bytes, each width 3.
fn write_byte_octal(block: &[u8; BLOCK], have: usize) {
    let mut i = 0usize;
    while i < have {
        write_all(1, b" ");
        write_radix_padded(block[i] as u64, 8, 3);
        i += 1;
    }
}

/// Print the block as up to 16 named/escaped characters in 4-wide cells.
fn write_named_char(block: &[u8; BLOCK], have: usize) {
    let mut i = 0usize;
    while i < have {
        let b = block[i];
        // Each cell is " " + 3-char content right-padded.
        let cell = name_cell(b);
        write_all(1, b" ");
        write_all(1, &cell);
        i += 1;
    }
}

/// Render one POSIX-named character cell (3 chars wide, space-padded).
///
/// POSIX `od -c` mappings:
///   * `\0 \a \b \t \n \v \f \r` for control codes that have an
///     escape sequence.
///   * 3-char octal otherwise (e.g. `\\b'\\xff'` becomes `377`).
///   * Printable ASCII becomes `" X "` (the byte then two spaces).
fn name_cell(b: u8) -> [u8; 3] {
    match b {
        0x00 => *b" \\0",
        0x07 => *b" \\a",
        0x08 => *b" \\b",
        0x09 => *b" \\t",
        0x0a => *b" \\n",
        0x0b => *b" \\v",
        0x0c => *b" \\f",
        0x0d => *b" \\r",
        0x20..=0x7e => {
            // Printable: "  X" right-aligned in 3 chars.
            let mut out = [b' '; 3];
            out[2] = b;
            out
        }
        _ => {
            // Non-printable: octal, padded to 3 digits, no leading space.
            let mut out = [b'0'; 3];
            let mut v = b;
            let mut pos = 3;
            while pos > 0 {
                pos -= 1;
                out[pos] = b'0' + (v & 0o7);
                v >>= 3;
            }
            out
        }
    }
}

// ---------------------------------------------------------------------------
// Numeric formatting
// ---------------------------------------------------------------------------

/// Render `value` in `radix` (8/10/16) right-aligned in a `width`-char
/// field, zero-padded on the left, and write it to stdout.
fn write_radix_padded(value: u64, radix: u32, width: usize) {
    debug_assert!(radix == 8 || radix == 10 || radix == 16);
    debug_assert!(width <= 22);

    let mut buf = [b'0'; 22];
    let mut pos = buf.len();
    let mut v = value;
    if v == 0 {
        pos -= 1;
        buf[pos] = b'0';
    } else {
        while v > 0 {
            pos -= 1;
            let d = (v % radix as u64) as u8;
            buf[pos] = if d < 10 { b'0' + d } else { b'a' + (d - 10) };
            v /= radix as u64;
        }
    }
    let digits = &buf[pos..];

    // Left-pad with '0' to reach `width` (truncates if digits already wider).
    if digits.len() < width {
        let pad = [b'0'; 22];
        let pad_len = width - digits.len();
        write_all(1, &pad[..pad_len.min(pad.len())]);
    }
    write_all(1, digits);
}

// ---------------------------------------------------------------------------
// I/O helpers
// ---------------------------------------------------------------------------

fn write_all(fd: i32, buf: &[u8]) {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: buf slice is valid for buf.len() bytes.
        let n = unsafe { libc::write(fd, buf[pos..].as_ptr(), buf.len() - pos) };
        if n <= 0 {
            break;
        }
        pos += n as usize;
    }
}

fn fail(msg: &[u8]) -> ! {
    write_all(2, msg);
    libc::exit(1)
}

/// SAFETY: caller guarantees `idx < argc` and `argv` is a valid argv pointer.
unsafe fn cstr_at(argv: *const *const u8, idx: usize) -> &'static [u8] {
    unsafe {
        let p = *argv.add(idx);
        if p.is_null() {
            return &[];
        }
        let mut len = 0usize;
        while *p.add(len) != 0 {
            len += 1;
            if len > 4096 {
                break;
            }
        }
        core::slice::from_raw_parts(p, len)
    }
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(2, b"od: panic\n");
    libc::exit(1)
}
