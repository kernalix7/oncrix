// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/base64` — RFC 4648 base64 encode/decode utility (GNU subset).
//!
//! Forms:
//!   * `base64 [FILE]`           encode FILE (or stdin if absent / `-`).
//!   * `base64 -d [FILE]`        decode FILE (or stdin if absent / `-`).
//!   * `base64 -w COLS [FILE]`   wrap encoded output at COLS (0 = no wrap).
//!
//! Alphabet: `A-Za-z0-9+/`, pad `=`. Default encode wrap is 76 columns
//! (POSIX/RFC default). On decode, whitespace (`\n`, `\r`, `\t`, ` `) is
//! silently skipped; any other non-alphabet byte yields
//! `base64: invalid input` on stderr and exit 1.
//!
//! Streaming: input is consumed 4 KiB at a time; the encoder emits to a 6 KiB
//! line buffer; the decoder buffers up to four valid alphabet chars before
//! emitting three output bytes. The full file is never held in memory.
//!
//! Exit status:
//!   * 0 — success
//!   * 1 — I/O failure, invalid option, or invalid base64 input on decode
//!
//! Not POSIX-standard (GNU coreutils utility). Algorithm: RFC 4648 §4.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// `_start` is a *naked* function so the Rust prologue does not allocate a
/// local stack frame before we capture argc/argv. The kernel's `sys_execve`
/// lays out the System V AMD64 initial stack at `RSP = 0x5FF000` with
/// `[rsp] = argc` and `[rsp+8..] = argv`.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym base64_main,
    );
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const STDIN: i32 = 0;
const STDOUT: i32 = 1;
const STDERR: i32 = 2;

/// Input chunk size for the streaming reader.
const IN_CHUNK: usize = 4096;

/// Output buffer size for the encoder. 4 KiB of input expands to at most
/// ceil(4096/3)*4 + newlines ≤ 5464 + 80 ≤ 6 KiB.
const OUT_BUF: usize = 6144;

/// Default encode line-wrap width (RFC 4648 / GNU default).
const DEFAULT_WRAP: u32 = 76;

/// RFC 4648 standard alphabet.
const ENC_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Decode lookup sentinels.
const DEC_INVALID: u8 = 0xFF;
const DEC_SPACE: u8 = 0xFE;
const DEC_PAD: u8 = 0xFD;

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

extern "C" fn base64_main(argc: usize, argv: *const *const u8) -> ! {
    let mut decode = false;
    let mut wrap: u32 = DEFAULT_WRAP;
    let mut file: *const u8 = core::ptr::null();

    // Tiny argv parser: -d / --decode, -w COLS / --wrap=COLS, -w=COLS,
    // optional single FILE operand (or `-` for stdin).
    let mut i = 1;
    while i < argc {
        // SAFETY: argv has at least `argc` valid pointers from execve.
        let ptr = unsafe { argv.add(i).read() };
        if ptr.is_null() {
            break;
        }

        if arg_eq(ptr, b"-d") || arg_eq(ptr, b"--decode") {
            decode = true;
        } else if arg_eq(ptr, b"-w") || arg_eq(ptr, b"--wrap") {
            // Value is in the next argv slot.
            i += 1;
            if i >= argc {
                write_all(STDERR, b"base64: option requires an argument: -w\n");
                libc::exit(1);
            }
            // SAFETY: i < argc, so argv[i] is one of the execve-supplied pointers.
            let v = unsafe { argv.add(i).read() };
            match parse_u32(v) {
                Some(n) => wrap = n,
                None => {
                    write_all(STDERR, b"base64: invalid wrap value\n");
                    libc::exit(1);
                }
            }
        } else if let Some(rest) = strip_prefix(ptr, b"--wrap=") {
            match parse_u32(rest) {
                Some(n) => wrap = n,
                None => {
                    write_all(STDERR, b"base64: invalid wrap value\n");
                    libc::exit(1);
                }
            }
        } else if let Some(rest) = strip_prefix(ptr, b"-w") {
            // -wCOLS without space.
            // SAFETY: strip_prefix returned a pointer inside the same C string.
            let first = unsafe { rest.read() };
            if first == 0 {
                write_all(STDERR, b"base64: option requires an argument: -w\n");
                libc::exit(1);
            }
            match parse_u32(rest) {
                Some(n) => wrap = n,
                None => {
                    write_all(STDERR, b"base64: invalid wrap value\n");
                    libc::exit(1);
                }
            }
        } else if arg_eq(ptr, b"--help") {
            write_all(STDOUT, USAGE);
            libc::exit(0);
        } else if arg_eq(ptr, b"--") {
            // End of options — next argv slot, if any, is the file operand.
            i += 1;
            if i < argc {
                // SAFETY: i < argc.
                let p = unsafe { argv.add(i).read() };
                if !p.is_null() && file.is_null() {
                    file = p;
                }
            }
            break;
        } else if is_option(ptr) {
            write_all(STDERR, b"base64: unknown option: ");
            write_cstr(STDERR, ptr);
            write_all(STDERR, b"\n");
            libc::exit(1);
        } else if file.is_null() {
            file = ptr;
        } else {
            write_all(STDERR, b"base64: extra operand\n");
            libc::exit(1);
        }
        i += 1;
    }

    // Resolve the source fd.
    let (fd, opened) = open_source(file);
    if fd < 0 {
        write_all(STDERR, b"base64: cannot open ");
        write_cstr(STDERR, file);
        write_all(STDERR, b"\n");
        libc::exit(1);
    }

    let ok = if decode {
        decode_stream(fd)
    } else {
        encode_stream(fd, wrap)
    };

    if opened {
        libc::close(fd);
    }

    libc::exit(if ok { 0 } else { 1 })
}

/// Short usage banner emitted for `--help`.
const USAGE: &[u8] =
    b"Usage: base64 [-d] [-w COLS] [FILE]\n  -d, --decode    decode data\n  -w, --wrap COLS wrap encoded lines at COLS (0 = no wrap)\n";

/// Resolve the source fd for the optional FILE operand.
/// Returns `(fd, opened_by_us)` — opened files are closed by the caller;
/// stdin is left alone.
fn open_source(file: *const u8) -> (i32, bool) {
    if file.is_null() {
        return (STDIN, false);
    }
    // SAFETY: `file` is a null-terminated argv pointer.
    let first = unsafe { file.read() };
    let second = unsafe { file.add(1).read() };
    if first == b'-' && second == 0 {
        return (STDIN, false);
    }
    // SAFETY: `file` is a null-terminated argv pointer.
    let fd = unsafe { libc::open(file, libc::O_RDONLY, 0) };
    if fd < 0 {
        return (-1, false);
    }
    (fd as i32, true)
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

/// Streaming base64 encoder.
///
/// Reads 4 KiB at a time, carries 0–2 leftover bytes between iterations, and
/// flushes the output buffer as it fills. With `wrap > 0`, a `\n` is emitted
/// after every `wrap` encoded characters. A single trailing `\n` always
/// terminates the stream when something was written.
fn encode_stream(fd: i32, wrap: u32) -> bool {
    let mut in_buf = [0u8; IN_CHUNK];
    let mut out_buf = [0u8; OUT_BUF];
    let mut out_len: usize = 0;
    let mut col: u32 = 0;

    // Carry-over for input not divisible by 3 between read() iterations.
    let mut carry = [0u8; 2];
    let mut ncarry: usize = 0;

    let mut wrote_any = false;

    loop {
        // SAFETY: in_buf is a stack array valid for IN_CHUNK writable bytes.
        let n = unsafe { libc::read(fd, in_buf.as_mut_ptr(), in_buf.len()) };
        if n < 0 {
            write_all(STDERR, b"base64: read error\n");
            return false;
        }
        if n == 0 {
            break;
        }
        let got = n as usize;

        // Merge carry + new bytes into a small scratch buffer at the head, then
        // process the bulk directly out of `in_buf`. To keep the implementation
        // simple and branch-free at scale, we walk the combined stream via an
        // index: positions 0..ncarry come from `carry`, positions ncarry.. come
        // from `in_buf[..got]`.
        let total = ncarry + got;
        let full_triples = total / 3;
        let consumed = full_triples * 3;

        let mut idx = 0;
        while idx + 3 <= consumed {
            let b0 = combined_byte(&carry, ncarry, &in_buf, idx);
            let b1 = combined_byte(&carry, ncarry, &in_buf, idx + 1);
            let b2 = combined_byte(&carry, ncarry, &in_buf, idx + 2);

            let c0 = ENC_TABLE[(b0 >> 2) as usize];
            let c1 = ENC_TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize];
            let c2 = ENC_TABLE[(((b1 & 0x0F) << 2) | (b2 >> 6)) as usize];
            let c3 = ENC_TABLE[(b2 & 0x3F) as usize];

            for ch in [c0, c1, c2, c3] {
                if !push_char(
                    &mut out_buf,
                    &mut out_len,
                    &mut col,
                    wrap,
                    ch,
                    fd_passthrough(),
                ) {
                    return false;
                }
                wrote_any = true;
            }
            idx += 3;
        }

        // Stash the new carry (0–2 bytes) for the next read iteration.
        let leftover = total - consumed;
        // Source those leftover bytes from the combined stream.
        let mut new_carry = [0u8; 2];
        let mut k = 0;
        while k < leftover {
            new_carry[k] = combined_byte(&carry, ncarry, &in_buf, consumed + k);
            k += 1;
        }
        carry = new_carry;
        ncarry = leftover;
    }

    // Final 1- or 2-byte tail gets padded with `=` to a full 4-char quartet.
    if ncarry == 1 {
        let b0 = carry[0];
        let c0 = ENC_TABLE[(b0 >> 2) as usize];
        let c1 = ENC_TABLE[((b0 & 0x03) << 4) as usize];
        for ch in [c0, c1, b'=', b'='] {
            if !push_char(
                &mut out_buf,
                &mut out_len,
                &mut col,
                wrap,
                ch,
                fd_passthrough(),
            ) {
                return false;
            }
            wrote_any = true;
        }
    } else if ncarry == 2 {
        let b0 = carry[0];
        let b1 = carry[1];
        let c0 = ENC_TABLE[(b0 >> 2) as usize];
        let c1 = ENC_TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize];
        let c2 = ENC_TABLE[((b1 & 0x0F) << 2) as usize];
        for ch in [c0, c1, c2, b'='] {
            if !push_char(
                &mut out_buf,
                &mut out_len,
                &mut col,
                wrap,
                ch,
                fd_passthrough(),
            ) {
                return false;
            }
            wrote_any = true;
        }
    }

    // Terminate the last line with a newline if anything was written and we
    // are not already at column 0 (or wrap is 0, in which case we still want
    // a final `\n` to match GNU coreutils behaviour).
    if wrote_any && (wrap == 0 || col != 0) && !push_raw(&mut out_buf, &mut out_len, b'\n') {
        return false;
    }

    flush(&mut out_buf, &mut out_len)
}

/// Read byte `i` from the virtual concatenation of `carry[..ncarry]` and
/// `in_buf` starting at offset 0.
#[inline(always)]
fn combined_byte(carry: &[u8; 2], ncarry: usize, in_buf: &[u8; IN_CHUNK], i: usize) -> u8 {
    if i < ncarry {
        carry[i]
    } else {
        in_buf[i - ncarry]
    }
}

/// Hack: `push_char` takes a writer-fd in its trailing arg so that the encode
/// hot loop can keep `out_buf` / `out_len` borrowed mutably without contending
/// with the read fd. We always emit to stdout, so just hard-code it.
#[inline(always)]
fn fd_passthrough() -> i32 {
    STDOUT
}

/// Append one encoded character to `out_buf`, inserting a line break every
/// `wrap` characters when `wrap != 0`. Flushes via the supplied `fd` when the
/// buffer is full.
#[inline]
fn push_char(
    out_buf: &mut [u8; OUT_BUF],
    out_len: &mut usize,
    col: &mut u32,
    wrap: u32,
    ch: u8,
    _fd: i32,
) -> bool {
    if wrap != 0 && *col == wrap {
        if !push_raw(out_buf, out_len, b'\n') {
            return false;
        }
        *col = 0;
    }
    if !push_raw(out_buf, out_len, ch) {
        return false;
    }
    *col += 1;
    true
}

/// Append a single byte to the output buffer, flushing to stdout when full.
#[inline]
fn push_raw(out_buf: &mut [u8; OUT_BUF], out_len: &mut usize, ch: u8) -> bool {
    if *out_len == OUT_BUF && !flush(out_buf, out_len) {
        return false;
    }
    out_buf[*out_len] = ch;
    *out_len += 1;
    true
}

/// Flush the output buffer to stdout. Returns `false` on write error.
fn flush(out_buf: &mut [u8; OUT_BUF], out_len: &mut usize) -> bool {
    let len = *out_len;
    if len == 0 {
        return true;
    }
    let mut pos = 0;
    while pos < len {
        // SAFETY: out_buf is a stack array, pos < len <= OUT_BUF.
        let n = unsafe { libc::write(STDOUT, out_buf[pos..].as_ptr(), len - pos) };
        if n <= 0 {
            return false;
        }
        pos += n as usize;
    }
    *out_len = 0;
    true
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

/// Streaming base64 decoder.
///
/// Maintains a 4-slot quartet accumulator over the entire stream, skipping
/// whitespace. On a non-alphabet byte (and not `=`/whitespace), emits
/// `base64: invalid input` and returns `false`.
fn decode_stream(fd: i32) -> bool {
    let dec_table = build_dec_table();

    let mut in_buf = [0u8; IN_CHUNK];
    let mut out_buf = [0u8; OUT_BUF];
    let mut out_len: usize = 0;

    let mut quartet = [0u8; 4];
    let mut nq: usize = 0;
    let mut pad_seen: u8 = 0;

    loop {
        // SAFETY: in_buf is a stack array valid for IN_CHUNK writable bytes.
        let n = unsafe { libc::read(fd, in_buf.as_mut_ptr(), in_buf.len()) };
        if n < 0 {
            write_all(STDERR, b"base64: read error\n");
            return false;
        }
        if n == 0 {
            break;
        }
        let got = n as usize;

        let mut i = 0;
        while i < got {
            let byte = in_buf[i];
            i += 1;
            let v = dec_table[byte as usize];

            if v == DEC_SPACE {
                continue;
            }
            if v == DEC_PAD {
                pad_seen += 1;
                if pad_seen > 2 {
                    write_all(STDERR, b"base64: invalid input\n");
                    return false;
                }
                quartet[nq] = DEC_PAD;
                nq += 1;
            } else if v == DEC_INVALID {
                write_all(STDERR, b"base64: invalid input\n");
                return false;
            } else {
                if pad_seen != 0 {
                    // Data after padding is invalid.
                    write_all(STDERR, b"base64: invalid input\n");
                    return false;
                }
                quartet[nq] = v;
                nq += 1;
            }

            if nq == 4 {
                if !flush_quartet(&quartet, pad_seen, &mut out_buf, &mut out_len) {
                    return false;
                }
                nq = 0;
                // If we saw padding, the stream is done after this quartet —
                // any further non-whitespace input is an error.
                if pad_seen != 0 {
                    // Sweep the rest of the buffer + remaining input for
                    // disallowed trailing content.
                    while i < got {
                        let b = in_buf[i];
                        i += 1;
                        if dec_table[b as usize] != DEC_SPACE {
                            write_all(STDERR, b"base64: invalid input\n");
                            return false;
                        }
                    }
                    // Drain the rest of the fd similarly so we surface
                    // trailing-garbage errors instead of silently ignoring.
                    loop {
                        // SAFETY: in_buf is a stack array valid for IN_CHUNK bytes.
                        let m = unsafe { libc::read(fd, in_buf.as_mut_ptr(), in_buf.len()) };
                        if m < 0 {
                            write_all(STDERR, b"base64: read error\n");
                            return false;
                        }
                        if m == 0 {
                            break;
                        }
                        let mg = m as usize;
                        let mut j = 0;
                        while j < mg {
                            if dec_table[in_buf[j] as usize] != DEC_SPACE {
                                write_all(STDERR, b"base64: invalid input\n");
                                return false;
                            }
                            j += 1;
                        }
                    }
                    return flush(&mut out_buf, &mut out_len);
                }
            }
        }
    }

    // EOF — the only legal residue is an empty quartet. A 1-, 2-, or 3-char
    // tail without padding is malformed.
    if nq != 0 {
        write_all(STDERR, b"base64: invalid input\n");
        return false;
    }

    flush(&mut out_buf, &mut out_len)
}

/// Decode a complete quartet into 1–3 output bytes.
///
/// `pad_count` is 0 (3 output bytes), 1 (2 output bytes), or 2 (1 output byte).
fn flush_quartet(
    q: &[u8; 4],
    pad_count: u8,
    out_buf: &mut [u8; OUT_BUF],
    out_len: &mut usize,
) -> bool {
    // Treat padding slots as zero for the bit reconstruction.
    let v0 = if q[0] == DEC_PAD { 0 } else { q[0] };
    let v1 = if q[1] == DEC_PAD { 0 } else { q[1] };
    let v2 = if q[2] == DEC_PAD { 0 } else { q[2] };
    let v3 = if q[3] == DEC_PAD { 0 } else { q[3] };

    let b0 = (v0 << 2) | (v1 >> 4);
    let b1 = ((v1 & 0x0F) << 4) | (v2 >> 2);
    let b2 = ((v2 & 0x03) << 6) | v3;

    let out_bytes: usize = match pad_count {
        0 => 3,
        1 => 2,
        2 => 1,
        _ => 0,
    };

    if out_bytes >= 1 && !push_raw(out_buf, out_len, b0) {
        return false;
    }
    if out_bytes >= 2 && !push_raw(out_buf, out_len, b1) {
        return false;
    }
    if out_bytes >= 3 && !push_raw(out_buf, out_len, b2) {
        return false;
    }
    true
}

/// Build the 256-entry decode lookup table. Alphabet bytes map to their 6-bit
/// value; `=` maps to `DEC_PAD`; whitespace (`\n`, `\r`, `\t`, ` `) maps to
/// `DEC_SPACE`; everything else maps to `DEC_INVALID`.
fn build_dec_table() -> [u8; 256] {
    let mut t = [DEC_INVALID; 256];
    let mut i: usize = 0;
    while i < 64 {
        t[ENC_TABLE[i] as usize] = i as u8;
        i += 1;
    }
    t[b'=' as usize] = DEC_PAD;
    t[b' ' as usize] = DEC_SPACE;
    t[b'\n' as usize] = DEC_SPACE;
    t[b'\r' as usize] = DEC_SPACE;
    t[b'\t' as usize] = DEC_SPACE;
    t
}

// ---------------------------------------------------------------------------
// Tiny C-string / argv helpers
// ---------------------------------------------------------------------------

/// Compare a null-terminated C string to a byte slice for exact equality.
fn arg_eq(ptr: *const u8, expected: &[u8]) -> bool {
    let mut i = 0;
    while i < expected.len() {
        // SAFETY: caller passes a null-terminated argv pointer; we stop on NUL
        // before reading past the end.
        let c = unsafe { ptr.add(i).read() };
        if c == 0 || c != expected[i] {
            return false;
        }
        i += 1;
    }
    // SAFETY: same as above.
    unsafe { ptr.add(i).read() == 0 }
}

/// If the C string at `ptr` begins with `prefix`, return a pointer just past
/// the prefix; otherwise return `None`.
fn strip_prefix(ptr: *const u8, prefix: &[u8]) -> Option<*const u8> {
    let mut i = 0;
    while i < prefix.len() {
        // SAFETY: ptr is a null-terminated argv pointer.
        let c = unsafe { ptr.add(i).read() };
        if c == 0 || c != prefix[i] {
            return None;
        }
        i += 1;
    }
    // SAFETY: in-bounds offset on the same C string.
    Some(unsafe { ptr.add(i) })
}

/// Return `true` if the argv entry begins with `-` and is more than one byte
/// (so plain `-` falls through as the stdin operand).
fn is_option(ptr: *const u8) -> bool {
    // SAFETY: ptr is a null-terminated argv pointer.
    let first = unsafe { ptr.read() };
    let second = unsafe { ptr.add(1).read() };
    first == b'-' && second != 0
}

/// Parse a non-negative decimal `u32` from a null-terminated C string. Returns
/// `None` for empty input, non-digit characters, or overflow.
fn parse_u32(ptr: *const u8) -> Option<u32> {
    if ptr.is_null() {
        return None;
    }
    let mut acc: u32 = 0;
    let mut i = 0;
    let mut any = false;
    loop {
        // SAFETY: ptr is a null-terminated C string; we break on the NUL.
        let c = unsafe { ptr.add(i).read() };
        if c == 0 {
            break;
        }
        if !c.is_ascii_digit() {
            return None;
        }
        let d = (c - b'0') as u32;
        acc = acc.checked_mul(10)?.checked_add(d)?;
        any = true;
        i += 1;
    }
    if any { Some(acc) } else { None }
}

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

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

/// Write the entire slice or stop on error. Used for diagnostics where we
/// don't need to distinguish partial writes.
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
    write_all(STDERR, b"base64: panic\n");
    libc::exit(1)
}
