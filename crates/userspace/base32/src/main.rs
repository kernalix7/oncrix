// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/base32` — RFC 4648 base32 encode/decode utility (GNU subset).
//!
//! Forms:
//!   * `base32 [FILE]`           encode FILE (or stdin if absent / `-`).
//!   * `base32 -d [FILE]`        decode FILE (or stdin if absent / `-`).
//!   * `base32 -w COLS [FILE]`   wrap encoded output at COLS (0 = no wrap).
//!
//! Alphabet: `A-Z2-7`, pad `=`. Default encode wrap is 76 columns
//! (GNU coreutils default). On decode, whitespace (`\n`, `\r`, `\t`, ` `)
//! is silently skipped; any other non-alphabet byte yields
//! `base32: invalid input` on stderr and exit 1.
//!
//! Streaming: input is consumed 4 KiB at a time; the encoder emits to an 8 KiB
//! line buffer; the decoder buffers up to eight valid alphabet chars before
//! emitting five output bytes. The full file is never held in memory.
//!
//! Exit status:
//!   * 0 — success
//!   * 1 — I/O failure, invalid option, or invalid base32 input on decode
//!
//! Not POSIX-standard (GNU coreutils utility). Algorithm: RFC 4648 §6.

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
        main = sym base32_main,
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
/// ceil(4096/5)*8 ≤ 6560 chars + newlines; 8 KiB gives headroom.
const OUT_BUF: usize = 8192;

/// Default encode line-wrap width (RFC 4648 / GNU default).
const DEFAULT_WRAP: u32 = 76;

/// RFC 4648 §6 standard base32 alphabet.
const ENC_TABLE: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Decode lookup sentinels.
const DEC_INVALID: u8 = 0xFF;
const DEC_SPACE: u8 = 0xFE;
const DEC_PAD: u8 = 0xFD;

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

extern "C" fn base32_main(argc: usize, argv: *const *const u8) -> ! {
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
                write_all(STDERR, b"base32: option requires an argument: -w\n");
                libc::exit(1);
            }
            // SAFETY: i < argc, so argv[i] is one of the execve-supplied pointers.
            let v = unsafe { argv.add(i).read() };
            match parse_u32(v) {
                Some(n) => wrap = n,
                None => {
                    write_all(STDERR, b"base32: invalid wrap value\n");
                    libc::exit(1);
                }
            }
        } else if let Some(rest) = strip_prefix(ptr, b"--wrap=") {
            match parse_u32(rest) {
                Some(n) => wrap = n,
                None => {
                    write_all(STDERR, b"base32: invalid wrap value\n");
                    libc::exit(1);
                }
            }
        } else if let Some(rest) = strip_prefix(ptr, b"-w") {
            // -wCOLS without space.
            // SAFETY: strip_prefix returned a pointer inside the same C string.
            let first = unsafe { rest.read() };
            if first == 0 {
                write_all(STDERR, b"base32: option requires an argument: -w\n");
                libc::exit(1);
            }
            match parse_u32(rest) {
                Some(n) => wrap = n,
                None => {
                    write_all(STDERR, b"base32: invalid wrap value\n");
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
            write_all(STDERR, b"base32: unknown option: ");
            write_cstr(STDERR, ptr);
            write_all(STDERR, b"\n");
            libc::exit(1);
        } else if file.is_null() {
            file = ptr;
        } else {
            write_all(STDERR, b"base32: extra operand\n");
            libc::exit(1);
        }
        i += 1;
    }

    // Resolve the source fd.
    let (fd, opened) = open_source(file);
    if fd < 0 {
        write_all(STDERR, b"base32: cannot open ");
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
    b"Usage: base32 [-d] [-w COLS] [FILE]\n  -d, --decode    decode data\n  -w, --wrap COLS wrap encoded lines at COLS (0 = no wrap)\n";

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

/// Streaming base32 encoder.
///
/// Reads 4 KiB at a time, carries 0–4 leftover bytes between iterations, and
/// flushes the output buffer as it fills. With `wrap > 0`, a `\n` is emitted
/// after every `wrap` encoded characters. A single trailing `\n` always
/// terminates the stream when something was written.
fn encode_stream(fd: i32, wrap: u32) -> bool {
    let mut in_buf = [0u8; IN_CHUNK];
    let mut out_buf = [0u8; OUT_BUF];
    let mut out_len: usize = 0;
    let mut col: u32 = 0;

    // Carry-over for input not divisible by 5 between read() iterations.
    let mut carry = [0u8; 4];
    let mut ncarry: usize = 0;

    let mut wrote_any = false;

    loop {
        // SAFETY: in_buf is a stack array valid for IN_CHUNK writable bytes.
        let n = unsafe { libc::read(fd, in_buf.as_mut_ptr(), in_buf.len()) };
        if n < 0 {
            write_all(STDERR, b"base32: read error\n");
            return false;
        }
        if n == 0 {
            break;
        }
        let got = n as usize;

        // Merge carry + new bytes via a virtual index: positions 0..ncarry
        // come from `carry`, positions ncarry.. come from `in_buf[..got]`.
        let total = ncarry + got;
        let full_groups = total / 5;
        let consumed = full_groups * 5;

        let mut idx = 0;
        while idx + 5 <= consumed {
            let b0 = combined_byte(&carry, ncarry, &in_buf, idx);
            let b1 = combined_byte(&carry, ncarry, &in_buf, idx + 1);
            let b2 = combined_byte(&carry, ncarry, &in_buf, idx + 2);
            let b3 = combined_byte(&carry, ncarry, &in_buf, idx + 3);
            let b4 = combined_byte(&carry, ncarry, &in_buf, idx + 4);

            // 40 bits → eight 5-bit groups, high-to-low.
            let c0 = ENC_TABLE[(b0 >> 3) as usize];
            let c1 = ENC_TABLE[(((b0 & 0x07) << 2) | (b1 >> 6)) as usize];
            let c2 = ENC_TABLE[((b1 >> 1) & 0x1F) as usize];
            let c3 = ENC_TABLE[(((b1 & 0x01) << 4) | (b2 >> 4)) as usize];
            let c4 = ENC_TABLE[(((b2 & 0x0F) << 1) | (b3 >> 7)) as usize];
            let c5 = ENC_TABLE[((b3 >> 2) & 0x1F) as usize];
            let c6 = ENC_TABLE[(((b3 & 0x03) << 3) | (b4 >> 5)) as usize];
            let c7 = ENC_TABLE[(b4 & 0x1F) as usize];

            for ch in [c0, c1, c2, c3, c4, c5, c6, c7] {
                if !push_char(&mut out_buf, &mut out_len, &mut col, wrap, ch) {
                    return false;
                }
                wrote_any = true;
            }
            idx += 5;
        }

        // Stash the new carry (0–4 bytes) for the next read iteration.
        let leftover = total - consumed;
        let mut new_carry = [0u8; 4];
        let mut k = 0;
        while k < leftover {
            new_carry[k] = combined_byte(&carry, ncarry, &in_buf, consumed + k);
            k += 1;
        }
        carry = new_carry;
        ncarry = leftover;
    }

    // Final 1/2/3/4-byte tail gets padded with `=` to a full 8-char group.
    // Pad counts per RFC 4648 §6: 1B→6=, 2B→4=, 3B→3=, 4B→1=.
    if ncarry != 0 {
        let mut bytes = [0u8; 5];
        let mut k = 0;
        while k < ncarry {
            bytes[k] = carry[k];
            k += 1;
        }
        let b0 = bytes[0];
        let b1 = bytes[1];
        let b2 = bytes[2];
        let b3 = bytes[3];
        let b4 = bytes[4];

        let c0 = ENC_TABLE[(b0 >> 3) as usize];
        let c1 = ENC_TABLE[(((b0 & 0x07) << 2) | (b1 >> 6)) as usize];
        let c2 = ENC_TABLE[((b1 >> 1) & 0x1F) as usize];
        let c3 = ENC_TABLE[(((b1 & 0x01) << 4) | (b2 >> 4)) as usize];
        let c4 = ENC_TABLE[(((b2 & 0x0F) << 1) | (b3 >> 7)) as usize];
        let c5 = ENC_TABLE[((b3 >> 2) & 0x1F) as usize];
        let c6 = ENC_TABLE[(((b3 & 0x03) << 3) | (b4 >> 5)) as usize];
        let c7 = ENC_TABLE[(b4 & 0x1F) as usize];

        // Number of valid (non-pad) output chars: 1B→2, 2B→4, 3B→5, 4B→7.
        let valid: usize = match ncarry {
            1 => 2,
            2 => 4,
            3 => 5,
            4 => 7,
            _ => 0,
        };
        let chars = [c0, c1, c2, c3, c4, c5, c6, c7];
        let mut j = 0;
        while j < 8 {
            let ch = if j < valid { chars[j] } else { b'=' };
            if !push_char(&mut out_buf, &mut out_len, &mut col, wrap, ch) {
                return false;
            }
            wrote_any = true;
            j += 1;
        }
    }

    // Terminate the last line with a newline if anything was written. When
    // wrap is non-zero and we already happen to be at column 0 we skip the
    // duplicate; match GNU coreutils which always emits a final `\n`.
    if wrote_any && (wrap == 0 || col != 0) && !push_raw(&mut out_buf, &mut out_len, b'\n') {
        return false;
    }

    flush(&mut out_buf, &mut out_len)
}

/// Read byte `i` from the virtual concatenation of `carry[..ncarry]` and
/// `in_buf` starting at offset 0.
#[inline(always)]
fn combined_byte(carry: &[u8; 4], ncarry: usize, in_buf: &[u8; IN_CHUNK], i: usize) -> u8 {
    if i < ncarry {
        carry[i]
    } else {
        in_buf[i - ncarry]
    }
}

/// Append one encoded character to `out_buf`, inserting a line break every
/// `wrap` characters when `wrap != 0`. Flushes when the buffer is full.
#[inline]
fn push_char(
    out_buf: &mut [u8; OUT_BUF],
    out_len: &mut usize,
    col: &mut u32,
    wrap: u32,
    ch: u8,
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

/// Streaming base32 decoder.
///
/// Maintains an 8-slot group accumulator over the entire stream, skipping
/// whitespace. On a non-alphabet byte (and not `=`/whitespace), emits
/// `base32: invalid input` and returns `false`.
fn decode_stream(fd: i32) -> bool {
    let dec_table = build_dec_table();

    let mut in_buf = [0u8; IN_CHUNK];
    let mut out_buf = [0u8; OUT_BUF];
    let mut out_len: usize = 0;

    let mut group = [0u8; 8];
    let mut ng: usize = 0;
    let mut pad_seen: u8 = 0;

    loop {
        // SAFETY: in_buf is a stack array valid for IN_CHUNK writable bytes.
        let n = unsafe { libc::read(fd, in_buf.as_mut_ptr(), in_buf.len()) };
        if n < 0 {
            write_all(STDERR, b"base32: read error\n");
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
                // Max legal pad count in an 8-char group is 6 (1-byte tail).
                if pad_seen > 6 {
                    write_all(STDERR, b"base32: invalid input\n");
                    return false;
                }
                group[ng] = DEC_PAD;
                ng += 1;
            } else if v == DEC_INVALID {
                write_all(STDERR, b"base32: invalid input\n");
                return false;
            } else {
                if pad_seen != 0 {
                    // Data after padding is invalid.
                    write_all(STDERR, b"base32: invalid input\n");
                    return false;
                }
                group[ng] = v;
                ng += 1;
            }

            if ng == 8 {
                // Legal pad counts: 0, 1, 3, 4, 6. 2 and 5 are malformed.
                if pad_seen == 2 || pad_seen == 5 || pad_seen == 7 || pad_seen == 8 {
                    write_all(STDERR, b"base32: invalid input\n");
                    return false;
                }
                if !flush_group(&group, pad_seen, &mut out_buf, &mut out_len) {
                    return false;
                }
                ng = 0;
                // If we saw padding, the stream is done after this group —
                // any further non-whitespace input is an error.
                if pad_seen != 0 {
                    while i < got {
                        let b = in_buf[i];
                        i += 1;
                        if dec_table[b as usize] != DEC_SPACE {
                            write_all(STDERR, b"base32: invalid input\n");
                            return false;
                        }
                    }
                    // Drain the rest of the fd similarly so we surface
                    // trailing-garbage errors instead of silently ignoring.
                    loop {
                        // SAFETY: in_buf is a stack array valid for IN_CHUNK bytes.
                        let m = unsafe { libc::read(fd, in_buf.as_mut_ptr(), in_buf.len()) };
                        if m < 0 {
                            write_all(STDERR, b"base32: read error\n");
                            return false;
                        }
                        if m == 0 {
                            break;
                        }
                        let mg = m as usize;
                        let mut j = 0;
                        while j < mg {
                            if dec_table[in_buf[j] as usize] != DEC_SPACE {
                                write_all(STDERR, b"base32: invalid input\n");
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

    // EOF — the only legal residue is an empty group. A partial group without
    // padding is malformed.
    if ng != 0 {
        write_all(STDERR, b"base32: invalid input\n");
        return false;
    }

    flush(&mut out_buf, &mut out_len)
}

/// Decode a complete 8-char group into 1–5 output bytes.
///
/// `pad_count` ∈ {0, 1, 3, 4, 6} → output length 5, 4, 3, 2, 1.
fn flush_group(
    g: &[u8; 8],
    pad_count: u8,
    out_buf: &mut [u8; OUT_BUF],
    out_len: &mut usize,
) -> bool {
    // Treat padding slots as zero for the bit reconstruction.
    let v0 = if g[0] == DEC_PAD { 0 } else { g[0] };
    let v1 = if g[1] == DEC_PAD { 0 } else { g[1] };
    let v2 = if g[2] == DEC_PAD { 0 } else { g[2] };
    let v3 = if g[3] == DEC_PAD { 0 } else { g[3] };
    let v4 = if g[4] == DEC_PAD { 0 } else { g[4] };
    let v5 = if g[5] == DEC_PAD { 0 } else { g[5] };
    let v6 = if g[6] == DEC_PAD { 0 } else { g[6] };
    let v7 = if g[7] == DEC_PAD { 0 } else { g[7] };

    // 40 bits assembled from eight 5-bit groups.
    let b0 = (v0 << 3) | (v1 >> 2);
    let b1 = ((v1 & 0x03) << 6) | (v2 << 1) | (v3 >> 4);
    let b2 = ((v3 & 0x0F) << 4) | (v4 >> 1);
    let b3 = ((v4 & 0x01) << 7) | (v5 << 2) | (v6 >> 3);
    let b4 = ((v6 & 0x07) << 5) | v7;

    let out_bytes: usize = match pad_count {
        0 => 5,
        1 => 4,
        3 => 3,
        4 => 2,
        6 => 1,
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
    if out_bytes >= 4 && !push_raw(out_buf, out_len, b3) {
        return false;
    }
    if out_bytes >= 5 && !push_raw(out_buf, out_len, b4) {
        return false;
    }
    true
}

/// Build the 256-entry decode lookup table. Alphabet bytes map to their 5-bit
/// value; `=` maps to `DEC_PAD`; whitespace (`\n`, `\r`, `\t`, ` `) maps to
/// `DEC_SPACE`; everything else maps to `DEC_INVALID`.
fn build_dec_table() -> [u8; 256] {
    let mut t = [DEC_INVALID; 256];
    let mut i: usize = 0;
    while i < 32 {
        t[ENC_TABLE[i] as usize] = i as u8;
        i += 1;
    }
    // GNU coreutils base32 -d accepts lower-case alphabet bytes too.
    let mut j: usize = 0;
    while j < 26 {
        t[(b'a' + j as u8) as usize] = j as u8;
        j += 1;
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
    write_all(STDERR, b"base32: panic\n");
    libc::exit(1)
}
