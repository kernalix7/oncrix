// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/split` — split a file into pieces with sequential
//! suffix names.
//!
//! Usage:
//!   split [-l N | -b SIZE] [-a SUFLEN] [FILE [PREFIX]]
//!
//! Splits FILE (stdin if `-` or absent) into pieces named
//! `<PREFIX><suffix>` where `<suffix>` is a base-26 lowercase letter
//! string of length SUFLEN (default 2). PREFIX defaults to `x`.
//!
//! Flags:
//!   -l N     break every N input lines (default 1000).
//!   -b SIZE  break every SIZE bytes; SIZE accepts a trailing `K`
//!            (×1024) or `M` (×1048576) suffix.
//!   -a N     suffix length (default 2 → aa..zz). Caps at 6.
//!
//! Streaming: 4 KiB read chunk. Output fd is rotated when the
//! current piece reaches its threshold (line count or byte count
//! depending on mode). On rotation the current fd is closed and
//! the next path opened with O_WRONLY|O_CREAT|O_TRUNC, mode 0o644.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/split.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const READ_CHUNK: usize = 4096;
const MAX_SUFLEN: usize = 6;
const PREFIX_MAX: usize = 200;

/// Split mode — either by line count or by byte count.
#[derive(Clone, Copy)]
enum Mode {
    Lines(u64),
    Bytes(u64),
}

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym split_main,
    );
}

extern "C" fn split_main(argc: usize, argv: *const *const u8) -> ! {
    let mut mode = Mode::Lines(1000);
    let mut suflen: usize = 2;
    let mut positional: [&[u8]; 2] = [b""; 2];
    let mut n_pos = 0usize;
    let mut idx = 1usize;

    while idx < argc {
        // SAFETY: idx < argc; argv is a kernel-supplied valid pointer array.
        let arg = unsafe { cstr_at(argv, idx) };
        if arg == b"-l" {
            idx += 1;
            if idx >= argc {
                fail(b"split: -l needs N\n");
            }
            // SAFETY: idx < argc.
            let v = unsafe { cstr_at(argv, idx) };
            mode =
                Mode::Lines(parse_u64(v).unwrap_or_else(|| fail(b"split: invalid line count\n")));
        } else if arg == b"-b" {
            idx += 1;
            if idx >= argc {
                fail(b"split: -b needs SIZE\n");
            }
            // SAFETY: idx < argc.
            let v = unsafe { cstr_at(argv, idx) };
            mode =
                Mode::Bytes(parse_size(v).unwrap_or_else(|| fail(b"split: invalid byte size\n")));
        } else if arg == b"-a" {
            idx += 1;
            if idx >= argc {
                fail(b"split: -a needs SUFLEN\n");
            }
            // SAFETY: idx < argc.
            let v = unsafe { cstr_at(argv, idx) };
            let n = parse_u64(v).unwrap_or_else(|| fail(b"split: invalid suffix length\n"));
            if n == 0 || n as usize > MAX_SUFLEN {
                fail(b"split: suffix length out of range\n");
            }
            suflen = n as usize;
        } else if arg == b"--" {
            // After --, all remaining argv elements are positional.
            idx += 1;
            while idx < argc && n_pos < positional.len() {
                // SAFETY: idx < argc.
                positional[n_pos] = unsafe { cstr_at(argv, idx) };
                n_pos += 1;
                idx += 1;
            }
            break;
        } else if !arg.is_empty() && arg[0] == b'-' && arg != b"-" {
            fail(b"split: unknown option\n");
        } else if n_pos < positional.len() {
            positional[n_pos] = arg;
            n_pos += 1;
        } else {
            fail(b"split: too many operands\n");
        }
        idx += 1;
    }

    // Resolve positional args.
    let in_path = if n_pos >= 1 { positional[0] } else { b"-" };
    let prefix = if n_pos >= 2 { positional[1] } else { b"x" };

    if prefix.len() > PREFIX_MAX {
        fail(b"split: prefix too long\n");
    }

    // Open input fd.
    let in_fd: i32 = if in_path == b"-" {
        0
    } else {
        let mut buf = [0u8; 256];
        let n = in_path.len().min(buf.len() - 1);
        buf[..n].copy_from_slice(&in_path[..n]);
        // SAFETY: buf is NUL-terminated by construction.
        let r = unsafe { libc::open(buf.as_ptr(), libc::O_RDONLY, 0) };
        if r < 0 {
            fail(b"split: cannot open input file\n");
        }
        r as i32
    };

    // Suffix counter, suffix buffer, and full output path buffer.
    let mut suffix = [0u8; MAX_SUFLEN];
    for s in suffix.iter_mut().take(suflen) {
        *s = b'a';
    }
    let mut path_buf = [0u8; PREFIX_MAX + MAX_SUFLEN + 1];
    let mut out_fd: i32 = -1;
    let mut piece_lines: u64 = 0;
    let mut piece_bytes: u64 = 0;
    let mut first_piece = true;

    let mut read_buf = [0u8; READ_CHUNK];
    loop {
        // SAFETY: read_buf is owned and writable.
        let n = unsafe { libc::read(in_fd, read_buf.as_mut_ptr(), read_buf.len()) };
        if n <= 0 {
            break;
        }
        let chunk = &read_buf[..n as usize];

        match mode {
            Mode::Lines(limit) => {
                // Emit bytes one logical line at a time: walk the chunk
                // looking for '\n' boundaries; rotate after `limit` lines.
                let mut start = 0usize;
                let mut i = 0usize;
                while i < chunk.len() {
                    let need_open = first_piece || out_fd < 0;
                    if need_open {
                        if !rotate(
                            &mut out_fd,
                            &suffix[..suflen],
                            prefix,
                            &mut path_buf,
                            first_piece,
                            &mut piece_lines,
                            &mut piece_bytes,
                        ) {
                            fail(b"split: cannot open output piece\n");
                        }
                        first_piece = false;
                    }

                    if chunk[i] == b'\n' {
                        piece_lines += 1;
                        i += 1;
                        if piece_lines >= limit {
                            if !write_all(out_fd, &chunk[start..i]) {
                                fail(b"split: write failed\n");
                            }
                            start = i;
                            let _ = libc::close(out_fd);
                            out_fd = -1;
                            advance_suffix(&mut suffix[..suflen]);
                            piece_lines = 0;
                            piece_bytes = 0;
                        }
                    } else {
                        i += 1;
                    }
                }
                if start < chunk.len() && out_fd >= 0 && !write_all(out_fd, &chunk[start..]) {
                    fail(b"split: write failed\n");
                }
            }
            Mode::Bytes(limit) => {
                let mut start = 0usize;
                while start < chunk.len() {
                    let need_open = first_piece || out_fd < 0;
                    if need_open {
                        if !rotate(
                            &mut out_fd,
                            &suffix[..suflen],
                            prefix,
                            &mut path_buf,
                            first_piece,
                            &mut piece_lines,
                            &mut piece_bytes,
                        ) {
                            fail(b"split: cannot open output piece\n");
                        }
                        first_piece = false;
                    }
                    let remaining = limit - piece_bytes;
                    let take = ((chunk.len() - start) as u64).min(remaining) as usize;
                    if !write_all(out_fd, &chunk[start..start + take]) {
                        fail(b"split: write failed\n");
                    }
                    piece_bytes += take as u64;
                    start += take;
                    if piece_bytes >= limit {
                        let _ = libc::close(out_fd);
                        out_fd = -1;
                        advance_suffix(&mut suffix[..suflen]);
                        piece_bytes = 0;
                    }
                }
            }
        }
    }

    if out_fd >= 0 {
        let _ = libc::close(out_fd);
    }
    if in_fd > 0 {
        let _ = libc::close(in_fd);
    }

    libc::exit(0)
}

/// Open the next piece file. Returns `true` on success.
///
/// Composes `<prefix><suffix>\0` into `path_buf`, opens with
/// O_WRONLY|O_CREAT|O_TRUNC mode 0o644, and stores the fd into
/// `*out_fd`. Resets piece counters.
fn rotate(
    out_fd: &mut i32,
    suffix: &[u8],
    prefix: &[u8],
    path_buf: &mut [u8],
    _first_piece: bool,
    piece_lines: &mut u64,
    piece_bytes: &mut u64,
) -> bool {
    let mut p = 0usize;
    for &b in prefix {
        if p >= path_buf.len() - 1 {
            return false;
        }
        path_buf[p] = b;
        p += 1;
    }
    for &b in suffix {
        if p >= path_buf.len() - 1 {
            return false;
        }
        path_buf[p] = b;
        p += 1;
    }
    path_buf[p] = 0;
    // SAFETY: path_buf is NUL-terminated above.
    let r = unsafe {
        libc::open(
            path_buf.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            0o644,
        )
    };
    if r < 0 {
        return false;
    }
    *out_fd = r as i32;
    *piece_lines = 0;
    *piece_bytes = 0;
    true
}

/// Increment the base-26 lowercase suffix in place. Carries left.
/// At overflow (zz..z → aa..a) the suffix wraps silently — caller
/// is responsible for not creating more pieces than the suffix can
/// number.
fn advance_suffix(suffix: &mut [u8]) {
    let mut i = suffix.len();
    while i > 0 {
        i -= 1;
        if suffix[i] < b'z' {
            suffix[i] += 1;
            return;
        }
        suffix[i] = b'a';
    }
}

fn parse_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut acc: u64 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(acc)
}

/// Parse `-b` SIZE — optional trailing `K` (×1024) or `M` (×1048576).
fn parse_size(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let last = *bytes.last()?;
    let (digits, mult): (&[u8], u64) = match last {
        b'K' | b'k' => (&bytes[..bytes.len() - 1], 1024),
        b'M' | b'm' => (&bytes[..bytes.len() - 1], 1024 * 1024),
        _ => (bytes, 1),
    };
    let v = parse_u64(digits)?;
    v.checked_mul(mult)
}

fn fail(msg: &[u8]) -> ! {
    let _ = write_all(2, msg);
    libc::exit(1)
}

fn write_all(fd: i32, buf: &[u8]) -> bool {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: buf slice is valid for buf.len() bytes.
        let n = unsafe { libc::write(fd, buf[pos..].as_ptr(), buf.len() - pos) };
        if n <= 0 {
            return false;
        }
        pos += n as usize;
    }
    true
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

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let _ = write_all(2, b"split: panic\n");
    libc::exit(1)
}
