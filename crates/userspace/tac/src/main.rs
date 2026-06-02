// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/tac` — concatenate and print files in reverse line order.
//!
//! Usage:
//!   tac           — read stdin, then emit lines in reverse.
//!   tac FILE...   — concatenate FILEs and emit lines in reverse. Up to
//!                   `MAX_FILES` operands. The operand `-` is stdin.
//!
//! No heap is available; storage is bounded:
//!   - 64 KiB byte buffer for accumulated input (`BUF_CAP`)
//!   - 4096 line slices via `(offset, length)` (`LINE_MAX`)
//!
//! Excess input bytes or excess lines are dropped silently and a warning
//! is emitted to stderr at exit. After buffering, the line index array is
//! walked backwards and each line is written followed by `'\n'`.
//!
//! GNU coreutils semantics — not part of POSIX, but ubiquitous in shell
//! scripts; behaviour is modelled on GNU `tac` minus separator/regex
//! options.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

/// Maximum number of bytes of input retained.
const BUF_CAP: usize = 64 * 1024;

/// Maximum number of input lines tracked.
const LINE_MAX: usize = 4096;

/// Read chunk size for the input loop.
const READ_CHUNK: usize = 4096;

/// Maximum number of file operands accepted.
const MAX_FILES: usize = 4;

/// Slice of the input buffer representing a single line (no trailing `\n`).
#[derive(Clone, Copy)]
struct Line {
    off: u32,
    len: u32,
}

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym tac_main,
    );
}

extern "C" fn tac_main(argc: usize, argv: *const *const u8) -> ! {
    let mut buf = [0u8; BUF_CAP];
    let mut buf_len = 0usize;
    let mut input_truncated = false;
    let mut io_error = false;

    let mut file_count = 0usize;
    let mut idx = 1usize;
    while idx < argc {
        // SAFETY: idx < argc by loop guard; argv has argc valid entries.
        let ptr = unsafe { argv.add(idx).read() };
        if ptr.is_null() {
            break;
        }
        if file_count >= MAX_FILES {
            write_err(b"tac: too many file operands; extras ignored\n");
            break;
        }
        // SAFETY: argv strings are NUL-terminated by the kernel's execve.
        let is_dash = unsafe { ptr.read() } == b'-' && unsafe { ptr.add(1).read() } == 0;
        let fd = if is_dash {
            0
        } else {
            // SAFETY: ptr is a NUL-terminated argv string.
            let r = unsafe { libc::open(ptr, libc::O_RDONLY, 0) };
            if r < 0 {
                write_err(b"tac: cannot open file\n");
                io_error = true;
                idx += 1;
                file_count += 1;
                continue;
            }
            r as i32
        };
        if !drain_fd(fd, &mut buf, &mut buf_len, &mut input_truncated) {
            io_error = true;
        }
        if !is_dash {
            libc::close(fd);
        }
        file_count += 1;
        idx += 1;
    }

    if file_count == 0 && !drain_fd(0, &mut buf, &mut buf_len, &mut input_truncated) {
        io_error = true;
    }

    let mut lines = [Line { off: 0, len: 0 }; LINE_MAX];
    let mut line_count = 0usize;
    let mut lines_dropped = false;

    let mut start = 0usize;
    let mut i = 0usize;
    while i < buf_len {
        if buf[i] == b'\n' {
            if line_count < LINE_MAX {
                lines[line_count] = Line {
                    off: start as u32,
                    len: (i - start) as u32,
                };
                line_count += 1;
            } else {
                lines_dropped = true;
            }
            start = i + 1;
        }
        i += 1;
    }
    // Trailing line without newline.
    if start < buf_len {
        if line_count < LINE_MAX {
            lines[line_count] = Line {
                off: start as u32,
                len: (buf_len - start) as u32,
            };
            line_count += 1;
        } else {
            lines_dropped = true;
        }
    }

    let mut k = line_count;
    while k > 0 {
        k -= 1;
        let ln = lines[k];
        let s = ln.off as usize;
        let e = s + ln.len as usize;
        let _ = write_all(1, &buf[s..e]);
        let _ = write_all(1, b"\n");
    }

    if input_truncated {
        write_err(b"tac: input exceeded 64 KiB buffer; trailing data dropped\n");
    }
    if lines_dropped {
        write_err(b"tac: line count exceeded 4096; extra lines dropped\n");
    }

    libc::exit(if io_error { 1 } else { 0 })
}

/// Read all bytes from `fd` into `buf` starting at `*buf_len`. Returns
/// `true` on clean EOF, `false` on read error. Sets `*input_truncated` if
/// data had to be discarded for lack of room.
fn drain_fd(fd: i32, buf: &mut [u8; BUF_CAP], buf_len: &mut usize, input_truncated: &mut bool) -> bool {
    let mut readbuf = [0u8; READ_CHUNK];
    loop {
        // SAFETY: readbuf is owned and writable for its full length.
        let n = unsafe { libc::read(fd, readbuf.as_mut_ptr(), readbuf.len()) };
        if n < 0 {
            write_err(b"tac: read error\n");
            return false;
        }
        if n == 0 {
            return true;
        }
        let want = n as usize;
        let space = buf.len() - *buf_len;
        let take = if want <= space { want } else { space };
        if take > 0 {
            buf[*buf_len..*buf_len + take].copy_from_slice(&readbuf[..take]);
            *buf_len += take;
        }
        if take < want {
            *input_truncated = true;
            // Drain remaining input so a piped writer closes gracefully.
            loop {
                // SAFETY: readbuf is owned and writable.
                let m = unsafe { libc::read(fd, readbuf.as_mut_ptr(), readbuf.len()) };
                if m <= 0 {
                    break;
                }
            }
            return true;
        }
    }
}

fn write_all(fd: i32, buf: &[u8]) -> bool {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: buf is a borrowed slice valid for buf.len() bytes.
        let n = unsafe { libc::write(fd, buf[pos..].as_ptr(), buf.len() - pos) };
        if n <= 0 {
            return false;
        }
        pos += n as usize;
    }
    true
}

fn write_err(msg: &[u8]) {
    let _ = write_all(2, msg);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_err(b"tac: panic\n");
    libc::exit(1)
}
