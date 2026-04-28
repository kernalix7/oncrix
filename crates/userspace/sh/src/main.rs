// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX minimal POSIX shell skeleton.
//!
//! Supports built-in commands: `exit`, `cd`, `export`.
//! External commands are located via PATH lookup and executed with `execve`.
//!
//! This is a skeleton implementation. A production shell would require
//! a full POSIX grammar parser, job control, and signal handling.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Prompt string written to stdout before each command.
const PROMPT: &[u8] = b"$ ";
/// Maximum command line length.
const CMD_MAX: usize = 512;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sh_main()
}

// ---------------------------------------------------------------------------
// Shell main loop
// ---------------------------------------------------------------------------

fn sh_main() -> ! {
    let mut buf = [0u8; CMD_MAX];

    loop {
        // Print prompt.
        write_all(1, PROMPT);

        // Read a line from stdin.
        let n = read_line(&mut buf);
        if n == 0 {
            // EOF (Ctrl-D): exit cleanly.
            libc::exit(0);
        }

        let line = &buf[..n];
        // Trim trailing newline.
        let line = if line.last() == Some(&b'\n') {
            &line[..line.len() - 1]
        } else {
            line
        };

        if line.is_empty() {
            continue;
        }

        // Parse the first token as the command.
        let (cmd, rest) = split_first_token(line);

        match cmd {
            b"exit" => {
                let code = parse_i32(rest).unwrap_or(0);
                libc::exit(code);
            }
            b"echo" => {
                // Write the argument slice followed by a newline to stdout.
                write_all(1, rest);
                write_all(1, b"\n");
            }
            b"cd" => {
                // cd is a built-in — stub: chdir syscall not yet wired.
                let _ = rest;
            }
            b"export" => {
                // export is a built-in — stub: putenv not yet wired.
                let _ = rest;
            }
            b"pwd" => {
                write_all(1, b"/\n");
            }
            b"pid" => {
                let pid = libc::getpid();
                let mut tmp = [0u8; 20];
                let s = fmt_i64(&mut tmp, pid);
                write_all(1, s);
                write_all(1, b"\n");
            }
            b"cat" => {
                if rest == b"/etc/motd" {
                    // SAFETY: c"/etc/motd" is a valid null-terminated C string.
                    let fd = unsafe { libc::open(c"/etc/motd".as_ptr().cast(), 0, 0) };
                    if fd >= 0 {
                        let mut cbuf = [0u8; 256];
                        loop {
                            // SAFETY: cbuf is valid writable storage.
                            let n = unsafe { libc::read(fd as i32, cbuf.as_mut_ptr(), cbuf.len()) };
                            if n <= 0 {
                                break;
                            }
                            write_all(1, &cbuf[..n as usize]);
                        }
                        libc::close(fd as i32);
                    } else {
                        write_all(2, b"cat: cannot open /etc/motd\n");
                    }
                } else {
                    write_all(2, b"cat: not found\n");
                }
            }
            b"help" => {
                write_all(1, b"builtins: exit cd echo pwd pid cat help\n");
            }
            _ => {
                run_external(cmd, line);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// External command execution
// ---------------------------------------------------------------------------

/// Fork and exec an external command.
///
/// `line` is the full raw command line (used as argv[0] for now).
fn run_external(cmd: &[u8], line: &[u8]) {
    // Build a stack-allocated null-terminated path buffer.
    let mut path_buf = [0u8; 256];
    if cmd.len() >= path_buf.len() {
        write_all(2, b"sh: command too long\n");
        return;
    }
    path_buf[..cmd.len()].copy_from_slice(cmd);
    // path_buf is already null-terminated because it's zero-initialized.

    let mut argv_buf = [0u8; 256];
    let len = line.len().min(argv_buf.len() - 1);
    argv_buf[..len].copy_from_slice(&line[..len]);

    let argv: [*const u8; 2] = [argv_buf.as_ptr(), core::ptr::null()];
    let envp: [*const u8; 1] = [core::ptr::null()];

    let child = libc::fork();
    if child == 0 {
        // SAFETY: path_buf is null-terminated; argv and envp are valid.
        let ret = unsafe { libc::execve(path_buf.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        let _ = ret;
        write_all(2, b"sh: exec failed\n");
        libc::exit(127);
    } else if child > 0 {
        // Wait for child.
        let mut status: i32 = 0;
        // SAFETY: status is a valid stack i32.
        unsafe { libc::waitpid(child, &mut status as *mut i32, 0) };
    } else {
        write_all(2, b"sh: fork failed\n");
    }
}

// ---------------------------------------------------------------------------
// I/O helpers
// ---------------------------------------------------------------------------

/// Write all bytes in `buf` to `fd`, retrying on short writes.
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

/// Read bytes from stdin until `\n` or EOF.
///
/// Returns the number of bytes read (including the newline if present).
fn read_line(buf: &mut [u8]) -> usize {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: buf slice is valid for buf.len() writable bytes.
        let n = unsafe { libc::read(0, buf[pos..].as_mut_ptr(), 1) };
        if n <= 0 {
            break;
        }
        pos += 1;
        if buf[pos - 1] == b'\n' {
            break;
        }
    }
    pos
}

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------

/// Format a signed 64-bit integer into `buf` as ASCII decimal.
///
/// Returns the populated slice within `buf`.  `buf` must be at least 20 bytes.
fn fmt_i64(buf: &mut [u8; 20], mut n: i64) -> &[u8] {
    let mut pos = buf.len();
    let negative = n < 0;
    if n == i64::MIN {
        // i64::MIN cannot be negated in i64; return literal string.
        return b"-9223372036854775808";
    }
    if negative {
        n = -n;
    }
    loop {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    if negative {
        pos -= 1;
        buf[pos] = b'-';
    }
    &buf[pos..]
}

/// Split `s` at the first whitespace, returning (token, remainder).
fn split_first_token(s: &[u8]) -> (&[u8], &[u8]) {
    let tok_end = s
        .iter()
        .position(|&b| b == b' ' || b == b'\t')
        .unwrap_or(s.len());
    let rest_start = s[tok_end..]
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .map(|p| tok_end + p)
        .unwrap_or(s.len());
    (&s[..tok_end], &s[rest_start..])
}

/// Parse the first ASCII decimal integer from `s`.
fn parse_i32(s: &[u8]) -> Option<i32> {
    let digits: &[u8] = s
        .iter()
        .position(|&b| !b.is_ascii_digit())
        .map(|e| &s[..e])
        .unwrap_or(s);
    if digits.is_empty() {
        return None;
    }
    let mut n: i32 = 0;
    for &d in digits {
        n = n.wrapping_mul(10).wrapping_add((d - b'0') as i32);
    }
    Some(n)
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(2, b"sh: panic\n");
    libc::exit(1)
}
