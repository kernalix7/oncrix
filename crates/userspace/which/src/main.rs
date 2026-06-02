// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/which` — locate a command in the (implicit) PATH.
//!
//! Usage:
//!   which [-a] CMD...
//!
//! Subset semantics:
//!   - `-a`  Print every match. ONCRIX delivers at most one match per CMD
//!     today (each embedded binary lives at a single fixed path), so
//!     the flag is accepted as a no-op for script compatibility.
//!
//! Resolution:
//!   1. If CMD contains a `/`, treat it as a literal path and emit it iff
//!      `stat(2)` succeeds.
//!   2. Otherwise probe `/bin/<CMD>`. ONCRIX has no `PATH` environment
//!      variable yet, so the search list is hardcoded to `/bin`. The kernel
//!      intercepts `/bin/*` paths during `sys_open` via `embedded_lookup`,
//!      which is how `/bin` "exists" without a real ramfs directory.
//!
//! Exit status: 0 if every CMD was located, 1 otherwise. On not-found, a
//! `which: no <CMD> in (/bin)` diagnostic is written to stderr.
//!
//! Up to 16 CMD operands per invocation.
//!
//! Not a POSIX-standard utility (debianutils / GNU which), but ubiquitous
//! in shell scripts.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

/// Maximum number of CMD operands accepted per invocation.
const MAX_CMDS: usize = 16;

/// Maximum byte length of a single argv operand.
const ARG_BUF: usize = 1024;

/// Capacity of the path buffer used to compose `/bin/<CMD>` and the
/// NUL-terminated literal-path copy. 4 KiB matches `PATH_MAX` on most
/// Unix systems.
const PATH_CAP: usize = 4096;

/// Hardcoded search directory. ONCRIX has no `PATH` envvar yet.
const BIN_DIR: &[u8] = b"/bin/";

/// `_start` must be a *naked* function so the Rust prologue does not
/// allocate a local stack frame before we capture argc/argv from the
/// System V AMD64 initial stack layout.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym which_main,
    );
}

extern "C" fn which_main(argc: usize, argv: *const *const u8) -> ! {
    let mut idx = 1usize;

    // Option parsing: only `-a` is recognised; `--` ends option scanning.
    while idx < argc {
        // SAFETY: idx < argc, argv is a valid argv from the loader.
        let arg = unsafe { cstr_at(argv, idx) };
        if arg == b"-a" {
            idx += 1;
            continue;
        }
        if arg == b"--" {
            idx += 1;
            break;
        }
        if arg.len() > 1 && arg[0] == b'-' {
            write_err(b"which: unknown option\n");
            libc::exit(1);
        }
        break;
    }

    if idx >= argc {
        write_err(b"which: missing operand\n");
        libc::exit(1);
    }

    let mut had_error = false;
    let mut processed = 0usize;
    while idx < argc && processed < MAX_CMDS {
        // SAFETY: idx < argc.
        let cmd = unsafe { cstr_at(argv, idx) };
        if !process_one(cmd) {
            had_error = true;
        }
        processed += 1;
        idx += 1;
    }

    if idx < argc {
        write_err(b"which: too many operands\n");
        had_error = true;
    }

    libc::exit(if had_error { 1 } else { 0 })
}

/// Resolve a single CMD operand. Returns `true` on success (path emitted
/// to stdout), `false` if CMD was empty, not found, or stat() failed.
fn process_one(cmd: &[u8]) -> bool {
    if cmd.is_empty() {
        write_err(b"which: empty operand\n");
        return false;
    }

    // Case 1: CMD contains '/' → treat as literal path.
    if cmd.contains(&b'/') {
        let mut buf = [0u8; PATH_CAP];
        if cmd.len() + 1 > PATH_CAP {
            write_err(b"which: path too long\n");
            return false;
        }
        buf[..cmd.len()].copy_from_slice(cmd);
        buf[cmd.len()] = 0;
        if !path_exists(&buf, cmd.len()) {
            report_missing(cmd);
            return false;
        }
        // Emit the literal path as given, plus a newline.
        let mut out = [0u8; PATH_CAP];
        out[..cmd.len()].copy_from_slice(cmd);
        out[cmd.len()] = b'\n';
        return write_all(1, &out[..cmd.len() + 1]);
    }

    // Case 2: bare command → probe /bin/<CMD>.
    let mut buf = [0u8; PATH_CAP];
    let total = BIN_DIR.len() + cmd.len();
    if total + 1 > PATH_CAP {
        write_err(b"which: path too long\n");
        return false;
    }
    buf[..BIN_DIR.len()].copy_from_slice(BIN_DIR);
    buf[BIN_DIR.len()..total].copy_from_slice(cmd);
    buf[total] = 0;

    if !path_exists(&buf, total) {
        report_missing(cmd);
        return false;
    }

    // Emit `/bin/<CMD>\n`.
    let mut out = [0u8; PATH_CAP];
    out[..total].copy_from_slice(&buf[..total]);
    out[total] = b'\n';
    write_all(1, &out[..total + 1])
}

/// Probe `path` (NUL-terminated within `buf`, with `path_len` content bytes
/// before the NUL) via `stat(2)`. Returns `true` on success.
fn path_exists(buf: &[u8], path_len: usize) -> bool {
    debug_assert!(path_len < buf.len() && buf[path_len] == 0);
    // SAFETY: `Stat` is a `#[repr(C)]` POD that the kernel fully overwrites
    // on success; we never read from `st` if `stat` fails, so the zero-init
    // is sound. `buf.as_ptr()` points to a NUL-terminated path.
    let mut st = core::mem::MaybeUninit::<libc::Stat>::zeroed();
    let r = unsafe { libc::stat(buf.as_ptr(), st.as_mut_ptr()) };
    r >= 0
}

/// Emit `which: no <cmd> in (/bin)\n` to stderr.
fn report_missing(cmd: &[u8]) {
    let prefix = b"which: no ";
    let suffix = b" in (/bin)\n";
    let mut out = [0u8; PATH_CAP];
    let mut pos = 0;
    if prefix.len() + cmd.len() + suffix.len() > PATH_CAP {
        // Fallback: best-effort short message.
        let _ = write_all(2, b"which: not found\n");
        return;
    }
    out[pos..pos + prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    out[pos..pos + cmd.len()].copy_from_slice(cmd);
    pos += cmd.len();
    out[pos..pos + suffix.len()].copy_from_slice(suffix);
    pos += suffix.len();
    let _ = write_all(2, &out[..pos]);
}

/// Write the entire buffer to `fd`, retrying on partial writes. Returns
/// `true` if every byte was written, `false` if `write(2)` ever returned
/// an error or zero.
fn write_all(fd: i32, buf: &[u8]) -> bool {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: slice is valid for `buf.len()` bytes.
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

/// Read the C string at `argv[idx]` as a byte slice (NUL-terminated, with
/// the terminator excluded). Returns an empty slice for null pointers.
///
/// # Safety
///
/// Caller guarantees `idx < argc` and `argv` is the valid argv pointer
/// supplied by the program loader.
unsafe fn cstr_at(argv: *const *const u8, idx: usize) -> &'static [u8] {
    unsafe {
        let p = *argv.add(idx);
        if p.is_null() {
            return &[];
        }
        let mut len = 0usize;
        while *p.add(len) != 0 {
            len += 1;
            if len > ARG_BUF {
                break;
            }
        }
        core::slice::from_raw_parts(p, len)
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_err(b"which: panic\n");
    libc::exit(1)
}
