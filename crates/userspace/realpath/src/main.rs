// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/realpath` — print the canonical absolute pathname.
//!
//! Usage:
//!   realpath [-q] [-e | -m] PATH...
//!
//! Subset semantics (modeled on GNU coreutils `realpath`):
//!   - `-q`  Quiet: suppress per-path error messages on missing/invalid paths.
//!   - `-e`  Existence check: every path component must exist (uses `stat(2)`).
//!   - `-m`  Missing okay: do not check for existence; lexically normalise only.
//!
//! Default behaviour (no `-e`/`-m`) matches `-m`. ONCRIX has no symlink resolver
//! yet (no `readlink(2)`), so canonicalisation is purely lexical:
//!
//!   1. If PATH does not start with `/`, prepend `getcwd()` followed by `/`.
//!   2. Walk slash-separated components:
//!        `.`             - drop.
//!        `..`            - pop the previous accumulated component (no-op at root).
//!        empty (`//`)    - drop.
//!        other           - push.
//!   3. Reassemble as `/c1/c2/...`. The result is always at least `/`.
//!
//! Up to 16 PATH operands and up to 64 path components per result.
//!
//! Exit status: 0 if every PATH was emitted successfully, 1 otherwise.
//!
//! Not a POSIX-standard utility, but ubiquitous in shell scripts.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

/// Maximum number of PATH operands accepted per invocation.
const MAX_PATHS: usize = 16;

/// Capacity of the working path buffer (bytes). 4 KiB matches `PATH_MAX`
/// on most Unix systems and lives comfortably on the user-space stack.
const PATH_CAP: usize = 4096;

/// Maximum number of components a single canonical path may contain.
const MAX_COMPONENTS: usize = 64;

/// Maximum byte length of a single argv path operand.
const ARG_BUF: usize = 1024;

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
        main = sym realpath_main,
    );
}

/// Existence-check mode selected on the command line.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Default / `-m`: do not require existence.
    Lexical,
    /// `-e`: every component must exist.
    MustExist,
}

extern "C" fn realpath_main(argc: usize, argv: *const *const u8) -> ! {
    let mut quiet = false;
    let mut mode = Mode::Lexical;
    let mut idx = 1usize;

    while idx < argc {
        // SAFETY: idx < argc, argv is a valid argv from the loader.
        let arg = unsafe { cstr_at(argv, idx) };
        if arg == b"-q" {
            quiet = true;
            idx += 1;
            continue;
        }
        if arg == b"-e" {
            mode = Mode::MustExist;
            idx += 1;
            continue;
        }
        if arg == b"-m" {
            mode = Mode::Lexical;
            idx += 1;
            continue;
        }
        if arg == b"--" {
            idx += 1;
            break;
        }
        if arg.len() > 1 && arg[0] == b'-' {
            write_err(b"realpath: unknown option\n");
            libc::exit(1);
        }
        break;
    }

    if idx >= argc {
        write_err(b"realpath: missing operand\n");
        libc::exit(1);
    }

    let mut had_error = false;
    let mut processed = 0usize;
    while idx < argc && processed < MAX_PATHS {
        // SAFETY: idx < argc.
        let path = unsafe { cstr_at(argv, idx) };
        if !process_one(path, mode, quiet) {
            had_error = true;
        }
        processed += 1;
        idx += 1;
    }

    if idx < argc {
        if !quiet {
            write_err(b"realpath: too many operands\n");
        }
        had_error = true;
    }

    libc::exit(if had_error { 1 } else { 0 })
}

/// Canonicalise one PATH and emit it to stdout. Returns `true` on success.
fn process_one(path: &[u8], mode: Mode, quiet: bool) -> bool {
    if path.is_empty() {
        if !quiet {
            write_err(b"realpath: empty path\n");
        }
        return false;
    }

    let mut buf = [0u8; PATH_CAP];

    // Step 1: anchor relative paths against getcwd().
    let len = if path[0] != b'/' {
        let mut cwd = [0u8; PATH_CAP];
        // SAFETY: `cwd` is valid for `PATH_CAP` writable bytes.
        let n = unsafe { libc::getcwd(cwd.as_mut_ptr(), PATH_CAP) };
        if n <= 0 {
            if !quiet {
                write_err(b"realpath: getcwd failed\n");
            }
            return false;
        }
        // `n` is bytes written including the trailing NUL.
        let cwd_len = (n as usize).saturating_sub(1);
        if cwd_len + 1 + path.len() >= PATH_CAP {
            if !quiet {
                write_err(b"realpath: path too long\n");
            }
            return false;
        }
        buf[..cwd_len].copy_from_slice(&cwd[..cwd_len]);
        let mut cur = cwd_len;
        buf[cur] = b'/';
        cur += 1;
        buf[cur..cur + path.len()].copy_from_slice(path);
        cur + path.len()
    } else {
        if path.len() >= PATH_CAP {
            if !quiet {
                write_err(b"realpath: path too long\n");
            }
            return false;
        }
        buf[..path.len()].copy_from_slice(path);
        path.len()
    };

    // Step 2: lexical canonicalisation.
    let mut comps: [(usize, usize); MAX_COMPONENTS] = [(0, 0); MAX_COMPONENTS];
    let mut n_comps = 0usize;
    let mut i = 0usize;
    while i < len {
        // Skip slashes.
        while i < len && buf[i] == b'/' {
            i += 1;
        }
        if i >= len {
            break;
        }
        let start = i;
        while i < len && buf[i] != b'/' {
            i += 1;
        }
        let end = i;
        let comp = &buf[start..end];
        if comp == b"." {
            continue;
        }
        if comp == b".." {
            if n_comps > 0 {
                n_comps -= 1;
            }
            continue;
        }
        if n_comps >= MAX_COMPONENTS {
            if !quiet {
                write_err(b"realpath: too many path components\n");
            }
            return false;
        }
        comps[n_comps] = (start, end - start);
        n_comps += 1;
    }

    // Step 3: assemble the canonical path into `out`.
    let mut out = [0u8; PATH_CAP];
    let mut out_len = 0usize;
    if n_comps == 0 {
        out[0] = b'/';
        out_len = 1;
    } else {
        for k in 0..n_comps {
            let (start, clen) = comps[k];
            if out_len + 1 + clen >= PATH_CAP {
                if !quiet {
                    write_err(b"realpath: path too long\n");
                }
                return false;
            }
            out[out_len] = b'/';
            out_len += 1;
            out[out_len..out_len + clen].copy_from_slice(&buf[start..start + clen]);
            out_len += clen;
        }
    }

    // Optional existence check (`-e`). Requires a NUL terminator for `stat`.
    if mode == Mode::MustExist {
        if out_len + 1 >= PATH_CAP {
            if !quiet {
                write_err(b"realpath: path too long\n");
            }
            return false;
        }
        // Append NUL transiently for the syscall (out is over-sized, room exists).
        out[out_len] = 0;
        // SAFETY: `Stat` is a `#[repr(C)]` POD whose bytes the kernel will
        // fully overwrite on success; we never read from `st` if `stat`
        // fails, so the zero-init is sound. `out` is NUL-terminated above.
        let mut st = core::mem::MaybeUninit::<libc::Stat>::zeroed();
        let r = unsafe { libc::stat(out.as_ptr(), st.as_mut_ptr()) };
        if r < 0 {
            if !quiet {
                write_err(b"realpath: path does not exist\n");
            }
            return false;
        }
    }

    // Step 4: emit `<canonical>\n`.
    if out_len + 1 >= PATH_CAP {
        if !quiet {
            write_err(b"realpath: path too long\n");
        }
        return false;
    }
    out[out_len] = b'\n';
    write_all(1, &out[..out_len + 1])
}

/// Write the entire buffer to `fd`, retrying on partial writes.
/// Returns `true` if every byte was written, `false` if `write(2)` ever
/// returned an error or zero.
fn write_all(fd: i32, buf: &[u8]) -> bool {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: `buf` slice is valid for `buf.len()` bytes.
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

/// Read the C string at `argv[idx]` as a byte slice (NUL-terminated, with the
/// terminator excluded). Returns an empty slice for null pointers.
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
    write_err(b"realpath: panic\n");
    libc::exit(1)
}
