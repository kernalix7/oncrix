// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/cp` — POSIX.1-2024 `cp` utility (subset).
//!
//! Supported forms:
//!   * `cp SRC DST`              — copy a single file.
//!   * `cp SRC1 ... SRCN DSTDIR` — copy multiple sources into a directory.
//!
//! Recognised options (parsed but treated as no-ops):
//!   * `-i` — interactive prompt before overwrite. ONCRIX has no
//!     terminal yes/no path yet, so overwrite is always allowed.
//!   * `-f` — force overwrite. This matches the default behaviour
//!     (open with `O_TRUNC`), so the flag is a no-op.
//!
//! Unsupported flags: `-R`/`-r` (recursive), `-p` (preserve), `-H`/`-L`/`-P`
//! (symlink semantics) — emit an error and continue with remaining files.
//!
//! Exit status is `0` on full success, `1` if any source could not be
//! copied (per-file failures do not abort the run).
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/cp.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// `_start` must be a *naked* function so the Rust prologue does not
/// allocate a local stack frame before we capture argc/argv. The kernel's
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
        main = sym cp_main,
    );
}

// ---------------------------------------------------------------------------
// Limits and buffers
// ---------------------------------------------------------------------------

/// Maximum number of file operands accepted on the command line.
const MAX_FILES: usize = 16;

/// I/O chunk size for the copy loop.
const CHUNK: usize = 4096;

/// Maximum byte length of a destination path assembled in `join_path`.
/// 256 bytes covers ramfs limits with room for the appended basename.
const PATH_MAX: usize = 256;

// ---------------------------------------------------------------------------
// cp logic
// ---------------------------------------------------------------------------

extern "C" fn cp_main(argc: usize, argv: *const *const u8) -> ! {
    let mut files: [*const u8; MAX_FILES] = [core::ptr::null(); MAX_FILES];
    let mut nfiles: usize = 0;
    let mut exit_code: i32 = 0;

    // ---- Argument parsing ------------------------------------------------
    let mut i = 1;
    while i < argc {
        // SAFETY: argv has at least `argc` valid pointers from execve.
        let ptr = unsafe { argv.add(i).read() };
        if ptr.is_null() {
            break;
        }
        // SAFETY: argv strings are null-terminated.
        let first = unsafe { ptr.read() };
        // SAFETY: argv strings are null-terminated; reading byte 1 is safe
        // because if byte 0 is non-zero, byte 1 is at worst the terminator.
        let second = unsafe { ptr.add(1).read() };

        if first == b'-' && second != 0 {
            // Walk option characters: `-if` is two flags, like POSIX.
            let mut j: usize = 1;
            loop {
                // SAFETY: ptr is null-terminated; we stop at the NUL.
                let c = unsafe { ptr.add(j).read() };
                if c == 0 {
                    break;
                }
                match c {
                    b'i' | b'f' => {} // accepted, no behaviour change
                    _ => {
                        write_all(2, b"cp: unsupported option\n");
                        libc::exit(1);
                    }
                }
                j += 1;
            }
        } else {
            if nfiles >= MAX_FILES {
                write_all(2, b"cp: too many file arguments\n");
                libc::exit(1);
            }
            files[nfiles] = ptr;
            nfiles += 1;
        }
        i += 1;
    }

    if nfiles < 2 {
        write_all(2, b"cp: missing operand\n");
        libc::exit(1);
    }

    // ---- Resolve destination --------------------------------------------
    let dst = files[nfiles - 1];
    let nsrc = nfiles - 1;
    let dst_is_dir = is_directory(dst);

    if nsrc > 1 && !dst_is_dir {
        write_all(2, b"cp: target must be a directory\n");
        libc::exit(1);
    }

    // ---- Copy each source -----------------------------------------------
    for &src in files.iter().take(nsrc) {
        if dst_is_dir {
            let mut path = [0u8; PATH_MAX];
            match join_path(&mut path, dst, src) {
                Some(_len) => {
                    if !copy_one(src, path.as_ptr()) {
                        exit_code = 1;
                    }
                }
                None => {
                    write_all(2, b"cp: path too long\n");
                    exit_code = 1;
                }
            }
        } else if !copy_one(src, dst) {
            exit_code = 1;
        }
    }

    libc::exit(exit_code)
}

/// Returns `true` if `path` names an existing directory.
///
/// Any error from `stat` (including "not found") yields `false`, which
/// is the right thing for cp: a non-existent destination on a single-source
/// invocation is treated as a regular-file target to create.
fn is_directory(path: *const u8) -> bool {
    let mut st = stat_zero();
    // SAFETY: `path` is a null-terminated argv pointer; `&mut st` is a
    // valid writable Stat.
    let rc = unsafe { libc::stat(path, &mut st) };
    if rc < 0 {
        return false;
    }
    (st.st_mode & libc::S_IFMT) == libc::S_IFDIR
}

/// Construct a zero-initialised [`libc::Stat`] without invoking `Default`
/// (the libc crate does not derive it for the stat ABI mirror).
fn stat_zero() -> libc::Stat {
    // SAFETY: `Stat` is a `repr(C)` POD with no niches; an all-zero bit
    // pattern is a valid (if meaningless) value, and we always overwrite
    // it via `stat(2)` before reading any field.
    unsafe { core::mem::zeroed() }
}

/// Copy bytes from one path to another. Returns `true` on success.
///
/// Both `src` and `dst` must be null-terminated C strings.
fn copy_one(src: *const u8, dst: *const u8) -> bool {
    // SAFETY: caller guarantees `src` is null-terminated.
    let in_fd = unsafe { libc::open(src, libc::O_RDONLY, 0) };
    if in_fd < 0 {
        write_all(2, b"cp: cannot open source\n");
        return false;
    }

    // SAFETY: caller guarantees `dst` is null-terminated.
    let out_fd = unsafe { libc::open(dst, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, 0o644) };
    if out_fd < 0 {
        libc::close(in_fd as i32);
        write_all(2, b"cp: cannot open destination\n");
        return false;
    }

    let mut ok = true;
    let mut buf = [0u8; CHUNK];
    loop {
        // SAFETY: buf is valid writable storage of CHUNK bytes.
        let n = unsafe { libc::read(in_fd as i32, buf.as_mut_ptr(), CHUNK) };
        if n == 0 {
            break;
        }
        if n < 0 {
            write_all(2, b"cp: read error\n");
            ok = false;
            break;
        }
        if !write_all_checked(out_fd as i32, &buf[..n as usize]) {
            write_all(2, b"cp: write error\n");
            ok = false;
            break;
        }
    }

    libc::close(in_fd as i32);
    libc::close(out_fd as i32);
    ok
}

/// Append `basename(src)` to `dir`, separated by `/`, into `out`.
///
/// Returns the resulting path length on success (the buffer is
/// null-terminated at that index), or `None` if the result would exceed
/// [`PATH_MAX`].
fn join_path(out: &mut [u8; PATH_MAX], dir: *const u8, src: *const u8) -> Option<usize> {
    let dir_len = c_strlen(dir);
    if dir_len >= PATH_MAX {
        return None;
    }
    // SAFETY: dir is null-terminated for `dir_len` bytes.
    for (k, slot) in out.iter_mut().enumerate().take(dir_len) {
        *slot = unsafe { dir.add(k).read() };
    }

    // Strip a single trailing slash to avoid a "//" in the joined path
    // (POSIX cp never produces "dir//file"). Keep "/" itself intact.
    let mut pos = dir_len;
    if pos > 1 && out[pos - 1] == b'/' {
        pos -= 1;
    }

    if pos + 1 >= PATH_MAX {
        return None;
    }
    out[pos] = b'/';
    pos += 1;

    let base = basename(src);
    let base_len = c_strlen(base);
    if pos + base_len + 1 > PATH_MAX {
        return None;
    }
    // SAFETY: base is null-terminated for `base_len` bytes.
    for (k, slot) in out[pos..pos + base_len].iter_mut().enumerate() {
        *slot = unsafe { base.add(k).read() };
    }
    pos += base_len;
    out[pos] = 0;
    Some(pos)
}

/// Return a pointer to the basename component of a null-terminated path.
///
/// For "/a/b/c" returns the pointer to "c"; for "foo" returns the input.
/// A pure pointer arithmetic scan — no allocation.
fn basename(path: *const u8) -> *const u8 {
    let len = c_strlen(path);
    let mut last_slash: Option<usize> = None;
    for k in 0..len {
        // SAFETY: 0 <= k < len, within the null-terminated string.
        if unsafe { path.add(k).read() } == b'/' {
            last_slash = Some(k);
        }
    }
    match last_slash {
        // SAFETY: idx + 1 <= len, still within the null-terminated string.
        Some(idx) => unsafe { path.add(idx + 1) },
        None => path,
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

// ---------------------------------------------------------------------------
// I/O helpers
// ---------------------------------------------------------------------------

/// Write the entire slice or stop on error. Used for diagnostics where we
/// don't care to distinguish partial writes.
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

/// Write the entire slice; return `false` if any write returned `<= 0`.
fn write_all_checked(fd: i32, buf: &[u8]) -> bool {
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

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(2, b"cp: panic\n");
    libc::exit(1)
}
