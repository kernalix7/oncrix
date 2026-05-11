// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/install` — copy files (or create directories) with a
//! chosen permission mode.
//!
//! Usage:
//!   install [-m MODE] SRC DST
//!   install [-m MODE] SRC1 SRC2 ... DSTDIR
//!   install -d [-m MODE] DIR...
//!
//! Default MODE is 0755 octal. Multi-source mode is detected when the
//! last argument refers to an existing directory (via `libc::stat` and
//! the S_IFDIR bit). Per-file failures continue but flip the exit
//! status to 1.
//!
//! Because ONCRIX libc has no chmod syscall, the mode is set at file
//! creation time via `libc::open(... , O_CREAT, mode)`. This matches
//! GNU install when targets do not pre-exist.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const MAX_ARGS: usize = 16;
const CHUNK: usize = 4096;
const PATH_MAX: usize = 256;

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym install_main,
    );
}

extern "C" fn install_main(argc: usize, argv: *const *const u8) -> ! {
    let mut mode: u32 = 0o755;
    let mut dir_mode = false;
    let mut positional: [&[u8]; MAX_ARGS] = [b""; MAX_ARGS];
    let mut n_pos = 0usize;
    let mut idx = 1usize;

    while idx < argc {
        // SAFETY: idx < argc; argv is a kernel-supplied valid array.
        let arg = unsafe { cstr_at(argv, idx) };
        if arg == b"-d" {
            dir_mode = true;
        } else if arg == b"-m" {
            idx += 1;
            if idx >= argc {
                fail(b"install: -m needs MODE\n");
            }
            // SAFETY: idx < argc.
            let v = unsafe { cstr_at(argv, idx) };
            mode = parse_octal(v).unwrap_or_else(|| fail(b"install: invalid MODE\n"));
        } else if arg == b"--" {
            idx += 1;
            while idx < argc && n_pos < MAX_ARGS {
                // SAFETY: idx < argc.
                positional[n_pos] = unsafe { cstr_at(argv, idx) };
                n_pos += 1;
                idx += 1;
            }
            break;
        } else if !arg.is_empty() && arg[0] == b'-' {
            fail(b"install: unknown option\n");
        } else if n_pos < MAX_ARGS {
            positional[n_pos] = arg;
            n_pos += 1;
        } else {
            fail(b"install: too many operands\n");
        }
        idx += 1;
    }

    if dir_mode {
        if n_pos == 0 {
            fail(b"install: -d needs at least one DIR operand\n");
        }
        let mut had_err = false;
        for p in &positional[..n_pos] {
            if !mkdir_one(p, mode) {
                had_err = true;
            }
        }
        libc::exit(if had_err { 1 } else { 0 });
    }

    if n_pos < 2 {
        fail(b"install: missing SRC and/or DST\n");
    }

    let dst = positional[n_pos - 1];
    let srcs = &positional[..n_pos - 1];
    let multi = srcs.len() > 1;

    if multi {
        if !is_directory(dst) {
            fail(b"install: multi-SRC mode requires DSTDIR\n");
        }
        let mut had_err = false;
        for src in srcs {
            let mut buf = [0u8; PATH_MAX];
            if !join_dir_basename(dst, src, &mut buf) {
                write_err(b"install: path too long\n");
                had_err = true;
                continue;
            }
            // SAFETY: buf is NUL-terminated by join_dir_basename.
            let dst_ptr = buf.as_ptr();
            if !copy_one(src, dst_ptr, mode) {
                had_err = true;
            }
        }
        libc::exit(if had_err { 1 } else { 0 });
    }

    let mut src_buf = [0u8; PATH_MAX];
    let mut dst_buf = [0u8; PATH_MAX];
    if !nul_terminate(srcs[0], &mut src_buf) || !nul_terminate(dst, &mut dst_buf) {
        fail(b"install: path too long\n");
    }
    let ok = copy_one(srcs[0], dst_buf.as_ptr(), mode);
    libc::exit(if ok { 0 } else { 1 })
}

/// SAFETY: `dst` must be NUL-terminated.
fn copy_one(src: &[u8], dst: *const u8, mode: u32) -> bool {
    let mut src_buf = [0u8; PATH_MAX];
    if !nul_terminate(src, &mut src_buf) {
        write_err(b"install: source path too long\n");
        return false;
    }
    // SAFETY: src_buf is NUL-terminated.
    let in_fd = unsafe { libc::open(src_buf.as_ptr(), libc::O_RDONLY, 0) };
    if in_fd < 0 {
        write_err(b"install: cannot open source\n");
        return false;
    }
    // SAFETY: caller ensures dst is NUL-terminated.
    let out_fd = unsafe {
        libc::open(
            dst,
            libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            mode,
        )
    };
    if out_fd < 0 {
        let _ = libc::close(in_fd as i32);
        write_err(b"install: cannot open destination\n");
        return false;
    }
    let mut buf = [0u8; CHUNK];
    loop {
        // SAFETY: buf is owned and writable.
        let n = unsafe { libc::read(in_fd as i32, buf.as_mut_ptr(), buf.len()) };
        if n <= 0 {
            break;
        }
        if !write_all(out_fd as i32, &buf[..n as usize]) {
            let _ = libc::close(in_fd as i32);
            let _ = libc::close(out_fd as i32);
            write_err(b"install: write failed\n");
            return false;
        }
    }
    let _ = libc::close(in_fd as i32);
    let _ = libc::close(out_fd as i32);
    true
}

fn mkdir_one(path: &[u8], mode: u32) -> bool {
    let mut buf = [0u8; PATH_MAX];
    if !nul_terminate(path, &mut buf) {
        write_err(b"install: dir path too long\n");
        return false;
    }
    // SAFETY: buf is NUL-terminated.
    let r = unsafe { libc::mkdir(buf.as_ptr(), mode) };
    // -17 = EEXIST — install -d treats that as success per GNU.
    if r < 0 && r != -17 {
        write_err(b"install: mkdir failed\n");
        return false;
    }
    true
}

fn is_directory(path: &[u8]) -> bool {
    let mut buf = [0u8; PATH_MAX];
    if !nul_terminate(path, &mut buf) {
        return false;
    }
    // SAFETY: `Stat` is a `#[repr(C)]` POD; zeroed bytes are fine until
    // the kernel writes into it on success.
    let mut st = core::mem::MaybeUninit::<libc::Stat>::zeroed();
    // SAFETY: buf is NUL-terminated; `st` is owned here.
    let r = unsafe { libc::stat(buf.as_ptr(), st.as_mut_ptr()) };
    if r < 0 {
        return false;
    }
    // SAFETY: stat succeeded, so the struct is fully initialised.
    let mode = unsafe { st.assume_init().st_mode };
    (mode & 0o170000) == 0o040000 // S_IFDIR
}

/// Build `dir_path/basename(src_path)` into `out`, NUL-terminated.
///
/// Returns `false` if the joined path overflows `out`.
fn join_dir_basename(dir_path: &[u8], src_path: &[u8], out: &mut [u8]) -> bool {
    // Trim a single trailing slash from dir_path (keep bare "/").
    let mut dlen = dir_path.len();
    if dlen > 1 && dir_path[dlen - 1] == b'/' {
        dlen -= 1;
    }
    // basename: everything after the last '/' in src_path (or the
    // whole thing if there's no slash).
    let base_start = src_path.iter().rposition(|&b| b == b'/').map_or(0, |p| p + 1);
    let base = &src_path[base_start..];

    let total = dlen + 1 + base.len() + 1;
    if total > out.len() {
        return false;
    }
    let mut pos = 0;
    out[..dlen].copy_from_slice(&dir_path[..dlen]);
    pos += dlen;
    out[pos] = b'/';
    pos += 1;
    out[pos..pos + base.len()].copy_from_slice(base);
    pos += base.len();
    out[pos] = 0;
    true
}

fn nul_terminate(src: &[u8], out: &mut [u8]) -> bool {
    if src.len() + 1 > out.len() {
        return false;
    }
    out[..src.len()].copy_from_slice(src);
    out[src.len()] = 0;
    true
}

fn parse_octal(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return None;
    }
    let digits = if bytes.starts_with(b"0o") || bytes.starts_with(b"0O") {
        &bytes[2..]
    } else {
        bytes
    };
    if digits.is_empty() || digits.len() > 7 {
        return None;
    }
    let mut acc: u32 = 0;
    for &b in digits {
        if !(b'0'..=b'7').contains(&b) {
            return None;
        }
        acc = acc.checked_mul(8)?.checked_add((b - b'0') as u32)?;
    }
    Some(acc)
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

fn write_err(msg: &[u8]) {
    let _ = write_all(2, msg);
}

fn fail(msg: &[u8]) -> ! {
    write_err(msg);
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

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_err(b"install: panic\n");
    libc::exit(1)
}
