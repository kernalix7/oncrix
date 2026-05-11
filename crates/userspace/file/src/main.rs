// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/file` — determine file type via magic-number sniffing.
//!
//! For each FILE operand the utility prints `FILE: TYPE\n` where TYPE is
//! determined first by the kernel's `stat(2)` (directories, character
//! specials, FIFOs, empty regular files) and otherwise by matching the
//! first 256 bytes against a hard-coded magic table (ELF, MZ, gzip, zip,
//! PNG, JPEG, GIF, `#!` script, ASCII text, generic data).
//!
//! Limits:
//!   * up to 16 FILE arguments per invocation
//!   * paths longer than `MAX_PATH` bytes are rejected
//!
//! Per-file errors emit `FILE: cannot open` to stderr and flip exit to 1.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/file.html`

#![no_std]
#![no_main]

use core::mem::MaybeUninit;
use core::panic::PanicInfo;

use oncrix_ulibc as libc;

/// Maximum number of file arguments accepted in one invocation.
const MAX_FILES: usize = 16;
/// Maximum length of a single file path argument.
const MAX_PATH: usize = 256;
/// Number of bytes sniffed from the head of a regular file.
const SNIFF_LEN: usize = 256;

/// `_start` must be a *naked* function so the Rust prologue does not
/// shift `[rsp]` away from `argc` before we capture it.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym file_main,
    );
}

extern "C" fn file_main(argc: usize, argv: *const *const u8) -> ! {
    let mut files: [&[u8]; MAX_FILES] = [b""; MAX_FILES];
    let mut nfiles = 0usize;

    let mut i = 1usize;
    while i < argc && nfiles < MAX_FILES {
        // SAFETY: argv has at least argc valid pointers.
        let p = unsafe { argv.add(i).read() };
        if p.is_null() {
            break;
        }
        // SAFETY: p is a NUL-terminated argv string from sys_execve.
        let arg = unsafe { cstr_to_slice(p) };
        files[nfiles] = arg;
        nfiles += 1;
        i += 1;
    }

    if nfiles == 0 {
        write_all(2, b"file: missing operand\n");
        libc::exit(1);
    }

    let mut exit_code = 0i32;
    for f in files.iter().take(nfiles) {
        if !file_one(f) {
            exit_code = 1;
        }
    }
    libc::exit(exit_code);
}

/// Classify one file and emit `PATH: TYPE\n`. Returns `false` when the
/// path could not be opened or stat'd (caller flips exit code).
fn file_one(path: &[u8]) -> bool {
    if path.is_empty() || path.len() > MAX_PATH {
        write_all(2, b"file: cannot open\n");
        return false;
    }

    // NUL-terminated copy of `path` for syscalls.
    let mut path_buf = [0u8; MAX_PATH + 1];
    path_buf[..path.len()].copy_from_slice(path);

    // SAFETY: zero-initialised — all fields are POD integers/arrays.
    let mut st = unsafe { MaybeUninit::<libc::Stat>::zeroed().assume_init() };
    // SAFETY: path_buf is NUL-terminated; st is valid for write.
    let rc = unsafe { libc::stat(path_buf.as_ptr(), &mut st) };
    if rc < 0 {
        write_all(1, path);
        write_all(1, b": cannot open\n");
        return false;
    }

    // stat-only verdicts come first — directories/specials never reach
    // the magic table even when they happen to have the right bytes.
    let type_bits = st.st_mode & libc::S_IFMT;
    let type_word: Option<&[u8]> = match type_bits {
        libc::S_IFDIR => Some(b"directory"),
        libc::S_IFCHR => Some(b"character special"),
        libc::S_IFBLK => Some(b"block special"),
        libc::S_IFIFO => Some(b"fifo (named pipe)"),
        libc::S_IFSOCK => Some(b"socket"),
        libc::S_IFLNK => Some(b"symbolic link"),
        _ => None,
    };

    if let Some(word) = type_word {
        emit(path, word);
        return true;
    }

    // Regular file (or unknown type): consult size + magic table.
    if st.st_size == 0 {
        emit(path, b"empty");
        return true;
    }

    let mut buf = [0u8; SNIFF_LEN];
    // SAFETY: path_buf is NUL-terminated.
    let fd = unsafe { libc::open(path_buf.as_ptr(), libc::O_RDONLY, 0) };
    if fd < 0 {
        write_all(1, path);
        write_all(1, b": cannot open\n");
        return false;
    }
    let fd = fd as i32;

    // SAFETY: buf is valid for SNIFF_LEN writable bytes.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr(), SNIFF_LEN) };
    libc::close(fd);
    if n < 0 {
        write_all(1, path);
        write_all(1, b": cannot open\n");
        return false;
    }
    let n = n as usize;
    if n == 0 {
        emit(path, b"empty");
        return true;
    }

    emit(path, classify(&buf[..n]));
    true
}

/// Match `data` (up to `SNIFF_LEN` bytes) against the hard-coded magic
/// table; falls through to text/data heuristics.
fn classify(data: &[u8]) -> &'static [u8] {
    // ELF — `\x7fELF` followed by class byte at offset 4 (1=32, 2=64).
    if data.starts_with(b"\x7fELF") {
        if data.len() >= 5 && data[4] == 1 {
            return b"ELF 32-bit LSB executable";
        }
        return b"ELF 64-bit LSB executable";
    }
    // PE/COFF DOS stub.
    if data.starts_with(b"MZ") {
        return b"DOS/Windows executable";
    }
    // gzip — RFC 1952 §2.3.1.
    if data.starts_with(b"\x1f\x8b") {
        return b"gzip compressed data";
    }
    // Zip local file header — `PK\x03\x04`.
    if data.starts_with(b"PK\x03\x04") {
        return b"Zip archive data";
    }
    // PNG — §5 signature.
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return b"PNG image";
    }
    // JPEG SOI + first segment marker.
    if data.starts_with(b"\xff\xd8\xff") {
        return b"JPEG image";
    }
    // GIF87a / GIF89a — §17.
    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return b"GIF image";
    }
    // Shebang script — `#!` followed by `/`.
    if data.starts_with(b"#!/") {
        return b"script, ASCII text executable";
    }

    // Plain-text heuristic: every byte must be a printable ASCII glyph
    // or one of `\t \n \r`. A trailing-newline-bearing buffer is "text";
    // a printable buffer without `\n` is "text, no line terminators".
    let mut has_nl = false;
    let mut all_printable = true;
    for &b in data {
        match b {
            b'\n' => has_nl = true,
            b'\t' | b'\r' => {}
            0x20..=0x7e => {}
            _ => {
                all_printable = false;
                break;
            }
        }
    }
    if all_printable {
        if has_nl {
            b"ASCII text"
        } else {
            b"ASCII text, no line terminators"
        }
    } else {
        b"data"
    }
}

/// Write `PATH: TYPE\n` to stdout in one logical record.
fn emit(path: &[u8], type_word: &[u8]) {
    write_all(1, path);
    write_all(1, b": ");
    write_all(1, type_word);
    write_all(1, b"\n");
}

/// Walk a NUL-terminated argv string and return it as a byte slice
/// (excluding the terminator). Returns `b""` if longer than `MAX_PATH` bytes.
///
/// # Safety
///
/// `p` must point to a NUL-terminated byte sequence in user space.
unsafe fn cstr_to_slice<'a>(p: *const u8) -> &'a [u8] {
    let mut len = 0usize;
    while len < MAX_PATH {
        // SAFETY: caller-validated pointer; loop bounds prevent OOB.
        if unsafe { *p.add(len) } == 0 {
            break;
        }
        len += 1;
    }
    // SAFETY: we just walked `len` bytes confirming they exist.
    unsafe { core::slice::from_raw_parts(p, len) }
}

/// Best-effort `write(2)` loop — drops the rest on EINTR/short-write failure.
fn write_all(fd: i32, buf: &[u8]) {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: buf slice valid for buf.len() bytes.
        let n = unsafe { libc::write(fd, buf[pos..].as_ptr(), buf.len() - pos) };
        if n <= 0 {
            break;
        }
        pos += n as usize;
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(2, b"file: panic\n");
    libc::exit(1)
}
