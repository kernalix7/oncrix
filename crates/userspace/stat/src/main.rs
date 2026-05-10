// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/stat` — print detailed file metadata.
//!
//! GNU coreutils-style `stat` utility. Not POSIX-standard, but ubiquitous in
//! shell scripts and useful for filesystem debugging.
//!
//! Usage:
//!   stat FILE...                — multi-line summary block per file
//!   stat -c FORMAT FILE...      — terse format string with directives
//!
//! Format directives (subset):
//!   %n  filename                %s  size in bytes
//!   %a  access mode (octal)     %F  file type word
//!   %u  uid                     %g  gid
//!   %i  inode number            %h  hard link count
//!   %X  access time (epoch s)   %Y  modify time (epoch s)
//!   %Z  change time (epoch s)   %%  literal '%'
//!   \n  newline                 \t  tab
//!
//! Per-file errors emit `stat: cannot stat 'PATH'` to stderr and flip exit to 1.
//!
//! Username/groupname are always shown numerically — ONCRIX has no
//! `/etc/passwd` resolver yet.

#![no_std]
#![no_main]

use core::mem::MaybeUninit;
use core::panic::PanicInfo;

use oncrix_ulibc as libc;

/// Maximum number of file arguments accepted in one invocation.
const MAX_FILES: usize = 16;
/// Maximum length of a single file path argument.
const MAX_PATH: usize = 256;

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
        main = sym stat_main,
    );
}

extern "C" fn stat_main(argc: usize, argv: *const *const u8) -> ! {
    // Parse arguments: optional `-c FORMAT` followed by FILE...
    let mut format: Option<&[u8]> = None;
    let mut files: [&[u8]; MAX_FILES] = [b""; MAX_FILES];
    let mut nfiles = 0usize;

    let mut i = 1usize;
    while i < argc {
        // SAFETY: argv has at least argc valid pointers.
        let p = unsafe { argv.add(i).read() };
        if p.is_null() {
            break;
        }
        // SAFETY: p is a NUL-terminated argv string from sys_execve.
        let arg = unsafe { cstr_to_slice(p) };
        if arg == b"-c" && i + 1 < argc {
            i += 1;
            // SAFETY: argv has argc valid pointers; bounds checked above.
            let fp = unsafe { argv.add(i).read() };
            if !fp.is_null() {
                // SAFETY: fp is a NUL-terminated argv string.
                format = Some(unsafe { cstr_to_slice(fp) });
            }
        } else if nfiles < MAX_FILES {
            files[nfiles] = arg;
            nfiles += 1;
        }
        i += 1;
    }

    if nfiles == 0 {
        write_all(2, b"stat: missing operand\n");
        libc::exit(1);
    }

    let mut exit_code = 0i32;
    for f in files.iter().take(nfiles) {
        if !stat_one(f, format) {
            exit_code = 1;
        }
    }
    libc::exit(exit_code);
}

/// Stat one file and print either the multi-line summary or a `-c FORMAT`
/// rendering. Returns `false` on error (path missing, stat syscall failed).
fn stat_one(path: &[u8], format: Option<&[u8]>) -> bool {
    // NUL-terminated copy of `path` for the syscall.
    let mut path_buf = [0u8; MAX_PATH + 1];
    let len = path.len().min(MAX_PATH);
    path_buf[..len].copy_from_slice(&path[..len]);

    // SAFETY: zero-initialised — all fields are POD integers/arrays.
    let mut st = unsafe { MaybeUninit::<libc::Stat>::zeroed().assume_init() };
    // SAFETY: path_buf is NUL-terminated; st is valid for write.
    let rc = unsafe { libc::stat(path_buf.as_ptr(), &mut st) };
    if rc < 0 {
        write_all(2, b"stat: cannot stat '");
        write_all(2, path);
        write_all(2, b"'\n");
        return false;
    }

    match format {
        Some(fmt) => print_format(fmt, path, &st),
        None => print_summary(path, &st),
    }
    true
}

/// Print the multi-line summary block (default mode).
fn print_summary(path: &[u8], st: &libc::Stat) {
    let mut nbuf = [0u8; 24];

    write_all(1, b"  File: ");
    write_all(1, path);
    write_all(1, b"\n");

    // Size / Blocks / IO Block / TYPE
    write_all(1, b"  Size: ");
    let n = u64_to_dec(st.st_size as u64, &mut nbuf);
    write_all(1, &nbuf[..n]);
    write_all(1, b"\tBlocks: ");
    let n = u64_to_dec(st.st_blocks as u64, &mut nbuf);
    write_all(1, &nbuf[..n]);
    write_all(1, b"\tIO Block: ");
    let n = u64_to_dec(st.st_blksize as u64, &mut nbuf);
    write_all(1, &nbuf[..n]);
    write_all(1, b"\t");
    write_all(1, file_type_word(st.st_mode));
    write_all(1, b"\n");

    // Device / Inode / Links
    write_all(1, b"Device: ");
    let n = u64_to_dec(st.st_dev, &mut nbuf);
    write_all(1, &nbuf[..n]);
    write_all(1, b"\tInode: ");
    let n = u64_to_dec(st.st_ino, &mut nbuf);
    write_all(1, &nbuf[..n]);
    write_all(1, b"\tLinks: ");
    let n = u64_to_dec(st.st_nlink, &mut nbuf);
    write_all(1, &nbuf[..n]);
    write_all(1, b"\n");

    // Access: (mode_octal/mode_symbolic) Uid: ( UID/UID) Gid: ( GID/GID)
    write_all(1, b"Access: (");
    let mut obuf = [0u8; 6];
    let on = mode_octal(st.st_mode, &mut obuf);
    write_all(1, &obuf[..on]);
    write_all(1, b"/");
    let type_char = file_type_char(st.st_mode);
    write_all(1, &[type_char]);
    write_all(1, &format_perm_bits(st.st_mode));
    write_all(1, b")  Uid: (");
    let n = u64_to_dec(st.st_uid as u64, &mut nbuf);
    write_all(1, &nbuf[..n]);
    write_all(1, b"/");
    let n = u64_to_dec(st.st_uid as u64, &mut nbuf);
    write_all(1, &nbuf[..n]);
    write_all(1, b")  Gid: (");
    let n = u64_to_dec(st.st_gid as u64, &mut nbuf);
    write_all(1, &nbuf[..n]);
    write_all(1, b"/");
    let n = u64_to_dec(st.st_gid as u64, &mut nbuf);
    write_all(1, &nbuf[..n]);
    write_all(1, b")\n");

    // Times (epoch seconds — no /etc/timezone yet)
    write_all(1, b"Access: ");
    let n = u64_to_dec(st.st_atime, &mut nbuf);
    write_all(1, &nbuf[..n]);
    write_all(1, b"\n");
    write_all(1, b"Modify: ");
    let n = u64_to_dec(st.st_mtime, &mut nbuf);
    write_all(1, &nbuf[..n]);
    write_all(1, b"\n");
    write_all(1, b"Change: ");
    let n = u64_to_dec(st.st_ctime, &mut nbuf);
    write_all(1, &nbuf[..n]);
    write_all(1, b"\n");
}

/// Render `fmt` to stdout, expanding `%X` directives and `\n`/`\t` escapes.
fn print_format(fmt: &[u8], path: &[u8], st: &libc::Stat) {
    let mut nbuf = [0u8; 24];
    let mut i = 0usize;
    while i < fmt.len() {
        let c = fmt[i];
        if c == b'%' && i + 1 < fmt.len() {
            i += 1;
            match fmt[i] {
                b'n' => write_all(1, path),
                b's' => {
                    let n = u64_to_dec(st.st_size as u64, &mut nbuf);
                    write_all(1, &nbuf[..n]);
                }
                b'a' => {
                    let mut obuf = [0u8; 6];
                    let n = mode_octal(st.st_mode, &mut obuf);
                    write_all(1, &obuf[..n]);
                }
                b'u' => {
                    let n = u64_to_dec(st.st_uid as u64, &mut nbuf);
                    write_all(1, &nbuf[..n]);
                }
                b'g' => {
                    let n = u64_to_dec(st.st_gid as u64, &mut nbuf);
                    write_all(1, &nbuf[..n]);
                }
                b'i' => {
                    let n = u64_to_dec(st.st_ino, &mut nbuf);
                    write_all(1, &nbuf[..n]);
                }
                b'h' => {
                    let n = u64_to_dec(st.st_nlink, &mut nbuf);
                    write_all(1, &nbuf[..n]);
                }
                b'F' => write_all(1, file_type_word(st.st_mode)),
                b'X' => {
                    let n = u64_to_dec(st.st_atime, &mut nbuf);
                    write_all(1, &nbuf[..n]);
                }
                b'Y' => {
                    let n = u64_to_dec(st.st_mtime, &mut nbuf);
                    write_all(1, &nbuf[..n]);
                }
                b'Z' => {
                    let n = u64_to_dec(st.st_ctime, &mut nbuf);
                    write_all(1, &nbuf[..n]);
                }
                b'%' => write_all(1, b"%"),
                other => {
                    // Unknown directive — pass through verbatim.
                    write_all(1, b"%");
                    write_all(1, &[other]);
                }
            }
            i += 1;
        } else if c == b'\\' && i + 1 < fmt.len() {
            i += 1;
            match fmt[i] {
                b'n' => write_all(1, b"\n"),
                b't' => write_all(1, b"\t"),
                b'\\' => write_all(1, b"\\"),
                other => write_all(1, &[other]),
            }
            i += 1;
        } else {
            write_all(1, &[c]);
            i += 1;
        }
    }
    write_all(1, b"\n");
}

/// Map the type bits of `st_mode` to a long human-readable word.
fn file_type_word(mode: u32) -> &'static [u8] {
    match mode & libc::S_IFMT {
        libc::S_IFREG => b"regular file",
        libc::S_IFDIR => b"directory",
        libc::S_IFLNK => b"symbolic link",
        libc::S_IFCHR => b"character special file",
        libc::S_IFBLK => b"block special file",
        libc::S_IFIFO => b"fifo",
        libc::S_IFSOCK => b"socket",
        _ => b"unknown",
    }
}

/// Map the type bits of `st_mode` to the leading character used in `ls -l`.
fn file_type_char(mode: u32) -> u8 {
    match mode & libc::S_IFMT {
        libc::S_IFREG => b'-',
        libc::S_IFDIR => b'd',
        libc::S_IFLNK => b'l',
        libc::S_IFCHR => b'c',
        libc::S_IFBLK => b'b',
        libc::S_IFIFO => b'p',
        libc::S_IFSOCK => b's',
        _ => b'?',
    }
}

/// Format the 9 permission bits of `mode` as `rwxrwxrwx` (or `-` for unset).
fn format_perm_bits(mode: u32) -> [u8; 9] {
    let bits = [
        (0o400, b'r'),
        (0o200, b'w'),
        (0o100, b'x'),
        (0o040, b'r'),
        (0o020, b'w'),
        (0o010, b'x'),
        (0o004, b'r'),
        (0o002, b'w'),
        (0o001, b'x'),
    ];
    let mut out = [b'-'; 9];
    for (i, &(mask, ch)) in bits.iter().enumerate() {
        if mode & mask != 0 {
            out[i] = ch;
        }
    }
    out
}

/// Render the low 12 mode bits (suid/sgid/sticky + perms) as a 4-digit octal
/// string (e.g. `0755`). Returns the number of bytes written into `buf`.
fn mode_octal(mode: u32, buf: &mut [u8; 6]) -> usize {
    let m = mode & 0o7777;
    buf[0] = b'0' + ((m >> 9) & 0o7) as u8;
    buf[1] = b'0' + ((m >> 6) & 0o7) as u8;
    buf[2] = b'0' + ((m >> 3) & 0o7) as u8;
    buf[3] = b'0' + (m & 0o7) as u8;
    4
}

/// Convert a `u64` to its decimal ASCII digits, writing into `buf`.
/// Returns the number of bytes written (always >= 1).
fn u64_to_dec(mut n: u64, buf: &mut [u8; 24]) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 24];
    let mut i = 24usize;
    while n > 0 {
        i -= 1;
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    let len = 24 - i;
    buf[..len].copy_from_slice(&tmp[i..]);
    len
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
    write_all(2, b"stat: panic\n");
    libc::exit(1)
}
