// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/ls` — POSIX.1-2024 `ls` utility.
//!
//! Lists the contents of one directory (defaults to `/`).  Without flags,
//! prints one name per line.  With `-l`, prints long-format lines:
//!
//! ```text
//! [d/-/?]rwxrwxrwx  size  name
//! ```
//!
//! Exit status:
//!   0 — success
//!   1 — open(2) failed (likely ENOENT or ENOTDIR)
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/ls.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

/// `_start` must be a *naked* function — see `cat`/`echo` for the
/// rationale (Rust prologue would shift `[rsp]` away from argc).
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym ls_main,
    );
}

extern "C" fn ls_main(argc: usize, argv: *const *const u8) -> ! {
    // Parse arguments: optional `-l` flag followed by optional path.
    let mut long_fmt = false;
    let mut target: &[u8] = b"/";

    let mut i = 1usize;
    while i < argc {
        // SAFETY: argv has at least argc valid pointers.
        let p = unsafe { argv.add(i).read() };
        if p.is_null() {
            break;
        }
        // SAFETY: p is a NUL-terminated argv string from sys_execve.
        let arg = unsafe { cstr_to_slice(p) };
        if arg == b"-l" {
            long_fmt = true;
        } else {
            target = arg;
        }
        i += 1;
    }

    let exit_code = if list_dir(target, long_fmt) { 0 } else { 1 };
    libc::exit(exit_code);
}

/// Walk a NUL-terminated argv string and return it as a byte slice
/// (excluding the terminator). Returns `b""` if the string is longer
/// than 256 bytes.
///
/// # Safety
///
/// `p` must point to a NUL-terminated byte sequence in user space.
unsafe fn cstr_to_slice<'a>(p: *const u8) -> &'a [u8] {
    let mut len = 0usize;
    while len < 256 {
        // SAFETY: caller-validated pointer; loop bounds prevent OOB.
        if unsafe { *p.add(len) } == 0 {
            break;
        }
        len += 1;
    }
    // SAFETY: we just walked `len` bytes confirming they exist.
    unsafe { core::slice::from_raw_parts(p, len) }
}

/// Open `target` and list its directory entries.
///
/// Without `long_fmt`: prints one name per line.
/// With `long_fmt`: prints `[d/-/?]rwxrwxrwx  size  name` per line.
///
/// Returns `true` on success.
fn list_dir(target: &[u8], long_fmt: bool) -> bool {
    // Stack-allocated NUL-terminated path buffer.
    let mut path_buf = [0u8; 257];
    let len = target.len().min(256);
    path_buf[..len].copy_from_slice(&target[..len]);

    // SAFETY: path_buf is zero-initialised, so it is NUL-terminated.
    let fd = unsafe { libc::open(path_buf.as_ptr(), 0, 0) };
    if fd < 0 {
        write_all(2, b"ls: cannot open: ");
        write_all(2, target);
        write_all(2, b"\n");
        return false;
    }

    let mut buf = [0u8; 4096];
    loop {
        // SAFETY: buf is a valid 4096-byte writable buffer.
        let n = unsafe { libc::getdents64(fd as i32, buf.as_mut_ptr(), buf.len()) };
        if n <= 0 {
            break;
        }
        // Walk linux_dirent64 records.
        //   d_ino:    u64   offset  0
        //   d_off:    u64   offset  8
        //   d_reclen: u16   offset 16
        //   d_type:    u8   offset 18
        //   d_name:  []u8   offset 19, NUL-terminated
        let mut pos = 0usize;
        while pos < n as usize {
            if pos + 19 > n as usize {
                break;
            }
            let reclen = u16::from_ne_bytes([buf[pos + 16], buf[pos + 17]]) as usize;
            if reclen == 0 || pos + reclen > n as usize {
                break;
            }
            let name_start = pos + 19;
            let name_end = buf[name_start..pos + reclen]
                .iter()
                .position(|&b| b == 0)
                .map(|i| name_start + i)
                .unwrap_or(pos + reclen);
            let name = &buf[name_start..name_end];

            if long_fmt {
                // Build the entry's absolute path to call stat(2).
                let mut entry_path = [0u8; 513];
                let base_len = target.len().min(256);
                entry_path[..base_len].copy_from_slice(&target[..base_len]);
                let mut ep_len = base_len;
                if ep_len > 0 && entry_path[ep_len - 1] != b'/' {
                    entry_path[ep_len] = b'/';
                    ep_len += 1;
                }
                let name_copy = name.len().min(512 - ep_len);
                entry_path[ep_len..ep_len + name_copy].copy_from_slice(&name[..name_copy]);
                // entry_path is already NUL-terminated (array init).

                let mut st = libc::Stat {
                    st_dev: 0,
                    st_ino: 0,
                    st_nlink: 0,
                    st_mode: 0,
                    st_uid: 0,
                    st_gid: 0,
                    __pad0: 0,
                    st_rdev: 0,
                    st_size: 0,
                    st_blksize: 0,
                    st_blocks: 0,
                    st_atime: 0,
                    st_atime_ns: 0,
                    st_mtime: 0,
                    st_mtime_ns: 0,
                    st_ctime: 0,
                    st_ctime_ns: 0,
                    __unused: [0; 3],
                };
                // SAFETY: entry_path is NUL-terminated; st is valid for write.
                let _ = unsafe { libc::stat(entry_path.as_ptr(), &mut st) };

                // Format: type_char + permission string + "  " + size + "  " + name + "\n"
                let type_char = if libc::s_isdir(st.st_mode) {
                    b'd'
                } else if libc::s_islnk(st.st_mode) {
                    b'l'
                } else if libc::s_isfifo(st.st_mode) {
                    b'p'
                } else if libc::s_isreg(st.st_mode) {
                    b'-'
                } else {
                    b'?'
                };
                let mut size_buf = [0u8; 20];
                let size_len = u64_to_dec(st.st_size as u64, &mut size_buf);
                write_all(1, &[type_char]);
                write_all(1, &format_perm_bits(st.st_mode));
                write_all(1, b"  ");
                write_all(1, &size_buf[..size_len]);
                write_all(1, b"  ");
                write_all(1, name);
                write_all(1, b"\n");
            } else {
                write_all(1, name);
                write_all(1, b"\n");
            }

            pos += reclen;
        }
    }

    libc::close(fd as i32);
    true
}

/// Format the 9 permission bits of `mode` as `rwxrwxrwx` or `---`.
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

/// Convert a `u64` to its decimal ASCII digits, writing into `buf`.
/// Returns the number of bytes written (always >= 1).
fn u64_to_dec(mut n: u64, buf: &mut [u8; 20]) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut i = 20usize;
    while n > 0 {
        i -= 1;
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    let len = 20 - i;
    buf[..len].copy_from_slice(&tmp[i..]);
    len
}

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
    write_all(2, b"ls: panic\n");
    libc::exit(1)
}
