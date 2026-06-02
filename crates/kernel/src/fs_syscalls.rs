// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel-side implementations of filesystem syscalls:
//! `mkdir(2)`, `unlink(2)`, and `getdents64(2)`.
//!
//! These call into the global VFS ([`crate::state::with_global_mut`])
//! via the [`KernelVfs`] high-level API.  User pointers are validated
//! with the same bounded-copy pattern as `fork_dispatch`.
//!
//! # POSIX.1-2024 references
//!
//! - `mkdir(3p)` — creates a new directory.
//! - `unlink(3p)` — removes a filesystem name.
//! - `getdents(3p)` / Linux `getdents64(2)` — reads directory entries.

use oncrix_vfs::inode::FileType;

/// Maximum path length accepted from user space.
const MAX_PATH: usize = 256;

/// Size of path copy buffer (MAX_PATH + 1 for null terminator).
const PATH_BUF_LEN: usize = MAX_PATH + 1;

// ── linux_dirent64 field offsets ──────────────────────────────────
//
//  offset  0: d_ino    u64   — inode number
//  offset  8: d_off    u64   — opaque next-entry offset
//  offset 16: d_reclen u16   — total size of this record (8-byte aligned)
//  offset 18: d_type   u8    — DT_DIR / DT_REG / DT_UNKNOWN
//  offset 19: d_name   []u8  — null-terminated entry name + zero-padding

/// Minimum fixed prefix size before the entry name.
const DIRENT64_FIXED: usize = 19;

/// DT_DIR — entry is a directory.
const DT_DIR: u8 = 4;
/// DT_REG — entry is a regular file.
const DT_REG: u8 = 8;
/// DT_UNKNOWN — file type unknown.
const DT_UNKNOWN: u8 = 0;

// ── User-pointer validation helper ────────────────────────────────

/// Copy a null-terminated string from user space into `buf`.
///
/// Returns the byte length (excluding the terminating null) on success,
/// or a negative errno on error.
///
/// # Safety
///
/// `user_ptr` must originate from the SYSCALL dispatch path (ring 3 RSP
/// context).  The caller is responsible for ensuring the string is
/// accessible; we only check that the pointer is non-null and not in
/// kernel canonical space.
unsafe fn copy_user_path(user_ptr: u64, buf: &mut [u8; PATH_BUF_LEN]) -> Result<usize, i64> {
    if user_ptr == 0 || user_ptr >= 0xFFFF_8000_0000_0000 {
        return Err(-14); // EFAULT
    }
    let base = user_ptr as *const u8;
    let mut i = 0usize;
    loop {
        if i >= MAX_PATH {
            return Err(-36); // ENAMETOOLONG
        }
        // SAFETY: pointer validated above; volatile to prevent reordering.
        let byte = unsafe { base.add(i).read_volatile() };
        if byte == 0 {
            break;
        }
        buf[i] = byte;
        i += 1;
    }
    buf[i] = 0;
    Ok(i)
}

/// Resolve a raw user path slice to an absolute path, writing into `abs_buf`.
///
/// If `path` starts with `/`, it is copied directly.  Otherwise the calling
/// thread's cwd is prepended.  Returns the number of bytes in the absolute
/// path (excluding any null terminator), or a negative errno on overflow.
fn resolve_path_abs(path: &[u8], abs_buf: &mut [u8; PATH_BUF_LEN]) -> Result<usize, i64> {
    if path.is_empty() {
        return Err(-2); // ENOENT
    }
    if path[0] == b'/' {
        // Reject rather than silently truncate an over-long absolute path: a
        // truncated path can resolve to a *different* existing file, so
        // unlink/rename/chmod could operate on the wrong target.
        if path.len() > MAX_PATH {
            return Err(-36); // ENAMETOOLONG
        }
        let len = path.len();
        abs_buf[..len].copy_from_slice(&path[..len]);
        abs_buf[len] = 0;
        return Ok(len);
    }
    // Relative: prepend cwd.
    let (cwd_ptr, cwd_len) = crate::current::current_thread()
        .map(|t| {
            let s = t.cwd();
            (s.as_ptr(), s.len())
        })
        .unwrap_or((b"/".as_ptr(), 1));
    // SAFETY: cwd slice is always within the thread's own cwd buffer.
    let cwd = unsafe { core::slice::from_raw_parts(cwd_ptr, cwd_len) };

    let copy_cwd = cwd.len().min(MAX_PATH);
    abs_buf[..copy_cwd].copy_from_slice(&cwd[..copy_cwd]);
    let mut out = copy_cwd;
    if out < MAX_PATH && (out == 0 || abs_buf[out - 1] != b'/') {
        abs_buf[out] = b'/';
        out += 1;
    }
    // Reject when cwd + '/' + path would overflow, instead of clamping
    // copy_path (which made the `out > MAX_PATH` guard below dead code and
    // silently truncated the tail). Compute the full required length first.
    let need = out.saturating_add(path.len());
    if need > MAX_PATH {
        return Err(-36); // ENAMETOOLONG
    }
    abs_buf[out..out + path.len()].copy_from_slice(path);
    out += path.len();
    abs_buf[out] = 0;
    Ok(out)
}

// ── sys_mkdir ─────────────────────────────────────────────────────

/// Kernel handler for `SYS_MKDIR` (number 83).
///
/// POSIX.1-2024 `mkdir(3p)` — creates a new directory.
///
/// # Errors (returned as negative errno)
///
/// - `-2` ENOENT — parent directory does not exist.
/// - `-17` EEXIST — path already exists.
/// - `-12` ENOMEM — ramfs inode table full.
/// - `-22` EINVAL — path is non-absolute or otherwise invalid.
/// - `-14` EFAULT — bad user pointer.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.
pub unsafe fn sys_mkdir(pathname_ptr: u64, _mode: u64) -> i64 {
    static mut PATH_BUF: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    static mut ABS_BUF: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    // SAFETY: single-CPU SYSCALL context; PATH_BUF/ABS_BUF not concurrently accessed.
    #[allow(static_mut_refs)]
    let path_len = unsafe {
        match copy_user_path(pathname_ptr, &mut PATH_BUF) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    // SAFETY: PATH_BUF[..path_len] was written above.
    #[allow(static_mut_refs)]
    let path_bytes: &[u8] = unsafe { &PATH_BUF[..path_len] };

    // SAFETY: single-CPU SYSCALL context; ABS_BUF exclusively owned here.
    #[allow(static_mut_refs)]
    let abs_len = unsafe {
        match resolve_path_abs(path_bytes, &mut ABS_BUF) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    #[allow(static_mut_refs)]
    let abs_path: &[u8] = unsafe { &ABS_BUF[..abs_len] };

    let result = crate::state::with_global_mut(|s| s.vfs.create_dir(abs_path));

    match result {
        Some(Ok(())) => 0,
        Some(Err(oncrix_lib::Error::NotFound)) => -2, // ENOENT
        Some(Err(oncrix_lib::Error::AlreadyExists)) => -17, // EEXIST
        Some(Err(oncrix_lib::Error::OutOfMemory)) => -12, // ENOMEM
        Some(Err(_)) => -22,                          // EINVAL
        None => -5,                                   // EIO — VFS not ready
    }
}

// ── sys_unlink ────────────────────────────────────────────────────

/// Kernel handler for `SYS_UNLINK` (number 87).
///
/// POSIX.1-2024 `unlink(3p)` — removes a file from the directory.
/// Cannot remove a directory (use `rmdir`); returns `-1` EPERM if tried.
///
/// # Errors (returned as negative errno)
///
/// - `-2` ENOENT — file does not exist.
/// - `-1` EPERM — path names a directory.
/// - `-22` EINVAL — path is non-absolute or malformed.
/// - `-14` EFAULT — bad user pointer.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.
pub unsafe fn sys_unlink(pathname_ptr: u64) -> i64 {
    static mut PATH_BUF2: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    static mut ABS_BUF2: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    // SAFETY: single-CPU SYSCALL context; PATH_BUF2/ABS_BUF2 not concurrently accessed.
    #[allow(static_mut_refs)]
    let path_len = unsafe {
        match copy_user_path(pathname_ptr, &mut PATH_BUF2) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    // SAFETY: PATH_BUF2[..path_len] was written above.
    #[allow(static_mut_refs)]
    let path_bytes: &[u8] = unsafe { &PATH_BUF2[..path_len] };

    // SAFETY: single-CPU SYSCALL context; ABS_BUF2 exclusively owned here.
    #[allow(static_mut_refs)]
    let abs_len = unsafe {
        match resolve_path_abs(path_bytes, &mut ABS_BUF2) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    #[allow(static_mut_refs)]
    let abs_path: &[u8] = unsafe { &ABS_BUF2[..abs_len] };

    let result = crate::state::with_global_mut(|s| s.vfs.unlink_path(abs_path));

    match result {
        Some(Ok(())) => 0,
        Some(Err(oncrix_lib::Error::NotFound)) => -2, // ENOENT
        Some(Err(oncrix_lib::Error::InvalidArgument)) => -21, // EISDIR (mapped)
        Some(Err(_)) => -22,                          // EINVAL
        None => -5,                                   // EIO
    }
}

// ── sys_rename ────────────────────────────────────────────────────

/// Kernel handler for `SYS_RENAME` (number 82).
///
/// POSIX.1-2024 `rename(2)` (ramfs subset): moves `oldpath` to `newpath`,
/// overwriting an existing `newpath`. The underlying inode is preserved.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path. Both
/// pointers must reference NUL-terminated paths in user space.
pub unsafe fn sys_rename(oldpath_ptr: u64, newpath_ptr: u64) -> i64 {
    static mut OLD_PATH: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    static mut OLD_ABS: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    static mut NEW_PATH: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    static mut NEW_ABS: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];

    // Copy + absolutise the source path.
    // SAFETY: single-CPU SYSCALL context; OLD_PATH not concurrently accessed.
    #[allow(static_mut_refs)]
    let old_len = unsafe {
        match copy_user_path(oldpath_ptr, &mut OLD_PATH) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    // SAFETY: OLD_PATH[..old_len] written above; OLD_ABS exclusively owned.
    #[allow(static_mut_refs)]
    let old_abs_len = unsafe {
        match resolve_path_abs(&OLD_PATH[..old_len], &mut OLD_ABS) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };

    // Copy + absolutise the destination path.
    // SAFETY: single-CPU SYSCALL context; NEW_PATH not concurrently accessed.
    #[allow(static_mut_refs)]
    let new_len = unsafe {
        match copy_user_path(newpath_ptr, &mut NEW_PATH) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    // SAFETY: NEW_PATH[..new_len] written above; NEW_ABS exclusively owned.
    #[allow(static_mut_refs)]
    let new_abs_len = unsafe {
        match resolve_path_abs(&NEW_PATH[..new_len], &mut NEW_ABS) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };

    // SAFETY: both abs buffers written to the returned lengths above.
    #[allow(static_mut_refs)]
    let result = unsafe {
        let old = &OLD_ABS[..old_abs_len];
        let new = &NEW_ABS[..new_abs_len];
        crate::state::with_global_mut(|s| s.vfs.rename_path(old, new))
    };

    match result {
        Some(Ok(())) => 0,
        Some(Err(oncrix_lib::Error::NotFound)) => -2, // ENOENT
        Some(Err(oncrix_lib::Error::InvalidArgument)) => -22, // EINVAL
        Some(Err(_)) => -22,                          // EINVAL
        None => -5,                                   // EIO
    }
}

// ── sys_link ──────────────────────────────────────────────────────

/// Kernel handler for `SYS_LINK` (number 86).
///
/// POSIX.1-2024 `link(2)` (ramfs subset): creates `newpath` as a hard
/// link to the existing `oldpath`, bumping the inode link count.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path. Both
/// pointers must reference NUL-terminated paths in user space.
pub unsafe fn sys_link(oldpath_ptr: u64, newpath_ptr: u64) -> i64 {
    static mut L_OLD_PATH: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    static mut L_OLD_ABS: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    static mut L_NEW_PATH: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    static mut L_NEW_ABS: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];

    // SAFETY: single-CPU SYSCALL context; L_OLD_PATH not concurrently accessed.
    #[allow(static_mut_refs)]
    let old_len = unsafe {
        match copy_user_path(oldpath_ptr, &mut L_OLD_PATH) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    // SAFETY: L_OLD_PATH[..old_len] written above; L_OLD_ABS exclusively owned.
    #[allow(static_mut_refs)]
    let old_abs_len = unsafe {
        match resolve_path_abs(&L_OLD_PATH[..old_len], &mut L_OLD_ABS) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };

    // SAFETY: single-CPU SYSCALL context; L_NEW_PATH not concurrently accessed.
    #[allow(static_mut_refs)]
    let new_len = unsafe {
        match copy_user_path(newpath_ptr, &mut L_NEW_PATH) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    // SAFETY: L_NEW_PATH[..new_len] written above; L_NEW_ABS exclusively owned.
    #[allow(static_mut_refs)]
    let new_abs_len = unsafe {
        match resolve_path_abs(&L_NEW_PATH[..new_len], &mut L_NEW_ABS) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };

    // SAFETY: both abs buffers written to the returned lengths above.
    #[allow(static_mut_refs)]
    let result = unsafe {
        let old = &L_OLD_ABS[..old_abs_len];
        let new = &L_NEW_ABS[..new_abs_len];
        crate::state::with_global_mut(|s| s.vfs.link_path(old, new))
    };

    match result {
        Some(Ok(())) => 0,
        Some(Err(oncrix_lib::Error::NotFound)) => -2, // ENOENT
        Some(Err(oncrix_lib::Error::AlreadyExists)) => -17, // EEXIST
        Some(Err(oncrix_lib::Error::InvalidArgument)) => -22, // EINVAL (e.g. dir)
        Some(Err(_)) => -22,                          // EINVAL
        None => -5,                                   // EIO
    }
}

// ── sys_chmod ─────────────────────────────────────────────────────

/// Kernel handler for `SYS_CHMOD` (number 90).
///
/// POSIX.1-2024 `chmod(2)` (ramfs subset): updates the inode permission
/// bits of the file at `pathname`. ONCRIX does not enforce permissions
/// yet, so the change is observable via `stat` but has no access effect.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path. `pathname_ptr`
/// must reference a NUL-terminated path in user space.
pub unsafe fn sys_chmod(pathname_ptr: u64, mode: u64) -> i64 {
    static mut PATH_BUF3: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    static mut ABS_BUF3: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    // SAFETY: single-CPU SYSCALL context; PATH_BUF3 not concurrently accessed.
    #[allow(static_mut_refs)]
    let path_len = unsafe {
        match copy_user_path(pathname_ptr, &mut PATH_BUF3) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    // SAFETY: PATH_BUF3[..path_len] written above; ABS_BUF3 exclusively owned.
    #[allow(static_mut_refs)]
    let abs_len = unsafe {
        match resolve_path_abs(&PATH_BUF3[..path_len], &mut ABS_BUF3) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    // SAFETY: ABS_BUF3[..abs_len] written above.
    #[allow(static_mut_refs)]
    let result = unsafe {
        let abs = &ABS_BUF3[..abs_len];
        crate::state::with_global_mut(|s| s.vfs.chmod_path(abs, mode as u32))
    };

    match result {
        Some(Ok(())) => 0,
        Some(Err(oncrix_lib::Error::NotFound)) => -2, // ENOENT
        Some(Err(_)) => -22,                          // EINVAL
        None => -5,                                   // EIO
    }
}

// ── sys_symlink ───────────────────────────────────────────────────

/// Kernel handler for `SYS_SYMLINK` (number 88).
///
/// POSIX.1-2024 `symlink(2)` (ramfs subset): creates `linkpath` as a
/// symbolic link with literal contents `target`. The link is not yet
/// followed by path resolution.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path. Both
/// pointers must reference NUL-terminated strings in user space.
pub unsafe fn sys_symlink(target_ptr: u64, linkpath_ptr: u64) -> i64 {
    static mut SL_TARGET: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    static mut SL_LINK: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    static mut SL_LINK_ABS: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];

    // Copy the target verbatim (stored as-is, not resolved).
    // SAFETY: single-CPU SYSCALL context; SL_TARGET not concurrently accessed.
    #[allow(static_mut_refs)]
    let tgt_len = unsafe {
        match copy_user_path(target_ptr, &mut SL_TARGET) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };

    // Copy + absolutise the link path.
    // SAFETY: single-CPU SYSCALL context; SL_LINK not concurrently accessed.
    #[allow(static_mut_refs)]
    let link_len = unsafe {
        match copy_user_path(linkpath_ptr, &mut SL_LINK) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    // SAFETY: SL_LINK[..link_len] written above; SL_LINK_ABS exclusively owned.
    #[allow(static_mut_refs)]
    let link_abs_len = unsafe {
        match resolve_path_abs(&SL_LINK[..link_len], &mut SL_LINK_ABS) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };

    // SAFETY: SL_TARGET[..tgt_len] and SL_LINK_ABS[..link_abs_len] written above.
    #[allow(static_mut_refs)]
    let result = unsafe {
        let target = &SL_TARGET[..tgt_len];
        let link = &SL_LINK_ABS[..link_abs_len];
        crate::state::with_global_mut(|s| s.vfs.symlink_path(target, link))
    };

    match result {
        Some(Ok(())) => 0,
        Some(Err(oncrix_lib::Error::AlreadyExists)) => -17, // EEXIST
        Some(Err(oncrix_lib::Error::NotFound)) => -2,       // ENOENT
        Some(Err(_)) => -22,                                // EINVAL
        None => -5,                                         // EIO
    }
}

// ── sys_readlink ──────────────────────────────────────────────────

/// Kernel handler for `SYS_READLINK` (number 89).
///
/// POSIX.1-2024 `readlink(2)`: copies up to `bufsiz` bytes of the
/// symlink target at `pathname` into the user buffer. Does NOT
/// NUL-terminate (per POSIX). Returns the byte count, or a negative
/// errno.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path. `pathname_ptr`
/// must be a NUL-terminated path; `buf_ptr..buf_ptr+bufsiz` must be
/// writable user memory.
pub unsafe fn sys_readlink(pathname_ptr: u64, buf_ptr: u64, bufsiz: u64) -> i64 {
    if buf_ptr == 0 || buf_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    static mut RL_PATH: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    static mut RL_ABS: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    static mut RL_OUT: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];

    // SAFETY: single-CPU SYSCALL context; RL_PATH not concurrently accessed.
    #[allow(static_mut_refs)]
    let path_len = unsafe {
        match copy_user_path(pathname_ptr, &mut RL_PATH) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    // SAFETY: RL_PATH[..path_len] written above; RL_ABS exclusively owned.
    #[allow(static_mut_refs)]
    let abs_len = unsafe {
        match resolve_path_abs(&RL_PATH[..path_len], &mut RL_ABS) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };

    // Read the link target into a kernel staging buffer.
    let cap = (bufsiz as usize).min(PATH_BUF_LEN);
    // SAFETY: RL_ABS[..abs_len] written above; RL_OUT exclusively owned.
    #[allow(static_mut_refs)]
    let result = unsafe {
        let abs = &RL_ABS[..abs_len];
        crate::state::with_global_mut(|s| s.vfs.readlink_path(abs, &mut RL_OUT[..cap]))
    };

    let n = match result {
        Some(Ok(n)) => n,
        Some(Err(oncrix_lib::Error::NotFound)) => return -2, // ENOENT
        Some(Err(oncrix_lib::Error::InvalidArgument)) => return -22, // EINVAL (not a symlink)
        Some(Err(_)) => return -22,
        None => return -5,
    };

    // Copy out to user (no NUL terminator, per POSIX).
    // SAFETY: buf_ptr validated non-null user address; n <= cap <= bufsiz.
    unsafe {
        let dst = buf_ptr as *mut u8;
        #[allow(static_mut_refs)]
        for (i, &b) in RL_OUT[..n].iter().enumerate() {
            dst.add(i).write_volatile(b);
        }
    }
    n as i64
}

// ── sys_mknod ─────────────────────────────────────────────────────

/// Kernel handler for `SYS_MKNOD` (number 133).
///
/// POSIX.1-2024 `mkfifo(2)` subset: creates a named pipe (FIFO) at
/// `pathname`. Only the FIFO node type is supported (the `mode`'s
/// file-type bits are ignored; any invocation creates a FIFO). The FIFO
/// is not yet connected to a pipe ring.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path. `pathname_ptr`
/// must reference a NUL-terminated path in user space.
pub unsafe fn sys_mknod(pathname_ptr: u64, mode: u64) -> i64 {
    static mut MN_PATH: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    static mut MN_ABS: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    // SAFETY: single-CPU SYSCALL context; MN_PATH not concurrently accessed.
    #[allow(static_mut_refs)]
    let path_len = unsafe {
        match copy_user_path(pathname_ptr, &mut MN_PATH) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    // SAFETY: MN_PATH[..path_len] written above; MN_ABS exclusively owned.
    #[allow(static_mut_refs)]
    let abs_len = unsafe {
        match resolve_path_abs(&MN_PATH[..path_len], &mut MN_ABS) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    // SAFETY: MN_ABS[..abs_len] written above.
    #[allow(static_mut_refs)]
    let result = unsafe {
        let abs = &MN_ABS[..abs_len];
        crate::state::with_global_mut(|s| s.vfs.mkfifo_path(abs, mode as u32 & 0o7777))
    };

    match result {
        Some(Ok(())) => 0,
        Some(Err(oncrix_lib::Error::AlreadyExists)) => -17, // EEXIST
        Some(Err(oncrix_lib::Error::NotFound)) => -2,       // ENOENT
        Some(Err(_)) => -22,                                // EINVAL
        None => -5,
    }
}

// ── sys_rmdir ─────────────────────────────────────────────────────

/// Kernel handler for `SYS_RMDIR` (number 84).
///
/// POSIX.1-2024 `rmdir(2)`: removes the empty directory at `pathname`.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path. `pathname_ptr`
/// must reference a NUL-terminated path in user space.
pub unsafe fn sys_rmdir(pathname_ptr: u64) -> i64 {
    static mut RD_PATH: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    static mut RD_ABS: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    // SAFETY: single-CPU SYSCALL context; RD_PATH not concurrently accessed.
    #[allow(static_mut_refs)]
    let path_len = unsafe {
        match copy_user_path(pathname_ptr, &mut RD_PATH) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    // SAFETY: RD_PATH[..path_len] written above; RD_ABS exclusively owned.
    #[allow(static_mut_refs)]
    let abs_len = unsafe {
        match resolve_path_abs(&RD_PATH[..path_len], &mut RD_ABS) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    // SAFETY: RD_ABS[..abs_len] written above.
    #[allow(static_mut_refs)]
    let result = unsafe {
        let abs = &RD_ABS[..abs_len];
        crate::state::with_global_mut(|s| s.vfs.rmdir_path(abs))
    };

    match result {
        Some(Ok(())) => 0,
        Some(Err(oncrix_lib::Error::NotFound)) => -2, // ENOENT
        Some(Err(oncrix_lib::Error::InvalidArgument)) => -39, // ENOTEMPTY / ENOTDIR
        Some(Err(_)) => -22,
        None => -5,
    }
}

// ── sys_truncate ──────────────────────────────────────────────────

/// Kernel handler for `SYS_TRUNCATE` (number 76).
///
/// POSIX.1-2024 `truncate(2)` (ramfs subset): sets the length of the
/// file at `pathname`. Shrinking discards the tail; growing zero-fills.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path. `pathname_ptr`
/// must reference a NUL-terminated path in user space.
pub unsafe fn sys_truncate(pathname_ptr: u64, length: u64) -> i64 {
    static mut TR_PATH: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    static mut TR_ABS: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    // SAFETY: single-CPU SYSCALL context; TR_PATH not concurrently accessed.
    #[allow(static_mut_refs)]
    let path_len = unsafe {
        match copy_user_path(pathname_ptr, &mut TR_PATH) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    // SAFETY: TR_PATH[..path_len] written above; TR_ABS exclusively owned.
    #[allow(static_mut_refs)]
    let abs_len = unsafe {
        match resolve_path_abs(&TR_PATH[..path_len], &mut TR_ABS) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    // SAFETY: TR_ABS[..abs_len] written above.
    #[allow(static_mut_refs)]
    let result = unsafe {
        let abs = &TR_ABS[..abs_len];
        crate::state::with_global_mut(|s| s.vfs.truncate_path(abs, length))
    };

    match result {
        Some(Ok(())) => 0,
        Some(Err(oncrix_lib::Error::NotFound)) => -2, // ENOENT
        Some(Err(oncrix_lib::Error::InvalidArgument)) => -22, // EINVAL (not a regular file)
        Some(Err(oncrix_lib::Error::OutOfMemory)) => -27, // EFBIG (exceeds ramfs file cap)
        Some(Err(_)) => -22,
        None => -5, // EIO
    }
}

// ── sys_ftruncate ─────────────────────────────────────────────────

/// Kernel handler for `SYS_FTRUNCATE` (Linux number 77).
///
/// POSIX `ftruncate(fd, length)`: resize the regular file referenced by
/// `fd` to exactly `length` bytes. Backed by the ramfs `truncate` op via
/// [`crate::state`]; the fd backend must be `RamfsFile`. Other backends
/// (pipes, sockets, eventfds, etc.) yield `-EINVAL`.
///
/// Returns 0 / `-EBADF` / `-EINVAL` / `-ENOENT` / `-EFBIG` / `-EIO`.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU).
pub unsafe fn sys_ftruncate(fd: u64, length: u64) -> i64 {
    // SAFETY: single-CPU SYSCALL context.
    let ino = unsafe {
        match crate::fd_table::fd_get(fd as usize) {
            Some(h) => match h.backend {
                oncrix_process::fd_table::FileBackend::RamfsFile { ino } => ino,
                _ => return -22, // EINVAL — backend has no truncate op
            },
            None => return -9, // EBADF
        }
    };

    let result = crate::state::with_global_mut(|s| s.vfs.truncate_ino(ino, length));
    match result {
        Some(Ok(())) => 0,
        Some(Err(oncrix_lib::Error::NotFound)) => -2, // ENOENT
        Some(Err(oncrix_lib::Error::InvalidArgument)) => -22, // EINVAL — not a regular file
        Some(Err(oncrix_lib::Error::OutOfMemory)) => -27, // EFBIG
        Some(Err(_)) => -22,
        None => -5, // EIO
    }
}

// ── sys_fchmod / sys_fchown ───────────────────────────────────────

/// Resolve `fd` to its ramfs inode number, or a negative errno.
///
/// Shared by [`sys_fchmod`] and [`sys_fchown`]. `-EBADF` if `fd` is not
/// open; `-EINVAL` if the backend is not a `RamfsFile` (the console, pipes,
/// eventfds, etc. have no mutable inode mode/owner).
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU).
unsafe fn fd_ramfs_ino(fd: i32) -> core::result::Result<oncrix_vfs::inode::InodeNumber, i64> {
    // SAFETY: single-CPU SYSCALL context.
    let handle = unsafe {
        match crate::fd_table::fd_get(fd as usize) {
            Some(h) => h,
            None => return Err(-9), // EBADF
        }
    };
    match handle.backend {
        crate::fd_table::FileBackend::RamfsFile { ino } => Ok(ino),
        _ => Err(-22), // EINVAL — backend has no inode mode/owner
    }
}

/// Kernel handler for `SYS_FCHMOD` (number 91).
///
/// POSIX `fchmod(fd, mode)`: change the permission bits of the regular file
/// referenced by `fd`. Returns 0 / `-EBADF` / `-EINVAL` / `-ENOENT` /
/// `-EIO`.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU).
pub unsafe fn sys_fchmod(fd: i32, mode: u32) -> i64 {
    // SAFETY: single-CPU SYSCALL context.
    let ino = match unsafe { fd_ramfs_ino(fd) } {
        Ok(i) => i,
        Err(e) => return e,
    };
    let result = crate::state::with_global_mut(|s| s.vfs.chmod_ino(ino, mode));
    match result {
        Some(Ok(())) => 0,
        Some(Err(oncrix_lib::Error::NotFound)) => -2, // ENOENT
        Some(Err(_)) => -22,                          // EINVAL
        None => -5,                                   // EIO
    }
}

/// Kernel handler for `SYS_FCHOWN` (number 93).
///
/// POSIX `fchown(fd, uid, gid)`: change the owner/group of the regular file
/// referenced by `fd`. A `uid`/`gid` of `u32::MAX` leaves that id unchanged.
/// Returns 0 / `-EBADF` / `-EINVAL` / `-ENOENT` / `-EIO`.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU).
pub unsafe fn sys_fchown(fd: i32, uid: u32, gid: u32) -> i64 {
    // SAFETY: single-CPU SYSCALL context.
    let ino = match unsafe { fd_ramfs_ino(fd) } {
        Ok(i) => i,
        Err(e) => return e,
    };
    let result = crate::state::with_global_mut(|s| s.vfs.chown_ino(ino, uid, gid));
    match result {
        Some(Ok(())) => 0,
        Some(Err(oncrix_lib::Error::NotFound)) => -2, // ENOENT
        Some(Err(_)) => -22,                          // EINVAL
        None => -5,                                   // EIO
    }
}

// ── sys_chown ─────────────────────────────────────────────────────

/// Kernel handler for `SYS_CHOWN` (number 92).
///
/// POSIX.1-2024 `chown(2)` (ramfs subset): sets the owner/group of the
/// file at `pathname`. A `uid`/`gid` of `u32::MAX` (`(uid_t)-1`) leaves
/// that id unchanged. Metadata-only; ownership is not enforced.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path. `pathname_ptr`
/// must reference a NUL-terminated path in user space.
pub unsafe fn sys_chown(pathname_ptr: u64, uid: u64, gid: u64) -> i64 {
    static mut PATH_BUF4: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    static mut ABS_BUF4: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    // SAFETY: single-CPU SYSCALL context; PATH_BUF4 not concurrently accessed.
    #[allow(static_mut_refs)]
    let path_len = unsafe {
        match copy_user_path(pathname_ptr, &mut PATH_BUF4) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    // SAFETY: PATH_BUF4[..path_len] written above; ABS_BUF4 exclusively owned.
    #[allow(static_mut_refs)]
    let abs_len = unsafe {
        match resolve_path_abs(&PATH_BUF4[..path_len], &mut ABS_BUF4) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    // SAFETY: ABS_BUF4[..abs_len] written above.
    #[allow(static_mut_refs)]
    let result = unsafe {
        let abs = &ABS_BUF4[..abs_len];
        crate::state::with_global_mut(|s| s.vfs.chown_path(abs, uid as u32, gid as u32))
    };

    match result {
        Some(Ok(())) => 0,
        Some(Err(oncrix_lib::Error::NotFound)) => -2, // ENOENT
        Some(Err(_)) => -22,                          // EINVAL
        None => -5,                                   // EIO
    }
}

// ── sys_getdents64 ────────────────────────────────────────────────

/// Kernel handler for `SYS_GETDENTS64` (number 217).
///
/// Fills `buf_ptr..buf_ptr+buf_len` with `linux_dirent64` records for the
/// directory open on `fd`.  The fd offset is advanced so that repeated
/// calls drain the directory.  Returns 0 when the directory is exhausted.
///
/// Because the ramfs holds all entries in memory, this implementation
/// collects them in a single call and uses the fd's byte offset as an
/// index into the serialised record stream.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.  `buf_ptr`
/// must point to at least `buf_len` writable bytes in user space.
pub unsafe fn sys_getdents64(fd: usize, buf_ptr: u64, buf_len: u64) -> i64 {
    // Validate user buffer.
    if buf_ptr == 0 || buf_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    let buf_len = buf_len as usize;
    if buf_len < DIRENT64_FIXED + 1 {
        return -22; // EINVAL — buffer too small for even one entry
    }

    // Resolve the directory inode from the fd table.
    // SAFETY: single-CPU SYSCALL context.
    let maybe_handle = unsafe { crate::fd_table::fd_get(fd) };
    let handle = match maybe_handle {
        Some(h) => h,
        None => return -9, // EBADF
    };

    let dir_ino = match handle.backend {
        crate::fd_table::FileBackend::RamfsFile { ino } => ino,
        _ => return -9, // EBADF — not a file/directory handle
    };

    let dir_offset = handle.offset as usize;

    // Verify the inode is a directory and collect its children.
    // We use `with_global` (immutable) since listing does not mutate.
    let entries_result = crate::state::with_global(|s| {
        let inode = s.vfs.ramfs.inode_by_number(dir_ino)?;
        if inode.file_type != FileType::Directory {
            return None; // not a directory
        }
        let children = s.vfs.ramfs.list_children(&inode);
        Some(children)
    });

    let children = match entries_result {
        Some(Some(v)) => v,
        _ => return -20, // ENOTDIR
    };

    // Serialise entries into a temporary stack buffer, then copy to user.
    // We accumulate bytes to know the total stream size.
    let user_buf = buf_ptr as *mut u8;
    let mut written = 0usize; // bytes written to user buf this call
    let mut stream_off = 0usize; // byte offset within the full record stream

    for child in &children {
        let name_bytes = child.name.as_bytes();
        let name_len = name_bytes.len().min(255);
        let reclen = align8(DIRENT64_FIXED + name_len + 1); // +1 for null

        if stream_off < dir_offset {
            // This record was already returned in a previous call.
            stream_off += reclen;
            continue;
        }

        if written + reclen > buf_len {
            // User buffer full — stop here; next call continues from dir_offset.
            break;
        }

        let ino_num: u64 = child.ino.0;
        let d_type: u8 = match child.kind {
            FileType::Directory => DT_DIR,
            FileType::Regular => DT_REG,
            _ => DT_UNKNOWN,
        };
        let next_off = (stream_off + reclen) as u64;

        // Write the linux_dirent64 record into user space.
        // SAFETY: validated buf_ptr; written + reclen <= buf_len.
        unsafe {
            let p = user_buf.add(written);
            // d_ino  (8 bytes)
            p.copy_from_nonoverlapping(ino_num.to_ne_bytes().as_ptr(), 8);
            // d_off  (8 bytes) — opaque offset cookie
            p.add(8)
                .copy_from_nonoverlapping(next_off.to_ne_bytes().as_ptr(), 8);
            // d_reclen (2 bytes)
            p.add(16)
                .copy_from_nonoverlapping((reclen as u16).to_ne_bytes().as_ptr(), 2);
            // d_type (1 byte)
            p.add(18).write(d_type);
            // d_name: copy name, then zero-pad to end of record
            let name_dst = p.add(19);
            name_dst.copy_from_nonoverlapping(name_bytes.as_ptr(), name_len);
            // Zero-pad (includes null terminator and alignment padding).
            name_dst
                .add(name_len)
                .write_bytes(0, reclen - DIRENT64_FIXED - name_len);
        }

        written += reclen;
        stream_off += reclen;
    }

    if written == 0 {
        // All records already consumed — end of directory.
        // Reset offset so the caller can re-read from the start.
        // SAFETY: single-CPU SYSCALL context.
        if let Some(h) = unsafe { crate::fd_table::fd_get_mut(fd) } {
            h.offset = 0;
        }
        return 0;
    }

    // Advance the fd offset by the bytes we produced.
    // SAFETY: single-CPU SYSCALL context.
    if let Some(h) = unsafe { crate::fd_table::fd_get_mut(fd) } {
        h.offset = (dir_offset + written) as u64;
    }

    written as i64
}

/// Round `n` up to the nearest multiple of 8 (record alignment).
#[inline]
const fn align8(n: usize) -> usize {
    (n + 7) & !7
}

// ── Linux-compatible struct stat layout ───────────────────────────
//
// This matches the x86-64 Linux `struct stat` layout exactly so that
// userspace libc can cast the raw bytes to its own mirror struct.
//
// Offsets (all little-endian):
//   0:  st_dev      u64   — device ID (stub: 1)
//   8:  st_ino      u64   — inode number
//   16: st_nlink    u64   — hard link count
//   24: st_mode     u32   — file type + permission bits
//   28: st_uid      u32   — owner UID
//   32: st_gid      u32   — owner GID
//   36: __pad0      u32   — padding
//   40: st_rdev     u64   — device ID if special file (0)
//   48: st_size     i64   — file size in bytes
//   56: st_blksize  i64   — preferred I/O block size (4096)
//   64: st_blocks   i64   — 512-byte blocks allocated
//   72: st_atime    u64   — last access time (0)
//   80: st_atime_ns u64   — nanoseconds
//   88: st_mtime    u64   — last modification time (0)
//   96: st_mtime_ns u64   — nanoseconds
//  104: st_ctime    u64   — last status change time (0)
//  112: st_ctime_ns u64   — nanoseconds
//  120: __unused    [3]u64
// Total: 144 bytes

const STAT_SIZE: usize = 144;

/// Fill a 144-byte Linux `struct stat` from an inode's metadata.
///
/// File type bits follow the POSIX definition:
///   S_IFDIR = 0o040000, S_IFREG = 0o100000.
///
/// Permissions come from the inode's `mode` field (lower 12 bits).
///
/// # Safety
///
/// `buf` must point to at least 144 writable bytes in user space.
/// The caller must have validated the pointer.
unsafe fn fill_stat_buf(buf: *mut u8, inode: &oncrix_vfs::inode::Inode) {
    let mut raw = [0u8; STAT_SIZE];

    // st_dev = 1 (single virtual device)
    raw[0..8].copy_from_slice(&1u64.to_ne_bytes());
    // st_ino
    raw[8..16].copy_from_slice(&inode.ino.0.to_ne_bytes());
    // st_nlink
    raw[16..24].copy_from_slice(&(inode.nlink as u64).to_ne_bytes());

    // st_mode: type bits + permission bits
    let type_bits: u32 = match inode.file_type {
        oncrix_vfs::inode::FileType::Directory => 0o040000,
        oncrix_vfs::inode::FileType::Regular => 0o100000,
        oncrix_vfs::inode::FileType::Symlink => 0o120000,
        oncrix_vfs::inode::FileType::CharDevice => 0o020000,
        oncrix_vfs::inode::FileType::BlockDevice => 0o060000,
        oncrix_vfs::inode::FileType::Fifo => 0o010000,
        oncrix_vfs::inode::FileType::Socket => 0o140000,
    };
    let mode: u32 = type_bits | (inode.mode.0 as u32 & 0o7777);
    raw[24..28].copy_from_slice(&mode.to_ne_bytes());
    // st_uid, st_gid
    raw[28..32].copy_from_slice(&inode.uid.to_ne_bytes());
    raw[32..36].copy_from_slice(&inode.gid.to_ne_bytes());
    // st_size
    raw[48..56].copy_from_slice(&(inode.size as i64).to_ne_bytes());
    // st_blksize = 4096
    raw[56..64].copy_from_slice(&4096i64.to_ne_bytes());
    // st_blocks = (size + 511) / 512
    let blocks = inode.size.div_ceil(512) as i64;
    raw[64..72].copy_from_slice(&blocks.to_ne_bytes());

    // SAFETY: caller guarantees `buf` is valid for STAT_SIZE writable bytes.
    unsafe { buf.copy_from_nonoverlapping(raw.as_ptr(), STAT_SIZE) };
}

// ── sys_stat ──────────────────────────────────────────────────────

/// Kernel handler for `SYS_STAT` (number 4).
///
/// POSIX.1-2024 `stat(3p)` — obtain file status by path.
///
/// # Errors (returned as negative errno)
///
/// - `-2` ENOENT — path does not exist.
/// - `-14` EFAULT — bad user pointer.
/// - `-36` ENAMETOOLONG — path too long.
/// - `-22` EINVAL — invalid path.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.
pub unsafe fn sys_stat(path_ptr: u64, statbuf_ptr: u64) -> i64 {
    // Validate statbuf pointer.
    if statbuf_ptr == 0 || statbuf_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }

    static mut STAT_PATH_BUF: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    static mut STAT_ABS_BUF: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];

    // SAFETY: single-CPU SYSCALL context; buffers exclusively owned here.
    #[allow(static_mut_refs)]
    let path_len = unsafe {
        match copy_user_path(path_ptr, &mut STAT_PATH_BUF) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };

    #[allow(static_mut_refs)]
    let path_bytes: &[u8] = unsafe { &STAT_PATH_BUF[..path_len] };

    #[allow(static_mut_refs)]
    let abs_len = unsafe {
        match resolve_path_abs(path_bytes, &mut STAT_ABS_BUF) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };

    #[allow(static_mut_refs)]
    let abs_path: &[u8] = unsafe { &STAT_ABS_BUF[..abs_len] };

    let result = crate::state::with_global(|s| s.vfs.lookup_path(abs_path));

    match result {
        Some(Ok(inode)) => {
            // SAFETY: statbuf_ptr validated above; fill_stat_buf writes exactly STAT_SIZE bytes.
            unsafe { fill_stat_buf(statbuf_ptr as *mut u8, &inode) };
            0
        }
        Some(Err(oncrix_lib::Error::NotFound)) => -2, // ENOENT
        Some(Err(_)) => -22,                          // EINVAL
        None => -5,                                   // EIO
    }
}

// ── sys_lstat ─────────────────────────────────────────────────────

/// Kernel handler for `SYS_LSTAT` (number 6).
///
/// POSIX.1-2024 `lstat(2)`: like `stat`, but does NOT follow a terminal
/// symbolic link — reports the link itself (S_IFLNK) rather than its
/// target.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path. `statbuf_ptr`
/// must point to >= 144 writable user bytes.
pub unsafe fn sys_lstat(path_ptr: u64, statbuf_ptr: u64) -> i64 {
    if statbuf_ptr == 0 || statbuf_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    static mut LSTAT_PATH: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    static mut LSTAT_ABS: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    // SAFETY: single-CPU SYSCALL context; buffers exclusively owned here.
    #[allow(static_mut_refs)]
    let path_len = unsafe {
        match copy_user_path(path_ptr, &mut LSTAT_PATH) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    // SAFETY: LSTAT_PATH[..path_len] written above; LSTAT_ABS exclusively owned.
    #[allow(static_mut_refs)]
    let abs_len = unsafe {
        match resolve_path_abs(&LSTAT_PATH[..path_len], &mut LSTAT_ABS) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    // SAFETY: LSTAT_ABS[..abs_len] written above.
    #[allow(static_mut_refs)]
    let result = unsafe {
        let abs = &LSTAT_ABS[..abs_len];
        crate::state::with_global(|s| s.vfs.lookup_path_nofollow(abs))
    };

    match result {
        Some(Ok(inode)) => {
            // SAFETY: statbuf_ptr validated; fill_stat_buf writes STAT_SIZE bytes.
            unsafe { fill_stat_buf(statbuf_ptr as *mut u8, &inode) };
            0
        }
        Some(Err(oncrix_lib::Error::NotFound)) => -2, // ENOENT
        Some(Err(_)) => -22,                          // EINVAL
        None => -5,                                   // EIO
    }
}

// ── sys_fstat ─────────────────────────────────────────────────────

/// Kernel handler for `SYS_FSTAT` (number 5).
///
/// POSIX.1-2024 `fstat(3p)` — obtain file status by file descriptor.
///
/// # Errors (returned as negative errno)
///
/// - `-9` EBADF — bad file descriptor.
/// - `-14` EFAULT — bad statbuf pointer.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.
pub unsafe fn sys_fstat(fd: i32, statbuf_ptr: u64) -> i64 {
    if statbuf_ptr == 0 || statbuf_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }

    // SAFETY: single-CPU SYSCALL context.
    let handle = unsafe { crate::fd_table::fd_get(fd as usize) };
    let handle = match handle {
        Some(h) => h,
        None => return -9, // EBADF
    };

    let ino = match handle.backend {
        crate::fd_table::FileBackend::RamfsFile { ino } => ino,
        // Console and device files have no inode; return a synthetic stat.
        crate::fd_table::FileBackend::Console | crate::fd_table::FileBackend::DevFile { .. } => {
            // Return a zeroed-out stat (mode = char device, size = 0).
            let mut raw = [0u8; STAT_SIZE];
            // st_dev = 1, st_ino = 0, st_mode = S_IFCHR | 0o666
            raw[0..8].copy_from_slice(&1u64.to_ne_bytes());
            let mode: u32 = 0o020000 | 0o666;
            raw[24..28].copy_from_slice(&mode.to_ne_bytes());
            raw[16..24].copy_from_slice(&1u64.to_ne_bytes()); // nlink=1
            raw[56..64].copy_from_slice(&4096i64.to_ne_bytes()); // blksize
            // SAFETY: validated above.
            unsafe { (statbuf_ptr as *mut u8).copy_from_nonoverlapping(raw.as_ptr(), STAT_SIZE) };
            return 0;
        }
        _ => return -9, // EBADF (pipe/socket — not yet supported by fstat)
    };

    let maybe_inode = crate::state::with_global(|s| s.vfs.ramfs.inode_by_number(ino));

    match maybe_inode.flatten() {
        Some(inode) => {
            // SAFETY: statbuf_ptr validated above.
            unsafe { fill_stat_buf(statbuf_ptr as *mut u8, &inode) };
            0
        }
        None => -9, // EBADF
    }
}

// ── sys_access ─────────────────────────────────────────────────────

/// Kernel handler for `SYS_ACCESS` (number 21).
///
/// POSIX.1-2024 `access(3p)`: check whether the calling process can access
/// the file at `pathname`. ONCRIX's single-user ramfs has no permission
/// enforcement, so this handler only checks for existence — a path that
/// resolves via VFS returns 0, otherwise ENOENT. The `mode` argument
/// (F_OK / R_OK / W_OK / X_OK) is accepted but not enforced.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path. `pathname_ptr`
/// must reference a NUL-terminated path in user space.
pub unsafe fn sys_access(pathname_ptr: u64, _mode: u64) -> i64 {
    static mut AC_PATH: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    static mut AC_ABS: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    // SAFETY: single-CPU SYSCALL context; AC_PATH not concurrently accessed.
    #[allow(static_mut_refs)]
    let path_len = unsafe {
        match copy_user_path(pathname_ptr, &mut AC_PATH) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    // SAFETY: AC_PATH[..path_len] written above; AC_ABS exclusively owned.
    #[allow(static_mut_refs)]
    let abs_len = unsafe {
        match resolve_path_abs(&AC_PATH[..path_len], &mut AC_ABS) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };
    // SAFETY: AC_ABS[..abs_len] written above.
    #[allow(static_mut_refs)]
    let result = unsafe {
        // SAFETY: AC_ABS slice is valid for abs_len bytes written above.
        crate::state::with_global(|s| s.vfs.lookup_path(&AC_ABS[..abs_len]))
    };

    match result {
        Some(Ok(_)) => 0,
        Some(Err(oncrix_lib::Error::NotFound)) => -2, // ENOENT
        Some(Err(_)) => -22,                          // EINVAL
        None => -5,                                   // EIO
    }
}

// ── *at family (AT_FDCWD delegation) ──────────────────────────────

/// Kernel handler for `SYS_FACCESSAT` (number 269).
///
/// POSIX.1-2024 `faccessat(3p)`: check whether the calling process can access
/// the file at `pathname`, interpreted relative to the open directory descriptor
/// `dirfd`.  On ONCRIX the VFS has no per-directory `chdir`-style root anchoring
/// for arbitrary fds yet, so only `AT_FDCWD` (-100) is supported.  When `dirfd`
/// is `AT_FDCWD` the call is a thin wrapper around [`sys_access`], which checks
/// path existence on the ramfs (permission-bit enforcement is deferred).
///
/// `_flags` (`AT_EACCESS`, `AT_SYMLINK_NOFOLLOW`) are accepted and silently
/// ignored — ONCRIX ramfs has no permission distinction between real/effective
/// uid and no symlink semantics to alter.
///
/// # Errors
///
/// Returns `-9` (EBADF) when `dirfd` is not `AT_FDCWD`.  All other errors are
/// propagated from `sys_access`.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.  `pathname` must
/// reference a NUL-terminated path in user space.
pub unsafe fn sys_faccessat(dirfd: i64, pathname: u64, mode: u64, _flags: u64) -> i64 {
    const AT_FDCWD: i64 = -100;

    // Cross-directory `*at` semantics (arbitrary open-dir fd as base) are not
    // modelled in ONCRIX yet.  Only AT_FDCWD, which is equivalent to the plain
    // access(2) call, is supported.  Any other dirfd is rejected with EBADF.
    if dirfd != AT_FDCWD {
        return -9; // EBADF
    }

    // SAFETY: caller guarantees single-CPU SYSCALL context and that `pathname`
    // is a valid NUL-terminated user-space pointer — same contract as sys_access.
    unsafe { sys_access(pathname, mode) }
}

/// Kernel handler for `SYS_FCHMODAT` (number 268).
///
/// POSIX.1-2024 `fchmodat(2)` (ramfs subset): changes the permission bits of the file at
/// `pathname`. When `dirfd` is `AT_FDCWD` and `pathname` is absolute, this is identical to
/// `chmod(2)`. Cross-directory `*at` resolution (relative paths with a real `dirfd`) is not
/// yet modelled by the ONCRIX VFS — any `dirfd` other than `AT_FDCWD` returns `-EBADF` until
/// that support is added.
///
/// The `flags` argument is accepted but ignored. Once `AT_SYMLINK_NOFOLLOW` support is
/// added the handler will need to be revisited.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path. `pathname` must reference a
/// NUL-terminated path in user space that remains valid for the duration of the call.
pub unsafe fn sys_fchmodat(dirfd: i64, pathname: u64, mode: u64, _flags: u64) -> i64 {
    /// Sentinel value for "use the current working directory" as the base descriptor.
    const AT_FDCWD: i64 = -100;

    if dirfd != AT_FDCWD {
        // Cross-directory *at resolution with a real dirfd is not yet implemented.
        // Return -EBADF until VFS gains full openat-style directory traversal.
        return -9; // EBADF
    }

    // SAFETY: `pathname` is a valid user-space pointer (same guarantee that the caller
    // gives us); we forward it unchanged to sys_chmod which performs the actual copy
    // from user space and NUL-terminated length check.
    unsafe { sys_chmod(pathname, mode) }
}

/// Kernel handler for `SYS_FCHOWNAT` (number 260).
///
/// POSIX.1-2024 `fchownat(2)`: change the owner and/or group of the file named
/// by `pathname`. When `dirfd` is `AT_FDCWD` the call is equivalent to
/// `chown(pathname, uid, gid)` and delegates directly to [`sys_chown`].
///
/// Cross-directory `*at` semantics (dirfd pointing at an open directory other
/// than `AT_FDCWD`) are **not yet modelled** in the ramfs VFS layer. Any such
/// call returns `-EBADF` (`-9`) until proper dirfd-relative path resolution is
/// implemented.
///
/// The `flags` argument is accepted but ignored; `AT_SYMLINK_NOFOLLOW` support
/// will be added together with full symlink resolution.
///
/// Returns 0 on success, or a negative errno value.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path. `pathname` must
/// reference a NUL-terminated path string in user space.
pub unsafe fn sys_fchownat(dirfd: i64, pathname: u64, uid: u64, gid: u64, _flags: u64) -> i64 {
    // AT_FDCWD (-100): the pathname is interpreted relative to the calling
    // process's current working directory, identical to plain chown(2).
    const AT_FDCWD: i64 = -100;

    if dirfd != AT_FDCWD {
        // Cross-directory *at resolution is not yet implemented.
        // EBADF (-9): dirfd does not refer to an open directory fd that this
        // kernel can resolve paths against.
        return -9;
    }

    // SAFETY: `pathname` is a user-space pointer to a NUL-terminated path;
    // the caller (single-CPU SYSCALL path) guarantees this invariant, which
    // sys_chown enforces via copy_user_path.
    unsafe { sys_chown(pathname, uid, gid) }
}

/// Kernel handler for `SYS_MKDIRAT` (number 258).
///
/// POSIX.1-2024 `mkdirat(3p)` — creates a new directory, interpreting a
/// relative `pathname` with respect to the open directory `dirfd`.
///
/// # Limitations
///
/// Cross-directory `*at` path resolution (dirfd pointing at an arbitrary open
/// directory) is not yet modelled in ONCRIX's VFS layer. Only `AT_FDCWD`
/// (-100) is accepted as `dirfd`; any other value causes an immediate `-9`
/// (EBADF) return. Callers that need true relative-directory semantics must
/// wait for a future VFS update that tracks per-process working-directory
/// file handles.
///
/// # Errors (returned as negative errno)
///
/// - `-9`  EBADF  — `dirfd` is not `AT_FDCWD`.
/// - `-2`  ENOENT — parent directory does not exist.
/// - `-17` EEXIST — path already exists.
/// - `-12` ENOMEM — ramfs inode table full.
/// - `-22` EINVAL — path is non-absolute or otherwise invalid.
/// - `-14` EFAULT — bad user pointer.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.
/// `pathname` must be a valid user-space pointer to a null-terminated path
/// string; it is validated by the delegated `sys_mkdir` handler.
pub unsafe fn sys_mkdirat(dirfd: i64, pathname: u64, mode: u64) -> i64 {
    // AT_FDCWD is the Linux/POSIX sentinel meaning "relative to cwd".
    // ONCRIX does not yet model arbitrary open-directory fds for *at calls.
    const AT_FDCWD: i64 = -100;

    if dirfd != AT_FDCWD {
        // Cross-directory mkdirat is not yet implemented; only AT_FDCWD is
        // supported. Return EBADF to signal an unsupported dirfd.
        return -9; // EBADF
    }

    // SAFETY: caller is the single-CPU SYSCALL dispatch path; `pathname` and
    // `mode` are forwarded unchanged to sys_mkdir, which performs its own
    // pointer validation via copy_user_path().
    unsafe { sys_mkdir(pathname, mode) }
}

/// Kernel handler for `SYS_UNLINKAT` (number 263).
///
/// POSIX.1-2024 `unlinkat(3p)` — remove a directory entry, relative to a
/// directory file descriptor.
///
/// # Behaviour
///
/// * If `dirfd` ≠ `AT_FDCWD` (-100) this implementation returns `-9` (EBADF).
///   Relative-to-directory-fd semantics are not yet modelled; all paths must
///   be absolute or resolved from the process working directory via `AT_FDCWD`.
/// * If `flags & AT_REMOVEDIR` (0x200) is set, delegates to [`sys_rmdir`].
/// * Otherwise delegates to [`sys_unlink`].
///
/// All other `flags` bits are silently ignored (Linux-compatible).
///
/// # Errors (returned as negative errno)
///
/// * `-9`  EBADF   — `dirfd` is not `AT_FDCWD` (cross-dir not implemented).
/// * `-22` EINVAL  — `pathname` is non-absolute or malformed.
/// * `-14` EFAULT  — `pathname` is an invalid user pointer.
/// * `-2`  ENOENT  — file or directory does not exist.
/// * `-39` ENOTEMPTY — directory is not empty (rmdir path only).
/// * `-1`  EPERM   — path names a directory (unlink path only).
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.
/// `pathname` must be a NUL-terminated pointer into user address space.
pub unsafe fn sys_unlinkat(dirfd: i64, pathname: u64, flags: u64) -> i64 {
    const AT_FDCWD: i64 = -100;
    const AT_REMOVEDIR: u64 = 0x200;

    if dirfd != AT_FDCWD {
        // Cross-directory unlinkat (dirfd pointing to an open directory
        // other than the process CWD) is not yet implemented.
        return -9; // EBADF
    }

    if flags & AT_REMOVEDIR != 0 {
        // SAFETY: We are on the single-CPU SYSCALL path; `pathname` is the
        // user-supplied pointer, which `sys_rmdir` validates internally.
        unsafe { sys_rmdir(pathname) }
    } else {
        // SAFETY: We are on the single-CPU SYSCALL path; `pathname` is the
        // user-supplied pointer, which `sys_unlink` validates internally.
        unsafe { sys_unlink(pathname) }
    }
}

/// Kernel handler for `SYS_RENAMEAT` (number 264).
///
/// POSIX.1-2024 `renameat(2)`: renames `oldpath` to `newpath`, where each path is interpreted
/// relative to the directory referred to by the corresponding directory file descriptor.
///
/// # Current Limitations
///
/// Cross-directory `*at` operations (where a dirfd refers to an actual open directory rather than
/// `AT_FDCWD`) are not yet modelled in the VFS layer. When either `olddirfd` or `newdirfd` is not
/// `AT_FDCWD`, this function returns `-EBADF` (-9). Both descriptors must be `AT_FDCWD` for the
/// call to succeed; in that case it delegates directly to [`sys_rename`].
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path. `oldpath` and `newpath` must
/// reference NUL-terminated path strings in user space. Both `olddirfd` and `newdirfd` must
/// either be `AT_FDCWD` or valid open directory file descriptors (the latter returns `-EBADF`
/// until cross-directory support is implemented).
pub unsafe fn sys_renameat(olddirfd: i64, oldpath: u64, newdirfd: i64, newpath: u64) -> i64 {
    /// Sentinel value meaning "relative to the process's current working directory".
    const AT_FDCWD: i64 = -100;

    if olddirfd != AT_FDCWD || newdirfd != AT_FDCWD {
        // Cross-directory *at operations are not yet implemented in the VFS layer.
        // Return -EBADF (-9) for any dirfd that is not AT_FDCWD.
        return -9; // EBADF
    }

    // SAFETY: Both dirfds are AT_FDCWD, so this is semantically identical to rename(2).
    // The caller guarantees `oldpath` and `newpath` are valid NUL-terminated user-space pointers,
    // and we are on the single-CPU SYSCALL dispatch path.
    unsafe { sys_rename(oldpath, newpath) }
}

/// `readlinkat(2)` — read the target of a symbolic link, interpreting `pathname`
/// relative to the directory file descriptor `dirfd`.
///
/// This implementation supports only `AT_FDCWD` (-100) as `dirfd`. Any other
/// value causes an immediate return of `-EBADF` (-9). Relative-directory
/// resolution via an open directory descriptor is not yet modelled in the VFS
/// layer and will be added in a future revision.
///
/// On success the target bytes (without a NUL terminator, per POSIX) are
/// written into `buf[..bufsiz]` and the byte count is returned. On failure a
/// negative errno value is returned.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.
/// `pathname` must be a valid, NUL-terminated user-space string pointer.
/// `buf..buf+bufsiz` must be a writable user-space memory region.
pub unsafe fn sys_readlinkat(dirfd: i64, pathname: u64, buf: u64, bufsiz: u64) -> i64 {
    const AT_FDCWD: i64 = -100;

    if dirfd != AT_FDCWD {
        // Only AT_FDCWD is supported; cross-directory *at resolution is not
        // yet implemented. Return EBADF to signal the unsupported dirfd.
        return -9; // EBADF
    }

    // SAFETY: dirfd == AT_FDCWD, so `pathname` is a cwd-relative (or absolute)
    // path identical to what sys_readlink expects. Caller guarantees the
    // pointer and buffer validity required by that function.
    unsafe { sys_readlink(pathname, buf, bufsiz) }
}

/// Kernel handler for `SYS_SYMLINKAT` (number 266).
///
/// POSIX.1-2024 `symlinkat(2)`: creates `linkpath` as a symbolic link with literal
/// contents `target`, where `linkpath` is interpreted relative to the directory
/// referred to by `newdirfd`. When `newdirfd` is `AT_FDCWD`, the call is equivalent
/// to `symlink(target, linkpath)` and is delegated directly to [`sys_symlink`].
///
/// # Limitations
///
/// Cross-directory `*at` resolution (i.e. `newdirfd` pointing to an open directory
/// other than `AT_FDCWD`) is not yet modelled by the VFS layer. Any `newdirfd`
/// value other than `AT_FDCWD` causes an immediate `-EBADF` return. This will be
/// lifted once `UnifiedFdTable` exposes directory-fd path anchoring.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path. `target_ptr` and
/// `linkpath_ptr` must reference valid NUL-terminated strings in user space.
pub unsafe fn sys_symlinkat(target_ptr: u64, newdirfd: i64, linkpath_ptr: u64) -> i64 {
    // AT_FDCWD (-100): the standard sentinel meaning "relative to CWD", which
    // is the only mode the current VFS path resolver supports.
    const AT_FDCWD: i64 = -100;

    if newdirfd != AT_FDCWD {
        // SAFETY: no memory access; pure integer comparison.
        return -9; // EBADF — non-CWD directory fds not yet supported
    }

    // SAFETY: caller guarantees this is the single-CPU SYSCALL dispatch path and
    // that both pointers reference NUL-terminated user-space strings, satisfying
    // the preconditions of sys_symlink.
    unsafe { sys_symlink(target_ptr, linkpath_ptr) }
}

/// Kernel handler for `SYS_NEWFSTATAT` (number 262).
///
/// POSIX.1-2024 `fstatat(3p)`: obtains file status for `pathname`, optionally not
/// following a terminal symbolic link.  When `flags & AT_SYMLINK_NOFOLLOW` is set this
/// is equivalent to `lstat(2)`; otherwise it is equivalent to `stat(2)`.
///
/// # Current limitation
///
/// Only `dirfd == AT_FDCWD` is supported.  Any other value causes an immediate return
/// of `-9` (`EBADF`).  Full cross-directory resolution requires VFS-level support that
/// has not yet been implemented; this stub documents the gap and keeps the ABI slot
/// occupied so user-space code that always passes `AT_FDCWD` works correctly.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.  `pathname` must be a
/// valid null-terminated user-space string pointer.  `statbuf` must point to at least
/// 144 writable bytes in user space (kernel `struct stat` ABI size).
pub unsafe fn sys_newfstatat(dirfd: i64, pathname: u64, statbuf: u64, flags: u64) -> i64 {
    /// Only `AT_FDCWD` is accepted for `dirfd`; all other values return `EBADF`.
    const AT_FDCWD: i64 = -100;
    /// When set in `flags`, the call delegates to `lstat` instead of `stat`.
    const AT_SYMLINK_NOFOLLOW: u64 = 0x100;

    if dirfd != AT_FDCWD {
        // Cross-directory fstatat is not yet implemented.  Return EBADF to signal
        // that only the AT_FDCWD sentinel is supported at this time.
        return -9; // EBADF
    }

    if flags & AT_SYMLINK_NOFOLLOW != 0 {
        // SAFETY: caller guarantees pathname and statbuf are valid user pointers;
        // we are on the single-CPU SYSCALL dispatch path; sys_lstat upholds the
        // same invariants.
        unsafe { sys_lstat(pathname, statbuf) }
    } else {
        // SAFETY: same as above; sys_stat upholds the same invariants.
        unsafe { sys_stat(pathname, statbuf) }
    }
}

// ── statfs / fstatfs helpers ──────────────────────────────────────

/// RAMFS magic number (matches the value used by Linux ramfs).
///
/// The specific magic is not mandated by POSIX but is required by musl/glibc
/// `statfs(2)` consumers that identify the filesystem type.
const RAMFS_MAGIC: i64 = 0x858458f6_u32 as i64;

/// Total inode slots in the ramfs table.
///
/// Must stay in sync with `MAX_INODES` in `crates/vfs/src/ramfs.rs`.
const RAMFS_MAX_INODES: i64 = 128;

/// Fixed block size reported by ramfs (4 KiB), matching the kernel page size.
///
/// Ramfs has no real block accounting; this constant is a POSIX-compliant
/// placeholder so that space-estimation code (`df`, `statvfs`) gets a
/// consistent and reasonable answer.
const RAMFS_BSIZE: i64 = 4096;

/// Reported total blocks for ramfs (64 MiB worth at 4 KiB/block).
///
/// Ramfs is unbounded by design but POSIX requires a non-zero `f_blocks` value.
/// 16 384 × 4 KiB = 64 MiB is a conservative but plausible ceiling for a
/// single-process early-boot system.
const RAMFS_BLOCKS: i64 = 16384;

/// Reported free/available blocks.
///
/// Chosen as half of `RAMFS_BLOCKS`; ramfs has no real accounting.
const RAMFS_BFREE: i64 = 8192;

/// Maximum component name length for ramfs.
const RAMFS_NAMELEN: i64 = 255;

/// `struct statfs` size in the Linux x86_64 ABI (120 bytes).
const STATFS_SIZE: usize = 120;

/// Fill the 120-byte Linux x86_64 `struct statfs` at `buf` with ramfs data.
///
/// Layout (all fields little-endian, matching Linux abi/x86/statfs.h):
///
/// ```text
///  @  0  i64   f_type
///  @  8  i64   f_bsize
///  @ 16  i64   f_blocks
///  @ 24  i64   f_bfree
///  @ 32  i64   f_bavail
///  @ 40  i64   f_files
///  @ 48  i64   f_ffree
///  @ 56  i32   f_fsid[0]
///  @ 60  i32   f_fsid[1]
///  @ 64  i64   f_namelen
///  @ 72  i64   f_frsize
///  @ 80  i64   f_flags
///  @ 88  i64   f_spare[4]  (zero-filled)
/// ```
///
/// # Safety
///
/// `buf` must point to at least `STATFS_SIZE` (120) writable bytes.
/// The caller must have validated the pointer (non-null, user-space range).
unsafe fn fill_statfs_buf(buf: *mut u8, used_inodes: i64) {
    let free_inodes = (RAMFS_MAX_INODES - used_inodes).max(0);

    let mut raw = [0u8; STATFS_SIZE];

    // f_type @ 0
    raw[0..8].copy_from_slice(&RAMFS_MAGIC.to_ne_bytes());
    // f_bsize @ 8
    raw[8..16].copy_from_slice(&RAMFS_BSIZE.to_ne_bytes());
    // f_blocks @ 16
    raw[16..24].copy_from_slice(&RAMFS_BLOCKS.to_ne_bytes());
    // f_bfree @ 24
    raw[24..32].copy_from_slice(&RAMFS_BFREE.to_ne_bytes());
    // f_bavail @ 32  (same as f_bfree — ramfs has no reserved blocks)
    raw[32..40].copy_from_slice(&RAMFS_BFREE.to_ne_bytes());
    // f_files @ 40  (total inode slots)
    raw[40..48].copy_from_slice(&RAMFS_MAX_INODES.to_ne_bytes());
    // f_ffree @ 48  (free inode slots)
    raw[48..56].copy_from_slice(&free_inodes.to_ne_bytes());
    // f_fsid @ 56–63  (zero — ramfs has no persistent device id)
    // f_namelen @ 64
    raw[64..72].copy_from_slice(&RAMFS_NAMELEN.to_ne_bytes());
    // f_frsize @ 72  (fragment size == block size for ramfs)
    raw[72..80].copy_from_slice(&RAMFS_BSIZE.to_ne_bytes());
    // f_flags @ 80  (0 — no special mount flags reported)
    // f_spare[4] @ 88–119  (zero-filled — already zeroed)

    // SAFETY: caller guarantees buf is valid for STATFS_SIZE writable bytes.
    unsafe { buf.copy_from_nonoverlapping(raw.as_ptr(), STATFS_SIZE) };
}

// ── sys_statfs ────────────────────────────────────────────────────

/// Kernel handler for `SYS_STATFS` (number 137).
///
/// POSIX.1-2024 `statfs(2)` — return statistics for the filesystem
/// containing `pathname`.  On ONCRIX the only mounted filesystem is ramfs, so
/// the syscall succeeds for any path that exists in the VFS and fills a
/// 120-byte Linux x86_64 `struct statfs` at `buf`.
///
/// # Errors (returned as negative errno)
///
/// - `-2`  ENOENT — `pathname` does not resolve in the VFS.
/// - `-14` EFAULT — `pathname_ptr` or `buf_ptr` is NULL / kernel-canonical.
/// - `-36` ENAMETOOLONG — path exceeds the internal limit.
/// - `-22` EINVAL — empty or non-absolute path after resolution.
/// - `-5`  EIO — global VFS state unavailable.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.
/// `pathname_ptr` must be a null-terminated user-space string.
/// `buf_ptr` must point to at least 120 writable user-space bytes.
pub unsafe fn sys_statfs(pathname_ptr: u64, buf_ptr: u64) -> i64 {
    if pathname_ptr == 0 || pathname_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    if buf_ptr == 0 || buf_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }

    static mut STATFS_PATH: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];
    static mut STATFS_ABS: [u8; PATH_BUF_LEN] = [0u8; PATH_BUF_LEN];

    // SAFETY: single-CPU SYSCALL context; buffers exclusively owned here.
    #[allow(static_mut_refs)]
    let path_len = unsafe {
        match copy_user_path(pathname_ptr, &mut STATFS_PATH) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };

    #[allow(static_mut_refs)]
    let abs_len = unsafe {
        match resolve_path_abs(&STATFS_PATH[..path_len], &mut STATFS_ABS) {
            Ok(n) => n,
            Err(e) => return e,
        }
    };

    // SAFETY: STATFS_ABS[..abs_len] written above; exclusively owned here.
    #[allow(static_mut_refs)]
    let lookup = unsafe {
        let abs = &STATFS_ABS[..abs_len];
        crate::state::with_global(|s| s.vfs.lookup_path(abs))
    };

    match lookup {
        Some(Ok(_)) => {}
        Some(Err(oncrix_lib::Error::NotFound)) => return -2, // ENOENT
        Some(Err(_)) => return -22,                          // EINVAL
        None => return -5,                                   // EIO
    }

    let used = crate::state::with_global(|s| s.vfs.ramfs_used_inodes()).unwrap_or(0) as i64;

    // SAFETY: buf_ptr validated above; fill_statfs_buf writes exactly STATFS_SIZE bytes.
    unsafe { fill_statfs_buf(buf_ptr as *mut u8, used) };
    0
}

// ── sys_fstatfs ───────────────────────────────────────────────────

/// Kernel handler for `SYS_FSTATFS` (number 138).
///
/// POSIX.1-2024 `fstatfs(2)` — return statistics for the filesystem
/// underlying the open file descriptor `fd`.  Any valid open descriptor is
/// accepted (regular file, directory, pipe, console) because all of them
/// ultimately live on the single ramfs mount.  Fills a 120-byte Linux
/// x86_64 `struct statfs` at `buf`.
///
/// # Errors (returned as negative errno)
///
/// - `-9`  EBADF — `fd` is not open.
/// - `-14` EFAULT — `buf_ptr` is NULL / kernel-canonical.
/// - `-5`  EIO — global VFS state unavailable.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.
/// `buf_ptr` must point to at least 120 writable user-space bytes.
pub unsafe fn sys_fstatfs(fd: i32, buf_ptr: u64) -> i64 {
    if buf_ptr == 0 || buf_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }

    // SAFETY: single-CPU SYSCALL context.
    let handle = unsafe { crate::fd_table::fd_get(fd as usize) };
    if handle.is_none() {
        return -9; // EBADF
    }

    let used = crate::state::with_global(|s| s.vfs.ramfs_used_inodes()).unwrap_or(0) as i64;

    // SAFETY: buf_ptr validated above; fill_statfs_buf writes exactly STATFS_SIZE bytes.
    unsafe { fill_statfs_buf(buf_ptr as *mut u8, used) };
    0
}

// ── sysinfo(2) ────────────────────────────────────────────────────

/// Total physical RAM exposed to userspace (fixed for this single-board
/// build — 96 MiB matches the frame-pool size used by the memory manager).
const SYSINFO_TOTAL_RAM: u64 = 96 * 1024 * 1024;

/// `sysinfo(info)` — fill a Linux-ABI `struct sysinfo` at `info`.
///
/// Populates the 112-byte `struct sysinfo` (Linux x86_64 ABI) at the
/// user pointer `info`:
///
/// | Offset | Field      | Value source                                  |
/// |--------|------------|-----------------------------------------------|
/// | 0      | uptime     | PIT ticks / 100 (seconds since boot)          |
/// | 8      | loads[3]   | 0, 0, 0 (load-average not yet computed)       |
/// | 32     | totalram   | 96 MiB (fixed frame-pool size)                |
/// | 40     | freeram    | 96 MiB − 2 MiB per live process               |
/// | 48     | sharedram  | 0                                             |
/// | 56     | bufferram  | 0                                             |
/// | 64     | totalswap  | 0 (no swap)                                   |
/// | 72     | freeswap   | 0 (no swap)                                   |
/// | 80     | procs      | live process count from the process table     |
/// | 82     | pad        | 0                                             |
/// | 84     | _pad[2]    | 0 (alignment padding to reach offset 88)      |
/// | 88     | totalhigh  | 0 (no high-memory zone on this target)        |
/// | 96     | freehigh   | 0                                             |
/// | 104    | mem_unit   | 1 (all RAM fields are in bytes)               |
/// | 108    | _f[4]      | 0 (padding to 112 bytes)                      |
///
/// Returns 0 on success, or a negative errno value on error.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path (interrupts
/// effectively disabled via `FMASK`). `info` must point to at least 112
/// writable bytes in user space; non-canonical addresses are rejected with
/// `-14` (`EFAULT`).
pub unsafe fn sys_sysinfo(info: u64) -> i64 {
    // Reject null or kernel-half pointers.
    if info == 0 || info >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }

    // Read the current PIT tick counter.
    //
    // SAFETY: Single-CPU SYSCALL dispatch path (IF=0 via FMASK).
    // `PIT_TIMER` is a `static mut` that is only mutated from the timer
    // IRQ handler (which runs with IF=0 through an interrupt gate) and
    // read here on the same CPU while interrupts are disabled. No
    // concurrent mutation is possible.
    let ticks = unsafe {
        use oncrix_hal::timer::Timer;
        let pit_ptr = &raw const crate::arch::x86_64::init::PIT_TIMER;
        (*pit_ptr).current_ticks()
    };
    /// PIT tick frequency: `init_pic_and_timer` programs divisor 11932 → ~100 Hz.
    const TIMER_HZ: u64 = 100;
    let uptime: i64 = (ticks / TIMER_HZ) as i64;

    // Count live processes from the process table.
    //
    // SAFETY: Single-CPU SYSCALL dispatch path. `process_table_mut`
    // requires the single-borrower invariant; no other code path holding
    // the table borrow is on the call stack here.
    let procs: u16 = {
        let table = unsafe { crate::fork_dispatch::process_table_mut() };
        table.count().min(u16::MAX as usize) as u16
    };

    // Estimate free RAM: subtract 2 MiB per live process (each gets one
    // 2 MiB user-address-space backing region). Saturate at zero.
    let used_ram: u64 = (procs as u64).saturating_mul(2 * 1024 * 1024);
    let freeram: u64 = SYSINFO_TOTAL_RAM.saturating_sub(used_ram);

    // Build the 112-byte struct sysinfo as a byte array.
    //
    // Layout (all fields little-endian, as on x86_64):
    //   [0..8]   uptime     i64
    //   [8..32]  loads[3]   u64 × 3
    //   [32..40] totalram   u64
    //   [40..48] freeram    u64
    //   [48..56] sharedram  u64
    //   [56..64] bufferram  u64
    //   [64..72] totalswap  u64
    //   [72..80] freeswap   u64
    //   [80..82] procs      u16
    //   [82..84] pad        u16
    //   [84..88] _pad       u32   (alignment gap before totalhigh)
    //   [88..96] totalhigh  u64
    //   [96..104] freehigh  u64
    //   [104..108] mem_unit u32
    //   [108..112] _f       u32   (struct padded to 112 bytes)
    let mut buf = [0u8; 112];
    buf[0..8].copy_from_slice(&uptime.to_le_bytes());
    // loads[0..3] remain zero (offset 8..32).
    buf[32..40].copy_from_slice(&SYSINFO_TOTAL_RAM.to_le_bytes());
    buf[40..48].copy_from_slice(&freeram.to_le_bytes());
    // sharedram (48..56) = 0.
    // bufferram (56..64) = 0.
    // totalswap (64..72) = 0.
    // freeswap  (72..80) = 0.
    buf[80..82].copy_from_slice(&procs.to_le_bytes());
    // pad (82..84) = 0, _pad (84..88) = 0.
    // totalhigh (88..96) = 0.
    // freehigh  (96..104) = 0.
    buf[104..108].copy_from_slice(&1u32.to_le_bytes()); // mem_unit = 1
    // _f (108..112) = 0.

    // SAFETY: `info` is a canonical user-space pointer (checked above).
    // We write exactly 112 bytes; an unmapped user page would fault into
    // the page-fault handler, which delivers SIGSEGV to the process.
    unsafe {
        core::ptr::write_unaligned(info as *mut [u8; 112], buf);
    }
    0
}

// ── flock / I/O advisory / fallocate ──────────────────────────────

// (anywhere in the file is fine; suggested placement: after sys_fchown).

/// Kernel handler for `SYS_FLOCK` (number 73).
///
/// POSIX / Linux `flock(2)`: apply or remove an advisory whole-file lock.
/// ONCRIX is single-user with an in-memory VFS — no lock table exists, so
/// the operation always succeeds. The only validation performed is an
/// `EBADF` check: if `fd` is not present in the current fd table the call
/// returns `-9` (EBADF), matching Linux semantics for a closed descriptor.
///
/// Advisory locks are **not** recorded; a subsequent `flock` with
/// `LOCK_UN` on the same fd also returns 0.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU context).
pub unsafe fn sys_flock(fd: i32, _op: i32) -> i64 {
    // SAFETY: single-CPU SYSCALL context; fd_table is exclusively owned here.
    let handle = unsafe { crate::fd_table::fd_get(fd as usize) };
    if handle.is_none() {
        return -9; // EBADF
    }
    0
}

// ── sys_fadvise64 ─────────────────────────────────────────────────

/// Kernel handler for `SYS_FADVISE64` (Linux number 221).
///
/// POSIX `posix_fadvise(fd, offset, len, advice)`: hints the kernel about the
/// expected access pattern for the byte range `[offset, offset+len)` of the
/// file referenced by `fd`. On ONCRIX's in-memory ramfs there is no page cache
/// to tune, so the advice is silently accepted and success is returned.
///
/// Returns 0 on success, or `-EBADF` if `fd` is not open.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.
pub unsafe fn sys_fadvise64(fd: i32, _offset: u64, _len: u64, _advice: i32) -> i64 {
    // SAFETY: single-CPU SYSCALL context.
    match unsafe { crate::fd_table::fd_get(fd as usize) } {
        Some(_) => 0,
        None => -9, // EBADF
    }
}

// ── sys_readahead ─────────────────────────────────────────────────

/// Kernel handler for `SYS_READAHEAD` (Linux number 187).
///
/// `readahead(fd, offset, count)`: initiates read-ahead of `count` bytes
/// starting at `offset` in the file referenced by `fd`. On ONCRIX's in-memory
/// ramfs all data is always resident, so this is a validated no-op.
///
/// Returns 0 on success, or `-EBADF` if `fd` is not open.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.
pub unsafe fn sys_readahead(fd: i32, _offset: u64, _count: usize) -> i64 {
    // SAFETY: single-CPU SYSCALL context.
    match unsafe { crate::fd_table::fd_get(fd as usize) } {
        Some(_) => 0,
        None => -9, // EBADF
    }
}

// ── sys_sync_file_range ───────────────────────────────────────────

/// Kernel handler for `SYS_SYNC_FILE_RANGE` (Linux number 277).
///
/// `sync_file_range(fd, offset, nbytes, flags)`: writes a segment of a file's
/// dirty page-cache pages to backing store. ONCRIX ramfs has no backing store,
/// so this is a validated no-op that returns success.
///
/// Returns 0 on success, or `-EBADF` if `fd` is not open.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.
pub unsafe fn sys_sync_file_range(fd: i32, _offset: u64, _nbytes: u64, _flags: u32) -> i64 {
    // SAFETY: single-CPU SYSCALL context.
    match unsafe { crate::fd_table::fd_get(fd as usize) } {
        Some(_) => 0,
        None => -9, // EBADF
    }
}

// ── sys_fallocate ─────────────────────────────────────────────────

/// Kernel handler for `SYS_FALLOCATE` (Linux number 285).
///
/// `fallocate(fd, mode, offset, len)`: manipulates file space allocation.
///
/// For `mode == 0` (plain pre-allocation / hole-punching disabled): ensures the
/// file is at least `offset + len` bytes long by extending it via
/// [`crate::state::with_global_mut`] → `truncate_ino`. If the file is already
/// at least that size, it is left untouched.
///
/// For any non-zero `mode` flag (e.g. `FALLOC_FL_KEEP_SIZE = 1`,
/// `FALLOC_FL_PUNCH_HOLE = 2`): ramfs has no sparse-file or discard
/// semantics, so non-zero modes are accepted silently and success is returned
/// (the file is not modified).
///
/// Returns 0 / `-EBADF` / `-EINVAL` / `-ENOENT` / `-EFBIG` / `-EIO`.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.
pub unsafe fn sys_fallocate(fd: i32, mode: i32, offset: u64, len: u64) -> i64 {
    // Validate the fd first regardless of mode.
    // SAFETY: single-CPU SYSCALL context.
    let ino = match unsafe { crate::fd_table::fd_get(fd as usize) } {
        Some(h) => match h.backend {
            oncrix_process::fd_table::FileBackend::RamfsFile { ino } => ino,
            _ => return -22, // EINVAL — backend has no file-allocation op
        },
        None => return -9, // EBADF
    };

    // Non-zero mode: advisory / modifier flags that ramfs cannot honour.
    // Accept silently — callers that set FALLOC_FL_KEEP_SIZE etc. expect
    // no visible change to the file anyway.
    if mode != 0 {
        return 0;
    }

    // mode == 0: ensure the file reaches at least offset+len bytes.
    let required = match offset.checked_add(len) {
        Some(v) => v,
        None => return -22, // EINVAL — overflow
    };

    // Read current file size; skip the extend if already large enough.
    let current_size = crate::state::with_global_mut(|s| s.vfs.inode_size(ino)).flatten();
    if let Some(sz) = current_size {
        if sz >= required {
            return 0;
        }
    }

    let result = crate::state::with_global_mut(|s| s.vfs.truncate_ino(ino, required));
    match result {
        Some(Ok(())) => 0,
        Some(Err(oncrix_lib::Error::NotFound)) => -2, // ENOENT
        Some(Err(oncrix_lib::Error::InvalidArgument)) => -22, // EINVAL
        Some(Err(oncrix_lib::Error::OutOfMemory)) => -27, // EFBIG
        Some(Err(_)) => -22,
        None => -5, // EIO
    }
}

// ── capget / capset / getgroups / setgroups / personality ─────────

// ── sys_capget ────────────────────────────────────────────────────

/// Kernel handler for `SYS_CAPGET` (number 125).
///
/// `capget(header, data)` — retrieve the capability sets for the calling
/// thread.  ONCRIX does not implement a capability model; the process
/// holds no capabilities.  The handler:
///
/// 1. Validates `header_ptr` (non-null, not in kernel-canonical space).
/// 2. If `data_ptr` is non-null and valid, zero-fills the 24-byte
///    `cap_user_data_t[2]` structure so the caller sees all-zero
///    effective / permitted / inheritable capability sets.
/// 3. Returns 0.
///
/// # Errors (returned as negative errno)
///
/// - `-14` EFAULT — `header_ptr` is null or kernel-canonical.
/// - `-14` EFAULT — `data_ptr` is non-null but kernel-canonical.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.
pub unsafe fn sys_capget(header_ptr: u64, data_ptr: u64) -> i64 {
    // Validate the mandatory header pointer.
    if header_ptr == 0 || header_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }

    // The capability-set ABI version selects the data-block size:
    //   _LINUX_CAPABILITY_VERSION_1 (0x19980330) -> ONE cap_user_data_t (12 B)
    //   v2 (0x20071026) / v3 (0x20080522)        -> TWO entries (24 B)
    // A v1 caller allocates only 12 bytes, so unconditionally writing 24
    // would overflow its buffer. Read the version before sizing the write.
    /// `_LINUX_CAPABILITY_VERSION_1` — single 12-byte data block.
    const CAP_V1: u32 = 0x1998_0330;
    // SAFETY: header_ptr validated non-null/user above; reading 4 bytes.
    let version = unsafe { core::ptr::read_unaligned(header_ptr as *const u32) };
    let data_len: usize = if version == CAP_V1 { 12 } else { 24 };

    // data_ptr may be null (caller only querying the version in the header).
    // If non-null it must be a valid user address for the whole data block.
    if data_ptr != 0 && data_ptr >= 0xFFFF_8000_0000_0000 - data_len as u64 {
        return -14; // EFAULT
    }

    if data_ptr != 0 {
        // Zero-fill the cap_user_data_t block (no capabilities held).
        // SAFETY: validated above; data_len (12 or 24) bytes within user range.
        unsafe {
            core::ptr::write_bytes(data_ptr as *mut u8, 0, data_len);
        }
    }

    0
}

// ── sys_capset ────────────────────────────────────────────────────

/// Kernel handler for `SYS_CAPSET` (number 126).
///
/// `capset(header, data)` — set the capability sets for the calling thread.
/// ONCRIX does not implement a capability model; any well-formed call
/// succeeds silently (no-op).  The handler validates the pointer arguments
/// and returns 0.
///
/// # Errors (returned as negative errno)
///
/// - `-14` EFAULT — `header_ptr` is null or kernel-canonical.
/// - `-14` EFAULT — `data_ptr` is non-null but kernel-canonical.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.
pub unsafe fn sys_capset(header_ptr: u64, data_ptr: u64) -> i64 {
    // The header pointer is required by the Linux ABI.
    if header_ptr == 0 || header_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    // data_ptr may be null for version-probe calls; if non-null validate it.
    if data_ptr != 0 && data_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }

    // No capability enforcement: accept and succeed.
    0
}

// ── sys_getgroups ─────────────────────────────────────────────────

/// Kernel handler for `SYS_GETGROUPS` (number 115).
///
/// `getgroups(size, list)` — get the supplementary group IDs of the calling
/// process.  ONCRIX runs a single-user model with no supplementary groups,
/// so the group list is always empty.
///
/// POSIX.1-2024 semantics:
/// - If `size == 0`, return the number of supplementary groups (0 here).
/// - If `size > 0` and the list fits, copy group IDs into `list` and return
///   the count.  Since the count is 0, nothing is written.
/// - If `size > 0` and `list` is a bad pointer, return `-EFAULT`.
///
/// # Errors (returned as negative errno)
///
/// - `-14` EFAULT — `size > 0` and `list_ptr` is null or kernel-canonical.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.
pub unsafe fn sys_getgroups(size: i64, list_ptr: u64) -> i64 {
    if size == 0 {
        // POSIX: return the number of supplementary groups.
        return 0;
    }
    if size < 0 {
        return -22; // EINVAL
    }
    // size > 0: validate the output pointer even though we write nothing.
    if list_ptr == 0 || list_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    // The supplementary group list is empty; return 0 (count written).
    0
}

// ── sys_setgroups ─────────────────────────────────────────────────

/// Kernel handler for `SYS_SETGROUPS` (number 116).
///
/// `setgroups(size, list)` — set the supplementary group IDs of the calling
/// process.  ONCRIX is a single-user system without supplementary group
/// support:
///
/// - `size == 0`: clear the supplementary group list (already empty); succeed.
/// - `size > 0`: return `-EPERM` — the process does not hold `CAP_SETGID`.
///
/// # Errors (returned as negative errno)
///
/// - `-1` EPERM — `size > 0`; changing supplementary groups is not permitted.
/// - `-22` EINVAL — `size < 0`.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.
pub unsafe fn sys_setgroups(size: i64, _list_ptr: u64) -> i64 {
    if size < 0 {
        return -22; // EINVAL
    }
    if size == 0 {
        // Clearing the supplementary group list is always accepted.
        return 0;
    }
    // Any attempt to install supplementary groups is refused: ONCRIX has no
    // supplementary-group support and the calling process holds no CAP_SETGID.
    -1 // EPERM
}

// ── sys_personality ───────────────────────────────────────────────

/// Kernel handler for `SYS_PERSONALITY` (number 135).
///
/// `personality(persona)` — query or set the execution domain (personality).
/// ONCRIX supports only `PER_LINUX` (0x0000).  The call always succeeds and
/// returns 0 regardless of the requested `persona`:
///
/// - `persona == 0xFFFF_FFFF`: query; return the current personality (0).
/// - Any other value: acknowledge the set request; return the previous
///   personality (0).  No domain switch is performed.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.
pub unsafe fn sys_personality(_persona: u64) -> i64 {
    // Return the previous personality: PER_LINUX = 0.
    0
}

// ── sendfile / copy_file_range ────────────────────────────────────

// ── sys_sendfile ──────────────────────────────────────────────────

/// Kernel handler for `SYS_SENDFILE` (number 40).
///
/// `sendfile(out_fd, in_fd, offset, count)` — copy up to `count` bytes from
/// `in_fd` to `out_fd` entirely within the kernel, bypassing user-space
/// memory.  Both descriptors must back a [`FileBackend::RamfsFile`]; any
/// other backend (console, pipe, socket, …) returns `-EINVAL`.
///
/// **Offset semantics** (POSIX / Linux `sendfile(2)`):
/// - If `offset_ptr` is non-null it is treated as a `*mut i64` pointing to
///   the source offset.  Data is read from `*offset_ptr` inside `in_fd`;
///   the file-position of `in_fd` is **not** changed, but `*offset_ptr` is
///   advanced by the number of bytes copied.
/// - If `offset_ptr` is null, data is read from `in_fd`'s current file
///   position, which is advanced by the number of bytes copied.
///
/// The copy is performed through a 4 096-byte kernel stack bounce buffer
/// (`kbuf`) that is never exposed to user space.  The destination `out_fd`
/// is always written at its current file position, which is advanced.
///
/// # Errors (returned as negative errno)
///
/// - `-9`  EBADF  — `in_fd` or `out_fd` is not open.
/// - `-14` EFAULT — `offset_ptr` is non-null but falls in kernel space.
/// - `-22` EINVAL — either fd's backend is not a `RamfsFile`.
/// - `-5`  EIO    — the VFS is uninitialised (global state missing).
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.
pub unsafe fn sys_sendfile(out_fd: u64, in_fd: u64, offset_ptr: u64, count: u64) -> i64 {
    // Validate the optional offset pointer: if non-null it must be a
    // readable/writable user-space address.
    if offset_ptr != 0 && offset_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }

    // Resolve both descriptors to RamfsFile inode numbers.
    // SAFETY: single-CPU SYSCALL context.
    let in_ino = match unsafe { fd_ramfs_ino(in_fd as i32) } {
        Ok(i) => i,
        Err(e) => return e,
    };
    let out_ino = match unsafe { fd_ramfs_ino(out_fd as i32) } {
        Ok(i) => i,
        Err(e) => return e,
    };

    // Determine the starting read offset inside in_fd.
    // If offset_ptr is non-null, read *offset_ptr; otherwise use the handle
    // position.  We snapshot it now; advancement happens after each chunk.
    let use_ptr_offset = offset_ptr != 0;
    let mut in_off: u64 = if use_ptr_offset {
        // SAFETY: offset_ptr validated above (non-null, user-space).
        let raw = unsafe { (offset_ptr as *const i64).read_volatile() };
        if raw < 0 {
            return -22; // EINVAL — negative offset
        }
        raw as u64
    } else {
        // SAFETY: single-CPU SYSCALL context.
        match unsafe { crate::fd_table::fd_get(in_fd as usize) } {
            Some(h) => h.offset,
            None => return -9, // EBADF
        }
    };

    // Current write offset inside out_fd (always from handle position).
    let mut out_off: u64 = match unsafe { crate::fd_table::fd_get(out_fd as usize) } {
        Some(h) => h.offset,
        None => return -9, // EBADF
    };

    let want = count as usize;
    let mut total_copied: usize = 0;
    let mut kbuf = [0u8; 4096];

    while total_copied < want {
        let chunk = (want - total_copied).min(kbuf.len());

        // ── Read chunk from in_fd via VFS ──────────────────────────
        let n_read = {
            let res = crate::state::with_global(|s| {
                let inode = match s.vfs.lookup_path_by_ino(in_ino) {
                    Some(i) => i,
                    None => return Err(oncrix_lib::Error::NotFound),
                };
                s.vfs.read_inode(&inode, in_off, &mut kbuf[..chunk])
            });
            match res {
                Some(Ok(n)) => n,
                Some(Err(oncrix_lib::Error::NotFound)) => return -9, // EBADF
                Some(Err(_)) => return -22,                          // EINVAL
                None => return -5,                                   // EIO
            }
        };

        if n_read == 0 {
            break; // EOF on in_fd
        }

        // ── Write chunk to out_fd via VFS ─────────────────────────
        let n_written = {
            let res = crate::state::with_global_mut(|s| {
                let inode = match s.vfs.lookup_path_by_ino(out_ino) {
                    Some(i) => i,
                    None => return Err(oncrix_lib::Error::NotFound),
                };
                s.vfs.write_inode(&inode, out_off, &kbuf[..n_read])
            });
            match res {
                Some(Ok(n)) => n,
                Some(Err(oncrix_lib::Error::NotFound)) => return -9, // EBADF
                Some(Err(_)) => return -22,                          // EINVAL
                None => return -5,                                   // EIO
            }
        };

        in_off += n_written as u64;
        out_off += n_written as u64;
        total_copied += n_written;
    }

    // ── Persist updated offsets ───────────────────────────────────
    if use_ptr_offset {
        // Advance *offset_ptr; do NOT touch in_fd's file position.
        // SAFETY: validated as non-null user-space pointer above.
        unsafe {
            (offset_ptr as *mut i64).write_volatile(in_off as i64);
        }
    } else {
        // Advance in_fd's file position.
        // SAFETY: single-CPU SYSCALL context.
        unsafe {
            if let Some(t) = crate::current::current_thread_mut() {
                if let Some(h) = t.fd_table.get_mut(in_fd as usize) {
                    h.offset = in_off;
                }
            }
        }
    }

    // Always advance out_fd's file position.
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        if let Some(t) = crate::current::current_thread_mut() {
            if let Some(h) = t.fd_table.get_mut(out_fd as usize) {
                h.offset = out_off;
            }
        }
    }

    total_copied as i64
}

// ── sys_copy_file_range ───────────────────────────────────────────

/// Kernel handler for `SYS_COPY_FILE_RANGE` (number 326).
///
/// `copy_file_range(fd_in, off_in, fd_out, off_out, len, flags)` — copy up
/// to `len` bytes from `fd_in` to `fd_out` entirely within the kernel.
/// Both descriptors must back a [`FileBackend::RamfsFile`].
///
/// **Offset semantics** (Linux `copy_file_range(2)`, POSIX future):
/// - `off_in` / `off_out` are `*mut i64`.  If non-null, the pointed-to
///   value supplies the read / write offset, which is updated on return; the
///   handle's file position is **not** changed.  If null, the handle's
///   current file position is used and advanced.
/// - `flags` is reserved; must be zero (non-zero → `-EINVAL`).
///
/// The copy proceeds through a 4 096-byte kernel stack bounce buffer.
/// Returns the number of bytes copied (≥ 0) or a negative errno.
///
/// # Errors (returned as negative errno)
///
/// - `-9`  EBADF  — `fd_in` or `fd_out` is not open.
/// - `-14` EFAULT — a non-null offset pointer falls in kernel space.
/// - `-22` EINVAL — either fd is not a `RamfsFile`, `flags != 0`, or a
///   supplied offset is negative.
/// - `-5`  EIO    — VFS uninitialised.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.
pub unsafe fn sys_copy_file_range(
    fd_in: u64,
    off_in_ptr: u64,
    fd_out: u64,
    off_out_ptr: u64,
    len: u64,
    flags: u64,
) -> i64 {
    // flags must be zero (Linux ABI).
    if flags != 0 {
        return -22; // EINVAL
    }

    // Validate optional offset pointers.
    if off_in_ptr != 0 && off_in_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    if off_out_ptr != 0 && off_out_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }

    // Resolve both descriptors to RamfsFile inode numbers.
    // SAFETY: single-CPU SYSCALL context.
    let in_ino = match unsafe { fd_ramfs_ino(fd_in as i32) } {
        Ok(i) => i,
        Err(e) => return e,
    };
    let out_ino = match unsafe { fd_ramfs_ino(fd_out as i32) } {
        Ok(i) => i,
        Err(e) => return e,
    };

    // Determine starting read offset.
    let use_in_ptr = off_in_ptr != 0;
    let mut in_off: u64 = if use_in_ptr {
        // SAFETY: validated above.
        let raw = unsafe { (off_in_ptr as *const i64).read_volatile() };
        if raw < 0 {
            return -22; // EINVAL
        }
        raw as u64
    } else {
        match unsafe { crate::fd_table::fd_get(fd_in as usize) } {
            Some(h) => h.offset,
            None => return -9, // EBADF
        }
    };

    // Determine starting write offset.
    let use_out_ptr = off_out_ptr != 0;
    let mut out_off: u64 = if use_out_ptr {
        // SAFETY: validated above.
        let raw = unsafe { (off_out_ptr as *const i64).read_volatile() };
        if raw < 0 {
            return -22; // EINVAL
        }
        raw as u64
    } else {
        match unsafe { crate::fd_table::fd_get(fd_out as usize) } {
            Some(h) => h.offset,
            None => return -9, // EBADF
        }
    };

    let want = len as usize;
    let mut total_copied: usize = 0;
    let mut kbuf = [0u8; 4096];

    while total_copied < want {
        let chunk = (want - total_copied).min(kbuf.len());

        // ── Read from fd_in ───────────────────────────────────────
        let n_read = {
            let res = crate::state::with_global(|s| {
                let inode = match s.vfs.lookup_path_by_ino(in_ino) {
                    Some(i) => i,
                    None => return Err(oncrix_lib::Error::NotFound),
                };
                s.vfs.read_inode(&inode, in_off, &mut kbuf[..chunk])
            });
            match res {
                Some(Ok(n)) => n,
                Some(Err(oncrix_lib::Error::NotFound)) => return -9,
                Some(Err(_)) => return -22,
                None => return -5,
            }
        };

        if n_read == 0 {
            break; // EOF
        }

        // ── Write to fd_out ───────────────────────────────────────
        let n_written = {
            let res = crate::state::with_global_mut(|s| {
                let inode = match s.vfs.lookup_path_by_ino(out_ino) {
                    Some(i) => i,
                    None => return Err(oncrix_lib::Error::NotFound),
                };
                s.vfs.write_inode(&inode, out_off, &kbuf[..n_read])
            });
            match res {
                Some(Ok(n)) => n,
                Some(Err(oncrix_lib::Error::NotFound)) => return -9,
                Some(Err(_)) => return -22,
                None => return -5,
            }
        };

        in_off += n_written as u64;
        out_off += n_written as u64;
        total_copied += n_written;
    }

    // ── Persist updated offsets ───────────────────────────────────
    if use_in_ptr {
        // SAFETY: validated as non-null user-space pointer above.
        unsafe { (off_in_ptr as *mut i64).write_volatile(in_off as i64) };
    } else {
        // SAFETY: single-CPU SYSCALL context.
        unsafe {
            if let Some(t) = crate::current::current_thread_mut() {
                if let Some(h) = t.fd_table.get_mut(fd_in as usize) {
                    h.offset = in_off;
                }
            }
        }
    }

    if use_out_ptr {
        // SAFETY: validated as non-null user-space pointer above.
        unsafe { (off_out_ptr as *mut i64).write_volatile(out_off as i64) };
    } else {
        // SAFETY: single-CPU SYSCALL context.
        unsafe {
            if let Some(t) = crate::current::current_thread_mut() {
                if let Some(h) = t.fd_table.get_mut(fd_out as usize) {
                    h.offset = out_off;
                }
            }
        }
    }

    total_copied as i64
}

// ── memfd_create ──────────────────────────────────────────────────

/// Monotonic counter for anonymous `memfd_create` backing paths.
static mut MEMFD_COUNTER: u32 = 0;

/// Kernel handler for `SYS_MEMFD_CREATE` (Linux number 319).
///
/// Creates an anonymous in-memory file and returns a new file descriptor
/// backed by a ramfs regular file. ONCRIX has no true anonymous inodes, so
/// a unique synthetic path `"/.memfd-<n>"` is created in the ramfs and the
/// fd is installed pointing at it.
///
/// `flags`: `MFD_CLOEXEC` (1) sets `FD_CLOEXEC`; `MFD_ALLOW_SEALING` (2) is
/// accepted and ignored; any other bit yields `-EINVAL`. The user `name`
/// argument is validated but only used for diagnostics (the backing path
/// uses the counter for uniqueness).
///
/// Returns the new fd, or `-EINVAL` / `-EFAULT` / `-ENFILE` / `-EMFILE`.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path. `name` must be
/// a NUL-terminated user string.
pub unsafe fn sys_memfd_create(name: u64, flags: u32) -> i64 {
    /// `MFD_CLOEXEC` — set `FD_CLOEXEC` on the new fd.
    const MFD_CLOEXEC: u32 = 1;
    /// `MFD_ALLOW_SEALING` — permit file seals (accepted, ignored).
    const MFD_ALLOW_SEALING: u32 = 2;

    if flags & !(MFD_CLOEXEC | MFD_ALLOW_SEALING) != 0 {
        return -22; // EINVAL — unknown flag bits
    }
    if name == 0 || name >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }

    // Build a unique backing path "/.memfd-<n>".
    let mut path = [0u8; 32];
    let prefix = b"/.memfd-";
    let mut len = prefix.len();
    path[..len].copy_from_slice(prefix);
    // SAFETY: single-CPU SYSCALL context; MEMFD_COUNTER not concurrently used.
    let n = unsafe {
        let p = &raw mut MEMFD_COUNTER;
        *p = (*p).wrapping_add(1);
        *p
    };
    // Append the decimal counter.
    let mut digits = [0u8; 10];
    let mut dlen = 0;
    let mut v = n;
    if v == 0 {
        digits[dlen] = b'0';
        dlen += 1;
    }
    while v > 0 {
        digits[dlen] = b'0' + (v % 10) as u8;
        dlen += 1;
        v /= 10;
    }
    for i in 0..dlen {
        path[len] = digits[dlen - 1 - i];
        len += 1;
    }

    // Create the backing ramfs file and resolve its inode.
    let ino = crate::state::with_global_mut(|s| {
        s.vfs.create_file(&path[..len], b"")?;
        s.vfs.lookup_path(&path[..len]).map(|inode| inode.ino)
    });
    let ino = match ino {
        Some(Ok(i)) => i,
        Some(Err(oncrix_lib::Error::OutOfMemory)) => return -23, // ENFILE
        Some(Err(_)) => return -22,                              // EINVAL
        None => return -5,                                       // EIO
    };

    // Build a RDWR RamfsFile handle, honouring MFD_CLOEXEC.
    let mut hflags = crate::fd_table::HandleFlags::RDWR.0;
    if flags & MFD_CLOEXEC != 0 {
        hflags |= crate::fd_table::HandleFlags::FD_CLOEXEC_BIT;
    }
    let handle = crate::fd_table::FileHandle {
        backend: crate::fd_table::FileBackend::RamfsFile { ino },
        offset: 0,
        flags: crate::fd_table::HandleFlags(hflags),
    };
    // SAFETY: single-CPU SYSCALL context.
    match unsafe { crate::fd_table::fd_install(handle) } {
        Ok(fd) => fd as i64,
        Err(_) => -24, // EMFILE
    }
}
