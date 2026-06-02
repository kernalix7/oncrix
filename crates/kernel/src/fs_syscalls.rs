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
        let len = path.len().min(MAX_PATH);
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
    let copy_path = path.len().min(MAX_PATH - out);
    abs_buf[out..out + copy_path].copy_from_slice(&path[..copy_path]);
    out += copy_path;
    if out > MAX_PATH {
        return Err(-36); // ENAMETOOLONG
    }
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
