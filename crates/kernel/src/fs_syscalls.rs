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
