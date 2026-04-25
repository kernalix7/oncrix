// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-process file descriptor table for the ONCRIX kernel.
//!
//! This module defines [`FileHandle`] — a lightweight per-fd record holding
//! the backend type, current offset, and open flags — and [`KernelFdTable`]
//! — a fixed-size array mapping fd numbers to open handles.
//!
//! A global static [`CURRENT_FD_TABLE`] is used for the single running
//! process (Phase 12 simplification; a real kernel attaches one per-thread).
//! Access is safe because all SYSCALL dispatch runs on a single CPU with
//! interrupts effectively disabled (FMASK cleared IF on SYSCALL entry).
//!
//! # File backends
//!
//! [`FileBackend`] distinguishes between the two backends available in
//! Phase 12:
//!
//! - [`FileBackend::Console`] — reads return 0, writes forward to COM1 serial.
//! - [`FileBackend::RamfsFile`] — backed by a VFS inode in the global ramfs.
//!
//! # POSIX.1-2024 references
//!
//! - `open(3p)` — fd allocation, lowest-available rule.
//! - `close(3p)` — fd de-allocation.
//! - `lseek(3p)` — `SEEK_SET`/`SEEK_CUR`/`SEEK_END` semantics.

use oncrix_hal::arch::x86_64::uart::{COM1, Uart16550};
use oncrix_hal::serial::SerialPort;
use oncrix_lib::{Error, Result};
use oncrix_vfs::inode::{Inode, InodeNumber};

// ── Constants ─────────────────────────────────────────────────────

/// Maximum number of open file descriptors per process (POSIX OPEN_MAX).
///
/// Conservatively small for Phase 12; Linux defaults to 1024.
pub const MAX_FDS: usize = 32;

// ── FileBackend ───────────────────────────────────────────────────

/// The backing resource for an open file description.
///
/// Determines how read and write operations are dispatched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileBackend {
    /// The kernel console — backed by COM1 serial output.
    ///
    /// Reads always return 0 (no data / would block).
    /// Writes forward bytes to the UART via the existing serial path.
    Console,

    /// A regular file (or directory) in the ramfs.
    ///
    /// The inode number is stable for the lifetime of the file.
    RamfsFile {
        /// Inode number in the global ramfs.
        ino: InodeNumber,
    },
}

// ── Open flags ────────────────────────────────────────────────────

/// Per-fd status flags stored alongside each open file description.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandleFlags(pub u32);

impl HandleFlags {
    /// No flags.
    pub const RDONLY: Self = Self(0);
    /// Write-only.
    pub const WRONLY: Self = Self(1);
    /// Read-write.
    pub const RDWR: Self = Self(2);
    /// Append mode: writes always go to EOF.
    pub const APPEND: Self = Self(0o2000);

    /// Return `true` if writing is allowed (O_WRONLY or O_RDWR).
    pub const fn is_writable(self) -> bool {
        (self.0 & 0b11) != 0
    }

    /// Return `true` if reading is allowed (not O_WRONLY).
    pub const fn is_readable(self) -> bool {
        (self.0 & 0b11) != 1
    }

    /// Return `true` if O_APPEND is set.
    pub const fn is_append(self) -> bool {
        (self.0 & 0o2000) != 0
    }
}

// ── FileHandle ────────────────────────────────────────────────────

/// An open file description.
///
/// Tracks the backing resource, current byte offset, and open flags.
/// Offset is meaningful only for `RamfsFile`; console ignores it.
#[derive(Debug, Clone, Copy)]
pub struct FileHandle {
    /// What backs this file description.
    pub backend: FileBackend,
    /// Current seek offset (bytes from file start).
    pub offset: u64,
    /// Open mode flags.
    pub flags: HandleFlags,
}

impl FileHandle {
    /// Create a console handle (used for fd 0, 1, 2).
    pub const fn console() -> Self {
        Self {
            backend: FileBackend::Console,
            offset: 0,
            flags: HandleFlags::RDWR,
        }
    }

    /// Create a ramfs file handle.
    pub const fn ramfs_file(inode: &Inode, flags: HandleFlags) -> Self {
        Self {
            backend: FileBackend::RamfsFile { ino: inode.ino },
            offset: 0,
            flags,
        }
    }
}

// ── KernelFdTable ─────────────────────────────────────────────────

/// Per-process file descriptor table.
///
/// Fixed-size array of [`MAX_FDS`] slots. Slot index == fd number.
/// The lowest free slot is allocated on each `install` call
/// (POSIX lowest-available-fd rule).
pub struct KernelFdTable {
    /// Open file description slots.
    slots: [Option<FileHandle>; MAX_FDS],
}

impl KernelFdTable {
    /// Create an empty fd table.
    pub const fn new() -> Self {
        const NONE: Option<FileHandle> = None;
        Self {
            slots: [NONE; MAX_FDS],
        }
    }

    /// Install standard I/O file descriptors (0=stdin, 1=stdout, 2=stderr)
    /// all pointing at the console backend.
    ///
    /// Called once for the init process and once for each child created
    /// by fork (the child inherits the console fds).
    pub fn install_stdio(&mut self) {
        self.slots[0] = Some(FileHandle::console());
        self.slots[1] = Some(FileHandle::console());
        self.slots[2] = Some(FileHandle::console());
    }

    /// Allocate the lowest available fd for `handle`.
    ///
    /// Returns `Err(OutOfMemory)` if the table is full (all
    /// [`MAX_FDS`] slots are occupied — maps to `EMFILE`).
    pub fn install(&mut self, handle: FileHandle) -> Result<usize> {
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(handle);
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory) // EMFILE
    }

    /// Return a shared reference to the handle at `fd`.
    ///
    /// Returns `None` if `fd` is out of range or not open.
    pub fn get(&self, fd: usize) -> Option<&FileHandle> {
        self.slots.get(fd).and_then(|s| s.as_ref())
    }

    /// Return a mutable reference to the handle at `fd`.
    ///
    /// Returns `None` if `fd` is out of range or not open.
    pub fn get_mut(&mut self, fd: usize) -> Option<&mut FileHandle> {
        self.slots.get_mut(fd).and_then(|s| s.as_mut())
    }

    /// Close fd `fd`, releasing its slot.
    ///
    /// Returns `Err(InvalidArgument)` if the fd is not open (`EBADF`).
    pub fn close(&mut self, fd: usize) -> Result<()> {
        let slot = self.slots.get_mut(fd).ok_or(Error::InvalidArgument)?;
        if slot.is_none() {
            return Err(Error::InvalidArgument); // EBADF
        }
        *slot = None;
        Ok(())
    }
}

impl Default for KernelFdTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── Global fd table (single-process Phase 12) ─────────────────────

/// Global fd table for the current process.
///
/// Phase 12 simplification: a single process runs at a time, so a
/// single static table is sufficient. SMP / multi-process support
/// will require a per-thread pointer (stored in Thread or a per-CPU
/// variable) and a proper refcount; that upgrade is deferred.
///
/// # Safety invariant
///
/// Accessed exclusively from the SYSCALL dispatch path where the
/// single CPU is in ring 0 with interrupts logically disabled
/// (FMASK cleared IF on SYSCALL entry). No concurrent mutation
/// is possible on single-CPU builds.
// SAFETY: see module-level note. Accessed only from single-CPU
// interrupt-disabled SYSCALL context.
static mut CURRENT_FD_TABLE: KernelFdTable = KernelFdTable::new();

/// Install a [`FileHandle`] in the current process's fd table,
/// returning the assigned fd number.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU,
/// interrupts effectively disabled).
pub unsafe fn fd_install(handle: FileHandle) -> Result<usize> {
    // SAFETY: single-CPU SYSCALL context; no aliased access.
    unsafe {
        #[allow(static_mut_refs)]
        CURRENT_FD_TABLE.install(handle)
    }
}

/// Retrieve a shared reference to the handle for `fd` in the current
/// process's fd table.
///
/// Returns `None` if `fd` is not open or out of range.
///
/// # Safety
///
/// Same as [`fd_install`].
pub unsafe fn fd_get(fd: usize) -> Option<FileHandle> {
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        CURRENT_FD_TABLE.get(fd).copied()
    }
}

/// Retrieve a mutable reference to the handle for `fd` in the current
/// process's fd table.
///
/// Returns `None` if `fd` is not open or out of range.
///
/// # Safety
///
/// Same as [`fd_install`].
pub unsafe fn fd_get_mut(fd: usize) -> Option<&'static mut FileHandle> {
    // SAFETY: single-CPU SYSCALL context; sole accessor.
    unsafe {
        #[allow(static_mut_refs)]
        CURRENT_FD_TABLE.get_mut(fd)
    }
}

/// Close `fd` in the current process's fd table.
///
/// Returns `Err(InvalidArgument)` (EBADF) if the fd is not open.
///
/// # Safety
///
/// Same as [`fd_install`].
pub unsafe fn fd_close(fd: usize) -> Result<()> {
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        CURRENT_FD_TABLE.close(fd)
    }
}

/// Install the standard I/O fds (0/1/2 = console) in the current
/// process's fd table.
///
/// Must be called during init-process setup and (for Phase 12 single
/// shared table) is effectively idempotent.
///
/// # Safety
///
/// Same as [`fd_install`].
pub unsafe fn install_stdio() {
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        CURRENT_FD_TABLE.install_stdio();
    }
}

// ── I/O dispatch ─────────────────────────────────────────────────

/// Write `count` bytes from the user-space buffer `buf_ptr` to fd `fd`.
///
/// Dispatches to the appropriate backend:
/// - [`FileBackend::Console`] — forwards bytes to COM1 serial.
/// - [`FileBackend::RamfsFile`] — writes to the ramfs inode at the
///   current offset, advancing the offset afterwards.
///
/// Returns the number of bytes written (>= 0) or a negative errno:
/// - `-9` (`EBADF`) — fd is not open.
/// - `-14` (`EFAULT`) — `buf_ptr` is NULL or in kernel space.
/// - `-22` (`EINVAL`) — ramfs returned an error.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path. `buf_ptr` must be
/// a non-null user-space address readable for at least `count` bytes.
pub unsafe fn dispatch_write(fd: usize, buf_ptr: u64, count: u64) -> i64 {
    // Basic user-space pointer validation.
    if buf_ptr == 0 || buf_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    let count = count.min(4096) as usize; // cap at 4 KiB per write
    if count == 0 {
        return 0;
    }

    // SAFETY: fd_get is safe to call from SYSCALL dispatch.
    let handle = unsafe {
        match fd_get(fd) {
            Some(h) => h,
            None => return -9, // EBADF
        }
    };

    match handle.backend {
        FileBackend::Console => {
            // Forward bytes to COM1 serial, byte-by-byte.
            let mut serial = Uart16550::new(COM1);
            // SAFETY: `buf_ptr` is a non-null user-space address validated above.
            let written = unsafe {
                let ptr = buf_ptr as *const u8;
                let mut n = 0usize;
                while n < count {
                    let byte = ptr.add(n).read_volatile();
                    if serial.write_byte(byte).is_err() {
                        break;
                    }
                    n += 1;
                }
                n
            };
            written as i64
        }
        FileBackend::RamfsFile { ino } => {
            // Copy bytes into a kernel buffer, then write to ramfs.
            // We process in chunks of up to 4 KiB (already capped above).
            let mut kbuf = [0u8; 4096];
            // SAFETY: `buf_ptr` validated above; reading `count` bytes.
            unsafe {
                let ptr = buf_ptr as *const u8;
                for (i, b) in kbuf[..count].iter_mut().enumerate() {
                    *b = ptr.add(i).read_volatile();
                }
            }

            // Retrieve the current offset and write.
            let (offset, new_offset) = unsafe {
                #[allow(static_mut_refs)]
                match CURRENT_FD_TABLE.get_mut(fd) {
                    Some(h) => {
                        let off = if h.flags.is_append() {
                            // O_APPEND: look up inode size via the global VFS.
                            crate::state::with_global(|s| s.vfs.inode_size(ino))
                                .flatten()
                                .unwrap_or(0)
                        } else {
                            h.offset
                        };
                        (off, off) // new_offset is updated after write
                    }
                    None => return -9, // EBADF
                }
            };
            let _ = new_offset;

            // Perform the VFS write via the global kernel state.
            let written = crate::state::with_global_mut(|s| {
                let inode_val = match s.vfs.lookup_path_by_ino(ino) {
                    Some(i) => i,
                    None => return Err(Error::NotFound),
                };
                s.vfs.write_inode(&inode_val, offset, &kbuf[..count])
            });

            match written {
                Some(Ok(n)) => {
                    // Advance the offset.
                    // SAFETY: single-CPU SYSCALL context.
                    unsafe {
                        #[allow(static_mut_refs)]
                        if let Some(h) = CURRENT_FD_TABLE.get_mut(fd) {
                            h.offset = offset + n as u64;
                        }
                    }
                    n as i64
                }
                Some(Err(_)) => -22, // EINVAL
                None => -9,          // EBADF (VFS not initialised)
            }
        }
    }
}

/// Read up to `count` bytes from fd `fd` into user-space buffer `buf_ptr`.
///
/// Dispatches to the appropriate backend:
/// - [`FileBackend::Console`] — returns 0 (no data available).
/// - [`FileBackend::RamfsFile`] — reads from the ramfs inode at the
///   current offset, advancing the offset afterwards.
///
/// Returns the number of bytes read (0 = EOF) or a negative errno:
/// - `-9` (`EBADF`) — fd is not open.
/// - `-14` (`EFAULT`) — `buf_ptr` is NULL or in kernel space.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path. `buf_ptr` must be
/// a non-null user-space address writable for at least `count` bytes.
pub unsafe fn dispatch_read(fd: usize, buf_ptr: u64, count: u64) -> i64 {
    // Basic user-space pointer validation.
    if buf_ptr == 0 || buf_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    let count = count.min(4096) as usize;
    if count == 0 {
        return 0;
    }

    // SAFETY: fd_get is safe from SYSCALL dispatch.
    let handle = unsafe {
        match fd_get(fd) {
            Some(h) => h,
            None => return -9, // EBADF
        }
    };

    match handle.backend {
        FileBackend::Console => {
            // Console read: no data available (returns 0 = would block).
            // POSIX.1-2024 read(3p): returns 0 at EOF / no data.
            0
        }
        FileBackend::RamfsFile { ino } => {
            let offset = handle.offset;
            let mut kbuf = [0u8; 4096];

            // Read from ramfs.
            let result = crate::state::with_global(|s| {
                let inode_val = match s.vfs.lookup_path_by_ino(ino) {
                    Some(i) => i,
                    None => return Err(Error::NotFound),
                };
                s.vfs.read_inode(&inode_val, offset, &mut kbuf[..count])
            });

            match result {
                Some(Ok(n)) => {
                    // Copy kernel buffer to user space.
                    // SAFETY: `buf_ptr` validated above; writing `n` bytes.
                    unsafe {
                        let ptr = buf_ptr as *mut u8;
                        for (i, byte) in kbuf.iter().take(n).enumerate() {
                            ptr.add(i).write_volatile(*byte);
                        }
                    }
                    // Advance the offset.
                    // SAFETY: single-CPU SYSCALL context.
                    unsafe {
                        #[allow(static_mut_refs)]
                        if let Some(h) = CURRENT_FD_TABLE.get_mut(fd) {
                            h.offset = offset + n as u64;
                        }
                    }
                    n as i64
                }
                Some(Err(_)) => -22, // EINVAL
                None => -9,          // EBADF
            }
        }
    }
}

/// POSIX `lseek(2)` — reposition the file offset.
///
/// `whence`:
/// - `0` (`SEEK_SET`) — set offset to `off`.
/// - `1` (`SEEK_CUR`) — add `off` to current offset.
/// - `2` (`SEEK_END`) — set offset to file size + `off`.
///
/// Returns the new offset on success, or a negative errno:
/// - `-9` (`EBADF`) — fd is not open.
/// - `-29` (`ESPIPE`) — fd is a console (not seekable).
/// - `-22` (`EINVAL`) — invalid whence or offset would be negative.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn dispatch_lseek(fd: usize, off: i64, whence: i32) -> i64 {
    // SAFETY: single-CPU SYSCALL context.
    let handle = unsafe {
        match fd_get(fd) {
            Some(h) => h,
            None => return -9, // EBADF
        }
    };

    match handle.backend {
        FileBackend::Console => -29, // ESPIPE — pipe/console not seekable
        FileBackend::RamfsFile { ino } => {
            let current_offset = handle.offset;

            let new_offset: i64 = match whence {
                0 => {
                    // SEEK_SET
                    if off < 0 {
                        return -22; // EINVAL
                    }
                    off
                }
                1 => {
                    // SEEK_CUR
                    (current_offset as i64).checked_add(off).unwrap_or(-1)
                }
                2 => {
                    // SEEK_END
                    let size = crate::state::with_global(|s| s.vfs.inode_size(ino))
                        .flatten()
                        .unwrap_or(0);
                    (size as i64).checked_add(off).unwrap_or(-1)
                }
                _ => return -22, // EINVAL — bad whence
            };

            if new_offset < 0 {
                return -22; // EINVAL — result would be negative
            }

            // Update the handle's offset.
            // SAFETY: single-CPU SYSCALL context.
            unsafe {
                #[allow(static_mut_refs)]
                if let Some(h) = CURRENT_FD_TABLE.get_mut(fd) {
                    h.offset = new_offset as u64;
                }
            }
            new_offset
        }
    }
}
