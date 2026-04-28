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
//! [`FileBackend`] distinguishes between the backends available:
//!
//! - [`FileBackend::Console`] — reads return 0, writes forward to COM1 serial.
//! - [`FileBackend::RamfsFile`] — backed by a VFS inode in the global ramfs.
//! - [`FileBackend::Pipe`] — one end of an anonymous pipe ring buffer.
//! - [`FileBackend::Socket`] — a Unix-domain socket handle.
//!
//! # POSIX.1-2024 references
//!
//! - `open(3p)` — fd allocation, lowest-available rule.
//! - `close(3p)` — fd de-allocation.
//! - `lseek(3p)` — `SEEK_SET`/`SEEK_CUR`/`SEEK_END` semantics.
//! - `pipe(3p)` — pipe creation and read/write semantics.
//! - `socket(3p)` — socket creation and I/O.

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
    /// Reads block until a byte is available from the keyboard ring buffer.
    /// Writes forward bytes to the UART via the existing serial path.
    Console,

    /// A regular file (or directory) in the ramfs.
    ///
    /// The inode number is stable for the lifetime of the file.
    RamfsFile {
        /// Inode number in the global ramfs.
        ino: InodeNumber,
    },

    /// One end of an anonymous pipe.
    ///
    /// The `ring_id` indexes into `pipe::PIPE_TABLE`; `is_write_end`
    /// distinguishes the write end (producer) from the read end (consumer).
    Pipe {
        /// Index into the global pipe ring table.
        ring_id: u32,
        /// `true` for the write end; `false` for the read end.
        is_write_end: bool,
    },

    /// A Unix-domain socket handle.
    ///
    /// The `handle_id` indexes into `socket::SOCKET_TABLE`.
    Socket {
        /// Index into the global socket registry.
        handle_id: u32,
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
/// Offset is meaningful only for `RamfsFile`; console/pipe/socket ignore it.
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
/// In addition to releasing the fd slot, propagates close semantics to
/// the underlying backend:
/// - [`FileBackend::Pipe`] — marks the appropriate pipe end as closed,
///   potentially freeing the ring slot when both ends are shut.
/// - [`FileBackend::Socket`] — closes the socket and releases its slot.
///
/// Returns `Err(InvalidArgument)` (EBADF) if the fd is not open.
///
/// # Safety
///
/// Same as [`fd_install`].
pub unsafe fn fd_close(fd: usize) -> Result<()> {
    // Snapshot the backend before releasing the slot.
    // SAFETY: single-CPU SYSCALL context.
    let backend = unsafe {
        #[allow(static_mut_refs)]
        CURRENT_FD_TABLE.get(fd).map(|h| h.backend)
    };

    // Release the fd slot.
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        CURRENT_FD_TABLE.close(fd)?;
    }

    // Propagate close to the backend resource.
    match backend {
        Some(FileBackend::Pipe {
            ring_id,
            is_write_end,
        }) => {
            // SAFETY: single-CPU SYSCALL context; pipe table exclusively owned here.
            unsafe {
                if is_write_end {
                    crate::pipe::pipe_close_write(ring_id);
                } else {
                    crate::pipe::pipe_close_read(ring_id);
                }
            }
        }
        Some(FileBackend::Socket { handle_id }) => {
            // SAFETY: single-CPU SYSCALL context.
            unsafe { crate::socket::socket_close(handle_id) }
        }
        _ => {}
    }

    Ok(())
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
/// - [`FileBackend::Pipe`] — pushes bytes into the pipe ring buffer.
/// - [`FileBackend::Socket`] — sends bytes through the socket.
///
/// Returns the number of bytes written (>= 0) or a negative errno:
/// - `-9` (`EBADF`) — fd is not open.
/// - `-14` (`EFAULT`) — `buf_ptr` is NULL or in kernel space.
/// - `-22` (`EINVAL`) — backend returned an error.
/// - `-32` (`EPIPE`) — pipe read end is closed.
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
                        (off, off)
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
        FileBackend::Pipe {
            ring_id,
            is_write_end,
        } => {
            if !is_write_end {
                return -9; // EBADF — cannot write to read end
            }
            // Copy user bytes into kernel buffer, then push into ring.
            let mut kbuf = [0u8; 4096];
            // SAFETY: `buf_ptr` validated above; reading `count` bytes.
            unsafe {
                let ptr = buf_ptr as *const u8;
                for (i, b) in kbuf[..count].iter_mut().enumerate() {
                    *b = ptr.add(i).read_volatile();
                }
            }
            // Blocking write: spin-yield until all bytes are pushed or read end is closed.
            let mut written = 0usize;
            loop {
                // SAFETY: Single-CPU SYSCALL context.
                let ring = unsafe {
                    match crate::pipe::pipe_get_mut(ring_id) {
                        Some(r) => r,
                        None => return -32, // EPIPE — slot gone
                    }
                };
                if !ring.read_open {
                    return -32; // EPIPE
                }
                written += ring.push(&kbuf[written..count]);
                if written >= count {
                    return written as i64;
                }
                // Buffer temporarily full — yield and retry.
                // SAFETY: SYSCALL context; yield_now is documented for this.
                unsafe {
                    let _ = crate::current::yield_now();
                }
            }
        }
        FileBackend::Socket { handle_id } => {
            // Copy user bytes into kernel buffer, then send via socket.
            let mut kbuf = [0u8; 4096];
            // SAFETY: `buf_ptr` validated above; reading `count` bytes.
            unsafe {
                let ptr = buf_ptr as *const u8;
                for (i, b) in kbuf[..count].iter_mut().enumerate() {
                    *b = ptr.add(i).read_volatile();
                }
            }
            loop {
                // SAFETY: Single-CPU SYSCALL context.
                let result = unsafe { crate::socket::socket_send(handle_id, &kbuf[..count]) };
                match result {
                    Ok(n) => return n as i64,
                    Err(oncrix_lib::Error::WouldBlock) => {
                        // Peer buffer full — yield and retry.
                        unsafe {
                            let _ = crate::current::yield_now();
                        }
                    }
                    Err(_) => return -22, // EINVAL
                }
            }
        }
    }
}

/// Read up to `count` bytes from fd `fd` into user-space buffer `buf_ptr`.
///
/// Dispatches to the appropriate backend:
/// - [`FileBackend::Console`] — blocks until at least one byte is available.
/// - [`FileBackend::RamfsFile`] — reads from the ramfs inode at the
///   current offset, advancing the offset afterwards.
/// - [`FileBackend::Pipe`] — pops bytes from the pipe ring buffer.
/// - [`FileBackend::Socket`] — receives bytes from the socket.
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
            // POSIX.1-2024 read(3p) on a tty-like device: block until
            // at least one byte is available, then return that byte
            // (and any further bytes already buffered up to `count`
            // or the first `\n`, whichever comes first). The keyboard
            // IRQ handler is the producer that fills `STDIN_BUF`; we
            // are the consumer.
            let user_ptr = buf_ptr as *mut u8;
            let mut written = 0usize;
            loop {
                // SAFETY: single-CPU SYSCALL context; the IRQ handler
                // runs with IF=0 so we cannot race against the
                // producer here. `console_pop_byte` upholds the
                // documented invariant.
                let next = unsafe { crate::console::console_pop_byte() };
                match next {
                    Some(b) => {
                        // SAFETY: `buf_ptr` validated above. We have
                        // written `written < count` bytes so far.
                        unsafe { user_ptr.add(written).write_volatile(b) };
                        written += 1;
                        if b == b'\n' || written >= count {
                            return written as i64;
                        }
                    }
                    None => {
                        if written > 0 {
                            // Hand the partial line back so the user
                            // can act on whatever has arrived so far
                            // (matches Linux tty behaviour).
                            return written as i64;
                        }
                        // Nothing yet — yield the CPU and retry.
                        // SAFETY: interrupts-off SYSCALL context;
                        // yield_now is documented to require it.
                        unsafe {
                            let _ = crate::current::yield_now();
                        }
                    }
                }
            }
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
        FileBackend::Pipe {
            ring_id,
            is_write_end,
        } => {
            if is_write_end {
                return -9; // EBADF — cannot read from write end
            }
            let user_ptr = buf_ptr as *mut u8;
            loop {
                // SAFETY: Single-CPU SYSCALL context.
                let ring = unsafe {
                    match crate::pipe::pipe_get_mut(ring_id) {
                        Some(r) => r,
                        None => return -9, // slot gone
                    }
                };
                let mut kbuf = [0u8; 4096];
                let n = ring.pop(&mut kbuf[..count]);
                if n > 0 {
                    // SAFETY: `buf_ptr` validated above; writing `n` bytes.
                    unsafe {
                        let ptr = user_ptr;
                        for (i, &byte) in kbuf.iter().take(n).enumerate() {
                            ptr.add(i).write_volatile(byte);
                        }
                    }
                    return n as i64;
                }
                // Buffer empty — check if write end is closed (EOF).
                if !ring.write_open {
                    return 0; // POSIX EOF
                }
                // No data yet — yield and retry.
                // SAFETY: SYSCALL context; yield_now documented for this.
                unsafe {
                    let _ = crate::current::yield_now();
                }
            }
        }
        FileBackend::Socket { handle_id } => {
            let user_ptr = buf_ptr as *mut u8;
            loop {
                let mut kbuf = [0u8; 4096];
                // SAFETY: Single-CPU SYSCALL context.
                let result = unsafe { crate::socket::socket_recv(handle_id, &mut kbuf[..count]) };
                match result {
                    Ok(n) if n > 0 => {
                        // SAFETY: `buf_ptr` validated above; writing `n` bytes.
                        unsafe {
                            for (i, &byte) in kbuf.iter().take(n).enumerate() {
                                user_ptr.add(i).write_volatile(byte);
                            }
                        }
                        return n as i64;
                    }
                    Ok(_) | Err(oncrix_lib::Error::WouldBlock) => {
                        // No data available — yield and retry.
                        unsafe {
                            let _ = crate::current::yield_now();
                        }
                    }
                    Err(_) => return -22, // EINVAL
                }
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
/// - `-29` (`ESPIPE`) — fd is not seekable (console, pipe, or socket).
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
        FileBackend::Console => -29,       // ESPIPE — not seekable
        FileBackend::Pipe { .. } => -29,   // ESPIPE — pipes not seekable
        FileBackend::Socket { .. } => -29, // ESPIPE — sockets not seekable
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
