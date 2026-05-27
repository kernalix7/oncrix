// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-process file descriptor table for the ONCRIX kernel.
//!
//! The data types ([`FileBackend`], [`FileHandle`], [`KernelFdTable`]) live in
//! `oncrix_process::fd_table` and are re-exported here so callers do not need
//! to import from two crates.  The I/O dispatch functions and the syscall-level
//! helpers (`fd_install`, `fd_get`, `fd_close`, `fd_dup2`) live here because
//! they call into VFS, pipe, and socket subsystems.
//!
//! # Per-thread fd ownership
//!
//! Every [`oncrix_process::thread::Thread`] owns its `fd_table` field.
//! All helpers below retrieve the current thread via
//! [`crate::current::current_thread_mut`] and operate on its fd table.
//! For the very early-boot window before a thread exists, writes to fd 1/2
//! fall through to the COM1 serial fallback.
//!
//! # POSIX.1-2024 references
//!
//! - `open(3p)` — fd allocation, lowest-available rule.
//! - `close(3p)` — fd de-allocation.
//! - `lseek(3p)` — `SEEK_SET`/`SEEK_CUR`/`SEEK_END` semantics.
//! - `pipe(3p)` — pipe creation and read/write semantics.
//! - `dup2(3p)` — duplicate an fd.
//! - `fork(3p)` — "the child inherits copies of the parent's set of
//!   open file descriptors".

use oncrix_hal::arch::x86_64::uart::{COM1, Uart16550};
use oncrix_hal::serial::SerialPort;
use oncrix_lib::{Error, Result};

// Re-export the data types from oncrix_process so callers only import from here.
pub use oncrix_process::fd_table::{
    DevFileKind, FileBackend, FileHandle, HandleFlags, KernelFdTable, MAX_FDS, ProcFileKind,
};

// ── Current-thread fd table helpers ───────────────────────────────

/// Install a [`FileHandle`] in the current thread's fd table,
/// returning the assigned fd number.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU,
/// interrupts effectively disabled).
pub unsafe fn fd_install(handle: FileHandle) -> Result<usize> {
    // SAFETY: single-CPU SYSCALL context; caller guarantees no concurrent access.
    unsafe {
        match crate::current::current_thread_mut() {
            Some(t) => t.fd_table.install(handle),
            None => Err(Error::NotFound),
        }
    }
}

/// Retrieve a copy of the handle for `fd` in the current thread's fd table.
///
/// Returns `None` if `fd` is not open or out of range.
///
/// # Safety
///
/// Same as [`fd_install`].
pub unsafe fn fd_get(fd: usize) -> Option<FileHandle> {
    crate::current::current_thread().and_then(|t| t.fd_table.get(fd))
}

/// Retrieve a mutable reference to the handle for `fd` in the current
/// thread's fd table.
///
/// Returns `None` if `fd` is not open or out of range.
///
/// # Safety
///
/// Same as [`fd_install`].
pub unsafe fn fd_get_mut(fd: usize) -> Option<&'static mut FileHandle> {
    // SAFETY: single-CPU SYSCALL context; sole accessor.
    unsafe {
        crate::current::current_thread_mut()
            .and_then(|t| t.fd_table.get_mut(fd))
            // SAFETY: the returned reference borrows the thread's fd_table.
            // The 'static lifetime is an approximation valid within the
            // single-CPU SYSCALL dispatch window where no other code can
            // evict or modify the current thread.
            .map(|h| &mut *(h as *mut FileHandle))
    }
}

/// Close `fd` in the current thread's fd table.
///
/// Also propagates close semantics to the underlying backend
/// (pipe refcount / socket release).
///
/// Returns `Err(InvalidArgument)` (EBADF) if the fd is not open.
///
/// # Safety
///
/// Same as [`fd_install`].
pub unsafe fn fd_close(fd: usize) -> Result<()> {
    // Snapshot and remove in one step.
    // SAFETY: single-CPU SYSCALL context.
    let handle = unsafe {
        match crate::current::current_thread_mut() {
            Some(t) => t.fd_table.close(fd)?,
            None => return Err(Error::NotFound),
        }
    };

    // Propagate close to the backend resource.
    match handle.backend {
        FileBackend::Pipe {
            ring_id,
            is_write_end,
        } => {
            // SAFETY: single-CPU SYSCALL context; pipe table exclusively owned here.
            unsafe {
                if is_write_end {
                    crate::pipe::pipe_close_write(ring_id);
                } else {
                    crate::pipe::pipe_close_read(ring_id);
                }
            }
        }
        FileBackend::Socket { handle_id } => {
            // SAFETY: single-CPU SYSCALL context.
            unsafe { crate::socket::socket_close(handle_id) }
        }
        _ => {}
    }

    Ok(())
}

/// Duplicate `oldfd` onto `newfd`, atomically closing `newfd` first if open.
///
/// POSIX.1-2024 `dup2(3p)` semantics:
/// - If `oldfd` is not open, returns `-EBADF` and leaves `newfd` alone.
/// - If `oldfd == newfd` and `oldfd` is open, returns `newfd` (no-op).
/// - Otherwise closes `newfd` if open (propagating backend close), then
///   copies the handle from `oldfd` and returns `newfd`.
///
/// # Safety
///
/// Same as [`fd_install`].
pub unsafe fn fd_dup2(oldfd: usize, newfd: usize) -> i64 {
    // SAFETY: single-CPU SYSCALL context.
    let handle = unsafe {
        match fd_get(oldfd) {
            Some(h) => h,
            None => return -9, // EBADF
        }
    };

    if oldfd == newfd {
        return newfd as i64;
    }
    if newfd >= MAX_FDS {
        return -9; // EBADF
    }

    // Close newfd first (if open) so backends release resources.
    let newfd_open = crate::current::current_thread()
        .and_then(|t| t.fd_table.get(newfd))
        .is_some();
    if newfd_open {
        let _ = unsafe { fd_close(newfd) };
    }

    // Bump backend refcounts for the new alias.
    match handle.backend {
        FileBackend::Pipe {
            ring_id,
            is_write_end,
        } => {
            // SAFETY: single-CPU SYSCALL context.
            unsafe {
                if is_write_end {
                    crate::pipe::pipe_dup_write(ring_id);
                } else {
                    crate::pipe::pipe_dup_read(ring_id);
                }
            }
        }
        FileBackend::Console
        | FileBackend::RamfsFile { .. }
        | FileBackend::Socket { .. }
        | FileBackend::DevFile { .. }
        | FileBackend::ProcFile { .. } => {}
    }

    // SAFETY: single-CPU SYSCALL context.
    let result = unsafe {
        match crate::current::current_thread_mut() {
            Some(t) => t.fd_table.install_at(newfd, handle),
            None => return -9,
        }
    };

    match result {
        Ok(()) => newfd as i64,
        Err(_) => -9, // EBADF (out of range — unreachable: bounded above)
    }
}

/// Install the standard I/O fds (0/1/2 = console) in the current
/// thread's fd table.
///
/// # Safety
///
/// Same as [`fd_install`].
pub unsafe fn install_stdio() {
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        if let Some(t) = crate::current::current_thread_mut() {
            t.fd_table.install_stdio();
        }
    }
}

/// Open the FIFO inode `ino` and install a pipe-backed fd for it.
///
/// Wires a `/bin/mkfifo`-created FIFO node to the kernel pipe machinery:
/// the inode carries a lazily-allocated pipe `ring_id` (allocated here on
/// first open and persisted in the ramfs inode), so a writer and a reader
/// opening the same path share one ring buffer.
///
/// `flags` are the raw `open(2)` flags. `O_WRONLY` selects the write end;
/// anything else (`O_RDONLY`, `O_RDWR`) selects the read end. The matching
/// pipe end refcount is bumped so that `read`/`write` see the correct
/// EOF / `EPIPE` semantics and the ring frees when both ends close.
///
/// # POSIX.1-2024 `open(2)` FIFO blocking semantics
///
/// Without `O_NONBLOCK`:
/// - `O_RDONLY` blocks until a writer opens the same FIFO.
/// - `O_WRONLY` blocks until a reader opens the same FIFO.
///
/// With `O_NONBLOCK`:
/// - `O_RDONLY` returns immediately (success even with no writer).
/// - `O_WRONLY` returns `-ENXIO` (6) if no reader is currently open.
///
/// `O_RDWR` on a FIFO is a Linux extension that never blocks; it is treated
/// here as a read-end open.
///
/// Returns the assigned fd on success, or a negative errno:
/// `-ENFILE` (23) if no pipe slot is free, `-EMFILE` (24) if the fd table
/// is full, `-ENXIO` (6) for non-blocking `O_WRONLY` with no reader,
/// `-EINVAL` (22) if `ino` is not a FIFO, `-EIO` (5) if the VFS is
/// uninitialised.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU, interrupts
/// effectively disabled).
pub unsafe fn open_fifo(ino: oncrix_vfs::inode::InodeNumber, flags: u32) -> i64 {
    /// `O_NONBLOCK` flag bit (octal 04000), matching `oncrix_vfs::file_ops`.
    const O_NONBLOCK: u32 = 0o4000;

    // Resolve the FIFO's backing ring, allocating one on first open.
    let ring_id = crate::state::with_global_mut(|s| match s.vfs.fifo_ring_id(ino) {
        Ok(Some(id)) => Ok(id),
        Ok(None) => {
            // SAFETY: single-CPU SYSCALL context; pipe table exclusively owned here.
            let id = match unsafe { crate::pipe::pipe_alloc_fifo() } {
                Some(id) => id,
                None => return Err(Error::Busy), // ENFILE proxy — no pipe slots
            };
            s.vfs.set_fifo_ring_id(ino, id)?;
            Ok(id)
        }
        Err(e) => Err(e),
    });

    let ring_id = match ring_id {
        Some(Ok(id)) => id,
        Some(Err(Error::Busy)) => return -23, // ENFILE
        Some(Err(Error::InvalidArgument)) => return -22, // EINVAL — not a FIFO
        Some(Err(_)) => return -22,           // EINVAL
        None => return -5,                    // EIO — VFS not initialised
    };

    // O_WRONLY (bit 0 set, bit 1 clear) → write end; otherwise read end.
    let is_write_end = (flags & 0b11) == 1;
    let nonblock = (flags & O_NONBLOCK) != 0;

    // Non-blocking O_WRONLY with no reader currently attached → ENXIO,
    // before we bump any refcount.
    if is_write_end && nonblock {
        // SAFETY: single-CPU SYSCALL context.
        if unsafe { crate::pipe::pipe_peer_refs(ring_id, true) } == 0 {
            return -6; // ENXIO
        }
    }

    // SAFETY: single-CPU SYSCALL context; pipe table exclusively owned here.
    if !unsafe { crate::pipe::pipe_open_end(ring_id, is_write_end) } {
        return -5; // EIO — slot vanished (should not happen)
    }

    // Blocking open: wait until the peer end attaches. O_RDWR and any
    // O_NONBLOCK open skip the wait (peer presence not required to proceed).
    if !nonblock && (flags & 0b11) != 2 {
        loop {
            // SAFETY: single-CPU SYSCALL context.
            if unsafe { crate::pipe::pipe_peer_refs(ring_id, is_write_end) } > 0 {
                break;
            }
            // SAFETY: SYSCALL context; cooperative yield (same model as nanosleep).
            unsafe {
                let _ = crate::current::yield_now();
            }
        }
    }

    let handle = FileHandle {
        backend: FileBackend::Pipe {
            ring_id,
            is_write_end,
        },
        offset: 0,
        flags: HandleFlags(flags),
    };

    // SAFETY: single-CPU SYSCALL context.
    match unsafe { fd_install(handle) } {
        Ok(fd) => fd as i64,
        Err(_) => {
            // Roll back the refcount bump so the slot can free.
            // SAFETY: single-CPU SYSCALL context.
            unsafe {
                if is_write_end {
                    crate::pipe::pipe_close_write(ring_id);
                } else {
                    crate::pipe::pipe_close_read(ring_id);
                }
            }
            -24 // EMFILE
        }
    }
}

// ── fcntl ─────────────────────────────────────────────────────────

/// `fcntl(2)` command numbers (Linux/glibc ABI).
const F_DUPFD: i32 = 0;
/// Get the file-descriptor flags (`FD_CLOEXEC`).
const F_GETFD: i32 = 1;
/// Set the file-descriptor flags (`FD_CLOEXEC`).
const F_SETFD: i32 = 2;
/// Get the file-status flags and access mode.
const F_GETFL: i32 = 3;
/// Set the file-status flags (`O_APPEND` / `O_NONBLOCK`).
const F_SETFL: i32 = 4;
/// Like `F_DUPFD` but set `FD_CLOEXEC` on the new descriptor.
const F_DUPFD_CLOEXEC: i32 = 1030;

/// `FD_CLOEXEC` flag value as seen by user space (`fcntl.h`).
const FD_CLOEXEC: i32 = 1;

/// Kernel handler for `SYS_FCNTL` (Linux number 72).
///
/// POSIX.1-2024 `fcntl(2)` subset:
/// - `F_DUPFD` / `F_DUPFD_CLOEXEC` — duplicate `fd` to the lowest free
///   descriptor `>= arg`. The duplicate shares the open file description
///   (same backend / offset); `FD_CLOEXEC` is cleared (`F_DUPFD`) or set
///   (`F_DUPFD_CLOEXEC`) on the new fd.
/// - `F_GETFD` — return the `FD_CLOEXEC` descriptor flag (0 or 1).
/// - `F_SETFD` — set/clear `FD_CLOEXEC` from `arg`.
/// - `F_GETFL` — return the open flags (access mode + status flags).
/// - `F_SETFL` — set `O_APPEND` / `O_NONBLOCK` from `arg`; access-mode and
///   creation bits in `arg` are ignored (POSIX).
///
/// Returns the command-specific value on success or a negative errno:
/// `-EBADF` (9) if `fd` is not open, `-EINVAL` (22) for an unsupported
/// `cmd` or out-of-range `arg`, `-EMFILE` (24) if no descriptor is free.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU, interrupts
/// effectively disabled).
pub unsafe fn sys_fcntl(fd: usize, cmd: i32, arg: u64) -> i64 {
    // SAFETY: single-CPU SYSCALL context.
    let handle = unsafe {
        match fd_get(fd) {
            Some(h) => h,
            None => return -9, // EBADF
        }
    };

    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let min_fd = arg as usize;
            if min_fd >= MAX_FDS {
                return -22; // EINVAL
            }

            // The duplicate references the same backend; bump its refcount.
            match handle.backend {
                FileBackend::Pipe {
                    ring_id,
                    is_write_end,
                } => {
                    // SAFETY: single-CPU SYSCALL context.
                    unsafe {
                        if is_write_end {
                            crate::pipe::pipe_dup_write(ring_id);
                        } else {
                            crate::pipe::pipe_dup_read(ring_id);
                        }
                    }
                }
                FileBackend::Console
                | FileBackend::RamfsFile { .. }
                | FileBackend::Socket { .. }
                | FileBackend::DevFile { .. }
                | FileBackend::ProcFile { .. } => {}
            }

            // The new fd's FD_CLOEXEC is cleared for F_DUPFD, set for
            // F_DUPFD_CLOEXEC. The shared file-status flags are preserved.
            let mut dup = handle;
            let base = dup.flags.0 & !HandleFlags::FD_CLOEXEC_BIT;
            dup.flags = HandleFlags(if cmd == F_DUPFD_CLOEXEC {
                base | HandleFlags::FD_CLOEXEC_BIT
            } else {
                base
            });

            // SAFETY: single-CPU SYSCALL context.
            let installed = unsafe {
                match crate::current::current_thread_mut() {
                    Some(t) => t.fd_table.install_from(min_fd, dup),
                    None => return -9, // EBADF — no current thread
                }
            };
            match installed {
                Ok(newfd) => newfd as i64,
                Err(_) => {
                    // Roll back the backend refcount bump.
                    if let FileBackend::Pipe {
                        ring_id,
                        is_write_end,
                    } = handle.backend
                    {
                        // SAFETY: single-CPU SYSCALL context.
                        unsafe {
                            if is_write_end {
                                crate::pipe::pipe_close_write(ring_id);
                            } else {
                                crate::pipe::pipe_close_read(ring_id);
                            }
                        }
                    }
                    -24 // EMFILE
                }
            }
        }
        F_GETFD => {
            if handle.flags.is_cloexec() {
                FD_CLOEXEC as i64
            } else {
                0
            }
        }
        F_SETFD => {
            let set_cloexec = (arg as i32 & FD_CLOEXEC) != 0;
            // SAFETY: single-CPU SYSCALL context.
            unsafe {
                if let Some(h) = fd_get_mut(fd) {
                    if set_cloexec {
                        h.flags.0 |= HandleFlags::FD_CLOEXEC_BIT;
                    } else {
                        h.flags.0 &= !HandleFlags::FD_CLOEXEC_BIT;
                    }
                    0
                } else {
                    -9 // EBADF
                }
            }
        }
        F_GETFL => handle.flags.open_flags() as i64,
        F_SETFL => {
            // Only O_APPEND / O_NONBLOCK are honoured; access mode and
            // creation flags in `arg` are ignored (POSIX).
            let new_status = arg as u32 & HandleFlags::SETFL_MASK;
            // SAFETY: single-CPU SYSCALL context.
            unsafe {
                if let Some(h) = fd_get_mut(fd) {
                    // Preserve access mode, creation flags, and the reserved
                    // FD_CLOEXEC bit; replace only the settable status flags.
                    h.flags.0 = (h.flags.0 & !HandleFlags::SETFL_MASK) | new_status;
                    0
                } else {
                    -9 // EBADF
                }
            }
        }
        _ => -22, // EINVAL — unsupported command
    }
}

// ── poll ──────────────────────────────────────────────────────────

/// `poll(2)` event bits (Linux/POSIX `poll.h`).
const POLLIN: i16 = 0x0001;
/// The descriptor is ready for writing.
const POLLOUT: i16 = 0x0004;
/// An error condition (revents only). Reserved; not yet raised.
const _POLLERR: i16 = 0x0008;
/// The writer hung up (revents only).
const POLLHUP: i16 = 0x0010;
/// The fd value is not an open descriptor (revents only).
const POLLNVAL: i16 = 0x0020;

/// Maximum number of `pollfd` entries accepted in a single call.
const POLL_MAX_FDS: usize = 64;

/// PIT tick frequency (Hz) — matches `crate::time_syscalls::TIMER_HZ`.
const POLL_TIMER_HZ: u64 = 100;

/// Read the current PIT tick count for poll's timeout accounting.
///
/// # Safety
///
/// Single-CPU SYSCALL dispatch path; `PIT_TIMER` has no concurrent
/// mutation (timer IRQ runs with IF=0, SYSCALL entry clears IF via FMASK).
unsafe fn poll_now_ticks() -> u64 {
    use oncrix_hal::timer::Timer;
    // SAFETY: see fn-level note.
    unsafe {
        let pit_ptr = &raw const crate::arch::x86_64::init::PIT_TIMER;
        (*pit_ptr).current_ticks()
    }
}

/// Compute the `revents` for one `pollfd` given its requested `events`.
///
/// Returns the readiness bitmask: `POLLNVAL` for a closed/out-of-range fd,
/// otherwise the requested `POLLIN`/`POLLOUT` bits that are satisfiable plus
/// any `POLLHUP`. Regular files, `/dev`, and `/proc` always poll ready.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
unsafe fn poll_one(fd: usize, events: i16) -> i16 {
    // SAFETY: single-CPU SYSCALL context.
    let handle = match unsafe { fd_get(fd) } {
        Some(h) => h,
        None => return POLLNVAL,
    };

    let (readable, writable, hup) = match handle.backend {
        FileBackend::Pipe { ring_id, .. } => {
            // SAFETY: single-CPU SYSCALL context.
            unsafe { crate::pipe::pipe_poll(ring_id) }
        }
        FileBackend::Console => {
            // SAFETY: single-CPU SYSCALL context.
            let readable = unsafe { crate::console::console_has_byte() };
            (readable, true, false)
        }
        // Regular files, /dev/{null,zero}, and /proc always poll ready for
        // both reading and writing and never hang up.
        FileBackend::RamfsFile { .. }
        | FileBackend::DevFile { .. }
        | FileBackend::ProcFile { .. }
        | FileBackend::Socket { .. } => (true, true, false),
    };

    let mut revents = 0i16;
    if events & POLLIN != 0 && readable {
        revents |= POLLIN;
    }
    if events & POLLOUT != 0 && writable {
        revents |= POLLOUT;
    }
    // POLLHUP and POLLERR are reported regardless of the events mask.
    if hup {
        revents |= POLLHUP;
    }
    revents
}

/// Kernel handler for `SYS_POLL` (Linux number 7).
///
/// POSIX.1-2024 `poll(2)`: examines `nfds` `pollfd` structures at `fds_ptr`,
/// each `struct pollfd { fd: i32, events: i16, revents: i16 }` (8 bytes),
/// and reports per-fd readiness in `revents`.
///
/// `timeout_ms`: `< 0` blocks indefinitely; `0` performs a single
/// non-blocking scan; `> 0` blocks up to that many milliseconds. Blocking
/// uses cooperative `yield_now` polling (same model as `nanosleep`).
///
/// Readiness rules:
/// - `POLLIN` when a read would not block (pipe has data, console has input,
///   or a pipe writer has hung up so a read returns EOF).
/// - `POLLOUT` when a write would not block (pipe not full and a reader
///   remains; regular files / devices always writable).
/// - `POLLHUP` (revents-only) when a pipe's write end is closed.
/// - `POLLNVAL` (revents-only) for an fd that is not open.
/// - A negative `fd` entry is skipped and its `revents` cleared to 0.
///
/// Returns the number of fds with a non-zero `revents`, `0` on timeout, or
/// a negative errno: `-EFAULT` (14) for a bad pointer, `-EINVAL` (22) if
/// `nfds` exceeds [`POLL_MAX_FDS`].
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU, interrupts
/// effectively disabled). `fds_ptr` must address `nfds` writable `pollfd`
/// structs in user space.
pub unsafe fn sys_poll(fds_ptr: u64, nfds: u64, timeout_ms: i64) -> i64 {
    let nfds = nfds as usize;
    if nfds == 0 {
        // No descriptors: poll degenerates to a (bounded) sleep. Treat as an
        // immediate timeout return of 0 to avoid an unbounded spin.
        return 0;
    }
    if nfds > POLL_MAX_FDS {
        return -22; // EINVAL
    }
    if fds_ptr == 0 || fds_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }

    // Snapshot the requested (fd, events) pairs from user space once; the
    // POSIX contract forbids modifying the fd/events members, so we only
    // write back revents.
    let mut fds = [0i32; POLL_MAX_FDS];
    let mut events = [0i16; POLL_MAX_FDS];
    // SAFETY: `fds_ptr` validated user-canonical above; each entry is 8 bytes.
    unsafe {
        let base = fds_ptr as *const u8;
        for i in 0..nfds {
            let entry = base.add(i * 8);
            fds[i] = (entry as *const i32).read_volatile();
            events[i] = (entry.add(4) as *const i16).read_volatile();
        }
    }

    // Compute the deadline in PIT ticks for a positive timeout.
    let deadline = if timeout_ms > 0 {
        let ticks = (timeout_ms as u64).saturating_mul(POLL_TIMER_HZ) / 1000;
        // SAFETY: single-CPU SYSCALL context.
        Some(unsafe { poll_now_ticks() }.saturating_add(ticks.max(1)))
    } else {
        None
    };

    loop {
        let mut ready = 0i64;
        let mut revents = [0i16; POLL_MAX_FDS];
        for i in 0..nfds {
            if fds[i] < 0 {
                continue; // Negative fd: skip, revents already 0.
            }
            // SAFETY: single-CPU SYSCALL context.
            let r = unsafe { poll_one(fds[i] as usize, events[i]) };
            revents[i] = r;
            if r != 0 {
                ready += 1;
            }
        }

        // Write revents back and return if any fd is ready, or if this is a
        // non-blocking poll (timeout == 0), or if a positive timeout expired.
        let expired = match deadline {
            // SAFETY: single-CPU SYSCALL context.
            Some(d) => (unsafe { poll_now_ticks() }) >= d,
            None => false,
        };
        if ready > 0 || timeout_ms == 0 || expired {
            // SAFETY: `fds_ptr` validated above; writing the 2-byte revents
            // field (offset 6) of each entry.
            unsafe {
                let base = fds_ptr as *mut u8;
                for (i, &rv) in revents.iter().take(nfds).enumerate() {
                    (base.add(i * 8 + 6) as *mut i16).write_volatile(rv);
                }
            }
            return ready;
        }

        // Nothing ready yet and we may still block: yield and rescan.
        // SAFETY: SYSCALL context; cooperative yield (same model as nanosleep).
        unsafe {
            let _ = crate::current::yield_now();
        }
    }
}

// ── I/O dispatch ─────────────────────────────────────────────────

/// Write `count` bytes from the user-space buffer `buf_ptr` to fd `fd`.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path. `buf_ptr` must be
/// a non-null user-space address readable for at least `count` bytes.
pub unsafe fn dispatch_write(fd: usize, buf_ptr: u64, count: u64) -> i64 {
    if buf_ptr == 0 || buf_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    let count = count.min(4096) as usize;
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
            let mut serial = Uart16550::new(COM1);
            // SAFETY: `buf_ptr` validated above.
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
            let mut kbuf = [0u8; 4096];
            // SAFETY: `buf_ptr` validated above.
            unsafe {
                let ptr = buf_ptr as *const u8;
                for (i, b) in kbuf[..count].iter_mut().enumerate() {
                    *b = ptr.add(i).read_volatile();
                }
            }

            let offset = unsafe {
                match crate::current::current_thread_mut() {
                    Some(t) => match t.fd_table.get_mut(fd) {
                        Some(h) => {
                            if h.flags.is_append() {
                                crate::state::with_global(|s| s.vfs.inode_size(ino))
                                    .flatten()
                                    .unwrap_or(0)
                            } else {
                                h.offset
                            }
                        }
                        None => return -9,
                    },
                    None => return -9,
                }
            };

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
                        if let Some(t) = crate::current::current_thread_mut() {
                            if let Some(h) = t.fd_table.get_mut(fd) {
                                h.offset = offset + n as u64;
                            }
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
            let mut kbuf = [0u8; 4096];
            // SAFETY: `buf_ptr` validated above.
            unsafe {
                let ptr = buf_ptr as *const u8;
                for (i, b) in kbuf[..count].iter_mut().enumerate() {
                    *b = ptr.add(i).read_volatile();
                }
            }
            let nonblock = handle.flags.is_nonblock();
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
                // Buffer is full and the request is unfinished. With
                // O_NONBLOCK, return the partial count if any bytes were
                // written, else -EAGAIN; otherwise block via yield.
                if nonblock {
                    if written > 0 {
                        return written as i64;
                    }
                    return -11; // EAGAIN
                }
                // SAFETY: SYSCALL context; yield_now is documented for this.
                unsafe {
                    let _ = crate::current::yield_now();
                }
            }
        }
        FileBackend::Socket { handle_id } => {
            let mut kbuf = [0u8; 4096];
            // SAFETY: `buf_ptr` validated above.
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
                    Err(oncrix_lib::Error::WouldBlock) => unsafe {
                        let _ = crate::current::yield_now();
                    },
                    Err(_) => return -22, // EINVAL
                }
            }
        }
        FileBackend::DevFile { .. } => count as i64, // /dev/null and /dev/zero discard writes
        FileBackend::ProcFile { .. } => -30,         // EROFS — proc files are read-only
    }
}

/// Read up to `count` bytes from fd `fd` into user-space buffer `buf_ptr`.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path. `buf_ptr` must be
/// a non-null user-space address writable for at least `count` bytes.
pub unsafe fn dispatch_read(fd: usize, buf_ptr: u64, count: u64) -> i64 {
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
            let user_ptr = buf_ptr as *mut u8;
            let mut written = 0usize;
            loop {
                // SAFETY: single-CPU SYSCALL context.
                let next = unsafe { crate::console::console_pop_byte() };
                match next {
                    Some(b) => {
                        // SAFETY: `buf_ptr` validated above.
                        unsafe { user_ptr.add(written).write_volatile(b) };
                        written += 1;
                        if b == b'\n' || written >= count {
                            return written as i64;
                        }
                    }
                    None => {
                        if written > 0 {
                            return written as i64;
                        }
                        // SAFETY: We hold no live borrows of any single-CPU-protected
                        // data in this branch. The IRQ handlers save/restore context.
                        unsafe {
                            core::arch::asm!("sti; hlt; cli", options(nomem, nostack));
                        }
                    }
                }
            }
        }
        FileBackend::RamfsFile { ino } => {
            let offset = handle.offset;
            let mut kbuf = [0u8; 4096];

            let result = crate::state::with_global(|s| {
                let inode_val = match s.vfs.lookup_path_by_ino(ino) {
                    Some(i) => i,
                    None => return Err(Error::NotFound),
                };
                s.vfs.read_inode(&inode_val, offset, &mut kbuf[..count])
            });

            match result {
                Some(Ok(n)) => {
                    // SAFETY: `buf_ptr` validated above.
                    unsafe {
                        let ptr = buf_ptr as *mut u8;
                        for (i, byte) in kbuf.iter().take(n).enumerate() {
                            ptr.add(i).write_volatile(*byte);
                        }
                    }
                    // Advance the offset.
                    // SAFETY: single-CPU SYSCALL context.
                    unsafe {
                        if let Some(t) = crate::current::current_thread_mut() {
                            if let Some(h) = t.fd_table.get_mut(fd) {
                                h.offset = offset + n as u64;
                            }
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
            let nonblock = handle.flags.is_nonblock();
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
                    // SAFETY: `buf_ptr` validated above.
                    unsafe {
                        let ptr = user_ptr;
                        for (i, &byte) in kbuf.iter().take(n).enumerate() {
                            ptr.add(i).write_volatile(byte);
                        }
                    }
                    return n as i64;
                }
                if !ring.write_open {
                    return 0; // POSIX EOF
                }
                // Buffer is empty but writers remain. With O_NONBLOCK return
                // -EAGAIN rather than blocking; otherwise yield and retry.
                if nonblock {
                    return -11; // EAGAIN
                }
                // SAFETY: SYSCALL context.
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
                        // SAFETY: `buf_ptr` validated above.
                        unsafe {
                            for (i, &byte) in kbuf.iter().take(n).enumerate() {
                                user_ptr.add(i).write_volatile(byte);
                            }
                        }
                        return n as i64;
                    }
                    Ok(_) | Err(oncrix_lib::Error::WouldBlock) => unsafe {
                        let _ = crate::current::yield_now();
                    },
                    Err(_) => return -22, // EINVAL
                }
            }
        }
        FileBackend::DevFile { kind } => match kind {
            DevFileKind::Null => 0,
            DevFileKind::Zero => {
                // SAFETY: `buf_ptr` validated above.
                unsafe {
                    let ptr = buf_ptr as *mut u8;
                    for i in 0..count {
                        ptr.add(i).write_volatile(0u8);
                    }
                }
                count as i64
            }
        },
        FileBackend::ProcFile { kind } => {
            let vfs_kind = match kind {
                ProcFileKind::Uptime => oncrix_vfs::procfs::ProcKind::Uptime,
                ProcFileKind::Version => oncrix_vfs::procfs::ProcKind::Version,
                ProcFileKind::Meminfo => oncrix_vfs::procfs::ProcKind::Meminfo,
            };
            let offset = handle.offset as usize;
            let mut kbuf = [0u8; 256];
            // SAFETY: SYSCALL dispatch path.
            let total = unsafe { crate::procfs_dispatch::proc_synthesize(vfs_kind, &mut kbuf) };
            if offset >= total {
                return 0; // EOF
            }
            let available = total - offset;
            let n = available.min(count);
            // SAFETY: `buf_ptr` validated above.
            unsafe {
                let ptr = buf_ptr as *mut u8;
                for (i, &byte) in kbuf[offset..offset + n].iter().enumerate() {
                    ptr.add(i).write_volatile(byte);
                }
            }
            // Advance the offset.
            // SAFETY: single-CPU SYSCALL context.
            unsafe {
                if let Some(t) = crate::current::current_thread_mut() {
                    if let Some(h) = t.fd_table.get_mut(fd) {
                        h.offset = (offset + n) as u64;
                    }
                }
            }
            n as i64
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
        FileBackend::Console => -29,         // ESPIPE
        FileBackend::Pipe { .. } => -29,     // ESPIPE
        FileBackend::Socket { .. } => -29,   // ESPIPE
        FileBackend::DevFile { .. } => -29,  // ESPIPE
        FileBackend::ProcFile { .. } => -29, // ESPIPE
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
                return -22; // EINVAL
            }

            // Update the handle's offset.
            // SAFETY: single-CPU SYSCALL context.
            unsafe {
                if let Some(t) = crate::current::current_thread_mut() {
                    if let Some(h) = t.fd_table.get_mut(fd) {
                        h.offset = new_offset as u64;
                    }
                }
            }
            new_offset
        }
    }
}
