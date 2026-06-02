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

// ── eventfd backing store ─────────────────────────────────────────

/// Maximum number of simultaneously open `eventfd` objects.
const MAX_EVENTFDS: usize = 32;

/// Largest counter value a write may leave behind. `eventfd(2)` reserves
/// `u64::MAX` as the "would overflow" sentinel; a write that would push the
/// counter past this value blocks (or returns `EAGAIN`).
const EVENTFD_MAX: u64 = u64::MAX - 1;

/// One `eventfd` slot: a `u64` counter plus its semaphore-mode flag.
#[derive(Clone, Copy)]
struct EventFdSlot {
    /// `true` when this slot is in use.
    in_use: bool,
    /// The 64-bit counter.
    counter: u64,
    /// `EFD_SEMAPHORE`: read decrements by 1 and returns 1, rather than
    /// returning and zeroing the whole counter.
    semaphore: bool,
    /// Number of fds referencing this slot (`dup`/`dup2`/`fork` increment,
    /// `close` decrements). The slot frees when this reaches zero.
    refs: u32,
}

impl EventFdSlot {
    const fn new() -> Self {
        Self {
            in_use: false,
            counter: 0,
            semaphore: false,
            refs: 0,
        }
    }
}

/// Global eventfd registry (single-CPU, no heap).
///
/// # Safety invariant
///
/// Accessed exclusively from the SYSCALL dispatch path (single CPU, IF
/// cleared on entry via FMASK), identical to the pipe table invariant.
// SAFETY: See note. Single-CPU SYSCALL context only.
static mut EVENTFD_TABLE: [EventFdSlot; MAX_EVENTFDS] = {
    const EMPTY: EventFdSlot = EventFdSlot::new();
    [EMPTY; MAX_EVENTFDS]
};

/// Allocate an eventfd slot initialised to `initval`/`semaphore`.
///
/// Returns the slot id, or `None` if all [`MAX_EVENTFDS`] slots are in use.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
unsafe fn eventfd_alloc(initval: u64, semaphore: bool) -> Option<u32> {
    // SAFETY: single-CPU SYSCALL context; no aliased mutation.
    unsafe {
        #[allow(static_mut_refs)]
        for (i, slot) in EVENTFD_TABLE.iter_mut().enumerate() {
            if !slot.in_use {
                slot.in_use = true;
                slot.counter = initval;
                slot.semaphore = semaphore;
                slot.refs = 1;
                return Some(i as u32);
            }
        }
    }
    None
}

/// Drop one reference to eventfd `id`; free the slot when it hits zero.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
unsafe fn eventfd_close(id: u32) {
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        if let Some(slot) = EVENTFD_TABLE.get_mut(id as usize)
            && slot.in_use
        {
            slot.refs = slot.refs.saturating_sub(1);
            if slot.refs == 0 {
                *slot = EventFdSlot::new();
            }
        }
    }
}

/// Add one reference to eventfd `id` (for `dup`/`dup2`/`fork`).
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn eventfd_dup(id: u32) {
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        if let Some(slot) = EVENTFD_TABLE.get_mut(id as usize)
            && slot.in_use
        {
            slot.refs = slot.refs.saturating_add(1);
        }
    }
}

/// Return `(counter, semaphore)` for eventfd `id`, or `None` if not in use.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
unsafe fn eventfd_peek(id: u32) -> Option<(u64, bool)> {
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        let slot = EVENTFD_TABLE.get(id as usize)?;
        if slot.in_use {
            Some((slot.counter, slot.semaphore))
        } else {
            None
        }
    }
}

/// `EFD_SEMAPHORE` flag — read decrements by 1 instead of zeroing.
const EFD_SEMAPHORE: u32 = 1;
/// `EFD_NONBLOCK` flag (octal 04000) — equivalent to `O_NONBLOCK`.
const EFD_NONBLOCK: u32 = 0o4000;
/// `EFD_CLOEXEC` flag (octal 02000000) — set `FD_CLOEXEC` on the new fd.
const EFD_CLOEXEC: u32 = 0o2000000;

/// Kernel handler for `SYS_EVENTFD2` (Linux number 290).
///
/// Linux `eventfd2(initval, flags)`: creates an fd backed by a `u64`
/// counter initialised to `initval`. Recognised flags:
/// - `EFD_SEMAPHORE` (1) — semaphore-mode reads (return 1, decrement by 1).
/// - `EFD_NONBLOCK` (0o4000) — set `O_NONBLOCK` on the fd (read/write return
///   `-EAGAIN` instead of blocking).
/// - `EFD_CLOEXEC` (0o2000000) — set `FD_CLOEXEC` on the fd.
///
/// Returns the new fd, or a negative errno: `-EINVAL` (22) for an unknown
/// flag bit, `-ENFILE` (23) if no eventfd slot is free, `-EMFILE` (24) if
/// the fd table is full.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU, interrupts
/// effectively disabled).
pub unsafe fn sys_eventfd2(initval: u64, flags: u32) -> i64 {
    let known = EFD_SEMAPHORE | EFD_NONBLOCK | EFD_CLOEXEC;
    if flags & !known != 0 {
        return -22; // EINVAL — unsupported flag bit
    }

    let semaphore = flags & EFD_SEMAPHORE != 0;
    // SAFETY: single-CPU SYSCALL context.
    let id = match unsafe { eventfd_alloc(initval, semaphore) } {
        Some(id) => id,
        None => return -23, // ENFILE — no free eventfd slots
    };

    // Map EFD_NONBLOCK -> O_NONBLOCK and EFD_CLOEXEC -> reserved cloexec bit
    // in the handle flags (RDWR access mode: eventfd is read/write).
    let mut hflags = HandleFlags::RDWR.0;
    if flags & EFD_NONBLOCK != 0 {
        hflags |= HandleFlags::NONBLOCK;
    }
    if flags & EFD_CLOEXEC != 0 {
        hflags |= HandleFlags::FD_CLOEXEC_BIT;
    }

    let handle = FileHandle {
        backend: FileBackend::EventFd { id },
        offset: 0,
        flags: HandleFlags(hflags),
    };

    // SAFETY: single-CPU SYSCALL context.
    match unsafe { fd_install(handle) } {
        Ok(fd) => fd as i64,
        Err(_) => {
            // SAFETY: single-CPU SYSCALL context.
            unsafe { eventfd_close(id) };
            -24 // EMFILE
        }
    }
}

// ── socketpair ────────────────────────────────────────────────────

/// Kernel handler for `SYS_SOCKETPAIR` (Linux number 53).
///
/// Creates a connected pair of `AF_UNIX`/`SOCK_STREAM` descriptors backed by
/// two pipe rings (one per direction). `sv[0]` reads from ring A / writes to
/// ring B; `sv[1]` reads from ring B / writes to ring A. The flag bits
/// `SOCK_NONBLOCK`/`SOCK_CLOEXEC` may be OR'd into `type_`.
///
/// Returns 0 on success and writes the two fds to `sv_ptr`, or a negative
/// errno: `-EAFNOSUPPORT`(97) for a non-`AF_UNIX` domain, `-EINVAL`(22) for a
/// non-`SOCK_STREAM` type, `-EFAULT`(14) for a bad `sv` pointer, `-ENFILE`(23)
/// if pipe rings are exhausted, `-EMFILE`(24) if the fd table is full.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU).
pub unsafe fn sys_socketpair(domain: i64, type_: i64, _protocol: i64, sv_ptr: u64) -> i64 {
    const AF_UNIX: i64 = 1;
    const SOCK_STREAM: i64 = 1;
    const SOCK_NONBLOCK: i64 = 0o4000;
    const SOCK_CLOEXEC: i64 = 0o2000000;

    if domain != AF_UNIX {
        return -97; // EAFNOSUPPORT
    }
    let flag_bits = type_ & (SOCK_NONBLOCK | SOCK_CLOEXEC);
    if type_ & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != SOCK_STREAM {
        return -22; // EINVAL — only SOCK_STREAM is supported
    }
    if sv_ptr == 0 || sv_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }

    // Allocate the two direction rings. Each ring starts with one reader
    // and one writer ref (pipe_alloc), exactly matching the two endpoints.
    // SAFETY: single-CPU SYSCALL context.
    let ring_a = unsafe {
        match crate::pipe::pipe_alloc() {
            Some(id) => id,
            None => return -23, // ENFILE
        }
    };
    // SAFETY: single-CPU SYSCALL context.
    let ring_b = unsafe {
        match crate::pipe::pipe_alloc() {
            Some(id) => id,
            None => {
                crate::pipe::pipe_close_read(ring_a);
                crate::pipe::pipe_close_write(ring_a);
                return -23; // ENFILE
            }
        }
    };

    let mut hflags = HandleFlags::RDWR.0;
    if flag_bits & SOCK_NONBLOCK != 0 {
        hflags |= HandleFlags::NONBLOCK;
    }
    if flag_bits & SOCK_CLOEXEC != 0 {
        hflags |= HandleFlags::FD_CLOEXEC_BIT;
    }

    let h0 = FileHandle {
        backend: FileBackend::SocketPair {
            read_ring: ring_a,
            write_ring: ring_b,
        },
        offset: 0,
        flags: HandleFlags(hflags),
    };
    let h1 = FileHandle {
        backend: FileBackend::SocketPair {
            read_ring: ring_b,
            write_ring: ring_a,
        },
        offset: 0,
        flags: HandleFlags(hflags),
    };

    // SAFETY: single-CPU SYSCALL context.
    let fd0 = unsafe {
        match fd_install(h0) {
            Ok(fd) => fd,
            Err(_) => {
                // Release all four ring ends.
                crate::pipe::pipe_close_read(ring_a);
                crate::pipe::pipe_close_write(ring_b);
                crate::pipe::pipe_close_read(ring_b);
                crate::pipe::pipe_close_write(ring_a);
                return -24; // EMFILE
            }
        }
    };
    // SAFETY: single-CPU SYSCALL context.
    let fd1 = unsafe {
        match fd_install(h1) {
            Ok(fd) => fd,
            Err(_) => {
                // fd_close(fd0) releases ring_a-read + ring_b-write; the ends
                // h1 would have owned (ring_b-read, ring_a-write) are released
                // manually so both rings free.
                let _ = fd_close(fd0);
                crate::pipe::pipe_close_read(ring_b);
                crate::pipe::pipe_close_write(ring_a);
                return -24; // EMFILE
            }
        }
    };

    // SAFETY: `sv_ptr` validated above; writing two i32 (8 bytes).
    unsafe {
        let arr = sv_ptr as *mut i32;
        arr.write_volatile(fd0 as i32);
        arr.add(1).write_volatile(fd1 as i32);
    }
    0
}

// ── epoll backing store ───────────────────────────────────────────

/// Maximum number of simultaneously open epoll instances.
const MAX_EPOLLS: usize = 16;

/// Maximum interests (registered fds) per epoll instance.
const MAX_EPOLL_INTERESTS: usize = 32;

/// `epoll_ctl(2)` operations.
const EPOLL_CTL_ADD: i32 = 1;
/// Remove an fd from the interest list.
const EPOLL_CTL_DEL: i32 = 2;
/// Modify an existing fd's interest.
const EPOLL_CTL_MOD: i32 = 3;

/// `epoll_create1(2)` `EPOLL_CLOEXEC` flag (octal 02000000).
const EPOLL_CLOEXEC: i32 = 0o2000000;

/// `EPOLLIN` — the fd is readable.
const EPOLLIN: u32 = 0x0001;
/// `EPOLLOUT` — the fd is writable.
const EPOLLOUT: u32 = 0x0004;
/// `EPOLLHUP` — the fd hung up (revents-only; always reported).
const EPOLLHUP: u32 = 0x0010;

/// One registered interest in an epoll instance.
#[derive(Clone, Copy)]
struct EpollInterest {
    /// Watched file descriptor (in the owning thread's fd table).
    fd: u32,
    /// Requested event mask (`EPOLLIN`/`EPOLLOUT`/…); `EPOLLHUP`/`EPOLLERR`
    /// are always reported regardless of this mask.
    events: u32,
    /// Opaque user token echoed back in `epoll_wait` results.
    data: u64,
}

/// One epoll instance: a fixed interest list plus a refcount.
struct EpollSlot {
    /// `true` when this slot is in use.
    in_use: bool,
    /// Number of fds referencing this instance.
    refs: u32,
    /// Registered interests (slot occupied when `Some`).
    interests: [Option<EpollInterest>; MAX_EPOLL_INTERESTS],
}

impl EpollSlot {
    const fn new() -> Self {
        const NONE: Option<EpollInterest> = None;
        Self {
            in_use: false,
            refs: 0,
            interests: [NONE; MAX_EPOLL_INTERESTS],
        }
    }
}

/// Global epoll registry (single-CPU, no heap).
///
/// # Safety invariant
///
/// Accessed exclusively from the SYSCALL dispatch path (single CPU, IF
/// cleared via FMASK), identical to the pipe / eventfd table invariant.
// SAFETY: See note. Single-CPU SYSCALL context only.
static mut EPOLL_TABLE: [EpollSlot; MAX_EPOLLS] = {
    const EMPTY: EpollSlot = EpollSlot::new();
    [EMPTY; MAX_EPOLLS]
};

/// Allocate a free epoll instance and return its id.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
unsafe fn epoll_alloc() -> Option<u32> {
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        for (i, slot) in EPOLL_TABLE.iter_mut().enumerate() {
            if !slot.in_use {
                *slot = EpollSlot::new();
                slot.in_use = true;
                slot.refs = 1;
                return Some(i as u32);
            }
        }
    }
    None
}

/// Drop one reference to epoll instance `id`; free it when it hits zero.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
unsafe fn epoll_close(id: u32) {
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        if let Some(slot) = EPOLL_TABLE.get_mut(id as usize)
            && slot.in_use
        {
            slot.refs = slot.refs.saturating_sub(1);
            if slot.refs == 0 {
                *slot = EpollSlot::new();
            }
        }
    }
}

/// Add one reference to epoll instance `id` (for `dup`/`dup2`/`fork`).
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn epoll_dup(id: u32) {
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        if let Some(slot) = EPOLL_TABLE.get_mut(id as usize)
            && slot.in_use
        {
            slot.refs = slot.refs.saturating_add(1);
        }
    }
}

/// Kernel handler for `SYS_EPOLL_CREATE1` (Linux number 291).
///
/// Creates an epoll instance and returns an fd referencing it. The only
/// recognised flag is `EPOLL_CLOEXEC` (0o2000000), which sets `FD_CLOEXEC`
/// on the new fd.
///
/// Returns the fd, or `-EINVAL` (22) for an unknown flag, `-ENFILE` (23) if
/// no epoll slot is free, `-EMFILE` (24) if the fd table is full.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn sys_epoll_create1(flags: i32) -> i64 {
    if flags & !EPOLL_CLOEXEC != 0 {
        return -22; // EINVAL — unsupported flag
    }
    // SAFETY: single-CPU SYSCALL context.
    let id = match unsafe { epoll_alloc() } {
        Some(id) => id,
        None => return -23, // ENFILE
    };

    let mut hflags = HandleFlags::RDWR.0;
    if flags & EPOLL_CLOEXEC != 0 {
        hflags |= HandleFlags::FD_CLOEXEC_BIT;
    }
    let handle = FileHandle {
        backend: FileBackend::EpollInstance { id },
        offset: 0,
        flags: HandleFlags(hflags),
    };

    // SAFETY: single-CPU SYSCALL context.
    match unsafe { fd_install(handle) } {
        Ok(fd) => fd as i64,
        Err(_) => {
            // SAFETY: single-CPU SYSCALL context.
            unsafe { epoll_close(id) };
            -24 // EMFILE
        }
    }
}

/// Resolve `epfd` to its epoll instance id, or `None` if it is not an
/// open epoll fd.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
unsafe fn epoll_id_of(epfd: usize) -> Option<u32> {
    // SAFETY: single-CPU SYSCALL context.
    match unsafe { fd_get(epfd) } {
        Some(FileHandle {
            backend: FileBackend::EpollInstance { id },
            ..
        }) => Some(id),
        _ => None,
    }
}

/// Kernel handler for `SYS_EPOLL_CTL` (Linux number 233).
///
/// `epoll_ctl(epfd, op, fd, event)`: registers (`EPOLL_CTL_ADD`), modifies
/// (`EPOLL_CTL_MOD`), or removes (`EPOLL_CTL_DEL`) an interest in `fd`.
/// `event` points to a packed `struct epoll_event { events: u32, data: u64 }`
/// (12 bytes); it is ignored for `EPOLL_CTL_DEL`.
///
/// Returns 0 on success, or a negative errno: `-EBADF` (9) if `epfd` is not
/// an epoll fd or `fd` is not open, `-EINVAL` (22) for a bad `op` or
/// `epfd == fd`, `-EEXIST` (17) on ADD of an already-registered fd,
/// `-ENOENT` (2) on MOD/DEL of an unregistered fd, `-ENOSPC` (28) when the
/// interest list is full, `-EFAULT` (14) for a bad `event` pointer.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path. `event_ptr`, when used,
/// must address a readable 12-byte `epoll_event`.
pub unsafe fn sys_epoll_ctl(epfd: usize, op: i32, fd: usize, event_ptr: u64) -> i64 {
    // SAFETY: single-CPU SYSCALL context.
    let id = match unsafe { epoll_id_of(epfd) } {
        Some(id) => id,
        None => return -9, // EBADF — not an epoll fd
    };
    if epfd == fd {
        return -22; // EINVAL — cannot watch the epoll fd itself this way
    }

    // Read the epoll_event for ADD/MOD (packed: events @0 u32, data @4 u64).
    let (events, data) = if op == EPOLL_CTL_ADD || op == EPOLL_CTL_MOD {
        if event_ptr == 0 || event_ptr >= 0xFFFF_8000_0000_0000 {
            return -14; // EFAULT
        }
        // SAFETY: pointer validated user-canonical above; unaligned packed read.
        unsafe {
            let base = event_ptr as *const u8;
            let ev = (base as *const u32).read_unaligned();
            let dt = (base.add(4) as *const u64).read_unaligned();
            (ev, dt)
        }
    } else {
        (0, 0)
    };

    let fd32 = fd as u32;
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        let slot = match EPOLL_TABLE.get_mut(id as usize) {
            Some(s) if s.in_use => s,
            _ => return -9, // EBADF
        };

        match op {
            EPOLL_CTL_ADD => {
                // The target fd must be open.
                if fd_get(fd).is_none() {
                    return -9; // EBADF
                }
                if slot.interests.iter().flatten().any(|i| i.fd == fd32) {
                    return -17; // EEXIST
                }
                match slot.interests.iter_mut().find(|s| s.is_none()) {
                    Some(empty) => {
                        *empty = Some(EpollInterest {
                            fd: fd32,
                            events,
                            data,
                        });
                        0
                    }
                    None => -28, // ENOSPC — interest list full
                }
            }
            EPOLL_CTL_MOD => {
                match slot.interests.iter_mut().flatten().find(|i| i.fd == fd32) {
                    Some(interest) => {
                        interest.events = events;
                        interest.data = data;
                        0
                    }
                    None => -2, // ENOENT
                }
            }
            EPOLL_CTL_DEL => {
                match slot
                    .interests
                    .iter_mut()
                    .find(|s| s.is_some_and(|i| i.fd == fd32))
                {
                    Some(entry) => {
                        *entry = None;
                        0
                    }
                    None => -2, // ENOENT
                }
            }
            _ => -22, // EINVAL — bad op
        }
    }
}

/// Kernel handler for `SYS_EPOLL_WAIT` (Linux number 232).
///
/// `epoll_wait(epfd, events, maxevents, timeout_ms)`: scans the instance's
/// registered interests (level-triggered) via [`fd_readiness`] and writes up
/// to `maxevents` ready `struct epoll_event { events: u32, data: u64 }`
/// (12 bytes each) to `events_ptr`. `EPOLLIN`/`EPOLLOUT`/`EPOLLHUP` are
/// reported. Blocks via cooperative `yield_now` until at least one fd is
/// ready or the timeout elapses (`timeout_ms < 0` = infinite, `0` = single
/// scan).
///
/// Returns the number of ready fds, `0` on timeout, or a negative errno:
/// `-EBADF` (9) if `epfd` is not an epoll fd, `-EINVAL` (22) if `maxevents`
/// is not positive, `-EFAULT` (14) for a bad `events` pointer.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path. `events_ptr` must address
/// `maxevents` writable 12-byte `epoll_event` structs.
pub unsafe fn sys_epoll_wait(epfd: usize, events_ptr: u64, maxevents: i32, timeout_ms: i64) -> i64 {
    if maxevents <= 0 {
        return -22; // EINVAL
    }
    if events_ptr == 0 || events_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    // SAFETY: single-CPU SYSCALL context.
    let id = match unsafe { epoll_id_of(epfd) } {
        Some(id) => id,
        None => return -9, // EBADF
    };
    let maxevents = maxevents as usize;

    let deadline = if timeout_ms > 0 {
        let ticks = (timeout_ms as u64).saturating_mul(POLL_TIMER_HZ) / 1000;
        // SAFETY: single-CPU SYSCALL context.
        Some(unsafe { poll_now_ticks() }.saturating_add(ticks.max(1)))
    } else {
        None
    };

    loop {
        // Snapshot the interest list, then evaluate readiness outside the
        // table borrow so fd_readiness can take its own references.
        let mut interests = [(0u32, 0u32, 0u64); MAX_EPOLL_INTERESTS];
        let mut n_interests = 0usize;
        // SAFETY: single-CPU SYSCALL context.
        unsafe {
            #[allow(static_mut_refs)]
            let slot = match EPOLL_TABLE.get(id as usize) {
                Some(s) if s.in_use => s,
                _ => return -9, // EBADF — instance vanished
            };
            for i in slot.interests.iter().flatten() {
                interests[n_interests] = (i.fd, i.events, i.data);
                n_interests += 1;
            }
        }

        let mut written = 0usize;
        for &(fd, want, data) in interests.iter().take(n_interests) {
            if written >= maxevents {
                break;
            }
            // SAFETY: single-CPU SYSCALL context.
            let (readable, writable, hup) = match unsafe { fd_readiness(fd as usize) } {
                Some(r) => r,
                None => continue, // fd closed out from under us: skip
            };
            let mut revents = 0u32;
            if want & EPOLLIN != 0 && readable {
                revents |= EPOLLIN;
            }
            if want & EPOLLOUT != 0 && writable {
                revents |= EPOLLOUT;
            }
            if hup {
                revents |= EPOLLHUP;
            }
            if revents == 0 {
                continue;
            }
            // SAFETY: events_ptr validated above; packed 12-byte write.
            unsafe {
                let entry = (events_ptr as *mut u8).add(written * 12);
                (entry as *mut u32).write_unaligned(revents);
                (entry.add(4) as *mut u64).write_unaligned(data);
            }
            written += 1;
        }

        let expired = match deadline {
            // SAFETY: single-CPU SYSCALL context.
            Some(d) => (unsafe { poll_now_ticks() }) >= d,
            None => false,
        };
        if written > 0 || timeout_ms == 0 || expired {
            return written as i64;
        }

        // SAFETY: SYSCALL context; cooperative yield (same model as poll).
        unsafe {
            let _ = crate::current::yield_now();
        }
    }
}

// ── timerfd backing store ─────────────────────────────────────────

/// Maximum number of simultaneously open `timerfd` objects.
const MAX_TIMERFDS: usize = 16;

/// `timerfd_settime(2)` flag — interpret `new_value.it_value` as absolute.
const TFD_TIMER_ABSTIME: i32 = 1;

/// `timerfd_create(2)` flag — equivalent to `O_NONBLOCK` on the fd.
const TFD_NONBLOCK: i32 = 0o4000;

/// `timerfd_create(2)` flag — set `FD_CLOEXEC` on the fd.
const TFD_CLOEXEC: i32 = 0o2000000;

/// Recognised clock ids.  All map to the same PIT-derived source on this
/// build, so the difference is currently only validated, not enforced.
const CLOCK_REALTIME: i32 = 0;
/// Monotonic clock id.
const CLOCK_MONOTONIC: i32 = 1;
/// Boot-time clock id (Linux extension; alias for MONOTONIC here).
const CLOCK_BOOTTIME: i32 = 7;

/// One `timerfd` slot.
///
/// Times are kept in PIT ticks (100 Hz, 10 ms each). `expires_at` is the
/// absolute tick at which the timer next fires (0 == disarmed).
/// `interval_ticks` is the auto-reload period (0 == one-shot).
#[derive(Clone, Copy)]
struct TimerFdSlot {
    /// `true` when this slot is in use.
    in_use: bool,
    /// Number of fds referencing this slot.
    refs: u32,
    /// Clock id (`CLOCK_REALTIME`/`CLOCK_MONOTONIC`/`CLOCK_BOOTTIME`).
    clockid: i32,
    /// Absolute next-fire tick; 0 disarms the timer.
    expires_at: u64,
    /// Reload period in ticks; 0 marks a one-shot timer.
    interval_ticks: u64,
    /// Number of unread expirations since the last `read(2)`.
    expirations: u64,
}

impl TimerFdSlot {
    const fn new() -> Self {
        Self {
            in_use: false,
            refs: 0,
            clockid: 0,
            expires_at: 0,
            interval_ticks: 0,
            expirations: 0,
        }
    }
}

/// Global timerfd registry (single-CPU, no heap).
///
/// # Safety invariant
///
/// Mutated from two contexts — the SYSCALL dispatch path (single CPU,
/// IF=0 via FMASK) and the PIT timer IRQ (interrupt gate, IF=0). Both are
/// IF=0 on a single-CPU build, so no concurrent mutation is possible.
// SAFETY: See note. Accessed only with IF=0.
static mut TIMERFD_TABLE: [TimerFdSlot; MAX_TIMERFDS] = {
    const EMPTY: TimerFdSlot = TimerFdSlot::new();
    [EMPTY; MAX_TIMERFDS]
};

/// PIT-tick equivalent of one second.
const TIMERFD_HZ: u64 = POLL_TIMER_HZ;
/// PIT tick period in nanoseconds (1 / 100 Hz = 10 ms).
const TIMERFD_TICK_NS: u64 = 1_000_000_000 / TIMERFD_HZ;

/// Convert `(secs, nsec)` to PIT ticks, rounding up so a sub-tick interval
/// still produces a single tick of delay rather than firing immediately.
fn timespec_to_ticks(secs: i64, nsec: i64) -> u64 {
    let secs = secs.max(0) as u64;
    let nsec = nsec.max(0) as u64;
    let mut ticks = secs.saturating_mul(TIMERFD_HZ);
    ticks = ticks.saturating_add(nsec.div_ceil(TIMERFD_TICK_NS));
    ticks
}

/// Convert PIT ticks back to a `(secs, nsec)` pair for `gettime`.
fn ticks_to_timespec(ticks: u64) -> (i64, i64) {
    let secs = ticks / TIMERFD_HZ;
    let nsec = (ticks % TIMERFD_HZ) * TIMERFD_TICK_NS;
    (secs as i64, nsec as i64)
}

/// Read the current PIT tick count without taking the trait into module scope.
///
/// # Safety
///
/// Caller must guarantee IF=0 (SYSCALL dispatch or timer IRQ).
unsafe fn timerfd_now_ticks() -> u64 {
    // SAFETY: see fn-level note.
    unsafe { poll_now_ticks() }
}

/// Allocate a free timerfd slot; return its id.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
unsafe fn timerfd_alloc(clockid: i32) -> Option<u32> {
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        for (i, slot) in TIMERFD_TABLE.iter_mut().enumerate() {
            if !slot.in_use {
                *slot = TimerFdSlot::new();
                slot.in_use = true;
                slot.refs = 1;
                slot.clockid = clockid;
                return Some(i as u32);
            }
        }
    }
    None
}

/// Drop one reference to timerfd `id`; free the slot when it hits zero.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
unsafe fn timerfd_close(id: u32) {
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        if let Some(slot) = TIMERFD_TABLE.get_mut(id as usize)
            && slot.in_use
        {
            slot.refs = slot.refs.saturating_sub(1);
            if slot.refs == 0 {
                *slot = TimerFdSlot::new();
            }
        }
    }
}

/// Snapshot the expiration count of timerfd `id`, or `None` if not in use.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
unsafe fn timerfd_peek(id: u32) -> Option<u64> {
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        let slot = TIMERFD_TABLE.get(id as usize)?;
        if slot.in_use {
            Some(slot.expirations)
        } else {
            None
        }
    }
}

/// Add one reference to timerfd `id` (for `dup`/`dup2`/`fork`).
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn timerfd_dup(id: u32) {
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        if let Some(slot) = TIMERFD_TABLE.get_mut(id as usize)
            && slot.in_use
        {
            slot.refs = slot.refs.saturating_add(1);
        }
    }
}

/// Advance every armed timerfd by one PIT tick, accumulating expirations
/// and reloading interval timers.
///
/// Called from the PIT timer IRQ in
/// `crate::arch::x86_64::interrupts::timer_handler` immediately after
/// `tick_itimers` so timerfd readers see expirations at the same cadence
/// as the rest of the kernel's tick-driven state.
///
/// # Safety
///
/// Must be called with IF=0 (interrupt gate context). No concurrent mutator
/// of [`TIMERFD_TABLE`] can run on a single-CPU build.
pub unsafe fn tick_timerfds() {
    // SAFETY: see fn-level note.
    unsafe {
        let now = timerfd_now_ticks();
        #[allow(static_mut_refs)]
        for slot in TIMERFD_TABLE.iter_mut() {
            if !slot.in_use || slot.expires_at == 0 {
                continue;
            }
            // Fire as many times as elapsed ticks allow. With an interval of
            // zero a single expiration disarms the timer; with a non-zero
            // interval we accumulate one expiration per period boundary.
            while slot.expires_at != 0 && now >= slot.expires_at {
                slot.expirations = slot.expirations.saturating_add(1);
                if slot.interval_ticks == 0 {
                    slot.expires_at = 0; // one-shot: disarm
                    break;
                }
                slot.expires_at = slot.expires_at.saturating_add(slot.interval_ticks);
            }
        }
    }
}

/// Resolve `fd` to a timerfd id, or return `-EINVAL` shape `None`.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
unsafe fn timerfd_id_of(fd: usize) -> Option<u32> {
    // SAFETY: single-CPU SYSCALL context.
    match unsafe { fd_get(fd) } {
        Some(FileHandle {
            backend: FileBackend::TimerFd { id },
            ..
        }) => Some(id),
        _ => None,
    }
}

/// Kernel handler for `SYS_TIMERFD_CREATE` (Linux number 283).
///
/// Creates a disarmed timerfd backed by [`TIMERFD_TABLE`]. Recognised
/// `clockid` values are `CLOCK_REALTIME`/`CLOCK_MONOTONIC`/`CLOCK_BOOTTIME`;
/// all map to the same PIT-derived monotonic source on this build.
/// Recognised flags: `TFD_NONBLOCK` (sets `O_NONBLOCK`) and `TFD_CLOEXEC`
/// (sets `FD_CLOEXEC`).
///
/// Returns the new fd, or a negative errno: `-EINVAL` (22) for an unknown
/// clockid/flag, `-ENFILE` (23) if no timer slot is free, `-EMFILE` (24)
/// if the fd table is full.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn sys_timerfd_create(clockid: i32, flags: i32) -> i64 {
    match clockid {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME => {}
        _ => return -22, // EINVAL
    }
    if flags & !(TFD_NONBLOCK | TFD_CLOEXEC) != 0 {
        return -22; // EINVAL
    }
    // SAFETY: single-CPU SYSCALL context.
    let id = match unsafe { timerfd_alloc(clockid) } {
        Some(id) => id,
        None => return -23, // ENFILE
    };

    let mut hflags = HandleFlags::RDWR.0;
    if flags & TFD_NONBLOCK != 0 {
        hflags |= HandleFlags::NONBLOCK;
    }
    if flags & TFD_CLOEXEC != 0 {
        hflags |= HandleFlags::FD_CLOEXEC_BIT;
    }
    let handle = FileHandle {
        backend: FileBackend::TimerFd { id },
        offset: 0,
        flags: HandleFlags(hflags),
    };

    // SAFETY: single-CPU SYSCALL context.
    match unsafe { fd_install(handle) } {
        Ok(fd) => fd as i64,
        Err(_) => {
            // SAFETY: single-CPU SYSCALL context.
            unsafe { timerfd_close(id) };
            -24 // EMFILE
        }
    }
}

/// Read an `itimerspec { it_interval: timespec, it_value: timespec }` from
/// user space. Each `timespec` is `(i64 tv_sec, i64 tv_nsec)` = 16 bytes;
/// the whole struct is 32 bytes.
///
/// # Safety
///
/// `ptr` must address a readable 32-byte `itimerspec`.
unsafe fn read_itimerspec(ptr: u64) -> ((i64, i64), (i64, i64)) {
    // SAFETY: caller validated `ptr`.
    unsafe {
        let p = ptr as *const i64;
        let it_interval = (p.read_volatile(), p.add(1).read_volatile());
        let it_value = (p.add(2).read_volatile(), p.add(3).read_volatile());
        (it_interval, it_value)
    }
}

/// Write an `itimerspec` to user space.
///
/// # Safety
///
/// `ptr` must address a writable 32-byte `itimerspec`.
unsafe fn write_itimerspec(ptr: u64, it_interval: (i64, i64), it_value: (i64, i64)) {
    // SAFETY: caller validated `ptr`.
    unsafe {
        let p = ptr as *mut i64;
        p.write_volatile(it_interval.0);
        p.add(1).write_volatile(it_interval.1);
        p.add(2).write_volatile(it_value.0);
        p.add(3).write_volatile(it_value.1);
    }
}

/// Kernel handler for `SYS_TIMERFD_SETTIME` (Linux number 286).
///
/// `timerfd_settime(fd, flags, new_value, old_value)`: arms or disarms `fd`.
/// `new_value->it_value` is the first expiry — absolute monotonic time when
/// `flags & TFD_TIMER_ABSTIME != 0`, otherwise a relative duration. A
/// zero-valued `it_value` disarms. `it_interval` (nonzero) sets the
/// auto-reload period. If `old_value` is non-null, the previous settings
/// are written there before the new ones take effect.
///
/// Returns 0 on success, or a negative errno: `-EBADF` (9) if `fd` is not a
/// timerfd, `-EINVAL` (22) for a bad flag or negative timespec field,
/// `-EFAULT` (14) for a bad pointer.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn sys_timerfd_settime(fd: usize, flags: i32, new_ptr: u64, old_ptr: u64) -> i64 {
    if flags & !TFD_TIMER_ABSTIME != 0 {
        return -22; // EINVAL
    }
    if new_ptr == 0 || new_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    if old_ptr != 0 && old_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    // SAFETY: single-CPU SYSCALL context.
    let id = match unsafe { timerfd_id_of(fd) } {
        Some(id) => id,
        None => return -9, // EBADF
    };

    // SAFETY: `new_ptr` validated user-canonical above.
    let ((iv_s, iv_n), (val_s, val_n)) = unsafe { read_itimerspec(new_ptr) };
    if iv_s < 0 || iv_n < 0 || val_s < 0 || val_n < 0 {
        return -22; // EINVAL
    }
    if iv_n >= 1_000_000_000 || val_n >= 1_000_000_000 {
        return -22; // EINVAL
    }

    let now = unsafe { timerfd_now_ticks() };
    let interval_ticks = timespec_to_ticks(iv_s, iv_n);
    let initial_ticks = timespec_to_ticks(val_s, val_n);
    let abstime = flags & TFD_TIMER_ABSTIME != 0;

    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        let slot = match TIMERFD_TABLE.get_mut(id as usize) {
            Some(s) if s.in_use => s,
            _ => return -9, // EBADF — slot vanished
        };

        // Optionally publish the previous arming.
        if old_ptr != 0 {
            let it_interval_old = ticks_to_timespec(slot.interval_ticks);
            let remaining = slot.expires_at.saturating_sub(now);
            let it_value_old = ticks_to_timespec(remaining);
            // SAFETY: `old_ptr` validated above.
            write_itimerspec(old_ptr, it_interval_old, it_value_old);
        }

        // Apply the new arming.
        if val_s == 0 && val_n == 0 {
            // Disarm (interval is ignored when value is zero).
            slot.expires_at = 0;
            slot.interval_ticks = 0;
        } else {
            slot.interval_ticks = interval_ticks;
            slot.expires_at = if abstime {
                initial_ticks
            } else {
                now.saturating_add(initial_ticks.max(1))
            };
            slot.expirations = 0;
        }
        0
    }
}

/// Kernel handler for `SYS_TIMERFD_GETTIME` (Linux number 287).
///
/// Writes the current arming (`it_interval`, remaining `it_value`) of
/// timerfd `fd` to `cur_ptr`. Returns 0 on success, `-EBADF` (9) if `fd` is
/// not a timerfd, `-EFAULT` (14) for a bad pointer.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn sys_timerfd_gettime(fd: usize, cur_ptr: u64) -> i64 {
    if cur_ptr == 0 || cur_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    // SAFETY: single-CPU SYSCALL context.
    let id = match unsafe { timerfd_id_of(fd) } {
        Some(id) => id,
        None => return -9, // EBADF
    };
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        let now = timerfd_now_ticks();
        #[allow(static_mut_refs)]
        let slot = match TIMERFD_TABLE.get(id as usize) {
            Some(s) if s.in_use => s,
            _ => return -9, // EBADF
        };
        let it_interval = ticks_to_timespec(slot.interval_ticks);
        let remaining = slot.expires_at.saturating_sub(now);
        let it_value = ticks_to_timespec(remaining);
        // SAFETY: `cur_ptr` validated above.
        write_itimerspec(cur_ptr, it_interval, it_value);
    }
    0
}

// ── signalfd backing store ────────────────────────────────────────

/// Maximum number of simultaneously open `signalfd` objects.
const MAX_SIGNALFDS: usize = 16;

/// `signalfd4(2)` flag — set `O_NONBLOCK` on the fd.
const SFD_NONBLOCK: i32 = 0o4000;
/// `signalfd4(2)` flag — set `FD_CLOEXEC` on the fd.
const SFD_CLOEXEC: i32 = 0o2000000;

/// Size of a `struct signalfd_siginfo` (Linux ABI).
const SIGNALFD_SIGINFO_SIZE: usize = 128;

/// One `signalfd` slot.
///
/// `mask` is the caller-supplied 64-bit sigset (only the low 32 bits are
/// meaningful here; signals are numbered 1..32). `owner_pid` records the
/// process whose pending mask is queried — the fd inherits the creator's
/// pid even when read after a fork (matches Linux signalfd semantics
/// where the fd watches the calling thread group's pending signals).
#[derive(Clone, Copy)]
struct SignalFdSlot {
    in_use: bool,
    refs: u32,
    mask: u64,
    owner_pid: u64,
}

impl SignalFdSlot {
    const fn new() -> Self {
        Self {
            in_use: false,
            refs: 0,
            mask: 0,
            owner_pid: 0,
        }
    }
}

/// Global signalfd registry (single-CPU, no heap).
///
/// # Safety invariant
///
/// Accessed exclusively from the SYSCALL dispatch path (single CPU,
/// IF=0 via FMASK), identical to the other fd backend tables.
// SAFETY: See note. Single-CPU SYSCALL context only.
static mut SIGNALFD_TABLE: [SignalFdSlot; MAX_SIGNALFDS] = {
    const EMPTY: SignalFdSlot = SignalFdSlot::new();
    [EMPTY; MAX_SIGNALFDS]
};

/// Allocate a free signalfd slot.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
unsafe fn signalfd_alloc(mask: u64, owner_pid: u64) -> Option<u32> {
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        for (i, slot) in SIGNALFD_TABLE.iter_mut().enumerate() {
            if !slot.in_use {
                *slot = SignalFdSlot::new();
                slot.in_use = true;
                slot.refs = 1;
                slot.mask = mask;
                slot.owner_pid = owner_pid;
                return Some(i as u32);
            }
        }
    }
    None
}

/// Drop one reference to signalfd `id`; free the slot when it hits zero.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
unsafe fn signalfd_close(id: u32) {
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        if let Some(slot) = SIGNALFD_TABLE.get_mut(id as usize)
            && slot.in_use
        {
            slot.refs = slot.refs.saturating_sub(1);
            if slot.refs == 0 {
                *slot = SignalFdSlot::new();
            }
        }
    }
}

/// Add one reference to signalfd `id` (for `dup`/`dup2`/`fork`).
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn signalfd_dup(id: u32) {
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        if let Some(slot) = SIGNALFD_TABLE.get_mut(id as usize)
            && slot.in_use
        {
            slot.refs = slot.refs.saturating_add(1);
        }
    }
}

/// Look up a signalfd slot without taking a mutable borrow.
///
/// Returns `(mask, owner_pid)` or `None` if the slot is not in use.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
unsafe fn signalfd_peek(id: u32) -> Option<(u64, u64)> {
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        let slot = SIGNALFD_TABLE.get(id as usize)?;
        if slot.in_use {
            Some((slot.mask, slot.owner_pid))
        } else {
            None
        }
    }
}

/// Replace the watched mask on signalfd `id`.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
unsafe fn signalfd_set_mask(id: u32, mask: u64) -> bool {
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        if let Some(slot) = SIGNALFD_TABLE.get_mut(id as usize)
            && slot.in_use
        {
            slot.mask = mask;
            return true;
        }
    }
    false
}

/// Return the lowest signal number (1..=32) that is both pending on the
/// owning process and present in `mask`, or `None` if none.
///
/// Consults the process table read-only (does not mutate pending state) so
/// it is safe to call from the readiness scan.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
unsafe fn signalfd_next_pending(owner_pid: u64, mask: u64) -> Option<u8> {
    use oncrix_process::pid::Pid;
    use oncrix_process::signal::Signal;
    // SAFETY: single-CPU SYSCALL context; we drop the borrow before
    // returning.
    unsafe {
        let table = crate::fork_dispatch::process_table_mut();
        let entry = table.get_mut(Pid::new(owner_pid))?;
        for bit in 0..Signal::MAX {
            let signo = bit + 1;
            if mask & (1u64 << bit) == 0 {
                continue;
            }
            if entry.signals.pending.is_pending(Signal(signo)) {
                return Some(signo);
            }
        }
        None
    }
}

/// Consume (clear) the pending bit for `signo` on the owning process,
/// returning `true` if it was actually set.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
unsafe fn signalfd_consume(owner_pid: u64, signo: u8) -> bool {
    use oncrix_process::pid::Pid;
    use oncrix_process::signal::Signal;
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        let table = crate::fork_dispatch::process_table_mut();
        let entry = match table.get_mut(Pid::new(owner_pid)) {
            Some(e) => e,
            None => return false,
        };
        let sig = Signal(signo);
        if entry.signals.pending.is_pending(sig) {
            entry.signals.pending.clear(sig);
            true
        } else {
            false
        }
    }
}

/// Kernel handler for `SYS_SIGNALFD4` (Linux number 289).
///
/// `signalfd4(fd, mask_ptr, sigsetsize, flags)`:
/// - If `fd == -1`, allocates a new signalfd slot, installs it in the fd
///   table, and returns the new fd.
/// - Otherwise the existing slot's mask is replaced and `fd` is returned.
///
/// `sigsetsize` must equal `8` (one `u64` sigset word — Linux glibc ABI).
/// Recognised flags: `SFD_NONBLOCK` (sets `O_NONBLOCK`) and `SFD_CLOEXEC`
/// (sets `FD_CLOEXEC`).
///
/// Returns the fd on success, or a negative errno: `-EBADF` (9) if `fd`
/// is not a signalfd, `-EINVAL` (22) for a bad sigsetsize/flag, `-EFAULT`
/// (14) for a bad mask pointer, `-ENFILE` (23) if no slot is free,
/// `-EMFILE` (24) if the fd table is full.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn sys_signalfd4(fd: i32, mask_ptr: u64, sigsetsize: u64, flags: i32) -> i64 {
    if sigsetsize != 8 {
        return -22; // EINVAL
    }
    if flags & !(SFD_NONBLOCK | SFD_CLOEXEC) != 0 {
        return -22; // EINVAL
    }
    if mask_ptr == 0 || mask_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    // SAFETY: `mask_ptr` validated user-canonical above; reads 8 bytes.
    let mask = unsafe { (mask_ptr as *const u64).read_volatile() };

    if fd >= 0 {
        // Update an existing signalfd's mask.
        // SAFETY: single-CPU SYSCALL context.
        let id = match unsafe { fd_get(fd as usize) } {
            Some(FileHandle {
                backend: FileBackend::SignalFd { id },
                ..
            }) => id,
            _ => return -9, // EBADF
        };
        // SAFETY: single-CPU SYSCALL context.
        if !unsafe { signalfd_set_mask(id, mask) } {
            return -9; // EBADF — slot vanished
        }
        return fd as i64;
    }

    // Allocate a fresh signalfd, owned by the current process.
    let owner_pid = match crate::current::current_pid() {
        Some(p) => p.as_u64(),
        None => return -9, // EBADF — no current thread
    };
    // SAFETY: single-CPU SYSCALL context.
    let id = match unsafe { signalfd_alloc(mask, owner_pid) } {
        Some(id) => id,
        None => return -23, // ENFILE
    };

    let mut hflags = HandleFlags::RDWR.0;
    if flags & SFD_NONBLOCK != 0 {
        hflags |= HandleFlags::NONBLOCK;
    }
    if flags & SFD_CLOEXEC != 0 {
        hflags |= HandleFlags::FD_CLOEXEC_BIT;
    }
    let handle = FileHandle {
        backend: FileBackend::SignalFd { id },
        offset: 0,
        flags: HandleFlags(hflags),
    };

    // SAFETY: single-CPU SYSCALL context.
    match unsafe { fd_install(handle) } {
        Ok(new_fd) => new_fd as i64,
        Err(_) => {
            // SAFETY: single-CPU SYSCALL context.
            unsafe { signalfd_close(id) };
            -24 // EMFILE
        }
    }
}

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
        FileBackend::SocketPair {
            read_ring,
            write_ring,
        } => {
            // SAFETY: single-CPU SYSCALL context; pipe table owned here.
            unsafe {
                crate::pipe::pipe_close_read(read_ring);
                crate::pipe::pipe_close_write(write_ring);
            }
        }
        FileBackend::EventFd { id } => {
            // SAFETY: single-CPU SYSCALL context.
            unsafe { eventfd_close(id) }
        }
        FileBackend::EpollInstance { id } => {
            // SAFETY: single-CPU SYSCALL context.
            unsafe { epoll_close(id) }
        }
        FileBackend::TimerFd { id } => {
            // SAFETY: single-CPU SYSCALL context.
            unsafe { timerfd_close(id) }
        }
        FileBackend::SignalFd { id } => {
            // SAFETY: single-CPU SYSCALL context.
            unsafe { signalfd_close(id) }
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
        FileBackend::SocketPair {
            read_ring,
            write_ring,
        } => {
            // SAFETY: single-CPU SYSCALL context.
            unsafe {
                crate::pipe::pipe_dup_read(read_ring);
                crate::pipe::pipe_dup_write(write_ring);
            }
        }
        FileBackend::EventFd { id } => {
            // SAFETY: single-CPU SYSCALL context.
            unsafe { eventfd_dup(id) }
        }
        FileBackend::EpollInstance { id } => {
            // SAFETY: single-CPU SYSCALL context.
            unsafe { epoll_dup(id) }
        }
        FileBackend::TimerFd { id } => {
            // SAFETY: single-CPU SYSCALL context.
            unsafe { timerfd_dup(id) }
        }
        FileBackend::SignalFd { id } => {
            // SAFETY: single-CPU SYSCALL context.
            unsafe { signalfd_dup(id) }
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

/// Kernel handler for `SYS_DUP3` (Linux number 292).
///
/// POSIX `dup3(2)` differs from [`fd_dup2`] in two ways:
/// - `oldfd == newfd` is an error (`-EINVAL`), not a no-op.
/// - The only accepted flag is `O_CLOEXEC` (`0o2000000`); when set, the new
///   descriptor has `FD_CLOEXEC` enabled. Any other flag bit yields
///   `-EINVAL`.
///
/// On success returns `newfd`; on error a negative errno.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU).
pub unsafe fn sys_dup3(oldfd: usize, newfd: usize, flags: u32) -> i64 {
    /// `O_CLOEXEC` flag bit (octal 02000000), matching `dup3(2)`.
    const O_CLOEXEC: u32 = 0o2000000;

    if oldfd == newfd {
        return -22; // EINVAL — POSIX explicitly disallows the no-op case
    }
    if flags & !O_CLOEXEC != 0 {
        return -22; // EINVAL — unknown flag bits
    }

    // SAFETY: dup2 handles the bulk of the work (refcount + close newfd).
    let rc = unsafe { fd_dup2(oldfd, newfd) };
    if rc < 0 {
        return rc;
    }
    if flags & O_CLOEXEC != 0 {
        // SAFETY: single-CPU SYSCALL context.
        unsafe {
            if let Some(t) = crate::current::current_thread_mut()
                && let Some(h) = t.fd_table.get_mut(newfd)
            {
                h.flags.0 |= HandleFlags::FD_CLOEXEC_BIT;
            }
        }
    }
    rc
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
                FileBackend::EventFd { id } => {
                    // SAFETY: single-CPU SYSCALL context.
                    unsafe { eventfd_dup(id) }
                }
                FileBackend::EpollInstance { id } => {
                    // SAFETY: single-CPU SYSCALL context.
                    unsafe { epoll_dup(id) }
                }
                FileBackend::TimerFd { id } => {
                    // SAFETY: single-CPU SYSCALL context.
                    unsafe { timerfd_dup(id) }
                }
                FileBackend::SignalFd { id } => {
                    // SAFETY: single-CPU SYSCALL context.
                    unsafe { signalfd_dup(id) }
                }
                FileBackend::SocketPair {
                    read_ring,
                    write_ring,
                } => {
                    // SAFETY: single-CPU SYSCALL context.
                    unsafe {
                        crate::pipe::pipe_dup_read(read_ring);
                        crate::pipe::pipe_dup_write(write_ring);
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
                    match handle.backend {
                        FileBackend::Pipe {
                            ring_id,
                            is_write_end,
                        } => {
                            // SAFETY: single-CPU SYSCALL context.
                            unsafe {
                                if is_write_end {
                                    crate::pipe::pipe_close_write(ring_id);
                                } else {
                                    crate::pipe::pipe_close_read(ring_id);
                                }
                            }
                        }
                        FileBackend::EventFd { id } => {
                            // SAFETY: single-CPU SYSCALL context.
                            unsafe { eventfd_close(id) }
                        }
                        FileBackend::EpollInstance { id } => {
                            // SAFETY: single-CPU SYSCALL context.
                            unsafe { epoll_close(id) }
                        }
                        FileBackend::TimerFd { id } => {
                            // SAFETY: single-CPU SYSCALL context.
                            unsafe { timerfd_close(id) }
                        }
                        FileBackend::SignalFd { id } => {
                            // SAFETY: single-CPU SYSCALL context.
                            unsafe { signalfd_close(id) }
                        }
                        FileBackend::SocketPair {
                            read_ring,
                            write_ring,
                        } => {
                            // SAFETY: single-CPU SYSCALL context.
                            unsafe {
                                crate::pipe::pipe_close_read(read_ring);
                                crate::pipe::pipe_close_write(write_ring);
                            }
                        }
                        _ => {}
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
/// Compute `(readable, writable, hup)` readiness for an open `fd`.
///
/// Shared by `poll(2)` and `select(2)`. Returns `None` if `fd` is not open.
/// Pipes consult [`crate::pipe::pipe_poll`]; the console reports `POLLIN`
/// when input is buffered and is always writable; regular files, `/dev`,
/// `/proc`, and sockets always poll ready for both directions (POSIX:
/// regular files always poll TRUE).
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
unsafe fn fd_readiness(fd: usize) -> Option<(bool, bool, bool)> {
    // SAFETY: single-CPU SYSCALL context.
    let handle = unsafe { fd_get(fd) }?;
    let ready = match handle.backend {
        FileBackend::Pipe { ring_id, .. } => {
            // SAFETY: single-CPU SYSCALL context.
            unsafe { crate::pipe::pipe_poll(ring_id) }
        }
        FileBackend::SocketPair {
            read_ring,
            write_ring,
        } => {
            // Readable from our read ring; writable into our write ring;
            // hangup when the peer closed our read ring's write end.
            // SAFETY: single-CPU SYSCALL context.
            let (readable, _, hup) = unsafe { crate::pipe::pipe_poll(read_ring) };
            // SAFETY: single-CPU SYSCALL context.
            let (_, writable, _) = unsafe { crate::pipe::pipe_poll(write_ring) };
            (readable, writable, hup)
        }
        FileBackend::Console => {
            // SAFETY: single-CPU SYSCALL context.
            let readable = unsafe { crate::console::console_has_byte() };
            (readable, true, false)
        }
        FileBackend::EventFd { id } => {
            // Readable when the counter is non-zero; writable when a write of
            // at least 1 would not overflow (counter < EVENTFD_MAX).
            // SAFETY: single-CPU SYSCALL context.
            match unsafe { eventfd_peek(id) } {
                Some((counter, _)) => (counter > 0, counter < EVENTFD_MAX, false),
                None => (false, false, false),
            }
        }
        FileBackend::EpollInstance { .. } => {
            // A nested epoll fd is reported never-ready to avoid recursing
            // into epoll_wait from the readiness scan. (Nested epoll is rare
            // and out of scope this phase.)
            (false, false, false)
        }
        FileBackend::TimerFd { id } => {
            // Readable once any expiration has accumulated; never writable
            // and no hangup.
            // SAFETY: single-CPU SYSCALL context.
            match unsafe { timerfd_peek(id) } {
                Some(exp) => (exp > 0, false, false),
                None => (false, false, false),
            }
        }
        FileBackend::SignalFd { id } => {
            // Readable when any signal in the watched mask is pending on
            // the owning process; never writable; no hangup.
            // SAFETY: single-CPU SYSCALL context.
            let pending = unsafe {
                match signalfd_peek(id) {
                    Some((mask, owner)) => signalfd_next_pending(owner, mask).is_some(),
                    None => false,
                }
            };
            (pending, false, false)
        }
        FileBackend::RamfsFile { .. }
        | FileBackend::DevFile { .. }
        | FileBackend::ProcFile { .. }
        | FileBackend::Socket { .. } => (true, true, false),
    };
    Some(ready)
}

unsafe fn poll_one(fd: usize, events: i16) -> i16 {
    // SAFETY: single-CPU SYSCALL context.
    let (readable, writable, hup) = match unsafe { fd_readiness(fd) } {
        Some(r) => r,
        None => return POLLNVAL,
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

// ── select ────────────────────────────────────────────────────────

/// `fd_set` size in bits — the classic 1024-descriptor limit.
const FD_SETSIZE: usize = 1024;
/// `fd_set` size in `u64` words (`1024 / 64`).
const FD_SET_WORDS: usize = FD_SETSIZE / 64;

/// Read an `fd_set` bitmap (`[u64; FD_SET_WORDS]`) from user space, or
/// return an all-zero set if `ptr` is null.
///
/// # Safety
///
/// `ptr`, when non-null, must address a readable `fd_set` (128 bytes).
unsafe fn fdset_read(ptr: u64, out: &mut [u64; FD_SET_WORDS]) {
    if ptr == 0 {
        return;
    }
    // SAFETY: caller guarantees `ptr` addresses a 128-byte fd_set.
    unsafe {
        let words = ptr as *const u64;
        for (i, w) in out.iter_mut().enumerate() {
            *w = words.add(i).read_volatile();
        }
    }
}

/// Write an `fd_set` bitmap back to user space; no-op if `ptr` is null.
///
/// # Safety
///
/// `ptr`, when non-null, must address a writable `fd_set` (128 bytes).
unsafe fn fdset_write(ptr: u64, src: &[u64; FD_SET_WORDS]) {
    if ptr == 0 {
        return;
    }
    // SAFETY: caller guarantees `ptr` addresses a 128-byte fd_set.
    unsafe {
        let words = ptr as *mut u64;
        for (i, &w) in src.iter().enumerate() {
            words.add(i).write_volatile(w);
        }
    }
}

/// Test bit `fd` in an `fd_set` bitmap.
fn fdset_test(set: &[u64; FD_SET_WORDS], fd: usize) -> bool {
    (set[fd / 64] >> (fd % 64)) & 1 != 0
}

/// Set bit `fd` in an `fd_set` bitmap.
fn fdset_set(set: &mut [u64; FD_SET_WORDS], fd: usize) {
    set[fd / 64] |= 1u64 << (fd % 64);
}

/// Kernel handler for `SYS_SELECT` (Linux number 23).
///
/// POSIX.1-2024 `select(2)`: examines descriptors `0..nfds` in the three
/// `fd_set` bitmaps and reports which are ready for reading, writing, or
/// have an exceptional condition. Each `fd_set` is a 1024-bit bitmap
/// (`[u64; 16]`, 128 bytes). A null set pointer means "not interested".
///
/// `timeout_ptr` points to a `struct timeval { tv_sec: i64, tv_usec: i64 }`:
/// null blocks indefinitely; a zero-valued timeval performs a single
/// non-blocking scan; a positive value bounds the wait. Blocking uses
/// cooperative `yield_now` polling (same model as `poll`).
///
/// On return the three bitmaps are rewritten in place to contain only the
/// ready descriptors. Readiness reuses [`fd_readiness`]: a pipe writer
/// hangup counts as read-ready (read returns EOF); the exceptfds set is
/// only marked for a not-open fd is impossible here (those are simply not
/// reported), so no exceptional conditions are currently raised.
///
/// Returns the total number of ready descriptors across all sets, `0` on
/// timeout, or a negative errno: `-EINVAL` (22) if `nfds` is negative or
/// exceeds [`FD_SETSIZE`], `-EFAULT` (14) for a bad pointer.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU, interrupts
/// effectively disabled). The set and timeout pointers, when non-null, must
/// address writable user memory of the documented sizes.
pub unsafe fn sys_select(
    nfds: i64,
    readfds_ptr: u64,
    writefds_ptr: u64,
    exceptfds_ptr: u64,
    timeout_ptr: u64,
) -> i64 {
    if nfds < 0 || nfds as usize > FD_SETSIZE {
        return -22; // EINVAL
    }
    let nfds = nfds as usize;

    // Reject non-null but non-canonical user pointers.
    for &p in &[readfds_ptr, writefds_ptr, exceptfds_ptr, timeout_ptr] {
        if p != 0 && p >= 0xFFFF_8000_0000_0000 {
            return -14; // EFAULT
        }
    }

    // Snapshot the input sets once (POSIX: only ready bits remain on output).
    let mut in_read = [0u64; FD_SET_WORDS];
    let mut in_write = [0u64; FD_SET_WORDS];
    let mut in_except = [0u64; FD_SET_WORDS];
    // SAFETY: pointers validated user-canonical above.
    unsafe {
        fdset_read(readfds_ptr, &mut in_read);
        fdset_read(writefds_ptr, &mut in_write);
        fdset_read(exceptfds_ptr, &mut in_except);
    }

    // Resolve the timeout: None = block forever; Some(ticks) = a deadline
    // (0 ticks => non-blocking single scan).
    let timeout_ticks: Option<u64> = if timeout_ptr == 0 {
        None
    } else {
        // SAFETY: pointer validated user-canonical above; reads two i64.
        let (secs, usecs) = unsafe {
            let p = timeout_ptr as *const i64;
            (p.read_volatile(), p.add(1).read_volatile())
        };
        if secs < 0 || usecs < 0 {
            return -22; // EINVAL
        }
        let total_us = (secs as u64)
            .saturating_mul(1_000_000)
            .saturating_add(usecs as u64);
        Some(total_us.saturating_mul(POLL_TIMER_HZ) / 1_000_000)
    };

    let nonblocking = matches!(timeout_ticks, Some(0));
    let deadline = match timeout_ticks {
        Some(t) if t > 0 => {
            // SAFETY: single-CPU SYSCALL context.
            Some(unsafe { poll_now_ticks() }.saturating_add(t))
        }
        _ => None,
    };

    loop {
        let mut out_read = [0u64; FD_SET_WORDS];
        let mut out_write = [0u64; FD_SET_WORDS];
        let out_except = [0u64; FD_SET_WORDS];
        let mut ready = 0i64;

        for fd in 0..nfds {
            let want_read = fdset_test(&in_read, fd);
            let want_write = fdset_test(&in_write, fd);
            let want_except = fdset_test(&in_except, fd);
            if !want_read && !want_write && !want_except {
                continue;
            }
            // SAFETY: single-CPU SYSCALL context.
            let (readable, writable, hup) = match unsafe { fd_readiness(fd) } {
                Some(r) => r,
                None => continue, // not open: not reported ready
            };
            if want_read && (readable || hup) {
                fdset_set(&mut out_read, fd);
                ready += 1;
            }
            if want_write && writable {
                fdset_set(&mut out_write, fd);
                ready += 1;
            }
            // No exceptional conditions are currently raised for any backend.
        }

        let expired = match deadline {
            // SAFETY: single-CPU SYSCALL context.
            Some(d) => (unsafe { poll_now_ticks() }) >= d,
            None => false,
        };

        if ready > 0 || nonblocking || expired {
            // SAFETY: pointers validated user-canonical above.
            unsafe {
                fdset_write(readfds_ptr, &out_read);
                fdset_write(writefds_ptr, &out_write);
                fdset_write(exceptfds_ptr, &out_except);
            }
            return ready;
        }

        // SAFETY: SYSCALL context; cooperative yield (same model as poll).
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
        FileBackend::SocketPair { write_ring, .. } => {
            // Write into our write ring (the peer reads from it). Mirrors the
            // pipe write end: EPIPE if the peer closed its read end.
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
                    match crate::pipe::pipe_get_mut(write_ring) {
                        Some(r) => r,
                        None => return -32, // EPIPE — slot gone
                    }
                };
                if !ring.read_open {
                    return -32; // EPIPE — peer closed its read end
                }
                written += ring.push(&kbuf[written..count]);
                if written >= count {
                    return written as i64;
                }
                if nonblock {
                    if written > 0 {
                        return written as i64;
                    }
                    return -11; // EAGAIN
                }
                // SAFETY: SYSCALL context; cooperative yield.
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
        FileBackend::EventFd { id } => {
            // eventfd write: the buffer must hold a u64; the value
            // 0xffff_ffff_ffff_ffff is rejected; otherwise the value is added
            // to the counter, blocking (or EAGAIN) if it would overflow past
            // EVENTFD_MAX until a read drains it.
            if count < 8 {
                return -22; // EINVAL — short write
            }
            // SAFETY: `buf_ptr` validated above; reading 8 bytes.
            let add = unsafe {
                let mut bytes = [0u8; 8];
                let ptr = buf_ptr as *const u8;
                for (i, b) in bytes.iter_mut().enumerate() {
                    *b = ptr.add(i).read_volatile();
                }
                u64::from_ne_bytes(bytes)
            };
            if add == u64::MAX {
                return -22; // EINVAL — reserved sentinel
            }
            let nonblock = handle.flags.is_nonblock();
            loop {
                // SAFETY: single-CPU SYSCALL context.
                let cur = match unsafe { eventfd_peek(id) } {
                    Some((c, _)) => c,
                    None => return -9, // EBADF — slot gone
                };
                // The add fits iff cur + add <= EVENTFD_MAX.
                if add <= EVENTFD_MAX - cur {
                    // SAFETY: single-CPU SYSCALL context.
                    unsafe {
                        #[allow(static_mut_refs)]
                        if let Some(slot) = EVENTFD_TABLE.get_mut(id as usize) {
                            slot.counter = cur + add;
                        }
                    }
                    return 8;
                }
                if nonblock {
                    return -11; // EAGAIN
                }
                // SAFETY: SYSCALL context; cooperative yield.
                unsafe {
                    let _ = crate::current::yield_now();
                }
            }
        }
        FileBackend::EpollInstance { .. } => -22, // EINVAL — epoll fd is not writable
        FileBackend::TimerFd { .. } => -22,       // EINVAL — timerfd is not writable
        FileBackend::SignalFd { .. } => -22,      // EINVAL — signalfd is not writable
    }
}

/// Set the file offset of `fd` in the current thread's table.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU).
unsafe fn set_fd_offset(fd: usize, offset: u64) {
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        if let Some(t) = crate::current::current_thread_mut()
            && let Some(h) = t.fd_table.get_mut(fd)
        {
            h.offset = offset;
        }
    }
}

/// Kernel handler for `SYS_PREAD64` (Linux number 17).
///
/// POSIX `pread(fd, buf, count, offset)`: read `count` bytes at `offset`
/// without changing the file's current position. Only seekable backends
/// (`RamfsFile`) are supported; pipes / sockets / fifos return `-ESPIPE`.
///
/// Implemented by temporarily setting the handle offset to `offset`,
/// delegating to [`dispatch_read`], then restoring the saved offset.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU).
pub unsafe fn dispatch_pread(fd: usize, buf_ptr: u64, count: u64, offset: u64) -> i64 {
    // SAFETY: single-CPU SYSCALL context.
    let saved = unsafe {
        match fd_get(fd) {
            Some(h) => match h.backend {
                FileBackend::RamfsFile { .. } => h.offset,
                _ => return -29, // ESPIPE — not seekable
            },
            None => return -9, // EBADF
        }
    };
    // SAFETY: single-CPU SYSCALL context.
    unsafe { set_fd_offset(fd, offset) };
    // SAFETY: same context; dispatch_read reads at the handle offset.
    let n = unsafe { dispatch_read(fd, buf_ptr, count) };
    // SAFETY: restore the pre-pread file position regardless of outcome.
    unsafe { set_fd_offset(fd, saved) };
    n
}

/// Kernel handler for `SYS_PWRITE64` (Linux number 18).
///
/// POSIX `pwrite(fd, buf, count, offset)`: write `count` bytes at `offset`
/// without changing the file's current position. Only seekable backends
/// (`RamfsFile`) are supported; others return `-ESPIPE`.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU).
pub unsafe fn dispatch_pwrite(fd: usize, buf_ptr: u64, count: u64, offset: u64) -> i64 {
    // SAFETY: single-CPU SYSCALL context.
    let saved = unsafe {
        match fd_get(fd) {
            Some(h) => match h.backend {
                FileBackend::RamfsFile { .. } => h.offset,
                _ => return -29, // ESPIPE — not seekable
            },
            None => return -9, // EBADF
        }
    };
    // SAFETY: single-CPU SYSCALL context.
    unsafe { set_fd_offset(fd, offset) };
    // SAFETY: same context; dispatch_write writes at the handle offset.
    let n = unsafe { dispatch_write(fd, buf_ptr, count) };
    // SAFETY: restore the pre-pwrite file position regardless of outcome.
    unsafe { set_fd_offset(fd, saved) };
    n
}

/// POSIX `read(2)` — read up to `count` bytes from `fd` at its current file
/// position, advancing the position by the number of bytes read.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU). `buf_ptr`
/// must reference `count` writable user bytes.
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
        FileBackend::SocketPair { read_ring, .. } => {
            // Read from our read ring (the peer writes into it). Mirrors the
            // pipe read end: EOF when the peer closed its write end.
            let nonblock = handle.flags.is_nonblock();
            let user_ptr = buf_ptr as *mut u8;
            loop {
                // SAFETY: Single-CPU SYSCALL context.
                let ring = unsafe {
                    match crate::pipe::pipe_get_mut(read_ring) {
                        Some(r) => r,
                        None => return -9, // slot gone
                    }
                };
                let mut kbuf = [0u8; 4096];
                let n = ring.pop(&mut kbuf[..count]);
                if n > 0 {
                    // SAFETY: `buf_ptr` validated above.
                    unsafe {
                        for (i, &byte) in kbuf.iter().take(n).enumerate() {
                            user_ptr.add(i).write_volatile(byte);
                        }
                    }
                    return n as i64;
                }
                if !ring.write_open {
                    return 0; // POSIX EOF — peer closed its write end
                }
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
        FileBackend::EventFd { id } => {
            // eventfd read: the buffer must hold a u64. Blocks (or EAGAIN)
            // while the counter is zero. On a non-zero counter: in semaphore
            // mode return 1 and decrement by 1; otherwise return the whole
            // counter and zero it.
            if count < 8 {
                return -22; // EINVAL — short read
            }
            let nonblock = handle.flags.is_nonblock();
            loop {
                // SAFETY: single-CPU SYSCALL context.
                let (counter, semaphore) = match unsafe { eventfd_peek(id) } {
                    Some(v) => v,
                    None => return -9, // EBADF — slot gone
                };
                if counter > 0 {
                    let out = if semaphore { 1u64 } else { counter };
                    // SAFETY: single-CPU SYSCALL context.
                    unsafe {
                        #[allow(static_mut_refs)]
                        if let Some(slot) = EVENTFD_TABLE.get_mut(id as usize) {
                            slot.counter = if semaphore { counter - 1 } else { 0 };
                        }
                    }
                    // SAFETY: `buf_ptr` validated above; writing 8 bytes.
                    unsafe {
                        let bytes = out.to_ne_bytes();
                        let ptr = buf_ptr as *mut u8;
                        for (i, &b) in bytes.iter().enumerate() {
                            ptr.add(i).write_volatile(b);
                        }
                    }
                    return 8;
                }
                if nonblock {
                    return -11; // EAGAIN
                }
                // SAFETY: SYSCALL context; cooperative yield.
                unsafe {
                    let _ = crate::current::yield_now();
                }
            }
        }
        FileBackend::EpollInstance { .. } => -22, // EINVAL — epoll fd is not readable
        FileBackend::TimerFd { id } => {
            // timerfd read: yields the accumulated expiration count as a
            // u64 then zeros it. Blocks while the count is zero unless
            // O_NONBLOCK is set, in which case returns -EAGAIN.
            if count < 8 {
                return -22; // EINVAL — short read
            }
            let nonblock = handle.flags.is_nonblock();
            loop {
                // SAFETY: single-CPU SYSCALL context.
                let exp = match unsafe { timerfd_peek(id) } {
                    Some(c) => c,
                    None => return -9, // EBADF — slot gone
                };
                if exp > 0 {
                    // SAFETY: single-CPU SYSCALL context.
                    unsafe {
                        #[allow(static_mut_refs)]
                        if let Some(slot) = TIMERFD_TABLE.get_mut(id as usize) {
                            slot.expirations = 0;
                        }
                    }
                    // SAFETY: `buf_ptr` validated above; writing 8 bytes.
                    unsafe {
                        let bytes = exp.to_ne_bytes();
                        let ptr = buf_ptr as *mut u8;
                        for (i, &b) in bytes.iter().enumerate() {
                            ptr.add(i).write_volatile(b);
                        }
                    }
                    return 8;
                }
                if nonblock {
                    return -11; // EAGAIN
                }
                // SAFETY: SYSCALL context; cooperative yield.
                unsafe {
                    let _ = crate::current::yield_now();
                }
            }
        }
        FileBackend::SignalFd { id } => {
            // signalfd read: emit one signalfd_siginfo per call. Block (or
            // -EAGAIN) until a signal in the watched mask is pending on the
            // owning process; consume the pending bit before returning.
            if count < SIGNALFD_SIGINFO_SIZE {
                return -22; // EINVAL — short read
            }
            // SAFETY: single-CPU SYSCALL context.
            let (mask, owner_pid) = match unsafe { signalfd_peek(id) } {
                Some(v) => v,
                None => return -9, // EBADF — slot gone
            };
            let nonblock = handle.flags.is_nonblock();
            loop {
                // SAFETY: single-CPU SYSCALL context.
                let next = unsafe { signalfd_next_pending(owner_pid, mask) };
                if let Some(signo) = next {
                    // SAFETY: single-CPU SYSCALL context.
                    let consumed = unsafe { signalfd_consume(owner_pid, signo) };
                    if !consumed {
                        // Lost the race — re-scan.
                        continue;
                    }
                    // Build a zeroed signalfd_siginfo and fill ssi_signo
                    // (u32 @0) and ssi_code (i32 @8). Phase: other fields
                    // (errno, pid, uid, status, etc.) are not populated.
                    let mut info = [0u8; SIGNALFD_SIGINFO_SIZE];
                    info[0..4].copy_from_slice(&(signo as u32).to_ne_bytes());
                    // ssi_code = SI_KERNEL (0x80) for kernel-raised signals.
                    info[8..12].copy_from_slice(&0x80i32.to_ne_bytes());
                    // SAFETY: `buf_ptr` validated above; writing 128 bytes.
                    unsafe {
                        let ptr = buf_ptr as *mut u8;
                        for (i, &b) in info.iter().enumerate() {
                            ptr.add(i).write_volatile(b);
                        }
                    }
                    return SIGNALFD_SIGINFO_SIZE as i64;
                }
                if nonblock {
                    return -11; // EAGAIN
                }
                // SAFETY: SYSCALL context; cooperative yield.
                unsafe {
                    let _ = crate::current::yield_now();
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
        FileBackend::Console => -29,              // ESPIPE
        FileBackend::Pipe { .. } => -29,          // ESPIPE
        FileBackend::SocketPair { .. } => -29,    // ESPIPE
        FileBackend::Socket { .. } => -29,        // ESPIPE
        FileBackend::DevFile { .. } => -29,       // ESPIPE
        FileBackend::ProcFile { .. } => -29,      // ESPIPE
        FileBackend::EventFd { .. } => -29,       // ESPIPE
        FileBackend::EpollInstance { .. } => -29, // ESPIPE
        FileBackend::TimerFd { .. } => -29,       // ESPIPE
        FileBackend::SignalFd { .. } => -29,      // ESPIPE
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
