// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended signalfd implementation with batch reads and RT signal queuing.
//!
//! Extends the base `signalfd(2)` support with:
//! - 128-byte `SignalfdSiginfo` structure matching the Linux ABI
//! - Batch read: multiple signals returned in one `read()` call
//! - Signal coalescing for standard (non-RT) signals
//! - FIFO queuing for real-time signals (SIGRTMIN..SIGRTMAX)
//! - Mask updates via `signalfd` with an existing fd
//!
//! # Signal delivery model
//!
//! Standard signals (1..31) are coalesced — if the same signal is
//! delivered multiple times before a read, only one `SignalfdSiginfo`
//! is returned (with the latest info).
//!
//! Real-time signals (32..64) are queued individually in FIFO order,
//! up to the per-fd queue depth limit.
//!
//! # References
//!
//! - Linux: `fs/signalfd.c`
//! - man page: `signalfd(2)`, `signalfd4(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of signalfd instances.
const MAX_SIGNALFDS: usize = 64;

/// Maximum pending signals per signalfd (standard + RT queue).
const MAX_PENDING_SIGNALS: usize = 64;

/// Batch read buffer size (max signals returned in one read).
const MAX_BATCH_READ: usize = 16;

/// First real-time signal number.
const SIGRTMIN: u32 = 32;

/// Last real-time signal number.
const SIGRTMAX: u32 = 64;

/// Maximum standard signal number.
const SIG_MAX_STD: u32 = 31;

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Set close-on-exec on the signalfd.
pub const SFD_CLOEXEC: u32 = 0x80000;

/// Enable non-blocking reads.
pub const SFD_NONBLOCK: u32 = 0x800;

/// All valid signalfd flag bits.
const SFD_VALID_FLAGS: u32 = SFD_CLOEXEC | SFD_NONBLOCK;

// ---------------------------------------------------------------------------
// SignalfdSiginfo — 128-byte signal info structure
// ---------------------------------------------------------------------------

/// Signal information structure read from a signalfd.
///
/// Each successful read returns one or more 128-byte structures.
/// The layout matches `struct signalfd_siginfo` from the Linux kernel.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignalfdSiginfo {
    /// Signal number (1-based).
    pub ssi_signo: u32,
    /// Error number (errno value from the signal sender).
    pub ssi_errno: i32,
    /// Signal code (SI_USER, SI_KERNEL, etc.).
    pub ssi_code: i32,
    /// PID of the sender.
    pub ssi_pid: u32,
    /// Real UID of the sender.
    pub ssi_uid: u32,
    /// File descriptor (for SIGIO/SIGPOLL).
    pub ssi_fd: i32,
    /// Kernel timer ID (for POSIX timers).
    pub ssi_tid: u32,
    /// Band event (for SIGPOLL).
    pub ssi_band: u32,
    /// POSIX timer overrun count.
    pub ssi_overrun: u32,
    /// Trap number (architecture-specific).
    pub ssi_trapno: u32,
    /// Exit status or signal number (for SIGCHLD).
    pub ssi_status: i32,
    /// Integer data from `sigqueue(3)`.
    pub ssi_int: i32,
    /// Pointer data from `sigqueue(3)`.
    pub ssi_ptr: u64,
    /// User time consumed (for SIGCHLD).
    pub ssi_utime: u64,
    /// System time consumed (for SIGCHLD).
    pub ssi_stime: u64,
    /// Faulting address (for SIGSEGV, SIGBUS, etc.).
    pub ssi_addr: u64,
    /// Address LSB (for SIGBUS with BUS_MCEERR_AO/AR).
    pub ssi_addr_lsb: u16,
    /// Padding to reach 128 bytes total.
    _pad: [u8; 46],
}

impl SignalfdSiginfo {
    /// Create a zeroed `SignalfdSiginfo`.
    pub const fn zeroed() -> Self {
        Self {
            ssi_signo: 0,
            ssi_errno: 0,
            ssi_code: 0,
            ssi_pid: 0,
            ssi_uid: 0,
            ssi_fd: 0,
            ssi_tid: 0,
            ssi_band: 0,
            ssi_overrun: 0,
            ssi_trapno: 0,
            ssi_status: 0,
            ssi_int: 0,
            ssi_ptr: 0,
            ssi_utime: 0,
            ssi_stime: 0,
            ssi_addr: 0,
            ssi_addr_lsb: 0,
            _pad: [0; 46],
        }
    }

    /// Create a basic `SignalfdSiginfo` for a given signal number.
    pub const fn from_signo(signo: u32) -> Self {
        let mut info = Self::zeroed();
        info.ssi_signo = signo;
        info
    }

    /// Return the size of the structure in bytes.
    pub const fn size() -> usize {
        128
    }

    /// Return `true` if this is a real-time signal.
    pub const fn is_realtime(&self) -> bool {
        self.ssi_signo >= SIGRTMIN && self.ssi_signo <= SIGRTMAX
    }

    /// Return `true` if this is a standard signal.
    pub const fn is_standard(&self) -> bool {
        self.ssi_signo >= 1 && self.ssi_signo <= SIG_MAX_STD
    }
}

impl Default for SignalfdSiginfo {
    fn default() -> Self {
        Self::zeroed()
    }
}

// Compile-time check: SignalfdSiginfo must be exactly 128 bytes.
const _: () = {
    assert!(core::mem::size_of::<SignalfdSiginfo>() == 128);
};

// ---------------------------------------------------------------------------
// SignalfdExt — extended signalfd instance
// ---------------------------------------------------------------------------

/// An extended signalfd instance with batch read and RT queuing.
///
/// Standard signals are stored in a coalescing array indexed by
/// signal number. Real-time signals are queued FIFO in a separate
/// ring buffer.
pub struct SignalfdExt {
    /// Unique identifier.
    id: u64,
    /// Signal mask (bit N = listening for signal N+1).
    mask: u64,
    /// Creation flags.
    flags: u32,
    /// PID of the owning process.
    owner_pid: u64,
    /// Whether this slot is in use.
    active: bool,
    /// Standard signal pending bitmap (bit N = signal N+1 pending).
    std_pending_bitmap: u32,
    /// Standard signal info (indexed by signo-1, signals 1..31).
    std_signals: [SignalfdSiginfo; SIG_MAX_STD as usize],
    /// RT signal queue (FIFO ring buffer).
    rt_queue: [SignalfdSiginfo; MAX_PENDING_SIGNALS],
    /// RT queue head index.
    rt_head: usize,
    /// RT queue tail index.
    rt_tail: usize,
    /// RT queue count.
    rt_count: usize,
    /// Total signals delivered (statistics).
    total_delivered: u64,
    /// Total signals read (statistics).
    total_read: u64,
}

impl SignalfdExt {
    /// Create an inactive signalfd.
    const fn new() -> Self {
        Self {
            id: 0,
            mask: 0,
            flags: 0,
            owner_pid: 0,
            active: false,
            std_pending_bitmap: 0,
            std_signals: [const { SignalfdSiginfo::zeroed() }; SIG_MAX_STD as usize],
            rt_queue: [const { SignalfdSiginfo::zeroed() }; MAX_PENDING_SIGNALS],
            rt_head: 0,
            rt_tail: 0,
            rt_count: 0,
            total_delivered: 0,
            total_read: 0,
        }
    }

    /// Return the signalfd ID.
    pub const fn id(&self) -> u64 {
        self.id
    }

    /// Return the signal mask.
    pub const fn mask(&self) -> u64 {
        self.mask
    }

    /// Return the creation flags.
    pub const fn flags(&self) -> u32 {
        self.flags
    }

    /// Return the owner PID.
    pub const fn owner_pid(&self) -> u64 {
        self.owner_pid
    }

    /// Return whether this signalfd is active.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Return the number of pending standard signals.
    pub fn std_pending_count(&self) -> u32 {
        self.std_pending_bitmap.count_ones()
    }

    /// Return the number of pending RT signals.
    pub const fn rt_pending_count(&self) -> usize {
        self.rt_count
    }

    /// Return the total number of pending signals.
    pub fn total_pending(&self) -> usize {
        self.std_pending_count() as usize + self.rt_count
    }

    /// Return total signals delivered.
    pub const fn total_delivered(&self) -> u64 {
        self.total_delivered
    }

    /// Return total signals read.
    pub const fn total_read(&self) -> u64 {
        self.total_read
    }

    /// Return `true` if there are any pending signals.
    pub fn has_pending(&self) -> bool {
        self.std_pending_bitmap != 0 || self.rt_count > 0
    }
}

// ---------------------------------------------------------------------------
// SignalfdExtRegistry
// ---------------------------------------------------------------------------

/// Registry managing extended signalfd instances.
pub struct SignalfdExtRegistry {
    /// Signalfd slot array.
    fds: [SignalfdExt; MAX_SIGNALFDS],
    /// Next ID to assign.
    next_id: u64,
    /// Number of active signalfds.
    count: usize,
}

impl SignalfdExtRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            fds: [const { SignalfdExt::new() }; MAX_SIGNALFDS],
            next_id: 1,
            count: 0,
        }
    }

    /// Return the number of active signalfds.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return `true` if no signalfds are active.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    // ---------------------------------------------------------------
    // Lookup helpers
    // ---------------------------------------------------------------

    /// Find an active signalfd by ID (shared reference).
    fn find(&self, id: u64) -> Result<&SignalfdExt> {
        self.fds
            .iter()
            .find(|f| f.active && f.id == id)
            .ok_or(Error::NotFound)
    }

    /// Find an active signalfd by ID (mutable reference).
    fn find_mut(&mut self, id: u64) -> Result<&mut SignalfdExt> {
        self.fds
            .iter_mut()
            .find(|f| f.active && f.id == id)
            .ok_or(Error::NotFound)
    }

    // ---------------------------------------------------------------
    // signalfd create / update mask
    // ---------------------------------------------------------------

    /// Create a new signalfd or update the mask of an existing one.
    ///
    /// If `existing_id` is `Some(id)`, updates the mask of that fd.
    /// If `None`, creates a new signalfd.
    pub fn create_or_update(
        &mut self,
        existing_id: Option<u64>,
        mask: u64,
        flags: u32,
        pid: u64,
    ) -> Result<u64> {
        if (flags & !SFD_VALID_FLAGS) != 0 {
            return Err(Error::InvalidArgument);
        }

        if mask == 0 {
            return Err(Error::InvalidArgument);
        }

        if let Some(id) = existing_id {
            // Update existing signalfd mask.
            let fd = self.find_mut(id)?;
            fd.mask = mask;
            return Ok(id);
        }

        // Create new signalfd.
        let idx = self
            .fds
            .iter()
            .position(|f| !f.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let slot = &mut self.fds[idx];
        slot.id = id;
        slot.mask = mask;
        slot.flags = flags;
        slot.owner_pid = pid;
        slot.active = true;
        slot.std_pending_bitmap = 0;
        slot.rt_head = 0;
        slot.rt_tail = 0;
        slot.rt_count = 0;
        slot.total_delivered = 0;
        slot.total_read = 0;

        self.count += 1;
        Ok(id)
    }

    // ---------------------------------------------------------------
    // Signal delivery
    // ---------------------------------------------------------------

    /// Deliver a signal to a signalfd.
    ///
    /// Standard signals are coalesced (latest info replaces previous).
    /// RT signals are queued FIFO. Returns `OutOfMemory` if the RT
    /// queue is full.
    pub fn deliver(&mut self, id: u64, info: &SignalfdSiginfo) -> Result<()> {
        let fd = self.find_mut(id)?;

        let signo = info.ssi_signo;
        if signo == 0 {
            return Err(Error::InvalidArgument);
        }

        // Check that signal is in the mask.
        let bit = 1u64 << (signo - 1);
        if fd.mask & bit == 0 {
            return Err(Error::InvalidArgument);
        }

        if signo >= SIGRTMIN && signo <= SIGRTMAX {
            // RT signal: queue FIFO.
            if fd.rt_count >= MAX_PENDING_SIGNALS {
                return Err(Error::OutOfMemory);
            }
            fd.rt_queue[fd.rt_tail] = *info;
            fd.rt_tail = (fd.rt_tail + 1) % MAX_PENDING_SIGNALS;
            fd.rt_count += 1;
        } else if signo >= 1 && signo <= SIG_MAX_STD {
            // Standard signal: coalesce (overwrite).
            let idx = (signo - 1) as usize;
            fd.std_signals[idx] = *info;
            fd.std_pending_bitmap |= 1 << (signo - 1);
        } else {
            return Err(Error::InvalidArgument);
        }

        fd.total_delivered = fd.total_delivered.saturating_add(1);
        Ok(())
    }

    // ---------------------------------------------------------------
    // Batch read
    // ---------------------------------------------------------------

    /// Read up to `max_count` pending signals from a signalfd.
    ///
    /// Standard signals are returned first (lowest number first),
    /// then RT signals in FIFO order. Returns the slice of the
    /// output buffer that was filled.
    ///
    /// # Arguments
    ///
    /// * `id` — Signalfd ID.
    /// * `buf` — Output buffer for signal info structures.
    /// * `max_count` — Maximum number of signals to read (capped at
    ///   `buf.len()` and [`MAX_BATCH_READ`]).
    ///
    /// # Returns
    ///
    /// Number of signals actually read.
    ///
    /// # Errors
    ///
    /// * [`Error::WouldBlock`] — No pending signals and fd is non-blocking.
    /// * [`Error::NotFound`] — Invalid signalfd ID.
    pub fn batch_read(
        &mut self,
        id: u64,
        buf: &mut [SignalfdSiginfo],
        max_count: usize,
    ) -> Result<usize> {
        let fd = self.find_mut(id)?;

        if !fd.has_pending() {
            if fd.flags & SFD_NONBLOCK != 0 {
                return Err(Error::WouldBlock);
            }
            return Err(Error::WouldBlock);
        }

        let limit = max_count.min(buf.len()).min(MAX_BATCH_READ);
        let mut read_count = 0usize;

        // Read standard signals first (lowest signal number first).
        let mut bitmap = fd.std_pending_bitmap;
        while bitmap != 0 && read_count < limit {
            let bit = bitmap.trailing_zeros();
            if bit >= SIG_MAX_STD {
                break;
            }
            buf[read_count] = fd.std_signals[bit as usize];
            fd.std_pending_bitmap &= !(1 << bit);
            bitmap &= !(1 << bit);
            read_count += 1;
        }

        // Read RT signals FIFO.
        while fd.rt_count > 0 && read_count < limit {
            buf[read_count] = fd.rt_queue[fd.rt_head];
            fd.rt_head = (fd.rt_head + 1) % MAX_PENDING_SIGNALS;
            fd.rt_count -= 1;
            read_count += 1;
        }

        fd.total_read = fd.total_read.saturating_add(read_count as u64);
        Ok(read_count)
    }

    /// Read a single signal from a signalfd.
    ///
    /// Convenience wrapper around [`batch_read`](Self::batch_read).
    pub fn read_one(&mut self, id: u64) -> Result<SignalfdSiginfo> {
        let mut buf = [SignalfdSiginfo::zeroed()];
        let n = self.batch_read(id, &mut buf, 1)?;
        if n == 0 {
            return Err(Error::WouldBlock);
        }
        Ok(buf[0])
    }

    // ---------------------------------------------------------------
    // Poll
    // ---------------------------------------------------------------

    /// Poll a signalfd for readiness.
    ///
    /// Returns a bitmask: bit 0 (POLLIN) if signals are pending.
    pub fn poll(&self, id: u64) -> Result<u32> {
        let fd = self.find(id)?;
        if fd.has_pending() { Ok(0x01) } else { Ok(0) }
    }

    // ---------------------------------------------------------------
    // Close / cleanup
    // ---------------------------------------------------------------

    /// Close a signalfd by ID.
    pub fn close(&mut self, id: u64) -> Result<()> {
        let fd = self.find_mut(id)?;
        fd.active = false;
        fd.mask = 0;
        fd.std_pending_bitmap = 0;
        fd.rt_count = 0;
        fd.rt_head = 0;
        fd.rt_tail = 0;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Close all signalfds owned by the given PID.
    pub fn cleanup_pid(&mut self, pid: u64) {
        for slot in self.fds.iter_mut() {
            if slot.active && slot.owner_pid == pid {
                slot.active = false;
                slot.mask = 0;
                slot.std_pending_bitmap = 0;
                slot.rt_count = 0;
                slot.rt_head = 0;
                slot.rt_tail = 0;
                self.count = self.count.saturating_sub(1);
            }
        }
    }
}

impl Default for SignalfdExtRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Syscall-level wrappers
// ---------------------------------------------------------------------------

/// Create a new signalfd or update mask of an existing one.
///
/// # Arguments
///
/// * `registry` — The global signalfd registry.
/// * `fd`       — -1 to create a new signalfd, or an existing ID to update.
/// * `mask`     — Signal mask (bit N = signal N+1).
/// * `flags`    — `SFD_CLOEXEC` and/or `SFD_NONBLOCK`.
/// * `pid`      — Calling process ID.
///
/// # Returns
///
/// The signalfd ID on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Invalid flags or zero mask.
/// * [`Error::OutOfMemory`] — Registry is full (create) or ID not found (update).
pub fn sys_signalfd(
    registry: &mut SignalfdExtRegistry,
    fd: i64,
    mask: u64,
    flags: u32,
    pid: u64,
) -> Result<u64> {
    let existing_id = if fd < 0 { None } else { Some(fd as u64) };
    registry.create_or_update(existing_id, mask, flags, pid)
}

/// Read up to `max_signals` pending signals from a signalfd.
///
/// Returns the number of signals actually read. Each signal is
/// a 128-byte [`SignalfdSiginfo`] structure.
///
/// # Errors
///
/// * [`Error::WouldBlock`] — No pending signals.
/// * [`Error::NotFound`] — Invalid signalfd ID.
pub fn sys_signalfd_read(
    registry: &mut SignalfdExtRegistry,
    id: u64,
    buf: &mut [SignalfdSiginfo],
    max_signals: usize,
) -> Result<usize> {
    registry.batch_read(id, buf, max_signals)
}

/// Deliver a signal to a signalfd.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Signal not in mask or zero signo.
/// * [`Error::OutOfMemory`] — RT queue full.
/// * [`Error::NotFound`] — Invalid signalfd ID.
pub fn sys_signalfd_deliver(
    registry: &mut SignalfdExtRegistry,
    id: u64,
    info: &SignalfdSiginfo,
) -> Result<()> {
    registry.deliver(id, info)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn siginfo(signo: u32) -> SignalfdSiginfo {
        SignalfdSiginfo::from_signo(signo)
    }

    #[test]
    fn siginfo_size_is_128_bytes() {
        assert_eq!(core::mem::size_of::<SignalfdSiginfo>(), 128);
    }

    #[test]
    fn create_signalfd() {
        let mut r = SignalfdExtRegistry::new();
        let id = sys_signalfd(&mut r, -1, 0x01, 0, 1);
        assert!(id.is_ok());
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn create_zero_mask_rejected() {
        let mut r = SignalfdExtRegistry::new();
        assert_eq!(
            sys_signalfd(&mut r, -1, 0, 0, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn create_invalid_flags_rejected() {
        let mut r = SignalfdExtRegistry::new();
        assert_eq!(
            sys_signalfd(&mut r, -1, 0x01, 0xDEAD, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn update_mask() {
        let mut r = SignalfdExtRegistry::new();
        let id = sys_signalfd(&mut r, -1, 0x01, 0, 1).unwrap();
        // Update mask.
        let id2 = sys_signalfd(&mut r, id as i64, 0x03, 0, 1).unwrap();
        assert_eq!(id, id2);
        assert_eq!(r.count(), 1); // No new fd created.
        let fd = r.find(id).unwrap();
        assert_eq!(fd.mask(), 0x03);
    }

    #[test]
    fn deliver_standard_signal() {
        let mut r = SignalfdExtRegistry::new();
        let mask = 0x01; // Signal 1 (SIGHUP).
        let id = sys_signalfd(&mut r, -1, mask, 0, 1).unwrap();
        let info = siginfo(1);
        assert_eq!(sys_signalfd_deliver(&mut r, id, &info), Ok(()));
        let fd = r.find(id).unwrap();
        assert_eq!(fd.total_pending(), 1);
    }

    #[test]
    fn standard_signal_coalescing() {
        let mut r = SignalfdExtRegistry::new();
        let mask = 0x01;
        let id = sys_signalfd(&mut r, -1, mask, SFD_NONBLOCK, 1).unwrap();
        // Deliver SIGHUP twice — should coalesce.
        let mut info1 = siginfo(1);
        info1.ssi_pid = 100;
        let _ = sys_signalfd_deliver(&mut r, id, &info1);
        let mut info2 = siginfo(1);
        info2.ssi_pid = 200;
        let _ = sys_signalfd_deliver(&mut r, id, &info2);
        let fd = r.find(id).unwrap();
        // Only one pending signal.
        assert_eq!(fd.std_pending_count(), 1);
        // Read should return the latest (pid=200).
        let result = r.read_one(id).unwrap();
        assert_eq!(result.ssi_pid, 200);
    }

    #[test]
    fn deliver_rt_signal_fifo() {
        let mut r = SignalfdExtRegistry::new();
        let mask = u64::MAX; // All signals.
        let id = sys_signalfd(&mut r, -1, mask, SFD_NONBLOCK, 1).unwrap();
        // Deliver 3 RT signals.
        let mut s1 = siginfo(SIGRTMIN);
        s1.ssi_int = 1;
        let mut s2 = siginfo(SIGRTMIN);
        s2.ssi_int = 2;
        let mut s3 = siginfo(SIGRTMIN);
        s3.ssi_int = 3;
        let _ = sys_signalfd_deliver(&mut r, id, &s1);
        let _ = sys_signalfd_deliver(&mut r, id, &s2);
        let _ = sys_signalfd_deliver(&mut r, id, &s3);
        let fd = r.find(id).unwrap();
        assert_eq!(fd.rt_pending_count(), 3);
        // Read in FIFO order.
        let r1 = r.read_one(id).unwrap();
        assert_eq!(r1.ssi_int, 1);
        let r2 = r.read_one(id).unwrap();
        assert_eq!(r2.ssi_int, 2);
    }

    #[test]
    fn batch_read_standard_then_rt() {
        let mut r = SignalfdExtRegistry::new();
        let mask = u64::MAX;
        let id = sys_signalfd(&mut r, -1, mask, SFD_NONBLOCK, 1).unwrap();
        // Deliver signal 2 (standard) and RT signal.
        let _ = sys_signalfd_deliver(&mut r, id, &siginfo(2));
        let _ = sys_signalfd_deliver(&mut r, id, &siginfo(SIGRTMIN));
        let mut buf = [SignalfdSiginfo::zeroed(); 4];
        let n = sys_signalfd_read(&mut r, id, &mut buf, 4).unwrap();
        assert_eq!(n, 2);
        // Standard signal first.
        assert_eq!(buf[0].ssi_signo, 2);
        // RT signal second.
        assert_eq!(buf[1].ssi_signo, SIGRTMIN);
    }

    #[test]
    fn read_empty_wouldblock() {
        let mut r = SignalfdExtRegistry::new();
        let id = sys_signalfd(&mut r, -1, 0x01, SFD_NONBLOCK, 1).unwrap();
        let mut buf = [SignalfdSiginfo::zeroed()];
        assert_eq!(
            sys_signalfd_read(&mut r, id, &mut buf, 1),
            Err(Error::WouldBlock)
        );
    }

    #[test]
    fn deliver_unmasked_signal_rejected() {
        let mut r = SignalfdExtRegistry::new();
        let mask = 0x01; // Only signal 1.
        let id = sys_signalfd(&mut r, -1, mask, 0, 1).unwrap();
        // Signal 2 is not in mask.
        assert_eq!(
            sys_signalfd_deliver(&mut r, id, &siginfo(2)),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn deliver_zero_signo_rejected() {
        let mut r = SignalfdExtRegistry::new();
        let id = sys_signalfd(&mut r, -1, u64::MAX, 0, 1).unwrap();
        assert_eq!(
            sys_signalfd_deliver(&mut r, id, &siginfo(0)),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn poll_with_pending() {
        let mut r = SignalfdExtRegistry::new();
        let id = sys_signalfd(&mut r, -1, 0x01, 0, 1).unwrap();
        assert_eq!(r.poll(id), Ok(0));
        let _ = sys_signalfd_deliver(&mut r, id, &siginfo(1));
        assert_eq!(r.poll(id), Ok(0x01));
    }

    #[test]
    fn close_signalfd() {
        let mut r = SignalfdExtRegistry::new();
        let id = sys_signalfd(&mut r, -1, 0x01, 0, 1).unwrap();
        assert_eq!(r.close(id), Ok(()));
        assert_eq!(r.count(), 0);
    }

    #[test]
    fn cleanup_pid() {
        let mut r = SignalfdExtRegistry::new();
        let _ = sys_signalfd(&mut r, -1, 0x01, 0, 42).unwrap();
        let _ = sys_signalfd(&mut r, -1, 0x01, 0, 42).unwrap();
        let _ = sys_signalfd(&mut r, -1, 0x01, 0, 99).unwrap();
        assert_eq!(r.count(), 3);
        r.cleanup_pid(42);
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn siginfo_is_rt_check() {
        assert!(siginfo(SIGRTMIN).is_realtime());
        assert!(siginfo(SIGRTMAX).is_realtime());
        assert!(!siginfo(1).is_realtime());
        assert!(siginfo(1).is_standard());
        assert!(!siginfo(SIGRTMIN).is_standard());
    }

    #[test]
    fn statistics_tracking() {
        let mut r = SignalfdExtRegistry::new();
        let id = sys_signalfd(&mut r, -1, u64::MAX, SFD_NONBLOCK, 1).unwrap();
        let _ = sys_signalfd_deliver(&mut r, id, &siginfo(1));
        let _ = sys_signalfd_deliver(&mut r, id, &siginfo(SIGRTMIN));
        let fd = r.find(id).unwrap();
        assert_eq!(fd.total_delivered(), 2);
        let mut buf = [SignalfdSiginfo::zeroed(); 4];
        let _ = sys_signalfd_read(&mut r, id, &mut buf, 4);
        let fd = r.find(id).unwrap();
        assert_eq!(fd.total_read(), 2);
    }
}
