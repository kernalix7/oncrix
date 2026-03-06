// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `io_uring_register(2)` — io_uring resource registration.
//!
//! This module implements the `io_uring_register` system call which
//! registers resources (buffers, files, eventfds) with an io_uring
//! instance to avoid repeated kernel lookups on the submission path.
//!
//! # Syscall signature
//!
//! ```text
//! int io_uring_register(unsigned int fd, unsigned int opcode,
//!                       void *arg, unsigned int nr_args);
//! ```
//!
//! # Opcodes
//!
//! | Opcode | Description |
//! |--------|-------------|
//! | `REGISTER_BUFFERS` | Register fixed buffers for zero-copy I/O |
//! | `UNREGISTER_BUFFERS` | Unregister previously registered buffers |
//! | `REGISTER_FILES` | Register fixed file descriptors |
//! | `UNREGISTER_FILES` | Unregister fixed file descriptors |
//! | `REGISTER_EVENTFD` | Register eventfd for completion notification |
//! | `UNREGISTER_EVENTFD` | Unregister eventfd |
//! | `REGISTER_FILES_UPDATE` | Update a subset of registered files |
//! | `REGISTER_PROBE` | Probe supported opcodes |
//! | `REGISTER_PERSONALITY` | Register credentials for SQEs |
//! | `UNREGISTER_PERSONALITY` | Unregister credentials |
//! | `REGISTER_RESTRICTIONS` | Apply restrictions to the ring |
//!
//! # Fixed buffers
//!
//! Registering buffers pins user pages in memory and pre-maps them
//! into kernel address space, eliminating per-I/O `get_user_pages`
//! overhead.
//!
//! # References
//!
//! - Linux: `io_uring/register.c`, `include/uapi/linux/io_uring.h`
//! - `io_uring_register(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants — opcodes
// ---------------------------------------------------------------------------

/// Register fixed I/O buffers.
pub const IORING_REGISTER_BUFFERS: u32 = 0;
/// Unregister fixed I/O buffers.
pub const IORING_UNREGISTER_BUFFERS: u32 = 1;
/// Register fixed file descriptors.
pub const IORING_REGISTER_FILES: u32 = 2;
/// Unregister fixed file descriptors.
pub const IORING_UNREGISTER_FILES: u32 = 3;
/// Register an eventfd for CQ notifications.
pub const IORING_REGISTER_EVENTFD: u32 = 4;
/// Unregister the eventfd.
pub const IORING_UNREGISTER_EVENTFD: u32 = 5;
/// Update a subset of registered files.
pub const IORING_REGISTER_FILES_UPDATE: u32 = 6;
/// Register an eventfd for async CQ notifications.
pub const IORING_REGISTER_EVENTFD_ASYNC: u32 = 7;
/// Probe supported operations.
pub const IORING_REGISTER_PROBE: u32 = 8;
/// Register a personality (credentials) for SQEs.
pub const IORING_REGISTER_PERSONALITY: u32 = 9;
/// Unregister a personality.
pub const IORING_UNREGISTER_PERSONALITY: u32 = 10;
/// Apply restrictions to the ring.
pub const IORING_REGISTER_RESTRICTIONS: u32 = 11;
/// Enable a disabled ring.
pub const IORING_REGISTER_ENABLE_RINGS: u32 = 12;

// ---------------------------------------------------------------------------
// Constants — restriction opcodes
// ---------------------------------------------------------------------------

/// Restrict to specific SQE opcodes.
pub const IORING_RESTRICTION_REGISTER_OP: u16 = 0;
/// Restrict to specific SQE flags.
pub const IORING_RESTRICTION_SQE_OP: u16 = 1;
/// Restrict SQE flags mask.
pub const IORING_RESTRICTION_SQE_FLAGS_ALLOWED: u16 = 2;
/// Restrict SQE flags required.
pub const IORING_RESTRICTION_SQE_FLAGS_REQUIRED: u16 = 3;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Maximum number of fixed buffers.
const MAX_FIXED_BUFFERS: usize = 64;

/// Maximum number of fixed file descriptors.
const MAX_FIXED_FILES: usize = 256;

/// Maximum number of registered personalities.
const MAX_PERSONALITIES: usize = 16;

/// Maximum number of restrictions.
const MAX_RESTRICTIONS: usize = 32;

/// Maximum number of probed operations.
const MAX_PROBE_OPS: usize = 64;

/// Sentinel for an empty file slot.
const FILE_SLOT_EMPTY: i32 = -1;

// ---------------------------------------------------------------------------
// IoVec — registered buffer descriptor
// ---------------------------------------------------------------------------

/// A registered I/O buffer (iovec equivalent).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoUringBuf {
    /// Base address of the buffer (user-space virtual address).
    pub base: u64,
    /// Length of the buffer in bytes.
    pub len: u64,
}

impl IoUringBuf {
    /// Create a new buffer descriptor.
    pub const fn new(base: u64, len: u64) -> Self {
        Self { base, len }
    }

    /// Validate the buffer descriptor.
    pub fn validate(&self) -> Result<()> {
        if self.len == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.base == 0 {
            return Err(Error::InvalidArgument);
        }
        // Check for overflow.
        self.base
            .checked_add(self.len)
            .ok_or(Error::InvalidArgument)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// IoUringPersonality — registered credentials
// ---------------------------------------------------------------------------

/// A registered personality (credential set) for io_uring SQEs.
#[derive(Debug, Clone, Copy)]
pub struct IoUringPersonality {
    /// Personality ID (returned to user-space).
    pub id: u16,
    /// User ID associated with this personality.
    pub uid: u32,
    /// Group ID associated with this personality.
    pub gid: u32,
    /// Whether this slot is active.
    pub active: bool,
}

impl IoUringPersonality {
    /// Create an inactive personality.
    pub const fn empty() -> Self {
        Self {
            id: 0,
            uid: 0,
            gid: 0,
            active: false,
        }
    }
}

// ---------------------------------------------------------------------------
// IoUringRestriction — ring restriction rule
// ---------------------------------------------------------------------------

/// A restriction rule applied to an io_uring instance.
#[derive(Debug, Clone, Copy)]
pub struct IoUringRestriction {
    /// Restriction type (IORING_RESTRICTION_*).
    pub opcode: u16,
    /// The restricted operation or flag value.
    pub arg: u8,
    /// Whether this restriction is enforced.
    pub enforced: bool,
}

impl IoUringRestriction {
    /// Create a new restriction.
    pub const fn new(opcode: u16, arg: u8) -> Self {
        Self {
            opcode,
            arg,
            enforced: true,
        }
    }

    /// Validate the restriction.
    pub fn validate(&self) -> Result<()> {
        if self.opcode > IORING_RESTRICTION_SQE_FLAGS_REQUIRED {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// IoUringProbeOp — probed operation capability
// ---------------------------------------------------------------------------

/// A single probed io_uring operation.
#[derive(Debug, Clone, Copy)]
pub struct IoUringProbeOp {
    /// Operation code.
    pub op: u8,
    /// Flags for this operation.
    pub flags: u16,
}

// ---------------------------------------------------------------------------
// IoUringRegCtx — per-ring registration context
// ---------------------------------------------------------------------------

/// Per-ring registration context for io_uring.
///
/// Manages the set of registered buffers, files, eventfds,
/// personalities, and restrictions for a single io_uring instance.
pub struct IoUringRegCtx {
    /// Fixed buffers (registered via IORING_REGISTER_BUFFERS).
    buffers: [Option<IoUringBuf>; MAX_FIXED_BUFFERS],
    /// Number of registered buffers.
    buffer_count: usize,
    /// Whether buffers are registered.
    buffers_registered: bool,

    /// Fixed file descriptors.
    files: [i32; MAX_FIXED_FILES],
    /// Number of registered files.
    file_count: usize,
    /// Whether files are registered.
    files_registered: bool,

    /// Registered eventfd (-1 if none).
    eventfd: i32,
    /// Whether eventfd is async-only.
    eventfd_async: bool,

    /// Registered personalities.
    personalities: [IoUringPersonality; MAX_PERSONALITIES],
    /// Next personality ID.
    next_personality_id: u16,

    /// Restriction rules.
    restrictions: [Option<IoUringRestriction>; MAX_RESTRICTIONS],
    /// Number of restrictions.
    restriction_count: usize,
    /// Whether restrictions are locked (cannot add more).
    restrictions_locked: bool,

    /// Whether the ring is enabled.
    ring_enabled: bool,
}

impl IoUringRegCtx {
    /// Create a new registration context.
    pub fn new() -> Self {
        Self {
            buffers: [const { None }; MAX_FIXED_BUFFERS],
            buffer_count: 0,
            buffers_registered: false,
            files: [FILE_SLOT_EMPTY; MAX_FIXED_FILES],
            file_count: 0,
            files_registered: false,
            eventfd: -1,
            eventfd_async: false,
            personalities: [const { IoUringPersonality::empty() }; MAX_PERSONALITIES],
            next_personality_id: 1,
            restrictions: [const { None }; MAX_RESTRICTIONS],
            restriction_count: 0,
            restrictions_locked: false,
            ring_enabled: true,
        }
    }

    // -----------------------------------------------------------------------
    // Buffer registration
    // -----------------------------------------------------------------------

    /// Register fixed buffers.
    ///
    /// Buffers must not be already registered. Each buffer is
    /// validated for non-zero address and length, and no overflow.
    pub fn register_buffers(&mut self, bufs: &[IoUringBuf]) -> Result<()> {
        if self.buffers_registered {
            return Err(Error::Busy);
        }
        if bufs.is_empty() || bufs.len() > MAX_FIXED_BUFFERS {
            return Err(Error::InvalidArgument);
        }
        for buf in bufs {
            buf.validate()?;
        }
        for (i, buf) in bufs.iter().enumerate() {
            self.buffers[i] = Some(*buf);
        }
        self.buffer_count = bufs.len();
        self.buffers_registered = true;
        Ok(())
    }

    /// Unregister all fixed buffers.
    pub fn unregister_buffers(&mut self) -> Result<()> {
        if !self.buffers_registered {
            return Err(Error::InvalidArgument);
        }
        for slot in &mut self.buffers {
            *slot = None;
        }
        self.buffer_count = 0;
        self.buffers_registered = false;
        Ok(())
    }

    /// Get a registered buffer by index.
    pub fn get_buffer(&self, index: usize) -> Result<&IoUringBuf> {
        if index >= self.buffer_count {
            return Err(Error::InvalidArgument);
        }
        self.buffers[index].as_ref().ok_or(Error::NotFound)
    }

    /// Return the number of registered buffers.
    pub const fn buffer_count(&self) -> usize {
        self.buffer_count
    }

    // -----------------------------------------------------------------------
    // File registration
    // -----------------------------------------------------------------------

    /// Register fixed file descriptors.
    pub fn register_files(&mut self, fds: &[i32]) -> Result<()> {
        if self.files_registered {
            return Err(Error::Busy);
        }
        if fds.is_empty() || fds.len() > MAX_FIXED_FILES {
            return Err(Error::InvalidArgument);
        }
        for (i, &fd) in fds.iter().enumerate() {
            self.files[i] = fd;
        }
        self.file_count = fds.len();
        self.files_registered = true;
        Ok(())
    }

    /// Unregister all fixed files.
    pub fn unregister_files(&mut self) -> Result<()> {
        if !self.files_registered {
            return Err(Error::InvalidArgument);
        }
        for slot in &mut self.files {
            *slot = FILE_SLOT_EMPTY;
        }
        self.file_count = 0;
        self.files_registered = false;
        Ok(())
    }

    /// Update a subset of registered files.
    ///
    /// `offset` is the starting index, `fds` are the new descriptors.
    pub fn update_files(&mut self, offset: usize, fds: &[i32]) -> Result<()> {
        if !self.files_registered {
            return Err(Error::InvalidArgument);
        }
        let end = offset
            .checked_add(fds.len())
            .ok_or(Error::InvalidArgument)?;
        if end > self.file_count {
            return Err(Error::InvalidArgument);
        }
        for (i, &fd) in fds.iter().enumerate() {
            self.files[offset + i] = fd;
        }
        Ok(())
    }

    /// Get a registered file descriptor by index.
    pub fn get_file(&self, index: usize) -> Result<i32> {
        if !self.files_registered || index >= self.file_count {
            return Err(Error::InvalidArgument);
        }
        let fd = self.files[index];
        if fd == FILE_SLOT_EMPTY {
            return Err(Error::NotFound);
        }
        Ok(fd)
    }

    /// Return the number of registered files.
    pub const fn file_count(&self) -> usize {
        self.file_count
    }

    // -----------------------------------------------------------------------
    // Eventfd registration
    // -----------------------------------------------------------------------

    /// Register an eventfd for CQ completion notification.
    pub fn register_eventfd(&mut self, fd: i32, async_only: bool) -> Result<()> {
        if self.eventfd >= 0 {
            return Err(Error::Busy);
        }
        if fd < 0 {
            return Err(Error::InvalidArgument);
        }
        self.eventfd = fd;
        self.eventfd_async = async_only;
        Ok(())
    }

    /// Unregister the eventfd.
    pub fn unregister_eventfd(&mut self) -> Result<()> {
        if self.eventfd < 0 {
            return Err(Error::InvalidArgument);
        }
        self.eventfd = -1;
        self.eventfd_async = false;
        Ok(())
    }

    /// Get the registered eventfd.
    pub const fn eventfd(&self) -> i32 {
        self.eventfd
    }

    // -----------------------------------------------------------------------
    // Personality registration
    // -----------------------------------------------------------------------

    /// Register a personality (credential set).
    pub fn register_personality(&mut self, uid: u32, gid: u32) -> Result<u16> {
        for slot in &mut self.personalities {
            if !slot.active {
                let id = self.next_personality_id;
                self.next_personality_id = self.next_personality_id.wrapping_add(1);
                if self.next_personality_id == 0 {
                    self.next_personality_id = 1;
                }
                *slot = IoUringPersonality {
                    id,
                    uid,
                    gid,
                    active: true,
                };
                return Ok(id);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Unregister a personality by ID.
    pub fn unregister_personality(&mut self, id: u16) -> Result<()> {
        for slot in &mut self.personalities {
            if slot.active && slot.id == id {
                *slot = IoUringPersonality::empty();
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    // -----------------------------------------------------------------------
    // Restriction registration
    // -----------------------------------------------------------------------

    /// Apply a restriction to the ring.
    pub fn register_restriction(&mut self, restriction: &IoUringRestriction) -> Result<()> {
        if self.restrictions_locked {
            return Err(Error::Busy);
        }
        restriction.validate()?;
        if self.restriction_count >= MAX_RESTRICTIONS {
            return Err(Error::OutOfMemory);
        }
        self.restrictions[self.restriction_count] = Some(*restriction);
        self.restriction_count += 1;
        Ok(())
    }

    /// Lock restrictions (no further modifications allowed).
    pub fn lock_restrictions(&mut self) {
        self.restrictions_locked = true;
    }

    /// Return the number of restrictions.
    pub const fn restriction_count(&self) -> usize {
        self.restriction_count
    }

    // -----------------------------------------------------------------------
    // Ring enable
    // -----------------------------------------------------------------------

    /// Enable a disabled ring.
    pub fn enable_rings(&mut self) -> Result<()> {
        if self.ring_enabled {
            return Err(Error::Busy);
        }
        self.ring_enabled = true;
        Ok(())
    }

    /// Return whether the ring is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.ring_enabled
    }

    // -----------------------------------------------------------------------
    // Probe
    // -----------------------------------------------------------------------

    /// Probe supported io_uring operations.
    ///
    /// Returns the number of supported operations.
    pub fn probe(&self) -> usize {
        // In a real kernel, this reflects the actual supported opcodes.
        // For the framework we report a fixed set.
        MAX_PROBE_OPS
    }
}

impl Default for IoUringRegCtx {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Syscall entry point
// ---------------------------------------------------------------------------

/// Process the `io_uring_register` syscall.
///
/// # Arguments
///
/// - `ctx` — Per-ring registration context.
/// - `opcode` — Registration opcode (IORING_REGISTER_*).
///
/// # Returns
///
/// Operation-specific result (0 on success for most operations,
/// personality ID for REGISTER_PERSONALITY).
///
/// # Errors
///
/// - `InvalidArgument` — Unknown opcode or invalid state.
/// - `Busy` — Resource already registered.
/// - `OutOfMemory` — No free slots.
pub fn sys_io_uring_register(ctx: &mut IoUringRegCtx, opcode: u32) -> Result<i32> {
    match opcode {
        IORING_REGISTER_BUFFERS
        | IORING_UNREGISTER_BUFFERS
        | IORING_REGISTER_FILES
        | IORING_UNREGISTER_FILES
        | IORING_REGISTER_EVENTFD
        | IORING_UNREGISTER_EVENTFD
        | IORING_REGISTER_FILES_UPDATE
        | IORING_REGISTER_EVENTFD_ASYNC
        | IORING_REGISTER_PROBE
        | IORING_REGISTER_PERSONALITY
        | IORING_UNREGISTER_PERSONALITY
        | IORING_REGISTER_RESTRICTIONS
        | IORING_REGISTER_ENABLE_RINGS => {
            // In a real kernel, each opcode would decode its args
            // from the user-space pointer. We validate the opcode
            // is known and return NotImplemented for the stub
            // dispatch path.
            let _ = ctx;
            Err(Error::NotImplemented)
        }
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_buffers() {
        let mut ctx = IoUringRegCtx::new();
        let bufs = [IoUringBuf::new(0x1000, 4096), IoUringBuf::new(0x2000, 8192)];
        assert!(ctx.register_buffers(&bufs).is_ok());
        assert_eq!(ctx.buffer_count(), 2);
    }

    #[test]
    fn test_register_buffers_already_registered() {
        let mut ctx = IoUringRegCtx::new();
        let bufs = [IoUringBuf::new(0x1000, 4096)];
        ctx.register_buffers(&bufs).unwrap();
        assert_eq!(ctx.register_buffers(&bufs).unwrap_err(), Error::Busy);
    }

    #[test]
    fn test_unregister_buffers() {
        let mut ctx = IoUringRegCtx::new();
        let bufs = [IoUringBuf::new(0x1000, 4096)];
        ctx.register_buffers(&bufs).unwrap();
        assert!(ctx.unregister_buffers().is_ok());
        assert_eq!(ctx.buffer_count(), 0);
    }

    #[test]
    fn test_unregister_buffers_not_registered() {
        let mut ctx = IoUringRegCtx::new();
        assert_eq!(
            ctx.unregister_buffers().unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_get_buffer() {
        let mut ctx = IoUringRegCtx::new();
        let bufs = [IoUringBuf::new(0x3000, 1024)];
        ctx.register_buffers(&bufs).unwrap();
        let buf = ctx.get_buffer(0).unwrap();
        assert_eq!(buf.base, 0x3000);
        assert_eq!(buf.len, 1024);
    }

    #[test]
    fn test_register_files() {
        let mut ctx = IoUringRegCtx::new();
        let fds = [3, 4, 5];
        assert!(ctx.register_files(&fds).is_ok());
        assert_eq!(ctx.file_count(), 3);
        assert_eq!(ctx.get_file(1).unwrap(), 4);
    }

    #[test]
    fn test_update_files() {
        let mut ctx = IoUringRegCtx::new();
        let fds = [3, 4, 5, 6];
        ctx.register_files(&fds).unwrap();
        assert!(ctx.update_files(1, &[10, 11]).is_ok());
        assert_eq!(ctx.get_file(1).unwrap(), 10);
        assert_eq!(ctx.get_file(2).unwrap(), 11);
    }

    #[test]
    fn test_update_files_out_of_range() {
        let mut ctx = IoUringRegCtx::new();
        let fds = [3, 4];
        ctx.register_files(&fds).unwrap();
        assert_eq!(
            ctx.update_files(1, &[10, 11]).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_register_eventfd() {
        let mut ctx = IoUringRegCtx::new();
        assert!(ctx.register_eventfd(42, false).is_ok());
        assert_eq!(ctx.eventfd(), 42);
    }

    #[test]
    fn test_register_eventfd_already_registered() {
        let mut ctx = IoUringRegCtx::new();
        ctx.register_eventfd(10, false).unwrap();
        assert_eq!(ctx.register_eventfd(20, false).unwrap_err(), Error::Busy);
    }

    #[test]
    fn test_unregister_eventfd() {
        let mut ctx = IoUringRegCtx::new();
        ctx.register_eventfd(10, false).unwrap();
        assert!(ctx.unregister_eventfd().is_ok());
        assert_eq!(ctx.eventfd(), -1);
    }

    #[test]
    fn test_register_personality() {
        let mut ctx = IoUringRegCtx::new();
        let id = ctx.register_personality(1000, 1000).unwrap();
        assert!(id > 0);
    }

    #[test]
    fn test_unregister_personality() {
        let mut ctx = IoUringRegCtx::new();
        let id = ctx.register_personality(1000, 1000).unwrap();
        assert!(ctx.unregister_personality(id).is_ok());
        assert_eq!(ctx.unregister_personality(id).unwrap_err(), Error::NotFound);
    }

    #[test]
    fn test_register_restriction() {
        let mut ctx = IoUringRegCtx::new();
        let r = IoUringRestriction::new(IORING_RESTRICTION_SQE_OP, 5);
        assert!(ctx.register_restriction(&r).is_ok());
        assert_eq!(ctx.restriction_count(), 1);
    }

    #[test]
    fn test_restrictions_locked() {
        let mut ctx = IoUringRegCtx::new();
        ctx.lock_restrictions();
        let r = IoUringRestriction::new(IORING_RESTRICTION_SQE_OP, 5);
        assert_eq!(ctx.register_restriction(&r).unwrap_err(), Error::Busy);
    }

    #[test]
    fn test_enable_rings() {
        let mut ctx = IoUringRegCtx::new();
        // Already enabled.
        assert_eq!(ctx.enable_rings().unwrap_err(), Error::Busy);
        ctx.ring_enabled = false;
        assert!(ctx.enable_rings().is_ok());
        assert!(ctx.is_enabled());
    }

    #[test]
    fn test_probe() {
        let ctx = IoUringRegCtx::new();
        assert!(ctx.probe() > 0);
    }

    #[test]
    fn test_dispatch_unknown_opcode() {
        let mut ctx = IoUringRegCtx::new();
        assert_eq!(
            sys_io_uring_register(&mut ctx, 999).unwrap_err(),
            Error::InvalidArgument,
        );
    }

    #[test]
    fn test_buf_validate() {
        assert!(IoUringBuf::new(0x1000, 4096).validate().is_ok());
        assert_eq!(
            IoUringBuf::new(0, 4096).validate().unwrap_err(),
            Error::InvalidArgument
        );
        assert_eq!(
            IoUringBuf::new(0x1000, 0).validate().unwrap_err(),
            Error::InvalidArgument
        );
        assert_eq!(
            IoUringBuf::new(u64::MAX, 1).validate().unwrap_err(),
            Error::InvalidArgument
        );
    }
}
