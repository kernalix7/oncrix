// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `rseq(2)` — restartable sequences.
//!
//! Restartable sequences (rseq) allow user-space to define critical
//! sections that are guaranteed to complete atomically on a single
//! CPU, or be restarted from an abort handler if preempted or
//! migrated. This is used by high-performance allocators and
//! per-CPU data structures to avoid atomic instructions in the
//! fast path.
//!
//! # Syscall signature
//!
//! ```text
//! int rseq(struct rseq *rseq, uint32_t rseq_len,
//!          int flags, uint32_t sig);
//! ```
//!
//! # Mechanism
//!
//! 1. User-space registers a per-thread `struct rseq` area.
//! 2. Before entering a critical section, user-space writes an
//!    `rseq_cs` descriptor to `rseq->rseq_cs`.
//! 3. The kernel checks `rseq_cs` on preemption/migration:
//!    - If the IP is in `[start_ip, start_ip + post_commit_offset)`,
//!      the kernel diverts execution to `abort_ip`.
//! 4. On successful commit (IP past post_commit_offset), the
//!    operation completed atomically on the current CPU.
//!
//! # Fields in `struct rseq`
//!
//! - `cpu_id_start`: CPU number at registration time.
//! - `cpu_id`: Current CPU number (updated by kernel).
//! - `rseq_cs`: Pointer to active critical section descriptor.
//! - `flags`: Per-thread flags.
//!
//! # References
//!
//! - Linux: `kernel/rseq.c`, `include/uapi/linux/rseq.h`
//! - `rseq(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants — flags
// ---------------------------------------------------------------------------

/// Unregister the rseq area for this thread.
pub const RSEQ_FLAG_UNREGISTER: u32 = 1 << 0;

/// Mask of all valid flags.
const RSEQ_FLAG_VALID_MASK: u32 = RSEQ_FLAG_UNREGISTER;

// ---------------------------------------------------------------------------
// Constants — rseq_cs flags
// ---------------------------------------------------------------------------

/// No specific CPU pinning required.
pub const RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT: u32 = 1 << 0;
/// No restart on signal delivery.
pub const RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL: u32 = 1 << 1;
/// No restart on CPU migration.
pub const RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE: u32 = 1 << 2;

/// Mask of all valid rseq_cs flags.
const RSEQ_CS_FLAG_VALID_MASK: u32 = RSEQ_CS_FLAG_NO_RESTART_ON_PREEMPT
    | RSEQ_CS_FLAG_NO_RESTART_ON_SIGNAL
    | RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE;

// ---------------------------------------------------------------------------
// Constants — special values
// ---------------------------------------------------------------------------

/// CPU ID value indicating uninitialized/unregistered state.
pub const RSEQ_CPU_ID_UNINITIALIZED: i32 = -1;

/// CPU ID value used during registration (before first schedule).
pub const RSEQ_CPU_ID_REGISTRATION: i32 = -2;

/// Expected rseq struct size (for ABI versioning).
pub const RSEQ_STRUCT_SIZE: u32 = 32;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Maximum number of threads with rseq registrations.
const MAX_RSEQ_THREADS: usize = 256;

/// Maximum valid CPU ID.
const MAX_CPU_ID: u32 = 4096;

/// User-space address limit.
const USER_ADDR_MAX: u64 = 0x0000_8000_0000_0000;

// ---------------------------------------------------------------------------
// RseqCs — critical section descriptor
// ---------------------------------------------------------------------------

/// Restartable sequence critical section descriptor.
///
/// Describes the code region that forms the critical section and
/// the abort handler to jump to if the section is interrupted.
///
/// Corresponds to `struct rseq_cs` in the Linux UAPI.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RseqCs {
    /// Version (must be 0 for current ABI).
    pub version: u32,
    /// Flags (RSEQ_CS_FLAG_*).
    pub flags: u32,
    /// Start IP of the critical section.
    pub start_ip: u64,
    /// Length of the critical section in bytes (from start_ip to
    /// just after the commit instruction).
    pub post_commit_offset: u64,
    /// IP of the abort handler (jumped to on preemption/migration).
    pub abort_ip: u64,
}

impl RseqCs {
    /// Create a new critical section descriptor.
    pub const fn new(start_ip: u64, post_commit_offset: u64, abort_ip: u64) -> Self {
        Self {
            version: 0,
            flags: 0,
            start_ip,
            post_commit_offset,
            abort_ip,
        }
    }

    /// Validate the critical section descriptor.
    pub fn validate(&self) -> Result<()> {
        if self.version != 0 {
            return Err(Error::InvalidArgument);
        }
        if self.flags & !RSEQ_CS_FLAG_VALID_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        // start_ip must be in user-space.
        if self.start_ip == 0 || self.start_ip >= USER_ADDR_MAX {
            return Err(Error::InvalidArgument);
        }
        // post_commit_offset must be positive.
        if self.post_commit_offset == 0 {
            return Err(Error::InvalidArgument);
        }
        // End of critical section must not overflow.
        let end_ip = self
            .start_ip
            .checked_add(self.post_commit_offset)
            .ok_or(Error::InvalidArgument)?;
        if end_ip >= USER_ADDR_MAX {
            return Err(Error::InvalidArgument);
        }
        // abort_ip must be in user-space and outside the CS.
        if self.abort_ip == 0 || self.abort_ip >= USER_ADDR_MAX {
            return Err(Error::InvalidArgument);
        }
        // abort_ip should not be inside the critical section.
        if self.abort_ip >= self.start_ip && self.abort_ip < end_ip {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Check if an instruction pointer is inside this critical section.
    pub fn contains_ip(&self, ip: u64) -> bool {
        ip >= self.start_ip && ip < self.start_ip.saturating_add(self.post_commit_offset)
    }

    /// Check if an IP is past the commit point.
    pub fn is_past_commit(&self, ip: u64) -> bool {
        ip >= self.start_ip.saturating_add(self.post_commit_offset)
    }
}

// ---------------------------------------------------------------------------
// RseqRegistration — per-thread rseq state
// ---------------------------------------------------------------------------

/// Per-thread rseq registration state.
///
/// Corresponds to `struct rseq` in the Linux UAPI.
#[derive(Debug, Clone, Copy)]
pub struct RseqRegistration {
    /// User-space address of the rseq struct.
    pub rseq_addr: u64,
    /// Size of the rseq struct (for ABI versioning).
    pub rseq_len: u32,
    /// Signature value (for ABI validation).
    pub sig: u32,
    /// Current CPU ID.
    pub cpu_id: i32,
    /// CPU ID at registration time.
    pub cpu_id_start: i32,
    /// Per-thread flags.
    pub flags: u32,
    /// Whether a registration is active.
    pub registered: bool,
    /// Active critical section (if any).
    pub active_cs: Option<RseqCs>,
}

impl RseqRegistration {
    /// Create an unregistered rseq state.
    pub const fn new() -> Self {
        Self {
            rseq_addr: 0,
            rseq_len: 0,
            sig: 0,
            cpu_id: RSEQ_CPU_ID_UNINITIALIZED,
            cpu_id_start: RSEQ_CPU_ID_UNINITIALIZED,
            flags: 0,
            registered: false,
            active_cs: None,
        }
    }

    /// Register the rseq area for this thread.
    pub fn register(
        &mut self,
        rseq_addr: u64,
        rseq_len: u32,
        sig: u32,
        current_cpu: u32,
    ) -> Result<()> {
        if self.registered {
            return Err(Error::Busy);
        }
        self.validate_addr(rseq_addr)?;
        if rseq_len < RSEQ_STRUCT_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.rseq_addr = rseq_addr;
        self.rseq_len = rseq_len;
        self.sig = sig;
        self.cpu_id = current_cpu as i32;
        self.cpu_id_start = current_cpu as i32;
        self.flags = 0;
        self.registered = true;
        self.active_cs = None;
        Ok(())
    }

    /// Unregister the rseq area.
    pub fn unregister(&mut self, rseq_addr: u64, sig: u32) -> Result<()> {
        if !self.registered {
            return Err(Error::InvalidArgument);
        }
        // Must match the registered address and signature.
        if rseq_addr != self.rseq_addr {
            return Err(Error::InvalidArgument);
        }
        if sig != self.sig {
            return Err(Error::InvalidArgument);
        }
        self.registered = false;
        self.rseq_addr = 0;
        self.rseq_len = 0;
        self.sig = 0;
        self.cpu_id = RSEQ_CPU_ID_UNINITIALIZED;
        self.cpu_id_start = RSEQ_CPU_ID_UNINITIALIZED;
        self.active_cs = None;
        Ok(())
    }

    /// Update the CPU ID (called on schedule/migration).
    pub fn update_cpu(&mut self, new_cpu: u32) -> Result<()> {
        if !self.registered {
            return Ok(()); // silently ignore if not registered
        }
        if new_cpu >= MAX_CPU_ID {
            return Err(Error::InvalidArgument);
        }
        self.cpu_id = new_cpu as i32;
        Ok(())
    }

    /// Set the active critical section.
    pub fn set_critical_section(&mut self, cs: RseqCs) -> Result<()> {
        if !self.registered {
            return Err(Error::InvalidArgument);
        }
        cs.validate()?;
        self.active_cs = Some(cs);
        Ok(())
    }

    /// Clear the active critical section.
    pub fn clear_critical_section(&mut self) {
        self.active_cs = None;
    }

    /// Check if the given IP is in the active critical section.
    ///
    /// Returns the abort IP if preemption/migration should abort
    /// the critical section, or `None` if no action is needed.
    pub fn check_preemption(&self, current_ip: u64) -> Option<u64> {
        if !self.registered {
            return None;
        }
        match &self.active_cs {
            Some(cs) => {
                if cs.contains_ip(current_ip) {
                    Some(cs.abort_ip)
                } else {
                    None
                }
            }
            None => None,
        }
    }

    /// Check if the IP is past the commit point of the active CS.
    pub fn is_committed(&self, ip: u64) -> bool {
        match &self.active_cs {
            Some(cs) => cs.is_past_commit(ip),
            None => false,
        }
    }

    /// Validate user-space address.
    fn validate_addr(&self, addr: u64) -> Result<()> {
        if addr == 0 || addr >= USER_ADDR_MAX {
            return Err(Error::InvalidArgument);
        }
        // Check alignment (8-byte aligned).
        if addr & 7 != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

impl Default for RseqRegistration {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// RseqManager — system-wide rseq manager
// ---------------------------------------------------------------------------

/// System-wide rseq registration manager.
///
/// Tracks per-thread rseq registrations for preemption handling.
pub struct RseqManager {
    /// Per-thread registrations (indexed by thread slot).
    threads: [RseqRegistration; MAX_RSEQ_THREADS],
    /// Number of active registrations.
    active_count: usize,
}

impl RseqManager {
    /// Create a new rseq manager.
    pub fn new() -> Self {
        Self {
            threads: [const { RseqRegistration::new() }; MAX_RSEQ_THREADS],
            active_count: 0,
        }
    }

    /// Register rseq for a thread.
    pub fn register(
        &mut self,
        thread_id: usize,
        rseq_addr: u64,
        rseq_len: u32,
        sig: u32,
        current_cpu: u32,
    ) -> Result<()> {
        if thread_id >= MAX_RSEQ_THREADS {
            return Err(Error::InvalidArgument);
        }
        self.threads[thread_id].register(rseq_addr, rseq_len, sig, current_cpu)?;
        self.active_count += 1;
        Ok(())
    }

    /// Unregister rseq for a thread.
    pub fn unregister(&mut self, thread_id: usize, rseq_addr: u64, sig: u32) -> Result<()> {
        if thread_id >= MAX_RSEQ_THREADS {
            return Err(Error::InvalidArgument);
        }
        self.threads[thread_id].unregister(rseq_addr, sig)?;
        self.active_count = self.active_count.saturating_sub(1);
        Ok(())
    }

    /// Handle preemption for a thread.
    ///
    /// Returns the abort IP if the thread was in a critical section.
    pub fn handle_preemption(&self, thread_id: usize, current_ip: u64) -> Option<u64> {
        if thread_id >= MAX_RSEQ_THREADS {
            return None;
        }
        self.threads[thread_id].check_preemption(current_ip)
    }

    /// Handle CPU migration for a thread.
    pub fn handle_migration(&mut self, thread_id: usize, new_cpu: u32) -> Result<Option<u64>> {
        if thread_id >= MAX_RSEQ_THREADS {
            return Err(Error::InvalidArgument);
        }
        // First check if we need to abort.
        // We can read the registration then mutate if needed because
        // active_cs is checked on a copy.
        let abort_ip = self.threads[thread_id].active_cs.as_ref().and_then(|cs| {
            // On migration, always abort the CS (if any).
            if cs.flags & RSEQ_CS_FLAG_NO_RESTART_ON_MIGRATE == 0 {
                Some(cs.abort_ip)
            } else {
                None
            }
        });
        self.threads[thread_id].update_cpu(new_cpu)?;
        if abort_ip.is_some() {
            self.threads[thread_id].clear_critical_section();
        }
        Ok(abort_ip)
    }

    /// Get a reference to a thread's registration.
    pub fn get_registration(&self, thread_id: usize) -> Result<&RseqRegistration> {
        if thread_id >= MAX_RSEQ_THREADS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.threads[thread_id])
    }

    /// Return the number of active registrations.
    pub const fn active_count(&self) -> usize {
        self.active_count
    }
}

impl Default for RseqManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Syscall entry point
// ---------------------------------------------------------------------------

/// Process the `rseq(2)` syscall.
///
/// # Arguments
///
/// - `mgr` — System-wide rseq manager.
/// - `thread_id` — Current thread ID.
/// - `rseq_addr` — User-space address of `struct rseq`.
/// - `rseq_len` — Size of the rseq struct.
/// - `flags` — Flags (0 or RSEQ_FLAG_UNREGISTER).
/// - `sig` — Signature for ABI validation.
/// - `current_cpu` — Current CPU number (for registration).
///
/// # Returns
///
/// 0 on success.
///
/// # Errors
///
/// - `InvalidArgument` — Bad address, size, flags, or signature.
/// - `Busy` — Already registered (for registration) or not
///   registered (for unregistration).
pub fn sys_rseq(
    mgr: &mut RseqManager,
    thread_id: usize,
    rseq_addr: u64,
    rseq_len: u32,
    flags: u32,
    sig: u32,
    current_cpu: u32,
) -> Result<i32> {
    if flags & !RSEQ_FLAG_VALID_MASK != 0 {
        return Err(Error::InvalidArgument);
    }
    if flags & RSEQ_FLAG_UNREGISTER != 0 {
        mgr.unregister(thread_id, rseq_addr, sig)?;
    } else {
        mgr.register(thread_id, rseq_addr, rseq_len, sig, current_cpu)?;
    }
    Ok(0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_ADDR: u64 = 0x7FFF_0000_0000;
    const TEST_SIG: u32 = 0x53053053;

    #[test]
    fn test_rseq_cs_validate() {
        let cs = RseqCs::new(0x1000, 0x100, 0x2000);
        assert!(cs.validate().is_ok());
    }

    #[test]
    fn test_rseq_cs_bad_version() {
        let mut cs = RseqCs::new(0x1000, 0x100, 0x2000);
        cs.version = 1;
        assert_eq!(cs.validate().unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn test_rseq_cs_abort_inside_cs() {
        // abort_ip inside [start_ip, start_ip + post_commit_offset)
        let cs = RseqCs::new(0x1000, 0x100, 0x1050);
        assert_eq!(cs.validate().unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn test_rseq_cs_contains_ip() {
        let cs = RseqCs::new(0x1000, 0x100, 0x2000);
        assert!(cs.contains_ip(0x1000));
        assert!(cs.contains_ip(0x1050));
        assert!(!cs.contains_ip(0x1100));
        assert!(!cs.contains_ip(0x0FFF));
    }

    #[test]
    fn test_rseq_cs_past_commit() {
        let cs = RseqCs::new(0x1000, 0x100, 0x2000);
        assert!(!cs.is_past_commit(0x1050));
        assert!(cs.is_past_commit(0x1100));
        assert!(cs.is_past_commit(0x2000));
    }

    #[test]
    fn test_registration_basic() {
        let mut reg = RseqRegistration::new();
        assert!(!reg.registered);
        assert!(
            reg.register(TEST_ADDR, RSEQ_STRUCT_SIZE, TEST_SIG, 0)
                .is_ok()
        );
        assert!(reg.registered);
        assert_eq!(reg.cpu_id, 0);
    }

    #[test]
    fn test_registration_double_register() {
        let mut reg = RseqRegistration::new();
        reg.register(TEST_ADDR, RSEQ_STRUCT_SIZE, TEST_SIG, 0)
            .unwrap();
        assert_eq!(
            reg.register(TEST_ADDR, RSEQ_STRUCT_SIZE, TEST_SIG, 1)
                .unwrap_err(),
            Error::Busy
        );
    }

    #[test]
    fn test_unregister() {
        let mut reg = RseqRegistration::new();
        reg.register(TEST_ADDR, RSEQ_STRUCT_SIZE, TEST_SIG, 0)
            .unwrap();
        assert!(reg.unregister(TEST_ADDR, TEST_SIG).is_ok());
        assert!(!reg.registered);
    }

    #[test]
    fn test_unregister_wrong_sig() {
        let mut reg = RseqRegistration::new();
        reg.register(TEST_ADDR, RSEQ_STRUCT_SIZE, TEST_SIG, 0)
            .unwrap();
        assert_eq!(
            reg.unregister(TEST_ADDR, 0xBAD).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_unregister_wrong_addr() {
        let mut reg = RseqRegistration::new();
        reg.register(TEST_ADDR, RSEQ_STRUCT_SIZE, TEST_SIG, 0)
            .unwrap();
        assert_eq!(
            reg.unregister(TEST_ADDR + 8, TEST_SIG).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_update_cpu() {
        let mut reg = RseqRegistration::new();
        reg.register(TEST_ADDR, RSEQ_STRUCT_SIZE, TEST_SIG, 0)
            .unwrap();
        assert!(reg.update_cpu(3).is_ok());
        assert_eq!(reg.cpu_id, 3);
    }

    #[test]
    fn test_check_preemption_no_cs() {
        let mut reg = RseqRegistration::new();
        reg.register(TEST_ADDR, RSEQ_STRUCT_SIZE, TEST_SIG, 0)
            .unwrap();
        assert!(reg.check_preemption(0x1050).is_none());
    }

    #[test]
    fn test_check_preemption_in_cs() {
        let mut reg = RseqRegistration::new();
        reg.register(TEST_ADDR, RSEQ_STRUCT_SIZE, TEST_SIG, 0)
            .unwrap();
        let cs = RseqCs::new(0x1000, 0x100, 0x2000);
        reg.set_critical_section(cs).unwrap();
        assert_eq!(reg.check_preemption(0x1050), Some(0x2000));
    }

    #[test]
    fn test_check_preemption_outside_cs() {
        let mut reg = RseqRegistration::new();
        reg.register(TEST_ADDR, RSEQ_STRUCT_SIZE, TEST_SIG, 0)
            .unwrap();
        let cs = RseqCs::new(0x1000, 0x100, 0x2000);
        reg.set_critical_section(cs).unwrap();
        assert!(reg.check_preemption(0x3000).is_none());
    }

    #[test]
    fn test_sys_rseq_register() {
        let mut mgr = RseqManager::new();
        let r = sys_rseq(&mut mgr, 0, TEST_ADDR, RSEQ_STRUCT_SIZE, 0, TEST_SIG, 0);
        assert!(r.is_ok());
        assert_eq!(mgr.active_count(), 1);
    }

    #[test]
    fn test_sys_rseq_unregister() {
        let mut mgr = RseqManager::new();
        sys_rseq(&mut mgr, 0, TEST_ADDR, RSEQ_STRUCT_SIZE, 0, TEST_SIG, 0).unwrap();
        let r = sys_rseq(&mut mgr, 0, TEST_ADDR, 0, RSEQ_FLAG_UNREGISTER, TEST_SIG, 0);
        assert!(r.is_ok());
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn test_sys_rseq_bad_flags() {
        let mut mgr = RseqManager::new();
        assert_eq!(
            sys_rseq(&mut mgr, 0, TEST_ADDR, RSEQ_STRUCT_SIZE, 0xFF, TEST_SIG, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_migration_aborts_cs() {
        let mut mgr = RseqManager::new();
        mgr.register(0, TEST_ADDR, RSEQ_STRUCT_SIZE, TEST_SIG, 0)
            .unwrap();
        let cs = RseqCs::new(0x1000, 0x100, 0x2000);
        mgr.threads[0].set_critical_section(cs).unwrap();
        let abort = mgr.handle_migration(0, 1).unwrap();
        assert_eq!(abort, Some(0x2000));
    }

    #[test]
    fn test_migration_no_cs() {
        let mut mgr = RseqManager::new();
        mgr.register(0, TEST_ADDR, RSEQ_STRUCT_SIZE, TEST_SIG, 0)
            .unwrap();
        let abort = mgr.handle_migration(0, 1).unwrap();
        assert!(abort.is_none());
    }

    #[test]
    fn test_bad_addr_zero() {
        let mut reg = RseqRegistration::new();
        assert_eq!(
            reg.register(0, RSEQ_STRUCT_SIZE, TEST_SIG, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_bad_addr_unaligned() {
        let mut reg = RseqRegistration::new();
        assert_eq!(
            reg.register(TEST_ADDR + 1, RSEQ_STRUCT_SIZE, TEST_SIG, 0)
                .unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_bad_rseq_len() {
        let mut reg = RseqRegistration::new();
        assert_eq!(
            reg.register(TEST_ADDR, 16, TEST_SIG, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }
}
