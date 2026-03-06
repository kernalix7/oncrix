// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `map_shadow_stack(2)` — allocate CET/GCS shadow stack pages.
//!
//! Shadow stacks are a hardware-enforced control-flow integrity mechanism:
//! - **Intel CET** (Control-flow Enforcement Technology) — x86_64, since
//!   Tiger Lake.
//! - **ARM GCS** (Guarded Control Stack) — AArch64, since ARMv9.3.
//!
//! A shadow stack is a special memory region that the CPU maintains in
//! parallel with the normal call stack.  On every `CALL`, the hardware
//! pushes the return address onto the shadow stack.  On `RET`, it pops
//! the shadow stack and faults if the two stacks disagree.
//!
//! # Syscall signature
//!
//! ```text
//! void *map_shadow_stack(unsigned long addr, unsigned long size,
//!                        unsigned long flags);
//! ```
//!
//! # Flags
//!
//! | Flag | Value | Effect |
//! |------|-------|--------|
//! | `SHADOW_STACK_SET_TOKEN` | `1` | Write a restore token at the stack top |
//!
//! # Size constraints
//!
//! - Must be page-aligned (or zero for the default size).
//! - Must be at least `PAGE_SIZE` and at most `MAX_SHADOW_STACK_BYTES`.
//!
//! # Linux reference
//!
//! `arch/x86/kernel/shstk.c`, `include/uapi/asm-generic/mman-common.h`.
//! Syscall number x86_64: 453.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// x86_64 Linux ABI syscall number for `map_shadow_stack`.
pub const SYS_MAP_SHADOW_STACK: u64 = 453;

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Minimum shadow stack size (one page).
const MIN_SHADOW_STACK_BYTES: u64 = PAGE_SIZE;

/// Maximum shadow stack size (8 MiB).
pub const MAX_SHADOW_STACK_BYTES: u64 = 8 * 1024 * 1024;

/// Default shadow stack size when the caller passes `size == 0` (64 KiB).
const DEFAULT_SHADOW_STACK_BYTES: u64 = 64 * 1024;

/// Write a restore token at the top of the shadow stack.
///
/// The token is required by `RSTORSSP` to validate a shadow-stack switch
/// during context restoration.
pub const SHADOW_STACK_SET_TOKEN: u64 = 1;

/// All valid flag bits.
const FLAGS_VALID: u64 = SHADOW_STACK_SET_TOKEN;

/// Maximum number of shadow stacks tracked per subsystem instance.
const MAX_ALLOCS: usize = 64;

/// Size of an Intel CET restore token (one 8-byte pointer).
const TOKEN_SIZE: u64 = 8;

/// Base virtual address used for sequential shadow stack placement.
const SHADOW_STACK_VA_BASE: u64 = 0x7FFF_0000_0000u64;

// ---------------------------------------------------------------------------
// ShadowStackAttrs — page-level attributes
// ---------------------------------------------------------------------------

/// Page-level attributes for a shadow stack allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShadowStackAttrs(u32);

impl ShadowStackAttrs {
    /// No special attributes.
    pub const NONE: Self = Self(0);
    /// Shadow stack pages (equivalent to Linux `VM_SHADOW_STACK`).
    pub const SHADOW_STACK: Self = Self(1 << 0);
    /// Guard page at the low end of the allocation.
    pub const GUARD_LOW: Self = Self(1 << 1);
    /// Guard page at the high end of the allocation.
    pub const GUARD_HIGH: Self = Self(1 << 2);
    /// A valid restore token has been written.
    pub const HAS_TOKEN: Self = Self(1 << 3);

    /// Return `true` if `other`'s bits are all set in `self`.
    pub const fn has(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Union of two attribute sets.
    pub const fn or(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl Default for ShadowStackAttrs {
    fn default() -> Self {
        Self::NONE
    }
}

// ---------------------------------------------------------------------------
// ShadowStackAlloc — a single allocation record
// ---------------------------------------------------------------------------

/// Record describing one shadow stack allocation.
#[derive(Debug, Clone, Copy)]
pub struct ShadowStackAlloc {
    /// Unique allocation ID.
    pub id: u64,
    /// Base virtual address of the allocation.
    pub base: u64,
    /// Size in bytes (page-aligned).
    pub size: u64,
    /// Requested flags.
    pub flags: u64,
    /// Page attributes.
    pub attrs: ShadowStackAttrs,
    /// Address of the restore token (if `SHADOW_STACK_SET_TOKEN`; else 0).
    pub token_addr: u64,
    /// Value written at `token_addr` (token = `token_addr | 1`).
    pub token_value: u64,
    /// PID of the owning process.
    pub owner_pid: u64,
    /// Whether this slot is in use.
    pub active: bool,
}

impl ShadowStackAlloc {
    /// Create an empty (inactive) allocation slot.
    const fn empty() -> Self {
        Self {
            id: 0,
            base: 0,
            size: 0,
            flags: 0,
            attrs: ShadowStackAttrs::NONE,
            token_addr: 0,
            token_value: 0,
            owner_pid: 0,
            active: false,
        }
    }

    /// Exclusive end address.
    pub const fn end(&self) -> u64 {
        self.base.saturating_add(self.size)
    }

    /// Number of pages in the allocation.
    pub const fn page_count(&self) -> u64 {
        (self.size + PAGE_SIZE - 1) / PAGE_SIZE
    }

    /// Return `true` if a restore token is present.
    pub const fn has_token(&self) -> bool {
        self.flags & SHADOW_STACK_SET_TOKEN != 0
    }

    /// Return `true` if `addr` falls within `[base, base+size)`.
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }
}

impl Default for ShadowStackAlloc {
    fn default() -> Self {
        Self::empty()
    }
}

// ---------------------------------------------------------------------------
// ShadowStackSubsystem — global allocation tracker
// ---------------------------------------------------------------------------

/// Global tracker for shadow stack allocations.
///
/// In a real kernel the actual page tables are manipulated; here we maintain
/// a metadata table for testing and validation.
pub struct ShadowStackSubsystem {
    allocs: [ShadowStackAlloc; MAX_ALLOCS],
    next_id: u64,
    next_va: u64,
    count: usize,
    /// Total bytes allocated across all active allocations.
    pub total_bytes: u64,
}

impl ShadowStackSubsystem {
    /// Create an empty subsystem.
    pub const fn new() -> Self {
        Self {
            allocs: [const { ShadowStackAlloc::empty() }; MAX_ALLOCS],
            next_id: 1,
            next_va: SHADOW_STACK_VA_BASE,
            count: 0,
            total_bytes: 0,
        }
    }

    /// Number of active allocations.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Find an active allocation by ID.
    pub fn find_by_id(&self, id: u64) -> Option<&ShadowStackAlloc> {
        self.allocs.iter().find(|a| a.active && a.id == id)
    }

    /// Find an active allocation containing `addr`.
    pub fn find_by_addr(&self, addr: u64) -> Option<&ShadowStackAlloc> {
        self.allocs.iter().find(|a| a.active && a.contains(addr))
    }

    /// Return `true` if `addr` is inside any active shadow stack.
    pub fn is_shadow_stack_addr(&self, addr: u64) -> bool {
        self.find_by_addr(addr).is_some()
    }

    /// Allocate a new shadow stack.
    fn allocate(&mut self, hint_addr: u64, size: u64, flags: u64, pid: u64) -> Result<u64> {
        let slot = self
            .allocs
            .iter()
            .position(|a| !a.active)
            .ok_or(Error::OutOfMemory)?;

        // Round size up to page boundary; use default if zero.
        let actual_size = if size == 0 {
            DEFAULT_SHADOW_STACK_BYTES
        } else {
            (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
        };

        // Choose base address: prefer the hint if page-aligned, else use VA bump.
        let base = if hint_addr != 0 && hint_addr % PAGE_SIZE == 0 {
            hint_addr
        } else {
            let va = self.next_va;
            // Bump: allocation + one guard page gap.
            self.next_va = self.next_va.wrapping_add(actual_size + PAGE_SIZE);
            va
        };

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        // Compute token if requested.
        let (token_addr, token_value, attrs) = if flags & SHADOW_STACK_SET_TOKEN != 0 {
            // Token is placed at the top of the stack (highest address - TOKEN_SIZE).
            let ta = base + actual_size - TOKEN_SIZE;
            let tv = ta | 1; // CET token = address | 1
            let a = ShadowStackAttrs::SHADOW_STACK
                .or(ShadowStackAttrs::GUARD_LOW)
                .or(ShadowStackAttrs::HAS_TOKEN);
            (ta, tv, a)
        } else {
            let a = ShadowStackAttrs::SHADOW_STACK.or(ShadowStackAttrs::GUARD_LOW);
            (0u64, 0u64, a)
        };

        self.allocs[slot] = ShadowStackAlloc {
            id,
            base,
            size: actual_size,
            flags,
            attrs,
            token_addr,
            token_value,
            owner_pid: pid,
            active: true,
        };
        self.count += 1;
        self.total_bytes = self.total_bytes.saturating_add(actual_size);
        Ok(base)
    }

    /// Deallocate a shadow stack by ID.
    pub fn deallocate(&mut self, id: u64) -> Result<()> {
        for a in self.allocs.iter_mut() {
            if a.active && a.id == id {
                self.total_bytes = self.total_bytes.saturating_sub(a.size);
                a.active = false;
                self.count = self.count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Deallocate all shadow stacks owned by `pid` (process exit cleanup).
    pub fn cleanup_pid(&mut self, pid: u64) {
        for a in self.allocs.iter_mut() {
            if a.active && a.owner_pid == pid {
                self.total_bytes = self.total_bytes.saturating_sub(a.size);
                a.active = false;
                self.count = self.count.saturating_sub(1);
            }
        }
    }
}

impl Default for ShadowStackSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate `map_shadow_stack` arguments.
///
/// # Checks
///
/// - `flags` contains only defined bits.
/// - `addr` is page-aligned if non-zero.
/// - `size`, when non-zero, is within `[MIN, MAX]` and page-aligned.
pub fn validate_map_shadow_stack_args(addr: u64, size: u64, flags: u64) -> Result<()> {
    if flags & !FLAGS_VALID != 0 {
        return Err(Error::InvalidArgument);
    }
    if addr != 0 && addr % PAGE_SIZE != 0 {
        return Err(Error::InvalidArgument);
    }
    if size != 0 {
        if size < MIN_SHADOW_STACK_BYTES || size > MAX_SHADOW_STACK_BYTES {
            return Err(Error::InvalidArgument);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// sys_map_shadow_stack — primary handler
// ---------------------------------------------------------------------------

/// `map_shadow_stack(2)` syscall handler.
///
/// Allocates a shadow stack region and optionally writes a restore token.
///
/// # Arguments
///
/// * `sys`   — Mutable shadow stack subsystem.
/// * `addr`  — Preferred base address (0 = kernel-chosen).
/// * `size`  — Size in bytes (0 = default 64 KiB; otherwise must be
///             page-aligned and in `[PAGE_SIZE, 8 MiB]`).
/// * `flags` — `SHADOW_STACK_SET_TOKEN` or 0.
/// * `pid`   — Calling process ID.
///
/// # Returns
///
/// The base address of the allocated shadow stack on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Invalid flags, misaligned/out-of-range size.
/// * [`Error::OutOfMemory`]     — Allocation table is full.
pub fn sys_map_shadow_stack(
    sys: &mut ShadowStackSubsystem,
    addr: u64,
    size: u64,
    flags: u64,
    pid: u64,
) -> Result<u64> {
    validate_map_shadow_stack_args(addr, size, flags)?;
    sys.allocate(addr, size, flags, pid)
}

/// Deallocate a shadow stack by its allocation ID.
///
/// # Errors
///
/// * [`Error::NotFound`] — No allocation with the given ID.
pub fn sys_unmap_shadow_stack(sys: &mut ShadowStackSubsystem, id: u64) -> Result<()> {
    sys.deallocate(id)
}

// ---------------------------------------------------------------------------
// Restore token validation helper
// ---------------------------------------------------------------------------

/// Verify that `token_value` is a valid CET restore token for `token_addr`.
///
/// A valid token equals `token_addr | 1`.
pub fn is_valid_restore_token(token_addr: u64, token_value: u64) -> bool {
    token_value == (token_addr | 1)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sys() -> ShadowStackSubsystem {
        ShadowStackSubsystem::new()
    }

    #[test]
    fn validate_ok_default() {
        assert_eq!(validate_map_shadow_stack_args(0, 0, 0), Ok(()));
    }

    #[test]
    fn validate_set_token_flag_ok() {
        assert_eq!(
            validate_map_shadow_stack_args(0, 0, SHADOW_STACK_SET_TOKEN),
            Ok(())
        );
    }

    #[test]
    fn validate_unknown_flags_rejected() {
        assert_eq!(
            validate_map_shadow_stack_args(0, 0, 0xDEAD),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_misaligned_addr_rejected() {
        assert_eq!(
            validate_map_shadow_stack_args(0x1001, 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_size_too_small_rejected() {
        assert_eq!(
            validate_map_shadow_stack_args(0, 100, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn validate_size_too_large_rejected() {
        assert_eq!(
            validate_map_shadow_stack_args(0, MAX_SHADOW_STACK_BYTES + 1, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn allocate_default_size() {
        let mut s = sys();
        let base = sys_map_shadow_stack(&mut s, 0, 0, 0, 1).unwrap();
        assert_eq!(s.count(), 1);
        assert_eq!(s.total_bytes, DEFAULT_SHADOW_STACK_BYTES);
        assert!(base >= SHADOW_STACK_VA_BASE);
    }

    #[test]
    fn allocate_explicit_size() {
        let mut s = sys();
        let base = sys_map_shadow_stack(&mut s, 0, 4 * PAGE_SIZE, 0, 1).unwrap();
        let alloc = s.find_by_addr(base).unwrap();
        assert_eq!(alloc.size, 4 * PAGE_SIZE);
    }

    #[test]
    fn allocate_with_token() {
        let mut s = sys();
        let base = sys_map_shadow_stack(&mut s, 0, 0, SHADOW_STACK_SET_TOKEN, 1).unwrap();
        let alloc = s.find_by_addr(base).unwrap();
        assert!(alloc.has_token());
        assert!(alloc.attrs.has(ShadowStackAttrs::HAS_TOKEN));
        assert!(is_valid_restore_token(alloc.token_addr, alloc.token_value));
    }

    #[test]
    fn allocate_preferred_addr() {
        let mut s = sys();
        let preferred = 0x7FFF_DEAD_0000u64;
        let base = sys_map_shadow_stack(&mut s, preferred, PAGE_SIZE, 0, 1).unwrap();
        assert_eq!(base, preferred);
    }

    #[test]
    fn two_allocations_have_distinct_addresses() {
        let mut s = sys();
        let a1 = sys_map_shadow_stack(&mut s, 0, 0, 0, 1).unwrap();
        let a2 = sys_map_shadow_stack(&mut s, 0, 0, 0, 1).unwrap();
        assert_ne!(a1, a2);
    }

    #[test]
    fn is_shadow_stack_addr_true() {
        let mut s = sys();
        let base = sys_map_shadow_stack(&mut s, 0, PAGE_SIZE, 0, 1).unwrap();
        assert!(s.is_shadow_stack_addr(base));
        assert!(s.is_shadow_stack_addr(base + 100));
        assert!(!s.is_shadow_stack_addr(base + PAGE_SIZE)); // past end
    }

    #[test]
    fn deallocate_removes_entry() {
        let mut s = sys();
        let base = sys_map_shadow_stack(&mut s, 0, 0, 0, 1).unwrap();
        let id = s.find_by_addr(base).unwrap().id;
        assert_eq!(s.count(), 1);
        sys_unmap_shadow_stack(&mut s, id).unwrap();
        assert_eq!(s.count(), 0);
        assert_eq!(s.total_bytes, 0);
    }

    #[test]
    fn deallocate_unknown_id_fails() {
        let mut s = sys();
        assert_eq!(sys_unmap_shadow_stack(&mut s, 9999), Err(Error::NotFound));
    }

    #[test]
    fn cleanup_pid_removes_all_owned() {
        let mut s = sys();
        sys_map_shadow_stack(&mut s, 0, 0, 0, 42).unwrap();
        sys_map_shadow_stack(&mut s, 0, 0, 0, 42).unwrap();
        sys_map_shadow_stack(&mut s, 0, 0, 0, 99).unwrap();
        assert_eq!(s.count(), 3);
        s.cleanup_pid(42);
        assert_eq!(s.count(), 1);
    }

    #[test]
    fn page_count_correct() {
        let mut s = sys();
        let base = sys_map_shadow_stack(&mut s, 0, 3 * PAGE_SIZE, 0, 1).unwrap();
        let alloc = s.find_by_addr(base).unwrap();
        assert_eq!(alloc.page_count(), 3);
    }

    #[test]
    fn restore_token_validation() {
        let addr = 0x7FFF_0000_FFF8u64;
        let token = addr | 1;
        assert!(is_valid_restore_token(addr, token));
        assert!(!is_valid_restore_token(addr, addr)); // missing bit 0
        assert!(!is_valid_restore_token(addr, 0));
    }
}
