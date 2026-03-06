// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `map_shadow_stack(2)` — allocate and configure shadow stack memory.
//!
//! Shadow stacks are a hardware-enforced security mechanism (Intel CET,
//! ARM GCS) that maintains a separate stack of return addresses.  Each
//! `CALL` pushes the return address onto both the regular and shadow
//! stacks; `RET` pops both and triggers a fault if they differ.
//!
//! The `map_shadow_stack` syscall allocates a shadow stack region and
//! optionally writes a restore token at its base for context switching.
//!
//! # Flags
//!
//! | Flag | Description |
//! |------|-------------|
//! | `SHADOW_STACK_SET_TOKEN` | Write a restore token at the stack base |
//!
//! # Page marking
//!
//! Shadow stack pages are marked with special attributes (equivalent to
//! Linux `VM_SHADOW_STACK`) that prevent ordinary reads/writes.  Only
//! the hardware shadow stack instructions (`CALL`/`RET`, `RSTORSSP`,
//! `SAVEPREVSSP`) can access this memory.
//!
//! # References
//!
//! - Linux: `arch/x86/kernel/shstk.c`
//! - Intel CET specification
//! - man page: `map_shadow_stack(2)`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of shadow stack allocations tracked.
const MAX_SHADOW_STACKS: usize = 64;

/// Standard page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Minimum shadow stack size (one page).
const MIN_SHADOW_STACK_SIZE: u64 = PAGE_SIZE;

/// Maximum shadow stack size (8 MiB — generous for deep recursion).
const MAX_SHADOW_STACK_SIZE: u64 = 8 * 1024 * 1024;

/// Default shadow stack size if zero is requested (64 KiB).
const DEFAULT_SHADOW_STACK_SIZE: u64 = 64 * 1024;

// ---------------------------------------------------------------------------
// Flags
// ---------------------------------------------------------------------------

/// Write a restore token at the shadow stack base.
///
/// The restore token allows the `RSTORSSP` instruction to switch
/// back to this shadow stack during context switches. The token
/// value is the address of the token itself, stored as a 64-bit
/// value with bit 0 set to indicate a valid token.
pub const SHADOW_STACK_SET_TOKEN: u64 = 1 << 0;

/// All valid flag bits.
const SHADOW_STACK_FLAGS_VALID: u64 = SHADOW_STACK_SET_TOKEN;

// ---------------------------------------------------------------------------
// Restore token
// ---------------------------------------------------------------------------

/// Size of a restore token in bytes.
const RESTORE_TOKEN_SIZE: u64 = 8;

/// Generate a restore token value for the given address.
///
/// The token is the address itself with bit 0 set, following
/// the Intel CET specification.
const fn make_restore_token(addr: u64) -> u64 {
    addr | 1
}

/// Validate a restore token at a given address.
///
/// Returns `true` if the token value matches `addr | 1`.
pub fn validate_restore_token(addr: u64, token_value: u64) -> bool {
    token_value == make_restore_token(addr)
}

// ---------------------------------------------------------------------------
// Shadow stack page attributes
// ---------------------------------------------------------------------------

/// Page marking flags for shadow stack memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShadowStackPageFlags(u32);

impl ShadowStackPageFlags {
    /// No special flags.
    pub const NONE: Self = Self(0);
    /// Page is a shadow stack page (VM_SHADOW_STACK equivalent).
    pub const SHADOW_STACK: Self = Self(1 << 0);
    /// Page contains a restore token.
    pub const HAS_TOKEN: Self = Self(1 << 1);
    /// Page is guard page (at the bottom of the shadow stack).
    pub const GUARD_PAGE: Self = Self(1 << 2);

    /// Create from raw value.
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Return raw value.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Check if a flag is set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Set a flag.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl Default for ShadowStackPageFlags {
    fn default() -> Self {
        Self::NONE
    }
}

// ---------------------------------------------------------------------------
// ShadowStackAllocation
// ---------------------------------------------------------------------------

/// A single shadow stack allocation record.
///
/// Tracks the base address, size, flags, and page attributes of
/// one shadow stack region.
#[derive(Debug, Clone, Copy)]
pub struct ShadowStackAllocation {
    /// Base virtual address of the allocation.
    pub base_addr: u64,
    /// Size of the allocation in bytes.
    pub size: u64,
    /// Flags from `map_shadow_stack`.
    pub flags: u64,
    /// Page attribute flags.
    pub page_flags: ShadowStackPageFlags,
    /// Address of the restore token (if `SHADOW_STACK_SET_TOKEN`).
    pub token_addr: u64,
    /// Token value written at `token_addr`.
    pub token_value: u64,
    /// PID of the owning process.
    pub owner_pid: u64,
    /// Whether this slot is active.
    pub active: bool,
    /// Unique ID for this allocation.
    pub id: u64,
}

impl ShadowStackAllocation {
    /// Create an inactive allocation.
    const fn new() -> Self {
        Self {
            base_addr: 0,
            size: 0,
            flags: 0,
            page_flags: ShadowStackPageFlags::NONE,
            token_addr: 0,
            token_value: 0,
            owner_pid: 0,
            active: false,
            id: 0,
        }
    }

    /// Return the end address (exclusive) of this allocation.
    pub const fn end_addr(&self) -> u64 {
        self.base_addr + self.size
    }

    /// Return `true` if this allocation has a restore token.
    pub const fn has_token(&self) -> bool {
        self.flags & SHADOW_STACK_SET_TOKEN != 0
    }

    /// Return the page count for this allocation.
    pub const fn page_count(&self) -> u64 {
        (self.size + PAGE_SIZE - 1) / PAGE_SIZE
    }
}

impl Default for ShadowStackAllocation {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ShadowStackRegistry
// ---------------------------------------------------------------------------

/// Registry tracking shadow stack allocations.
///
/// In a real kernel, shadow stack memory is backed by actual page
/// table entries with special attributes. This stub tracks the
/// allocations for validation and bookkeeping.
pub struct ShadowStackRegistry {
    /// Allocation slots.
    allocs: [ShadowStackAllocation; MAX_SHADOW_STACKS],
    /// Next allocation ID.
    next_id: u64,
    /// Number of active allocations.
    count: usize,
    /// Next base address to assign (simulated VA allocation).
    next_base: u64,
    /// Total bytes allocated.
    total_bytes: u64,
}

impl ShadowStackRegistry {
    /// Create an empty registry.
    ///
    /// Shadow stacks are allocated starting at a high virtual address
    /// to avoid conflicts with regular memory.
    pub const fn new() -> Self {
        Self {
            allocs: [const { ShadowStackAllocation::new() }; MAX_SHADOW_STACKS],
            next_id: 1,
            count: 0,
            // Start at a high VA to avoid conflicts with regular allocations.
            next_base: 0x7FFF_0000_0000,
            total_bytes: 0,
        }
    }

    /// Return the number of active allocations.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return `true` if no allocations are active.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Return total bytes allocated.
    pub const fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    // ---------------------------------------------------------------
    // Lookup helpers
    // ---------------------------------------------------------------

    /// Find an active allocation by ID (shared reference).
    fn find(&self, id: u64) -> Result<&ShadowStackAllocation> {
        self.allocs
            .iter()
            .find(|a| a.active && a.id == id)
            .ok_or(Error::NotFound)
    }

    /// Find an allocation that contains the given address.
    pub fn find_by_addr(&self, addr: u64) -> Option<&ShadowStackAllocation> {
        self.allocs
            .iter()
            .find(|a| a.active && addr >= a.base_addr && addr < a.end_addr())
    }

    /// Check if an address falls within any shadow stack allocation.
    pub fn is_shadow_stack_addr(&self, addr: u64) -> bool {
        self.find_by_addr(addr).is_some()
    }

    // ---------------------------------------------------------------
    // Allocation
    // ---------------------------------------------------------------

    /// Allocate a new shadow stack.
    fn allocate(
        &mut self,
        requested_size: u64,
        flags: u64,
        pid: u64,
    ) -> Result<&ShadowStackAllocation> {
        let idx = self
            .allocs
            .iter()
            .position(|a| !a.active)
            .ok_or(Error::OutOfMemory)?;

        // Determine actual size.
        let size = if requested_size == 0 {
            DEFAULT_SHADOW_STACK_SIZE
        } else {
            // Round up to page boundary.
            (requested_size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
        };

        // Assign base address.
        let base_addr = self.next_base;
        self.next_base = self.next_base.wrapping_add(size + PAGE_SIZE); // +guard

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        // Compute page flags.
        let mut page_flags = ShadowStackPageFlags::SHADOW_STACK;
        let mut token_addr = 0u64;
        let mut token_value = 0u64;

        if flags & SHADOW_STACK_SET_TOKEN != 0 {
            page_flags = page_flags.union(ShadowStackPageFlags::HAS_TOKEN);
            // Token is written at the top of the shadow stack (just below
            // the end, aligned to 8 bytes).
            token_addr = base_addr + size - RESTORE_TOKEN_SIZE;
            token_value = make_restore_token(token_addr);
        }

        let slot = &mut self.allocs[idx];
        slot.base_addr = base_addr;
        slot.size = size;
        slot.flags = flags;
        slot.page_flags = page_flags;
        slot.token_addr = token_addr;
        slot.token_value = token_value;
        slot.owner_pid = pid;
        slot.active = true;
        slot.id = id;

        self.count += 1;
        self.total_bytes = self.total_bytes.saturating_add(size);

        Ok(&self.allocs[idx])
    }

    // ---------------------------------------------------------------
    // Deallocation
    // ---------------------------------------------------------------

    /// Deallocate a shadow stack by ID.
    fn deallocate(&mut self, id: u64) -> Result<()> {
        for alloc in self.allocs.iter_mut() {
            if alloc.active && alloc.id == id {
                self.total_bytes = self.total_bytes.saturating_sub(alloc.size);
                alloc.active = false;
                self.count = self.count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Deallocate all shadow stacks owned by a PID.
    pub fn cleanup_pid(&mut self, pid: u64) {
        for alloc in self.allocs.iter_mut() {
            if alloc.active && alloc.owner_pid == pid {
                self.total_bytes = self.total_bytes.saturating_sub(alloc.size);
                alloc.active = false;
                self.count = self.count.saturating_sub(1);
            }
        }
    }
}

impl Default for ShadowStackRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate `map_shadow_stack` arguments.
fn validate_args(addr: u64, size: u64, flags: u64) -> Result<()> {
    // Flags: only known bits.
    if (flags & !SHADOW_STACK_FLAGS_VALID) != 0 {
        return Err(Error::InvalidArgument);
    }

    // If addr is specified, it must be page-aligned.
    if addr != 0 && (addr % PAGE_SIZE) != 0 {
        return Err(Error::InvalidArgument);
    }

    // Size validation (0 means default).
    if size != 0 {
        if size < MIN_SHADOW_STACK_SIZE {
            return Err(Error::InvalidArgument);
        }
        if size > MAX_SHADOW_STACK_SIZE {
            return Err(Error::InvalidArgument);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Syscall handlers
// ---------------------------------------------------------------------------

/// `map_shadow_stack(2)` — allocate a shadow stack.
///
/// # Arguments
///
/// * `registry` — The global shadow stack registry.
/// * `addr`     — Preferred base address (0 for kernel-chosen).
/// * `size`     — Requested size in bytes (0 for default, otherwise
///                must be at least `PAGE_SIZE` and page-aligned).
/// * `flags`    — `SHADOW_STACK_SET_TOKEN` to write a restore token.
/// * `pid`      — Calling process ID.
///
/// # Returns
///
/// The base address of the allocated shadow stack.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Invalid flags, misaligned address,
///   or size out of range.
/// * [`Error::OutOfMemory`] — Registry is full.
pub fn sys_map_shadow_stack(
    registry: &mut ShadowStackRegistry,
    addr: u64,
    size: u64,
    flags: u64,
    pid: u64,
) -> Result<u64> {
    validate_args(addr, size, flags)?;
    let alloc = registry.allocate(size, flags, pid)?;
    Ok(alloc.base_addr)
}

/// Deallocate a shadow stack by ID.
///
/// # Errors
///
/// * [`Error::NotFound`] — No allocation with the given ID.
pub fn sys_unmap_shadow_stack(registry: &mut ShadowStackRegistry, id: u64) -> Result<()> {
    registry.deallocate(id)
}

/// Look up a shadow stack allocation by address.
///
/// Returns details about the allocation containing the given address,
/// or `NotFound` if the address is not in any shadow stack.
pub fn sys_shadow_stack_info(
    registry: &ShadowStackRegistry,
    addr: u64,
) -> Result<&ShadowStackAllocation> {
    registry.find_by_addr(addr).ok_or(Error::NotFound)
}

/// Find a shadow stack allocation by ID.
///
/// # Errors
///
/// * [`Error::NotFound`] — No allocation with the given ID.
pub fn sys_shadow_stack_get(
    registry: &ShadowStackRegistry,
    id: u64,
) -> Result<&ShadowStackAllocation> {
    registry.find(id)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocate_default_size() {
        let mut r = ShadowStackRegistry::new();
        let addr = sys_map_shadow_stack(&mut r, 0, 0, 0, 1);
        assert!(addr.is_ok());
        assert_eq!(r.count(), 1);
        assert_eq!(r.total_bytes(), DEFAULT_SHADOW_STACK_SIZE);
    }

    #[test]
    fn allocate_specific_size() {
        let mut r = ShadowStackRegistry::new();
        let addr = sys_map_shadow_stack(&mut r, 0, 8 * PAGE_SIZE, 0, 1);
        assert!(addr.is_ok());
        assert_eq!(r.total_bytes(), 8 * PAGE_SIZE);
    }

    #[test]
    fn allocate_with_token() {
        let mut r = ShadowStackRegistry::new();
        let base = sys_map_shadow_stack(&mut r, 0, 0, SHADOW_STACK_SET_TOKEN, 1).unwrap();
        let alloc = r.find_by_addr(base).unwrap();
        assert!(alloc.has_token());
        assert!(alloc.page_flags.contains(ShadowStackPageFlags::HAS_TOKEN));
        assert_ne!(alloc.token_addr, 0);
        assert!(validate_restore_token(alloc.token_addr, alloc.token_value));
    }

    #[test]
    fn allocate_size_too_small_rejected() {
        let mut r = ShadowStackRegistry::new();
        assert_eq!(
            sys_map_shadow_stack(&mut r, 0, 100, 0, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn allocate_size_too_large_rejected() {
        let mut r = ShadowStackRegistry::new();
        assert_eq!(
            sys_map_shadow_stack(&mut r, 0, MAX_SHADOW_STACK_SIZE + 1, 0, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn allocate_misaligned_addr_rejected() {
        let mut r = ShadowStackRegistry::new();
        assert_eq!(
            sys_map_shadow_stack(&mut r, 0x1001, 0, 0, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn allocate_invalid_flags_rejected() {
        let mut r = ShadowStackRegistry::new();
        assert_eq!(
            sys_map_shadow_stack(&mut r, 0, 0, 0xDEAD, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn deallocate_shadow_stack() {
        let mut r = ShadowStackRegistry::new();
        let base = sys_map_shadow_stack(&mut r, 0, 0, 0, 1).unwrap();
        let alloc = r.find_by_addr(base).unwrap();
        let id = alloc.id;
        assert_eq!(r.count(), 1);
        assert_eq!(sys_unmap_shadow_stack(&mut r, id), Ok(()));
        assert_eq!(r.count(), 0);
        assert_eq!(r.total_bytes(), 0);
    }

    #[test]
    fn deallocate_unknown_id_fails() {
        let mut r = ShadowStackRegistry::new();
        assert_eq!(sys_unmap_shadow_stack(&mut r, 999), Err(Error::NotFound));
    }

    #[test]
    fn is_shadow_stack_addr() {
        let mut r = ShadowStackRegistry::new();
        let base = sys_map_shadow_stack(&mut r, 0, PAGE_SIZE, 0, 1).unwrap();
        assert!(r.is_shadow_stack_addr(base));
        assert!(r.is_shadow_stack_addr(base + 100));
        assert!(!r.is_shadow_stack_addr(base + PAGE_SIZE)); // Past end.
        assert!(!r.is_shadow_stack_addr(0x1000)); // Unrelated.
    }

    #[test]
    fn cleanup_pid_removes_allocations() {
        let mut r = ShadowStackRegistry::new();
        let _ = sys_map_shadow_stack(&mut r, 0, 0, 0, 42).unwrap();
        let _ = sys_map_shadow_stack(&mut r, 0, 0, 0, 42).unwrap();
        let _ = sys_map_shadow_stack(&mut r, 0, 0, 0, 99).unwrap();
        assert_eq!(r.count(), 3);
        r.cleanup_pid(42);
        assert_eq!(r.count(), 1);
    }

    #[test]
    fn page_count() {
        let mut r = ShadowStackRegistry::new();
        let base = sys_map_shadow_stack(&mut r, 0, 3 * PAGE_SIZE, 0, 1).unwrap();
        let alloc = r.find_by_addr(base).unwrap();
        assert_eq!(alloc.page_count(), 3);
    }

    #[test]
    fn restore_token_validation() {
        let addr = 0x7FFF_0000_FFF8;
        let token = make_restore_token(addr);
        assert_eq!(token, addr | 1);
        assert!(validate_restore_token(addr, token));
        assert!(!validate_restore_token(addr, addr)); // No bit 0.
    }

    #[test]
    fn shadow_stack_info_by_addr() {
        let mut r = ShadowStackRegistry::new();
        let base = sys_map_shadow_stack(&mut r, 0, PAGE_SIZE, SHADOW_STACK_SET_TOKEN, 1).unwrap();
        let info = sys_shadow_stack_info(&r, base).unwrap();
        assert_eq!(info.base_addr, base);
        assert!(info.has_token());
    }

    #[test]
    fn shadow_stack_info_unknown_addr() {
        let r = ShadowStackRegistry::new();
        assert_eq!(sys_shadow_stack_info(&r, 0x12345), Err(Error::NotFound));
    }

    #[test]
    fn page_flags_operations() {
        let f = ShadowStackPageFlags::SHADOW_STACK.union(ShadowStackPageFlags::HAS_TOKEN);
        assert!(f.contains(ShadowStackPageFlags::SHADOW_STACK));
        assert!(f.contains(ShadowStackPageFlags::HAS_TOKEN));
        assert!(!f.contains(ShadowStackPageFlags::GUARD_PAGE));
    }

    #[test]
    fn multiple_allocations_unique_addresses() {
        let mut r = ShadowStackRegistry::new();
        let a1 = sys_map_shadow_stack(&mut r, 0, PAGE_SIZE, 0, 1).unwrap();
        let a2 = sys_map_shadow_stack(&mut r, 0, PAGE_SIZE, 0, 1).unwrap();
        assert_ne!(a1, a2);
    }

    #[test]
    fn allocation_default_values() {
        let a = ShadowStackAllocation::default();
        assert!(!a.active);
        assert_eq!(a.base_addr, 0);
        assert_eq!(a.size, 0);
    }
}
