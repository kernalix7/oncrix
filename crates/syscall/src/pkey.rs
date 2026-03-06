// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Memory Protection Keys (`pkey`) — per-thread, hardware-enforced
//! memory access permissions.
//!
//! Implements the Linux `pkey_alloc(2)`, `pkey_free(2)`, and
//! `pkey_mprotect(2)` system calls.  Memory Protection Keys (MPK)
//! allow user-space to control access to groups of pages without
//! modifying page table entries, using a per-thread register (PKRU
//! on x86_64) that can be updated in user-space without a syscall.
//!
//! # Syscall signatures
//!
//! ```text
//! int pkey_alloc(unsigned int flags, unsigned int access_rights);
//! int pkey_free(int pkey);
//! int pkey_mprotect(void *addr, size_t len, int prot, int pkey);
//! ```
//!
//! # Architecture support
//!
//! - **x86_64**: Intel Memory Protection Keys (MPK), PKRU register
//!   (32-bit, 2 bits per key → 16 keys, key 0 reserved).
//! - **aarch64**: Not natively supported (emulated or stubbed).
//! - **riscv64**: Not supported.
//!
//! # Key allocation
//!
//! Keys 0..15 are available on x86_64. Key 0 is the default key
//! applied to all memory and cannot be allocated or freed by
//! user-space.
//!
//! # Relationship to mprotect
//!
//! `pkey_mprotect` is an extension of `mprotect(2)` that additionally
//! associates a protection key with the memory region. The key can
//! then be used to further restrict access via the PKRU register.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of protection keys (x86_64 hardware limit).
pub const PKEY_MAX: usize = 16;

/// Protection key 0 (default, always allocated, cannot be freed).
pub const PKEY_DEFAULT: i32 = 0;

/// Page size (4 KiB).
const PAGE_SIZE: u64 = 4096;

/// Page-offset mask (low 12 bits).
const PAGE_MASK: u64 = PAGE_SIZE - 1;

/// User-space address space limit (canonical lower-half on x86_64).
const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;

/// Syscall number for `pkey_mprotect` (x86_64 Linux ABI).
pub const SYS_PKEY_MPROTECT: u64 = 329;

/// Syscall number for `pkey_alloc` (x86_64 Linux ABI).
pub const SYS_PKEY_ALLOC: u64 = 330;

/// Syscall number for `pkey_free` (x86_64 Linux ABI).
pub const SYS_PKEY_FREE: u64 = 331;

// ---------------------------------------------------------------------------
// PkeyRights — access-restriction bitflags
// ---------------------------------------------------------------------------

/// Per-key access-restriction flags.
///
/// These flags are stored in the PKRU register (2 bits per key)
/// and control access to pages tagged with a given protection key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PkeyRights(u32);

impl PkeyRights {
    /// Disable all access (reads and writes) to pages with this key.
    pub const PKEY_DISABLE_ACCESS: u32 = 0x1;

    /// Disable write access to pages with this key (reads allowed).
    pub const PKEY_DISABLE_WRITE: u32 = 0x2;

    /// Mask of all valid right bits.
    const VALID_MASK: u32 = Self::PKEY_DISABLE_ACCESS | Self::PKEY_DISABLE_WRITE;

    /// Create a new `PkeyRights` from raw flags.
    ///
    /// Returns `InvalidArgument` if any unknown bits are set.
    pub fn from_raw(raw: u32) -> Result<Self> {
        if raw & !Self::VALID_MASK != 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self(raw))
    }

    /// Create an empty (no restrictions) rights value.
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Return the raw bits.
    pub const fn bits(&self) -> u32 {
        self.0
    }

    /// Check whether access is disabled.
    pub const fn is_access_disabled(&self) -> bool {
        self.0 & Self::PKEY_DISABLE_ACCESS != 0
    }

    /// Check whether write access is disabled.
    pub const fn is_write_disabled(&self) -> bool {
        self.0 & Self::PKEY_DISABLE_WRITE != 0
    }

    /// Return the two-bit value to place in the PKRU register
    /// for this key.
    ///
    /// Bit 0 = access-disable, Bit 1 = write-disable.
    pub const fn pkru_bits(&self) -> u32 {
        self.0
    }

    /// Compute the PKRU bit shift for a given key index.
    ///
    /// Each key occupies 2 bits in the PKRU register.
    pub const fn pkru_shift(pkey: u32) -> u32 {
        pkey * 2
    }

    /// Return `true` if the rights are empty (no restrictions).
    pub const fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

// ---------------------------------------------------------------------------
// Protection flags (PROT_*)
// ---------------------------------------------------------------------------

/// Pages may not be accessed.
pub const PROT_NONE: u32 = 0x0;
/// Pages may be read.
pub const PROT_READ: u32 = 0x1;
/// Pages may be written.
pub const PROT_WRITE: u32 = 0x2;
/// Pages may be executed.
pub const PROT_EXEC: u32 = 0x4;

/// Mask of all valid protection bits.
const PROT_VALID_MASK: u32 = PROT_READ | PROT_WRITE | PROT_EXEC;

// ---------------------------------------------------------------------------
// PkeyState — per-process protection key state
// ---------------------------------------------------------------------------

/// Per-process protection key allocation state.
///
/// Tracks which keys are allocated and their current access rights.
/// On x86_64, there are 16 keys (indices 0..15), with key 0
/// permanently allocated as the default key.
#[derive(Debug, Clone)]
pub struct PkeyState {
    /// Bitmap of allocated keys. Bit `i` set means key `i` is in use.
    allocated: u16,
    /// Access rights for each key.
    rights: [PkeyRights; PKEY_MAX],
}

impl PkeyState {
    /// Create a new `PkeyState` with key 0 pre-allocated.
    pub fn new() -> Self {
        Self {
            // Key 0 is always allocated.
            allocated: 1,
            rights: [PkeyRights::empty(); PKEY_MAX],
        }
    }

    /// Return `true` if the given key index is allocated.
    pub const fn is_allocated(&self, pkey: u32) -> bool {
        if pkey >= PKEY_MAX as u32 {
            return false;
        }
        self.allocated & (1 << pkey) != 0
    }

    /// Return the number of allocated keys.
    pub const fn allocated_count(&self) -> u32 {
        self.allocated.count_ones()
    }

    /// Return the number of free keys (excluding key 0).
    pub const fn free_count(&self) -> u32 {
        PKEY_MAX as u32 - self.allocated.count_ones()
    }

    /// Get the rights for a key.
    ///
    /// Returns `InvalidArgument` if the key is not allocated or
    /// out of range.
    pub fn get_rights(&self, pkey: u32) -> Result<PkeyRights> {
        if pkey >= PKEY_MAX as u32 {
            return Err(Error::InvalidArgument);
        }
        if !self.is_allocated(pkey) {
            return Err(Error::InvalidArgument);
        }
        Ok(self.rights[pkey as usize])
    }

    /// Set the rights for a key.
    ///
    /// Returns `InvalidArgument` if the key is not allocated or
    /// out of range.
    pub fn set_rights(&mut self, pkey: u32, rights: PkeyRights) -> Result<()> {
        if pkey >= PKEY_MAX as u32 {
            return Err(Error::InvalidArgument);
        }
        if !self.is_allocated(pkey) {
            return Err(Error::InvalidArgument);
        }
        self.rights[pkey as usize] = rights;
        Ok(())
    }

    /// Find and allocate a free protection key.
    ///
    /// Returns the key index on success. Key 0 is never allocated
    /// through this function.
    fn alloc_key(&mut self) -> Result<u32> {
        // Search keys 1..PKEY_MAX for a free slot.
        for i in 1..PKEY_MAX as u32 {
            if !self.is_allocated(i) {
                self.allocated |= 1 << i;
                return Ok(i);
            }
        }
        Err(Error::Busy)
    }

    /// Free a previously allocated protection key.
    ///
    /// Key 0 cannot be freed.
    fn free_key(&mut self, pkey: u32) -> Result<()> {
        if pkey == 0 || pkey >= PKEY_MAX as u32 {
            return Err(Error::InvalidArgument);
        }
        if !self.is_allocated(pkey) {
            return Err(Error::InvalidArgument);
        }
        self.allocated &= !(1 << pkey);
        self.rights[pkey as usize] = PkeyRights::empty();
        Ok(())
    }

    /// Compute the full PKRU register value from all key rights.
    ///
    /// The PKRU is a 32-bit register with 2 bits per key:
    /// - Bit `2*k`   = access-disable for key `k`
    /// - Bit `2*k+1` = write-disable for key `k`
    pub const fn compute_pkru(&self) -> u32 {
        let mut pkru: u32 = 0;
        let mut i: u32 = 0;
        while i < PKEY_MAX as u32 {
            let shift = PkeyRights::pkru_shift(i);
            pkru |= self.rights[i as usize].pkru_bits() << shift;
            i += 1;
        }
        pkru
    }

    /// Return the raw allocated bitmap.
    pub const fn allocated_bitmap(&self) -> u16 {
        self.allocated
    }
}

impl Default for PkeyState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MemoryRegionPkey — pkey association for a memory region
// ---------------------------------------------------------------------------

/// Describes a memory region with an associated protection key.
///
/// This is the result of a successful `pkey_mprotect` call: the
/// memory region `[addr, addr+len)` now has protection `prot` and
/// is tagged with protection key `pkey`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRegionPkey {
    /// Base address of the region (page-aligned).
    pub addr: u64,
    /// Length of the region in bytes (page-aligned).
    pub len: u64,
    /// Protection flags (`PROT_READ | PROT_WRITE | PROT_EXEC`).
    pub prot: u32,
    /// Protection key associated with this region.
    pub pkey: u32,
}

impl MemoryRegionPkey {
    /// Create a new region descriptor.
    pub const fn new(addr: u64, len: u64, prot: u32, pkey: u32) -> Self {
        Self {
            addr,
            len,
            prot,
            pkey,
        }
    }
}

// ---------------------------------------------------------------------------
// PkeyMprotectArgs — parameter bundle for pkey_mprotect
// ---------------------------------------------------------------------------

/// Arguments for the `pkey_mprotect` syscall.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PkeyMprotectArgs {
    /// Base address of the memory region.
    pub addr: u64,
    /// Length of the memory region.
    pub len: u64,
    /// Desired memory protection (PROT_*).
    pub prot: u32,
    /// Protection key to associate with the region.
    pub pkey: i32,
}

impl PkeyMprotectArgs {
    /// Validate the argument bundle.
    ///
    /// # Checks
    ///
    /// - `addr` is page-aligned.
    /// - `len` is non-zero and page-aligned.
    /// - `addr + len` does not overflow and stays in user-space.
    /// - `prot` contains only valid bits.
    /// - `pkey` is in the valid range `0..PKEY_MAX`.
    pub fn validate(&self) -> Result<()> {
        // Address alignment.
        if self.addr & PAGE_MASK != 0 {
            return Err(Error::InvalidArgument);
        }

        // Length checks.
        if self.len == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.len & PAGE_MASK != 0 {
            return Err(Error::InvalidArgument);
        }

        // Overflow check.
        let end = self
            .addr
            .checked_add(self.len)
            .ok_or(Error::InvalidArgument)?;

        // User-space range check.
        if end > USER_SPACE_END {
            return Err(Error::InvalidArgument);
        }

        // Protection flags.
        if self.prot & !PROT_VALID_MASK != 0 {
            return Err(Error::InvalidArgument);
        }

        // Key range.
        if self.pkey < 0 || self.pkey >= PKEY_MAX as i32 {
            return Err(Error::InvalidArgument);
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// do_pkey_alloc
// ---------------------------------------------------------------------------

/// Allocate a new protection key.
///
/// # Arguments
///
/// - `state` — Per-process protection key state.
/// - `flags` — Reserved, must be 0.
/// - `access_rights` — Initial access rights for the key.
///
/// # Returns
///
/// The allocated key index on success.
///
/// # Errors
///
/// - `InvalidArgument` — Non-zero flags or invalid rights.
/// - `Busy` — All 15 user keys are allocated.
pub fn do_pkey_alloc(state: &mut PkeyState, flags: u32, access_rights: u32) -> Result<i32> {
    // flags must be zero (no flags defined).
    if flags != 0 {
        return Err(Error::InvalidArgument);
    }

    let rights = PkeyRights::from_raw(access_rights)?;

    let pkey = state.alloc_key()?;

    // Set initial rights.
    // alloc_key guarantees the key is allocated, so this cannot fail.
    state.rights[pkey as usize] = rights;

    Ok(pkey as i32)
}

// ---------------------------------------------------------------------------
// do_pkey_free
// ---------------------------------------------------------------------------

/// Free a previously allocated protection key.
///
/// After freeing, the key must not be used with `pkey_mprotect`
/// until re-allocated. Any memory regions still tagged with this
/// key revert to the default key (key 0) behavior.
///
/// # Arguments
///
/// - `state` — Per-process protection key state.
/// - `pkey` — The key to free.
///
/// # Errors
///
/// - `InvalidArgument` — Key 0, out of range, or not allocated.
pub fn do_pkey_free(state: &mut PkeyState, pkey: i32) -> Result<()> {
    if pkey < 0 {
        return Err(Error::InvalidArgument);
    }
    state.free_key(pkey as u32)
}

// ---------------------------------------------------------------------------
// do_pkey_mprotect
// ---------------------------------------------------------------------------

/// Change memory protection and associate a protection key.
///
/// This extends `mprotect(2)` by additionally tagging the region
/// with a protection key. The key provides an additional layer of
/// access control via the per-thread PKRU register.
///
/// # Arguments
///
/// - `state` — Per-process protection key state.
/// - `args` — The syscall argument bundle.
///
/// # Returns
///
/// A [`MemoryRegionPkey`] describing the updated region.
///
/// # Errors
///
/// - `InvalidArgument` — Bad address, length, protection bits, or
///   key. Also returned if the key is not allocated.
pub fn do_pkey_mprotect(state: &PkeyState, args: &PkeyMprotectArgs) -> Result<MemoryRegionPkey> {
    args.validate()?;

    let pkey = args.pkey as u32;

    // Key must be allocated.
    if !state.is_allocated(pkey) {
        return Err(Error::InvalidArgument);
    }

    // In a real kernel, this is where we would:
    // 1. Look up the VMA(s) covering [addr, addr+len).
    // 2. Split VMAs at boundaries if needed.
    // 3. Update page table entries with new protection bits.
    // 4. Set the pkey field in the VMA struct.
    // 5. Flush TLB for affected pages.

    Ok(MemoryRegionPkey::new(args.addr, args.len, args.prot, pkey))
}

// ---------------------------------------------------------------------------
// PKRU register manipulation helpers
// ---------------------------------------------------------------------------

/// Read the PKRU register value for the current thread.
///
/// On x86_64, this reads the PKRU register via `RDPKRU`.
/// Returns 0 if PKU is not supported.
///
/// # Safety
///
/// This function uses inline assembly and must only be called
/// on x86_64 targets with PKU support.
#[cfg(target_arch = "x86_64")]
pub fn read_pkru() -> u32 {
    let pkru: u32;
    // SAFETY: RDPKRU is a user-mode instruction on x86_64 that reads
    // the PKRU register. ECX must be 0. The result is in EAX (EDX is
    // zeroed by the CPU but we ignore it).
    unsafe {
        core::arch::asm!(
            "xor ecx, ecx",
            "rdpkru",
            out("eax") pkru,
            out("ecx") _,
            out("edx") _,
            options(nomem, nostack),
        );
    }
    pkru
}

/// Write a new PKRU register value for the current thread.
///
/// On x86_64, this writes the PKRU register via `WRPKRU`.
///
/// # Safety
///
/// This function uses inline assembly and must only be called
/// on x86_64 targets with PKU support. Writing an incorrect
/// PKRU value may cause spurious access faults.
#[cfg(target_arch = "x86_64")]
pub fn write_pkru(pkru: u32) {
    // SAFETY: WRPKRU is a user-mode instruction on x86_64 that writes
    // the PKRU register. ECX and EDX must be 0. EAX contains the new
    // PKRU value.
    unsafe {
        core::arch::asm!(
            "xor ecx, ecx",
            "xor edx, edx",
            "wrpkru",
            in("eax") pkru,
            out("ecx") _,
            out("edx") _,
            options(nomem, nostack),
        );
    }
}

/// Stub for non-x86_64 architectures: read PKRU.
///
/// Returns 0 (no restrictions) since MPK is not available.
#[cfg(not(target_arch = "x86_64"))]
pub fn read_pkru() -> u32 {
    0
}

/// Stub for non-x86_64 architectures: write PKRU.
///
/// No-op since MPK is not available.
#[cfg(not(target_arch = "x86_64"))]
pub fn write_pkru(_pkru: u32) {}

// ---------------------------------------------------------------------------
// PKRU update helpers
// ---------------------------------------------------------------------------

/// Update the PKRU register to reflect the rights of a single key.
///
/// Reads the current PKRU, clears the two bits for `pkey`, and
/// sets them to the new `rights`.
pub fn update_pkru_for_key(pkey: u32, rights: PkeyRights) {
    if pkey >= PKEY_MAX as u32 {
        return;
    }
    let shift = PkeyRights::pkru_shift(pkey);
    let mask = !(0x3u32 << shift);
    let current = read_pkru();
    let new_val = (current & mask) | (rights.pkru_bits() << shift);
    write_pkru(new_val);
}

/// Synchronize the PKRU register with the full `PkeyState`.
///
/// Writes a PKRU value computed from all allocated keys' rights.
pub fn sync_pkru(state: &PkeyState) {
    write_pkru(state.compute_pkru());
}

// ---------------------------------------------------------------------------
// Syscall entry points (from raw register values)
// ---------------------------------------------------------------------------

/// Process a `pkey_alloc` syscall.
///
/// # Arguments
///
/// - `state` — Per-process pkey state.
/// - `flags` — Raw `flags` argument (must be 0).
/// - `access_rights` — Raw `access_rights` argument.
///
/// # Returns
///
/// Allocated key index on success, or error.
pub fn sys_pkey_alloc(state: &mut PkeyState, flags: u64, access_rights: u64) -> Result<i32> {
    let flags_u32 = u32::try_from(flags).map_err(|_| Error::InvalidArgument)?;
    let rights_u32 = u32::try_from(access_rights).map_err(|_| Error::InvalidArgument)?;

    do_pkey_alloc(state, flags_u32, rights_u32)
}

/// Process a `pkey_free` syscall.
///
/// # Arguments
///
/// - `state` — Per-process pkey state.
/// - `pkey` — Raw `pkey` argument.
pub fn sys_pkey_free(state: &mut PkeyState, pkey: u64) -> Result<()> {
    let pkey_i32 = i32::try_from(pkey).map_err(|_| Error::InvalidArgument)?;
    do_pkey_free(state, pkey_i32)
}

/// Process a `pkey_mprotect` syscall.
///
/// # Arguments
///
/// - `state` — Per-process pkey state.
/// - `addr` — Base address of the memory region.
/// - `len` — Length of the region.
/// - `prot` — Desired protection flags.
/// - `pkey` — Protection key to associate.
pub fn sys_pkey_mprotect(
    state: &PkeyState,
    addr: u64,
    len: u64,
    prot: u64,
    pkey: u64,
) -> Result<MemoryRegionPkey> {
    let prot_u32 = u32::try_from(prot).map_err(|_| Error::InvalidArgument)?;
    let pkey_i32 = i32::try_from(pkey).map_err(|_| Error::InvalidArgument)?;

    let args = PkeyMprotectArgs {
        addr,
        len,
        prot: prot_u32,
        pkey: pkey_i32,
    };

    do_pkey_mprotect(state, &args)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkey_rights_from_raw() {
        assert!(PkeyRights::from_raw(0).is_ok());
        assert!(PkeyRights::from_raw(PkeyRights::PKEY_DISABLE_ACCESS).is_ok());
        assert!(PkeyRights::from_raw(PkeyRights::PKEY_DISABLE_WRITE).is_ok());
        assert!(
            PkeyRights::from_raw(PkeyRights::PKEY_DISABLE_ACCESS | PkeyRights::PKEY_DISABLE_WRITE)
                .is_ok()
        );
        assert_eq!(
            PkeyRights::from_raw(0x4).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_pkey_rights_methods() {
        let rights = PkeyRights::from_raw(PkeyRights::PKEY_DISABLE_ACCESS).unwrap();
        assert!(rights.is_access_disabled());
        assert!(!rights.is_write_disabled());

        let rights = PkeyRights::from_raw(PkeyRights::PKEY_DISABLE_WRITE).unwrap();
        assert!(!rights.is_access_disabled());
        assert!(rights.is_write_disabled());

        let empty = PkeyRights::empty();
        assert!(empty.is_empty());
        assert!(!empty.is_access_disabled());
    }

    #[test]
    fn test_pkey_state_new() {
        let state = PkeyState::new();
        assert!(state.is_allocated(0));
        assert!(!state.is_allocated(1));
        assert_eq!(state.allocated_count(), 1);
        assert_eq!(state.free_count(), 15);
    }

    #[test]
    fn test_pkey_alloc_free() {
        let mut state = PkeyState::new();

        let k1 = do_pkey_alloc(&mut state, 0, 0).unwrap();
        assert!(k1 >= 1 && k1 < PKEY_MAX as i32);
        assert!(state.is_allocated(k1 as u32));

        let k2 = do_pkey_alloc(&mut state, 0, 0).unwrap();
        assert_ne!(k1, k2);
        assert!(state.is_allocated(k2 as u32));

        do_pkey_free(&mut state, k1).unwrap();
        assert!(!state.is_allocated(k1 as u32));

        // Free again should fail.
        assert_eq!(
            do_pkey_free(&mut state, k1).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_pkey_alloc_exhaustion() {
        let mut state = PkeyState::new();

        // Allocate all 15 user keys.
        for _ in 1..PKEY_MAX {
            do_pkey_alloc(&mut state, 0, 0).unwrap();
        }
        assert_eq!(state.free_count(), 0);

        // Next alloc should fail.
        assert_eq!(do_pkey_alloc(&mut state, 0, 0).unwrap_err(), Error::Busy);
    }

    #[test]
    fn test_pkey_alloc_bad_flags() {
        let mut state = PkeyState::new();
        assert_eq!(
            do_pkey_alloc(&mut state, 1, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_pkey_free_key_zero() {
        let mut state = PkeyState::new();
        assert_eq!(
            do_pkey_free(&mut state, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_pkey_mprotect_basic() {
        let mut state = PkeyState::new();
        let pkey = do_pkey_alloc(&mut state, 0, 0).unwrap();

        let args = PkeyMprotectArgs {
            addr: 0x1000,
            len: 0x2000,
            prot: PROT_READ | PROT_WRITE,
            pkey,
        };

        let result = do_pkey_mprotect(&state, &args).unwrap();
        assert_eq!(result.addr, 0x1000);
        assert_eq!(result.len, 0x2000);
        assert_eq!(result.prot, PROT_READ | PROT_WRITE);
        assert_eq!(result.pkey, pkey as u32);
    }

    #[test]
    fn test_pkey_mprotect_unallocated_key() {
        let state = PkeyState::new();
        let args = PkeyMprotectArgs {
            addr: 0x1000,
            len: 0x1000,
            prot: PROT_READ,
            pkey: 5,
        };
        assert_eq!(
            do_pkey_mprotect(&state, &args).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_pkey_mprotect_bad_alignment() {
        let mut state = PkeyState::new();
        let pkey = do_pkey_alloc(&mut state, 0, 0).unwrap();

        let args = PkeyMprotectArgs {
            addr: 0x1001, // not page-aligned
            len: 0x1000,
            prot: PROT_READ,
            pkey,
        };
        assert_eq!(
            do_pkey_mprotect(&state, &args).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_pkey_mprotect_bad_prot() {
        let mut state = PkeyState::new();
        let pkey = do_pkey_alloc(&mut state, 0, 0).unwrap();

        let args = PkeyMprotectArgs {
            addr: 0x1000,
            len: 0x1000,
            prot: 0xFF, // invalid
            pkey,
        };
        assert_eq!(
            do_pkey_mprotect(&state, &args).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_compute_pkru() {
        let mut state = PkeyState::new();

        // Key 0 with no restrictions → bits 0..1 = 0b00
        // Allocate key 1 with DISABLE_ACCESS → bits 2..3 = 0b01
        let k1 = do_pkey_alloc(&mut state, 0, PkeyRights::PKEY_DISABLE_ACCESS).unwrap();
        assert_eq!(k1, 1);

        let pkru = state.compute_pkru();
        assert_eq!(pkru & 0x3, 0); // key 0 = no restrictions
        assert_eq!((pkru >> 2) & 0x3, 1); // key 1 = disable access
    }

    #[test]
    fn test_pkru_shift() {
        assert_eq!(PkeyRights::pkru_shift(0), 0);
        assert_eq!(PkeyRights::pkru_shift(1), 2);
        assert_eq!(PkeyRights::pkru_shift(15), 30);
    }

    #[test]
    fn test_get_set_rights() {
        let mut state = PkeyState::new();
        let pkey = do_pkey_alloc(&mut state, 0, 0).unwrap();

        let rights = state.get_rights(pkey as u32).unwrap();
        assert!(rights.is_empty());

        let new_rights = PkeyRights::from_raw(PkeyRights::PKEY_DISABLE_WRITE).unwrap();
        state.set_rights(pkey as u32, new_rights).unwrap();

        let got = state.get_rights(pkey as u32).unwrap();
        assert!(got.is_write_disabled());
    }

    #[test]
    fn test_get_rights_unallocated() {
        let state = PkeyState::new();
        assert_eq!(state.get_rights(5).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn test_sys_pkey_alloc() {
        let mut state = PkeyState::new();
        let result = sys_pkey_alloc(&mut state, 0, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sys_pkey_free() {
        let mut state = PkeyState::new();
        let k = sys_pkey_alloc(&mut state, 0, 0).unwrap();
        assert!(sys_pkey_free(&mut state, k as u64).is_ok());
    }

    #[test]
    fn test_pkey_mprotect_args_validate_overflow() {
        let args = PkeyMprotectArgs {
            addr: u64::MAX - 0xFFF,
            len: 0x2000,
            prot: PROT_READ,
            pkey: 0,
        };
        assert_eq!(args.validate().unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn test_pkey_mprotect_args_validate_kernel_space() {
        let args = PkeyMprotectArgs {
            addr: 0x0000_7FFF_FFFF_F000,
            len: 0x2000,
            prot: PROT_READ,
            pkey: 0,
        };
        assert_eq!(args.validate().unwrap_err(), Error::InvalidArgument);
    }
}
