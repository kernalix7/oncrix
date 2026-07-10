// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel handler for the anonymous, private flavour of `SYS_MMAP`.
//!
//! Phase-14 scope: only `addr == NULL`, `flags == MAP_ANONYMOUS|MAP_PRIVATE`,
//! `fd == -1`, `off == 0` is supported. File-backed mappings, `MAP_FIXED`,
//! shared mappings, and explicit-hint mappings all return `-EINVAL`.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/functions/mmap.html`.
//!
//! The actual page-table work lives in
//! [`oncrix_mm::address_space::UserAddressSpace::mmap_anonymous`]; this
//! module is a thin SYSCALL adapter that validates inputs, looks up
//! the running thread, and performs the post-allocation `PD_0_1G[3]`
//! install so the calling process sees the new mapping immediately
//! (the scheduler keeps it in sync on every subsequent context switch).

use oncrix_mm::address_space::USER_MMAP_END;

/// `MAP_PRIVATE` — Linux/POSIX flag value (mutually exclusive with `MAP_SHARED`).
const MAP_PRIVATE: u64 = 0x02;
/// `MAP_ANONYMOUS` — Linux flag value (POSIX equivalent: anonymous backing).
const MAP_ANONYMOUS: u64 = 0x20;

/// Kernel handler for `SYS_MMAP` (Linux number 9), anonymous private subset.
///
/// Accepts only the fully unconstrained, anonymous, private mapping form:
/// - `addr` must be `0` (no `MAP_FIXED` support).
/// - `flags` must include both `MAP_ANONYMOUS` and `MAP_PRIVATE`.
/// - `fd` must be `-1` (no file-backed mapping).
/// - `len` must be non-zero and the resulting mapping must fit in the
///   per-process anonymous-mmap window.
///
/// On success returns the user VA of the first allocated page (always
/// inside `[USER_MMAP_BASE, USER_MMAP_END)`). On failure returns a
/// negative errno (`-EINVAL`, `-ENOMEM`).
///
/// `prot` is forwarded to
/// [`oncrix_mm::address_space::UserAddressSpace::mmap_anonymous`] which
/// translates POSIX `PROT_*` bits into PTE flags.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path with single-CPU,
/// interrupts-off invariants.
pub unsafe fn sys_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) -> i64 {
    // Reject MAP_FIXED-style hint (we always pick the address).
    if addr != 0 {
        return -22; // EINVAL
    }
    // Anonymous + private subset only.
    if flags & MAP_ANONYMOUS == 0 || flags & MAP_PRIVATE == 0 {
        return -22; // EINVAL
    }
    // File-backed mappings not supported in this phase.
    if fd as i64 != -1 {
        return -22; // EINVAL
    }
    // Anonymous mappings must use offset 0.
    if off != 0 {
        return -22; // EINVAL
    }
    if len == 0 {
        return -22; // EINVAL
    }
    // Reject obviously too-large requests up front (the per-call cap
    // is also enforced inside `mmap_anonymous`, but doing it here
    // prevents touching the allocator on a guaranteed failure).
    if len > USER_MMAP_END {
        return -12; // ENOMEM
    }

    // Run the allocation against the current thread's UserAddressSpace.
    //
    // SAFETY: single-CPU SYSCALL context guarantees exclusive access
    // to the current thread, the frame allocator, and PD_0_1G[3].
    unsafe {
        let alloc = crate::frame_alloc::frame_alloc();
        let thread = match crate::current::current_thread_mut() {
            Some(t) => t,
            None => return -22, // EINVAL — no current thread
        };
        let uas = match thread.user_address_space.as_mut() {
            Some(u) => u,
            None => return -22, // EINVAL — no user address space
        };
        let va = match uas.mmap_anonymous(alloc, len as usize, prot as u32) {
            Ok(va) => va,
            Err(oncrix_lib::Error::OutOfMemory) => return -12, // ENOMEM
            Err(_) => return -22,                              // EINVAL
        };
        // Install the (possibly newly created) mmap PT into PD_0_1G[3]
        // for the current process so the user code can touch the new
        // pages on the next instruction without waiting for a context
        // switch.
        let pt_phys = uas.mmap_pt_phys().map(|p| p.as_u64());
        crate::arch::init::install_user_mmap_pt(pt_phys);
        va as i64
    }
}
