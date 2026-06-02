// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `getrandom(2)` — fill a user-space buffer with pseudo-random bytes.
//!
//! # Design
//!
//! A kernel-global xorshift64 state (`RNG_STATE`) is seeded with a
//! compile-time nonzero constant and mixed with the PIT tick counter on
//! every call for additional variation.  The xorshift64 sequence
//! (`x ^= x << 13; x ^= x >> 7; x ^= x << 17`) has a period of
//! 2^64 − 1 and is fast enough for the syscall hot path.
//!
//! Flags `GRND_NONBLOCK` (1) and `GRND_RANDOM` (2) are accepted and
//! silently ignored; ONCRIX does not distinguish blocking and
//! non-blocking pools at this stage.
//!
//! # POSIX / Linux reference
//!
//! - Linux `getrandom(2)` — `GRND_NONBLOCK`, `GRND_RANDOM` semantics.
//! - SYS_GETRANDOM = 318 (x86-64 Linux ABI).

use oncrix_hal::timer::Timer;

// ── PRNG state ───────────────────────────────────────────────────────────────

/// Initial seed — must be nonzero for xorshift64.
const RNG_SEED: u64 = 0xDEAD_BEEF_CAFE_1337;

/// Kernel-global xorshift64 state.
///
/// # Safety
///
/// Mutated only on the single-CPU SYSCALL dispatch path.  SYSCALL entry
/// clears IF via FMASK so no timer IRQ can interleave; there are no
/// concurrent writers.
static mut RNG_STATE: u64 = RNG_SEED;

/// Advance the xorshift64 state by one step and return the new value.
///
/// # Safety
///
/// Must only be called from the single-CPU SYSCALL dispatch path (same
/// guarantee as [`RNG_STATE`]).
#[inline]
unsafe fn xorshift64_next() -> u64 {
    // SAFETY: single-CPU SYSCALL path; see RNG_STATE module-level note.
    let x = unsafe {
        let p = &raw mut RNG_STATE;
        &mut *p
    };
    *x ^= *x << 13;
    *x ^= *x >> 7;
    *x ^= *x << 17;
    *x
}

// ── Syscall handler ──────────────────────────────────────────────────────────

/// `getrandom(buf, buflen, flags)` — fill `buf[..buflen]` with pseudo-random
/// bytes and return the number of bytes written.
///
/// # Safety
///
/// Must be called only from the x86-64 SYSCALL dispatch path.  `buf_ptr`
/// must be a user-space pointer supplied by the calling process; it is
/// validated before any write.
///
/// # Errors
///
/// Returns `-14` (`EFAULT`) when `buf_ptr` is NULL or falls within the
/// kernel canonical-address range (`>= 0xFFFF_8000_0000_0000`).
pub unsafe fn sys_getrandom(buf_ptr: u64, buflen: u64, _flags: u64) -> i64 {
    // ── Validate user pointer ────────────────────────────────────────
    if buf_ptr == 0 || buf_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }

    let len = buflen as usize;
    if len == 0 {
        return 0;
    }

    // ── Mix in PIT tick counter for extra variation ──────────────────
    //
    // SAFETY: single-CPU SYSCALL dispatch path; PIT_TIMER has no
    // concurrent mutation (timer IRQ runs with IF=0, SYSCALL entry clears
    // IF via FMASK).
    let ticks = unsafe {
        let pit_ptr = &raw const crate::arch::x86_64::init::PIT_TIMER;
        (*pit_ptr).current_ticks()
    };

    // SAFETY: single-CPU path; see RNG_STATE note above.
    unsafe {
        let p = &raw mut RNG_STATE;
        *p ^= ticks.wrapping_mul(0x9E37_79B9_7F4A_7C15);
        // Ensure nonzero after mix.
        if *p == 0 {
            *p = RNG_SEED;
        }
    }

    // ── Fill user buffer word-by-word ────────────────────────────────
    let dst = buf_ptr as *mut u8;
    let mut written = 0usize;

    // Full 8-byte words.
    while written + 8 <= len {
        // SAFETY: single-CPU path; xorshift64_next only touches RNG_STATE.
        let word = unsafe { xorshift64_next() };
        let bytes = word.to_le_bytes();
        let mut i = 0usize;
        while i < 8 {
            // SAFETY: dst points into validated user space; offset is within
            // [0, len) which the EFAULT check above guarantees is accessible.
            unsafe { dst.add(written + i).write_volatile(bytes[i]) };
            i += 1;
        }
        written += 8;
    }

    // Remaining bytes (0–7).
    if written < len {
        // SAFETY: same as above.
        let word = unsafe { xorshift64_next() };
        let bytes = word.to_le_bytes();
        let mut i = 0usize;
        while written < len {
            // SAFETY: offset within validated range.
            unsafe { dst.add(written).write_volatile(bytes[i]) };
            written += 1;
            i += 1;
        }
    }

    written as i64
}
