// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX time-related syscalls backed by the PIT tick counter.
//!
//! ONCRIX has no RTC chip integration yet, so all clocks are
//! "since-boot" rather than since the POSIX epoch. The behavioural
//! contract is otherwise unchanged: `time(2)` returns whole seconds,
//! `clock_gettime(2)` returns a `(seconds, nanoseconds)` pair, and
//! `nanosleep(2)` blocks the calling thread for the requested
//! duration via cooperative `yield_now` polling.
//!
//! POSIX.1-2024 references (susv5):
//! - `time(3p)` — `functions/time.html`
//! - `clock_gettime(3p)` — `functions/clock_gettime.html`
//! - `nanosleep(3p)` — `functions/nanosleep.html`
//! - `clock_nanosleep(3p)` — `functions/clock_nanosleep.html`

use oncrix_hal::timer::Timer;

/// Read the current PIT tick count.
///
/// # Safety
///
/// Single-CPU SYSCALL dispatch path; no concurrent mutation of
/// `PIT_TIMER` is possible.
unsafe fn current_ticks() -> u64 {
    // SAFETY: see fn-level note. `PIT_TIMER` is a `static mut` only
    // touched from the timer IRQ handler (IF=0 interrupt gate) and
    // through this read path during SYSCALL dispatch (also IF=0 from
    // FMASK). No concurrent mutation on a single-CPU build.
    unsafe {
        let pit_ptr = &raw const crate::arch::x86_64::init::PIT_TIMER;
        (*pit_ptr).current_ticks()
    }
}

/// PIT tick frequency in hertz. `init_pic_and_timer` configures
/// divisor 11932 → ~100 Hz.
const TIMER_HZ: u64 = 100;

/// `time(tloc)` — return seconds elapsed since boot.
///
/// If `tloc` is non-zero, also writes the same value to `*tloc`.
/// Diverges from POSIX in that the returned time is since boot, not
/// since the POSIX epoch — the kernel has no RTC source.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU,
/// interrupts effectively disabled).
pub unsafe fn sys_time(tloc: u64) -> i64 {
    // SAFETY: see fn-level note.
    let secs = unsafe { current_ticks() / TIMER_HZ } as i64;
    if tloc != 0 {
        // Reject obviously bogus pointers.
        if tloc >= 0xFFFF_8000_0000_0000 {
            return -14; // EFAULT
        }
        // SAFETY: pointer validated user-canonical above; user page
        // fault handler converts unmapped accesses to SIGSEGV without
        // panicking the kernel.
        unsafe { (tloc as *mut i64).write_volatile(secs) };
    }
    secs
}

/// `clock_gettime(clk_id, tp)` — write the current time of `clk_id`
/// into the user-space `Timespec` at `ts_ptr`.
///
/// Supported clocks: `CLOCK_REALTIME` (0) and `CLOCK_MONOTONIC` (1).
/// Both are backed by the same PIT tick counter — there is no RTC,
/// so REALTIME == MONOTONIC == "since boot".
///
/// Returns 0 on success, `-EINVAL` (-22) for unsupported clock IDs,
/// `-EFAULT` (-14) for bogus user pointers.
///
/// # Safety
///
/// Same single-CPU SYSCALL invariant as the rest of this module.
pub unsafe fn sys_clock_gettime(clk_id: u32, ts_ptr: u64) -> i64 {
    // CLOCK_REALTIME = 0, CLOCK_MONOTONIC = 1; reject anything else.
    if clk_id > 1 {
        return -22; // EINVAL
    }
    if ts_ptr == 0 || ts_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    // SAFETY: see module-level note.
    let ticks = unsafe { current_ticks() };
    let secs = (ticks / TIMER_HZ) as i64;
    let frac_ticks = ticks % TIMER_HZ;
    // Each tick is 1 / TIMER_HZ seconds; convert to ns.
    let nsec = (frac_ticks * 1_000_000_000 / TIMER_HZ) as i64;

    // SAFETY: pointer validated above; user page-fault handler
    // converts unmapped writes to SIGSEGV.
    unsafe {
        let p = ts_ptr as *mut i64;
        p.write_volatile(secs);
        p.add(1).write_volatile(nsec);
    }
    0
}

/// `nanosleep(req, rem)` — block the current thread until at least
/// `*req` seconds + nanoseconds have elapsed.
///
/// Implementation polls `current_ticks` in a `yield_now` loop. There
/// is no signal-interrupt mechanism yet, so the call always sleeps
/// the full duration and returns 0; `*rem` (if non-null) is written
/// `(0, 0)`.
///
/// # Safety
///
/// Same single-CPU SYSCALL invariant. `yield_now` is an unsafe
/// scheduler hand-off that requires interrupts off and exclusive
/// access to the scheduler — both held by the caller of this fn.
pub unsafe fn sys_nanosleep(req_ptr: u64, rem_ptr: u64) -> i64 {
    if req_ptr == 0 || req_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    if rem_ptr != 0 && rem_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }

    // SAFETY: pointer validated above.
    let (req_secs, req_nsec) = unsafe {
        let p = req_ptr as *const i64;
        (p.read_volatile(), p.add(1).read_volatile())
    };

    if req_secs < 0 || !(0..1_000_000_000).contains(&req_nsec) {
        return -22; // EINVAL
    }

    // ceil(seconds * TIMER_HZ + nanos * TIMER_HZ / 1e9) — round up so
    // a 1-tick request actually waits at least one full tick.
    let mut delta = (req_secs as u64).saturating_mul(TIMER_HZ);
    let nano_ticks = (req_nsec as u64 * TIMER_HZ).div_ceil(1_000_000_000);
    delta = delta.saturating_add(nano_ticks);
    if delta == 0 {
        // Zero-duration sleep — POSIX permits returning immediately.
        if rem_ptr != 0 {
            // SAFETY: pointer validated above.
            unsafe {
                let p = rem_ptr as *mut i64;
                p.write_volatile(0);
                p.add(1).write_volatile(0);
            }
        }
        return 0;
    }

    // SAFETY: see module-level note.
    let deadline = unsafe { current_ticks() }.saturating_add(delta);
    while unsafe { current_ticks() } < deadline {
        // SYSCALL entry clears IF (FMASK), so timer IRQs cannot fire
        // while the syscall is running — which means `current_ticks()`
        // would never advance and this loop would spin forever. Enable
        // interrupts briefly, halt until the next IRQ (which is at
        // most 10 ms away on the 100 Hz PIT), then disable again
        // before re-reading the tick counter. This is the standard
        // x86 idle-with-timer pattern.
        //
        // SAFETY: We are running on the syscall path with no live
        // borrows of any single-CPU-protected data; allowing interrupts
        // for the duration of `hlt` is safe — the timer IRQ handler
        // saves/restores its own state. After `hlt` returns we
        // immediately `cli` so the rest of the loop body re-enters
        // the syscall's IF=0 contract.
        unsafe {
            core::arch::asm!("sti; hlt; cli", options(nomem, nostack));
        }
    }

    if rem_ptr != 0 {
        // SAFETY: pointer validated above.
        unsafe {
            let p = rem_ptr as *mut i64;
            p.write_volatile(0);
            p.add(1).write_volatile(0);
        }
    }
    0
}

/// `TIMER_ABSTIME` flag for `clock_nanosleep(2)`: interpret the request
/// as an absolute deadline on the chosen clock rather than a relative
/// duration.
const TIMER_ABSTIME: i32 = 1;

/// Convert a `(secs, nsec)` timespec to an absolute PIT-tick deadline,
/// rounding the nanosecond fraction up so a sub-tick request still waits
/// at least one full tick.
fn timespec_to_ticks(secs: i64, nsec: i64) -> u64 {
    let whole = (secs as u64).saturating_mul(TIMER_HZ);
    let frac = (nsec as u64 * TIMER_HZ).div_ceil(1_000_000_000);
    whole.saturating_add(frac)
}

/// Busy-idle until the global PIT tick counter reaches `deadline`.
///
/// Returns immediately if the deadline is already in the past. Uses the
/// `sti; hlt; cli` idle pattern so the timer IRQ can advance the tick
/// counter while the syscall is otherwise running with `IF=0`.
///
/// # Safety
///
/// Must run on the SYSCALL dispatch path with no live borrows of any
/// single-CPU-protected data — identical contract to [`sys_nanosleep`]'s
/// inner loop, from which this is factored out.
unsafe fn sleep_until_ticks(deadline: u64) {
    // SAFETY: see module-level note; current_ticks reads PIT only.
    while unsafe { current_ticks() } < deadline {
        // SAFETY: see [`sys_nanosleep`] — brief interrupt window around
        // `hlt` lets the 100 Hz timer advance the counter, then `cli`
        // restores the syscall's IF=0 contract before the next read.
        unsafe {
            core::arch::asm!("sti; hlt; cli", options(nomem, nostack));
        }
    }
}

/// `clock_nanosleep(clockid, flags, request, remain)` — high-resolution
/// sleep against a specified clock, relative or absolute.
///
/// Supported clocks: `CLOCK_REALTIME` (0) and `CLOCK_MONOTONIC` (1) —
/// both back onto the same since-boot PIT counter (no RTC). `flags` may
/// be `0` (relative, like `nanosleep`) or `TIMER_ABSTIME` (1, sleep
/// until the absolute clock value `*request`).
///
/// Relative mode sleeps for the `*request` duration; on normal
/// completion `*remain` (if non-null) is written `(0, 0)` since there is
/// no signal-interrupt path yet. In absolute mode `remain` is ignored
/// (POSIX: it is unused for `TIMER_ABSTIME`); an already-past deadline
/// returns `0` immediately.
///
/// Returns `0` on completion, `-22` (`EINVAL`) for a bad clock, unknown
/// flag bits, or an out-of-range `tv_nsec`, `-14` (`EFAULT`) for a bad
/// `request`/`remain` pointer.
///
/// # Safety
///
/// Same single-CPU SYSCALL invariant as the rest of this module; the
/// pointers are validated user-canonical before any dereference.
pub unsafe fn sys_clock_nanosleep(clockid: u32, flags: i32, request: u64, remain: u64) -> i64 {
    // CLOCK_REALTIME = 0, CLOCK_MONOTONIC = 1; reject anything else.
    if clockid > 1 {
        return -22; // EINVAL
    }
    // Only TIMER_ABSTIME (or none) is defined.
    if flags & !TIMER_ABSTIME != 0 {
        return -22; // EINVAL
    }
    let absolute = flags & TIMER_ABSTIME != 0;

    if request == 0 || request >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    // `remain` is only consulted in relative mode, but validate it
    // unconditionally when non-null so a bogus pointer is caught early.
    if remain != 0 && remain >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }

    // SAFETY: request validated user-canonical above.
    let (secs, nsec) = unsafe {
        let p = request as *const i64;
        (p.read_volatile(), p.add(1).read_volatile())
    };
    if secs < 0 || !(0..1_000_000_000).contains(&nsec) {
        return -22; // EINVAL
    }

    let want_ticks = timespec_to_ticks(secs, nsec);

    if absolute {
        // Absolute: the request IS the deadline (in since-boot ticks).
        // SAFETY: see module-level note.
        let now = unsafe { current_ticks() };
        if want_ticks > now {
            // SAFETY: SYSCALL path, no live borrows — see helper docs.
            unsafe { sleep_until_ticks(want_ticks) };
        }
        // remain is unused for TIMER_ABSTIME (POSIX); do not write it.
        return 0;
    }

    // Relative: sleep `want_ticks` from now.
    if want_ticks == 0 {
        if remain != 0 {
            // SAFETY: remain validated above.
            unsafe {
                let p = remain as *mut i64;
                p.write_volatile(0);
                p.add(1).write_volatile(0);
            }
        }
        return 0;
    }
    // SAFETY: see module-level note.
    let deadline = unsafe { current_ticks() }.saturating_add(want_ticks);
    // SAFETY: SYSCALL path, no live borrows — see helper docs.
    unsafe { sleep_until_ticks(deadline) };

    if remain != 0 {
        // SAFETY: remain validated above; full sleep completed so the
        // remaining time is zero (no early signal return path yet).
        unsafe {
            let p = remain as *mut i64;
            p.write_volatile(0);
            p.add(1).write_volatile(0);
        }
    }
    0
}
