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
        // Span-verify the exact 8-byte i64 write against the user's
        // backed window — a base-only guard would accept the
        // non-canonical hole, sub-USER_SPACE_START addresses, and a
        // near-boundary write straddling into the kernel half.
        if crate::uaccess::verify_user_access(tloc, 8, true).is_err() {
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
    // Span-verify the full 16-byte timespec write (two i64 fields)
    // against the user's backed window.
    if crate::uaccess::verify_user_access(ts_ptr, 16, true).is_err() {
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
    // Span-verify the 16-byte timespec read (two i64 fields).
    if crate::uaccess::verify_user_access(req_ptr, 16, false).is_err() {
        return -14; // EFAULT
    }
    // `rem` is NULL-optional; when present it is a 16-byte write target.
    if rem_ptr != 0 && crate::uaccess::verify_user_access(rem_ptr, 16, true).is_err() {
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

    // Span-verify the 16-byte timespec read (two i64 fields).
    if crate::uaccess::verify_user_access(request, 16, false).is_err() {
        return -14; // EFAULT
    }
    // `remain` is only consulted in relative mode, but validate it
    // unconditionally when non-null so a bogus pointer is caught early.
    // It is a 16-byte write target.
    if remain != 0 && crate::uaccess::verify_user_access(remain, 16, true).is_err() {
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

// ── gettimeofday / clock_getres / settimeofday ────────────────────

/// `gettimeofday(tv, tz)` — write the current time as `struct timeval`
/// (`{tv_sec: i64, tv_usec: i64}`) to `tv_ptr`, and optionally zero-fill
/// the obsolete `struct timezone` (`{tz_minuteswest: i32, tz_dsttime: i32}`)
/// at `tz_ptr`.
///
/// `tv_ptr` may be null — the call still succeeds (the caller may only want
/// timezone handling, or may just be testing the syscall).  `tz_ptr` is
/// always optional; when non-null it is zero-filled because timezone support
/// is obsolete per POSIX.1-2024.
///
/// Both pointers, when non-null, must be user-canonical
/// (< `0xFFFF_8000_0000_0000`); a kernel-space address returns `-EFAULT` (-14).
///
/// POSIX.1-2024 reference: `functions/gettimeofday.html` (obsolescent).
/// Both clocks map onto the PIT since-boot counter — no RTC is present.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path (interrupts
/// off via FMASK); no concurrent mutation of `PIT_TIMER` is possible.
pub unsafe fn sys_gettimeofday(tv_ptr: u64, tz_ptr: u64) -> i64 {
    // tv_ptr is NULL-optional; when present it is a 16-byte timeval
    // write target (two i64 fields). Span-verify the exact write.
    if tv_ptr != 0 && crate::uaccess::verify_user_access(tv_ptr, 16, true).is_err() {
        return -14; // EFAULT
    }
    // tz_ptr is NULL-optional; when present it is an 8-byte timezone
    // write target (two i32 fields). Span-verify the exact write.
    if tz_ptr != 0 && crate::uaccess::verify_user_access(tz_ptr, 8, true).is_err() {
        return -14; // EFAULT
    }

    if tv_ptr != 0 {
        // SAFETY: see module-level note; current_ticks reads PIT only.
        let ticks = unsafe { current_ticks() };
        let tv_sec = (ticks / TIMER_HZ) as i64;
        // tv_usec = (ticks % TIMER_HZ) * 1_000_000 / TIMER_HZ
        let tv_usec = ((ticks % TIMER_HZ) * 1_000_000 / TIMER_HZ) as i64;

        // SAFETY: tv_ptr is user-canonical; page-fault handler converts
        // unmapped accesses to SIGSEGV without panicking the kernel.
        unsafe {
            let p = tv_ptr as *mut i64;
            p.write_volatile(tv_sec);
            p.add(1).write_volatile(tv_usec);
        }
    }

    if tz_ptr != 0 {
        // struct timezone is two i32 fields (8 bytes total).  The spec marks
        // it obsolete; ONCRIX always returns (0, 0).
        //
        // SAFETY: tz_ptr is user-canonical; two consecutive i32 writes cover
        // the 8-byte struct timezone layout.
        unsafe {
            let p = tz_ptr as *mut i32;
            p.write_volatile(0); // tz_minuteswest
            p.add(1).write_volatile(0); // tz_dsttime
        }
    }

    0
}

/// `settimeofday(tv, tz)` — ONCRIX does not support setting the system clock
/// via this interface; there is no writable RTC source.
///
/// Returns `-1` (`EPERM`) unconditionally.  This is consistent with POSIX
/// behaviour for an unprivileged caller and mirrors what Linux does on
/// systems without a settable clock source.
///
/// `tv_ptr` and `tz_ptr` are ignored; no pointer dereferences are performed.
///
/// POSIX.1-2024 reference: `functions/settimeofday.html`.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.
pub unsafe fn sys_settimeofday(_tv_ptr: u64, _tz_ptr: u64) -> i64 {
    -1 // EPERM — no settable clock source
}

/// `clock_getres(clk_id, res)` — query the resolution of a clock.
///
/// Supported clock IDs: `CLOCK_REALTIME` (0) and `CLOCK_MONOTONIC` (1).
/// Both share the 100 Hz PIT, giving a resolution of 10 ms
/// (10_000_000 ns).  `res_ptr` may be null when the caller only wants to
/// validate `clk_id`.
///
/// Returns `0` on success, `-22` (`EINVAL`) for an unsupported clock,
/// `-14` (`EFAULT`) for a bogus non-null `res_ptr`.
///
/// POSIX.1-2024 reference: `functions/clock_getres.html`.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path (same
/// invariant as the rest of this module).
pub unsafe fn sys_clock_getres(clk_id: u32, res_ptr: u64) -> i64 {
    // Only CLOCK_REALTIME (0) and CLOCK_MONOTONIC (1) are backed by the PIT.
    if clk_id > 1 {
        return -22; // EINVAL
    }
    if res_ptr != 0 {
        // Span-verify the full 16-byte timespec write (two i64 fields).
        if crate::uaccess::verify_user_access(res_ptr, 16, true).is_err() {
            return -14; // EFAULT
        }
        // PIT resolution: 1/100 s = 10 ms = 10_000_000 ns.
        //
        // SAFETY: res_ptr is user-canonical; page-fault handler converts
        // unmapped writes to SIGSEGV without panicking the kernel.
        unsafe {
            let p = res_ptr as *mut i64;
            p.write_volatile(0); // tv_sec  = 0
            p.add(1).write_volatile(10_000_000); // tv_nsec = 10 ms
        }
    }
    0
}

// ── clock_settime / adjtimex / clock_adjtime ──────────────────────

/// `struct timex` `modes` field: any bit set requests a clock adjustment.
///
/// Linux defines the per-field modify flags `ADJ_OFFSET` (0x0001) ..
/// `ADJ_TICK` (0x4000), plus `ADJ_OFFSET_SS_READ` etc. A non-zero `modes`
/// always indicates the caller wants to *change* something; `modes == 0`
/// is a pure read-only query of the current clock state. We therefore gate
/// on `modes != 0` rather than enumerating individual bits, which is both
/// forward-compatible and fail-closed for any unknown adjust bit.
const ADJ_MODES_QUERY_ONLY: u32 = 0;

/// Effective capability set of the caller, for time-adjustment gating.
///
/// The SYSCALL dispatch path does not yet thread a per-task capability set
/// into the time syscalls (the scheduler tracks no `CapSet`, and there is
/// no global current-task credential accessor reachable here). Until that
/// plumbing exists this returns an **empty** set, which is fail-closed: any
/// caller requesting a clock adjustment is treated as lacking `CAP_SYS_TIME`
/// and denied with `EPERM`. A pure query (`modes == 0`) never consults this.
///
/// # SECURITY
///
/// When the dispatch site (`arch/x86_64/syscall_entry.rs`, owned by the
/// syscall-api team) is extended to thread the calling thread's effective
/// `CapSet` through, replace this with that real set and check
/// `caps.has(capability::CAP_SYS_TIME)`. Returning a non-empty set here
/// without that wiring would silently grant time-adjust privilege to every
/// caller — keep this empty until the real set is available.
fn caller_effective_caps() -> crate::capability::CapSet {
    crate::capability::CapSet::EMPTY
}

/// Returns `Ok(())` if the caller may perform a clock adjustment described
/// by `modes`, else `Err(())` (mapped to `EPERM` by the caller).
///
/// A `modes` of zero is a read-only query and is always permitted. Any
/// non-zero `modes` requires `CAP_SYS_TIME` in the caller's effective set;
/// with the current fail-closed [`caller_effective_caps`] that means every
/// adjustment is denied.
fn adjust_permitted(modes: u32) -> core::result::Result<(), ()> {
    if modes == ADJ_MODES_QUERY_ONLY {
        return Ok(());
    }
    if caller_effective_caps().has(crate::capability::CAP_SYS_TIME) {
        Ok(())
    } else {
        Err(())
    }
}

/// `clock_settime(clk_id, tp)` — attempt to set a POSIX clock.
///
/// ONCRIX has no settable clock source.  The syscall validates both
/// arguments for correctness and always returns `-EPERM` (-1) for a
/// recognised clock ID, matching the behaviour of `settimeofday(2)` on
/// this platform.
///
/// Validation order (mirrors POSIX.1-2024 `clock_settime(3p)`):
/// 1. `clk_id` — only `CLOCK_REALTIME` (0) and `CLOCK_MONOTONIC` (1) are
///    known; any other value returns `-EINVAL` (-22).
/// 2. `CLOCK_MONOTONIC` (1) is non-settable by definition — setting it
///    returns `-EINVAL` (-22) before any pointer access (POSIX: a monotonic
///    clock cannot be set, distinct from "no settable source").
/// 3. `tp_ptr` — must be non-null and below the kernel/user split
///    (`0xFFFF_8000_0000_0000`); otherwise `-EFAULT` (-14).
/// 4. All checks pass → `-EPERM` (-1): the (REALTIME) clock exists but ONCRIX
///    has no settable source.
///
/// POSIX.1-2024 reference: `functions/clock_settime.html`.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.  `tp_ptr` is
/// validated user-canonical before any access attempt; the kernel page-fault
/// handler converts an unmapped user address to `SIGSEGV` without panicking.
pub unsafe fn sys_clock_settime(clk_id: u32, tp_ptr: u64) -> i64 {
    // Only CLOCK_REALTIME (0) and CLOCK_MONOTONIC (1) are recognised.
    if clk_id > 1 {
        return -22; // EINVAL
    }
    // CLOCK_MONOTONIC (1) is non-settable by definition — reject before any
    // pointer access. (REALTIME falls through to the EPERM "no source" path.)
    const CLOCK_MONOTONIC: u32 = 1;
    if clk_id == CLOCK_MONOTONIC {
        return -22; // EINVAL
    }
    // tp must be a valid user-space pointer (non-null, not kernel-space).
    if tp_ptr == 0 || tp_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    // ONCRIX has no settable clock source — always EPERM for a known clock.
    -1 // EPERM
}

/// `adjtimex(buf)` — query or adjust kernel clock parameters.
///
/// ONCRIX performs no NTP clock discipline.  The syscall reads the `modes`
/// field of the user `struct timex` to decide whether the caller wants a
/// read-only query (`modes == 0`) or an adjustment (`modes != 0`):
///
/// - A query validates the pointer and returns `TIME_OK` (0) — the only
///   state ONCRIX can truthfully report (the clock is free-running).
/// - An adjustment requires `CAP_SYS_TIME`; without it the call returns
///   `-EPERM` (-1) and changes nothing. The current dispatch path threads
///   no capability set in, so [`adjust_permitted`] is fail-closed and every
///   adjustment is denied (see its `# SECURITY` note).
///
/// Returns `0` (`TIME_OK`) on a valid query, `-EFAULT` (-14) for a null /
/// kernel-space / unbacked `buf` pointer, `-EPERM` (-1) for an adjustment
/// the caller is not privileged to make.
///
/// POSIX.1-2024 / Linux reference: `adjtimex(2)`.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.  `buf_ptr` is
/// validated user-canonical before the `modes` field is read; the kernel
/// page-fault handler converts an unmapped user read to `SIGSEGV` without
/// panicking.
pub unsafe fn sys_adjtimex(buf_ptr: u64) -> i64 {
    // Reject null and kernel-space addresses without touching the pointer.
    if buf_ptr == 0 || buf_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    // The `modes` field is the first member of `struct timex` (offset 0,
    // 4 bytes). Span-verify the backed window before reading it.
    if crate::uaccess::verify_user_access(buf_ptr, 4, false).is_err() {
        return -14; // EFAULT
    }
    // SAFETY: pointer validated user-canonical and span-checked above; the
    // page-fault handler converts an unmapped read to SIGSEGV.
    let modes = unsafe { (buf_ptr as *const u32).read_volatile() };

    // Gate any requested adjustment behind CAP_SYS_TIME (fail-closed).
    if adjust_permitted(modes).is_err() {
        return -1; // EPERM
    }
    // Query (or a privileged no-op adjustment): report TIME_OK (0).
    0
}

/// `clock_adjtime(clk_id, buf)` — adjust the time of a specific POSIX clock.
///
/// ONCRIX performs no NTP clock discipline.  Like [`sys_adjtimex`], it reads
/// the `modes` field of the user `struct timex` and only permits an
/// adjustment (`modes != 0`) to a caller holding `CAP_SYS_TIME`; a query
/// (`modes == 0`) is always allowed and reports `TIME_OK` (0). The current
/// dispatch path threads no capability set in, so [`adjust_permitted`] is
/// fail-closed and every adjustment is denied with `-EPERM`.
///
/// `CLOCK_MONOTONIC` (1) is non-settable by definition: any adjustment
/// targeting it returns `-EINVAL` (-22) regardless of privilege. Other
/// `clk_id` values are accepted (a query is harmlessly no-oped) because
/// POSIX leaves probing of unsupported clocks implementation-defined.
///
/// Returns `0` (`TIME_OK`) on a valid query, `-EFAULT` (-14) for a null /
/// kernel-space / unbacked `buf` pointer, `-EINVAL` (-22) for an adjustment
/// of `CLOCK_MONOTONIC`, `-EPERM` (-1) for an adjustment the caller is not
/// privileged to make.
///
/// POSIX.1-2024 / Linux reference: `clock_adjtime(2)`.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.  `buf_ptr` is
/// validated user-canonical before the `modes` field is read; the kernel
/// page-fault handler converts an unmapped user read to `SIGSEGV` without
/// panicking.
pub unsafe fn sys_clock_adjtime(clk_id: u32, buf_ptr: u64) -> i64 {
    // Reject null and kernel-space addresses without touching the pointer.
    if buf_ptr == 0 || buf_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    // The `modes` field is the first member of `struct timex` (offset 0,
    // 4 bytes). Span-verify the backed window before reading it.
    if crate::uaccess::verify_user_access(buf_ptr, 4, false).is_err() {
        return -14; // EFAULT
    }
    // SAFETY: pointer validated user-canonical and span-checked above; the
    // page-fault handler converts an unmapped read to SIGSEGV.
    let modes = unsafe { (buf_ptr as *const u32).read_volatile() };

    // CLOCK_MONOTONIC (1) cannot be set/adjusted — reject any adjustment
    // request against it as invalid (a pure query still succeeds below).
    const CLOCK_MONOTONIC: u32 = 1;
    if modes != ADJ_MODES_QUERY_ONLY && clk_id == CLOCK_MONOTONIC {
        return -22; // EINVAL
    }
    // Gate any requested adjustment behind CAP_SYS_TIME (fail-closed).
    if adjust_permitted(modes).is_err() {
        return -1; // EPERM
    }
    // Query (or a privileged no-op adjustment): report TIME_OK (0).
    0
}
