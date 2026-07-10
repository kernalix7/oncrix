// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX scheduling-priority syscalls backed by the per-thread
//! [`Priority`](oncrix_process::thread::Priority).
//!
//! ONCRIX's scheduler is round-robin and does not yet honour priority
//! when picking the next thread, but the priority is real per-thread
//! state: these handlers read and write the current thread's stored
//! [`Priority`] so userspace `nice`/`renice` observe consistent values
//! and a future priority-aware scheduler can consume them unchanged.
//!
//! # Nice mapping
//!
//! POSIX nice is `[-20, 19]` (lower = more favourable). The kernel
//! priority axis is inverted (`0` = highest, `255` = lowest). The
//! conversion lives in [`Priority::from_nice`] / [`Priority::to_nice`]:
//! `level = (nice + 20) * 255 / 39`. Nice `0` lands near
//! [`Priority::NORMAL`].
//!
//! # `which` / `who`
//!
//! POSIX `getpriority`/`setpriority` take a `which` selector
//! (`PRIO_PROCESS`/`PRIO_PGRP`/`PRIO_USER`) and a `who` target. ONCRIX
//! has no process-group or per-user scheduling yet, so these handlers
//! only act on the **current thread** and treat `who == 0` (or any
//! value with `which == PRIO_PROCESS`) as "the caller". `which` and
//! `who` are otherwise accepted and ignored; this is documented
//! divergence from POSIX pending process-group support.
//!
//! POSIX.1-2024 references (susv5):
//! - `getpriority(3p)` — `functions/getpriority.html`
//! - `setpriority(3p)` — `functions/setpriority.html`
//! - `nice(3p)` — `functions/nice.html`

use crate::capability::{CAP_SYS_NICE, CapSet};
use crate::current::{current_pid, current_thread_mut, yield_now};
use oncrix_hal::timer::Timer;
use oncrix_process::pid::Pid;
use oncrix_process::signal::{
    SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK, Signal, SignalAction, SignalMask,
};
use oncrix_process::thread::{Priority, SchedPolicy};

/// `which` selector: act on a process (the only mode ONCRIX supports).
const PRIO_PROCESS: i64 = 0;
/// `which` selector: act on a process group (accepted, treated as self).
const _PRIO_PGRP: i64 = 1;
/// `which` selector: act on a user (accepted, treated as self).
const _PRIO_USER: i64 = 2;

/// Lowest (most favourable) POSIX nice value.
const NICE_MIN: i32 = -20;
/// Highest (least favourable) POSIX nice value.
const NICE_MAX: i32 = 19;

/// `getpriority(which, who)` — return the current thread's nice value.
///
/// Returns the nice value in `[-20, 19]`. POSIX returns nice values
/// offset-free (unlike the raw `getpriority(2)` ABI that the C library
/// re-biases); the libc wrapper is responsible for any `errno`
/// disambiguation. `which`/`who` are accepted and ignored beyond
/// selecting the calling thread (see module docs).
///
/// Returns `-3` (`ESRCH`) if there is no current thread.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path with
/// interrupts effectively disabled, so the mutable scheduler borrow
/// taken via [`current_thread_mut`] is exclusive.
pub unsafe fn sys_getpriority(_which: i64, _who: i64) -> i64 {
    // SAFETY: SYSCALL dispatch context (single-CPU, IF=0) guarantees no
    // concurrent scheduler mutation for the lifetime of this borrow.
    let prio = unsafe { current_thread_mut() }.map(|t| t.priority());
    match prio {
        Some(p) => p.to_nice() as i64,
        None => -3, // ESRCH
    }
}

/// `setpriority(which, who, prio)` — set the current thread's nice value.
///
/// `prio` is clamped to `[-20, 19]` and converted to a kernel
/// [`Priority`]. `which`/`who` are accepted and ignored beyond selecting
/// the calling thread (see module docs).
///
/// Returns `0` on success, `-3` (`ESRCH`) if there is no current thread.
///
/// # Safety
///
/// See [`sys_getpriority`].
pub unsafe fn sys_setpriority(which: i64, who: i64, prio: i64) -> i64 {
    // SECURITY: caps fail closed to EMPTY — lowering nice is denied for all
    // callers until syscall_entry.rs threads the real per-thread effective
    // CapSet into `sys_setpriority_checked`.
    // SAFETY: forwarded unchanged under the same SYSCALL dispatch contract.
    unsafe { sys_setpriority_checked(which, who, prio, caller_effective_caps()) }
}

/// Capability-checked core of [`sys_setpriority`].
///
/// Lowering the calling thread's nice (the privilege-raising direction)
/// requires [`CAP_SYS_NICE`] in `caller_caps`; otherwise `-1` (`EPERM`) is
/// returned and the priority is left unchanged. Raising or keeping nice is
/// always permitted.
///
/// # Safety
///
/// See [`sys_getpriority`].
unsafe fn sys_setpriority_checked(which: i64, _who: i64, prio: i64, caller_caps: CapSet) -> i64 {
    // Only PRIO_PROCESS is meaningfully distinct today; PGRP/USER are
    // accepted as aliases for "current thread". Reject unknown selectors.
    if which != PRIO_PROCESS && which != _PRIO_PGRP && which != _PRIO_USER {
        return -22; // EINVAL
    }
    let nice = clamp_nice(prio as i32);
    // SAFETY: SYSCALL dispatch context — exclusive scheduler access.
    match unsafe { current_thread_mut() } {
        Some(t) => {
            let cur_nice = t.priority().to_nice();
            // Gate the privilege-raising direction (nice lowered) on
            // CAP_SYS_NICE; the policy is unchanged here so pass the current
            // policy to the shared authorizer.
            if let Err(e) = authorize_sched_change(caller_caps, t.policy(), cur_nice, nice) {
                return e;
            }
            t.set_priority(Priority::from_nice(nice));
            0
        }
        None => -3, // ESRCH
    }
}

/// `nice(inc)` — add `inc` to the current thread's nice value.
///
/// Reads the current nice value, adds `inc`, clamps the result to
/// `[-20, 19]`, stores it, and returns the new nice value. Unlike the
/// historical `nice(2)` (which returns `-1`/`errno` on the boundary),
/// ONCRIX returns the new clamped nice directly; the libc wrapper maps
/// it to the POSIX return contract.
///
/// Returns the new nice value, or `-3` (`ESRCH`) if there is no current
/// thread. Because a valid nice value can be `-3`, the libc wrapper must
/// not treat `-3` as an error without also checking thread presence;
/// kernel-internal callers can rely on `None`-vs-`Some` instead.
///
/// # Safety
///
/// See [`sys_getpriority`].
pub unsafe fn sys_nice(inc: i64) -> i64 {
    // SECURITY: caps fail closed to EMPTY — a negative `inc` (lowering nice)
    // is denied for all callers until syscall_entry.rs threads the real
    // per-thread effective CapSet into `sys_nice_checked`.
    // SAFETY: forwarded unchanged under the same SYSCALL dispatch contract.
    unsafe { sys_nice_checked(inc, caller_effective_caps()) }
}

/// Capability-checked core of [`sys_nice`].
///
/// A negative `inc` lowers nice (the privilege-raising direction) and
/// requires [`CAP_SYS_NICE`] in `caller_caps`; without it `-1` (`EPERM`) is
/// returned and the nice value is left unchanged. A non-negative `inc`
/// (raising nice / yielding favour) is always permitted.
///
/// # Safety
///
/// See [`sys_getpriority`].
unsafe fn sys_nice_checked(inc: i64, caller_caps: CapSet) -> i64 {
    // SAFETY: SYSCALL dispatch context — exclusive scheduler access.
    match unsafe { current_thread_mut() } {
        Some(t) => {
            let cur = t.priority().to_nice();
            let new = clamp_nice(cur.saturating_add(inc as i32));
            // Gate the privilege-raising direction (nice lowered below the
            // current value) on CAP_SYS_NICE; policy is unchanged.
            if let Err(e) = authorize_sched_change(caller_caps, t.policy(), cur, new) {
                return e;
            }
            t.set_priority(Priority::from_nice(new));
            new as i64
        }
        None => -3, // ESRCH
    }
}

/// Clamp a nice value to the POSIX `[-20, 19]` range.
const fn clamp_nice(nice: i32) -> i32 {
    if nice < NICE_MIN {
        NICE_MIN
    } else if nice > NICE_MAX {
        NICE_MAX
    } else {
        nice
    }
}

/// POSIX `EPERM` errno returned when a privileged scheduling change is
/// requested without `CAP_SYS_NICE`.
const EPERM: i64 = -1;

/// Fetch the calling thread's effective capability set for scheduling
/// authorization, **failing closed** to an empty (unprivileged) set.
///
/// The kernel [`Thread`](oncrix_process::thread::Thread) does not yet
/// carry a [`ThreadCapState`](crate::capability::ThreadCapState), so there
/// is no per-thread credential to consult here. Until one is plumbed
/// through, this accessor returns [`CapSet::EMPTY`] so every
/// privilege-raising scheduling request (real-time policy, more-favourable
/// nice/priority) is denied for *all* callers — the safe default for a
/// Ring-0 gate that an unprivileged, attacker-controlled syscall reaches.
///
/// # SECURITY
///
/// This deliberately denies real-time promotion and nice-lowering to every
/// caller, including legitimately privileged ones, rather than leaving the
/// operation open. The out-of-lane dispatcher
/// `crates/kernel/src/arch/x86_64/syscall_entry.rs` (the
/// `SYS_SCHED_SETSCHEDULER`, `SYS_SCHED_SETPARAM`, `SYS_SCHED_SETATTR`,
/// `SYS_SETPRIORITY`, and `SYS_NICE` arms) MUST be updated to read the real
/// per-thread effective `CapSet` and pass it into the `*_checked`
/// entry points below; this accessor is the single place that change lands.
fn caller_effective_caps() -> CapSet {
    // Fail closed: no credential is wired to the kernel Thread yet, so we
    // cannot prove the caller holds CAP_SYS_NICE — treat them as unprivileged.
    CapSet::EMPTY
}

/// Return `true` if applying `requested_nice` to a thread currently at
/// `current_nice` is a privilege-raising change that requires
/// `CAP_SYS_NICE`.
///
/// POSIX nice is `[-20, 19]` with **lower = more favourable**; lowering the
/// value (making the thread more favoured) is the privileged direction.
/// Raising or keeping the nice value is always permitted.
const fn nice_change_needs_privilege(current_nice: i32, requested_nice: i32) -> bool {
    requested_nice < current_nice
}

/// Authorize a scheduling change against the caller's effective caps,
/// **failing closed**.
///
/// Denies (returns `Err(EPERM)`) when the request raises privilege —
/// either selecting a real-time policy (`SCHED_FIFO`/`SCHED_RR`) or
/// lowering nice below `current_nice` — and the caller lacks
/// [`CAP_SYS_NICE`]. A non-real-time policy whose nice is not more
/// favourable than the current value is always allowed (the valid path).
fn authorize_sched_change(
    caller_caps: CapSet,
    requested_policy: SchedPolicy,
    current_nice: i32,
    requested_nice: i32,
) -> Result<(), i64> {
    let wants_realtime = matches!(
        requested_policy,
        SchedPolicy::Fifo | SchedPolicy::RoundRobin
    );
    let wants_favourable = nice_change_needs_privilege(current_nice, requested_nice);
    if (wants_realtime || wants_favourable) && !caller_caps.has(CAP_SYS_NICE) {
        return Err(EPERM);
    }
    Ok(())
}

/// `sched_yield()` — relinquish the CPU to the next runnable thread.
///
/// POSIX `sched_yield(2)` forces the running thread to yield until it
/// again becomes runnable. ONCRIX drives this through the scheduler's
/// cooperative [`yield_now`] path, which performs a single round-robin
/// (priority-aware) switch if another thread is Ready. Always returns
/// `0` (POSIX only specifies failure for unsupported-but-this-is-Base).
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path: interrupts effectively
/// disabled (FMASK clears IF) and no outstanding scheduler borrow, which
/// is exactly what [`yield_now`] requires.
pub unsafe fn sys_sched_yield() -> i64 {
    // SAFETY: SYSCALL dispatch context satisfies yield_now's contract
    // (IF=0 on the single CPU, caller holds no scheduler borrow).
    let _switched = unsafe { yield_now() };
    0
}

/// `sched_getscheduler(pid)` — return the calling thread's policy.
///
/// Returns one of `SCHED_OTHER`/`SCHED_FIFO`/`SCHED_RR` (0/1/2). ONCRIX
/// has no cross-process scheduling control, so `pid == 0` (self) and any
/// other value are both treated as "the calling thread"; documented
/// divergence pending real per-pid lookup.
///
/// Returns `-3` (`ESRCH`) if there is no current thread.
///
/// # Safety
///
/// See [`sys_getpriority`].
pub unsafe fn sys_sched_getscheduler(_pid: i64) -> i64 {
    // SAFETY: SYSCALL dispatch context — exclusive scheduler access.
    match unsafe { current_thread_mut() } {
        Some(t) => t.policy().as_raw() as i64,
        None => -3, // ESRCH
    }
}

/// `sched_setscheduler(pid, policy, param)` — set the policy and (via
/// `param`'s `sched_priority`) the priority of the calling thread.
///
/// `policy` must be a known `SCHED_*` value or `-22` (`EINVAL`) is
/// returned. `param` is the user-space pointer to a `struct sched_param`
/// whose first field is `int sched_priority`; if non-null it is read as
/// the new priority and mapped onto the kernel [`Priority`] axis (higher
/// `sched_priority` ⇒ higher priority ⇒ lower raw level). A null/zero
/// `param` leaves the priority unchanged. As with `getscheduler`, `pid`
/// is treated as the calling thread regardless of value.
///
/// Returns `0` on success, `-22` (`EINVAL`) for a bad policy, `-14`
/// (`EFAULT`) for a non-canonical `param` pointer, `-3` (`ESRCH`) if
/// there is no current thread.
///
/// # Safety
///
/// See [`sys_getpriority`]. `param` is a raw user pointer; we reject
/// non-canonical addresses and rely on the user page-fault handler to
/// turn any unmapped-but-canonical access into a SIGSEGV.
pub unsafe fn sys_sched_setscheduler(pid: i64, policy: i64, param: u64) -> i64 {
    // SECURITY: caps fail closed to EMPTY — selecting SCHED_FIFO/SCHED_RR or
    // raising priority is denied for all callers until syscall_entry.rs
    // threads the real per-thread effective CapSet into
    // `sys_sched_setscheduler_checked`.
    // SAFETY: forwarded unchanged under the same SYSCALL dispatch contract.
    unsafe { sys_sched_setscheduler_checked(pid, policy, param, caller_effective_caps()) }
}

/// Capability-checked core of [`sys_sched_setscheduler`].
///
/// Selecting a real-time policy (`SCHED_FIFO`/`SCHED_RR`) or raising the
/// thread's priority above its current value requires [`CAP_SYS_NICE`] in
/// `caller_caps`; otherwise `-1` (`EPERM`) is returned and neither policy
/// nor priority is changed. Setting `SCHED_OTHER` with an equal-or-lower
/// priority is always permitted.
///
/// # Safety
///
/// See [`sys_sched_setscheduler`].
unsafe fn sys_sched_setscheduler_checked(
    _pid: i64,
    policy: i64,
    param: u64,
    caller_caps: CapSet,
) -> i64 {
    let Some(pol) = SchedPolicy::from_raw(policy as i32) else {
        return -22; // EINVAL
    };

    // Optionally read sched_priority from the param struct.
    let new_priority = if param != 0 {
        // Only the leading 4-byte `int sched_priority` is read; span- and
        // backed-window-validate exactly those bytes (rejects the
        // non-canonical hole, below-user, and unmapped pages).
        if crate::uaccess::verify_user_access(param, 4, false).is_err() {
            return -14; // EFAULT
        }
        // SAFETY: `param`'s leading 4 bytes were validated above. The first
        // field of `struct sched_param` is `int sched_priority`. An unmapped
        // page faults into the user handler (SIGSEGV); we only read 4 bytes.
        let sched_priority = unsafe { core::ptr::read_unaligned(param as *const i32) };
        Some(sched_priority_to_priority(sched_priority))
    } else {
        None
    };

    // SAFETY: SYSCALL dispatch context — exclusive scheduler access.
    match unsafe { current_thread_mut() } {
        Some(t) => {
            // Authorize before mutating: compare on the nice axis (lower nice
            // == more favourable == higher RT priority). A null `param`
            // leaves priority unchanged, so reuse the current nice in that
            // case — only the policy can then raise privilege.
            let cur_nice = t.priority().to_nice();
            let req_nice = new_priority.map_or(cur_nice, |p| p.to_nice());
            if let Err(e) = authorize_sched_change(caller_caps, pol, cur_nice, req_nice) {
                return e;
            }
            t.set_policy(pol);
            if let Some(p) = new_priority {
                t.set_priority(p);
            }
            0
        }
        None => -3, // ESRCH
    }
}

/// `sched_getparam(pid, param)` — write the calling thread's
/// `sched_priority` into the user `struct sched_param`.
///
/// Writes the thread's priority (mapped back to a `sched_priority` in
/// `[0, 99]`) to `*param`. As elsewhere, `pid` is treated as self.
///
/// Returns `0` on success, `-14` (`EFAULT`) for a bad pointer, `-3`
/// (`ESRCH`) if there is no current thread.
///
/// # Safety
///
/// See [`sys_sched_setscheduler`] regarding the `param` pointer.
pub unsafe fn sys_sched_getparam(_pid: i64, param: u64) -> i64 {
    // Only the leading 4-byte `int sched_priority` is written; span- and
    // backed-window-validate exactly those bytes before the write.
    if crate::uaccess::verify_user_access(param, 4, true).is_err() {
        return -14; // EFAULT
    }
    // SAFETY: SYSCALL dispatch context — exclusive scheduler access.
    let prio = match unsafe { current_thread_mut() } {
        Some(t) => t.priority(),
        None => return -3, // ESRCH
    };
    let sched_priority = priority_to_sched_priority(prio);
    // SAFETY: `param`'s leading 4 bytes were validated above. We write the
    // leading `int sched_priority` field only; an unmapped page faults into
    // the user handler (SIGSEGV).
    unsafe { core::ptr::write_unaligned(param as *mut i32, sched_priority) };
    0
}

/// `sched_setparam(pid, param)` — set the calling thread's priority from
/// the user `struct sched_param`'s `sched_priority`.
///
/// Returns `0` on success, `-14` (`EFAULT`) for a bad pointer, `-3`
/// (`ESRCH`) if there is no current thread.
///
/// # Safety
///
/// See [`sys_sched_setscheduler`] regarding the `param` pointer.
pub unsafe fn sys_sched_setparam(pid: i64, param: u64) -> i64 {
    // SECURITY: caps fail closed to EMPTY — raising priority is denied for
    // all callers until syscall_entry.rs threads the real per-thread
    // effective CapSet into `sys_sched_setparam_checked`.
    // SAFETY: forwarded unchanged under the same SYSCALL dispatch contract.
    unsafe { sys_sched_setparam_checked(pid, param, caller_effective_caps()) }
}

/// Capability-checked core of [`sys_sched_setparam`].
///
/// Raising the thread's priority above its current value (the same RT
/// promotion surface as `sched_setscheduler`) requires [`CAP_SYS_NICE`] in
/// `caller_caps`; otherwise `-1` (`EPERM`) is returned and the priority is
/// left unchanged. The policy is not changed by this call.
///
/// # Safety
///
/// See [`sys_sched_setscheduler`] regarding the `param` pointer.
unsafe fn sys_sched_setparam_checked(_pid: i64, param: u64, caller_caps: CapSet) -> i64 {
    // Only the leading 4-byte `int sched_priority` is read; span- and
    // backed-window-validate exactly those bytes before the read.
    if crate::uaccess::verify_user_access(param, 4, false).is_err() {
        return -14; // EFAULT
    }
    // SAFETY: `param`'s leading 4 bytes were validated above; read 4 bytes only.
    let sched_priority = unsafe { core::ptr::read_unaligned(param as *const i32) };
    let prio = sched_priority_to_priority(sched_priority);
    // SAFETY: SYSCALL dispatch context — exclusive scheduler access.
    match unsafe { current_thread_mut() } {
        Some(t) => {
            // Policy unchanged; gate on the priority (nice axis) rising above
            // the current value.
            let cur_nice = t.priority().to_nice();
            if let Err(e) =
                authorize_sched_change(caller_caps, t.policy(), cur_nice, prio.to_nice())
            {
                return e;
            }
            t.set_priority(prio);
            0
        }
        None => -3, // ESRCH
    }
}

/// Map a POSIX real-time `sched_priority` (`[0, 99]`, higher = more
/// favoured) onto the kernel [`Priority`] axis (`0` = highest, `255` =
/// lowest). Clamped to `[0, 99]`, then inverted and scaled so `99 → 0`
/// (HIGHEST) and `0 → ~252` (near IDLE): `level = (99 - sp) * 255 / 99`.
fn sched_priority_to_priority(sp: i32) -> Priority {
    let clamped = sp.clamp(0, 99);
    let level = ((99 - clamped) * 255 / 99) as u8;
    Priority::new(level)
}

/// Inverse of [`sched_priority_to_priority`]: map a kernel [`Priority`]
/// back to a POSIX `sched_priority` in `[0, 99]`.
fn priority_to_sched_priority(p: Priority) -> i32 {
    99 - (p.as_u8() as i32) * 99 / 255
}

/// PIT tick frequency in hertz (clock ticks per second). Matches the
/// divisor configured by `init_pic_and_timer` (~100 Hz) and the
/// `TIMER_HZ` used by the time syscalls. This is also the effective
/// `CLK_TCK` reported through `times(2)`'s `clock_t` units.
const CLK_TCK: u64 = 100;

/// Read the current global PIT tick count (elapsed ticks since boot).
///
/// # Safety
///
/// Single-CPU SYSCALL dispatch path; `PIT_TIMER` is only mutated from
/// the timer IRQ (IF=0 gate) and read here under the same IF=0 FMASK
/// invariant, so there is no concurrent mutation.
unsafe fn global_ticks() -> u64 {
    // SAFETY: see fn-level note.
    unsafe {
        let pit_ptr = &raw const crate::arch::init::PIT_TIMER;
        (*pit_ptr).current_ticks()
    }
}

/// Upper bound on `cpusetsize` accepted by `sched_{get,set}affinity`.
///
/// A Linux `cpu_set_t` is 128 bytes (1024 CPUs); ONCRIX is single-CPU and
/// only bit 0 is ever meaningful. Bounding the size keeps the user-pointer
/// span validation finite and prevents an attacker-supplied length from
/// driving an unbounded ring-0 write.
const CPU_SET_MAX_BYTES: u64 = 128;

/// `times(buffer)` — report the calling thread's CPU times.
///
/// Writes a `struct tms { clock_t tms_utime, tms_stime, tms_cutime,
/// tms_cstime; }` (four 64-bit `clock_t`s) to `buffer` and returns the
/// elapsed real time in clock ticks since boot.
///
/// ONCRIX coarse accounting: all charged ticks land in `tms_utime`;
/// `tms_stime` is `0`. Child times (`tms_cutime`/`tms_cstime`) are `0`
/// because per-process child-time aggregation is not wired yet
/// (documented divergence from POSIX).
///
/// Returns elapsed ticks on success, `-14` (`EFAULT`) for a bad
/// `buffer`, `-3` (`ESRCH`) if there is no current thread.
///
/// # Safety
///
/// SYSCALL dispatch path (single-CPU, IF=0). `buffer` is a raw user
/// pointer; non-canonical addresses are rejected and unmapped-canonical
/// accesses fault into the user handler (SIGSEGV).
pub unsafe fn sys_times(buffer: u64) -> i64 {
    // Span- and backed-window-validate the full 32-byte `struct tms`
    // write (four i64s).
    if crate::uaccess::verify_user_access(buffer, 32, true).is_err() {
        return -14; // EFAULT
    }
    // SAFETY: SYSCALL dispatch context — exclusive scheduler access.
    let (utime, stime) = match unsafe { current_thread_mut() } {
        Some(t) => (t.utime_ticks(), t.stime_ticks()),
        None => return -3, // ESRCH
    };
    // struct tms layout: [utime, stime, cutime, cstime] as i64 clock_t.
    let tms: [i64; 4] = [utime as i64, stime as i64, 0, 0];
    // SAFETY: buffer is canonical user space (checked). We write four
    // contiguous i64s; an unmapped page faults into the user handler.
    unsafe {
        core::ptr::write_unaligned(buffer as *mut [i64; 4], tms);
    }
    // SAFETY: see global_ticks fn-level note.
    let elapsed = unsafe { global_ticks() };
    elapsed as i64
}

/// `getrusage(who, r_usage)` — report resource usage.
///
/// Fills the leading `ru_utime` / `ru_stime` `struct timeval`s of a
/// `struct rusage`; the remaining `long` counters (`ru_maxrss`, page
/// faults, etc.) are zeroed. `who` selects `RUSAGE_SELF` (0) or
/// `RUSAGE_CHILDREN` (-1); ONCRIX reports the calling thread for `SELF`
/// and all-zero for `CHILDREN` (no child aggregation yet — documented).
///
/// The `timeval`s are derived from the per-thread tick counter at
/// [`CLK_TCK`] resolution: `tv_sec = ticks / CLK_TCK`, `tv_usec =
/// (ticks % CLK_TCK) * 1_000_000 / CLK_TCK`.
///
/// Returns `0` on success, `-14` (`EFAULT`) for a bad `r_usage`, `-22`
/// (`EINVAL`) for an unknown `who`, `-3` (`ESRCH`) if no current thread.
///
/// # Safety
///
/// See [`sys_times`] regarding the user pointer.
pub unsafe fn sys_getrusage(who: i64, r_usage: u64) -> i64 {
    const RUSAGE_SELF: i64 = 0;
    const RUSAGE_CHILDREN: i64 = -1;
    if who != RUSAGE_SELF && who != RUSAGE_CHILDREN {
        return -22; // EINVAL
    }
    // Span- and backed-window-validate the full 144-byte `struct rusage`
    // write (18 i64s).
    if crate::uaccess::verify_user_access(r_usage, 144, true).is_err() {
        return -14; // EFAULT
    }

    // The full struct rusage on the LP64 ABI is 144 bytes: two timevals
    // (each two i64) followed by 14 `long` counters. We zero it then set
    // the two timevals for RUSAGE_SELF.
    let mut buf = [0i64; 18];
    if who == RUSAGE_SELF {
        // SAFETY: SYSCALL dispatch context — exclusive scheduler access.
        let (utime, stime) = match unsafe { current_thread_mut() } {
            Some(t) => (t.utime_ticks(), t.stime_ticks()),
            None => return -3, // ESRCH
        };
        let (us, uu) = ticks_to_timeval(utime);
        let (ss, su) = ticks_to_timeval(stime);
        // ru_utime = buf[0..2], ru_stime = buf[2..4].
        buf[0] = us;
        buf[1] = uu;
        buf[2] = ss;
        buf[3] = su;
    }
    // SAFETY: r_usage is canonical user space (checked). We write 18
    // contiguous i64s (144 bytes); an unmapped page faults to SIGSEGV.
    unsafe {
        core::ptr::write_unaligned(r_usage as *mut [i64; 18], buf);
    }
    0
}

/// Convert a PIT tick count to a `(tv_sec, tv_usec)` pair at
/// [`CLK_TCK`] resolution.
fn ticks_to_timeval(ticks: u64) -> (i64, i64) {
    let sec = (ticks / CLK_TCK) as i64;
    let usec = ((ticks % CLK_TCK) * 1_000_000 / CLK_TCK) as i64;
    (sec, usec)
}

/// `sched_getaffinity(pid, cpusetsize, mask)` — report the calling
/// thread's CPU affinity.
///
/// Writes the thread's affinity bitmask into the user `cpu_set_t` at
/// `mask`, which is `cpusetsize` bytes long. ONCRIX is single-CPU, so at
/// most bit 0 is ever set; bytes beyond the low 8 are zeroed. `pid` is
/// treated as the calling thread (no cross-pid lookup yet — documented).
///
/// Returns the number of bytes written (`cpusetsize`, Linux semantics)
/// on success, `-22` (`EINVAL`) if `cpusetsize` is 0 or not a multiple
/// of 8 (a `cpu_set_t` is an array of 8-byte words), `-14` (`EFAULT`)
/// for a bad `mask`, `-3` (`ESRCH`) if there is no current thread.
///
/// # Safety
///
/// SYSCALL dispatch path (single-CPU, IF=0). `mask` is a raw user
/// pointer; non-canonical addresses are rejected and unmapped-canonical
/// accesses fault into the user handler (SIGSEGV).
pub unsafe fn sys_sched_getaffinity(_pid: i64, cpusetsize: u64, mask: u64) -> i64 {
    if cpusetsize == 0 || cpusetsize % 8 != 0 || cpusetsize > CPU_SET_MAX_BYTES {
        return -22; // EINVAL
    }
    // Span- and backed-window-validate the entire `cpusetsize`-byte
    // zero-fill write below so a bounded-but-large request cannot scribble
    // past the user buffer (and cannot hit an unmapped page in ring 0).
    if crate::uaccess::verify_user_access(mask, cpusetsize, true).is_err() {
        return -14; // EFAULT
    }
    // SAFETY: SYSCALL dispatch context — exclusive scheduler access.
    let cpu_mask = match unsafe { current_thread_mut() } {
        Some(t) => t.cpu_mask(),
        None => return -3, // ESRCH
    };

    // Zero the whole user buffer, then write our 8-byte mask in the first
    // word. Done byte-by-byte so we never write past `cpusetsize`.
    let size = cpusetsize as usize;
    for i in 0..size {
        let byte = if i < 8 {
            ((cpu_mask >> (i * 8)) & 0xFF) as u8
        } else {
            0
        };
        // SAFETY: i < cpusetsize and the full [mask, mask+cpusetsize) span
        // was validated above via verify_user_access, so each byte write
        // stays within the user buffer (faulting to SIGSEGV if unmapped).
        unsafe {
            core::ptr::write_unaligned((mask as *mut u8).add(i), byte);
        }
    }
    cpusetsize as i64
}

/// `sched_setaffinity(pid, cpusetsize, mask)` — set the calling thread's
/// CPU affinity.
///
/// Reads the user `cpu_set_t` at `mask` (`cpusetsize` bytes) and stores
/// it on the thread. Because ONCRIX has only CPU 0, the requested mask
/// **must include bit 0** or `-22` (`EINVAL`) is returned (an affinity
/// excluding the only CPU would leave the thread unrunnable). `pid` is
/// treated as the calling thread.
///
/// Returns `0` on success, `-22` (`EINVAL`) for a zero/misaligned
/// `cpusetsize` or a mask without CPU 0, `-14` (`EFAULT`) for a bad
/// `mask`, `-3` (`ESRCH`) if there is no current thread.
///
/// # Safety
///
/// See [`sys_sched_getaffinity`].
pub unsafe fn sys_sched_setaffinity(_pid: i64, cpusetsize: u64, mask: u64) -> i64 {
    if cpusetsize == 0 || cpusetsize % 8 != 0 || cpusetsize > CPU_SET_MAX_BYTES {
        return -22; // EINVAL
    }
    // Only the low 8 bytes are read below; span- and backed-window-validate
    // exactly those.
    if crate::uaccess::verify_user_access(mask, 8, false).is_err() {
        return -14; // EFAULT
    }

    // Read the low 8 bytes (the only CPUs we can model). Higher bytes are
    // ignored: on a single CPU they can only ever request absent CPUs.
    let mut low: u64 = 0;
    for i in 0..8usize {
        // SAFETY: the 8-byte span [mask, mask+8) was validated above via
        // verify_user_access, so each in-range read stays within user space.
        let byte = unsafe { core::ptr::read_unaligned((mask as *const u8).add(i)) };
        low |= (byte as u64) << (i * 8);
    }

    // The only runnable CPU is 0; the mask must select it.
    if low & 1 == 0 {
        return -22; // EINVAL
    }

    // SAFETY: SYSCALL dispatch context — exclusive scheduler access.
    match unsafe { current_thread_mut() } {
        Some(t) => {
            t.set_cpu_mask(low);
            0
        }
        None => -3, // ESRCH
    }
}

// ── ITIMER_REAL: alarm(2) / setitimer(2) / getitimer(2) ──────────────

/// `which` selector for `setitimer`/`getitimer`: real (wall-clock) time.
const ITIMER_REAL: i64 = 0;
/// `which` selector: virtual (user CPU) time — unsupported.
const _ITIMER_VIRTUAL: i64 = 1;
/// `which` selector: profiling (user + system CPU) time — unsupported.
const _ITIMER_PROF: i64 = 2;

/// Advance every armed `ITIMER_REAL` by one PIT tick and raise `SIGALRM`
/// on each process whose timer expires this tick.
///
/// Called from the timer interrupt handler. Periodic timers reload
/// automatically (see [`ItimerReal::tick`](oncrix_process::table::ItimerReal::tick)).
///
/// # Safety
///
/// Must be called from the timer IRQ (single-CPU, IF=0 interrupt gate):
/// the process-table `&mut` borrow taken here is exclusive only under
/// that invariant, and is fully dropped before this function returns.
pub unsafe fn tick_itimers() {
    // SAFETY: timer IRQ context (single-CPU, IF=0) — no other code path
    // holds the process table; the borrow is released at scope end.
    unsafe {
        let table = crate::fork_dispatch::process_table_mut();
        for entry in table.iter_mut() {
            if entry.itimer_real.tick() {
                entry.signals.pending.raise(Signal::SIGALRM);
            }
        }
    }
}

/// Convert a `(tv_sec, tv_usec)` pair to PIT ticks, rounding the
/// sub-tick remainder up so a small non-zero interval still arms for at
/// least one tick. Used for `itimerval` fields.
fn timeval_to_ticks(sec: i64, usec: i64) -> u64 {
    let whole = (sec as u64).saturating_mul(CLK_TCK);
    // usec → ticks: ceil(usec * CLK_TCK / 1_000_000).
    let frac = ((usec as u64).saturating_mul(CLK_TCK)).div_ceil(1_000_000);
    whole.saturating_add(frac)
}

/// Convert PIT ticks back to a `(tv_sec, tv_usec)` pair for reporting an
/// `itimerval` field.
fn ticks_to_timeval_usec(ticks: u64) -> (i64, i64) {
    let sec = (ticks / CLK_TCK) as i64;
    let usec = ((ticks % CLK_TCK) * 1_000_000 / CLK_TCK) as i64;
    (sec, usec)
}

/// Read the calling process's current `ITIMER_REAL` `(value_ticks,
/// interval_ticks)`, or `None` if there is no current process.
///
/// # Safety
///
/// SYSCALL dispatch path (single-CPU, IF=0); the process-table borrow is
/// dropped before returning.
unsafe fn read_itimer_real() -> Option<(u64, u64)> {
    let pid = current_pid()?;
    // SAFETY: SYSCALL context — exclusive process-table access; borrow
    // released at scope end.
    unsafe {
        let table = crate::fork_dispatch::process_table_mut();
        table
            .get(pid)
            .map(|e| (e.itimer_real.value_ticks, e.itimer_real.interval_ticks))
    }
}

/// Arm/replace the calling process's `ITIMER_REAL`, returning the
/// previous `(value_ticks, interval_ticks)`. Returns `None` if there is
/// no current process.
///
/// # Safety
///
/// See [`read_itimer_real`].
unsafe fn set_itimer_real(value_ticks: u64, interval_ticks: u64) -> Option<(u64, u64)> {
    let pid = current_pid()?;
    // SAFETY: SYSCALL context — exclusive process-table access; borrow
    // released at scope end.
    unsafe {
        let table = crate::fork_dispatch::process_table_mut();
        let e = table.get_mut(pid)?;
        let prev = (e.itimer_real.value_ticks, e.itimer_real.interval_ticks);
        e.itimer_real.value_ticks = value_ticks;
        e.itimer_real.interval_ticks = interval_ticks;
        Some(prev)
    }
}

/// `alarm(seconds)` — arrange for `SIGALRM` after `seconds` real seconds.
///
/// A thin one-shot `ITIMER_REAL`: arms a non-periodic timer for
/// `seconds` and returns the number of whole seconds remaining on any
/// previously-set alarm (rounded up), or `0` if none was pending.
/// `alarm(0)` cancels any pending alarm and returns the seconds that
/// were left. POSIX `alarm` never fails.
///
/// # Safety
///
/// SYSCALL dispatch path; the process-table borrows are confined to the
/// helper calls and released before return.
pub unsafe fn sys_alarm(seconds: u64) -> i64 {
    let new_value = seconds.saturating_mul(CLK_TCK);
    // SAFETY: SYSCALL context — see fn-level note.
    let prev = unsafe { set_itimer_real(new_value, 0) };
    match prev {
        // Round remaining ticks up to whole seconds for the return value.
        Some((prev_value, _)) => prev_value.div_ceil(CLK_TCK) as i64,
        None => 0,
    }
}

/// `getitimer(which, curr_value)` — report the calling process's timer.
///
/// Only `ITIMER_REAL` (0) is supported; `ITIMER_VIRTUAL`/`ITIMER_PROF`
/// return `-22` (`EINVAL`) (documented divergence — no CPU-time timers
/// yet). Writes a `struct itimerval { it_interval, it_value }` (two
/// `timeval`s, four `i64`s) to `curr_value`: `it_value` is the time left
/// until the next `SIGALRM`, `it_interval` the reload period.
///
/// Returns `0` on success, `-22` (`EINVAL`) for an unsupported `which`,
/// `-14` (`EFAULT`) for a bad `curr_value`, `-3` (`ESRCH`) if no current
/// process.
///
/// # Safety
///
/// SYSCALL dispatch path; `curr_value` validated user-canonical first.
pub unsafe fn sys_getitimer(which: i64, curr_value: u64) -> i64 {
    if which != ITIMER_REAL {
        return -22; // EINVAL
    }
    // The full 32-byte `struct itimerval` (four i64s) is written below;
    // span- and backed-window-validate exactly that write.
    if crate::uaccess::verify_user_access(curr_value, 32, true).is_err() {
        return -14; // EFAULT
    }
    // SAFETY: SYSCALL context — see fn-level note.
    let (value_ticks, interval_ticks) = match unsafe { read_itimer_real() } {
        Some(v) => v,
        None => return -3, // ESRCH
    };
    let (iv_sec, iv_usec) = ticks_to_timeval_usec(interval_ticks);
    let (vv_sec, vv_usec) = ticks_to_timeval_usec(value_ticks);
    // itimerval: [it_interval.sec, it_interval.usec, it_value.sec, it_value.usec].
    let buf: [i64; 4] = [iv_sec, iv_usec, vv_sec, vv_usec];
    // SAFETY: curr_value is canonical user space (checked); writes four
    // contiguous i64s, faulting to SIGSEGV on an unmapped page.
    unsafe {
        core::ptr::write_unaligned(curr_value as *mut [i64; 4], buf);
    }
    0
}

/// `setitimer(which, new_value, old_value)` — arm the calling process's
/// timer.
///
/// Only `ITIMER_REAL` (0) is supported. Reads `struct itimerval` from
/// `new_value` (it_interval then it_value, four `i64`s); if `old_value`
/// is non-null the previous setting is written there first (same layout
/// as [`sys_getitimer`]). An `it_value` of `(0, 0)` disarms the timer.
///
/// Returns `0` on success, `-22` (`EINVAL`) for an unsupported `which`
/// or out-of-range `tv_usec`, `-14` (`EFAULT`) for a bad pointer, `-3`
/// (`ESRCH`) if no current process.
///
/// # Safety
///
/// SYSCALL dispatch path; both pointers validated user-canonical first.
pub unsafe fn sys_setitimer(which: i64, new_value: u64, old_value: u64) -> i64 {
    if which != ITIMER_REAL {
        return -22; // EINVAL
    }
    // `new_value` is read as a 32-byte `struct itimerval` (four i64s);
    // span- and backed-window-validate exactly that read.
    if crate::uaccess::verify_user_access(new_value, 32, false).is_err() {
        return -14; // EFAULT
    }
    // `old_value` is the optional previous-setting out-param: NULL means
    // "don't report", which is valid; otherwise 32 bytes are written.
    if old_value != 0 && crate::uaccess::verify_user_access(old_value, 32, true).is_err() {
        return -14; // EFAULT
    }

    // SAFETY: new_value canonical (checked); read four contiguous i64s.
    let nv = unsafe { core::ptr::read_unaligned(new_value as *const [i64; 4]) };
    let (iv_sec, iv_usec, vv_sec, vv_usec) = (nv[0], nv[1], nv[2], nv[3]);
    // Validate tv_usec ranges and non-negative seconds.
    if iv_sec < 0
        || vv_sec < 0
        || !(0..1_000_000).contains(&iv_usec)
        || !(0..1_000_000).contains(&vv_usec)
    {
        return -22; // EINVAL
    }

    let interval_ticks = timeval_to_ticks(iv_sec, iv_usec);
    let value_ticks = timeval_to_ticks(vv_sec, vv_usec);

    // SAFETY: SYSCALL context — see fn-level note.
    let prev = match unsafe { set_itimer_real(value_ticks, interval_ticks) } {
        Some(p) => p,
        None => return -3, // ESRCH
    };

    if old_value != 0 {
        let (piv_sec, piv_usec) = ticks_to_timeval_usec(prev.1);
        let (pvv_sec, pvv_usec) = ticks_to_timeval_usec(prev.0);
        let buf: [i64; 4] = [piv_sec, piv_usec, pvv_sec, pvv_usec];
        // SAFETY: old_value canonical (checked); writes four i64s.
        unsafe {
            core::ptr::write_unaligned(old_value as *mut [i64; 4], buf);
        }
    }
    0
}

// ── rt_sigaction(2) / rt_sigprocmask(2) ───────────────────────────────

/// Sentinel `sa_handler` for `SIG_DFL` — restore the default action.
const SIG_DFL_HANDLER: u64 = 0;
/// Sentinel `sa_handler` for `SIG_IGN` — ignore the signal.
const SIG_IGN_HANDLER: u64 = 1;

/// Wire layout of the `struct sigaction` passed to `rt_sigaction(2)`.
///
/// Matches the Linux x86_64 ABI for `sigsetsize == 8`: a 64-bit handler
/// pointer, 64-bit flags, 64-bit restorer (unused — we round-trip but do
/// not invoke a separate restorer), and a single 64-bit `sigset_t` word
/// (low 32 bits used; high 32 reserved). Total 32 bytes.
#[repr(C)]
#[derive(Clone, Copy)]
struct RawSigaction {
    sa_handler: u64,
    sa_flags: u64,
    sa_restorer: u64,
    sa_mask: u64,
}

/// Decode a [`RawSigaction`] into a [`SignalAction`].
fn raw_to_action(handler: u64) -> SignalAction {
    match handler {
        SIG_DFL_HANDLER => SignalAction::Default,
        SIG_IGN_HANDLER => SignalAction::Ignore,
        rip => SignalAction::Handler(rip),
    }
}

/// Encode a [`SignalAction`] into the raw `sa_handler` value.
const fn action_to_raw(action: SignalAction) -> u64 {
    match action {
        SignalAction::Default => SIG_DFL_HANDLER,
        SignalAction::Ignore => SIG_IGN_HANDLER,
        SignalAction::Handler(rip) => rip,
    }
}

/// `rt_sigaction(sig, act, oact, sigsetsize)` — examine or change the
/// disposition of a signal.
///
/// Reads a `struct sigaction` from `act` (if non-null) and installs it
/// on the calling process. If `oact` is non-null, the previous setting
/// is written there first. `sigsetsize` must equal the kernel's
/// `sigset_t` size (8 bytes — one 64-bit word covers the 32 signals
/// ONCRIX models); other sizes return `-22` (`EINVAL`). Signals
/// `SIGKILL` and `SIGSTOP` cannot be caught or ignored — attempting to
/// install a handler for them returns `-22` (`EINVAL`).
///
/// Recognised `sa_flags`: `SA_RESTART`, `SA_NODEFER`, `SA_RESETHAND`,
/// `SA_SIGINFO`, `SA_NOCLDSTOP`, `SA_NOCLDWAIT`, `SA_ONSTACK`. They are
/// stored unchanged; the signal-delivery path is responsible for
/// honouring `SA_NODEFER` / `SA_RESETHAND` (see [`SA_NODEFER`] docs).
///
/// Returns `0` on success, `-22` (`EINVAL`) for a bad signal,
/// `sigsetsize`, or attempt to catch SIGKILL/SIGSTOP, `-14` (`EFAULT`)
/// for a bad pointer, `-3` (`ESRCH`) if there is no current process.
///
/// # Safety
///
/// SYSCALL dispatch path (single-CPU, IF=0); `act`/`oact` are validated
/// user-canonical before any access.
pub unsafe fn sys_rt_sigaction(sig: i64, act: u64, oact: u64, sigsetsize: u64) -> i64 {
    if sigsetsize != 8 {
        return -22; // EINVAL — only the 8-byte sigset_t is supported.
    }
    if sig <= 0 || sig as u32 > Signal::MAX as u32 {
        return -22; // EINVAL
    }
    let signum = Signal(sig as u8);
    // `act`/`oact` are read/written as a 32-byte `struct sigaction`
    // (RawSigaction); both are NULL-optional (NULL = no install / no
    // report). Span- and backed-window-validate exactly 32 bytes per side.
    if act != 0 && crate::uaccess::verify_user_access(act, 32, false).is_err() {
        return -14; // EFAULT
    }
    if oact != 0 && crate::uaccess::verify_user_access(oact, 32, true).is_err() {
        return -14; // EFAULT
    }
    if act == 0 && oact == 0 {
        // Nothing to read or write — pure no-op query, succeed.
        return 0;
    }

    let pid = match current_pid() {
        Some(p) => p,
        None => return -3, // ESRCH
    };

    // Snapshot old and (optionally) apply new under one process-table
    // borrow so the read/write pair is atomic w.r.t. signal delivery.
    //
    // SAFETY: SYSCALL context — exclusive process-table access; borrow
    // released at scope end.
    let result = unsafe {
        let table = crate::fork_dispatch::process_table_mut();
        let entry = match table.get_mut(pid) {
            Some(e) => e,
            None => return -3, // ESRCH
        };

        let old_action = entry.signals.get_action(signum);
        let old_flags = entry.signals.get_flags(signum);

        if act != 0 {
            // SAFETY: act validated canonical above; read 32 bytes.
            let new = core::ptr::read_unaligned(act as *const RawSigaction);
            let new_action = raw_to_action(new.sa_handler);
            if entry
                .signals
                .set_action_with_flags(signum, new_action, new.sa_flags)
                .is_err()
            {
                // SIGKILL/SIGSTOP or out-of-range signum.
                return -22; // EINVAL
            }
            // Note: `sa_mask` is read from userspace but not applied to
            // the per-process mask — POSIX `sigaction` only affects the
            // mask *during handler invocation*. The delivery path is the
            // right place to add those bits when entering the handler.
            // Stored implicitly through `handler_flags` (SA_NODEFER) for
            // now; per-signal sa_mask plumbing is a follow-up.
            let _ = new.sa_mask;
        }

        if oact != 0 {
            let old = RawSigaction {
                sa_handler: action_to_raw(old_action),
                sa_flags: old_flags,
                sa_restorer: 0,
                sa_mask: 0,
            };
            // SAFETY: oact validated canonical above; write 32 bytes.
            core::ptr::write_unaligned(oact as *mut RawSigaction, old);
        }
        0i64
    };
    result
}

/// `rt_sigprocmask(how, set, oldset, sigsetsize)` — examine or change
/// the calling process's signal mask.
///
/// If `set` is non-null, the new mask is computed from `how`:
///   * `SIG_BLOCK`   (0): `mask |= *set`
///   * `SIG_UNBLOCK` (1): `mask &= ~*set`
///   * `SIG_SETMASK` (2): `mask  = *set`
///
/// `SIGKILL` and `SIGSTOP` can never be masked: those bits are silently
/// cleared from the resulting mask (see
/// [`SignalMask::from_u32`](oncrix_process::signal::SignalMask::from_u32)).
/// If `oldset` is non-null the previous mask is written there first.
/// `sigsetsize` must be 8 bytes.
///
/// Returns `0` on success, `-22` (`EINVAL`) for a bad `how` or
/// `sigsetsize`, `-14` (`EFAULT`) for a bad pointer, `-3` (`ESRCH`) if
/// there is no current process.
///
/// # Safety
///
/// SYSCALL dispatch path; `set`/`oldset` validated user-canonical.
pub unsafe fn sys_rt_sigprocmask(how: i64, set: u64, oldset: u64, sigsetsize: u64) -> i64 {
    if sigsetsize != 8 {
        return -22; // EINVAL
    }
    // `set`/`oldset` are read/written as an 8-byte `sigset_t` word; both
    // are NULL-optional (NULL = no change / no report). Span- and
    // backed-window-validate exactly 8 bytes per side.
    if set != 0 && crate::uaccess::verify_user_access(set, 8, false).is_err() {
        return -14; // EFAULT
    }
    if oldset != 0 && crate::uaccess::verify_user_access(oldset, 8, true).is_err() {
        return -14; // EFAULT
    }
    let how_i32 = how as i32;
    if set != 0 && how_i32 != SIG_BLOCK && how_i32 != SIG_UNBLOCK && how_i32 != SIG_SETMASK {
        return -22; // EINVAL
    }

    let pid = match current_pid() {
        Some(p) => p,
        None => return -3, // ESRCH
    };

    // SAFETY: SYSCALL context — exclusive process-table access; borrow
    // released at scope end.
    unsafe {
        let table = crate::fork_dispatch::process_table_mut();
        let entry = match table.get_mut(pid) {
            Some(e) => e,
            None => return -3, // ESRCH
        };

        let old_mask = entry.signals.mask;

        if set != 0 {
            // SAFETY: set validated canonical above; read 8 bytes (the
            // low 32 bits are the only ones we model, the rest reserved).
            let raw = core::ptr::read_unaligned(set as *const u64);
            let new_bits = raw as u32;
            let new_mask = match how_i32 {
                SIG_BLOCK => SignalMask::from_u32(old_mask.as_u32() | new_bits),
                SIG_UNBLOCK => SignalMask::from_u32(old_mask.as_u32() & !new_bits),
                SIG_SETMASK => SignalMask::from_u32(new_bits),
                _ => return -22, // EINVAL (already filtered, but defensive)
            };
            entry.signals.mask = new_mask;
        }

        if oldset != 0 {
            let raw = old_mask.as_u32() as u64;
            // SAFETY: oldset validated canonical above; write 8 bytes.
            core::ptr::write_unaligned(oldset as *mut u64, raw);
        }
    }
    0
}

// ── setpgid(2) / getpgid(2) / setsid(2) / getsid(2) ───────────────────

/// Resolve a `pid` argument of `0` to the calling process; otherwise
/// turn the raw `u64` into a [`Pid`]. Returns `None` if the calling
/// thread has no associated process (used to map to `ESRCH`).
fn resolve_target_pid(pid: u64) -> Option<Pid> {
    if pid == 0 {
        current_pid()
    } else {
        Some(Pid::new(pid))
    }
}

/// `setpgid(pid, pgid)` — set the process group ID of `pid` to `pgid`.
///
/// `pid` of `0` selects the calling process; `pgid` of `0` selects the
/// same value as `pid`. The target must be either the caller or one of
/// the caller's children (`parent == self`); a session leader cannot
/// change its group (`EPERM`); the target and the requested `pgid`
/// owner (a process whose `pid == pgid`) must be in the same session
/// as the caller; otherwise `EPERM`. ONCRIX does not yet model "the
/// target has already exec'd in the child" → there is no
/// `EACCES`-after-exec semantics; the rest of the failure set is honoured.
///
/// Returns `0` on success, `-22` (`EINVAL`) for a negative `pgid` /
/// out-of-range PID, `-1` (`EPERM`) for the disallowed transitions
/// above, `-3` (`ESRCH`) if `pid` does not exist.
///
/// # Safety
///
/// SYSCALL dispatch path (single-CPU, IF=0); the process-table borrow
/// is exclusive within this call.
pub unsafe fn sys_setpgid(pid_arg: u64, pgid_arg: u64) -> i64 {
    // pgid as signed i64 to reject obviously negative values.
    let pgid_signed = pgid_arg as i64;
    if pgid_signed < 0 {
        return -22; // EINVAL
    }
    let caller = match current_pid() {
        Some(p) => p,
        None => return -3, // ESRCH
    };
    let target = match resolve_target_pid(pid_arg) {
        Some(p) => p,
        None => return -3, // ESRCH
    };
    // pgid==0 ⇒ use the target pid.
    let new_pgid = if pgid_arg == 0 {
        target
    } else {
        Pid::new(pgid_arg)
    };

    // SAFETY: SYSCALL context — exclusive process-table access; borrow
    // released at scope end.
    unsafe {
        let table = crate::fork_dispatch::process_table_mut();

        // Capture the caller's session for the "same session" checks
        // without holding a borrow across the mutable lookup below.
        let caller_sid = match table.get(caller) {
            Some(e) => e.sid,
            None => return -3, // ESRCH
        };

        let target_entry = match table.get(target) {
            Some(e) => e,
            None => return -3, // ESRCH
        };
        // Target must be the caller or a child of the caller.
        if target != caller && target_entry.parent != caller {
            return -1; // EPERM (target outside caller's reach)
        }
        // A session leader's pgid cannot change.
        if target_entry.sid == target {
            return -1; // EPERM (target is a session leader)
        }
        // Target must be in the caller's session.
        if target_entry.sid != caller_sid {
            return -1; // EPERM (different session)
        }

        // The requested pgid must either equal the target's pid (creating
        // a new group with the target as leader) or already exist as a
        // pgid in the caller's session.
        if new_pgid != target {
            let mut found = false;
            for e in table.iter() {
                if e.pgid == new_pgid && e.sid == caller_sid {
                    found = true;
                    break;
                }
            }
            if !found {
                return -1; // EPERM (no such group in this session)
            }
        }

        // All checks passed — apply the change.
        let entry_mut = match table.get_mut(target) {
            Some(e) => e,
            None => return -3, // ESRCH (raced; defensive)
        };
        entry_mut.pgid = new_pgid;
    }
    0
}

/// `getpgid(pid)` — return the process group ID of `pid`.
///
/// `pid` of `0` queries the calling process. Returns the `pgid` (as a
/// non-negative `i64`) on success, `-3` (`ESRCH`) if `pid` does not
/// exist.
///
/// # Safety
///
/// SYSCALL dispatch path.
pub unsafe fn sys_getpgid(pid_arg: u64) -> i64 {
    let target = match resolve_target_pid(pid_arg) {
        Some(p) => p,
        None => return -3, // ESRCH
    };
    // SAFETY: SYSCALL context — exclusive process-table access; borrow
    // released at scope end.
    unsafe {
        let table = crate::fork_dispatch::process_table_mut();
        match table.get(target) {
            Some(e) => e.pgid.as_u64() as i64,
            None => -3, // ESRCH
        }
    }
}

/// `setsid()` — create a new session.
///
/// The caller becomes the session leader and the process-group leader
/// of a brand-new session whose ID equals the caller's PID. Fails with
/// `-1` (`EPERM`) if the caller is already a process-group leader
/// (i.e. `pgid == pid`), per POSIX. On success returns the new
/// (caller PID) session ID.
///
/// # Safety
///
/// SYSCALL dispatch path.
pub unsafe fn sys_setsid() -> i64 {
    let caller = match current_pid() {
        Some(p) => p,
        None => return -3, // ESRCH
    };
    // SAFETY: SYSCALL context — exclusive process-table access; borrow
    // released at scope end.
    unsafe {
        let table = crate::fork_dispatch::process_table_mut();

        // Capture the caller's current pgid via a brief immutable
        // borrow, then drop it before the leader-check scan.
        let our_pgid = match table.get(caller) {
            Some(e) => e.pgid,
            None => return -3, // ESRCH
        };

        // POSIX: setsid fails if the caller is **already a real**
        // process-group leader — i.e. some *other* process shares this
        // pgid. Our default `pgid = pid` makes every freshly-spawned
        // process formally a "leader" of a one-process group, but POSIX
        // permits setsid in that case (it just folds the trivial group
        // into the new session). We therefore only reject when at least
        // one other process is in the same pgrp.
        for e in table.iter() {
            if e.pid() != caller && e.pgid == our_pgid {
                return -1; // EPERM (real pgrp leader)
            }
        }

        // Commit the new session and group.
        let entry = match table.get_mut(caller) {
            Some(e) => e,
            None => return -3, // ESRCH (defensive)
        };
        entry.sid = caller;
        entry.pgid = caller;
        caller.as_u64() as i64
    }
}

/// `getsid(pid)` — return the session ID of `pid`.
///
/// `pid` of `0` queries the calling process. Returns the `sid` on
/// success, `-3` (`ESRCH`) if `pid` does not exist. ONCRIX has no
/// cross-session permission model, so the optional POSIX `EPERM` case
/// ("target is in a different session and the implementation does not
/// permit cross-session queries") is not returned.
///
/// # Safety
///
/// SYSCALL dispatch path.
pub unsafe fn sys_getsid(pid_arg: u64) -> i64 {
    let target = match resolve_target_pid(pid_arg) {
        Some(p) => p,
        None => return -3, // ESRCH
    };
    // SAFETY: SYSCALL context — exclusive process-table access; borrow
    // released at scope end.
    unsafe {
        let table = crate::fork_dispatch::process_table_mut();
        match table.get(target) {
            Some(e) => e.sid.as_u64() as i64,
            None => -3, // ESRCH
        }
    }
}

// ── Resource limits (getrlimit/setrlimit/prlimit64) ──────────────

/// Wire layout of `struct rlimit` / `struct rlimit64`: two `u64`s
/// (`rlim_cur`, `rlim_max`).
const RLIMIT_WIRE_LEN: usize = 16;

/// Shared core for `prlimit64`/`getrlimit`/`setrlimit`.
///
/// Reads the old value into `*old_ptr` (when non-null) before applying the
/// new value from `*new_ptr` (when non-null). `target` of 0 means the
/// calling process. Returns 0 on success or a negative errno.
///
/// # Safety
///
/// `old_ptr`/`new_ptr`, when non-zero, must reference 16 writable/readable
/// user bytes respectively. Caller runs in SYSCALL context.
unsafe fn rlimit_op(target: u64, resource: u64, new_ptr: u64, old_ptr: u64) -> i64 {
    use oncrix_process::table::{RLIMIT_NLIMITS, Rlimit};

    let res = resource as usize;
    if res >= RLIMIT_NLIMITS {
        return -22; // EINVAL
    }
    // Each non-null pointer is dereferenced as a 16-byte `rlimit` below;
    // span- and backed-window-validate the exact access before any
    // read/write. NULL is the valid "absent" case for each side.
    if old_ptr != 0 && crate::uaccess::verify_user_access(old_ptr, 16, true).is_err() {
        return -14; // EFAULT
    }
    if new_ptr != 0 && crate::uaccess::verify_user_access(new_ptr, 16, false).is_err() {
        return -14; // EFAULT
    }
    let target_pid = match resolve_target_pid(target) {
        Some(p) => p,
        None => return -3, // ESRCH
    };

    // SAFETY: SYSCALL context — exclusive process-table access.
    unsafe {
        let table = crate::fork_dispatch::process_table_mut();
        let entry = match table.get_mut(target_pid) {
            Some(e) => e,
            None => return -3, // ESRCH
        };

        if old_ptr != 0 {
            let cur = entry.rlimits[res];
            let buf = [cur.rlim_cur, cur.rlim_max];
            // SAFETY: old_ptr validated above; 16 bytes.
            core::ptr::write_unaligned(old_ptr as *mut [u64; 2], buf);
        }

        if new_ptr != 0 {
            // SAFETY: new_ptr validated above; 16 bytes.
            let buf = core::ptr::read_unaligned(new_ptr as *const [u64; 2]);
            let (cur, max) = (buf[0], buf[1]);
            if cur > max {
                return -22; // EINVAL — soft limit above hard limit
            }
            entry.rlimits[res] = Rlimit {
                rlim_cur: cur,
                rlim_max: max,
            };
        }
    }
    0
}

/// `prlimit64(2)` — get and/or set a resource limit of process `pid`
/// (0 = caller). Writes the previous value to `old_value` (if non-null),
/// then applies `new_value` (if non-null).
///
/// # Safety
///
/// `new_value`/`old_value`, when non-zero, must be valid user pointers to a
/// 16-byte `rlimit64`. SYSCALL context only.
pub unsafe fn sys_prlimit64(pid: u64, resource: u64, new_value: u64, old_value: u64) -> i64 {
    // SAFETY: forwarded to rlimit_op under SYSCALL context.
    unsafe { rlimit_op(pid, resource, new_value, old_value) }
}

/// `getrlimit(2)` — read the calling process's limit for `resource` into
/// `rlim` (a 16-byte `rlimit`).
///
/// # Safety
///
/// `rlim` must point to 16 writable user bytes. SYSCALL context only.
pub unsafe fn sys_getrlimit(resource: u64, rlim: u64) -> i64 {
    if rlim == 0 {
        return -14; // EFAULT
    }
    let _ = RLIMIT_WIRE_LEN;
    // SAFETY: read current value into `rlim`, apply nothing.
    unsafe { rlimit_op(0, resource, 0, rlim) }
}

/// `setrlimit(2)` — set the calling process's limit for `resource` from
/// `rlim` (a 16-byte `rlimit`).
///
/// # Safety
///
/// `rlim` must point to 16 readable user bytes. SYSCALL context only.
pub unsafe fn sys_setrlimit(resource: u64, rlim: u64) -> i64 {
    if rlim == 0 {
        return -14; // EFAULT
    }
    // SAFETY: apply new value from `rlim`, report no old value.
    unsafe { rlimit_op(0, resource, rlim, 0) }
}

// ── umask ────────────────────────────────────────────────────────

/// `umask(2)` — atomically replace the calling process's file-mode
/// creation mask with `(mask & 0o777)` and return the previous mask.
///
/// Bits set in the umask are CLEARED from the mode of newly created files
/// (`open`/`creat`/`mkdir`). Stored on the [`ProcessEntry`]; enforcement
/// at file-creation sites is documented as a follow-up — storage and
/// retrieval are the deliverable here. Never fails when the calling
/// process exists; `-ESRCH` if it does not.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU).
pub unsafe fn sys_umask(mask: u64) -> i64 {
    let new = (mask as u32) & 0o777;
    let pid = match current_pid() {
        Some(p) => p,
        None => return -3, // ESRCH
    };
    // SAFETY: SYSCALL context — exclusive process-table access.
    unsafe {
        let table = crate::fork_dispatch::process_table_mut();
        match table.get_mut(pid) {
            Some(entry) => {
                let old = entry.umask;
                entry.umask = new;
                old as i64
            }
            None => -3, // ESRCH
        }
    }
}

// ── getcpu / sched_get_priority_max|min ───────────────────────────

/// `getcpu(cpu_ptr, node_ptr, tcache_ptr)` — report the calling thread's
/// current CPU index and NUMA node index.
///
/// ONCRIX is a single-CPU, single-node system. If `cpu_ptr` is non-null
/// and canonical, `0u32` is written to `*cpu_ptr`. If `node_ptr` is
/// non-null and canonical, `0u32` is written to `*node_ptr`. `tcache_ptr`
/// is accepted and ignored (the `getcpu_cache` struct is a Linux-specific
/// optimisation; POSIX does not define it).
///
/// Returns `0` on success, `-14` (`EFAULT`) if either non-null pointer is
/// non-canonical.
///
/// # Safety
///
/// Called from the single-CPU SYSCALL dispatch path with interrupts
/// effectively disabled (FMASK cleared IF). `cpu` and `node` are raw
/// user-space pointers; we reject non-canonical addresses and write only
/// 4 bytes each, relying on the user page-fault handler to convert an
/// unmapped-but-canonical access into a `SIGSEGV`.
pub unsafe fn sys_getcpu(cpu: u64, node: u64, _tcache: u64) -> i64 {
    // Validate cpu_ptr when non-null: span- and backed-window-validate the
    // exact 4-byte write (NULL = "don't report", which is valid).
    if cpu != 0 {
        if crate::uaccess::verify_user_access(cpu, 4, true).is_err() {
            return -14; // EFAULT
        }
        // SAFETY: the 4-byte span at `cpu` was validated above. We write
        // exactly 4 bytes (u32). An unmapped page faults to the user fault
        // handler (SIGSEGV) rather than corrupting the kernel.
        unsafe { core::ptr::write_unaligned(cpu as *mut u32, 0u32) };
    }

    // Validate node_ptr when non-null: span- and backed-window-validate the
    // exact 4-byte write (NULL = "don't report", which is valid).
    if node != 0 {
        if crate::uaccess::verify_user_access(node, 4, true).is_err() {
            return -14; // EFAULT
        }
        // SAFETY: same reasoning as cpu_ptr write above.
        unsafe { core::ptr::write_unaligned(node as *mut u32, 0u32) };
    }

    0
}

/// `sched_get_priority_max(policy)` — return the maximum real-time
/// priority for the given scheduling policy.
///
/// Per POSIX.1-2024 (`sched_get_priority_max(3p)`):
/// - `SCHED_FIFO` (1) and `SCHED_RR` (2): returns `99`.
/// - `SCHED_OTHER` (0): returns `0`.
/// - Any other value: returns `-22` (`EINVAL`).
///
/// # Safety
///
/// Called from the single-CPU SYSCALL dispatch path. No pointers are
/// dereferenced; the argument is a plain scalar policy number.
pub unsafe fn sys_sched_get_priority_max(policy: i64) -> i64 {
    match policy as i32 {
        0 => 0,      // SCHED_OTHER
        1 | 2 => 99, // SCHED_FIFO | SCHED_RR
        _ => -22,    // EINVAL
    }
}

/// `sched_get_priority_min(policy)` — return the minimum real-time
/// priority for the given scheduling policy.
///
/// Per POSIX.1-2024 (`sched_get_priority_min(3p)`):
/// - `SCHED_FIFO` (1) and `SCHED_RR` (2): returns `1`.
/// - `SCHED_OTHER` (0): returns `0`.
/// - Any other value: returns `-22` (`EINVAL`).
///
/// # Safety
///
/// Called from the single-CPU SYSCALL dispatch path. No pointers are
/// dereferenced; the argument is a plain scalar policy number.
pub unsafe fn sys_sched_get_priority_min(policy: i64) -> i64 {
    match policy as i32 {
        0 => 0,     // SCHED_OTHER
        1 | 2 => 1, // SCHED_FIFO | SCHED_RR
        _ => -22,   // EINVAL
    }
}

// ── sched_rr_get_interval ─────────────────────────────────────────

/// `sched_rr_get_interval(pid, tp)` — write the round-robin time quantum for
/// the calling process into the `struct timespec` pointed to by `tp`.
///
/// ONCRIX runs a single fixed-period scheduler driven by the 8254 PIT at
/// 100 Hz.  Every runnable task therefore receives a 10 ms quantum regardless
/// of `pid`.  The `pid` argument is validated for type only (must fit in i32)
/// but is otherwise ignored — single-scheduler policy.
///
/// On success the value `{tv_sec: 0, tv_nsec: 10_000_000}` is written to
/// `*tp` and `0` is returned.
///
/// # Errors
///
/// * `-14` (`EFAULT`) — `tp` is null or falls in the kernel half of the
///   address space (`>= 0xFFFF_8000_0000_0000`).
///
/// # Safety
///
/// Called exclusively from the single-CPU SYSCALL dispatch path.
/// `tp` is a raw user-space pointer; the caller must ensure it is mapped
/// and writable before invoking this function (the 16-byte span is
/// validated here via `verify_user_access`).
pub unsafe fn sys_sched_rr_get_interval(pid: u64, tp: u64) -> i64 {
    // Two i64s are written at tp and tp+8 (16-byte `struct timespec`);
    // span- and backed-window-validate the full 16-byte range before any
    // write.
    if crate::uaccess::verify_user_access(tp, 16, true).is_err() {
        return -14; // EFAULT
    }

    // SAFETY: the full 16-byte span at `tp` was validated above.
    // The write is unaligned to tolerate any user-space alignment; the
    // two i64 fields are written individually so no padding bytes are
    // assumed.
    unsafe {
        // tv_sec  = 0  (quantum is sub-second)
        core::ptr::write_unaligned(tp as *mut i64, 0i64);
        // tv_nsec = 10_000_000  (10 ms at 100 Hz PIT)
        core::ptr::write_unaligned((tp + 8) as *mut i64, 10_000_000i64);
    }

    let _ = pid; // pid accepted per POSIX; ignored on single-scheduler.
    0
}

// ── sched_setattr(2) / sched_getattr(2) ──────────────────────────────────────

/// Wire layout of `struct sched_attr` (Linux UAPI, version 0, 48 bytes).
///
/// Fields beyond `sched_period` (version 1: util_min/util_max) are not read
/// or written by ONCRIX — the struct is always reported as 48 bytes and only
/// the version-0 fields are meaningful.
///
/// Byte offsets on LP64:
///   0  u32 size
///   4  u32 sched_policy
///   8  u64 sched_flags
///  16  i32 sched_nice
///  20  u32 sched_priority
///  24  u64 sched_runtime
///  32  u64 sched_deadline
///  40  u64 sched_period
///  total: 48 bytes
#[repr(C)]
#[derive(Clone, Copy)]
struct RawSchedAttr {
    size: u32,
    sched_policy: u32,
    sched_flags: u64,
    sched_nice: i32,
    sched_priority: u32,
    sched_runtime: u64,
    sched_deadline: u64,
    sched_period: u64,
}

/// Minimum accepted `size` field / read-length for `sched_attr` (version 0).
const SCHED_ATTR_SIZE_V0: u32 = 48;

/// `sched_setattr(pid, attr, flags)` — set extended scheduling attributes.
///
/// Reads a `struct sched_attr` from the user pointer `attr`, applies the
/// policy (`sched_policy`, 0=Other/1=FIFO/2=RR) and nice value
/// (`sched_nice`, clamped to `[-20, 19]`) to the calling thread.
///
/// `flags` must be `0`; any other value returns `-22` (`EINVAL`).
/// `pid` must be `0` or the calling thread's own PID; ONCRIX has no
/// cross-thread scheduling control yet (documented divergence).
///
/// Returns `0` on success, `-22` (`EINVAL`) for bad policy/flags,
/// `-14` (`EFAULT`) for a non-canonical `attr`, `-3` (`ESRCH`) if
/// there is no current thread.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path with
/// interrupts effectively disabled (FMASK clears IF), so the mutable
/// scheduler borrow taken via [`current_thread_mut`] is exclusive.
/// `attr` is a raw user-space pointer; non-canonical addresses are
/// rejected and unmapped-canonical accesses fault into the user handler.
pub unsafe fn sys_sched_setattr(pid: i64, attr: u64, flags: i64) -> i64 {
    // SECURITY: caps fail closed to EMPTY — selecting SCHED_FIFO/SCHED_RR or
    // lowering nice is denied for all callers until syscall_entry.rs threads
    // the real per-thread effective CapSet into `sys_sched_setattr_checked`.
    // SAFETY: forwarded unchanged under the same SYSCALL dispatch contract.
    unsafe { sys_sched_setattr_checked(pid, attr, flags, caller_effective_caps()) }
}

/// Capability-checked core of [`sys_sched_setattr`].
///
/// Selecting a real-time policy (`SCHED_FIFO`/`SCHED_RR`) or lowering the
/// requested `sched_nice` below the thread's current nice requires
/// [`CAP_SYS_NICE`] in `caller_caps`; otherwise `-1` (`EPERM`) is returned
/// and neither policy nor nice is changed.
///
/// # Safety
///
/// See [`sys_sched_setattr`].
unsafe fn sys_sched_setattr_checked(_pid: i64, attr: u64, flags: i64, caller_caps: CapSet) -> i64 {
    if flags != 0 {
        return -22; // EINVAL
    }
    // Span- and backed-window-validate the full 48-byte `struct sched_attr`
    // read.
    if crate::uaccess::verify_user_access(attr, SCHED_ATTR_SIZE_V0 as u64, false).is_err() {
        return -14; // EFAULT
    }

    // SAFETY: the full 48-byte span at `attr` was validated above.  We read
    // exactly 48 bytes (version-0 sched_attr); an unmapped page faults into
    // the user handler (SIGSEGV) rather than corrupting the kernel.
    let raw: RawSchedAttr = unsafe { core::ptr::read_unaligned(attr as *const RawSchedAttr) };

    // `flags` field inside the struct must be 0 for ONCRIX.
    if raw.sched_flags != 0 {
        return -22; // EINVAL
    }

    // Only ONCRIX-supported policies: Other=0, Fifo=1, RoundRobin=2.
    let Some(pol) = SchedPolicy::from_raw(raw.sched_policy as i32) else {
        return -22; // EINVAL
    };

    let nice = clamp_nice(raw.sched_nice);

    // SAFETY: SYSCALL dispatch context — exclusive scheduler access.
    match unsafe { current_thread_mut() } {
        Some(t) => {
            // Authorize before mutating: RT policy or a more-favourable nice
            // requires CAP_SYS_NICE.
            let cur_nice = t.priority().to_nice();
            if let Err(e) = authorize_sched_change(caller_caps, pol, cur_nice, nice) {
                return e;
            }
            t.set_policy(pol);
            t.set_priority(Priority::from_nice(nice));
            0
        }
        None => -3, // ESRCH
    }
}

/// `sched_getattr(pid, attr, size, flags)` — get extended scheduling attributes.
///
/// Writes a zero-filled `struct sched_attr` (48 bytes, version 0) to the
/// user pointer `attr`, then sets `size=48`, `sched_policy` to the calling
/// thread's current policy, `sched_nice` to the current nice value, and
/// `sched_priority=0` (ONCRIX maps priority into the nice/level axis only).
///
/// `size` must be `>= 48` (version-0 minimum); `flags` must be `0`.
///
/// Returns `0` on success, `-22` (`EINVAL`) for bad `size`/`flags`,
/// `-14` (`EFAULT`) for a non-canonical `attr`, `-3` (`ESRCH`) if
/// there is no current thread.
///
/// # Safety
///
/// See [`sys_sched_setattr`] regarding the pointer and dispatch invariants.
pub unsafe fn sys_sched_getattr(_pid: i64, attr: u64, size: u64, flags: i64) -> i64 {
    if flags != 0 {
        return -22; // EINVAL
    }
    if size < SCHED_ATTR_SIZE_V0 as u64 {
        return -22; // EINVAL
    }
    // Span- and backed-window-validate the full 48-byte `struct sched_attr`
    // write.
    if crate::uaccess::verify_user_access(attr, SCHED_ATTR_SIZE_V0 as u64, true).is_err() {
        return -14; // EFAULT
    }

    // SAFETY: SYSCALL dispatch context — exclusive scheduler access.
    let (pol, nice) = match unsafe { current_thread_mut() } {
        Some(t) => (t.policy().as_raw() as u32, t.priority().to_nice()),
        None => return -3, // ESRCH
    };

    let out = RawSchedAttr {
        size: SCHED_ATTR_SIZE_V0,
        sched_policy: pol,
        sched_flags: 0,
        sched_nice: nice,
        sched_priority: 0,
        sched_runtime: 0,
        sched_deadline: 0,
        sched_period: 0,
    };

    // SAFETY: the full 48-byte span at `attr` was validated above.  We write
    // 48 bytes (version-0 sched_attr); an unmapped page faults into the user
    // handler (SIGSEGV).
    unsafe {
        core::ptr::write_unaligned(attr as *mut RawSchedAttr, out);
    }
    0
}
