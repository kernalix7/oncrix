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

use crate::current::{current_thread_mut, yield_now};
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
pub unsafe fn sys_setpriority(which: i64, _who: i64, prio: i64) -> i64 {
    // Only PRIO_PROCESS is meaningfully distinct today; PGRP/USER are
    // accepted as aliases for "current thread". Reject unknown selectors.
    if which != PRIO_PROCESS && which != _PRIO_PGRP && which != _PRIO_USER {
        return -22; // EINVAL
    }
    let nice = clamp_nice(prio as i32);
    // SAFETY: SYSCALL dispatch context — exclusive scheduler access.
    match unsafe { current_thread_mut() } {
        Some(t) => {
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
    // SAFETY: SYSCALL dispatch context — exclusive scheduler access.
    match unsafe { current_thread_mut() } {
        Some(t) => {
            let cur = t.priority().to_nice();
            let new = clamp_nice(cur.saturating_add(inc as i32));
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
pub unsafe fn sys_sched_setscheduler(_pid: i64, policy: i64, param: u64) -> i64 {
    let Some(pol) = SchedPolicy::from_raw(policy as i32) else {
        return -22; // EINVAL
    };

    // Optionally read sched_priority from the param struct.
    let new_priority = if param != 0 {
        if param >= 0xFFFF_8000_0000_0000 {
            return -14; // EFAULT: non-canonical / kernel-half pointer
        }
        // SAFETY: `param` is canonical user space (checked above). The
        // first field of `struct sched_param` is `int sched_priority`.
        // An unmapped page faults into the user fault handler (SIGSEGV)
        // rather than corrupting the kernel; we only read 4 bytes.
        let sched_priority = unsafe { core::ptr::read_unaligned(param as *const i32) };
        Some(sched_priority_to_priority(sched_priority))
    } else {
        None
    };

    // SAFETY: SYSCALL dispatch context — exclusive scheduler access.
    match unsafe { current_thread_mut() } {
        Some(t) => {
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
    if param == 0 || param >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    // SAFETY: SYSCALL dispatch context — exclusive scheduler access.
    let prio = match unsafe { current_thread_mut() } {
        Some(t) => t.priority(),
        None => return -3, // ESRCH
    };
    let sched_priority = priority_to_sched_priority(prio);
    // SAFETY: `param` is canonical user space (checked above). We write
    // the leading `int sched_priority` field only; an unmapped page
    // faults into the user handler (SIGSEGV).
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
pub unsafe fn sys_sched_setparam(_pid: i64, param: u64) -> i64 {
    if param == 0 || param >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    // SAFETY: canonical user pointer (checked); read 4 bytes only.
    let sched_priority = unsafe { core::ptr::read_unaligned(param as *const i32) };
    let prio = sched_priority_to_priority(sched_priority);
    // SAFETY: SYSCALL dispatch context — exclusive scheduler access.
    match unsafe { current_thread_mut() } {
        Some(t) => {
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
