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

use crate::current::current_thread_mut;
use oncrix_process::thread::Priority;

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
