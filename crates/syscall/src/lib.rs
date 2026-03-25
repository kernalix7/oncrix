// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX-compatible system call interface for the ONCRIX operating system.
//!
//! Defines the system call ABI, argument validation, and dispatching.
//! All user-space pointers are validated before kernel-space access.
//! Implements POSIX-compliant syscall semantics for compatibility.
//!
//! # Modules
//!
//! - [`number`] — POSIX syscall number constants
//! - [`dispatch`] — Syscall dispatcher (number → handler)
//! - [`handler`] — Individual syscall implementations

#![no_std]

pub mod clock;
pub mod copy_range;
pub mod dispatch;
pub mod epoll_calls;
pub mod execveat;
pub mod handler;
pub mod ioctl;
pub mod libc;
pub mod memfd;
pub mod mmap_calls;
#[allow(dead_code, clippy::all)]
pub mod mount_api;
pub mod number;
pub mod poll;
pub mod prctl;
pub mod process_calls;
pub mod rename;
pub mod resource;
pub mod signalfd;
pub mod socket_calls;
pub mod statx;
pub mod waitid;

// --- Batch 5 ---
#[allow(dead_code, clippy::all)]
pub mod close_range;
#[allow(dead_code, clippy::all)]
pub mod openat2;

// --- Batch 6 ---
#[allow(dead_code, clippy::all)]
pub mod futex2;
#[allow(dead_code, clippy::all)]
pub mod io_uring_setup;
#[allow(dead_code, clippy::all)]
pub mod landlock_calls;

// --- Batch 7 ---
#[allow(dead_code, clippy::all)]
pub mod faccessat2;
#[allow(dead_code, clippy::all)]
pub mod pidfd_calls;
#[allow(dead_code, clippy::all)]
pub mod sched_calls;

// --- Batch 8 ---
#[allow(dead_code, clippy::all)]
pub mod io_pgetevents;
#[allow(dead_code, clippy::all)]
pub mod preadwritev2;
#[allow(dead_code, clippy::all)]
pub mod process_madvise;

// --- Batch 9 ---
#[allow(dead_code, clippy::all)]
pub mod pkey;
#[allow(dead_code, clippy::all)]
pub mod process_vm;
#[allow(dead_code, clippy::all)]
pub mod userfaultfd_calls;

// --- Batch 10 ---
#[allow(dead_code, clippy::all)]
pub mod mount_new_api;
#[allow(dead_code, clippy::all)]
pub mod pidfd_ext_calls;
#[allow(dead_code, clippy::all)]
pub mod splice_calls;

// --- Batch 11 ---
#[allow(dead_code, clippy::all)]
pub mod cachestat;
#[allow(dead_code, clippy::all)]
pub mod io_uring_enter;

// --- Batch 12 ---
#[allow(dead_code, clippy::all)]
pub mod epoll_pwait2;
#[allow(dead_code, clippy::all)]
pub mod listxattr_calls;
#[allow(dead_code, clippy::all)]
pub mod quotactl;

// --- Batch 13 ---
#[allow(dead_code, clippy::all)]
pub mod fchmodat2;
#[allow(dead_code, clippy::all)]
pub mod io_uring_cmd;
#[allow(dead_code, clippy::all)]
pub mod mseal;

// --- Batch 14 ---
#[allow(dead_code, clippy::all)]
pub mod eventfd_calls;
#[allow(dead_code, clippy::all)]
pub mod futex_waitv;
#[allow(dead_code, clippy::all)]
pub mod map_shadow_stack;
#[allow(dead_code, clippy::all)]
pub mod membarrier;
#[allow(dead_code, clippy::all)]
pub mod signalfd_ext;
#[allow(dead_code, clippy::all)]
pub mod timerfd_calls;

// --- Batch 15 ---
#[allow(dead_code, clippy::all)]
pub mod bpf_calls;
#[allow(dead_code, clippy::all)]
pub mod io_uring_register;
#[allow(dead_code, clippy::all)]
pub mod kcmp;
#[allow(dead_code, clippy::all)]
pub mod mempolicy;
#[allow(dead_code, clippy::all)]
pub mod perf_event_open;
#[allow(dead_code, clippy::all)]
pub mod rseq_calls;
