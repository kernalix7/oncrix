// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Process and thread management for the ONCRIX operating system.
//!
//! Implements process creation, destruction, scheduling, and thread
//! lifecycle management. Includes the microkernel task scheduler
//! with priority-based preemptive scheduling.
//!
//! # Modules
//!
//! - [`cred`] — Process credentials (UID/GID, supplementary groups)
//! - [`pid`] — `Pid` and `Tid` newtypes, atomic ID allocation
//! - [`process`] — `Process` struct and lifecycle
//! - [`rusage`] — Resource usage accounting (`getrusage`, `times`)
//! - [`thread`] — `Thread` struct, state, and priority

#![no_std]

pub mod affinity;
pub mod clone;
pub mod coredump;
pub mod cred;
pub mod fork;
pub mod group;
pub mod namespace;
pub mod pid;
pub mod process;
pub mod ptrace;
pub mod rusage;
pub mod scheduler;
pub mod signal;
pub mod table;
pub mod thread;
