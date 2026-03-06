// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Process and thread management for the ONCRIX operating system.
//!
//! Implements process creation, destruction, scheduling, and thread
//! lifecycle management. Includes the microkernel task scheduler
//! with priority-based preemptive scheduling.

#![no_std]
