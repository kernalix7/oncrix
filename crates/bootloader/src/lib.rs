// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Bootloader and early initialization for the ONCRIX operating system.
//!
//! Handles boot protocol negotiation, early hardware initialization,
//! memory map parsing, and handoff to the kernel entry point.

#![no_std]
