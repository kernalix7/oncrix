// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Bootloader and early initialization for the ONCRIX operating system.
//!
//! Handles boot protocol negotiation, early hardware initialization,
//! memory map parsing, and handoff to the kernel entry point.
//!
//! # Modules
//!
//! - [`boot_info`] — Boot information passed from bootloader to kernel
//! - [`memory_map`] — Physical memory map types

#![no_std]

pub mod boot_info;
pub mod memory_map;
