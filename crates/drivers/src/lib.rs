// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! User-space device drivers for the ONCRIX operating system.
//!
//! In the microkernel architecture, device drivers run in user space
//! for fault isolation. This crate provides the driver framework,
//! device registration, and common driver interfaces.

#![no_std]
