// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX-compatible system call interface for the ONCRIX operating system.
//!
//! Defines the system call ABI, argument validation, and dispatching.
//! All user-space pointers are validated before kernel-space access.
//! Implements POSIX-compliant syscall semantics for compatibility.

#![no_std]
