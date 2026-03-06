// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Inter-Process Communication primitives for the ONCRIX operating system.
//!
//! Implements synchronous and asynchronous message passing, shared memory
//! regions, and capability-based endpoint management. IPC is the backbone
//! of the microkernel architecture, enabling communication between
//! user-space services.

#![no_std]
