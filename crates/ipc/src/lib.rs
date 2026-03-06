// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Inter-Process Communication primitives for the ONCRIX operating system.
//!
//! Implements synchronous and asynchronous message passing, shared memory
//! regions, and capability-based endpoint management. IPC is the backbone
//! of the microkernel architecture, enabling communication between
//! user-space services.
//!
//! # Modules
//!
//! - [`message`] — `Message`, `MessageHeader`, `EndpointId`
//! - [`endpoint`] — `Endpoint`, `SyncIpc` trait

#![no_std]

pub mod async_ipc;
pub mod channel;
pub mod endpoint;
pub mod eventfd;
pub mod message;
pub mod mqueue;
pub mod pipe_buf;
pub mod shm_ipc;
pub mod unix_socket;

#[allow(dead_code, clippy::all)]
pub mod binder_ipc;

// --- Batch 11 ---
#[allow(dead_code, clippy::all)]
pub mod tipc;
