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

#[allow(dead_code, clippy::all)]
pub mod tipc;

#[allow(dead_code, clippy::all)]
pub mod vsock;

#[allow(dead_code, clippy::all)]
pub mod kcm;

#[allow(dead_code, clippy::all)]
pub mod netlink_ipc;
#[allow(dead_code, clippy::all)]
pub mod posix_sem;

#[allow(dead_code, clippy::all)]
pub mod dbus_bus;
#[allow(dead_code, clippy::all)]
pub mod rpmsg;

#[allow(dead_code, clippy::all)]
pub mod ipc_namespace;
#[allow(dead_code, clippy::all)]
pub mod ipc_shm_ext;

#[allow(dead_code, clippy::all)]
pub mod ipc_msg;
#[allow(dead_code, clippy::all)]
pub mod ipc_sem;

#[allow(dead_code, clippy::all)]
pub mod ipc_audit;
#[allow(dead_code, clippy::all)]
pub mod ipc_compat;

#[allow(dead_code, clippy::all)]
pub mod ipc_mq_notify;
#[allow(dead_code, clippy::all)]
pub mod ipc_socket_pair;
