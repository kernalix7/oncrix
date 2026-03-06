// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IPC endpoint management.

use crate::message::{EndpointId, Message};
use oncrix_lib::Result;

/// IPC endpoint state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointState {
    /// Endpoint is idle, not waiting for a message.
    Idle,
    /// Endpoint is blocked waiting to send a message.
    Sending,
    /// Endpoint is blocked waiting to receive a message.
    Receiving,
}

/// An IPC endpoint through which processes send and receive messages.
///
/// In the ONCRIX microkernel, endpoints are the fundamental IPC
/// primitive. A process creates an endpoint, then uses it to
/// participate in synchronous send/receive/reply protocols.
#[derive(Debug)]
pub struct Endpoint {
    /// Unique identifier for this endpoint.
    id: EndpointId,
    /// Current state.
    state: EndpointState,
}

impl Endpoint {
    /// Create a new endpoint with the given identifier.
    pub const fn new(id: EndpointId) -> Self {
        Self {
            id,
            state: EndpointState::Idle,
        }
    }

    /// Return the endpoint identifier.
    pub const fn id(&self) -> EndpointId {
        self.id
    }

    /// Return the current endpoint state.
    pub const fn state(&self) -> EndpointState {
        self.state
    }
}

/// Synchronous IPC operations.
///
/// These are the core IPC primitives of the ONCRIX microkernel.
/// Actual implementations will be provided by the kernel's IPC
/// subsystem; this trait defines the interface.
pub trait SyncIpc {
    /// Send a message and block until the receiver accepts it.
    fn send(&mut self, msg: &Message) -> Result<()>;

    /// Block until a message arrives on this endpoint.
    fn receive(&mut self, endpoint: &Endpoint) -> Result<Message>;

    /// Reply to a previously received message.
    fn reply(&mut self, msg: &Message) -> Result<()>;

    /// Combined send-and-receive: send a message, then block
    /// waiting for a reply on the same endpoint.
    fn call(&mut self, msg: &Message, reply_endpoint: &Endpoint) -> Result<Message>;
}
