// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IPC message types for synchronous message passing.

use core::fmt;

/// Maximum inline payload size in bytes.
///
/// Messages larger than this must use shared memory regions.
pub const MAX_INLINE_PAYLOAD: usize = 256;

/// Unique endpoint identifier for IPC communication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct EndpointId(u64);

impl EndpointId {
    /// Create a new endpoint identifier.
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Return the raw identifier value.
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for EndpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Endpoint({})", self.0)
    }
}

/// IPC message header.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct MessageHeader {
    /// Sender endpoint.
    pub sender: EndpointId,
    /// Destination endpoint.
    pub receiver: EndpointId,
    /// Message tag (protocol-defined operation code).
    pub tag: u32,
    /// Length of the payload in bytes.
    pub payload_len: u32,
}

/// An IPC message with an inline payload buffer.
///
/// For the synchronous IPC model (send/receive/reply), the kernel
/// copies the message between sender and receiver address spaces.
#[derive(Clone)]
pub struct Message {
    /// Message header.
    pub header: MessageHeader,
    /// Inline payload data.
    payload: [u8; MAX_INLINE_PAYLOAD],
}

impl Message {
    /// Create a new message with the given header and no payload.
    pub const fn new(sender: EndpointId, receiver: EndpointId, tag: u32) -> Self {
        Self {
            header: MessageHeader {
                sender,
                receiver,
                tag,
                payload_len: 0,
            },
            payload: [0u8; MAX_INLINE_PAYLOAD],
        }
    }

    /// Set the payload from a byte slice.
    ///
    /// Returns `Err(InvalidArgument)` if the slice exceeds
    /// `MAX_INLINE_PAYLOAD`.
    pub fn set_payload(&mut self, data: &[u8]) -> oncrix_lib::Result<()> {
        if data.len() > MAX_INLINE_PAYLOAD {
            return Err(oncrix_lib::Error::InvalidArgument);
        }
        self.payload[..data.len()].copy_from_slice(data);
        self.header.payload_len = data.len() as u32;
        Ok(())
    }

    /// Return the payload as a byte slice.
    ///
    /// Clamps `payload_len` to `MAX_INLINE_PAYLOAD` to prevent
    /// out-of-bounds access if the header was corrupted.
    pub fn payload(&self) -> &[u8] {
        let len = (self.header.payload_len as usize).min(MAX_INLINE_PAYLOAD);
        &self.payload[..len]
    }

    /// Return the message tag.
    pub const fn tag(&self) -> u32 {
        self.header.tag
    }
}

impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message")
            .field("sender", &self.header.sender)
            .field("receiver", &self.header.receiver)
            .field("tag", &self.header.tag)
            .field("payload_len", &self.header.payload_len)
            .finish()
    }
}
