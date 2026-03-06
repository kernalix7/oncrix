// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Synchronous IPC channel implementation.
//!
//! A channel connects exactly two endpoints. Messages are buffered in
//! a fixed-size ring buffer. When the buffer is full, send blocks
//! (returns `WouldBlock`); when empty, receive blocks.
//!
//! In a full kernel, blocking would suspend the calling thread.
//! This initial implementation returns errors for non-blocking
//! semantics, letting the scheduler retry.

use crate::message::{EndpointId, MAX_INLINE_PAYLOAD, Message};
use oncrix_lib::{Error, Result};

/// Channel ring buffer capacity (number of messages).
const CHANNEL_CAPACITY: usize = 16;

/// A synchronous IPC channel with a fixed-size message ring buffer.
pub struct Channel {
    /// Source endpoint.
    src: EndpointId,
    /// Destination endpoint.
    dst: EndpointId,
    /// Ring buffer of messages.
    buffer: [MessageSlot; CHANNEL_CAPACITY],
    /// Write index (next slot to write).
    head: usize,
    /// Read index (next slot to read).
    tail: usize,
    /// Number of messages in the buffer.
    count: usize,
}

/// A slot in the channel ring buffer.
#[derive(Clone)]
struct MessageSlot {
    /// Whether this slot contains a valid message.
    occupied: bool,
    /// Sender endpoint.
    sender: EndpointId,
    /// Message tag.
    tag: u32,
    /// Payload length.
    payload_len: u32,
    /// Payload data.
    payload: [u8; MAX_INLINE_PAYLOAD],
}

impl MessageSlot {
    /// Create an empty slot.
    const fn empty() -> Self {
        Self {
            occupied: false,
            sender: EndpointId::new(0),
            tag: 0,
            payload_len: 0,
            payload: [0u8; MAX_INLINE_PAYLOAD],
        }
    }
}

impl Channel {
    /// Create a new channel between two endpoints.
    pub const fn new(src: EndpointId, dst: EndpointId) -> Self {
        Self {
            src,
            dst,
            buffer: [const { MessageSlot::empty() }; CHANNEL_CAPACITY],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Return the source endpoint.
    pub const fn src(&self) -> EndpointId {
        self.src
    }

    /// Return the destination endpoint.
    pub const fn dst(&self) -> EndpointId {
        self.dst
    }

    /// Send a message into the channel.
    ///
    /// Returns `WouldBlock` if the channel is full.
    pub fn send(&mut self, msg: &Message) -> Result<()> {
        if self.count >= CHANNEL_CAPACITY {
            return Err(Error::WouldBlock);
        }

        let slot = &mut self.buffer[self.head];
        slot.occupied = true;
        slot.sender = msg.header.sender;
        slot.tag = msg.header.tag;
        // Clamp payload_len to MAX_INLINE_PAYLOAD to prevent OOB.
        let len = (msg.header.payload_len as usize).min(MAX_INLINE_PAYLOAD);
        slot.payload_len = len as u32;
        slot.payload[..len].copy_from_slice(&msg.payload()[..len]);

        self.head = (self.head + 1) % CHANNEL_CAPACITY;
        self.count += 1;
        Ok(())
    }

    /// Receive a message from the channel.
    ///
    /// Returns `WouldBlock` if the channel is empty.
    pub fn receive(&mut self) -> Result<Message> {
        if self.count == 0 {
            return Err(Error::WouldBlock);
        }

        let slot = &self.buffer[self.tail];
        let mut msg = Message::new(slot.sender, self.dst, slot.tag);
        let len = (slot.payload_len as usize).min(MAX_INLINE_PAYLOAD);
        if len > 0 {
            msg.set_payload(&slot.payload[..len])?;
        }

        self.buffer[self.tail] = MessageSlot::empty();
        self.tail = (self.tail + 1) % CHANNEL_CAPACITY;
        self.count -= 1;
        Ok(msg)
    }

    /// Return the number of messages currently buffered.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Check if the channel buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Check if the channel buffer is full.
    pub fn is_full(&self) -> bool {
        self.count >= CHANNEL_CAPACITY
    }
}

/// Maximum number of channels in the system.
const MAX_CHANNELS: usize = 64;

/// Global channel registry.
///
/// Maps endpoint pairs to channels. A production kernel would use
/// a hash map; this fixed-size array suffices for early boot.
pub struct ChannelRegistry {
    /// Channel slots.
    channels: [Option<Channel>; MAX_CHANNELS],
    /// Number of active channels.
    count: usize,
}

impl Default for ChannelRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ChannelRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        const NONE: Option<Channel> = None;
        Self {
            channels: [NONE; MAX_CHANNELS],
            count: 0,
        }
    }

    /// Create a new channel between two endpoints.
    pub fn create(&mut self, src: EndpointId, dst: EndpointId) -> Result<()> {
        if self.count >= MAX_CHANNELS {
            return Err(Error::OutOfMemory);
        }
        for slot in self.channels.iter_mut() {
            if slot.is_none() {
                *slot = Some(Channel::new(src, dst));
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a channel by source and destination endpoints.
    pub fn find(&self, src: EndpointId, dst: EndpointId) -> Option<&Channel> {
        self.channels
            .iter()
            .filter_map(|s| s.as_ref())
            .find(|ch| ch.src() == src && ch.dst() == dst)
    }

    /// Find a mutable channel by source and destination endpoints.
    pub fn find_mut(&mut self, src: EndpointId, dst: EndpointId) -> Option<&mut Channel> {
        self.channels
            .iter_mut()
            .filter_map(|s| s.as_mut())
            .find(|ch| ch.src() == src && ch.dst() == dst)
    }

    /// Return the number of active channels.
    pub fn count(&self) -> usize {
        self.count
    }
}
