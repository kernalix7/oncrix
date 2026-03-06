// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hardware mailbox abstraction for inter-processor communication.
//!
//! Many SoCs include a hardware mailbox (or "message unit") that allows the
//! application processor to signal a coprocessor (e.g., a Cortex-M core,
//! DSP, or secure enclave) and exchange small data payloads without shared
//! memory. This module provides a HAL-level abstraction over such hardware.

use oncrix_lib::{Error, Result};

/// Maximum payload size in 32-bit words.
pub const MAILBOX_MAX_WORDS: usize = 4;

/// Maximum number of channels per mailbox controller.
pub const MAILBOX_MAX_CHANNELS: usize = 8;

/// A single mailbox message (up to [`MAILBOX_MAX_WORDS`] × 32 bits).
#[derive(Debug, Clone, Copy, Default)]
pub struct MailboxMessage {
    /// Number of valid words in `data`.
    pub len: usize,
    /// Message payload.
    pub data: [u32; MAILBOX_MAX_WORDS],
}

impl MailboxMessage {
    /// Creates a new empty message.
    pub const fn new() -> Self {
        Self {
            len: 0,
            data: [0u32; MAILBOX_MAX_WORDS],
        }
    }

    /// Creates a single-word message.
    pub const fn word(val: u32) -> Self {
        let mut data = [0u32; MAILBOX_MAX_WORDS];
        data[0] = val;
        Self { len: 1, data }
    }
}

/// Mailbox channel state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelState {
    /// Channel is idle and ready to send.
    Idle,
    /// Message sent; waiting for acknowledgement from remote.
    Pending,
    /// Remote side is transmitting to us.
    Receiving,
    /// Channel is in an error state.
    Faulted,
}

/// Hardware mailbox channel.
#[derive(Debug)]
pub struct MailboxChannel {
    /// Channel index within the controller.
    pub index: usize,
    /// Current channel state.
    pub state: ChannelState,
    /// Received message (valid when `state == Receiving`).
    pub rx_msg: MailboxMessage,
}

impl MailboxChannel {
    /// Creates a new idle channel.
    pub const fn new(index: usize) -> Self {
        Self {
            index,
            state: ChannelState::Idle,
            rx_msg: MailboxMessage::new(),
        }
    }
}

/// Hardware mailbox controller register offsets (generic ARM-style layout).
///
/// Concrete hardware may use different offsets; override in platform code.
struct Regs;

impl Regs {
    /// Interrupt status register (read-clear).
    const INTR_STAT: usize = 0x00;
    /// Interrupt mask register.
    const INTR_MASK: usize = 0x04;
    /// Interrupt clear register.
    const INTR_CLR: usize = 0x08;
    /// Transmit data register base (one per channel, stride 0x04).
    const TX_DATA: usize = 0x40;
    /// Receive data register base (one per channel, stride 0x04).
    const RX_DATA: usize = 0x80;
}

/// Hardware mailbox controller.
///
/// # Safety
///
/// All MMIO accesses use `read/write_volatile`. The caller must map the MMIO
/// region at `base` before constructing this struct.
pub struct MailboxController {
    /// MMIO base address of the mailbox controller.
    base: usize,
    /// Number of channels provided by this controller.
    num_channels: usize,
    /// Per-channel state.
    channels: [MailboxChannel; MAILBOX_MAX_CHANNELS],
}

impl MailboxController {
    /// Creates a new mailbox controller.
    ///
    /// # Arguments
    ///
    /// * `base` — MMIO base address (must be mapped).
    /// * `num_channels` — Number of channels (≤ [`MAILBOX_MAX_CHANNELS`]).
    pub const fn new(base: usize, num_channels: usize) -> Self {
        Self {
            base,
            num_channels,
            channels: [const {
                MailboxChannel {
                    index: 0,
                    state: ChannelState::Idle,
                    rx_msg: MailboxMessage::new(),
                }
            }; MAILBOX_MAX_CHANNELS],
        }
    }

    /// Initialises the mailbox: unmasks all channel interrupts.
    pub fn init(&mut self) -> Result<()> {
        if self.num_channels == 0 || self.num_channels > MAILBOX_MAX_CHANNELS {
            return Err(Error::InvalidArgument);
        }
        // Assign channel indices and unmask interrupt bits.
        for i in 0..self.num_channels {
            self.channels[i].index = i;
        }
        // Unmask all configured channels.
        let mask: u32 = !((1u32 << self.num_channels).wrapping_sub(1));
        self.mmio_write32(Regs::INTR_MASK, mask);
        Ok(())
    }

    /// Sends a message on `channel`.
    ///
    /// Fails with [`Error::Busy`] if the channel is not idle.
    pub fn send(&mut self, channel: usize, msg: &MailboxMessage) -> Result<()> {
        self.check_channel(channel)?;
        if self.channels[channel].state != ChannelState::Idle {
            return Err(Error::Busy);
        }
        if msg.len == 0 || msg.len > MAILBOX_MAX_WORDS {
            return Err(Error::InvalidArgument);
        }
        // Write payload words into TX FIFO registers.
        let tx_base = Regs::TX_DATA + channel * 0x04;
        for (i, &word) in msg.data[..msg.len].iter().enumerate() {
            self.mmio_write32(tx_base + i * 4, word);
        }
        // Trigger channel interrupt to signal remote side.
        self.mmio_write32(Regs::INTR_CLR, 1 << channel);
        self.channels[channel].state = ChannelState::Pending;
        Ok(())
    }

    /// Polls for a received message on `channel`.
    ///
    /// Returns `None` if no message is available.
    pub fn poll_rx(&mut self, channel: usize) -> Result<Option<MailboxMessage>> {
        self.check_channel(channel)?;
        let stat = self.mmio_read32(Regs::INTR_STAT);
        if (stat & (1 << channel)) == 0 {
            return Ok(None);
        }
        // Read payload.
        let rx_base = Regs::RX_DATA + channel * 0x04;
        let mut msg = MailboxMessage::new();
        msg.len = MAILBOX_MAX_WORDS;
        for i in 0..MAILBOX_MAX_WORDS {
            msg.data[i] = self.mmio_read32(rx_base + i * 4);
        }
        // Clear interrupt.
        self.mmio_write32(Regs::INTR_CLR, 1 << channel);
        self.channels[channel].state = ChannelState::Idle;
        Ok(Some(msg))
    }

    /// Handles an incoming interrupt: returns the set of channels with activity.
    pub fn handle_irq(&mut self) -> u32 {
        let stat = self.mmio_read32(Regs::INTR_STAT);
        // Clear all pending bits.
        self.mmio_write32(Regs::INTR_CLR, stat);
        for i in 0..self.num_channels {
            if (stat & (1 << i)) != 0 {
                self.channels[i].state = ChannelState::Receiving;
            }
        }
        stat
    }

    /// Returns the number of channels.
    pub fn num_channels(&self) -> usize {
        self.num_channels
    }

    /// Returns the state of `channel`.
    pub fn channel_state(&self, channel: usize) -> Result<ChannelState> {
        self.check_channel(channel)?;
        Ok(self.channels[channel].state)
    }

    // ---- private helpers ----

    fn check_channel(&self, channel: usize) -> Result<()> {
        if channel >= self.num_channels {
            Err(Error::InvalidArgument)
        } else {
            Ok(())
        }
    }

    fn mmio_read32(&self, offset: usize) -> u32 {
        let ptr = (self.base + offset) as *const u32;
        // SAFETY: base is a valid mapped MMIO address; volatile prevents caching.
        unsafe { core::ptr::read_volatile(ptr) }
    }

    fn mmio_write32(&self, offset: usize, value: u32) {
        let ptr = (self.base + offset) as *mut u32;
        // SAFETY: base is a valid mapped MMIO address; volatile prevents caching.
        unsafe { core::ptr::write_volatile(ptr, value) }
    }
}

/// Trait for platform-specific mailbox channel callbacks.
pub trait MailboxClient {
    /// Called when a message is received on `channel`.
    fn message_received(&mut self, channel: usize, msg: &MailboxMessage);

    /// Called when the remote side acknowledges our sent message.
    fn tx_done(&mut self, channel: usize);
}

/// Returns a textual description of a [`ChannelState`].
pub fn channel_state_name(state: ChannelState) -> &'static str {
    match state {
        ChannelState::Idle => "idle",
        ChannelState::Pending => "pending",
        ChannelState::Receiving => "receiving",
        ChannelState::Faulted => "faulted",
    }
}
