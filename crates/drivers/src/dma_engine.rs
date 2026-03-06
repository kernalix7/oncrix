// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DMA engine driver framework.
//!
//! Provides abstractions for system DMA controllers (Intel CBDMA / IOAT,
//! generic ISA DMA) and a channel management framework for driver use.
//! Supports memory-to-memory copy, fill, and scatter/gather operations.

use oncrix_lib::{Error, Result};

/// ISA DMA controller ports (8237A compatible).
const DMA1_BASE: u16 = 0x00; // Channels 0-3 (8-bit)
const DMA2_BASE: u16 = 0xC0; // Channels 4-7 (16-bit)
const DMA1_STATUS: u16 = 0x08;
const DMA1_CMD: u16 = 0x08;
const DMA1_REQ: u16 = 0x09;
const DMA1_MASK: u16 = 0x0A;
const DMA1_MODE: u16 = 0x0B;
const DMA1_CLEAR_FF: u16 = 0x0C;
const DMA1_RESET: u16 = 0x0D;
const DMA1_CLR_MASK: u16 = 0x0E;
const DMA2_MASK: u16 = 0xD4;
const DMA2_MODE: u16 = 0xD6;
const DMA2_CLEAR_FF: u16 = 0xD8;

/// DMA channel address and count ports (channels 0-3).
const DMA_CH_ADDR: [u16; 4] = [0x00, 0x02, 0x04, 0x06];
const DMA_CH_COUNT: [u16; 4] = [0x01, 0x03, 0x05, 0x07];
const DMA_CH_PAGE: [u16; 4] = [0x87, 0x83, 0x81, 0x82];

/// DMA mode register bits.
const DMA_MODE_DEMAND: u8 = 0 << 6;
const DMA_MODE_SINGLE: u8 = 1 << 6;
const DMA_MODE_BLOCK: u8 = 2 << 6;
const DMA_MODE_CASCADE: u8 = 3 << 6;
const DMA_MODE_DECREMENT: u8 = 1 << 5;
const DMA_MODE_AUTO_INIT: u8 = 1 << 4;
const DMA_MODE_READ: u8 = 1 << 3; // Transfer from memory to device
const DMA_MODE_WRITE: u8 = 0 << 3; // Transfer from device to memory

/// Maximum number of managed DMA channels.
const MAX_CHANNELS: usize = 8;

/// Maximum scatter/gather list entries per transfer.
const MAX_SGL_ENTRIES: usize = 32;

/// DMA transfer direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DmaDirection {
    /// Memory → Device (DMA read from memory).
    ToDevice,
    /// Device → Memory (DMA write to memory).
    FromDevice,
    /// Memory → Memory.
    MemToMem,
}

/// A scatter/gather list entry.
#[derive(Clone, Copy, Debug, Default)]
pub struct SglEntry {
    /// Physical address of this segment.
    pub phys_addr: u64,
    /// Length of this segment in bytes.
    pub len: u32,
}

/// DMA channel state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChannelState {
    /// Channel is free.
    Free,
    /// Channel is allocated but idle.
    Idle,
    /// Channel is actively transferring.
    Active,
}

/// A single DMA channel.
#[derive(Clone, Copy, Debug)]
pub struct DmaChannel {
    /// Channel index (0–7).
    pub index: usize,
    /// Current state.
    pub state: ChannelState,
    /// Channel width in bits (8 or 16).
    pub width: u8,
    /// Driver tag that owns this channel.
    pub owner: u32,
}

impl DmaChannel {
    /// Create a new free channel.
    pub const fn new(index: usize, width: u8) -> Self {
        Self {
            index,
            state: ChannelState::Free,
            width,
            owner: 0,
        }
    }
}

/// DMA engine driver (manages ISA DMA channels 0-7).
pub struct DmaEngine {
    /// Channel state for all 8 ISA DMA channels.
    channels: [DmaChannel; MAX_CHANNELS],
}

impl DmaEngine {
    /// Create a new DMA engine driver.
    pub fn new() -> Self {
        Self {
            channels: [
                DmaChannel::new(0, 8),
                DmaChannel::new(1, 8),
                DmaChannel::new(2, 8),
                DmaChannel::new(3, 8),
                DmaChannel::new(4, 16), // Channel 4 is cascade for channels 0-3
                DmaChannel::new(5, 16),
                DmaChannel::new(6, 16),
                DmaChannel::new(7, 16),
            ],
        }
    }

    /// Initialize the 8237A DMA controllers.
    pub fn init(&mut self) -> Result<()> {
        // Reset both DMA controllers.
        self.write_port(DMA1_RESET, 0xFF);
        self.write_port(DMA2_MASK, 0x0F); // Mask all channels 4-7.
        // Enable cascade on channel 4 (connects DMA1 to DMA2).
        self.write_port(DMA2_MODE, DMA_MODE_CASCADE | 0x00); // Channel 4 = cascade
        self.write_port(DMA2_MASK, 0x0E); // Unmask channel 4.
        Ok(())
    }

    /// Allocate a DMA channel. Returns the channel index.
    pub fn alloc_channel(&mut self, width: u8, owner: u32) -> Result<usize> {
        for ch in self.channels.iter_mut() {
            if ch.state == ChannelState::Free && ch.width == width && ch.index != 4 {
                ch.state = ChannelState::Idle;
                ch.owner = owner;
                return Ok(ch.index);
            }
        }
        Err(Error::Busy)
    }

    /// Release a previously allocated channel.
    pub fn free_channel(&mut self, index: usize) -> Result<()> {
        if index >= MAX_CHANNELS {
            return Err(Error::InvalidArgument);
        }
        if self.channels[index].state == ChannelState::Active {
            self.mask_channel(index);
        }
        self.channels[index].state = ChannelState::Free;
        self.channels[index].owner = 0;
        Ok(())
    }

    /// Program a DMA channel for a single-mode transfer.
    ///
    /// # Arguments
    /// - `channel`: channel index (0–3 for 8-bit, 5–7 for 16-bit)
    /// - `phys_addr`: physical address of the DMA buffer
    /// - `len`: number of bytes to transfer (max 65535 for 8-bit channels)
    /// - `dir`: transfer direction
    pub fn program_transfer(
        &mut self,
        channel: usize,
        phys_addr: u64,
        len: u32,
        dir: DmaDirection,
    ) -> Result<()> {
        if channel >= MAX_CHANNELS || channel == 4 {
            return Err(Error::InvalidArgument);
        }
        let ch = &self.channels[channel];
        if ch.state == ChannelState::Free {
            return Err(Error::InvalidArgument);
        }
        // Mask the channel during programming.
        self.mask_channel(channel);
        let mode_dir = match dir {
            DmaDirection::ToDevice => DMA_MODE_READ,
            DmaDirection::FromDevice | DmaDirection::MemToMem => DMA_MODE_WRITE,
        };
        let mode = DMA_MODE_SINGLE | mode_dir | (channel as u8 & 0x03);
        if channel < 4 {
            // 8-bit channel programming.
            self.write_port(DMA1_CLEAR_FF, 0xFF);
            self.write_port(DMA1_MODE, mode);
            let page = ((phys_addr >> 16) & 0xFF) as u8;
            let addr_lo = (phys_addr & 0xFF) as u8;
            let addr_hi = ((phys_addr >> 8) & 0xFF) as u8;
            let count = (len - 1) as u16;
            self.write_port(DMA_CH_ADDR[channel], addr_lo);
            self.write_port(DMA_CH_ADDR[channel], addr_hi);
            self.write_port(DMA_CH_PAGE[channel], page);
            self.write_port(DMA_CH_COUNT[channel], (count & 0xFF) as u8);
            self.write_port(DMA_CH_COUNT[channel], ((count >> 8) & 0xFF) as u8);
        }
        // Unmask to start the transfer.
        self.unmask_channel(channel);
        self.channels[channel].state = ChannelState::Active;
        Ok(())
    }

    /// Check whether a channel has completed its transfer.
    pub fn is_transfer_complete(&self, channel: usize) -> bool {
        if channel >= MAX_CHANNELS {
            return false;
        }
        let sts = self.read_port(DMA1_STATUS);
        (sts >> channel) & 0x01 != 0
    }

    /// Return a reference to the channel descriptor.
    pub fn channel(&self, index: usize) -> Option<&DmaChannel> {
        self.channels.get(index)
    }

    // --- 8237 DMA port helpers ---

    fn mask_channel(&self, channel: usize) {
        let val = 0x04 | (channel as u8 & 0x03);
        if channel < 4 {
            self.write_port(DMA1_MASK, val);
        } else {
            self.write_port(DMA2_MASK, val & 0x07);
        }
    }

    fn unmask_channel(&self, channel: usize) {
        let val = channel as u8 & 0x03;
        if channel < 4 {
            self.write_port(DMA1_MASK, val);
        } else {
            self.write_port(DMA2_MASK, val & 0x07);
        }
    }

    fn read_port(&self, port: u16) -> u8 {
        #[cfg(target_arch = "x86_64")]
        {
            let val: u8;
            // SAFETY: All ports used are standard 8237 DMA controller registers
            // present on all PC-compatible hardware.
            unsafe {
                core::arch::asm!(
                    "in al, dx",
                    in("dx") port,
                    out("al") val,
                    options(nomem, nostack)
                );
            }
            return val;
        }
        #[allow(unreachable_code)]
        0
    }

    fn write_port(&self, port: u16, val: u8) {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: Standard 8237 DMA controller ports; volatile PIO write.
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") port,
                in("al") val,
                options(nomem, nostack)
            );
        }
    }
}

impl Default for DmaEngine {
    fn default() -> Self {
        Self::new()
    }
}
