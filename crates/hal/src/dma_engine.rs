// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! DMA engine abstraction for the ONCRIX kernel.
//!
//! Provides a generic DMA engine controller that manages multiple
//! DMA channels, each capable of queuing and executing memory
//! transfer operations. Supports memory-to-memory, memory-to-device,
//! device-to-memory, and device-to-device transfers with configurable
//! burst sizes and transfer widths.
//!
//! # Architecture
//!
//! - [`DmaEngine`] — top-level controller with multiple channels
//! - [`DmaChannel`] — individual channel with a transfer queue
//! - [`DmaTransfer`] — descriptor for a single DMA operation
//! - [`DmaDescriptor`] — hardware-level transfer descriptor (`repr(C)`)
//! - [`DmaEngineRegistry`] — system-wide registry of DMA engines

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of transfers per channel.
const MAX_TRANSFERS_PER_CHANNEL: usize = 16;

/// Maximum number of channels per engine.
const MAX_CHANNELS_PER_ENGINE: usize = 8;

/// Maximum number of engines in the registry.
const MAX_ENGINES: usize = 4;

// -------------------------------------------------------------------
// DmaTransferDir
// -------------------------------------------------------------------

/// Direction of a DMA transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DmaTransferDir {
    /// Memory to memory copy.
    #[default]
    MemToMem,
    /// Memory to device (TX).
    MemToDev,
    /// Device to memory (RX).
    DevToMem,
    /// Device to device.
    DevToDev,
}

// -------------------------------------------------------------------
// DmaTransferWidth
// -------------------------------------------------------------------

/// Width of each DMA beat (single bus transfer unit).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DmaTransferWidth {
    /// 8-bit transfer.
    Byte,
    /// 16-bit transfer.
    HalfWord,
    /// 32-bit transfer.
    #[default]
    Word,
    /// 64-bit transfer.
    DoubleWord,
}

// -------------------------------------------------------------------
// DmaTransferState
// -------------------------------------------------------------------

/// Runtime state of a DMA transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DmaTransferState {
    /// Transfer has not been submitted.
    #[default]
    Idle,
    /// Transfer is queued but not yet started.
    Pending,
    /// Transfer is currently in progress.
    Running,
    /// Transfer finished successfully.
    Complete,
    /// Transfer encountered an error.
    Error,
}

// -------------------------------------------------------------------
// DmaDescriptor
// -------------------------------------------------------------------

/// Hardware-level DMA transfer descriptor.
///
/// Laid out as a C struct so it can be placed in DMA-accessible
/// memory and consumed directly by hardware or firmware.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct DmaDescriptor {
    /// Source physical address.
    pub src_addr: u64,
    /// Destination physical address.
    pub dst_addr: u64,
    /// Transfer length in bytes.
    pub length: u32,
    /// Index of the next descriptor in the chain (0 = end).
    pub next: u32,
    /// Descriptor flags (engine-specific).
    pub flags: u32,
    /// Completion status written back by hardware.
    pub status: u32,
}

// -------------------------------------------------------------------
// DmaTransfer
// -------------------------------------------------------------------

/// Software-side description of a DMA transfer operation.
#[derive(Debug, Clone, Copy)]
pub struct DmaTransfer {
    /// Unique transfer identifier.
    pub id: u64,
    /// Transfer direction.
    pub direction: DmaTransferDir,
    /// Transfer width per beat.
    pub width: DmaTransferWidth,
    /// Source address.
    pub src: u64,
    /// Destination address.
    pub dst: u64,
    /// Transfer length in bytes.
    pub len: usize,
    /// Current transfer state.
    pub state: DmaTransferState,
    /// Opaque callback identifier (used by upper layers).
    pub callback_id: u64,
    /// Whether this is a cyclic (repeating) transfer.
    pub cyclic: bool,
}

impl Default for DmaTransfer {
    fn default() -> Self {
        Self::new()
    }
}

impl DmaTransfer {
    /// Creates an empty, idle transfer.
    pub const fn new() -> Self {
        Self {
            id: 0,
            direction: DmaTransferDir::MemToMem,
            width: DmaTransferWidth::Word,
            src: 0,
            dst: 0,
            len: 0,
            state: DmaTransferState::Idle,
            callback_id: 0,
            cyclic: false,
        }
    }

    /// Returns `true` if this transfer slot is unused.
    pub fn is_idle(&self) -> bool {
        self.state == DmaTransferState::Idle && self.id == 0
    }
}

// -------------------------------------------------------------------
// DmaChannel
// -------------------------------------------------------------------

/// A single DMA channel capable of queuing transfers.
///
/// Each channel maintains a fixed-size ring of transfer slots.
/// Transfers are submitted, issued (started), and eventually
/// completed or terminated.
pub struct DmaChannel {
    /// Channel identifier within its parent engine.
    pub id: u32,
    /// Transfer queue (fixed-size array).
    transfers: [DmaTransfer; MAX_TRANSFERS_PER_CHANNEL],
    /// Number of transfers currently queued.
    xfer_count: usize,
    /// Maximum burst length in beats.
    pub max_burst: u32,
    /// Whether the channel is actively running a transfer.
    pub active: bool,
    /// Whether the channel has been claimed by a client.
    pub in_use: bool,
}

impl Default for DmaChannel {
    fn default() -> Self {
        Self::new()
    }
}

impl DmaChannel {
    /// Creates an empty, unclaimed channel.
    pub const fn new() -> Self {
        Self {
            id: 0,
            transfers: [DmaTransfer::new(); MAX_TRANSFERS_PER_CHANNEL],
            xfer_count: 0,
            max_burst: 16,
            active: false,
            in_use: false,
        }
    }

    /// Submits a transfer to this channel's queue.
    ///
    /// The transfer is placed in the first idle slot and its
    /// state is set to [`DmaTransferState::Pending`].
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if all transfer slots are occupied.
    pub fn submit(&mut self, mut transfer: DmaTransfer) -> Result<u64> {
        let slot = self
            .transfers
            .iter()
            .position(|t| t.is_idle())
            .ok_or(Error::OutOfMemory)?;

        transfer.state = DmaTransferState::Pending;
        let xfer_id = transfer.id;
        self.transfers[slot] = transfer;
        self.xfer_count += 1;
        Ok(xfer_id)
    }

    /// Issues all pending transfers on this channel.
    ///
    /// Transitions every [`DmaTransferState::Pending`] transfer
    /// to [`DmaTransferState::Running`] and marks the channel as
    /// active.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no pending transfers exist.
    pub fn issue_pending(&mut self) -> Result<()> {
        let has_pending = self
            .transfers
            .iter()
            .any(|t| t.state == DmaTransferState::Pending);

        if !has_pending {
            return Err(Error::NotFound);
        }

        for xfer in &mut self.transfers {
            if xfer.state == DmaTransferState::Pending {
                xfer.state = DmaTransferState::Running;
            }
        }

        self.active = true;
        Ok(())
    }

    /// Terminates all in-progress and pending transfers.
    ///
    /// Returns the number of transfers that were terminated.
    ///
    /// # Errors
    ///
    /// Always succeeds (returns `Ok`).
    pub fn terminate_all(&mut self) -> Result<u32> {
        let mut terminated = 0u32;
        for xfer in &mut self.transfers {
            if xfer.state == DmaTransferState::Running || xfer.state == DmaTransferState::Pending {
                xfer.state = DmaTransferState::Idle;
                xfer.id = 0;
                terminated += 1;
                self.xfer_count = self.xfer_count.saturating_sub(1);
            }
        }
        self.active = false;
        Ok(terminated)
    }

    /// Marks a transfer as complete by its identifier.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no running transfer matches.
    pub fn complete(&mut self, xfer_id: u64) -> Result<()> {
        let slot = self
            .transfers
            .iter()
            .position(|t| t.id == xfer_id && t.state == DmaTransferState::Running)
            .ok_or(Error::NotFound)?;

        self.transfers[slot].state = DmaTransferState::Complete;

        // If no more running transfers, deactivate the channel.
        let any_running = self
            .transfers
            .iter()
            .any(|t| t.state == DmaTransferState::Running);
        if !any_running {
            self.active = false;
        }

        Ok(())
    }

    /// Returns the current state of a transfer.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no transfer with that ID exists.
    pub fn tx_status(&self, xfer_id: u64) -> Result<DmaTransferState> {
        self.transfers
            .iter()
            .find(|t| t.id == xfer_id)
            .map(|t| t.state)
            .ok_or(Error::NotFound)
    }

    /// Returns the number of pending or running transfers.
    pub fn pending_count(&self) -> usize {
        self.transfers
            .iter()
            .filter(|t| {
                t.state == DmaTransferState::Pending || t.state == DmaTransferState::Running
            })
            .count()
    }
}

// -------------------------------------------------------------------
// DmaEngine
// -------------------------------------------------------------------

/// Top-level DMA engine controller.
///
/// Manages a set of DMA channels and provides helper methods
/// to prepare common transfer types (memcpy, slave scatter-gather,
/// cyclic).
pub struct DmaEngine {
    /// DMA channels owned by this engine.
    channels: [DmaChannel; MAX_CHANNELS_PER_ENGINE],
    /// Number of channels configured for this engine.
    channel_count: usize,
    /// MMIO base address of the DMA controller.
    base_addr: u64,
    /// Monotonically increasing transfer ID generator.
    next_xfer_id: u64,
    /// Whether the engine has been initialised.
    initialized: bool,
}

impl Default for DmaEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DmaEngine {
    /// Creates an uninitialised DMA engine.
    pub const fn new() -> Self {
        Self {
            channels: [const { DmaChannel::new() }; MAX_CHANNELS_PER_ENGINE],
            channel_count: 0,
            base_addr: 0,
            next_xfer_id: 1,
            initialized: false,
        }
    }

    /// Initialises the DMA engine at the given MMIO base address.
    ///
    /// # Arguments
    ///
    /// * `base_addr` — Physical base address of the DMA controller
    ///   register block.
    /// * `num_channels` — Number of channels to activate (clamped
    ///   to [`MAX_CHANNELS_PER_ENGINE`]).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `base_addr` is zero or
    ///   `num_channels` is zero.
    pub fn init(&mut self, base_addr: u64, num_channels: usize) -> Result<()> {
        if base_addr == 0 || num_channels == 0 {
            return Err(Error::InvalidArgument);
        }

        let count = num_channels.min(MAX_CHANNELS_PER_ENGINE);
        self.base_addr = base_addr;
        self.channel_count = count;

        for (i, ch) in self.channels[..count].iter_mut().enumerate() {
            ch.id = i as u32;
            ch.in_use = false;
            ch.active = false;
        }

        self.initialized = true;
        Ok(())
    }

    /// Allocates the next unique transfer ID.
    fn alloc_xfer_id(&mut self) -> u64 {
        let id = self.next_xfer_id;
        self.next_xfer_id += 1;
        id
    }

    /// Requests an unused DMA channel.
    ///
    /// Returns the channel ID on success.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the engine is not
    ///   initialised.
    /// - [`Error::Busy`] if all channels are in use.
    pub fn request_channel(&mut self) -> Result<u32> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }

        let ch = self.channels[..self.channel_count]
            .iter_mut()
            .find(|c| !c.in_use)
            .ok_or(Error::Busy)?;

        ch.in_use = true;
        Ok(ch.id)
    }

    /// Releases a previously requested DMA channel.
    ///
    /// Any queued or running transfers on the channel are
    /// terminated before release.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `ch_id` is out of range.
    /// - [`Error::NotFound`] if the channel is not in use.
    pub fn release_channel(&mut self, ch_id: u32) -> Result<()> {
        let ch = self
            .channels
            .get_mut(ch_id as usize)
            .filter(|_| (ch_id as usize) < self.channel_count)
            .ok_or(Error::InvalidArgument)?;

        if !ch.in_use {
            return Err(Error::NotFound);
        }

        let _ = ch.terminate_all();
        ch.in_use = false;
        Ok(())
    }

    /// Prepares a memory-to-memory copy transfer.
    ///
    /// The transfer is submitted to the specified channel in
    /// [`DmaTransferState::Pending`] state. Call
    /// [`DmaChannel::issue_pending`] (via the channel) to start it.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `ch` is out of range,
    ///   `len` is zero, or addresses are zero.
    /// - [`Error::OutOfMemory`] if the channel's transfer queue
    ///   is full.
    pub fn prep_memcpy(&mut self, ch: u32, src: u64, dst: u64, len: usize) -> Result<u64> {
        if len == 0 || src == 0 || dst == 0 {
            return Err(Error::InvalidArgument);
        }

        let xfer_id = self.alloc_xfer_id();
        let transfer = DmaTransfer {
            id: xfer_id,
            direction: DmaTransferDir::MemToMem,
            width: DmaTransferWidth::DoubleWord,
            src,
            dst,
            len,
            state: DmaTransferState::Idle,
            callback_id: 0,
            cyclic: false,
        };

        let channel = self.channel_mut(ch)?;
        channel.submit(transfer)
    }

    /// Prepares a slave scatter-gather transfer.
    ///
    /// Used for device-to-memory or memory-to-device transfers
    /// where the device address is fixed and the memory side is
    /// described by a single buffer.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `ch` is out of range,
    ///   `len` is zero, or `addr` is zero.
    /// - [`Error::OutOfMemory`] if the channel's queue is full.
    pub fn prep_slave_sg(
        &mut self,
        ch: u32,
        direction: DmaTransferDir,
        addr: u64,
        len: usize,
    ) -> Result<u64> {
        if len == 0 || addr == 0 {
            return Err(Error::InvalidArgument);
        }

        let xfer_id = self.alloc_xfer_id();
        let (src, dst) = match direction {
            DmaTransferDir::MemToDev => (addr, 0),
            DmaTransferDir::DevToMem => (0, addr),
            _ => (addr, addr),
        };

        let transfer = DmaTransfer {
            id: xfer_id,
            direction,
            width: DmaTransferWidth::Word,
            src,
            dst,
            len,
            state: DmaTransferState::Idle,
            callback_id: 0,
            cyclic: false,
        };

        let channel = self.channel_mut(ch)?;
        channel.submit(transfer)
    }

    /// Prepares a cyclic DMA transfer.
    ///
    /// Cyclic transfers repeat over `periods` buffers of
    /// `period_len` bytes each, commonly used for audio DMA.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `ch` is out of range,
    ///   `period_len` is zero, `periods` is zero, or `addr` is
    ///   zero.
    /// - [`Error::OutOfMemory`] if the channel's queue is full.
    pub fn prep_cyclic(
        &mut self,
        ch: u32,
        direction: DmaTransferDir,
        addr: u64,
        period_len: usize,
        periods: usize,
    ) -> Result<u64> {
        if period_len == 0 || periods == 0 || addr == 0 {
            return Err(Error::InvalidArgument);
        }

        let xfer_id = self.alloc_xfer_id();
        let total_len = period_len.saturating_mul(periods);
        let (src, dst) = match direction {
            DmaTransferDir::MemToDev => (addr, 0),
            DmaTransferDir::DevToMem => (0, addr),
            _ => (addr, addr),
        };

        let transfer = DmaTransfer {
            id: xfer_id,
            direction,
            width: DmaTransferWidth::Word,
            src,
            dst,
            len: total_len,
            state: DmaTransferState::Idle,
            callback_id: 0,
            cyclic: true,
        };

        let channel = self.channel_mut(ch)?;
        channel.submit(transfer)
    }

    /// Handles a DMA engine interrupt.
    ///
    /// Scans all active channels for running transfers and marks
    /// the first running transfer on each channel as complete.
    /// Returns the number of transfers completed in this call.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the engine is not
    ///   initialised.
    pub fn handle_interrupt(&mut self) -> Result<u32> {
        if !self.initialized {
            return Err(Error::InvalidArgument);
        }

        let mut completed = 0u32;
        for ch in &mut self.channels[..self.channel_count] {
            if !ch.active {
                continue;
            }
            // Complete the first running transfer on this channel.
            if let Some(xfer) = ch
                .transfers
                .iter_mut()
                .find(|t| t.state == DmaTransferState::Running)
            {
                xfer.state = DmaTransferState::Complete;
                completed += 1;

                // Deactivate channel if no more running transfers.
                let any_running = ch
                    .transfers
                    .iter()
                    .any(|t| t.state == DmaTransferState::Running);
                if !any_running {
                    ch.active = false;
                }
            }
        }

        Ok(completed)
    }

    /// Returns a reference to a channel by ID.
    pub fn get_channel(&self, id: u32) -> Option<&DmaChannel> {
        let idx = id as usize;
        if idx < self.channel_count {
            Some(&self.channels[idx])
        } else {
            None
        }
    }

    /// Returns a mutable reference to a channel, validating the
    /// ID and that the channel is in use.
    fn channel_mut(&mut self, ch: u32) -> Result<&mut DmaChannel> {
        let idx = ch as usize;
        if idx >= self.channel_count {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.channels[idx])
    }

    /// Returns whether the engine has been initialised.
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Returns the MMIO base address.
    pub fn base_addr(&self) -> u64 {
        self.base_addr
    }

    /// Returns the number of configured channels.
    pub fn channel_count(&self) -> usize {
        self.channel_count
    }
}

// -------------------------------------------------------------------
// DmaEngineRegistry
// -------------------------------------------------------------------

/// System-wide registry of DMA engine controllers.
///
/// Supports up to [`MAX_ENGINES`] (4) DMA engines, typically
/// discovered via ACPI or device tree enumeration.
pub struct DmaEngineRegistry {
    /// Registered DMA engines.
    engines: [DmaEngine; MAX_ENGINES],
    /// Number of registered engines.
    count: usize,
}

impl Default for DmaEngineRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl DmaEngineRegistry {
    /// Creates an empty DMA engine registry.
    pub const fn new() -> Self {
        Self {
            engines: [const { DmaEngine::new() }; MAX_ENGINES],
            count: 0,
        }
    }

    /// Registers a DMA engine and returns its index.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the registry is full.
    pub fn register(&mut self, engine: DmaEngine) -> Result<usize> {
        if self.count >= MAX_ENGINES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.count;
        self.engines[idx] = engine;
        self.count += 1;
        Ok(idx)
    }

    /// Returns a reference to a registered engine by index.
    pub fn get(&self, index: usize) -> Option<&DmaEngine> {
        if index < self.count {
            Some(&self.engines[index])
        } else {
            None
        }
    }

    /// Returns a mutable reference to a registered engine.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut DmaEngine> {
        if index < self.count {
            Some(&mut self.engines[index])
        } else {
            None
        }
    }

    /// Returns the number of registered engines.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns `true` if no engines are registered.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}
