// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! eXpress Data Path (XDP) subsystem for the ONCRIX kernel.
//!
//! XDP provides a high-performance, programmable packet processing
//! framework that runs BPF programs at the earliest point in the
//! network receive path -- before the kernel allocates any socket
//! buffers.
//!
//! # Architecture
//!
//! ```text
//! NIC → [XDP hook] → drop / pass / tx / redirect
//!            │
//!            └→ (pass) → normal kernel stack
//! ```
//!
//! Key components:
//!
//! - [`XdpAction`]: verdict returned by an XDP program after
//!   inspecting a packet (drop, pass, transmit, redirect, abort).
//! - [`XdpBuff`]: metadata and data pointers for a single packet
//!   buffer, presented to XDP programs for direct read/write access.
//! - [`XdpProgram`]: a loaded BPF program reference with an
//!   interface binding and a `run` method that returns an action.
//! - [`XdpHook`]: per-interface attachment point where exactly one
//!   XDP program runs on every received packet.
//! - [`XdpStats`]: per-action packet counters for observability.
//! - [`XdpRegistry`]: system-wide registry managing up to
//!   [`MAX_INTERFACES`] interface hooks.
//!
//! Reference: Linux `net/core/dev.c` (XDP path),
//! `include/uapi/linux/bpf.h` (XDP actions).

use oncrix_lib::{Error, Result};

// =========================================================================
// Constants
// =========================================================================

/// Maximum number of interfaces that support XDP hooks.
const MAX_INTERFACES: usize = 32;

/// Maximum packet buffer size in bytes.
const XDP_PACKET_BUF_SIZE: usize = 2048;

// =========================================================================
// XdpAction
// =========================================================================

/// Verdict returned by an XDP program after processing a packet.
///
/// Values match the Linux `XDP_*` constants from
/// `include/uapi/linux/bpf.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u32)]
pub enum XdpAction {
    /// Error or exception during processing; packet is dropped
    /// and an error counter is incremented.
    Aborted = 0,
    /// Silently drop the packet.
    Drop = 1,
    /// Pass the packet up to the normal kernel network stack.
    #[default]
    Pass = 2,
    /// Bounce the packet back out the same interface it arrived on.
    Tx = 3,
    /// Redirect the packet to another interface, CPU, or socket.
    Redirect = 4,
}

impl XdpAction {
    /// Convert a raw `u32` to an [`XdpAction`].
    ///
    /// Unknown values map to [`XdpAction::Aborted`].
    pub const fn from_u32(v: u32) -> Self {
        match v {
            0 => Self::Aborted,
            1 => Self::Drop,
            2 => Self::Pass,
            3 => Self::Tx,
            4 => Self::Redirect,
            _ => Self::Aborted,
        }
    }
}

// =========================================================================
// XdpBuff
// =========================================================================

/// Packet buffer presented to XDP programs.
///
/// Simulates the Linux `struct xdp_buff` using a fixed-size byte
/// array with offset markers.  XDP programs can inspect and modify
/// the packet data between `data_start` and `data_end`.
///
/// ```text
/// ┌──── data_meta ────┬── data_start ──┬──── data_end ────┐
/// │  metadata area     │  packet data   │  (unused tail)   │
/// └───────────────────────────────────────────────────────┘
/// ```
pub struct XdpBuff {
    /// Raw packet storage.
    buf: [u8; XDP_PACKET_BUF_SIZE],
    /// Offset where optional metadata begins (≤ `data_start`).
    pub data_meta: usize,
    /// Offset where packet data begins.
    pub data_start: usize,
    /// Offset one past the last byte of packet data.
    pub data_end: usize,
    /// Interface index the packet was received on.
    pub rx_queue_index: u32,
}

impl Default for XdpBuff {
    fn default() -> Self {
        Self::new()
    }
}

impl XdpBuff {
    /// Create an empty XDP buffer.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; XDP_PACKET_BUF_SIZE],
            data_meta: 0,
            data_start: 0,
            data_end: 0,
            rx_queue_index: 0,
        }
    }

    /// Load packet data into the buffer.
    ///
    /// Copies up to [`XDP_PACKET_BUF_SIZE`] bytes from `data`.
    /// The `data_start` is set to 0 and `data_end` to the number
    /// of bytes copied.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `data` is empty.
    pub fn load(&mut self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            return Err(Error::InvalidArgument);
        }
        let len = data.len().min(XDP_PACKET_BUF_SIZE);
        self.buf[..len].copy_from_slice(&data[..len]);
        self.data_meta = 0;
        self.data_start = 0;
        self.data_end = len;
        Ok(())
    }

    /// Return the packet data slice between `data_start` and
    /// `data_end`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the offsets are
    /// inconsistent.
    pub fn data(&self) -> Result<&[u8]> {
        if self.data_start > self.data_end || self.data_end > XDP_PACKET_BUF_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.buf[self.data_start..self.data_end])
    }

    /// Return the packet data length.
    pub const fn len(&self) -> usize {
        self.data_end.saturating_sub(self.data_start)
    }

    /// Return whether the buffer contains no packet data.
    pub const fn is_empty(&self) -> bool {
        self.data_end <= self.data_start
    }

    /// Return a mutable reference to the packet data between
    /// `data_start` and `data_end`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the offsets are
    /// inconsistent.
    pub fn data_mut(&mut self) -> Result<&mut [u8]> {
        if self.data_start > self.data_end || self.data_end > XDP_PACKET_BUF_SIZE {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.buf[self.data_start..self.data_end])
    }

    /// Adjust the headroom by moving `data_start`.
    ///
    /// A positive `delta` shrinks the packet (moves `data_start`
    /// forward); a negative `delta` grows it (moves `data_start`
    /// backward into the metadata area).
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if the resulting
    /// `data_start` would be out of bounds.
    pub fn adjust_head(&mut self, delta: i32) -> Result<()> {
        let new_start = (self.data_start as i64) + (delta as i64);
        if new_start < 0 || new_start as usize > self.data_end {
            return Err(Error::InvalidArgument);
        }
        self.data_start = new_start as usize;
        Ok(())
    }
}

// =========================================================================
// XdpProgram
// =========================================================================

/// A reference to a loaded BPF program used as an XDP hook.
///
/// In a real kernel this would hold a pointer to a verified BPF
/// program.  Here we store the program's registry ID and simulate
/// execution by examining the first byte of the packet to produce
/// a deterministic [`XdpAction`].
pub struct XdpProgram {
    /// BPF program registry identifier.
    pub prog_id: u32,
    /// Interface index this program is attached to (0 = unattached).
    pub ifindex: u32,
}

impl XdpProgram {
    /// Create a new XDP program reference.
    pub const fn new(prog_id: u32) -> Self {
        Self {
            prog_id,
            ifindex: 0,
        }
    }

    /// Execute the XDP program on the given packet buffer.
    ///
    /// In this simulation the action is derived from the first byte
    /// of the packet data modulo 5, mapping to the five
    /// [`XdpAction`] variants.  A real implementation would run the
    /// verified BPF bytecode via [`crate::bpf::BpfVm`].
    pub fn run(&self, buff: &XdpBuff) -> XdpAction {
        if buff.is_empty() {
            return XdpAction::Aborted;
        }
        let first = buff.buf[buff.data_start];
        XdpAction::from_u32((first % 5) as u32)
    }
}

// =========================================================================
// XdpStats
// =========================================================================

/// Per-action packet counters for an XDP attachment point.
///
/// All counters are monotonically increasing and wrap on overflow.
#[derive(Debug, Clone, Copy, Default)]
pub struct XdpStats {
    /// Packets that triggered [`XdpAction::Aborted`].
    pub aborted: u64,
    /// Packets dropped by [`XdpAction::Drop`].
    pub drop: u64,
    /// Packets passed to the kernel stack via [`XdpAction::Pass`].
    pub pass: u64,
    /// Packets reflected via [`XdpAction::Tx`].
    pub tx: u64,
    /// Packets redirected via [`XdpAction::Redirect`].
    pub redirect: u64,
}

impl XdpStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            aborted: 0,
            drop: 0,
            pass: 0,
            tx: 0,
            redirect: 0,
        }
    }

    /// Increment the counter for the given action.
    pub fn record(&mut self, action: XdpAction) {
        match action {
            XdpAction::Aborted => self.aborted = self.aborted.wrapping_add(1),
            XdpAction::Drop => self.drop = self.drop.wrapping_add(1),
            XdpAction::Pass => self.pass = self.pass.wrapping_add(1),
            XdpAction::Tx => self.tx = self.tx.wrapping_add(1),
            XdpAction::Redirect => self.redirect = self.redirect.wrapping_add(1),
        }
    }

    /// Return the total number of packets processed.
    pub const fn total(&self) -> u64 {
        self.aborted
            .wrapping_add(self.drop)
            .wrapping_add(self.pass)
            .wrapping_add(self.tx)
            .wrapping_add(self.redirect)
    }
}

// =========================================================================
// XdpHook
// =========================================================================

/// Per-interface XDP attachment point.
///
/// At most one XDP program may be attached to an interface at a
/// time.  When a program is attached, every received packet is run
/// through it before reaching the normal kernel network stack.
pub struct XdpHook {
    /// The attached XDP program, if any.
    prog: Option<XdpProgram>,
    /// Per-action statistics since the program was attached.
    pub stats: XdpStats,
    /// Interface index.
    pub ifindex: u32,
}

impl XdpHook {
    /// Create a new hook for the given interface.
    pub const fn new(ifindex: u32) -> Self {
        Self {
            prog: None,
            stats: XdpStats::new(),
            ifindex,
        }
    }

    /// Return whether an XDP program is currently attached.
    pub const fn has_program(&self) -> bool {
        self.prog.is_some()
    }

    /// Return the attached program's ID, if any.
    pub fn prog_id(&self) -> Option<u32> {
        self.prog.as_ref().map(|p| p.prog_id)
    }

    /// Attach an XDP program to this hook.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Busy`] if a program is already attached.
    pub fn attach(&mut self, mut prog: XdpProgram) -> Result<()> {
        if self.prog.is_some() {
            return Err(Error::Busy);
        }
        prog.ifindex = self.ifindex;
        self.stats = XdpStats::new();
        self.prog = Some(prog);
        Ok(())
    }

    /// Detach the currently attached XDP program.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no program is attached.
    pub fn detach(&mut self) -> Result<XdpProgram> {
        self.prog.take().ok_or(Error::NotFound)
    }

    /// Process a packet through the attached XDP program.
    ///
    /// Returns the action determined by the program.  If no program
    /// is attached the packet passes through unconditionally.
    pub fn process_packet(&mut self, buff: &XdpBuff) -> XdpAction {
        let action = match &self.prog {
            Some(prog) => prog.run(buff),
            None => XdpAction::Pass,
        };
        self.stats.record(action);
        action
    }
}

// =========================================================================
// XdpRegistry
// =========================================================================

/// System-wide XDP hook registry managing up to [`MAX_INTERFACES`]
/// interfaces.
///
/// Provides a centralized API for attaching, detaching, and running
/// XDP programs on any interface.
pub struct XdpRegistry {
    /// Per-interface XDP hooks.
    hooks: [XdpHook; MAX_INTERFACES],
}

impl Default for XdpRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl XdpRegistry {
    /// Create a registry with hooks for all interfaces.
    pub fn new() -> Self {
        Self {
            hooks: core::array::from_fn(|i| XdpHook::new(i as u32)),
        }
    }

    /// Attach an XDP program to the specified interface.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `ifindex` is out of range.
    /// - [`Error::Busy`] if a program is already attached.
    pub fn attach(&mut self, ifindex: usize, prog: XdpProgram) -> Result<()> {
        let hook = self.hooks.get_mut(ifindex).ok_or(Error::InvalidArgument)?;
        hook.attach(prog)
    }

    /// Detach the XDP program from the specified interface.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `ifindex` is out of range.
    /// - [`Error::NotFound`] if no program is attached.
    pub fn detach(&mut self, ifindex: usize) -> Result<XdpProgram> {
        let hook = self.hooks.get_mut(ifindex).ok_or(Error::InvalidArgument)?;
        hook.detach()
    }

    /// Run the XDP hook for a received packet on the given
    /// interface.
    ///
    /// Returns [`XdpAction::Pass`] if the interface has no XDP
    /// program or the index is out of range.
    pub fn process_packet(&mut self, ifindex: usize, buff: &XdpBuff) -> XdpAction {
        match self.hooks.get_mut(ifindex) {
            Some(hook) => hook.process_packet(buff),
            None => XdpAction::Pass,
        }
    }

    /// Return the statistics for an interface's XDP hook.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `ifindex` is out of
    /// range.
    pub fn stats(&self, ifindex: usize) -> Result<&XdpStats> {
        let hook = self.hooks.get(ifindex).ok_or(Error::InvalidArgument)?;
        Ok(&hook.stats)
    }

    /// Return the program ID attached to an interface, if any.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `ifindex` is out of
    /// range.
    pub fn prog_id(&self, ifindex: usize) -> Result<Option<u32>> {
        let hook = self.hooks.get(ifindex).ok_or(Error::InvalidArgument)?;
        Ok(hook.prog_id())
    }
}
