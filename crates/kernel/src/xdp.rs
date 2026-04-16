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

/// Maximum number of entries in a DEVMAP (redirect map).
const DEVMAP_SIZE: usize = 64;

/// Maximum number of logical CPUs for per-CPU statistics.
const MAX_CPUS: usize = 64;

/// Maximum number of packets in the bulk transmit flush queue.
const XDP_BULK_QUEUE_SIZE: usize = 16;

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

    /// Replace the XDP program on an interface atomically.
    ///
    /// Detaches any existing program and attaches the new one in a
    /// single operation.  Statistics are reset.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `ifindex` is out of
    /// range.
    pub fn replace(&mut self, ifindex: usize, prog: XdpProgram) -> Result<Option<XdpProgram>> {
        let hook = self.hooks.get_mut(ifindex).ok_or(Error::InvalidArgument)?;
        let old = hook.prog.take();
        hook.stats = XdpStats::new();
        let mut new_prog = prog;
        new_prog.ifindex = hook.ifindex;
        hook.prog = Some(new_prog);
        Ok(old)
    }
}

// =========================================================================
// XdpDevMap — redirect target map
// =========================================================================

/// A single entry in the DEVMAP specifying a redirect target.
#[derive(Debug, Clone, Copy)]
pub struct DevMapEntry {
    /// Target interface index for redirect.
    pub ifindex: u32,
    /// Whether this entry is occupied.
    pub active: bool,
}

impl DevMapEntry {
    /// An empty, inactive entry.
    const EMPTY: Self = Self {
        ifindex: 0,
        active: false,
    };
}

/// XDP redirect device map (DEVMAP).
///
/// Maps a key (index) to a target interface.  When an XDP program
/// returns [`XdpAction::Redirect`], the redirect target is looked
/// up by key in this map to determine the egress interface.
///
/// Reference: Linux `include/net/xdp.h` (`struct bpf_dtab_netdev`).
pub struct XdpDevMap {
    /// Map entries indexed by key.
    entries: [DevMapEntry; DEVMAP_SIZE],
    /// Number of active entries.
    count: usize,
}

impl Default for XdpDevMap {
    fn default() -> Self {
        Self::new()
    }
}

impl XdpDevMap {
    /// Create an empty DEVMAP.
    pub const fn new() -> Self {
        Self {
            entries: [DevMapEntry::EMPTY; DEVMAP_SIZE],
            count: 0,
        }
    }

    /// Return the number of active entries.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Insert or update a redirect target at the given key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `key` is out of range.
    pub fn insert(&mut self, key: usize, ifindex: u32) -> Result<()> {
        let entry = self.entries.get_mut(key).ok_or(Error::InvalidArgument)?;
        if !entry.active {
            self.count += 1;
        }
        entry.ifindex = ifindex;
        entry.active = true;
        Ok(())
    }

    /// Remove a redirect target at the given key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `key` is out of range.
    /// Returns [`Error::NotFound`] if the entry is not active.
    pub fn remove(&mut self, key: usize) -> Result<()> {
        let entry = self.entries.get_mut(key).ok_or(Error::InvalidArgument)?;
        if !entry.active {
            return Err(Error::NotFound);
        }
        entry.active = false;
        entry.ifindex = 0;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Look up the redirect target interface for a key.
    ///
    /// Returns `None` if the key is out of range or inactive.
    pub fn lookup(&self, key: usize) -> Option<u32> {
        self.entries
            .get(key)
            .and_then(|e| if e.active { Some(e.ifindex) } else { None })
    }

    /// Remove all entries from the map.
    pub fn flush(&mut self) {
        for entry in self.entries.iter_mut() {
            entry.active = false;
            entry.ifindex = 0;
        }
        self.count = 0;
    }
}

// =========================================================================
// XdpPerCpuStats — per-CPU action counters
// =========================================================================

/// Per-CPU XDP statistics array.
///
/// Each logical CPU maintains its own set of action counters so that
/// the fast path can increment without cross-CPU contention.  The
/// aggregate view is obtained by summing across all CPUs.
pub struct XdpPerCpuStats {
    /// Per-CPU statistics slots.
    cpus: [XdpStats; MAX_CPUS],
    /// Number of CPUs actually in use.
    nr_cpus: usize,
}

impl Default for XdpPerCpuStats {
    fn default() -> Self {
        Self::new(1)
    }
}

impl XdpPerCpuStats {
    /// Create per-CPU statistics for `nr_cpus` processors.
    ///
    /// Clamps to [`MAX_CPUS`] if the value exceeds the limit.
    pub fn new(nr_cpus: usize) -> Self {
        let capped = if nr_cpus == 0 {
            1
        } else {
            nr_cpus.min(MAX_CPUS)
        };
        Self {
            cpus: [const { XdpStats::new() }; MAX_CPUS],
            nr_cpus: capped,
        }
    }

    /// Record an action on the specified CPU.
    ///
    /// If `cpu` is out of range, the action is silently attributed
    /// to CPU 0.
    pub fn record(&mut self, cpu: usize, action: XdpAction) {
        let idx = if cpu < self.nr_cpus { cpu } else { 0 };
        self.cpus[idx].record(action);
    }

    /// Return the statistics for a single CPU.
    ///
    /// Returns `None` if `cpu` is out of range.
    pub fn cpu_stats(&self, cpu: usize) -> Option<&XdpStats> {
        if cpu < self.nr_cpus {
            Some(&self.cpus[cpu])
        } else {
            None
        }
    }

    /// Compute the aggregate statistics across all CPUs.
    pub fn aggregate(&self) -> XdpStats {
        let mut agg = XdpStats::new();
        for (i, stats) in self.cpus.iter().enumerate() {
            if i >= self.nr_cpus {
                break;
            }
            agg.aborted = agg.aborted.wrapping_add(stats.aborted);
            agg.drop = agg.drop.wrapping_add(stats.drop);
            agg.pass = agg.pass.wrapping_add(stats.pass);
            agg.tx = agg.tx.wrapping_add(stats.tx);
            agg.redirect = agg.redirect.wrapping_add(stats.redirect);
        }
        agg
    }

    /// Reset all per-CPU counters to zero.
    pub fn reset(&mut self) {
        for (i, stats) in self.cpus.iter_mut().enumerate() {
            if i >= self.nr_cpus {
                break;
            }
            *stats = XdpStats::new();
        }
    }

    /// Return the number of CPUs tracked.
    pub const fn nr_cpus(&self) -> usize {
        self.nr_cpus
    }
}

// =========================================================================
// XdpBulkQueue — deferred packet flush
// =========================================================================

/// A single queued redirect entry awaiting bulk flush.
#[derive(Debug, Clone, Copy)]
pub struct BulkEntry {
    /// Target interface index.
    pub ifindex: u32,
    /// Offset into the XDP buffer where this packet's data starts.
    pub data_start: usize,
    /// Offset one past the last byte of packet data.
    pub data_end: usize,
    /// Whether this slot is occupied.
    pub active: bool,
}

impl BulkEntry {
    /// An empty entry.
    const EMPTY: Self = Self {
        ifindex: 0,
        data_start: 0,
        data_end: 0,
        active: false,
    };
}

/// Queue for batching XDP_REDIRECT packets before flushing.
///
/// Instead of immediately forwarding each redirected packet, the
/// XDP fast path enqueues redirect decisions.  At the end of a
/// receive batch (NAPI poll), [`XdpBulkQueue::flush`] transmits
/// all queued packets to their target interfaces in one burst.
///
/// This reduces per-packet overhead from device TX ring
/// doorbell writes.
pub struct XdpBulkQueue {
    /// Queued redirect entries.
    queue: [BulkEntry; XDP_BULK_QUEUE_SIZE],
    /// Number of entries currently queued.
    count: usize,
    /// Total packets successfully flushed since creation.
    total_flushed: u64,
    /// Total flush operations performed.
    flush_count: u64,
}

impl Default for XdpBulkQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl XdpBulkQueue {
    /// Create an empty bulk queue.
    pub const fn new() -> Self {
        Self {
            queue: [BulkEntry::EMPTY; XDP_BULK_QUEUE_SIZE],
            count: 0,
            total_flushed: 0,
            flush_count: 0,
        }
    }

    /// Return the number of entries currently queued.
    pub const fn pending(&self) -> usize {
        self.count
    }

    /// Return whether the queue is full.
    pub const fn is_full(&self) -> bool {
        self.count >= XDP_BULK_QUEUE_SIZE
    }

    /// Return total packets flushed since creation.
    pub const fn total_flushed(&self) -> u64 {
        self.total_flushed
    }

    /// Return total flush operations performed.
    pub const fn flush_count(&self) -> u64 {
        self.flush_count
    }

    /// Enqueue a redirect decision for deferred transmission.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the queue is full.  The
    /// caller should flush first, then retry.
    pub fn enqueue(&mut self, ifindex: u32, data_start: usize, data_end: usize) -> Result<()> {
        if self.count >= XDP_BULK_QUEUE_SIZE {
            return Err(Error::OutOfMemory);
        }
        self.queue[self.count] = BulkEntry {
            ifindex,
            data_start,
            data_end,
            active: true,
        };
        self.count += 1;
        Ok(())
    }

    /// Return a reference to the queued entries pending flush.
    ///
    /// The returned slice contains exactly [`Self::pending`] active
    /// entries.  Callers (e.g. the NIC driver) use this to iterate
    /// over the redirect targets before or during flush.
    pub fn entries(&self) -> &[BulkEntry] {
        &self.queue[..self.count]
    }

    /// Flush all queued redirect entries.
    ///
    /// Returns the number of entries that were flushed.  In a real
    /// implementation this would invoke the target NIC's
    /// `ndo_xdp_xmit` for each queued packet; here we simply
    /// account for the entries and clear the queue.
    pub fn flush(&mut self) -> usize {
        let flushed = self.count;
        for (i, entry) in self.queue.iter_mut().enumerate() {
            if i >= self.count {
                break;
            }
            entry.active = false;
        }
        self.total_flushed = self.total_flushed.wrapping_add(flushed as u64);
        self.flush_count = self.flush_count.wrapping_add(1);
        self.count = 0;
        flushed
    }
}

// =========================================================================
// XdpActionDispatch — run action after XDP program verdict
// =========================================================================

/// Result of dispatching an XDP action.
///
/// After the XDP program returns a verdict, the dispatcher
/// executes the corresponding action and reports back what
/// happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XdpDispatchResult {
    /// Packet was dropped (either by XDP_DROP or XDP_ABORTED).
    Dropped,
    /// Packet should be passed up to the kernel network stack.
    PassToStack,
    /// Packet was reflected back on the ingress interface (XDP_TX).
    Transmitted,
    /// Packet was enqueued for redirect to another interface.
    Redirected {
        /// Target interface index.
        target_ifindex: u32,
    },
    /// Redirect failed because the DEVMAP lookup returned no target.
    RedirectFailed,
}

/// Dispatch an XDP action after a program verdict.
///
/// Given the action returned by an XDP program, this function
/// performs the corresponding operation:
///
/// - **Aborted / Drop**: packet is discarded.
/// - **Pass**: packet continues to the kernel network stack.
/// - **Tx**: packet is reflected back on the ingress interface.
/// - **Redirect**: packet is looked up in the `devmap` and
///   enqueued in the `bulk_queue` for deferred transmission.
///
/// # Arguments
///
/// * `action` — the verdict from the XDP program.
/// * `devmap_key` — key to look up in the DEVMAP for redirect
///   (typically the ingress `ifindex` or a program-set value).
/// * `devmap` — the DEVMAP containing redirect targets.
/// * `bulk_queue` — the bulk queue for batching redirects.
/// * `buff` — the packet buffer (needed for redirect enqueue
///   offsets).
pub fn xdp_dispatch_action(
    action: XdpAction,
    devmap_key: usize,
    devmap: &XdpDevMap,
    bulk_queue: &mut XdpBulkQueue,
    buff: &XdpBuff,
) -> XdpDispatchResult {
    match action {
        XdpAction::Aborted | XdpAction::Drop => XdpDispatchResult::Dropped,
        XdpAction::Pass => XdpDispatchResult::PassToStack,
        XdpAction::Tx => XdpDispatchResult::Transmitted,
        XdpAction::Redirect => {
            if let Some(target) = devmap.lookup(devmap_key) {
                let _ = bulk_queue.enqueue(target, buff.data_start, buff.data_end);
                XdpDispatchResult::Redirected {
                    target_ifindex: target,
                }
            } else {
                XdpDispatchResult::RedirectFailed
            }
        }
    }
}

/// Run the full XDP receive path for a single packet.
///
/// Combines hook execution, per-CPU statistics recording, and
/// action dispatch into one call.  This is the top-level entry
/// point invoked by the NIC driver's NAPI poll loop.
///
/// # Arguments
///
/// * `registry` — the system-wide XDP hook registry.
/// * `ifindex` — interface the packet was received on.
/// * `cpu` — logical CPU running the NAPI poll.
/// * `buff` — the packet buffer.
/// * `devmap` — the DEVMAP for redirect lookups.
/// * `per_cpu` — per-CPU statistics.
/// * `bulk_queue` — bulk queue for deferred redirects.
///
/// # Returns
///
/// The dispatch result indicating what happened to the packet.
pub fn xdp_receive(
    registry: &mut XdpRegistry,
    ifindex: usize,
    cpu: usize,
    buff: &XdpBuff,
    devmap: &XdpDevMap,
    per_cpu: &mut XdpPerCpuStats,
    bulk_queue: &mut XdpBulkQueue,
) -> XdpDispatchResult {
    let action = registry.process_packet(ifindex, buff);
    per_cpu.record(cpu, action);

    xdp_dispatch_action(action, ifindex, devmap, bulk_queue, buff)
}
