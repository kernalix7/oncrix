// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! XDP core framework — redirect maps, AF_XDP sockets, metadata,
//! bulk processing, and multi-program dispatch.
//!
//! Extends the basic XDP hook layer ([`super::xdp`]) with the
//! subsystems required for production XDP deployments:
//!
//! # Architecture
//!
//! ```text
//! NIC RX
//!   │
//!   ▼
//! [XDP hook] ──── XDP_REDIRECT ───→ [DevMap / CpuMap / XskMap]
//!   │                                        │
//!   │ XDP_PASS                               ▼
//!   ▼                               [target NIC TX / CPU / AF_XDP]
//! kernel stack
//! ```
//!
//! Key components:
//!
//! - [`XdpDevMapEntry`] / [`XdpDevMap`]: device redirect map
//!   (`BPF_MAP_TYPE_DEVMAP`) for forwarding packets to other
//!   interfaces.
//! - [`XdpCpuMapEntry`] / [`XdpCpuMap`]: CPU redirect map
//!   (`BPF_MAP_TYPE_CPUMAP`) for steering packets to specific CPUs.
//! - [`XdpXskEntry`] / [`XdpXskMap`]: AF_XDP socket map for
//!   zero-copy delivery to user-space.
//! - [`XdpMetadata`]: per-packet metadata (timestamps, hash,
//!   VLAN, mark) passed through the XDP pipeline.
//! - [`XdpBulkQueue`]: batched TX queue for amortizing per-packet
//!   overhead when redirecting.
//! - [`XdpMultiProg`]: multi-program dispatcher supporting
//!   chained and round-robin program execution.
//! - [`XdpCoreRegistry`]: central coordinator tying all XDP core
//!   subsystems together.
//!
//! Reference: Linux `net/core/xdp.c`, `kernel/bpf/devmap.c`,
//! `kernel/bpf/cpumap.c`, `net/xdp/xsk.c`.

use oncrix_lib::{Error, Result};

// =========================================================================
// Constants
// =========================================================================

/// Maximum entries in a device redirect map.
const DEVMAP_MAX_ENTRIES: usize = 64;

/// Maximum entries in a CPU redirect map.
const CPUMAP_MAX_ENTRIES: usize = 16;

/// Maximum entries in an AF_XDP socket map.
const XSKMAP_MAX_ENTRIES: usize = 32;

/// Maximum packets in a bulk transmit queue.
const BULK_QUEUE_SIZE: usize = 64;

/// Maximum packet size for bulk queue entries.
const BULK_PKT_SIZE: usize = 2048;

/// Maximum number of XDP programs in a multi-prog dispatcher.
const MAX_MULTI_PROGS: usize = 8;

/// Maximum number of interfaces managed by the core registry.
const MAX_CORE_INTERFACES: usize = 32;

/// Maximum AF_XDP ring size (entries).
const XSK_RING_SIZE: usize = 256;

/// Maximum AF_XDP frame size.
const XSK_FRAME_SIZE: usize = 2048;

/// Maximum name length for map entries.
const MAX_MAP_NAME_LEN: usize = 32;

/// Maximum number of redirect maps (dev + cpu + xsk) in the
/// system.
const MAX_REDIRECT_MAPS: usize = 16;

// =========================================================================
// XdpDevMapEntry
// =========================================================================

/// Single entry in a device redirect map.
///
/// Maps a key (index) to a target interface for XDP_REDIRECT.
/// Optionally holds a BPF program ID that runs on the packet
/// before it is transmitted on the target interface.
#[derive(Debug, Clone, Copy)]
pub struct XdpDevMapEntry {
    /// Target interface index.
    pub ifindex: u32,
    /// Optional BPF program to run before TX (0 = none).
    pub prog_id: u32,
    /// Whether this entry is populated.
    pub active: bool,
}

impl XdpDevMapEntry {
    /// Create an empty (inactive) entry.
    pub const fn new() -> Self {
        Self {
            ifindex: 0,
            prog_id: 0,
            active: false,
        }
    }
}

// =========================================================================
// XdpDevMap
// =========================================================================

/// Device redirect map (`BPF_MAP_TYPE_DEVMAP`).
///
/// Used by XDP programs to redirect packets to a different network
/// interface. Each entry maps an integer key to a target interface
/// index plus an optional egress BPF program.
pub struct XdpDevMap {
    /// Map name for identification.
    name: [u8; MAX_MAP_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Map entries indexed by key.
    entries: [XdpDevMapEntry; DEVMAP_MAX_ENTRIES],
    /// Number of active entries.
    count: usize,
    /// Total lookups performed.
    pub lookups: u64,
    /// Total redirects performed.
    pub redirects: u64,
    /// Total lookup misses (key not found / inactive).
    pub misses: u64,
}

impl XdpDevMap {
    /// Create a new empty device map.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_MAP_NAME_LEN],
            name_len: 0,
            entries: [const { XdpDevMapEntry::new() }; DEVMAP_MAX_ENTRIES],
            count: 0,
            lookups: 0,
            redirects: 0,
            misses: 0,
        }
    }

    /// Set the map name.
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_MAP_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    /// Insert or update an entry.
    pub fn insert(&mut self, key: usize, ifindex: u32, prog_id: u32) -> Result<()> {
        if key >= DEVMAP_MAX_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        if !self.entries[key].active {
            self.count += 1;
        }
        self.entries[key] = XdpDevMapEntry {
            ifindex,
            prog_id,
            active: true,
        };
        Ok(())
    }

    /// Look up an entry by key.
    pub fn lookup(&mut self, key: usize) -> Result<&XdpDevMapEntry> {
        self.lookups += 1;
        if key >= DEVMAP_MAX_ENTRIES || !self.entries[key].active {
            self.misses += 1;
            return Err(Error::NotFound);
        }
        Ok(&self.entries[key])
    }

    /// Delete an entry by key.
    pub fn delete(&mut self, key: usize) -> Result<()> {
        if key >= DEVMAP_MAX_ENTRIES || !self.entries[key].active {
            return Err(Error::NotFound);
        }
        self.entries[key].active = false;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Number of active entries.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether the map is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Perform a redirect lookup and record the redirect.
    pub fn redirect(&mut self, key: usize) -> Result<(u32, u32)> {
        self.lookups += 1;
        if key >= DEVMAP_MAX_ENTRIES || !self.entries[key].active {
            self.misses += 1;
            return Err(Error::NotFound);
        }
        self.redirects += 1;
        let e = &self.entries[key];
        Ok((e.ifindex, e.prog_id))
    }
}

// =========================================================================
// XdpCpuMapEntry
// =========================================================================

/// Single entry in a CPU redirect map.
///
/// Maps a key to a target CPU for XDP_REDIRECT, used to steer
/// packets to specific cores for processing.
#[derive(Debug, Clone, Copy)]
pub struct XdpCpuMapEntry {
    /// Target CPU identifier.
    pub cpu_id: u32,
    /// Queue size allocated for this CPU.
    pub queue_size: u32,
    /// Optional BPF program to run on the target CPU (0 = none).
    pub prog_id: u32,
    /// Whether this entry is populated.
    pub active: bool,
    /// Packets steered to this CPU.
    pub packets: u64,
    /// Packets dropped due to full queue.
    pub drops: u64,
}

impl XdpCpuMapEntry {
    /// Create an empty entry.
    pub const fn new() -> Self {
        Self {
            cpu_id: 0,
            queue_size: 0,
            prog_id: 0,
            active: false,
            packets: 0,
            drops: 0,
        }
    }
}

// =========================================================================
// XdpCpuMap
// =========================================================================

/// CPU redirect map (`BPF_MAP_TYPE_CPUMAP`).
///
/// Allows XDP programs to steer packets to specific CPUs, enabling
/// receive-side scaling at the XDP layer. Each entry maps an index
/// to a CPU ID with a per-CPU queue.
pub struct XdpCpuMap {
    /// Map name.
    name: [u8; MAX_MAP_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Map entries.
    entries: [XdpCpuMapEntry; CPUMAP_MAX_ENTRIES],
    /// Number of active entries.
    count: usize,
    /// Total redirects.
    pub total_redirects: u64,
    /// Total drops across all CPUs.
    pub total_drops: u64,
}

impl XdpCpuMap {
    /// Create a new empty CPU map.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_MAP_NAME_LEN],
            name_len: 0,
            entries: [const { XdpCpuMapEntry::new() }; CPUMAP_MAX_ENTRIES],
            count: 0,
            total_redirects: 0,
            total_drops: 0,
        }
    }

    /// Set the map name.
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_MAP_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    /// Insert or update a CPU map entry.
    pub fn insert(&mut self, key: usize, cpu_id: u32, queue_size: u32, prog_id: u32) -> Result<()> {
        if key >= CPUMAP_MAX_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        if queue_size == 0 {
            return Err(Error::InvalidArgument);
        }
        if !self.entries[key].active {
            self.count += 1;
        }
        self.entries[key] = XdpCpuMapEntry {
            cpu_id,
            queue_size,
            prog_id,
            active: true,
            packets: 0,
            drops: 0,
        };
        Ok(())
    }

    /// Look up an entry by key.
    pub fn lookup(&self, key: usize) -> Result<&XdpCpuMapEntry> {
        if key >= CPUMAP_MAX_ENTRIES || !self.entries[key].active {
            return Err(Error::NotFound);
        }
        Ok(&self.entries[key])
    }

    /// Perform a redirect to a CPU.
    pub fn redirect(&mut self, key: usize) -> Result<u32> {
        if key >= CPUMAP_MAX_ENTRIES || !self.entries[key].active {
            return Err(Error::NotFound);
        }
        self.entries[key].packets += 1;
        self.total_redirects += 1;
        Ok(self.entries[key].cpu_id)
    }

    /// Record a drop on the specified entry.
    pub fn record_drop(&mut self, key: usize) {
        if key < CPUMAP_MAX_ENTRIES && self.entries[key].active {
            self.entries[key].drops += 1;
            self.total_drops += 1;
        }
    }

    /// Delete an entry.
    pub fn delete(&mut self, key: usize) -> Result<()> {
        if key >= CPUMAP_MAX_ENTRIES || !self.entries[key].active {
            return Err(Error::NotFound);
        }
        self.entries[key].active = false;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Number of active entries.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether the map is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// =========================================================================
// XdpXskEntry
// =========================================================================

/// AF_XDP socket map entry.
///
/// Represents a user-space socket that can receive XDP-redirected
/// packets via a shared UMEM ring buffer.
pub struct XdpXskEntry {
    /// Socket file descriptor (simulated).
    pub socket_fd: u32,
    /// Queue index within the socket.
    pub queue_id: u32,
    /// Whether this entry is populated.
    pub active: bool,
    /// RX ring: packet data storage.
    rx_ring: [[u8; XSK_FRAME_SIZE]; XSK_RING_SIZE],
    /// RX ring: length of each frame.
    rx_ring_len: [usize; XSK_RING_SIZE],
    /// RX ring producer index (kernel writes).
    rx_prod: usize,
    /// RX ring consumer index (user-space reads).
    rx_cons: usize,
    /// Total frames enqueued.
    pub frames_rx: u64,
    /// Total frames dropped (ring full).
    pub frames_dropped: u64,
}

impl XdpXskEntry {
    /// Create an empty AF_XDP socket entry.
    pub const fn new() -> Self {
        Self {
            socket_fd: 0,
            queue_id: 0,
            active: false,
            rx_ring: [[0u8; XSK_FRAME_SIZE]; XSK_RING_SIZE],
            rx_ring_len: [0usize; XSK_RING_SIZE],
            rx_prod: 0,
            rx_cons: 0,
            frames_rx: 0,
            frames_dropped: 0,
        }
    }

    /// Bind this entry to a socket.
    pub fn bind(&mut self, socket_fd: u32, queue_id: u32) -> Result<()> {
        if self.active {
            return Err(Error::AlreadyExists);
        }
        self.socket_fd = socket_fd;
        self.queue_id = queue_id;
        self.active = true;
        self.rx_prod = 0;
        self.rx_cons = 0;
        self.frames_rx = 0;
        self.frames_dropped = 0;
        Ok(())
    }

    /// Enqueue a packet into the RX ring.
    ///
    /// Called by the kernel when an XDP program redirects a packet
    /// to this AF_XDP socket.
    pub fn enqueue(&mut self, data: &[u8]) -> Result<()> {
        if !self.active {
            return Err(Error::InvalidArgument);
        }
        if data.len() > XSK_FRAME_SIZE {
            return Err(Error::InvalidArgument);
        }

        let next_prod = (self.rx_prod + 1) % XSK_RING_SIZE;
        if next_prod == self.rx_cons {
            // Ring full
            self.frames_dropped += 1;
            return Err(Error::WouldBlock);
        }

        self.rx_ring[self.rx_prod][..data.len()].copy_from_slice(data);
        self.rx_ring_len[self.rx_prod] = data.len();
        self.rx_prod = next_prod;
        self.frames_rx += 1;
        Ok(())
    }

    /// Dequeue a packet from the RX ring (user-space read).
    ///
    /// Copies frame data into `buf` and returns the length.
    pub fn dequeue(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.active {
            return Err(Error::InvalidArgument);
        }
        if self.rx_cons == self.rx_prod {
            return Err(Error::WouldBlock);
        }

        let len = self.rx_ring_len[self.rx_cons];
        if buf.len() < len {
            return Err(Error::InvalidArgument);
        }

        buf[..len].copy_from_slice(&self.rx_ring[self.rx_cons][..len]);
        self.rx_cons = (self.rx_cons + 1) % XSK_RING_SIZE;
        Ok(len)
    }

    /// Number of frames available to read.
    pub fn available(&self) -> usize {
        if self.rx_prod >= self.rx_cons {
            self.rx_prod - self.rx_cons
        } else {
            XSK_RING_SIZE - self.rx_cons + self.rx_prod
        }
    }

    /// Unbind the socket.
    pub fn unbind(&mut self) {
        self.active = false;
        self.rx_prod = 0;
        self.rx_cons = 0;
    }
}

// =========================================================================
// XdpXskMap
// =========================================================================

/// AF_XDP socket map (`BPF_MAP_TYPE_XSKMAP`).
///
/// Maps queue indices to AF_XDP sockets for zero-copy packet
/// delivery to user-space applications.
pub struct XdpXskMap {
    /// Map name.
    name: [u8; MAX_MAP_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// Socket entries.
    entries: [XdpXskEntry; XSKMAP_MAX_ENTRIES],
    /// Number of active entries.
    count: usize,
}

impl XdpXskMap {
    /// Create a new empty XSK map.
    pub const fn new() -> Self {
        Self {
            name: [0u8; MAX_MAP_NAME_LEN],
            name_len: 0,
            entries: [const { XdpXskEntry::new() }; XSKMAP_MAX_ENTRIES],
            count: 0,
        }
    }

    /// Set the map name.
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(MAX_MAP_NAME_LEN);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len;
    }

    /// Bind a socket to a map entry.
    pub fn bind(&mut self, key: usize, socket_fd: u32, queue_id: u32) -> Result<()> {
        if key >= XSKMAP_MAX_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        self.entries[key].bind(socket_fd, queue_id)?;
        self.count += 1;
        Ok(())
    }

    /// Unbind a socket from a map entry.
    pub fn unbind(&mut self, key: usize) -> Result<()> {
        if key >= XSKMAP_MAX_ENTRIES || !self.entries[key].active {
            return Err(Error::NotFound);
        }
        self.entries[key].unbind();
        self.count = self.count.saturating_sub(1);
        Ok(())
    }

    /// Redirect a packet to the AF_XDP socket at the given key.
    pub fn redirect(&mut self, key: usize, data: &[u8]) -> Result<()> {
        if key >= XSKMAP_MAX_ENTRIES || !self.entries[key].active {
            return Err(Error::NotFound);
        }
        self.entries[key].enqueue(data)
    }

    /// Read a packet from the AF_XDP socket at the given key.
    pub fn read(&mut self, key: usize, buf: &mut [u8]) -> Result<usize> {
        if key >= XSKMAP_MAX_ENTRIES || !self.entries[key].active {
            return Err(Error::NotFound);
        }
        self.entries[key].dequeue(buf)
    }

    /// Number of active entries.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether the map is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}

// =========================================================================
// XdpMetadata
// =========================================================================

/// Per-packet metadata carried through the XDP pipeline.
///
/// Provides hardware offload hints and software-set marks that
/// XDP programs can read and write. Modeled after the Linux
/// `struct xdp_hints_*` and `xdp_md` fields.
#[derive(Debug, Clone, Copy)]
pub struct XdpMetadata {
    /// Hardware RX timestamp in nanoseconds (0 = not available).
    pub rx_timestamp_ns: u64,
    /// RSS hash computed by the NIC.
    pub rx_hash: u32,
    /// RSS hash type (e.g., L3-only, L3+L4).
    pub rx_hash_type: u32,
    /// VLAN tag if present (0 = no VLAN).
    pub vlan_tci: u16,
    /// Whether a VLAN tag is present.
    pub vlan_present: bool,
    /// Software mark set by an XDP program.
    pub mark: u32,
    /// Ingress interface index.
    pub ingress_ifindex: u32,
    /// Egress interface index (set by redirect).
    pub egress_ifindex: u32,
    /// Packet priority / QoS class.
    pub priority: u32,
    /// BTF ID for metadata type (for XDP hints).
    pub btf_id: u32,
}

impl XdpMetadata {
    /// Create empty metadata.
    pub const fn new() -> Self {
        Self {
            rx_timestamp_ns: 0,
            rx_hash: 0,
            rx_hash_type: 0,
            vlan_tci: 0,
            vlan_present: false,
            mark: 0,
            ingress_ifindex: 0,
            egress_ifindex: 0,
            priority: 0,
            btf_id: 0,
        }
    }

    /// Set hardware offload fields.
    pub fn set_hw_metadata(&mut self, timestamp_ns: u64, hash: u32, hash_type: u32) {
        self.rx_timestamp_ns = timestamp_ns;
        self.rx_hash = hash;
        self.rx_hash_type = hash_type;
    }

    /// Set VLAN information.
    pub fn set_vlan(&mut self, tci: u16) {
        self.vlan_tci = tci;
        self.vlan_present = tci != 0;
    }

    /// Clear all metadata.
    pub fn clear(&mut self) {
        *self = Self::new();
    }
}

impl Default for XdpMetadata {
    fn default() -> Self {
        Self::new()
    }
}

// =========================================================================
// XdpBulkQueue
// =========================================================================

/// Batched packet TX queue for XDP redirects.
///
/// Accumulates packets destined for the same output interface and
/// flushes them in bulk to amortize per-packet TX overhead. This
/// mirrors the Linux `struct xdp_frame_bulk` mechanism.
pub struct XdpBulkQueue {
    /// Target interface index for this batch.
    pub target_ifindex: u32,
    /// Buffered packet data.
    packets: [[u8; BULK_PKT_SIZE]; BULK_QUEUE_SIZE],
    /// Length of each buffered packet.
    pkt_len: [usize; BULK_QUEUE_SIZE],
    /// Number of packets currently buffered.
    count: usize,
    /// Total packets flushed.
    pub total_flushed: u64,
    /// Total flushes performed.
    pub flush_count: u64,
}

impl XdpBulkQueue {
    /// Create a new empty bulk queue for the given interface.
    pub const fn new(target_ifindex: u32) -> Self {
        Self {
            target_ifindex,
            packets: [[0u8; BULK_PKT_SIZE]; BULK_QUEUE_SIZE],
            pkt_len: [0usize; BULK_QUEUE_SIZE],
            count: 0,
            total_flushed: 0,
            flush_count: 0,
        }
    }

    /// Enqueue a packet for batched transmission.
    ///
    /// Returns `Err(WouldBlock)` if the queue is full and needs
    /// flushing.
    pub fn enqueue(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > BULK_PKT_SIZE {
            return Err(Error::InvalidArgument);
        }
        if self.count >= BULK_QUEUE_SIZE {
            return Err(Error::WouldBlock);
        }
        self.packets[self.count][..data.len()].copy_from_slice(data);
        self.pkt_len[self.count] = data.len();
        self.count += 1;
        Ok(())
    }

    /// Flush all buffered packets.
    ///
    /// Returns the number of packets that were in the queue.
    /// In a real kernel this would invoke the NIC's ndo_xdp_xmit.
    pub fn flush(&mut self) -> usize {
        let flushed = self.count;
        if flushed > 0 {
            self.total_flushed += flushed as u64;
            self.flush_count += 1;
            self.count = 0;
        }
        flushed
    }

    /// Number of buffered packets.
    pub const fn pending(&self) -> usize {
        self.count
    }

    /// Whether the queue is full.
    pub const fn is_full(&self) -> bool {
        self.count >= BULK_QUEUE_SIZE
    }

    /// Whether the queue is empty.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Get buffered packet data by index.
    pub fn get_packet(&self, index: usize) -> Result<&[u8]> {
        if index >= self.count {
            return Err(Error::NotFound);
        }
        let len = self.pkt_len[index];
        Ok(&self.packets[index][..len])
    }
}

// =========================================================================
// XdpMultiProgMode
// =========================================================================

/// Execution mode for multi-program XDP dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum XdpMultiProgMode {
    /// Run all programs in order; last non-pass verdict wins.
    #[default]
    Chained,
    /// Round-robin: run one program per packet, cycling through.
    RoundRobin,
    /// Run all programs; first non-pass verdict wins immediately.
    FirstMatch,
}

// =========================================================================
// XdpMultiProg
// =========================================================================

/// Multi-program XDP dispatcher.
///
/// Supports attaching multiple BPF programs to a single interface
/// and dispatching packets through them according to the configured
/// [`XdpMultiProgMode`].
pub struct XdpMultiProg {
    /// Program IDs (0 = empty slot).
    prog_ids: [u32; MAX_MULTI_PROGS],
    /// Number of attached programs.
    count: usize,
    /// Execution mode.
    pub mode: XdpMultiProgMode,
    /// Round-robin index (for RoundRobin mode).
    rr_index: usize,
    /// Per-program invocation counters.
    invocations: [u64; MAX_MULTI_PROGS],
}

impl XdpMultiProg {
    /// Create a new empty multi-program dispatcher.
    pub const fn new() -> Self {
        Self {
            prog_ids: [0u32; MAX_MULTI_PROGS],
            count: 0,
            mode: XdpMultiProgMode::Chained,
            rr_index: 0,
            invocations: [0u64; MAX_MULTI_PROGS],
        }
    }

    /// Attach a program to the dispatcher.
    pub fn attach(&mut self, prog_id: u32) -> Result<usize> {
        if prog_id == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_MULTI_PROGS {
            return Err(Error::OutOfMemory);
        }
        // Check for duplicate
        for i in 0..self.count {
            if self.prog_ids[i] == prog_id {
                return Err(Error::AlreadyExists);
            }
        }
        let idx = self.count;
        self.prog_ids[idx] = prog_id;
        self.invocations[idx] = 0;
        self.count += 1;
        Ok(idx)
    }

    /// Detach a program by its ID.
    pub fn detach(&mut self, prog_id: u32) -> Result<()> {
        let pos = (0..self.count)
            .find(|&i| self.prog_ids[i] == prog_id)
            .ok_or(Error::NotFound)?;

        // Shift remaining entries
        for i in pos..self.count - 1 {
            self.prog_ids[i] = self.prog_ids[i + 1];
            self.invocations[i] = self.invocations[i + 1];
        }
        self.count -= 1;
        self.prog_ids[self.count] = 0;
        self.invocations[self.count] = 0;

        // Adjust round-robin index
        if self.rr_index >= self.count && self.count > 0 {
            self.rr_index = 0;
        }
        Ok(())
    }

    /// Select the next program(s) to run based on the mode.
    ///
    /// Returns the program ID to run next (for RoundRobin) or the
    /// first program ID (for Chained/FirstMatch — caller iterates).
    pub fn next_prog(&mut self) -> Result<u32> {
        if self.count == 0 {
            return Err(Error::NotFound);
        }
        match self.mode {
            XdpMultiProgMode::RoundRobin => {
                let idx = self.rr_index;
                self.invocations[idx] += 1;
                self.rr_index = (self.rr_index + 1) % self.count;
                Ok(self.prog_ids[idx])
            }
            _ => {
                // For Chained and FirstMatch, return the
                // first program; the caller iterates
                self.invocations[0] += 1;
                Ok(self.prog_ids[0])
            }
        }
    }

    /// Get all program IDs for iteration (Chained/FirstMatch).
    ///
    /// Copies active program IDs into `out` and returns the count.
    pub fn all_progs(&self, out: &mut [u32]) -> usize {
        let n = self.count.min(out.len());
        out[..n].copy_from_slice(&self.prog_ids[..n]);
        n
    }

    /// Number of attached programs.
    pub const fn len(&self) -> usize {
        self.count
    }

    /// Whether no programs are attached.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Record an invocation for a specific program index.
    pub fn record_invocation(&mut self, index: usize) {
        if index < self.count {
            self.invocations[index] += 1;
        }
    }

    /// Get the invocation count for a program index.
    pub fn invocation_count(&self, index: usize) -> u64 {
        if index < self.count {
            self.invocations[index]
        } else {
            0
        }
    }
}

// =========================================================================
// RedirectMapType
// =========================================================================

/// Type of XDP redirect map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectMapType {
    /// Device map (`BPF_MAP_TYPE_DEVMAP`).
    DevMap,
    /// CPU map (`BPF_MAP_TYPE_CPUMAP`).
    CpuMap,
    /// AF_XDP socket map (`BPF_MAP_TYPE_XSKMAP`).
    XskMap,
}

// =========================================================================
// PerIfState
// =========================================================================

/// Per-interface XDP core state.
///
/// Tracks the multi-program dispatcher and bulk queue for each
/// network interface.
pub struct PerIfState {
    /// Interface index.
    pub ifindex: u32,
    /// Whether this slot is active.
    pub active: bool,
    /// Multi-program dispatcher.
    pub multi_prog: XdpMultiProg,
    /// Bulk transmit queue.
    pub bulk_queue: XdpBulkQueue,
    /// Per-packet metadata template.
    pub metadata: XdpMetadata,
    /// Total packets processed.
    pub packets_processed: u64,
    /// Total redirects.
    pub redirects: u64,
    /// Total drops.
    pub drops: u64,
}

impl PerIfState {
    /// Create a new inactive per-interface state.
    pub const fn new() -> Self {
        Self {
            ifindex: 0,
            active: false,
            multi_prog: XdpMultiProg::new(),
            bulk_queue: XdpBulkQueue::new(0),
            metadata: XdpMetadata::new(),
            packets_processed: 0,
            redirects: 0,
            drops: 0,
        }
    }

    /// Activate this interface slot.
    pub fn activate(&mut self, ifindex: u32) {
        self.ifindex = ifindex;
        self.active = true;
        self.bulk_queue.target_ifindex = ifindex;
        self.packets_processed = 0;
        self.redirects = 0;
        self.drops = 0;
    }

    /// Deactivate and reset.
    pub fn deactivate(&mut self) {
        self.active = false;
        self.multi_prog = XdpMultiProg::new();
        self.bulk_queue.flush();
        self.metadata.clear();
    }
}

// =========================================================================
// XdpCoreRegistry
// =========================================================================

/// Central XDP core coordinator.
///
/// Ties together per-interface state, redirect maps, and provides
/// the top-level API for XDP core operations.
pub struct XdpCoreRegistry {
    /// Per-interface state.
    interfaces: [PerIfState; MAX_CORE_INTERFACES],
    /// Device redirect maps.
    dev_maps: [Option<XdpDevMap>; MAX_REDIRECT_MAPS],
    /// CPU redirect maps.
    cpu_maps: [Option<XdpCpuMap>; MAX_REDIRECT_MAPS],
    /// AF_XDP socket maps.
    xsk_maps: [Option<XdpXskMap>; MAX_REDIRECT_MAPS],
    /// Number of active interfaces.
    pub active_interfaces: usize,
    /// Total packets processed across all interfaces.
    pub total_packets: u64,
    /// Total redirects across all interfaces.
    pub total_redirects: u64,
}

impl XdpCoreRegistry {
    /// Create a new empty registry.
    pub const fn new() -> Self {
        Self {
            interfaces: [const { PerIfState::new() }; MAX_CORE_INTERFACES],
            dev_maps: [const { None }; MAX_REDIRECT_MAPS],
            cpu_maps: [const { None }; MAX_REDIRECT_MAPS],
            xsk_maps: [const { None }; MAX_REDIRECT_MAPS],
            active_interfaces: 0,
            total_packets: 0,
            total_redirects: 0,
        }
    }

    /// Register an interface for XDP core processing.
    pub fn register_interface(&mut self, ifindex: u32) -> Result<usize> {
        // Check for duplicate
        for i in 0..MAX_CORE_INTERFACES {
            if self.interfaces[i].active && self.interfaces[i].ifindex == ifindex {
                return Err(Error::AlreadyExists);
            }
        }

        let slot = self
            .interfaces
            .iter()
            .position(|s| !s.active)
            .ok_or(Error::OutOfMemory)?;

        self.interfaces[slot].activate(ifindex);
        self.active_interfaces += 1;
        Ok(slot)
    }

    /// Unregister an interface.
    pub fn unregister_interface(&mut self, ifindex: u32) -> Result<()> {
        let slot = self
            .interfaces
            .iter()
            .position(|s| s.active && s.ifindex == ifindex)
            .ok_or(Error::NotFound)?;

        self.interfaces[slot].deactivate();
        self.active_interfaces = self.active_interfaces.saturating_sub(1);
        Ok(())
    }

    /// Get interface state by ifindex.
    pub fn interface(&self, ifindex: u32) -> Result<&PerIfState> {
        self.interfaces
            .iter()
            .find(|s| s.active && s.ifindex == ifindex)
            .ok_or(Error::NotFound)
    }

    /// Get mutable interface state by ifindex.
    pub fn interface_mut(&mut self, ifindex: u32) -> Result<&mut PerIfState> {
        self.interfaces
            .iter_mut()
            .find(|s| s.active && s.ifindex == ifindex)
            .ok_or(Error::NotFound)
    }

    /// Attach a program to an interface's multi-prog dispatcher.
    pub fn attach_program(&mut self, ifindex: u32, prog_id: u32) -> Result<usize> {
        let iface = self.interface_mut(ifindex)?;
        iface.multi_prog.attach(prog_id)
    }

    /// Detach a program from an interface.
    pub fn detach_program(&mut self, ifindex: u32, prog_id: u32) -> Result<()> {
        let iface = self.interface_mut(ifindex)?;
        iface.multi_prog.detach(prog_id)
    }

    /// Set the multi-prog execution mode for an interface.
    pub fn set_multi_prog_mode(&mut self, ifindex: u32, mode: XdpMultiProgMode) -> Result<()> {
        let iface = self.interface_mut(ifindex)?;
        iface.multi_prog.mode = mode;
        Ok(())
    }

    // ── DevMap operations ────────────────────────────────────────

    /// Create a new device redirect map.
    ///
    /// Returns the map index.
    pub fn create_dev_map(&mut self, name: &[u8]) -> Result<usize> {
        let slot = self
            .dev_maps
            .iter()
            .position(|m| m.is_none())
            .ok_or(Error::OutOfMemory)?;

        let mut map = XdpDevMap::new();
        map.set_name(name);
        self.dev_maps[slot] = Some(map);
        Ok(slot)
    }

    /// Get a reference to a device map.
    pub fn dev_map(&self, index: usize) -> Result<&XdpDevMap> {
        if index >= MAX_REDIRECT_MAPS {
            return Err(Error::InvalidArgument);
        }
        self.dev_maps[index].as_ref().ok_or(Error::NotFound)
    }

    /// Get a mutable reference to a device map.
    pub fn dev_map_mut(&mut self, index: usize) -> Result<&mut XdpDevMap> {
        if index >= MAX_REDIRECT_MAPS {
            return Err(Error::InvalidArgument);
        }
        self.dev_maps[index].as_mut().ok_or(Error::NotFound)
    }

    /// Delete a device map.
    pub fn delete_dev_map(&mut self, index: usize) -> Result<()> {
        if index >= MAX_REDIRECT_MAPS {
            return Err(Error::InvalidArgument);
        }
        if self.dev_maps[index].is_none() {
            return Err(Error::NotFound);
        }
        self.dev_maps[index] = None;
        Ok(())
    }

    // ── CpuMap operations ────────────────────────────────────────

    /// Create a new CPU redirect map.
    pub fn create_cpu_map(&mut self, name: &[u8]) -> Result<usize> {
        let slot = self
            .cpu_maps
            .iter()
            .position(|m| m.is_none())
            .ok_or(Error::OutOfMemory)?;

        let mut map = XdpCpuMap::new();
        map.set_name(name);
        self.cpu_maps[slot] = Some(map);
        Ok(slot)
    }

    /// Get a reference to a CPU map.
    pub fn cpu_map(&self, index: usize) -> Result<&XdpCpuMap> {
        if index >= MAX_REDIRECT_MAPS {
            return Err(Error::InvalidArgument);
        }
        self.cpu_maps[index].as_ref().ok_or(Error::NotFound)
    }

    /// Get a mutable reference to a CPU map.
    pub fn cpu_map_mut(&mut self, index: usize) -> Result<&mut XdpCpuMap> {
        if index >= MAX_REDIRECT_MAPS {
            return Err(Error::InvalidArgument);
        }
        self.cpu_maps[index].as_mut().ok_or(Error::NotFound)
    }

    /// Delete a CPU map.
    pub fn delete_cpu_map(&mut self, index: usize) -> Result<()> {
        if index >= MAX_REDIRECT_MAPS {
            return Err(Error::InvalidArgument);
        }
        if self.cpu_maps[index].is_none() {
            return Err(Error::NotFound);
        }
        self.cpu_maps[index] = None;
        Ok(())
    }

    // ── XskMap operations ────────────────────────────────────────

    /// Create a new AF_XDP socket map.
    pub fn create_xsk_map(&mut self, name: &[u8]) -> Result<usize> {
        let slot = self
            .xsk_maps
            .iter()
            .position(|m| m.is_none())
            .ok_or(Error::OutOfMemory)?;

        let mut map = XdpXskMap::new();
        map.set_name(name);
        self.xsk_maps[slot] = Some(map);
        Ok(slot)
    }

    /// Get a reference to an XSK map.
    pub fn xsk_map(&self, index: usize) -> Result<&XdpXskMap> {
        if index >= MAX_REDIRECT_MAPS {
            return Err(Error::InvalidArgument);
        }
        self.xsk_maps[index].as_ref().ok_or(Error::NotFound)
    }

    /// Get a mutable reference to an XSK map.
    pub fn xsk_map_mut(&mut self, index: usize) -> Result<&mut XdpXskMap> {
        if index >= MAX_REDIRECT_MAPS {
            return Err(Error::InvalidArgument);
        }
        self.xsk_maps[index].as_mut().ok_or(Error::NotFound)
    }

    /// Delete an XSK map.
    pub fn delete_xsk_map(&mut self, index: usize) -> Result<()> {
        if index >= MAX_REDIRECT_MAPS {
            return Err(Error::InvalidArgument);
        }
        if self.xsk_maps[index].is_none() {
            return Err(Error::NotFound);
        }
        self.xsk_maps[index] = None;
        Ok(())
    }

    // ── Flush operations ─────────────────────────────────────────

    /// Flush bulk queues for all active interfaces.
    ///
    /// Returns the total number of packets flushed.
    pub fn flush_all_bulk_queues(&mut self) -> usize {
        let mut total = 0;
        for iface in &mut self.interfaces {
            if iface.active {
                total += iface.bulk_queue.flush();
            }
        }
        total
    }

    /// Flush the bulk queue for a specific interface.
    pub fn flush_bulk_queue(&mut self, ifindex: u32) -> Result<usize> {
        let iface = self.interface_mut(ifindex)?;
        Ok(iface.bulk_queue.flush())
    }
}
