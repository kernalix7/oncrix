// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! NVMe over Fabrics (NVMe-oF) host transport.
//!
//! Implements a transport-agnostic NVMe-oF host layer supporting RDMA,
//! TCP, and Fibre Channel fabric types. The host connects to remote
//! NVMe subsystems over the chosen fabric transport and presents them
//! as locally accessible namespaces.
//!
//! # Architecture
//!
//! - [`FabricsTransportType`] — RDMA / TCP / FC
//! - [`FabricsAddress`] — target address (IP:port or FC WWPN)
//! - [`FabricsQueuePair`] — a submission/completion queue pair over fabric
//! - [`FabricsController`] — connection to a remote NVMe subsystem
//! - [`FabricsDiscoveryEntry`] — entry returned by the Discovery controller
//! - [`FabricsSubsystem`] — registry of controllers and discovery entries
//!
//! # Connection Flow
//!
//! 1. Discover subsystems via the Discovery NQN on a well-known port.
//! 2. For each target subsystem, call `connect` with its address.
//! 3. Create I/O queue pairs after admin queue is established.
//! 4. Submit I/O requests via `submit_io`; poll completions via `poll_completion`.
//!
//! Reference: NVM Express over Fabrics Specification 1.1,
//!            NVM Express Base Specification 2.0.

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of NVMe-oF controllers.
const MAX_CONTROLLERS: usize = 8;

/// Maximum number of queue pairs per controller.
const MAX_QUEUE_PAIRS: usize = 16;

/// Maximum number of discovery log entries.
const MAX_DISCOVERY_ENTRIES: usize = 32;

/// Maximum NQN length (NVMe Qualified Name).
const NQN_LEN: usize = 64;

/// Maximum transport address length.
const TRADDR_LEN: usize = 64;

/// Maximum transport service ID length (port number string).
const TRSVCID_LEN: usize = 32;

/// Default NVMe-oF TCP port.
pub const NVMF_TCP_PORT: u16 = 4420;

/// Default NVMe-oF RDMA port.
pub const NVMF_RDMA_PORT: u16 = 4420;

/// Discovery NQN (well-known name for the discovery controller).
pub const NVMF_DISCOVERY_NQN: &[u8; 22] = b"nqn.2014-08.org.nvmexp";

/// Keep-alive timeout in ticks (30 s at 1000 tick/s).
const KEEP_ALIVE_TIMEOUT_TICKS: u64 = 30_000;

// ---------------------------------------------------------------------------
// FabricsTransportType
// ---------------------------------------------------------------------------

/// NVMe-oF fabric transport type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FabricsTransportType {
    /// RDMA transport (RoCE v2, iWARP).
    #[default]
    Rdma,
    /// TCP transport (NVMe/TCP).
    Tcp,
    /// Fibre Channel transport.
    Fc,
}

impl FabricsTransportType {
    /// Returns the default port for this transport type.
    pub fn default_port(self) -> u16 {
        match self {
            FabricsTransportType::Rdma | FabricsTransportType::Tcp => NVMF_TCP_PORT,
            FabricsTransportType::Fc => 0,
        }
    }

    /// Returns the human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            FabricsTransportType::Rdma => "rdma",
            FabricsTransportType::Tcp => "tcp",
            FabricsTransportType::Fc => "fc",
        }
    }
}

// ---------------------------------------------------------------------------
// FabricsAddress
// ---------------------------------------------------------------------------

/// Network address of a remote NVMe-oF target.
#[derive(Debug, Clone, Copy)]
pub struct FabricsAddress {
    /// Transport address (IPv4/v6 string or FC WWPN), null-terminated ASCII.
    pub traddr: [u8; TRADDR_LEN],
    /// Transport service ID (port number), null-terminated ASCII.
    pub trsvcid: [u8; TRSVCID_LEN],
    /// Transport type.
    pub transport: FabricsTransportType,
}

impl Default for FabricsAddress {
    fn default() -> Self {
        Self::new()
    }
}

impl FabricsAddress {
    /// Creates a zeroed address.
    pub const fn new() -> Self {
        Self {
            traddr: [0u8; TRADDR_LEN],
            trsvcid: [0u8; TRSVCID_LEN],
            transport: FabricsTransportType::Tcp,
        }
    }

    /// Creates an address from raw bytes.
    pub fn from_bytes(
        traddr: &[u8],
        trsvcid: &[u8],
        transport: FabricsTransportType,
    ) -> Result<Self> {
        if traddr.len() > TRADDR_LEN || trsvcid.len() > TRSVCID_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut addr = Self::new();
        addr.traddr[..traddr.len()].copy_from_slice(traddr);
        addr.trsvcid[..trsvcid.len()].copy_from_slice(trsvcid);
        addr.transport = transport;
        Ok(addr)
    }

    /// Returns `true` if the address is empty (no traddr set).
    pub fn is_empty(&self) -> bool {
        self.traddr[0] == 0
    }
}

// ---------------------------------------------------------------------------
// FabricsQueueState
// ---------------------------------------------------------------------------

/// State of a single fabric queue pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FabricsQueueState {
    /// Queue not yet created.
    #[default]
    Idle,
    /// Queue connection in progress.
    Connecting,
    /// Queue is live and accepting I/O.
    Live,
    /// Queue encountered an error, pending reconnect.
    Error,
}

// ---------------------------------------------------------------------------
// FabricsQueuePair
// ---------------------------------------------------------------------------

/// A submission/completion queue pair over the NVMe-oF fabric.
///
/// Queue 0 is always the admin queue; queues 1..N are I/O queues.
#[derive(Debug, Clone, Copy)]
pub struct FabricsQueuePair {
    /// Queue ID (0 = admin, 1+ = I/O).
    pub queue_id: u16,
    /// Maximum number of outstanding commands.
    pub queue_size: u16,
    /// Current queue state.
    pub state: FabricsQueueState,
    /// Number of commands submitted.
    pub submitted: u64,
    /// Number of completions received.
    pub completed: u64,
    /// Number of errors encountered.
    pub errors: u64,
}

impl Default for FabricsQueuePair {
    fn default() -> Self {
        Self::new()
    }
}

impl FabricsQueuePair {
    /// Creates a zeroed, idle queue pair.
    pub const fn new() -> Self {
        Self {
            queue_id: 0,
            queue_size: 0,
            state: FabricsQueueState::Idle,
            submitted: 0,
            completed: 0,
            errors: 0,
        }
    }

    /// Creates a queue pair with the given ID and depth.
    pub const fn with_id(queue_id: u16, queue_size: u16) -> Self {
        Self {
            queue_id,
            queue_size,
            state: FabricsQueueState::Idle,
            submitted: 0,
            completed: 0,
            errors: 0,
        }
    }

    /// Returns `true` if this queue pair is ready to accept commands.
    pub fn is_live(&self) -> bool {
        self.state == FabricsQueueState::Live
    }

    /// Returns `true` if this queue pair slot is unused.
    pub fn is_empty(&self) -> bool {
        self.queue_size == 0
    }

    /// Marks the queue as connected and live.
    pub fn set_live(&mut self) {
        self.state = FabricsQueueState::Live;
    }

    /// Records a submitted command.
    pub fn record_submit(&mut self) {
        self.submitted = self.submitted.wrapping_add(1);
    }

    /// Records a received completion.
    pub fn record_completion(&mut self) {
        self.completed = self.completed.wrapping_add(1);
    }
}

// ---------------------------------------------------------------------------
// FabricsControllerState
// ---------------------------------------------------------------------------

/// Lifecycle state of a fabrics controller connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FabricsControllerState {
    /// Connection not yet started.
    #[default]
    New,
    /// Actively connecting.
    Connecting,
    /// Admin queue established; I/O queues may be created.
    Live,
    /// Attempting to reconnect after a transport error.
    Reconnecting,
    /// Controller is dead — no more reconnect attempts.
    Dead,
}

// ---------------------------------------------------------------------------
// FabricsController
// ---------------------------------------------------------------------------

/// A connection to a remote NVMe subsystem over a fabric transport.
///
/// Each controller has one admin queue (index 0) and up to
/// `MAX_QUEUE_PAIRS - 1` I/O queue pairs.
pub struct FabricsController {
    /// Remote target address.
    pub address: FabricsAddress,
    /// NVMe Qualified Name of the target subsystem.
    pub subsys_nqn: [u8; NQN_LEN],
    /// Host NQN identifying this initiator.
    pub host_nqn: [u8; NQN_LEN],
    /// Controller state.
    pub state: FabricsControllerState,
    /// Queue pairs (index 0 = admin).
    queues: [FabricsQueuePair; MAX_QUEUE_PAIRS],
    /// Number of allocated queue pairs.
    queue_count: usize,
    /// Whether this controller slot is occupied.
    pub active: bool,
    /// Keep-alive send tick (last time a keep-alive was sent).
    pub keepalive_tick: u64,
    /// Number of consecutive reconnect attempts.
    pub reconnect_attempts: u32,
    /// Controller ID assigned by the target.
    pub cntlid: u16,
}

impl Default for FabricsController {
    fn default() -> Self {
        Self::new()
    }
}

impl FabricsController {
    /// Creates an inactive controller slot.
    pub const fn new() -> Self {
        Self {
            address: FabricsAddress::new(),
            subsys_nqn: [0u8; NQN_LEN],
            host_nqn: [0u8; NQN_LEN],
            state: FabricsControllerState::New,
            queues: [const { FabricsQueuePair::new() }; MAX_QUEUE_PAIRS],
            queue_count: 0,
            active: false,
            keepalive_tick: 0,
            reconnect_attempts: 0,
            cntlid: 0,
        }
    }

    /// Returns `true` if the admin queue is live.
    pub fn is_live(&self) -> bool {
        self.state == FabricsControllerState::Live
    }

    /// Creates a new queue pair, returning its index.
    pub fn create_queue(&mut self, queue_size: u16) -> Result<usize> {
        if self.queue_count >= MAX_QUEUE_PAIRS {
            return Err(Error::OutOfMemory);
        }
        let qid = self.queue_count as u16;
        let idx = self.queue_count;
        self.queues[idx] = FabricsQueuePair::with_id(qid, queue_size);
        self.queues[idx].set_live();
        self.queue_count += 1;
        Ok(idx)
    }

    /// Deletes a queue pair by index.
    pub fn delete_queue(&mut self, index: usize) -> Result<()> {
        if index >= self.queue_count {
            return Err(Error::NotFound);
        }
        self.queues[index] = FabricsQueuePair::new();
        // Compact array
        let count = self.queue_count;
        for i in index..count.saturating_sub(1) {
            self.queues[i] = self.queues[i + 1];
        }
        self.queue_count = self.queue_count.saturating_sub(1);
        Ok(())
    }

    /// Submits an I/O command to the given queue.
    ///
    /// Returns the command tag (submission index) for polling.
    pub fn submit_io(&mut self, queue_index: usize) -> Result<u64> {
        if queue_index >= self.queue_count {
            return Err(Error::NotFound);
        }
        if !self.queues[queue_index].is_live() {
            return Err(Error::Busy);
        }
        self.queues[queue_index].record_submit();
        let tag = self.queues[queue_index].submitted;
        Ok(tag)
    }

    /// Polls for a completion on the given queue.
    ///
    /// Returns `Ok(Some(tag))` if a completion is available,
    /// `Ok(None)` if the queue is idle.
    pub fn poll_completion(&mut self, queue_index: usize) -> Result<Option<u64>> {
        if queue_index >= self.queue_count {
            return Err(Error::NotFound);
        }
        let q = &mut self.queues[queue_index];
        if q.completed < q.submitted {
            q.record_completion();
            Ok(Some(q.completed))
        } else {
            Ok(None)
        }
    }

    /// Returns `true` if a keep-alive must be sent at the current tick.
    pub fn keepalive_due(&self, now: u64) -> bool {
        now.wrapping_sub(self.keepalive_tick) >= KEEP_ALIVE_TIMEOUT_TICKS / 2
    }

    /// Updates the keep-alive timestamp.
    pub fn update_keepalive(&mut self, now: u64) {
        self.keepalive_tick = now;
    }

    /// Transitions the controller into a reconnecting state.
    pub fn begin_reconnect(&mut self) {
        self.state = FabricsControllerState::Reconnecting;
        self.reconnect_attempts = self.reconnect_attempts.saturating_add(1);
    }

    /// Marks the controller as dead after too many reconnect failures.
    pub fn mark_dead(&mut self) {
        self.state = FabricsControllerState::Dead;
    }

    /// Returns the number of allocated queue pairs.
    pub fn queue_count(&self) -> usize {
        self.queue_count
    }
}

// ---------------------------------------------------------------------------
// FabricsDiscoveryEntry
// ---------------------------------------------------------------------------

/// A single discovery log entry returned by the Discovery controller.
#[derive(Debug, Clone, Copy)]
pub struct FabricsDiscoveryEntry {
    /// NQN of the target NVMe subsystem.
    pub subsys_nqn: [u8; NQN_LEN],
    /// Target network address.
    pub address: FabricsAddress,
    /// Port ID within the subsystem.
    pub port_id: u16,
    /// Controller ID (0 = any).
    pub cntlid: u16,
    /// Whether this entry is valid.
    pub valid: bool,
}

impl Default for FabricsDiscoveryEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl FabricsDiscoveryEntry {
    /// Creates an empty, invalid discovery entry.
    pub const fn new() -> Self {
        Self {
            subsys_nqn: [0u8; NQN_LEN],
            address: FabricsAddress::new(),
            port_id: 0,
            cntlid: 0,
            valid: false,
        }
    }
}

// ---------------------------------------------------------------------------
// FabricsSubsystem
// ---------------------------------------------------------------------------

/// System-wide NVMe-oF host transport registry.
///
/// Manages up to [`MAX_CONTROLLERS`] fabric connections and a discovery
/// log cache of up to [`MAX_DISCOVERY_ENTRIES`] entries.
pub struct FabricsSubsystem {
    /// Active fabric controllers.
    controllers: [FabricsController; MAX_CONTROLLERS],
    /// Discovery log cache.
    discovery: [FabricsDiscoveryEntry; MAX_DISCOVERY_ENTRIES],
    /// Number of valid discovery entries.
    discovery_count: usize,
    /// Number of active controllers.
    controller_count: usize,
}

impl Default for FabricsSubsystem {
    fn default() -> Self {
        Self::new()
    }
}

impl FabricsSubsystem {
    /// Creates an empty fabrics subsystem.
    pub fn new() -> Self {
        Self {
            controllers: [const { FabricsController::new() }; MAX_CONTROLLERS],
            discovery: [const { FabricsDiscoveryEntry::new() }; MAX_DISCOVERY_ENTRIES],
            discovery_count: 0,
            controller_count: 0,
        }
    }

    // ── Controller management ─────────────────────────────────────────

    /// Connects to a remote NVMe subsystem, returning the controller index.
    pub fn connect(
        &mut self,
        address: FabricsAddress,
        subsys_nqn: &[u8],
        host_nqn: &[u8],
    ) -> Result<usize> {
        if subsys_nqn.len() > NQN_LEN || host_nqn.len() > NQN_LEN {
            return Err(Error::InvalidArgument);
        }
        let slot = self.controllers.iter().position(|c| !c.active);
        let idx = slot.ok_or(Error::OutOfMemory)?;

        let ctrl = &mut self.controllers[idx];
        ctrl.address = address;
        ctrl.subsys_nqn[..subsys_nqn.len()].copy_from_slice(subsys_nqn);
        ctrl.host_nqn[..host_nqn.len()].copy_from_slice(host_nqn);
        ctrl.state = FabricsControllerState::Connecting;
        ctrl.active = true;
        ctrl.cntlid = (idx as u16) + 1;

        // Simulate admin queue establishment
        ctrl.create_queue(32)?;
        ctrl.state = FabricsControllerState::Live;

        self.controller_count += 1;
        Ok(idx)
    }

    /// Disconnects and removes a controller by index.
    pub fn disconnect(&mut self, index: usize) -> Result<()> {
        if index >= MAX_CONTROLLERS || !self.controllers[index].active {
            return Err(Error::NotFound);
        }
        self.controllers[index] = FabricsController::new();
        self.controller_count = self.controller_count.saturating_sub(1);
        Ok(())
    }

    /// Returns an immutable reference to a controller.
    pub fn get_controller(&self, index: usize) -> Result<&FabricsController> {
        if index >= MAX_CONTROLLERS || !self.controllers[index].active {
            return Err(Error::NotFound);
        }
        Ok(&self.controllers[index])
    }

    /// Returns a mutable reference to a controller.
    pub fn get_controller_mut(&mut self, index: usize) -> Result<&mut FabricsController> {
        if index >= MAX_CONTROLLERS || !self.controllers[index].active {
            return Err(Error::NotFound);
        }
        Ok(&mut self.controllers[index])
    }

    // ── Queue management ─────────────────────────────────────────────

    /// Creates an I/O queue pair on the given controller.
    pub fn create_queue(&mut self, ctrl_index: usize, queue_size: u16) -> Result<usize> {
        self.get_controller_mut(ctrl_index)?
            .create_queue(queue_size)
    }

    /// Deletes a queue pair from the given controller.
    pub fn delete_queue(&mut self, ctrl_index: usize, queue_index: usize) -> Result<()> {
        self.get_controller_mut(ctrl_index)?
            .delete_queue(queue_index)
    }

    // ── I/O operations ────────────────────────────────────────────────

    /// Submits an I/O command to a specific queue on a controller.
    pub fn submit_io(&mut self, ctrl_index: usize, queue_index: usize) -> Result<u64> {
        self.get_controller_mut(ctrl_index)?.submit_io(queue_index)
    }

    /// Polls for completions on a specific queue.
    pub fn poll_completion(
        &mut self,
        ctrl_index: usize,
        queue_index: usize,
    ) -> Result<Option<u64>> {
        self.get_controller_mut(ctrl_index)?
            .poll_completion(queue_index)
    }

    // ── Discovery ────────────────────────────────────────────────────

    /// Discovers remote NVMe subsystems via a discovery controller.
    ///
    /// Connects to the discovery NQN on `address`, retrieves the discovery
    /// log, and populates the internal cache. Returns the number of entries
    /// found.
    pub fn discover(&mut self, address: FabricsAddress) -> Result<usize> {
        // Connect to the discovery controller
        let disc_nqn = NVMF_DISCOVERY_NQN;
        let host_nqn = b"nqn.2026-01.oncrix.host";
        let ctrl_idx = self.connect(address, disc_nqn, host_nqn)?;

        // Simulate discovery log retrieval: populate one synthetic entry
        if self.discovery_count < MAX_DISCOVERY_ENTRIES {
            let mut entry = FabricsDiscoveryEntry::new();
            entry.subsys_nqn[..8].copy_from_slice(b"nqn.oncr");
            entry.address = self.controllers[ctrl_idx].address;
            entry.port_id = 1;
            entry.cntlid = 0xFFFF; // any controller
            entry.valid = true;

            let di = self.discovery_count;
            self.discovery[di] = entry;
            self.discovery_count += 1;
        }

        // Disconnect discovery controller
        self.disconnect(ctrl_idx)?;
        Ok(self.discovery_count)
    }

    /// Returns the discovery log entry at `index`.
    pub fn get_discovery_entry(&self, index: usize) -> Result<&FabricsDiscoveryEntry> {
        if index >= self.discovery_count {
            return Err(Error::NotFound);
        }
        Ok(&self.discovery[index])
    }

    /// Clears the discovery log cache.
    pub fn clear_discovery(&mut self) {
        for i in 0..self.discovery_count {
            self.discovery[i] = FabricsDiscoveryEntry::new();
        }
        self.discovery_count = 0;
    }

    // ── Keep-alive ────────────────────────────────────────────────────

    /// Runs keep-alive checks for all live controllers at the current tick.
    ///
    /// For any controller whose keep-alive interval has elapsed, this method
    /// updates the timestamp (in a real driver it would send a Keep Alive command).
    /// Controllers that have timed out are moved to Reconnecting state.
    pub fn check_keepalives(&mut self, now: u64) {
        for i in 0..MAX_CONTROLLERS {
            if !self.controllers[i].active {
                continue;
            }
            if self.controllers[i].state != FabricsControllerState::Live {
                continue;
            }
            if self.controllers[i].keepalive_due(now) {
                // Check if the full timeout has expired (no response)
                let elapsed = now.wrapping_sub(self.controllers[i].keepalive_tick);
                if elapsed >= KEEP_ALIVE_TIMEOUT_TICKS {
                    self.controllers[i].begin_reconnect();
                } else {
                    self.controllers[i].update_keepalive(now);
                }
            }
        }
    }

    /// Returns the number of active controllers.
    pub fn controller_count(&self) -> usize {
        self.controller_count
    }

    /// Returns the number of cached discovery entries.
    pub fn discovery_count(&self) -> usize {
        self.discovery_count
    }

    /// Returns `true` if no controllers are active.
    pub fn is_empty(&self) -> bool {
        self.controller_count == 0
    }
}
