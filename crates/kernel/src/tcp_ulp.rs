// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! TCP Upper Layer Protocol (ULP) framework.
//!
//! Provides a registration and dispatch mechanism for protocol
//! extensions that sit on top of TCP, such as TLS (kTLS), MPTCP,
//! and SMC-R. ULP modules intercept send/receive paths to perform
//! protocol-specific transformations (e.g., encryption for TLS,
//! subflow management for MPTCP).
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                     TcpUlpRegistry                           │
//! │                                                              │
//! │  Registered Types [0..MAX_ULP_TYPES]                         │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  TcpUlpTypeEntry: ulp_type, name, capabilities        │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  Active Instances [0..MAX_ULP_INSTANCES]                     │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  TcpUlpInstance: ulp_type, socket_id, state, active    │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  TcpUlpStats (global counters)                               │
//! │  - attached, detached, send_intercepts, recv_intercepts      │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Lifecycle
//!
//! 1. Register a ULP type via `register_ulp()`.
//! 2. Attach a ULP to a socket via `attach_ulp()` — allocates an
//!    instance and runs the ULP init callback.
//! 3. Send/receive interception: `tcp_ulp_sendmsg()` and
//!    `tcp_ulp_recvmsg()` delegate to the active ULP.
//! 4. Detach via `detach_ulp()` — runs release and frees instance.
//!
//! # Reference
//!
//! Linux `net/ipv4/tcp_ulp.c`, `include/net/tcp.h` (tcp_ulp_ops).

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum registered ULP types.
const MAX_ULP_TYPES: usize = 16;

/// Maximum concurrently active ULP instances.
const MAX_ULP_INSTANCES: usize = 128;

/// ULP type name buffer length.
const ULP_NAME_LEN: usize = 32;

/// ULP instance state buffer size.
const ULP_STATE_SIZE: usize = 64;

/// Maximum data buffer for send/recv interception.
const ULP_BUF_SIZE: usize = 256;

/// Capability flag: supports zero-copy send.
const ULP_CAP_ZEROCOPY_SEND: u32 = 1 << 0;

/// Capability flag: supports zero-copy receive.
const ULP_CAP_ZEROCOPY_RECV: u32 = 1 << 1;

/// Capability flag: supports offload.
const ULP_CAP_OFFLOAD: u32 = 1 << 2;

/// Capability flag: supports renegotiation.
const _ULP_CAP_RENEGO: u32 = 1 << 3;

// ══════════════════════════════════════════════════════════════
// TcpUlpType
// ══════════════════════════════════════════════════════════════

/// TCP Upper Layer Protocol type identifier.
///
/// Identifies the protocol extension being applied to a TCP
/// connection. Each type has distinct send/receive semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpUlpType {
    /// Kernel TLS — in-kernel encryption/decryption.
    Tls = 0,
    /// Multipath TCP — multiple subflows for resilience.
    Mptcp = 1,
    /// Shared Memory Communications over RDMA.
    Smc = 2,
    /// User-defined protocol extension.
    Custom0 = 3,
    /// User-defined protocol extension.
    Custom1 = 4,
    /// User-defined protocol extension.
    Custom2 = 5,
    /// User-defined protocol extension.
    Custom3 = 6,
    /// User-defined protocol extension.
    Custom4 = 7,
}

impl TcpUlpType {
    /// Convert a raw u8 to a `TcpUlpType`.
    pub fn from_u8(val: u8) -> Result<Self> {
        match val {
            0 => Ok(Self::Tls),
            1 => Ok(Self::Mptcp),
            2 => Ok(Self::Smc),
            3 => Ok(Self::Custom0),
            4 => Ok(Self::Custom1),
            5 => Ok(Self::Custom2),
            6 => Ok(Self::Custom3),
            7 => Ok(Self::Custom4),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Return the display name for this ULP type.
    pub fn name(self) -> &'static [u8] {
        match self {
            Self::Tls => b"tls",
            Self::Mptcp => b"mptcp",
            Self::Smc => b"smc",
            Self::Custom0 => b"custom0",
            Self::Custom1 => b"custom1",
            Self::Custom2 => b"custom2",
            Self::Custom3 => b"custom3",
            Self::Custom4 => b"custom4",
        }
    }
}

// ══════════════════════════════════════════════════════════════
// UlpState
// ══════════════════════════════════════════════════════════════

/// Lifecycle state of a ULP instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UlpState {
    /// Instance allocated but not yet initialized.
    Created = 0,
    /// Init callback has been run; ready for data.
    Initialized = 1,
    /// Actively processing data.
    Active = 2,
    /// Draining — no new data, finishing pending.
    Draining = 3,
    /// Released and ready for reuse.
    Released = 4,
}

impl UlpState {
    /// Convert a raw u8.
    pub fn from_u8(val: u8) -> Result<Self> {
        match val {
            0 => Ok(Self::Created),
            1 => Ok(Self::Initialized),
            2 => Ok(Self::Active),
            3 => Ok(Self::Draining),
            4 => Ok(Self::Released),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ══════════════════════════════════════════════════════════════
// TcpUlpTypeEntry
// ══════════════════════════════════════════════════════════════

/// Registered ULP type entry.
///
/// Describes a ULP type's capabilities and tracks how many
/// instances are currently active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpUlpTypeEntry {
    /// The ULP type.
    pub ulp_type: TcpUlpType,
    /// Human-readable name.
    pub name: [u8; ULP_NAME_LEN],
    /// Name length in bytes.
    pub name_len: usize,
    /// Capability flags.
    pub capabilities: u32,
    /// Whether this slot is registered.
    pub registered: bool,
    /// Number of active instances of this type.
    pub instance_count: u32,
    /// Maximum allowed concurrent instances (0 = unlimited).
    pub max_instances: u32,
}

impl TcpUlpTypeEntry {
    /// Create an empty (unregistered) type entry.
    pub const fn new() -> Self {
        Self {
            ulp_type: TcpUlpType::Tls,
            name: [0u8; ULP_NAME_LEN],
            name_len: 0,
            capabilities: 0,
            registered: false,
            instance_count: 0,
            max_instances: 0,
        }
    }

    /// Check whether this type supports zero-copy send.
    pub fn supports_zerocopy_send(&self) -> bool {
        (self.capabilities & ULP_CAP_ZEROCOPY_SEND) != 0
    }

    /// Check whether this type supports zero-copy receive.
    pub fn supports_zerocopy_recv(&self) -> bool {
        (self.capabilities & ULP_CAP_ZEROCOPY_RECV) != 0
    }

    /// Check whether this type supports offload.
    pub fn supports_offload(&self) -> bool {
        (self.capabilities & ULP_CAP_OFFLOAD) != 0
    }
}

// ══════════════════════════════════════════════════════════════
// TcpUlpInstance
// ══════════════════════════════════════════════════════════════

/// An active ULP instance attached to a socket.
///
/// The `state_data` buffer holds protocol-specific state (e.g.,
/// TLS session keys, MPTCP subflow table). Its interpretation
/// depends on the ULP type.
pub struct TcpUlpInstance {
    /// The ULP type for this instance.
    pub ulp_type: TcpUlpType,
    /// Socket ID this instance is attached to.
    pub socket_id: u64,
    /// Protocol-specific opaque state.
    pub state_data: [u8; ULP_STATE_SIZE],
    /// Whether this instance is active.
    pub active: bool,
    /// Current lifecycle state.
    pub lifecycle: UlpState,
    /// Number of send intercepts processed.
    pub send_count: u64,
    /// Number of receive intercepts processed.
    pub recv_count: u64,
    /// Total bytes processed through send path.
    pub send_bytes: u64,
    /// Total bytes processed through receive path.
    pub recv_bytes: u64,
    /// Tick at which this instance was created.
    pub created_tick: u64,
}

impl TcpUlpInstance {
    /// Create an empty (inactive) instance.
    pub const fn new() -> Self {
        Self {
            ulp_type: TcpUlpType::Tls,
            socket_id: 0,
            state_data: [0u8; ULP_STATE_SIZE],
            active: false,
            lifecycle: UlpState::Created,
            send_count: 0,
            recv_count: 0,
            send_bytes: 0,
            recv_bytes: 0,
            created_tick: 0,
        }
    }

    /// Initialize this instance for a socket.
    pub fn init(
        &mut self,
        ulp_type: TcpUlpType,
        socket_id: u64,
        initial_state: &[u8],
    ) -> Result<()> {
        if initial_state.len() > ULP_STATE_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.ulp_type = ulp_type;
        self.socket_id = socket_id;
        self.state_data = [0u8; ULP_STATE_SIZE];
        self.state_data[..initial_state.len()].copy_from_slice(initial_state);
        self.active = true;
        self.lifecycle = UlpState::Initialized;
        self.send_count = 0;
        self.recv_count = 0;
        self.send_bytes = 0;
        self.recv_bytes = 0;
        Ok(())
    }

    /// Transition to active state.
    pub fn activate(&mut self) -> Result<()> {
        if self.lifecycle != UlpState::Initialized {
            return Err(Error::InvalidArgument);
        }
        self.lifecycle = UlpState::Active;
        Ok(())
    }

    /// Transition to draining state.
    pub fn drain(&mut self) -> Result<()> {
        if self.lifecycle != UlpState::Active {
            return Err(Error::InvalidArgument);
        }
        self.lifecycle = UlpState::Draining;
        Ok(())
    }

    /// Release this instance.
    pub fn release(&mut self) {
        self.active = false;
        self.lifecycle = UlpState::Released;
        self.state_data = [0u8; ULP_STATE_SIZE];
    }

    /// Update protocol-specific state.
    pub fn update_state(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > ULP_STATE_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.state_data[..data.len()].copy_from_slice(data);
        Ok(())
    }

    /// Read protocol-specific state into the provided buffer.
    pub fn get_state(&self, out: &mut [u8]) -> usize {
        let len = out.len().min(ULP_STATE_SIZE);
        out[..len].copy_from_slice(&self.state_data[..len]);
        len
    }
}

// ══════════════════════════════════════════════════════════════
// TcpUlpStats
// ══════════════════════════════════════════════════════════════

/// Global statistics for the TCP ULP subsystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpUlpStats {
    /// Total number of ULP instances attached.
    pub attached: u64,
    /// Total number of ULP instances detached.
    pub detached: u64,
    /// Total send interceptions.
    pub send_intercepts: u64,
    /// Total receive interceptions.
    pub recv_intercepts: u64,
    /// Total bytes through send ULP path.
    pub send_bytes: u64,
    /// Total bytes through receive ULP path.
    pub recv_bytes: u64,
    /// Total ULP types registered.
    pub types_registered: u32,
    /// Total errors.
    pub errors: u64,
}

impl TcpUlpStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            attached: 0,
            detached: 0,
            send_intercepts: 0,
            recv_intercepts: 0,
            send_bytes: 0,
            recv_bytes: 0,
            types_registered: 0,
            errors: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// SendRecvResult
// ══════════════════════════════════════════════════════════════

/// Result of a ULP send/receive interception.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UlpIoResult {
    /// Number of bytes consumed / produced.
    pub bytes: usize,
    /// Whether the ULP wants to suppress further processing.
    pub consumed: bool,
}

impl UlpIoResult {
    /// Create a new I/O result.
    pub const fn new(bytes: usize, consumed: bool) -> Self {
        Self { bytes, consumed }
    }
}

// ══════════════════════════════════════════════════════════════
// TcpUlpRegistry
// ══════════════════════════════════════════════════════════════

/// Central registry for TCP ULP types and instances.
///
/// Manages the full ULP lifecycle: type registration, instance
/// attachment/detachment, and send/receive interception hooks.
pub struct TcpUlpRegistry {
    /// Registered ULP types.
    types: [TcpUlpTypeEntry; MAX_ULP_TYPES],
    /// Active ULP instances.
    instances: [TcpUlpInstance; MAX_ULP_INSTANCES],
    /// Global statistics.
    stats: TcpUlpStats,
}

impl TcpUlpRegistry {
    /// Create a new empty registry.
    pub const fn new() -> Self {
        Self {
            types: [const { TcpUlpTypeEntry::new() }; MAX_ULP_TYPES],
            instances: [const { TcpUlpInstance::new() }; MAX_ULP_INSTANCES],
            stats: TcpUlpStats::new(),
        }
    }

    /// Register a ULP type.
    pub fn register_ulp(
        &mut self,
        ulp_type: TcpUlpType,
        name: &[u8],
        capabilities: u32,
        max_instances: u32,
    ) -> Result<()> {
        // Check for duplicate registration
        if self
            .types
            .iter()
            .any(|t| t.registered && t.ulp_type as u8 == ulp_type as u8)
        {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .types
            .iter()
            .position(|t| !t.registered)
            .ok_or(Error::OutOfMemory)?;

        let entry = &mut self.types[slot];
        entry.ulp_type = ulp_type;
        entry.registered = true;
        entry.capabilities = capabilities;
        entry.max_instances = max_instances;
        entry.instance_count = 0;

        let copy_len = name.len().min(ULP_NAME_LEN);
        entry.name[..copy_len].copy_from_slice(&name[..copy_len]);
        entry.name_len = copy_len;

        self.stats.types_registered += 1;
        Ok(())
    }

    /// Unregister a ULP type.
    ///
    /// Fails if there are active instances of this type.
    pub fn unregister_ulp(&mut self, ulp_type: TcpUlpType) -> Result<()> {
        let slot = self
            .types
            .iter()
            .position(|t| t.registered && t.ulp_type as u8 == ulp_type as u8)
            .ok_or(Error::NotFound)?;

        if self.types[slot].instance_count > 0 {
            return Err(Error::Busy);
        }
        self.types[slot] = TcpUlpTypeEntry::new();
        self.stats.types_registered = self.stats.types_registered.saturating_sub(1);
        Ok(())
    }

    /// Attach a ULP to a socket.
    ///
    /// Creates a new instance, runs init, and returns the
    /// instance index.
    pub fn attach_ulp(
        &mut self,
        socket_id: u64,
        ulp_type: TcpUlpType,
        initial_state: &[u8],
    ) -> Result<usize> {
        // Verify the type is registered
        let type_slot = self
            .types
            .iter()
            .position(|t| t.registered && t.ulp_type as u8 == ulp_type as u8)
            .ok_or(Error::NotFound)?;

        // Check instance limit
        let entry = &self.types[type_slot];
        if entry.max_instances > 0 && entry.instance_count >= entry.max_instances {
            return Err(Error::OutOfMemory);
        }

        // Check socket not already ULP-attached
        if self
            .instances
            .iter()
            .any(|inst| inst.active && inst.socket_id == socket_id)
        {
            return Err(Error::AlreadyExists);
        }

        // Find a free instance slot
        let inst_slot = self
            .instances
            .iter()
            .position(|inst| !inst.active)
            .ok_or(Error::OutOfMemory)?;

        self.instances[inst_slot].init(ulp_type, socket_id, initial_state)?;
        self.instances[inst_slot].activate()?;
        self.types[type_slot].instance_count += 1;
        self.stats.attached += 1;
        Ok(inst_slot)
    }

    /// Detach a ULP from a socket.
    pub fn detach_ulp(&mut self, socket_id: u64) -> Result<()> {
        let inst_slot = self
            .instances
            .iter()
            .position(|inst| inst.active && inst.socket_id == socket_id)
            .ok_or(Error::NotFound)?;

        let ulp_type = self.instances[inst_slot].ulp_type;
        self.instances[inst_slot].release();

        // Decrement type instance count
        if let Some(type_entry) = self
            .types
            .iter_mut()
            .find(|t| t.registered && t.ulp_type as u8 == ulp_type as u8)
        {
            type_entry.instance_count = type_entry.instance_count.saturating_sub(1);
        }

        self.stats.detached += 1;
        Ok(())
    }

    /// Intercept a sendmsg on a ULP-attached socket.
    ///
    /// Returns the number of bytes consumed by the ULP. In a real
    /// implementation, the ULP would transform the data (e.g., TLS
    /// encryption). Currently returns the input length as a stub.
    pub fn tcp_ulp_sendmsg(&mut self, socket_id: u64, data: &[u8]) -> Result<UlpIoResult> {
        let inst_slot = self
            .instances
            .iter()
            .position(|inst| inst.active && inst.socket_id == socket_id)
            .ok_or(Error::NotFound)?;

        if self.instances[inst_slot].lifecycle != UlpState::Active {
            return Err(Error::InvalidArgument);
        }

        let len = data.len();
        self.instances[inst_slot].send_count += 1;
        self.instances[inst_slot].send_bytes += len as u64;
        self.stats.send_intercepts += 1;
        self.stats.send_bytes += len as u64;

        Ok(UlpIoResult::new(len, true))
    }

    /// Intercept a recvmsg on a ULP-attached socket.
    ///
    /// Returns the number of bytes produced by the ULP. In a real
    /// implementation, the ULP would transform the data (e.g., TLS
    /// decryption). Currently copies up to `out.len()` from data.
    pub fn tcp_ulp_recvmsg(
        &mut self,
        socket_id: u64,
        data: &[u8],
        out: &mut [u8],
    ) -> Result<UlpIoResult> {
        let inst_slot = self
            .instances
            .iter()
            .position(|inst| inst.active && inst.socket_id == socket_id)
            .ok_or(Error::NotFound)?;

        if self.instances[inst_slot].lifecycle != UlpState::Active {
            return Err(Error::InvalidArgument);
        }

        let copy_len = data.len().min(out.len());
        out[..copy_len].copy_from_slice(&data[..copy_len]);

        self.instances[inst_slot].recv_count += 1;
        self.instances[inst_slot].recv_bytes += copy_len as u64;
        self.stats.recv_intercepts += 1;
        self.stats.recv_bytes += copy_len as u64;

        Ok(UlpIoResult::new(copy_len, true))
    }

    /// Look up a ULP instance by socket ID.
    pub fn find_instance(&self, socket_id: u64) -> Result<&TcpUlpInstance> {
        self.instances
            .iter()
            .find(|inst| inst.active && inst.socket_id == socket_id)
            .ok_or(Error::NotFound)
    }

    /// Look up a registered ULP type.
    pub fn find_type(&self, ulp_type: TcpUlpType) -> Result<&TcpUlpTypeEntry> {
        self.types
            .iter()
            .find(|t| t.registered && t.ulp_type as u8 == ulp_type as u8)
            .ok_or(Error::NotFound)
    }

    /// Get information about an active ULP instance.
    pub fn get_info(&self, socket_id: u64, out: &mut [u8]) -> Result<usize> {
        let inst = self.find_instance(socket_id)?;
        Ok(inst.get_state(out))
    }

    /// Return global statistics.
    pub fn stats(&self) -> &TcpUlpStats {
        &self.stats
    }

    /// Return the number of active instances.
    pub fn active_instance_count(&self) -> usize {
        self.instances.iter().filter(|i| i.active).count()
    }

    /// Return the number of registered types.
    pub fn registered_type_count(&self) -> u32 {
        self.stats.types_registered
    }
}
