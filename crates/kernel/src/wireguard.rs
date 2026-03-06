// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! WireGuard VPN tunnel for the ONCRIX kernel.
//!
//! Implements a simplified WireGuard interface based on the Noise IK
//! handshake pattern.  Each [`WgDevice`] represents a virtual
//! tunnel interface with a local keypair and a list of peers.
//!
//! # Simplifications
//!
//! - Uses a placeholder symmetric cipher (XOR-based) instead of
//!   ChaCha20-Poly1305.  In a production kernel this would be
//!   replaced by a constant-time AEAD implementation.
//! - The Noise handshake is modelled as a state machine but does
//!   not perform real Diffie-Hellman; key agreement is simulated.
//! - Replay protection uses a simple sliding-window counter.
//!
//! # Architecture
//!
//! ```text
//! Userspace app
//!   │  socket I/O
//!   ▼
//! WgDevice (TUN-like interface)
//!   │  encrypt / decrypt
//!   ▼
//! UDP socket (port 51820)
//!   │  on-wire WireGuard packets
//!   ▼
//! Network
//! ```
//!
//! The device sits between the routing table and the physical
//! network.  Outbound cleartext packets are encrypted and sent via
//! UDP to the appropriate peer.  Inbound UDP packets are decrypted
//! and injected into the network stack.

use oncrix_lib::{Error, Result};

// =========================================================================
// Constants
// =========================================================================

/// Maximum number of WireGuard devices.
const MAX_DEVICES: usize = 8;

/// Maximum number of peers per device.
const MAX_PEERS: usize = 16;

/// Maximum allowed-IP entries per peer.
const MAX_ALLOWED_IPS: usize = 8;

/// WireGuard default listen port.
const DEFAULT_LISTEN_PORT: u16 = 51820;

/// Key size in bytes (Curve25519 = 32 bytes).
const KEY_SIZE: usize = 32;

/// Nonce size in bytes (96-bit for AEAD).
const NONCE_SIZE: usize = 12;

/// Handshake initiation message type.
const MSG_HANDSHAKE_INIT: u8 = 1;

/// Handshake response message type.
const MSG_HANDSHAKE_RESP: u8 = 2;

/// Cookie reply message type.
const MSG_COOKIE_REPLY: u8 = 3;

/// Transport data message type.
const MSG_TRANSPORT: u8 = 4;

/// Rekey after this many seconds.
const REKEY_AFTER_SECS: u64 = 120;

/// Reject packets after this many seconds without rekey.
const REJECT_AFTER_SECS: u64 = 180;

/// Keepalive interval in seconds (0 = disabled).
const DEFAULT_KEEPALIVE: u16 = 0;

/// Maximum size of a WireGuard message payload.
const MAX_PAYLOAD: usize = 1420;

/// Replay window size (bits).
const REPLAY_WINDOW: u64 = 64;

// =========================================================================
// Key types
// =========================================================================

/// A 32-byte cryptographic key (public or private).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WgKey {
    /// Raw key bytes.
    pub bytes: [u8; KEY_SIZE],
}

impl WgKey {
    /// Create an all-zero key (placeholder).
    pub const fn zero() -> Self {
        Self {
            bytes: [0u8; KEY_SIZE],
        }
    }

    /// Create a key from raw bytes.
    pub const fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Self { bytes }
    }

    /// Return `true` if this is the zero key.
    pub fn is_zero(&self) -> bool {
        self.bytes == [0u8; KEY_SIZE]
    }
}

impl Default for WgKey {
    fn default() -> Self {
        Self::zero()
    }
}

/// A 12-byte nonce for AEAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WgNonce {
    /// Raw nonce bytes.
    pub bytes: [u8; NONCE_SIZE],
}

impl WgNonce {
    /// Create a nonce from a 64-bit counter (little-endian, padded
    /// to 12 bytes).
    pub const fn from_counter(counter: u64) -> Self {
        let b = counter.to_le_bytes();
        Self {
            bytes: [b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], 0, 0, 0, 0],
        }
    }
}

// =========================================================================
// HandshakeState
// =========================================================================

/// Noise IK handshake state machine.
///
/// Models the three-message handshake used by WireGuard:
/// 1. Initiator sends initiation message
/// 2. Responder sends response message
/// 3. First transport message confirms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HandshakeState {
    /// No handshake in progress.
    #[default]
    None,
    /// Initiation sent, awaiting response.
    InitSent,
    /// Response sent, awaiting first data.
    RespSent,
    /// Handshake complete, session keys established.
    Complete,
    /// Handshake expired, needs re-initiation.
    Expired,
}

// =========================================================================
// SessionKeys
// =========================================================================

/// Symmetric session keys derived from a completed handshake.
///
/// In a real implementation these would be ChaCha20-Poly1305 keys.
/// Here we store them for the simplified encrypt/decrypt.
#[derive(Debug, Clone, Copy)]
pub struct SessionKeys {
    /// Key for sending (initiator -> responder).
    pub send_key: WgKey,
    /// Key for receiving (responder -> initiator).
    pub recv_key: WgKey,
    /// Sending nonce counter.
    pub send_counter: u64,
    /// Highest received nonce (for replay protection).
    pub recv_counter: u64,
    /// Bitmap for replay window.
    pub recv_bitmap: u64,
    /// Tick at which these keys were established.
    pub created_tick: u64,
    /// Whether these keys are valid.
    pub valid: bool,
}

impl SessionKeys {
    /// Create empty (invalid) session keys.
    const fn empty() -> Self {
        Self {
            send_key: WgKey::zero(),
            recv_key: WgKey::zero(),
            send_counter: 0,
            recv_counter: 0,
            recv_bitmap: 0,
            created_tick: 0,
            valid: false,
        }
    }

    /// Create session keys from a completed handshake.
    fn from_handshake(send_key: WgKey, recv_key: WgKey, tick: u64) -> Self {
        Self {
            send_key,
            recv_key,
            send_counter: 0,
            recv_counter: 0,
            recv_bitmap: 0,
            created_tick: tick,
            valid: true,
        }
    }

    /// Check whether these keys have expired.
    fn is_expired(&self, current_tick: u64) -> bool {
        if !self.valid {
            return true;
        }
        current_tick.saturating_sub(self.created_tick) > REJECT_AFTER_SECS
    }

    /// Check whether a rekey is needed.
    fn needs_rekey(&self, current_tick: u64) -> bool {
        if !self.valid {
            return true;
        }
        current_tick.saturating_sub(self.created_tick) > REKEY_AFTER_SECS
    }

    /// Check a nonce against the replay window.
    ///
    /// Returns `true` if the nonce is acceptable (not replayed).
    fn check_replay(&mut self, nonce: u64) -> bool {
        if nonce > self.recv_counter {
            let shift = nonce - self.recv_counter;
            if shift < REPLAY_WINDOW {
                self.recv_bitmap <<= shift;
            } else {
                self.recv_bitmap = 0;
            }
            self.recv_bitmap |= 1;
            self.recv_counter = nonce;
            true
        } else {
            let diff = self.recv_counter - nonce;
            if diff >= REPLAY_WINDOW {
                return false;
            }
            let bit = 1u64 << diff;
            if self.recv_bitmap & bit != 0 {
                return false;
            }
            self.recv_bitmap |= bit;
            true
        }
    }
}

// =========================================================================
// AllowedIp
// =========================================================================

/// An allowed-IP entry (CIDR network) for peer routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowedIp {
    /// IPv4 network address.
    pub addr: [u8; 4],
    /// CIDR prefix length (0..=32).
    pub prefix_len: u8,
}

impl AllowedIp {
    /// Create a new allowed-IP entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] if `prefix_len > 32`.
    pub const fn new(addr: [u8; 4], prefix_len: u8) -> Result<Self> {
        if prefix_len > 32 {
            return Err(Error::InvalidArgument);
        }
        Ok(Self { addr, prefix_len })
    }

    /// Check if `target` falls within this network.
    pub const fn matches(&self, target: &[u8; 4]) -> bool {
        if self.prefix_len == 0 {
            return true;
        }
        let mask = if self.prefix_len >= 32 {
            0xFFFF_FFFFu32
        } else {
            0xFFFF_FFFFu32 << (32 - self.prefix_len)
        };
        let a = Self::to_u32(self.addr);
        let b = Self::to_u32(*target);
        (a & mask) == (b & mask)
    }

    /// Convert four octets to host-order `u32`.
    const fn to_u32(o: [u8; 4]) -> u32 {
        ((o[0] as u32) << 24) | ((o[1] as u32) << 16) | ((o[2] as u32) << 8) | (o[3] as u32)
    }
}

// =========================================================================
// Endpoint
// =========================================================================

/// A peer's network endpoint (IP + port).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Endpoint {
    /// IPv4 address of the peer.
    pub addr: [u8; 4],
    /// UDP port.
    pub port: u16,
}

impl Endpoint {
    /// Create a new endpoint.
    pub const fn new(addr: [u8; 4], port: u16) -> Self {
        Self { addr, port }
    }
}

// =========================================================================
// WgPeer
// =========================================================================

/// A WireGuard peer.
///
/// Each peer has a public key, optional endpoint, allowed-IPs for
/// cryptokey routing, and session state.
pub struct WgPeer {
    /// Whether this peer slot is active.
    active: bool,
    /// Peer's public key.
    pub public_key: WgKey,
    /// Optional pre-shared key (for post-quantum resistance).
    pub preshared_key: WgKey,
    /// Last known endpoint.
    pub endpoint: Endpoint,
    /// Allowed source IPs for this peer.
    allowed_ips: [Option<AllowedIp>; MAX_ALLOWED_IPS],
    /// Number of active allowed-IP entries.
    allowed_ip_count: usize,
    /// Current handshake state.
    pub handshake_state: HandshakeState,
    /// Current session keys.
    pub session: SessionKeys,
    /// Previous session keys (kept briefly for rekey overlap).
    prev_session: SessionKeys,
    /// Persistent keepalive interval (seconds, 0 = off).
    pub keepalive_interval: u16,
    /// Tick of last received valid packet.
    pub last_recv_tick: u64,
    /// Tick of last sent packet.
    pub last_send_tick: u64,
    /// Tick of last handshake initiation.
    pub last_handshake_tick: u64,
    /// Total bytes received from this peer.
    pub rx_bytes: u64,
    /// Total bytes sent to this peer.
    pub tx_bytes: u64,
    /// Handshake attempts since last success.
    handshake_attempts: u32,
}

/// Compile-time None for allowed-IP array.
const EMPTY_AIP: Option<AllowedIp> = None;

impl WgPeer {
    /// Create a new peer with the given public key.
    fn new(public_key: WgKey) -> Self {
        Self {
            active: true,
            public_key,
            preshared_key: WgKey::zero(),
            endpoint: Endpoint::default(),
            allowed_ips: [EMPTY_AIP; MAX_ALLOWED_IPS],
            allowed_ip_count: 0,
            handshake_state: HandshakeState::None,
            session: SessionKeys::empty(),
            prev_session: SessionKeys::empty(),
            keepalive_interval: DEFAULT_KEEPALIVE,
            last_recv_tick: 0,
            last_send_tick: 0,
            last_handshake_tick: 0,
            rx_bytes: 0,
            tx_bytes: 0,
            handshake_attempts: 0,
        }
    }

    /// Add an allowed-IP entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the peer already has
    /// [`MAX_ALLOWED_IPS`] entries.
    pub fn add_allowed_ip(&mut self, aip: AllowedIp) -> Result<()> {
        if self.allowed_ip_count >= MAX_ALLOWED_IPS {
            return Err(Error::OutOfMemory);
        }
        self.allowed_ips[self.allowed_ip_count] = Some(aip);
        self.allowed_ip_count += 1;
        Ok(())
    }

    /// Check if a destination IP matches any allowed-IP entry.
    pub fn matches_allowed_ip(&self, dst: &[u8; 4]) -> bool {
        for entry in self.allowed_ips[..self.allowed_ip_count].iter().flatten() {
            if entry.matches(dst) {
                return true;
            }
        }
        false
    }

    /// Remove all allowed-IP entries.
    pub fn clear_allowed_ips(&mut self) {
        for slot in self.allowed_ips.iter_mut() {
            *slot = None;
        }
        self.allowed_ip_count = 0;
    }

    /// Return the number of allowed-IP entries.
    pub const fn allowed_ip_count(&self) -> usize {
        self.allowed_ip_count
    }

    /// Initiate a handshake.
    ///
    /// Returns a handshake initiation message type byte for the
    /// caller to wrap into a UDP packet.
    fn initiate_handshake(&mut self, current_tick: u64) -> u8 {
        self.handshake_state = HandshakeState::InitSent;
        self.last_handshake_tick = current_tick;
        self.handshake_attempts = self.handshake_attempts.saturating_add(1);
        MSG_HANDSHAKE_INIT
    }

    /// Process a received handshake response.
    fn receive_handshake_response(&mut self, current_tick: u64, send_key: WgKey, recv_key: WgKey) {
        self.prev_session = self.session;
        self.session = SessionKeys::from_handshake(send_key, recv_key, current_tick);
        self.handshake_state = HandshakeState::Complete;
        self.handshake_attempts = 0;
    }

    /// Check if the session needs rekeying.
    fn needs_rekey(&self, current_tick: u64) -> bool {
        self.session.needs_rekey(current_tick)
    }
}

// =========================================================================
// WgDevice
// =========================================================================

/// A WireGuard network device.
///
/// Represents a `wg0`-style interface with a local keypair, listen
/// port, and peer list.  Integrates with [`super::tun_tap`] for
/// the virtual NIC interface.
pub struct WgDevice {
    /// Whether this device slot is active.
    active: bool,
    /// Device name (e.g. `b"wg0"`).
    name: [u8; 16],
    /// Length of name.
    name_len: usize,
    /// Local private key.
    private_key: WgKey,
    /// Local public key (derived from private key).
    public_key: WgKey,
    /// UDP listen port.
    listen_port: u16,
    /// Firewall mark for outgoing packets.
    fwmark: u32,
    /// Peer list.
    peers: [Option<WgPeer>; MAX_PEERS],
    /// Number of active peers.
    peer_count: usize,
    /// Current monotonic tick.
    current_tick: u64,
    /// Total packets encrypted and sent.
    pub tx_packets: u64,
    /// Total packets received and decrypted.
    pub rx_packets: u64,
    /// Interface is up.
    pub up: bool,
}

/// Compile-time None for peer array.
const EMPTY_PEER: Option<WgPeer> = None;

impl WgDevice {
    /// Create a new WireGuard device.
    fn new(name: &[u8]) -> Self {
        let mut n = [0u8; 16];
        let len = if name.len() > 15 { 15 } else { name.len() };
        n[..len].copy_from_slice(&name[..len]);
        Self {
            active: true,
            name: n,
            name_len: len,
            private_key: WgKey::zero(),
            public_key: WgKey::zero(),
            listen_port: DEFAULT_LISTEN_PORT,
            fwmark: 0,
            peers: [EMPTY_PEER; MAX_PEERS],
            peer_count: 0,
            current_tick: 0,
            tx_packets: 0,
            rx_packets: 0,
            up: false,
        }
    }

    /// Return the device name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Set the local private key.
    ///
    /// In a real implementation this would also derive the public
    /// key via Curve25519 scalar multiplication.  Here we simulate
    /// it by XOR-ing the private key with a fixed mask.
    pub fn set_private_key(&mut self, key: WgKey) {
        self.private_key = key;
        // Simulated public key derivation
        let mut pub_bytes = key.bytes;
        for b in pub_bytes.iter_mut() {
            *b ^= 0xFF;
        }
        self.public_key = WgKey::from_bytes(pub_bytes);
    }

    /// Return the local public key.
    pub const fn public_key(&self) -> &WgKey {
        &self.public_key
    }

    /// Set the listen port.
    pub fn set_listen_port(&mut self, port: u16) {
        self.listen_port = port;
    }

    /// Return the listen port.
    pub const fn listen_port(&self) -> u16 {
        self.listen_port
    }

    /// Set the firewall mark.
    pub fn set_fwmark(&mut self, fwmark: u32) {
        self.fwmark = fwmark;
    }

    /// Add a peer.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the peer list is full.
    /// - [`Error::AlreadyExists`] if a peer with the same public
    ///   key exists.
    pub fn add_peer(&mut self, public_key: WgKey) -> Result<usize> {
        // Check for duplicate
        for p in self.peers.iter().flatten() {
            if p.active && p.public_key == public_key {
                return Err(Error::AlreadyExists);
            }
        }

        for (idx, slot) in self.peers.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(WgPeer::new(public_key));
                self.peer_count += 1;
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a peer by public key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching peer exists.
    pub fn remove_peer(&mut self, public_key: &WgKey) -> Result<()> {
        for slot in self.peers.iter_mut() {
            if let Some(p) = slot {
                if p.active && p.public_key == *public_key {
                    *slot = None;
                    self.peer_count = self.peer_count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Get a reference to a peer by index.
    pub fn peer(&self, index: usize) -> Option<&WgPeer> {
        if index >= MAX_PEERS {
            return None;
        }
        self.peers[index].as_ref().filter(|p| p.active)
    }

    /// Get a mutable reference to a peer by index.
    pub fn peer_mut(&mut self, index: usize) -> Option<&mut WgPeer> {
        if index >= MAX_PEERS {
            return None;
        }
        self.peers[index].as_mut().filter(|p| p.active)
    }

    /// Return the number of active peers.
    pub const fn peer_count(&self) -> usize {
        self.peer_count
    }

    /// Find the peer whose allowed-IPs match the given destination.
    ///
    /// This is the cryptokey routing lookup.
    pub fn route_by_dst(&self, dst: &[u8; 4]) -> Option<usize> {
        for (idx, slot) in self.peers.iter().enumerate() {
            if let Some(peer) = slot {
                if peer.active && peer.matches_allowed_ip(dst) {
                    return Some(idx);
                }
            }
        }
        None
    }

    /// Find a peer by public key and return its index.
    pub fn find_peer_index(&self, public_key: &WgKey) -> Option<usize> {
        for (idx, slot) in self.peers.iter().enumerate() {
            if let Some(p) = slot {
                if p.active && p.public_key == *public_key {
                    return Some(idx);
                }
            }
        }
        None
    }

    /// Encrypt a cleartext packet for transmission to a peer.
    ///
    /// In a real implementation this would use ChaCha20-Poly1305.
    /// Here we use a simple XOR with the session send key for
    /// demonstration.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no peer routes the destination.
    /// - [`Error::InvalidArgument`] if the session is not
    ///   established or the packet is too large.
    pub fn encrypt(&mut self, cleartext: &[u8], out: &mut [u8]) -> Result<(usize, usize)> {
        if cleartext.len() < 20 || cleartext.len() > MAX_PAYLOAD {
            return Err(Error::InvalidArgument);
        }

        // Extract destination IP from IPv4 header
        let dst = [cleartext[16], cleartext[17], cleartext[18], cleartext[19]];

        let peer_idx = self.route_by_dst(&dst).ok_or(Error::NotFound)?;

        let peer = self.peers[peer_idx].as_mut().ok_or(Error::NotFound)?;

        if peer.handshake_state != HandshakeState::Complete {
            return Err(Error::InvalidArgument);
        }
        if !peer.session.valid {
            return Err(Error::InvalidArgument);
        }

        // Header: type(1) + reserved(3) + counter(8) = 12 bytes
        let total = 12 + cleartext.len();
        if out.len() < total {
            return Err(Error::InvalidArgument);
        }

        // Write header
        out[0] = MSG_TRANSPORT;
        out[1] = 0;
        out[2] = 0;
        out[3] = 0;
        let counter = peer.session.send_counter;
        let counter_bytes = counter.to_le_bytes();
        out[4..12].copy_from_slice(&counter_bytes);

        // XOR encrypt
        let key = &peer.session.send_key.bytes;
        for (i, &b) in cleartext.iter().enumerate() {
            out[12 + i] = b ^ key[i % KEY_SIZE];
        }

        peer.session.send_counter = counter.saturating_add(1);
        peer.tx_bytes = peer.tx_bytes.saturating_add(cleartext.len() as u64);
        peer.last_send_tick = self.current_tick;
        self.tx_packets = self.tx_packets.saturating_add(1);

        Ok((total, peer_idx))
    }

    /// Decrypt a received WireGuard transport packet.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the packet is malformed.
    /// - [`Error::NotFound`] if no peer matches the source.
    /// - [`Error::PermissionDenied`] if replay check fails.
    pub fn decrypt(&mut self, ciphertext: &[u8], out: &mut [u8], peer_idx: usize) -> Result<usize> {
        if ciphertext.len() < 12 {
            return Err(Error::InvalidArgument);
        }
        if ciphertext[0] != MSG_TRANSPORT {
            return Err(Error::InvalidArgument);
        }

        let peer = self.peers[peer_idx].as_mut().ok_or(Error::NotFound)?;

        if !peer.session.valid {
            return Err(Error::InvalidArgument);
        }

        // Read counter
        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&ciphertext[4..12]);
        let counter = u64::from_le_bytes(counter_bytes);

        // Replay check
        if !peer.session.check_replay(counter) {
            return Err(Error::PermissionDenied);
        }

        let payload = &ciphertext[12..];
        if out.len() < payload.len() {
            return Err(Error::InvalidArgument);
        }

        // XOR decrypt
        let key = &peer.session.recv_key.bytes;
        for (i, &b) in payload.iter().enumerate() {
            out[i] = b ^ key[i % KEY_SIZE];
        }

        peer.rx_bytes = peer.rx_bytes.saturating_add(payload.len() as u64);
        peer.last_recv_tick = self.current_tick;
        self.rx_packets = self.rx_packets.saturating_add(1);

        Ok(payload.len())
    }

    /// Advance the tick counter and check for needed rekeys.
    ///
    /// Returns a list of peer indices that need handshake
    /// re-initiation (up to `out_len` entries).
    pub fn tick(&mut self, ticks: u64, rekey_peers: &mut [usize]) -> usize {
        self.current_tick = self.current_tick.saturating_add(ticks);
        let mut rekey_count = 0;

        for (idx, slot) in self.peers.iter().enumerate() {
            if let Some(peer) = slot {
                if peer.active
                    && peer.needs_rekey(self.current_tick)
                    && rekey_count < rekey_peers.len()
                {
                    rekey_peers[rekey_count] = idx;
                    rekey_count += 1;
                }
            }
        }
        rekey_count
    }
}

// =========================================================================
// WgRegistry
// =========================================================================

/// Registry of WireGuard devices.
pub struct WgRegistry {
    /// Device slots.
    devices: [Option<WgDevice>; MAX_DEVICES],
    /// Number of active devices.
    count: usize,
}

/// Compile-time None for device array.
const EMPTY_DEV: Option<WgDevice> = None;

impl WgRegistry {
    /// Create a new empty registry.
    pub const fn new() -> Self {
        Self {
            devices: [EMPTY_DEV; MAX_DEVICES],
            count: 0,
        }
    }

    /// Return the number of active devices.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Create a new WireGuard device.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `name` is empty or too long.
    /// - [`Error::AlreadyExists`] if the name is taken.
    /// - [`Error::OutOfMemory`] if no slots remain.
    pub fn create(&mut self, name: &[u8]) -> Result<usize> {
        if name.is_empty() || name.len() > 15 {
            return Err(Error::InvalidArgument);
        }

        for dev in self.devices.iter().flatten() {
            if dev.active && dev.name() == name {
                return Err(Error::AlreadyExists);
            }
        }

        for (idx, slot) in self.devices.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(WgDevice::new(name));
                self.count += 1;
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Destroy a device by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the index is invalid.
    pub fn destroy(&mut self, index: usize) -> Result<()> {
        if index >= MAX_DEVICES {
            return Err(Error::InvalidArgument);
        }
        match &self.devices[index] {
            Some(dev) if dev.active => {
                self.devices[index] = None;
                self.count = self.count.saturating_sub(1);
                Ok(())
            }
            _ => Err(Error::NotFound),
        }
    }

    /// Get a reference to a device by index.
    pub fn device(&self, index: usize) -> Option<&WgDevice> {
        if index >= MAX_DEVICES {
            return None;
        }
        self.devices[index].as_ref().filter(|d| d.active)
    }

    /// Get a mutable reference to a device by index.
    pub fn device_mut(&mut self, index: usize) -> Option<&mut WgDevice> {
        if index >= MAX_DEVICES {
            return None;
        }
        self.devices[index].as_mut().filter(|d| d.active)
    }

    /// Find a device by name.
    pub fn find_by_name(&self, name: &[u8]) -> Option<usize> {
        for (idx, slot) in self.devices.iter().enumerate() {
            if let Some(dev) = slot {
                if dev.active && dev.name() == name {
                    return Some(idx);
                }
            }
        }
        None
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(val: u8) -> WgKey {
        WgKey::from_bytes([val; KEY_SIZE])
    }

    #[test]
    fn test_create_device() {
        let mut reg = WgRegistry::new();
        let idx = reg.create(b"wg0").unwrap();
        assert_eq!(reg.count(), 1);
        let dev = reg.device(idx).unwrap();
        assert_eq!(dev.name(), b"wg0");
    }

    #[test]
    fn test_duplicate_device_rejected() {
        let mut reg = WgRegistry::new();
        reg.create(b"wg0").unwrap();
        assert!(reg.create(b"wg0").is_err());
    }

    #[test]
    fn test_add_peer() {
        let mut reg = WgRegistry::new();
        let idx = reg.create(b"wg0").unwrap();
        let dev = reg.device_mut(idx).unwrap();
        dev.set_private_key(test_key(0xAA));
        let peer_idx = dev.add_peer(test_key(0xBB)).unwrap();
        assert_eq!(dev.peer_count(), 1);
        assert!(dev.peer(peer_idx).is_some());
    }

    #[test]
    fn test_duplicate_peer_rejected() {
        let mut reg = WgRegistry::new();
        let idx = reg.create(b"wg0").unwrap();
        let dev = reg.device_mut(idx).unwrap();
        dev.add_peer(test_key(0xBB)).unwrap();
        assert!(dev.add_peer(test_key(0xBB)).is_err());
    }

    #[test]
    fn test_allowed_ip_routing() {
        let mut reg = WgRegistry::new();
        let idx = reg.create(b"wg0").unwrap();
        let dev = reg.device_mut(idx).unwrap();
        let pidx = dev.add_peer(test_key(0xBB)).unwrap();
        let peer = dev.peer_mut(pidx).unwrap();

        let aip = AllowedIp::new([10, 0, 0, 0], 24).unwrap();
        peer.add_allowed_ip(aip).unwrap();

        assert_eq!(dev.route_by_dst(&[10, 0, 0, 5]), Some(pidx));
        assert_eq!(dev.route_by_dst(&[192, 168, 1, 1]), None);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let mut reg = WgRegistry::new();
        let idx = reg.create(b"wg0").unwrap();
        let dev = reg.device_mut(idx).unwrap();
        dev.set_private_key(test_key(0xAA));
        let pidx = dev.add_peer(test_key(0xBB)).unwrap();

        // Set up allowed-IPs
        let peer = dev.peer_mut(pidx).unwrap();
        peer.add_allowed_ip(AllowedIp::new([10, 0, 0, 0], 8).unwrap())
            .unwrap();

        // Simulate completed handshake
        peer.handshake_state = HandshakeState::Complete;
        peer.session = SessionKeys::from_handshake(test_key(0x11), test_key(0x11), 0);

        // Build a minimal IPv4 packet with dst 10.0.0.2
        let mut cleartext = [0u8; 40];
        cleartext[0] = 0x45; // IPv4
        cleartext[16] = 10;
        cleartext[17] = 0;
        cleartext[18] = 0;
        cleartext[19] = 2;

        let mut cipher = [0u8; 128];
        let (enc_len, _) = dev.encrypt(&cleartext, &mut cipher).unwrap();
        assert!(enc_len > 12);

        // Decrypt
        let mut decrypted = [0u8; 128];
        let dec_len = dev
            .decrypt(&cipher[..enc_len], &mut decrypted, pidx)
            .unwrap();
        assert_eq!(dec_len, 40);
        assert_eq!(&decrypted[..dec_len], &cleartext[..]);
    }

    #[test]
    fn test_replay_protection() {
        let mut keys = SessionKeys::from_handshake(test_key(0x11), test_key(0x22), 0);
        assert!(keys.check_replay(0));
        assert!(keys.check_replay(1));
        // Replay of nonce 0
        assert!(!keys.check_replay(0));
        // Far future nonce
        assert!(keys.check_replay(100));
        // Nonce 50 is within window of 100
        assert!(keys.check_replay(50));
        // Replay of 50
        assert!(!keys.check_replay(50));
    }

    #[test]
    fn test_remove_peer() {
        let mut reg = WgRegistry::new();
        let idx = reg.create(b"wg0").unwrap();
        let dev = reg.device_mut(idx).unwrap();
        let key = test_key(0xCC);
        dev.add_peer(key).unwrap();
        assert_eq!(dev.peer_count(), 1);
        dev.remove_peer(&key).unwrap();
        assert_eq!(dev.peer_count(), 0);
    }

    #[test]
    fn test_destroy_device() {
        let mut reg = WgRegistry::new();
        let idx = reg.create(b"wg0").unwrap();
        reg.destroy(idx).unwrap();
        assert_eq!(reg.count(), 0);
    }

    #[test]
    fn test_find_by_name() {
        let mut reg = WgRegistry::new();
        reg.create(b"wg0").unwrap();
        assert!(reg.find_by_name(b"wg0").is_some());
        assert!(reg.find_by_name(b"wg1").is_none());
    }

    #[test]
    fn test_key_zero() {
        let k = WgKey::zero();
        assert!(k.is_zero());
        let k2 = test_key(0x42);
        assert!(!k2.is_zero());
    }
}
