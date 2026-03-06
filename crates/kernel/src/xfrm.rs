// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! XFRM / IPsec framework for the ONCRIX kernel.
//!
//! Implements the kernel's IPsec transform infrastructure, managing
//! Security Associations (SA) and Security Policies (SP) for
//! ESP (Encapsulating Security Payload) and AH (Authentication
//! Header) transforms.
//!
//! # Architecture
//!
//! ```text
//! Outbound:
//!   Routing → SP lookup (out) → SA lookup → ESP/AH transform → TX
//!
//! Inbound:
//!   RX → ESP/AH header → SA lookup (by SPI) → decrypt/verify →
//!   SP check (in) → deliver
//! ```
//!
//! # Components
//!
//! - **Security Association Database (SAD)**: Maps SPIs to
//!   cryptographic parameters (keys, algorithms, replay state).
//! - **Security Policy Database (SPD)**: Matches traffic selectors
//!   to determine which SA (or bypass/discard) applies.
//! - **Transform engine**: Applies ESP encapsulation or AH
//!   authentication to packets.
//!
//! # Simplifications
//!
//! - Crypto uses placeholder XOR operations.
//! - HMAC uses a simple hash for demonstration.
//! - No IKE/IKEv2 integration (SAs are manually configured).
//! - IPv4 only (IPv6 support is future work).

use oncrix_lib::{Error, Result};

// =========================================================================
// Constants
// =========================================================================

/// Maximum number of Security Associations.
const MAX_SA: usize = 64;

/// Maximum number of Security Policies.
const MAX_SP: usize = 64;

/// ESP protocol number.
const PROTO_ESP: u8 = 50;

/// AH protocol number.
const PROTO_AH: u8 = 51;

/// Key size in bytes for symmetric ciphers.
const CIPHER_KEY_SIZE: usize = 32;

/// Key size in bytes for authentication (HMAC).
const AUTH_KEY_SIZE: usize = 32;

/// ICV (Integrity Check Value) length for AH/ESP auth.
const ICV_LEN: usize = 12;

/// ESP header size (SPI + Seq).
const ESP_HEADER_LEN: usize = 8;

/// AH header size (minimum: next_hdr + len + reserved + SPI +
/// seq + ICV).
const AH_HEADER_LEN: usize = 12 + ICV_LEN;

/// Anti-replay window size (bits).
const REPLAY_WINDOW: u64 = 64;

/// Default SA lifetime in seconds.
const DEFAULT_SA_LIFETIME: u64 = 28800; // 8 hours

/// Maximum SA lifetime in bytes.
const DEFAULT_SA_BYTE_LIMIT: u64 = 4_294_967_296; // 4 GiB

// =========================================================================
// XfrmProto
// =========================================================================

/// IPsec protocol type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfrmProto {
    /// ESP — Encapsulating Security Payload (RFC 4303).
    Esp,
    /// AH — Authentication Header (RFC 4302).
    Ah,
}

impl XfrmProto {
    /// Return the IP protocol number.
    pub const fn proto_num(self) -> u8 {
        match self {
            Self::Esp => PROTO_ESP,
            Self::Ah => PROTO_AH,
        }
    }

    /// Create from IP protocol number.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for unknown protocols.
    pub const fn from_proto_num(num: u8) -> Result<Self> {
        match num {
            50 => Ok(Self::Esp),
            51 => Ok(Self::Ah),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// =========================================================================
// XfrmMode
// =========================================================================

/// IPsec encapsulation mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum XfrmMode {
    /// Transport mode — protect payload only.
    #[default]
    Transport,
    /// Tunnel mode — encapsulate entire original IP packet.
    Tunnel,
}

// =========================================================================
// XfrmDir
// =========================================================================

/// Direction of an IPsec policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XfrmDir {
    /// Inbound (decapsulation / verification).
    In,
    /// Outbound (encapsulation / signing).
    Out,
    /// Forwarded traffic.
    Fwd,
}

// =========================================================================
// PolicyAction
// =========================================================================

/// Action for a security policy match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyAction {
    /// Apply IPsec transform (encrypt / authenticate).
    #[default]
    Protect,
    /// Pass through without IPsec processing.
    Bypass,
    /// Discard the packet.
    Discard,
}

// =========================================================================
// CipherAlg / AuthAlg
// =========================================================================

/// Cipher algorithm for ESP encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CipherAlg {
    /// No encryption (NULL cipher — authentication only).
    Null,
    /// AES-128-CBC (placeholder).
    #[default]
    Aes128Cbc,
    /// AES-256-CBC (placeholder).
    Aes256Cbc,
    /// AES-128-GCM (AEAD — placeholder).
    Aes128Gcm,
}

/// Authentication algorithm for ESP/AH.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AuthAlg {
    /// No authentication.
    None,
    /// HMAC-SHA256-128 (truncated to 128 bits).
    #[default]
    HmacSha256,
    /// HMAC-SHA1-96 (truncated to 96 bits).
    HmacSha1,
}

// =========================================================================
// TrafficSelector
// =========================================================================

/// A traffic selector matching source/dest IP, ports, and protocol.
///
/// Used in Security Policies to select which traffic to protect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrafficSelector {
    /// Source IPv4 address.
    pub src_addr: [u8; 4],
    /// Source prefix length (CIDR).
    pub src_prefix: u8,
    /// Destination IPv4 address.
    pub dst_addr: [u8; 4],
    /// Destination prefix length (CIDR).
    pub dst_prefix: u8,
    /// IP protocol (0 = any).
    pub protocol: u8,
    /// Source port range start (0 = any).
    pub src_port_start: u16,
    /// Source port range end (inclusive).
    pub src_port_end: u16,
    /// Destination port range start (0 = any).
    pub dst_port_start: u16,
    /// Destination port range end (inclusive).
    pub dst_port_end: u16,
}

impl TrafficSelector {
    /// A wildcard selector that matches everything.
    pub const ANY: Self = Self {
        src_addr: [0; 4],
        src_prefix: 0,
        dst_addr: [0; 4],
        dst_prefix: 0,
        protocol: 0,
        src_port_start: 0,
        src_port_end: 0,
        dst_port_start: 0,
        dst_port_end: 0,
    };

    /// Check if a packet matches this selector.
    pub fn matches(
        &self,
        src_ip: &[u8; 4],
        dst_ip: &[u8; 4],
        proto: u8,
        src_port: u16,
        dst_port: u16,
    ) -> bool {
        if !Self::ip_matches(&self.src_addr, self.src_prefix, src_ip) {
            return false;
        }
        if !Self::ip_matches(&self.dst_addr, self.dst_prefix, dst_ip) {
            return false;
        }
        if self.protocol != 0 && self.protocol != proto {
            return false;
        }
        if self.src_port_start != 0
            && (src_port < self.src_port_start || src_port > self.src_port_end)
        {
            return false;
        }
        if self.dst_port_start != 0
            && (dst_port < self.dst_port_start || dst_port > self.dst_port_end)
        {
            return false;
        }
        true
    }

    /// Check IP address against a CIDR prefix.
    fn ip_matches(net: &[u8; 4], prefix: u8, addr: &[u8; 4]) -> bool {
        if prefix == 0 {
            return true;
        }
        let mask = if prefix >= 32 {
            0xFFFF_FFFFu32
        } else {
            0xFFFF_FFFFu32 << (32 - prefix)
        };
        let a = Self::to_u32(net);
        let b = Self::to_u32(addr);
        (a & mask) == (b & mask)
    }

    /// Convert four octets to host-order `u32`.
    fn to_u32(o: &[u8; 4]) -> u32 {
        ((o[0] as u32) << 24) | ((o[1] as u32) << 16) | ((o[2] as u32) << 8) | (o[3] as u32)
    }
}

impl Default for TrafficSelector {
    fn default() -> Self {
        Self::ANY
    }
}

// =========================================================================
// SecurityAssociation (SA)
// =========================================================================

/// A Security Association — the fundamental unit of IPsec.
///
/// An SA defines the cryptographic parameters for one direction of
/// a protected flow, identified by a unique SPI.
pub struct SecurityAssociation {
    /// Whether this SA slot is active.
    pub active: bool,
    /// Security Parameters Index (network byte order).
    pub spi: u32,
    /// IPsec protocol (ESP or AH).
    pub proto: XfrmProto,
    /// Encapsulation mode.
    pub mode: XfrmMode,
    /// Source tunnel address (tunnel mode only).
    pub src_addr: [u8; 4],
    /// Destination tunnel address (tunnel mode only).
    pub dst_addr: [u8; 4],
    /// Cipher algorithm.
    pub cipher_alg: CipherAlg,
    /// Cipher key.
    pub cipher_key: [u8; CIPHER_KEY_SIZE],
    /// Authentication algorithm.
    pub auth_alg: AuthAlg,
    /// Authentication key.
    pub auth_key: [u8; AUTH_KEY_SIZE],
    /// Outbound sequence number (for generating packets).
    pub seq_out: u32,
    /// Highest received sequence number (for replay protection).
    pub seq_in_max: u64,
    /// Replay window bitmap.
    pub replay_bitmap: u64,
    /// SA lifetime remaining (ticks/seconds).
    pub lifetime_secs: u64,
    /// SA byte limit remaining.
    pub lifetime_bytes: u64,
    /// Total bytes processed by this SA.
    pub bytes_processed: u64,
    /// Total packets processed by this SA.
    pub packets_processed: u64,
    /// Tick at which this SA was created.
    pub created_tick: u64,
    /// Whether this SA is in a "dying" state (soft limit hit).
    pub dying: bool,
}

impl SecurityAssociation {
    /// Create a new SA.
    fn new(spi: u32, proto: XfrmProto, mode: XfrmMode, src: [u8; 4], dst: [u8; 4]) -> Self {
        Self {
            active: true,
            spi,
            proto,
            mode,
            src_addr: src,
            dst_addr: dst,
            cipher_alg: CipherAlg::default(),
            cipher_key: [0u8; CIPHER_KEY_SIZE],
            auth_alg: AuthAlg::default(),
            auth_key: [0u8; AUTH_KEY_SIZE],
            seq_out: 0,
            seq_in_max: 0,
            replay_bitmap: 0,
            lifetime_secs: DEFAULT_SA_LIFETIME,
            lifetime_bytes: DEFAULT_SA_BYTE_LIMIT,
            bytes_processed: 0,
            packets_processed: 0,
            created_tick: 0,
            dying: false,
        }
    }

    /// Set the cipher key.
    pub fn set_cipher_key(&mut self, key: &[u8]) -> Result<()> {
        if key.len() > CIPHER_KEY_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.cipher_key[..key.len()].copy_from_slice(key);
        Ok(())
    }

    /// Set the authentication key.
    pub fn set_auth_key(&mut self, key: &[u8]) -> Result<()> {
        if key.len() > AUTH_KEY_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.auth_key[..key.len()].copy_from_slice(key);
        Ok(())
    }

    /// Check a received sequence number against the replay window.
    ///
    /// Returns `true` if the sequence number is acceptable.
    pub fn check_replay(&mut self, seq: u64) -> bool {
        if seq > self.seq_in_max {
            let shift = seq - self.seq_in_max;
            if shift < REPLAY_WINDOW {
                self.replay_bitmap <<= shift;
            } else {
                self.replay_bitmap = 0;
            }
            self.replay_bitmap |= 1;
            self.seq_in_max = seq;
            true
        } else {
            let diff = self.seq_in_max - seq;
            if diff >= REPLAY_WINDOW {
                return false;
            }
            let bit = 1u64 << diff;
            if self.replay_bitmap & bit != 0 {
                return false;
            }
            self.replay_bitmap |= bit;
            true
        }
    }

    /// Advance the outbound sequence number.
    fn next_seq(&mut self) -> u32 {
        let seq = self.seq_out;
        self.seq_out = seq.wrapping_add(1);
        seq
    }

    /// Record bytes processed for lifetime accounting.
    fn account(&mut self, bytes: u64) {
        self.bytes_processed = self.bytes_processed.saturating_add(bytes);
        self.packets_processed = self.packets_processed.saturating_add(1);
        self.lifetime_bytes = self.lifetime_bytes.saturating_sub(bytes);
        if self.lifetime_bytes == 0 {
            self.dying = true;
        }
    }

    /// Check if this SA has expired.
    pub fn is_expired(&self) -> bool {
        self.lifetime_secs == 0 || self.lifetime_bytes == 0
    }
}

// =========================================================================
// SecurityPolicy (SP)
// =========================================================================

/// A Security Policy — defines what to do with matching traffic.
pub struct SecurityPolicy {
    /// Whether this SP slot is active.
    pub active: bool,
    /// Policy index (unique identifier).
    pub index: u32,
    /// Direction.
    pub dir: XfrmDir,
    /// Traffic selector.
    pub selector: TrafficSelector,
    /// Action to take.
    pub action: PolicyAction,
    /// Required SPI (for Protect action; 0 = any SA matching
    /// the selector).
    pub reqid: u32,
    /// Required protocol (for Protect action).
    pub proto: XfrmProto,
    /// Required mode (for Protect action).
    pub mode: XfrmMode,
    /// Priority (lower = higher priority).
    pub priority: u32,
    /// Packets matched by this policy.
    pub packets: u64,
    /// Bytes matched by this policy.
    pub bytes: u64,
}

impl SecurityPolicy {
    /// Create a new policy.
    fn new(index: u32, dir: XfrmDir, selector: TrafficSelector, action: PolicyAction) -> Self {
        Self {
            active: true,
            index,
            dir,
            selector,
            action,
            reqid: 0,
            proto: XfrmProto::Esp,
            mode: XfrmMode::Transport,
            priority: 1000,
            packets: 0,
            bytes: 0,
        }
    }

    /// Record a match.
    fn record(&mut self, byte_count: u64) {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(byte_count);
    }
}

// =========================================================================
// SaDatabase
// =========================================================================

/// The Security Association Database (SAD).
///
/// Stores all active SAs and provides lookup by SPI.
pub struct SaDatabase {
    /// SA slots.
    entries: [Option<SecurityAssociation>; MAX_SA],
    /// Number of active SAs.
    count: usize,
}

/// Compile-time None for SA array.
const EMPTY_SA: Option<SecurityAssociation> = None;

impl SaDatabase {
    /// Create an empty SAD.
    pub const fn new() -> Self {
        Self {
            entries: [EMPTY_SA; MAX_SA],
            count: 0,
        }
    }

    /// Return the number of active SAs.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Add a new SA.
    ///
    /// # Errors
    ///
    /// - [`Error::AlreadyExists`] if an SA with the same SPI and
    ///   protocol exists.
    /// - [`Error::OutOfMemory`] if no free slots remain.
    pub fn add(
        &mut self,
        spi: u32,
        proto: XfrmProto,
        mode: XfrmMode,
        src: [u8; 4],
        dst: [u8; 4],
    ) -> Result<usize> {
        // Check for duplicate SPI + proto
        for sa in self.entries.iter().flatten() {
            if sa.active && sa.spi == spi && sa.proto == proto {
                return Err(Error::AlreadyExists);
            }
        }

        for (idx, slot) in self.entries.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(SecurityAssociation::new(spi, proto, mode, src, dst));
                self.count += 1;
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove an SA by SPI and protocol.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if no matching SA exists.
    pub fn remove(&mut self, spi: u32, proto: XfrmProto) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if let Some(sa) = slot {
                if sa.active && sa.spi == spi && sa.proto == proto {
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Look up an SA by SPI and protocol.
    pub fn lookup(&self, spi: u32, proto: XfrmProto) -> Option<&SecurityAssociation> {
        self.entries
            .iter()
            .flatten()
            .find(|&sa| sa.active && sa.spi == spi && sa.proto == proto)
            .map(|v| v as _)
    }

    /// Mutable lookup by SPI and protocol.
    pub fn lookup_mut(&mut self, spi: u32, proto: XfrmProto) -> Option<&mut SecurityAssociation> {
        for sa in self.entries.iter_mut().flatten() {
            if sa.active && sa.spi == spi && sa.proto == proto {
                return Some(sa);
            }
        }
        None
    }

    /// Look up an SA by index.
    pub fn get(&self, index: usize) -> Option<&SecurityAssociation> {
        if index >= MAX_SA {
            return None;
        }
        self.entries[index].as_ref().filter(|sa| sa.active)
    }

    /// Mutable lookup by index.
    pub fn get_mut(&mut self, index: usize) -> Option<&mut SecurityAssociation> {
        if index >= MAX_SA {
            return None;
        }
        self.entries[index].as_mut().filter(|sa| sa.active)
    }

    /// Advance tick and expire aged-out SAs.
    pub fn tick(&mut self, ticks: u64) -> usize {
        let mut expired = 0;
        for slot in self.entries.iter_mut() {
            if let Some(sa) = slot {
                if sa.active {
                    sa.lifetime_secs = sa.lifetime_secs.saturating_sub(ticks);
                    if sa.is_expired() {
                        *slot = None;
                        self.count = self.count.saturating_sub(1);
                        expired += 1;
                    }
                }
            }
        }
        expired
    }

    /// Remove all SAs.
    pub fn flush(&mut self) {
        for slot in self.entries.iter_mut() {
            *slot = None;
        }
        self.count = 0;
    }
}

// =========================================================================
// SpDatabase
// =========================================================================

/// The Security Policy Database (SPD).
///
/// Stores all active security policies and provides lookup by
/// traffic selector.
pub struct SpDatabase {
    /// SP slots.
    entries: [Option<SecurityPolicy>; MAX_SP],
    /// Number of active SPs.
    count: usize,
    /// Next policy index.
    next_index: u32,
}

/// Compile-time None for SP array.
const EMPTY_SP: Option<SecurityPolicy> = None;

impl SpDatabase {
    /// Create an empty SPD.
    pub const fn new() -> Self {
        Self {
            entries: [EMPTY_SP; MAX_SP],
            count: 0,
            next_index: 1,
        }
    }

    /// Return the number of active policies.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Add a new security policy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if no free slots remain.
    pub fn add(
        &mut self,
        dir: XfrmDir,
        selector: TrafficSelector,
        action: PolicyAction,
    ) -> Result<u32> {
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                let idx = self.next_index;
                *slot = Some(SecurityPolicy::new(idx, dir, selector, action));
                self.next_index = self.next_index.wrapping_add(1);
                self.count += 1;
                return Ok(idx);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a policy by index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if not found.
    pub fn remove(&mut self, index: u32) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if let Some(sp) = slot {
                if sp.active && sp.index == index {
                    *slot = None;
                    self.count = self.count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Look up the best-matching policy for a packet.
    ///
    /// Searches all policies in the given direction, returning the
    /// one with the lowest priority value (highest priority) that
    /// matches the traffic.
    pub fn lookup(
        &mut self,
        dir: XfrmDir,
        src_ip: &[u8; 4],
        dst_ip: &[u8; 4],
        proto: u8,
        src_port: u16,
        dst_port: u16,
        packet_len: u64,
    ) -> Option<PolicyAction> {
        let mut best: Option<(PolicyAction, u32)> = None;

        for sp in self.entries.iter_mut().flatten() {
            if !sp.active {
                continue;
            }
            let dir_match = match (&sp.dir, &dir) {
                (XfrmDir::In, XfrmDir::In)
                | (XfrmDir::Out, XfrmDir::Out)
                | (XfrmDir::Fwd, XfrmDir::Fwd) => true,
                _ => false,
            };
            if !dir_match {
                continue;
            }
            if sp
                .selector
                .matches(src_ip, dst_ip, proto, src_port, dst_port)
            {
                match best {
                    Some((_, bp)) if sp.priority < bp => {
                        sp.record(packet_len);
                        best = Some((sp.action, sp.priority));
                    }
                    None => {
                        sp.record(packet_len);
                        best = Some((sp.action, sp.priority));
                    }
                    _ => {}
                }
            }
        }

        best.map(|(action, _)| action)
    }

    /// Remove all policies.
    pub fn flush(&mut self) {
        for slot in self.entries.iter_mut() {
            *slot = None;
        }
        self.count = 0;
    }
}

// =========================================================================
// XfrmEngine — transform engine
// =========================================================================

/// The XFRM transform engine.
///
/// Provides the top-level API for applying IPsec transforms to
/// packets, combining the SAD and SPD.
pub struct XfrmEngine {
    /// Security Association Database.
    pub sad: SaDatabase,
    /// Security Policy Database.
    pub spd: SpDatabase,
    /// Whether XFRM processing is enabled.
    enabled: bool,
    /// Current monotonic tick.
    current_tick: u64,
}

impl XfrmEngine {
    /// Create a new XFRM engine.
    pub const fn new() -> Self {
        Self {
            sad: SaDatabase::new(),
            spd: SpDatabase::new(),
            enabled: true,
            current_tick: 0,
        }
    }

    /// Return whether processing is enabled.
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Enable XFRM processing.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable XFRM processing.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Apply ESP encapsulation to an outbound packet.
    ///
    /// Wraps the cleartext in an ESP header with sequence number,
    /// encrypts the payload, and appends an ICV.
    ///
    /// # Arguments
    ///
    /// * `spi` — SPI of the SA to use.
    /// * `cleartext` — original IP payload to protect.
    /// * `out` — buffer for the ESP-encapsulated packet.
    ///
    /// # Returns
    ///
    /// Number of bytes written to `out`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the SA does not exist.
    /// - [`Error::InvalidArgument`] if `out` is too small.
    pub fn esp_encrypt(&mut self, spi: u32, cleartext: &[u8], out: &mut [u8]) -> Result<usize> {
        if !self.enabled {
            return Err(Error::InvalidArgument);
        }

        let sa = self
            .sad
            .lookup_mut(spi, XfrmProto::Esp)
            .ok_or(Error::NotFound)?;

        let total = ESP_HEADER_LEN + cleartext.len() + ICV_LEN;
        if out.len() < total {
            return Err(Error::InvalidArgument);
        }

        // ESP header: SPI (4) + Sequence (4)
        let spi_bytes = sa.spi.to_be_bytes();
        let seq = sa.next_seq();
        let seq_bytes = seq.to_be_bytes();

        out[0..4].copy_from_slice(&spi_bytes);
        out[4..8].copy_from_slice(&seq_bytes);

        // XOR-encrypt payload with cipher key
        for (i, &b) in cleartext.iter().enumerate() {
            out[ESP_HEADER_LEN + i] = b ^ sa.cipher_key[i % CIPHER_KEY_SIZE];
        }

        // Compute simple ICV (XOR of auth key with data hash)
        let icv_offset = ESP_HEADER_LEN + cleartext.len();
        let mut icv = [0u8; ICV_LEN];
        let mut hash: u32 = 0;
        for &b in &out[..icv_offset] {
            hash = hash.wrapping_add(b as u32);
            hash = hash.wrapping_mul(31);
        }
        let hash_bytes = hash.to_le_bytes();
        for i in 0..ICV_LEN {
            icv[i] = hash_bytes[i % 4] ^ sa.auth_key[i % AUTH_KEY_SIZE];
        }
        out[icv_offset..icv_offset + ICV_LEN].copy_from_slice(&icv);

        sa.account(cleartext.len() as u64);

        Ok(total)
    }

    /// Decrypt and verify an inbound ESP packet.
    ///
    /// Parses the ESP header, checks the sequence number against
    /// the replay window, verifies the ICV, and decrypts the
    /// payload.
    ///
    /// # Returns
    ///
    /// Number of cleartext bytes written to `out`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the packet is malformed.
    /// - [`Error::NotFound`] if the SA does not exist.
    /// - [`Error::PermissionDenied`] if replay or ICV check fails.
    pub fn esp_decrypt(&mut self, packet: &[u8], out: &mut [u8]) -> Result<usize> {
        if !self.enabled {
            return Err(Error::InvalidArgument);
        }
        if packet.len() < ESP_HEADER_LEN + ICV_LEN {
            return Err(Error::InvalidArgument);
        }

        // Parse SPI and sequence
        let spi = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
        let seq = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);

        let sa = self
            .sad
            .lookup_mut(spi, XfrmProto::Esp)
            .ok_or(Error::NotFound)?;

        // Anti-replay check
        if !sa.check_replay(seq as u64) {
            return Err(Error::PermissionDenied);
        }

        let payload_len = packet.len() - ESP_HEADER_LEN - ICV_LEN;
        if out.len() < payload_len {
            return Err(Error::InvalidArgument);
        }

        // Verify ICV
        let icv_offset = ESP_HEADER_LEN + payload_len;
        let mut hash: u32 = 0;
        for &b in &packet[..icv_offset] {
            hash = hash.wrapping_add(b as u32);
            hash = hash.wrapping_mul(31);
        }
        let hash_bytes = hash.to_le_bytes();
        let mut expected_icv = [0u8; ICV_LEN];
        for i in 0..ICV_LEN {
            expected_icv[i] = hash_bytes[i % 4] ^ sa.auth_key[i % AUTH_KEY_SIZE];
        }
        if packet[icv_offset..icv_offset + ICV_LEN] != expected_icv {
            return Err(Error::PermissionDenied);
        }

        // XOR-decrypt
        let cipher_data = &packet[ESP_HEADER_LEN..icv_offset];
        for (i, &b) in cipher_data.iter().enumerate() {
            out[i] = b ^ sa.cipher_key[i % CIPHER_KEY_SIZE];
        }

        sa.account(payload_len as u64);

        Ok(payload_len)
    }

    /// Apply AH authentication to an outbound packet.
    ///
    /// Inserts an AH header with a computed ICV.  The original
    /// payload is not encrypted (AH provides authentication only).
    ///
    /// # Returns
    ///
    /// Number of bytes written to `out` (AH header + original
    /// payload).
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if the SA does not exist.
    /// - [`Error::InvalidArgument`] if `out` is too small.
    pub fn ah_sign(
        &mut self,
        spi: u32,
        payload: &[u8],
        next_header: u8,
        out: &mut [u8],
    ) -> Result<usize> {
        if !self.enabled {
            return Err(Error::InvalidArgument);
        }

        let sa = self
            .sad
            .lookup_mut(spi, XfrmProto::Ah)
            .ok_or(Error::NotFound)?;

        let total = AH_HEADER_LEN + payload.len();
        if out.len() < total {
            return Err(Error::InvalidArgument);
        }

        let seq = sa.next_seq();

        // AH header
        out[0] = next_header; // Next Header
        // Payload Length (in 32-bit words, minus 2)
        out[1] = ((AH_HEADER_LEN / 4) - 2) as u8;
        out[2] = 0; // Reserved
        out[3] = 0;
        let spi_bytes = sa.spi.to_be_bytes();
        out[4..8].copy_from_slice(&spi_bytes);
        let seq_bytes = seq.to_be_bytes();
        out[8..12].copy_from_slice(&seq_bytes);

        // Copy payload
        out[AH_HEADER_LEN..total].copy_from_slice(payload);

        // Compute ICV over header (with zeroed ICV field) +
        // payload
        let mut hash: u32 = 0;
        for i in 0..12 {
            hash = hash.wrapping_add(out[i] as u32);
            hash = hash.wrapping_mul(31);
        }
        for &b in payload {
            hash = hash.wrapping_add(b as u32);
            hash = hash.wrapping_mul(31);
        }
        let hash_bytes = hash.to_le_bytes();
        for i in 0..ICV_LEN {
            out[12 + i] = hash_bytes[i % 4] ^ sa.auth_key[i % AUTH_KEY_SIZE];
        }

        sa.account(payload.len() as u64);

        Ok(total)
    }

    /// Verify an inbound AH-protected packet.
    ///
    /// # Returns
    ///
    /// Number of payload bytes written to `out`.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if the packet is malformed.
    /// - [`Error::NotFound`] if the SA does not exist.
    /// - [`Error::PermissionDenied`] if sequence or ICV fails.
    pub fn ah_verify(&mut self, packet: &[u8], out: &mut [u8]) -> Result<usize> {
        if !self.enabled {
            return Err(Error::InvalidArgument);
        }
        if packet.len() < AH_HEADER_LEN {
            return Err(Error::InvalidArgument);
        }

        let spi = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
        let seq = u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);

        let sa = self
            .sad
            .lookup_mut(spi, XfrmProto::Ah)
            .ok_or(Error::NotFound)?;

        if !sa.check_replay(seq as u64) {
            return Err(Error::PermissionDenied);
        }

        let payload = &packet[AH_HEADER_LEN..];
        if out.len() < payload.len() {
            return Err(Error::InvalidArgument);
        }

        // Recompute ICV
        let mut hash: u32 = 0;
        for i in 0..12 {
            hash = hash.wrapping_add(packet[i] as u32);
            hash = hash.wrapping_mul(31);
        }
        for &b in payload {
            hash = hash.wrapping_add(b as u32);
            hash = hash.wrapping_mul(31);
        }
        let hash_bytes = hash.to_le_bytes();
        let mut expected_icv = [0u8; ICV_LEN];
        for i in 0..ICV_LEN {
            expected_icv[i] = hash_bytes[i % 4] ^ sa.auth_key[i % AUTH_KEY_SIZE];
        }
        if packet[12..12 + ICV_LEN] != expected_icv {
            return Err(Error::PermissionDenied);
        }

        out[..payload.len()].copy_from_slice(payload);
        sa.account(payload.len() as u64);

        Ok(payload.len())
    }

    /// Advance the tick counter and expire aged-out SAs.
    pub fn tick(&mut self, ticks: u64) -> usize {
        self.current_tick = self.current_tick.saturating_add(ticks);
        self.sad.tick(ticks)
    }

    /// Flush all SAs and SPs.
    pub fn flush(&mut self) {
        self.sad.flush();
        self.spd.flush();
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_sa() {
        let mut eng = XfrmEngine::new();
        let idx = eng
            .sad
            .add(
                0x1000,
                XfrmProto::Esp,
                XfrmMode::Transport,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
            )
            .unwrap();
        assert_eq!(eng.sad.count(), 1);
        assert!(eng.sad.get(idx).is_some());
    }

    #[test]
    fn test_duplicate_sa_rejected() {
        let mut eng = XfrmEngine::new();
        eng.sad
            .add(
                0x1000,
                XfrmProto::Esp,
                XfrmMode::Transport,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
            )
            .unwrap();
        let dup = eng.sad.add(
            0x1000,
            XfrmProto::Esp,
            XfrmMode::Transport,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
        );
        assert!(dup.is_err());
    }

    #[test]
    fn test_same_spi_different_proto_ok() {
        let mut eng = XfrmEngine::new();
        eng.sad
            .add(
                0x1000,
                XfrmProto::Esp,
                XfrmMode::Transport,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
            )
            .unwrap();
        eng.sad
            .add(
                0x1000,
                XfrmProto::Ah,
                XfrmMode::Transport,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
            )
            .unwrap();
        assert_eq!(eng.sad.count(), 2);
    }

    #[test]
    fn test_esp_encrypt_decrypt() {
        let mut eng = XfrmEngine::new();
        eng.sad
            .add(
                0x1000,
                XfrmProto::Esp,
                XfrmMode::Transport,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
            )
            .unwrap();
        // Set keys
        let key = [0x42u8; CIPHER_KEY_SIZE];
        let auth = [0x99u8; AUTH_KEY_SIZE];
        let sa = eng.sad.lookup_mut(0x1000, XfrmProto::Esp).unwrap();
        sa.set_cipher_key(&key).unwrap();
        sa.set_auth_key(&auth).unwrap();

        let cleartext = b"Hello IPsec world!";
        let mut cipher = [0u8; 256];
        let enc_len = eng.esp_encrypt(0x1000, cleartext, &mut cipher).unwrap();
        assert!(enc_len > cleartext.len());

        // Re-set sequence for decrypt (SA uses same entry)
        let sa = eng.sad.lookup_mut(0x1000, XfrmProto::Esp).unwrap();
        sa.seq_in_max = 0;
        sa.replay_bitmap = 0;

        let mut plain = [0u8; 256];
        let dec_len = eng.esp_decrypt(&cipher[..enc_len], &mut plain).unwrap();
        assert_eq!(dec_len, cleartext.len());
        assert_eq!(&plain[..dec_len], cleartext);
    }

    #[test]
    fn test_ah_sign_verify() {
        let mut eng = XfrmEngine::new();
        eng.sad
            .add(
                0x2000,
                XfrmProto::Ah,
                XfrmMode::Transport,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
            )
            .unwrap();
        let auth = [0xABu8; AUTH_KEY_SIZE];
        let sa = eng.sad.lookup_mut(0x2000, XfrmProto::Ah).unwrap();
        sa.set_auth_key(&auth).unwrap();

        let payload = b"Authenticated data";
        let mut out = [0u8; 256];
        let signed_len = eng.ah_sign(0x2000, payload, 6, &mut out).unwrap();

        // Reset sequence for verify
        let sa = eng.sad.lookup_mut(0x2000, XfrmProto::Ah).unwrap();
        sa.seq_in_max = 0;
        sa.replay_bitmap = 0;

        let mut verified = [0u8; 256];
        let ver_len = eng.ah_verify(&out[..signed_len], &mut verified).unwrap();
        assert_eq!(ver_len, payload.len());
        assert_eq!(&verified[..ver_len], payload);
    }

    #[test]
    fn test_esp_replay_rejection() {
        let mut eng = XfrmEngine::new();
        eng.sad
            .add(
                0x3000,
                XfrmProto::Esp,
                XfrmMode::Transport,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
            )
            .unwrap();
        let key = [0x11u8; CIPHER_KEY_SIZE];
        let auth = [0x22u8; AUTH_KEY_SIZE];
        let sa = eng.sad.lookup_mut(0x3000, XfrmProto::Esp).unwrap();
        sa.set_cipher_key(&key).unwrap();
        sa.set_auth_key(&auth).unwrap();

        let data = b"test replay";
        let mut cipher = [0u8; 256];
        let enc_len = eng.esp_encrypt(0x3000, data, &mut cipher).unwrap();

        // First decrypt succeeds
        let sa = eng.sad.lookup_mut(0x3000, XfrmProto::Esp).unwrap();
        sa.seq_in_max = 0;
        sa.replay_bitmap = 0;

        let mut plain = [0u8; 256];
        eng.esp_decrypt(&cipher[..enc_len], &mut plain).unwrap();

        // Replay of the same packet fails
        let result = eng.esp_decrypt(&cipher[..enc_len], &mut plain);
        assert!(result.is_err());
    }

    #[test]
    fn test_policy_lookup() {
        let mut eng = XfrmEngine::new();
        let sel = TrafficSelector {
            src_addr: [10, 0, 0, 0],
            src_prefix: 24,
            dst_addr: [192, 168, 1, 0],
            dst_prefix: 24,
            protocol: 6, // TCP
            src_port_start: 0,
            src_port_end: 0,
            dst_port_start: 443,
            dst_port_end: 443,
            ..TrafficSelector::ANY
        };
        eng.spd
            .add(XfrmDir::Out, sel, PolicyAction::Protect)
            .unwrap();

        // Should match
        let action = eng.spd.lookup(
            XfrmDir::Out,
            &[10, 0, 0, 5],
            &[192, 168, 1, 10],
            6,
            12345,
            443,
            64,
        );
        assert_eq!(action, Some(PolicyAction::Protect));

        // Wrong direction
        let action = eng.spd.lookup(
            XfrmDir::In,
            &[10, 0, 0, 5],
            &[192, 168, 1, 10],
            6,
            12345,
            443,
            64,
        );
        assert_eq!(action, None);

        // Wrong port
        let action = eng.spd.lookup(
            XfrmDir::Out,
            &[10, 0, 0, 5],
            &[192, 168, 1, 10],
            6,
            12345,
            80,
            64,
        );
        assert_eq!(action, None);
    }

    #[test]
    fn test_sa_expiry() {
        let mut eng = XfrmEngine::new();
        eng.sad
            .add(
                0x5000,
                XfrmProto::Esp,
                XfrmMode::Transport,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
            )
            .unwrap();
        assert_eq!(eng.sad.count(), 1);

        // Advance past lifetime
        let expired = eng.tick(DEFAULT_SA_LIFETIME + 1);
        assert_eq!(expired, 1);
        assert_eq!(eng.sad.count(), 0);
    }

    #[test]
    fn test_traffic_selector() {
        let sel = TrafficSelector {
            src_addr: [10, 0, 0, 0],
            src_prefix: 8,
            dst_addr: [0; 4],
            dst_prefix: 0,
            protocol: 0,
            src_port_start: 0,
            src_port_end: 0,
            dst_port_start: 0,
            dst_port_end: 0,
        };
        assert!(sel.matches(&[10, 1, 2, 3], &[8, 8, 8, 8], 17, 1234, 53,));
        assert!(!sel.matches(&[192, 168, 1, 1], &[8, 8, 8, 8], 17, 1234, 53,));
    }

    #[test]
    fn test_flush() {
        let mut eng = XfrmEngine::new();
        eng.sad
            .add(0x100, XfrmProto::Esp, XfrmMode::Transport, [0; 4], [0; 4])
            .unwrap();
        eng.spd
            .add(XfrmDir::Out, TrafficSelector::ANY, PolicyAction::Bypass)
            .unwrap();
        eng.flush();
        assert_eq!(eng.sad.count(), 0);
        assert_eq!(eng.spd.count(), 0);
    }
}
