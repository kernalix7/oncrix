// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! D-Bus kernel message bus — in-kernel message routing.
//!
//! This module implements a simplified D-Bus message bus (inspired by
//! `kdbus`, the never-merged Linux kernel D-Bus) that provides
//! in-kernel message routing with zero-copy transfers and credential
//! passing.
//!
//! # Architecture
//!
//! ```text
//! Connection A                    Bus                    Connection B
//! ────────────                    ───                    ────────────
//! unique=:1.1 ──method_call──► routing ──────────────► unique=:1.2
//!             ◄──method_return── table  ◄──method_return──
//!                                 │
//!             ◄──signal──────── match ──────signal──────►
//!                               rules
//! ```
//!
//! # Concepts
//!
//! - **Connection**: A process connected to the bus (gets a unique name).
//! - **Well-known name**: A human-readable name (e.g., `org.freedesktop.DBus`)
//!   owned by a connection.
//! - **Message types**: method_call, method_return, error, signal.
//! - **Match rules**: Subscriptions for signal broadcast delivery.
//! - **Credentials**: uid/gid/pid attached to every message.
//!
//! # Message routing
//!
//! - **Unicast**: Routed by destination unique name or well-known name.
//! - **Broadcast**: Signals are delivered to all connections with matching
//!   match rules.
//!
//! # References
//!
//! - D-Bus specification: https://dbus.freedesktop.org/doc/dbus-specification.html
//! - kdbus design: https://lwn.net/Articles/619068/

extern crate alloc;

use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants — message types
// ---------------------------------------------------------------------------

/// Method call: request a method invocation.
pub const DBUS_MSG_METHOD_CALL: u8 = 1;
/// Method return: successful reply to a method call.
pub const DBUS_MSG_METHOD_RETURN: u8 = 2;
/// Error: error reply to a method call.
pub const DBUS_MSG_ERROR: u8 = 3;
/// Signal: broadcast notification.
pub const DBUS_MSG_SIGNAL: u8 = 4;

// ---------------------------------------------------------------------------
// Constants — header field codes
// ---------------------------------------------------------------------------

/// Destination connection name.
pub const DBUS_HDR_DESTINATION: u8 = 6;
/// Sender connection name.
pub const DBUS_HDR_SENDER: u8 = 7;
/// Interface name (for method calls and signals).
pub const DBUS_HDR_INTERFACE: u8 = 2;
/// Member (method or signal) name.
pub const DBUS_HDR_MEMBER: u8 = 3;
/// Error name (for error replies).
pub const DBUS_HDR_ERROR_NAME: u8 = 4;
/// Reply serial (for method returns and errors).
pub const DBUS_HDR_REPLY_SERIAL: u8 = 5;
/// Object path.
pub const DBUS_HDR_PATH: u8 = 1;

// ---------------------------------------------------------------------------
// Constants — flags
// ---------------------------------------------------------------------------

/// No reply expected.
pub const DBUS_FLAG_NO_REPLY_EXPECTED: u8 = 0x1;
/// No auto-start the destination.
pub const DBUS_FLAG_NO_AUTO_START: u8 = 0x2;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Maximum number of connections on the bus.
const MAX_CONNECTIONS: usize = 128;

/// Maximum number of well-known names.
const MAX_WELL_KNOWN_NAMES: usize = 256;

/// Maximum number of match rules per connection.
const MAX_MATCH_RULES_PER_CONN: usize = 64;

/// Maximum number of queued messages per connection.
const MAX_QUEUED_MSGS: usize = 64;

/// Maximum message body size.
const MAX_MSG_BODY_SIZE: usize = 4096;

/// Maximum name length (bus name, interface, member).
const MAX_NAME_LEN: usize = 255;

/// Maximum header fields per message.
const MAX_HEADER_FIELDS: usize = 8;

// ---------------------------------------------------------------------------
// BusName — fixed-size name
// ---------------------------------------------------------------------------

/// A bus name (unique or well-known), stored inline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BusName {
    /// Name bytes.
    bytes: [u8; MAX_NAME_LEN],
    /// Actual length.
    len: usize,
}

impl BusName {
    /// Create a bus name from bytes.
    pub fn from_bytes(name: &[u8]) -> Result<Self> {
        if name.is_empty() || name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut bytes = [0u8; MAX_NAME_LEN];
        bytes[..name.len()].copy_from_slice(name);
        Ok(Self {
            bytes,
            len: name.len(),
        })
    }

    /// Return the name as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Return the length.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Return whether the name is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// ---------------------------------------------------------------------------
// DbusCredentials — message sender credentials
// ---------------------------------------------------------------------------

/// Credentials attached to a D-Bus connection/message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DbusCredentials {
    /// Process ID.
    pub pid: u32,
    /// User ID.
    pub uid: u32,
    /// Group ID.
    pub gid: u32,
}

impl DbusCredentials {
    /// Create new credentials.
    pub const fn new(pid: u32, uid: u32, gid: u32) -> Self {
        Self { pid, uid, gid }
    }
}

// ---------------------------------------------------------------------------
// DbusHeaderField — a single header field
// ---------------------------------------------------------------------------

/// A D-Bus message header field.
#[derive(Debug, Clone, Copy)]
pub struct DbusHeaderField {
    /// Field code (DBUS_HDR_*).
    pub code: u8,
    /// Field value (index into name table or serial number).
    pub value: u64,
}

// ---------------------------------------------------------------------------
// DbusMessage — a complete D-Bus message
// ---------------------------------------------------------------------------

/// A D-Bus message on the kernel bus.
pub struct DbusMessage {
    /// Message type (method_call, method_return, error, signal).
    pub msg_type: u8,
    /// Message flags.
    pub flags: u8,
    /// Serial number (unique per connection per direction).
    pub serial: u32,
    /// Header fields.
    pub header_fields: [Option<DbusHeaderField>; MAX_HEADER_FIELDS],
    /// Number of header fields.
    pub header_field_count: usize,
    /// Sender unique name (set by the bus).
    pub sender: Option<BusName>,
    /// Destination name (unique or well-known).
    pub destination: Option<BusName>,
    /// Sender credentials (set by the bus).
    pub credentials: Option<DbusCredentials>,
    /// Message body.
    pub body: Vec<u8>,
}

impl DbusMessage {
    /// Create a new message.
    pub fn new(msg_type: u8, serial: u32) -> Result<Self> {
        if msg_type == 0 || msg_type > DBUS_MSG_SIGNAL {
            return Err(Error::InvalidArgument);
        }
        Ok(Self {
            msg_type,
            flags: 0,
            serial,
            header_fields: [const { None }; MAX_HEADER_FIELDS],
            header_field_count: 0,
            sender: None,
            destination: None,
            credentials: None,
            body: Vec::new(),
        })
    }

    /// Add a header field.
    pub fn add_header_field(&mut self, code: u8, value: u64) -> Result<()> {
        if self.header_field_count >= MAX_HEADER_FIELDS {
            return Err(Error::InvalidArgument);
        }
        self.header_fields[self.header_field_count] = Some(DbusHeaderField { code, value });
        self.header_field_count += 1;
        Ok(())
    }

    /// Set the message body.
    pub fn set_body(&mut self, data: &[u8]) -> Result<()> {
        if data.len() > MAX_MSG_BODY_SIZE {
            return Err(Error::InvalidArgument);
        }
        self.body.clear();
        self.body.extend_from_slice(data);
        Ok(())
    }

    /// Return the body as a slice.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Return `true` if this is a signal message.
    pub const fn is_signal(&self) -> bool {
        self.msg_type == DBUS_MSG_SIGNAL
    }

    /// Return `true` if no reply is expected.
    pub const fn no_reply_expected(&self) -> bool {
        self.flags & DBUS_FLAG_NO_REPLY_EXPECTED != 0
    }
}

// ---------------------------------------------------------------------------
// MatchRule — signal subscription
// ---------------------------------------------------------------------------

/// A match rule for signal delivery.
///
/// Signals are delivered to connections whose match rules match
/// the signal's type, interface, and member.
#[derive(Debug, Clone, Copy)]
pub struct MatchRule {
    /// Match on message type (0 = any).
    pub msg_type: u8,
    /// Match on interface name hash (0 = any).
    pub interface_hash: u64,
    /// Match on member name hash (0 = any).
    pub member_hash: u64,
    /// Match on sender name hash (0 = any).
    pub sender_hash: u64,
    /// Whether this rule is active.
    pub active: bool,
}

impl MatchRule {
    /// Create a match-all rule.
    pub const fn match_all() -> Self {
        Self {
            msg_type: 0,
            interface_hash: 0,
            member_hash: 0,
            sender_hash: 0,
            active: true,
        }
    }

    /// Create a rule matching signals only.
    pub const fn signals_only() -> Self {
        Self {
            msg_type: DBUS_MSG_SIGNAL,
            interface_hash: 0,
            member_hash: 0,
            sender_hash: 0,
            active: true,
        }
    }

    /// Check if a message matches this rule.
    pub fn matches(&self, msg_type: u8, iface_hash: u64, member_hash: u64) -> bool {
        if !self.active {
            return false;
        }
        if self.msg_type != 0 && self.msg_type != msg_type {
            return false;
        }
        if self.interface_hash != 0 && self.interface_hash != iface_hash {
            return false;
        }
        if self.member_hash != 0 && self.member_hash != member_hash {
            return false;
        }
        true
    }
}

// ---------------------------------------------------------------------------
// DbusConnection — a connected client
// ---------------------------------------------------------------------------

/// A D-Bus connection to the bus.
pub struct DbusConnection {
    /// Unique name (e.g., ":1.1").
    pub unique_name: BusName,
    /// Connection credentials.
    pub credentials: DbusCredentials,
    /// Whether the connection is active.
    pub active: bool,
    /// Next serial number.
    next_serial: u32,
    /// Match rules for signal subscription.
    match_rules: [Option<MatchRule>; MAX_MATCH_RULES_PER_CONN],
    /// Number of match rules.
    match_rule_count: usize,
    /// Incoming message queue.
    msg_queue: Vec<Vec<u8>>,
    /// Number of queued messages.
    msg_count: usize,
}

impl DbusConnection {
    /// Create a new connection.
    pub fn new(unique_name: BusName, credentials: DbusCredentials) -> Self {
        Self {
            unique_name,
            credentials,
            active: true,
            next_serial: 1,
            match_rules: [const { None }; MAX_MATCH_RULES_PER_CONN],
            match_rule_count: 0,
            msg_queue: Vec::new(),
            msg_count: 0,
        }
    }

    /// Allocate the next serial number.
    pub fn alloc_serial(&mut self) -> u32 {
        let s = self.next_serial;
        self.next_serial = self.next_serial.wrapping_add(1);
        if self.next_serial == 0 {
            self.next_serial = 1;
        }
        s
    }

    /// Add a match rule.
    pub fn add_match_rule(&mut self, rule: MatchRule) -> Result<()> {
        if self.match_rule_count >= MAX_MATCH_RULES_PER_CONN {
            return Err(Error::OutOfMemory);
        }
        self.match_rules[self.match_rule_count] = Some(rule);
        self.match_rule_count += 1;
        Ok(())
    }

    /// Remove a match rule by index.
    pub fn remove_match_rule(&mut self, index: usize) -> Result<()> {
        if index >= self.match_rule_count {
            return Err(Error::InvalidArgument);
        }
        self.match_rules[index] = None;
        // Compact.
        let mut dst = index;
        for src in (index + 1)..self.match_rule_count {
            self.match_rules[dst] = self.match_rules[src].take();
            dst += 1;
        }
        self.match_rule_count -= 1;
        Ok(())
    }

    /// Check if any match rule matches the given signal.
    pub fn matches_signal(&self, msg_type: u8, iface_hash: u64, member_hash: u64) -> bool {
        for rule in &self.match_rules[..self.match_rule_count] {
            if let Some(r) = rule {
                if r.matches(msg_type, iface_hash, member_hash) {
                    return true;
                }
            }
        }
        false
    }

    /// Enqueue a message (as serialized bytes).
    pub fn enqueue_msg(&mut self, data: &[u8]) -> Result<()> {
        if self.msg_count >= MAX_QUEUED_MSGS {
            return Err(Error::WouldBlock);
        }
        let mut buf = Vec::new();
        buf.extend_from_slice(data);
        self.msg_queue.push(buf);
        self.msg_count += 1;
        Ok(())
    }

    /// Dequeue a message.
    pub fn dequeue_msg(&mut self) -> Result<Vec<u8>> {
        if self.msg_queue.is_empty() {
            return Err(Error::WouldBlock);
        }
        self.msg_count = self.msg_count.saturating_sub(1);
        Ok(self.msg_queue.remove(0))
    }

    /// Return the number of queued messages.
    pub const fn msg_count(&self) -> usize {
        self.msg_count
    }

    /// Return the number of match rules.
    pub const fn match_rule_count(&self) -> usize {
        self.match_rule_count
    }
}

// ---------------------------------------------------------------------------
// WellKnownName — name ownership record
// ---------------------------------------------------------------------------

/// A well-known name ownership record.
#[derive(Debug, Clone, Copy)]
pub struct WellKnownName {
    /// The well-known name.
    pub name: BusName,
    /// Index of the owning connection.
    pub owner_index: usize,
    /// Whether this record is active.
    pub active: bool,
}

// ---------------------------------------------------------------------------
// DbusBus — the message bus
// ---------------------------------------------------------------------------

/// The D-Bus kernel message bus.
///
/// Manages connections, well-known name ownership, message routing,
/// and signal broadcast with match rules.
pub struct DbusBus {
    /// Connected clients.
    connections: [Option<DbusConnection>; MAX_CONNECTIONS],
    /// Number of connections.
    conn_count: usize,
    /// Next unique name counter.
    next_unique_id: u32,
    /// Well-known name table.
    names: [Option<WellKnownName>; MAX_WELL_KNOWN_NAMES],
    /// Number of well-known names.
    name_count: usize,
}

impl DbusBus {
    /// Create a new empty bus.
    pub fn new() -> Self {
        Self {
            connections: [const { None }; MAX_CONNECTIONS],
            conn_count: 0,
            next_unique_id: 1,
            names: [const { None }; MAX_WELL_KNOWN_NAMES],
            name_count: 0,
        }
    }

    /// Generate a unique name (":1.N").
    fn generate_unique_name(&mut self) -> Result<BusName> {
        let id = self.next_unique_id;
        self.next_unique_id += 1;
        // Format ":1.{id}" manually (no_std).
        let mut buf = [0u8; 32];
        buf[0] = b':';
        buf[1] = b'1';
        buf[2] = b'.';
        let mut n = id;
        let mut digits = [0u8; 10];
        let mut dlen = 0;
        if n == 0 {
            digits[0] = b'0';
            dlen = 1;
        } else {
            while n > 0 {
                digits[dlen] = b'0' + (n % 10) as u8;
                dlen += 1;
                n /= 10;
            }
            // Reverse.
            let half = dlen / 2;
            for i in 0..half {
                digits.swap(i, dlen - 1 - i);
            }
        }
        let name_len = 3 + dlen;
        if name_len > MAX_NAME_LEN {
            return Err(Error::OutOfMemory);
        }
        buf[3..3 + dlen].copy_from_slice(&digits[..dlen]);
        BusName::from_bytes(&buf[..name_len])
    }

    /// Connect a new client to the bus.
    pub fn connect(&mut self, credentials: DbusCredentials) -> Result<usize> {
        let unique_name = self.generate_unique_name()?;
        for (i, slot) in self.connections.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(DbusConnection::new(unique_name, credentials));
                self.conn_count += 1;
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Disconnect a client.
    pub fn disconnect(&mut self, index: usize) -> Result<()> {
        if index >= MAX_CONNECTIONS {
            return Err(Error::InvalidArgument);
        }
        if self.connections[index].is_none() {
            return Err(Error::NotFound);
        }
        // Release all well-known names owned by this connection.
        for slot in &mut self.names {
            if let Some(wkn) = slot {
                if wkn.owner_index == index && wkn.active {
                    wkn.active = false;
                    self.name_count = self.name_count.saturating_sub(1);
                }
            }
        }
        self.connections[index] = None;
        self.conn_count = self.conn_count.saturating_sub(1);
        Ok(())
    }

    /// Request a well-known name for a connection.
    pub fn request_name(&mut self, conn_index: usize, name: &BusName) -> Result<()> {
        if conn_index >= MAX_CONNECTIONS {
            return Err(Error::InvalidArgument);
        }
        if self.connections[conn_index].is_none() {
            return Err(Error::NotFound);
        }

        // Check if name is already taken.
        for slot in &self.names {
            if let Some(wkn) = slot {
                if wkn.active && wkn.name == *name {
                    return Err(Error::AlreadyExists);
                }
            }
        }

        // Find free slot.
        for slot in &mut self.names {
            if slot.is_none() || matches!(slot, Some(wkn) if !wkn.active) {
                *slot = Some(WellKnownName {
                    name: *name,
                    owner_index: conn_index,
                    active: true,
                });
                self.name_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Release a well-known name.
    pub fn release_name(&mut self, conn_index: usize, name: &BusName) -> Result<()> {
        for slot in &mut self.names {
            if let Some(wkn) = slot {
                if wkn.active && wkn.name == *name {
                    if wkn.owner_index != conn_index {
                        return Err(Error::PermissionDenied);
                    }
                    wkn.active = false;
                    self.name_count = self.name_count.saturating_sub(1);
                    return Ok(());
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Resolve a well-known name to a connection index.
    pub fn resolve_name(&self, name: &BusName) -> Result<usize> {
        for slot in &self.names {
            if let Some(wkn) = slot {
                if wkn.active && wkn.name == *name {
                    return Ok(wkn.owner_index);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Find a connection by its unique name.
    fn find_conn_by_unique_name(&self, name: &BusName) -> Result<usize> {
        for (i, slot) in self.connections.iter().enumerate() {
            if let Some(conn) = slot {
                if conn.active && conn.unique_name == *name {
                    return Ok(i);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Send a unicast message to a specific destination.
    pub fn send_unicast(
        &mut self,
        sender_index: usize,
        dest_name: &BusName,
        data: &[u8],
    ) -> Result<()> {
        if sender_index >= MAX_CONNECTIONS {
            return Err(Error::InvalidArgument);
        }
        if self.connections[sender_index].is_none() {
            return Err(Error::NotFound);
        }

        // Resolve destination: try well-known name first, then unique name.
        let dest_index = self
            .resolve_name(dest_name)
            .or_else(|_| self.find_conn_by_unique_name(dest_name))?;

        // Enqueue at destination.
        match &mut self.connections[dest_index] {
            Some(conn) if conn.active => conn.enqueue_msg(data),
            _ => Err(Error::NotFound),
        }
    }

    /// Broadcast a signal to all connections with matching rules.
    ///
    /// `iface_hash` and `member_hash` are used for match rule filtering.
    pub fn broadcast_signal(
        &mut self,
        sender_index: usize,
        data: &[u8],
        iface_hash: u64,
        member_hash: u64,
    ) -> Result<usize> {
        if sender_index >= MAX_CONNECTIONS {
            return Err(Error::InvalidArgument);
        }
        if self.connections[sender_index].is_none() {
            return Err(Error::NotFound);
        }

        // Collect matching connection indices first to avoid
        // borrow issues with self.connections.
        let mut matching = [false; MAX_CONNECTIONS];
        for (i, slot) in self.connections.iter().enumerate() {
            if i == sender_index {
                continue;
            }
            if let Some(conn) = slot {
                if conn.active && conn.matches_signal(DBUS_MSG_SIGNAL, iface_hash, member_hash) {
                    matching[i] = true;
                }
            }
        }

        let mut delivered = 0usize;
        for (i, should_deliver) in matching.iter().enumerate() {
            if *should_deliver {
                if let Some(ref mut conn) = self.connections[i] {
                    // Best effort delivery — skip full queues.
                    if conn.enqueue_msg(data).is_ok() {
                        delivered += 1;
                    }
                }
            }
        }
        Ok(delivered)
    }

    /// Receive a message from a connection's queue.
    pub fn recv(&mut self, conn_index: usize) -> Result<Vec<u8>> {
        if conn_index >= MAX_CONNECTIONS {
            return Err(Error::InvalidArgument);
        }
        match &mut self.connections[conn_index] {
            Some(conn) if conn.active => conn.dequeue_msg(),
            _ => Err(Error::NotFound),
        }
    }

    /// Add a match rule to a connection.
    pub fn add_match_rule(&mut self, conn_index: usize, rule: MatchRule) -> Result<()> {
        if conn_index >= MAX_CONNECTIONS {
            return Err(Error::InvalidArgument);
        }
        match &mut self.connections[conn_index] {
            Some(conn) if conn.active => conn.add_match_rule(rule),
            _ => Err(Error::NotFound),
        }
    }

    /// Get the credentials for a connection.
    pub fn get_credentials(&self, conn_index: usize) -> Result<DbusCredentials> {
        if conn_index >= MAX_CONNECTIONS {
            return Err(Error::InvalidArgument);
        }
        match &self.connections[conn_index] {
            Some(conn) if conn.active => Ok(conn.credentials),
            _ => Err(Error::NotFound),
        }
    }

    /// Get the unique name for a connection.
    pub fn get_unique_name(&self, conn_index: usize) -> Result<&BusName> {
        if conn_index >= MAX_CONNECTIONS {
            return Err(Error::InvalidArgument);
        }
        match &self.connections[conn_index] {
            Some(conn) if conn.active => Ok(&conn.unique_name),
            _ => Err(Error::NotFound),
        }
    }

    /// Return the number of connections.
    pub const fn connection_count(&self) -> usize {
        self.conn_count
    }

    /// Return the number of well-known names.
    pub const fn name_count(&self) -> usize {
        self.name_count
    }
}

impl Default for DbusBus {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn creds(pid: u32) -> DbusCredentials {
        DbusCredentials::new(pid, 1000, 1000)
    }

    fn wk_name(s: &[u8]) -> BusName {
        BusName::from_bytes(s).unwrap()
    }

    #[test]
    fn test_bus_connect() {
        let mut bus = DbusBus::new();
        let idx = bus.connect(creds(100)).unwrap();
        assert_eq!(bus.connection_count(), 1);
        let name = bus.get_unique_name(idx).unwrap();
        assert_eq!(name.as_bytes(), b":1.1");
    }

    #[test]
    fn test_bus_connect_multiple() {
        let mut bus = DbusBus::new();
        let i1 = bus.connect(creds(100)).unwrap();
        let i2 = bus.connect(creds(200)).unwrap();
        assert_ne!(i1, i2);
        let n1 = bus.get_unique_name(i1).unwrap();
        let n2 = bus.get_unique_name(i2).unwrap();
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_bus_disconnect() {
        let mut bus = DbusBus::new();
        let idx = bus.connect(creds(100)).unwrap();
        assert!(bus.disconnect(idx).is_ok());
        assert_eq!(bus.connection_count(), 0);
    }

    #[test]
    fn test_bus_disconnect_releases_names() {
        let mut bus = DbusBus::new();
        let idx = bus.connect(creds(100)).unwrap();
        let name = wk_name(b"org.test.Service");
        bus.request_name(idx, &name).unwrap();
        bus.disconnect(idx).unwrap();
        assert_eq!(bus.name_count(), 0);
    }

    #[test]
    fn test_request_release_name() {
        let mut bus = DbusBus::new();
        let idx = bus.connect(creds(100)).unwrap();
        let name = wk_name(b"org.test.Service");
        assert!(bus.request_name(idx, &name).is_ok());
        assert_eq!(bus.name_count(), 1);
        assert!(bus.release_name(idx, &name).is_ok());
        assert_eq!(bus.name_count(), 0);
    }

    #[test]
    fn test_request_name_duplicate() {
        let mut bus = DbusBus::new();
        let i1 = bus.connect(creds(100)).unwrap();
        let i2 = bus.connect(creds(200)).unwrap();
        let name = wk_name(b"org.test.Service");
        bus.request_name(i1, &name).unwrap();
        assert_eq!(
            bus.request_name(i2, &name).unwrap_err(),
            Error::AlreadyExists
        );
    }

    #[test]
    fn test_release_name_not_owner() {
        let mut bus = DbusBus::new();
        let i1 = bus.connect(creds(100)).unwrap();
        let i2 = bus.connect(creds(200)).unwrap();
        let name = wk_name(b"org.test.Service");
        bus.request_name(i1, &name).unwrap();
        assert_eq!(
            bus.release_name(i2, &name).unwrap_err(),
            Error::PermissionDenied
        );
    }

    #[test]
    fn test_resolve_name() {
        let mut bus = DbusBus::new();
        let idx = bus.connect(creds(100)).unwrap();
        let name = wk_name(b"org.test.Service");
        bus.request_name(idx, &name).unwrap();
        assert_eq!(bus.resolve_name(&name).unwrap(), idx);
    }

    #[test]
    fn test_send_unicast_by_unique_name() {
        let mut bus = DbusBus::new();
        let i1 = bus.connect(creds(100)).unwrap();
        let i2 = bus.connect(creds(200)).unwrap();
        let dest_name = *bus.get_unique_name(i2).unwrap();
        assert!(bus.send_unicast(i1, &dest_name, b"hello").is_ok());
        let msg = bus.recv(i2).unwrap();
        assert_eq!(&msg, b"hello");
    }

    #[test]
    fn test_send_unicast_by_well_known_name() {
        let mut bus = DbusBus::new();
        let i1 = bus.connect(creds(100)).unwrap();
        let i2 = bus.connect(creds(200)).unwrap();
        let name = wk_name(b"org.test.Service");
        bus.request_name(i2, &name).unwrap();
        assert!(bus.send_unicast(i1, &name, b"method_call").is_ok());
        let msg = bus.recv(i2).unwrap();
        assert_eq!(&msg, b"method_call");
    }

    #[test]
    fn test_recv_empty() {
        let mut bus = DbusBus::new();
        let idx = bus.connect(creds(100)).unwrap();
        assert_eq!(bus.recv(idx).unwrap_err(), Error::WouldBlock);
    }

    #[test]
    fn test_broadcast_signal() {
        let mut bus = DbusBus::new();
        let sender = bus.connect(creds(100)).unwrap();
        let r1 = bus.connect(creds(200)).unwrap();
        let r2 = bus.connect(creds(300)).unwrap();

        // Add match rules.
        bus.add_match_rule(r1, MatchRule::signals_only()).unwrap();
        bus.add_match_rule(r2, MatchRule::match_all()).unwrap();

        let delivered = bus.broadcast_signal(sender, b"signal_data", 0, 0).unwrap();
        assert_eq!(delivered, 2);
        assert!(bus.recv(r1).is_ok());
        assert!(bus.recv(r2).is_ok());
    }

    #[test]
    fn test_broadcast_no_match() {
        let mut bus = DbusBus::new();
        let sender = bus.connect(creds(100)).unwrap();
        let _r1 = bus.connect(creds(200)).unwrap();
        // r1 has no match rules.
        let delivered = bus.broadcast_signal(sender, b"signal", 0, 0).unwrap();
        assert_eq!(delivered, 0);
    }

    #[test]
    fn test_match_rule_filtering() {
        let rule = MatchRule {
            msg_type: DBUS_MSG_SIGNAL,
            interface_hash: 42,
            member_hash: 0,
            sender_hash: 0,
            active: true,
        };
        assert!(rule.matches(DBUS_MSG_SIGNAL, 42, 99));
        assert!(!rule.matches(DBUS_MSG_METHOD_CALL, 42, 99));
        assert!(!rule.matches(DBUS_MSG_SIGNAL, 43, 99));
    }

    #[test]
    fn test_credentials() {
        let mut bus = DbusBus::new();
        let idx = bus.connect(creds(42)).unwrap();
        let c = bus.get_credentials(idx).unwrap();
        assert_eq!(c.pid, 42);
        assert_eq!(c.uid, 1000);
    }

    #[test]
    fn test_message_create() {
        let msg = DbusMessage::new(DBUS_MSG_METHOD_CALL, 1);
        assert!(msg.is_ok());
    }

    #[test]
    fn test_message_bad_type() {
        assert_eq!(DbusMessage::new(0, 1).unwrap_err(), Error::InvalidArgument);
        assert_eq!(DbusMessage::new(5, 1).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn test_message_body() {
        let mut msg = DbusMessage::new(DBUS_MSG_SIGNAL, 1).unwrap();
        msg.set_body(b"test data").unwrap();
        assert_eq!(msg.body(), b"test data");
    }

    #[test]
    fn test_message_header_fields() {
        let mut msg = DbusMessage::new(DBUS_MSG_METHOD_CALL, 1).unwrap();
        msg.add_header_field(DBUS_HDR_DESTINATION, 1).unwrap();
        msg.add_header_field(DBUS_HDR_INTERFACE, 2).unwrap();
        assert_eq!(msg.header_field_count, 2);
    }

    #[test]
    fn test_bus_name() {
        let name = BusName::from_bytes(b"org.test").unwrap();
        assert_eq!(name.as_bytes(), b"org.test");
        assert_eq!(name.len(), 8);
        assert!(!name.is_empty());
    }

    #[test]
    fn test_bus_name_empty() {
        assert_eq!(
            BusName::from_bytes(b"").unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn test_connection_serial() {
        let name = BusName::from_bytes(b":1.1").unwrap();
        let mut conn = DbusConnection::new(name, creds(1));
        assert_eq!(conn.alloc_serial(), 1);
        assert_eq!(conn.alloc_serial(), 2);
    }

    #[test]
    fn test_connection_match_rules() {
        let name = BusName::from_bytes(b":1.1").unwrap();
        let mut conn = DbusConnection::new(name, creds(1));
        conn.add_match_rule(MatchRule::signals_only()).unwrap();
        assert_eq!(conn.match_rule_count(), 1);
        assert!(conn.matches_signal(DBUS_MSG_SIGNAL, 0, 0));
        assert!(!conn.matches_signal(DBUS_MSG_METHOD_CALL, 0, 0));
    }

    #[test]
    fn test_disconnect_nonexistent() {
        let mut bus = DbusBus::new();
        assert_eq!(bus.disconnect(0).unwrap_err(), Error::NotFound);
    }
}
