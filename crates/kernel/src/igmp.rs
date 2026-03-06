// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IGMP multicast group management for the ONCRIX network stack.
//!
//! Implements IGMPv2 (RFC 2236) and IGMPv3 (RFC 3376) message
//! parsing, multicast group membership tracking, and query/report
//! processing for the kernel's IPv4 multicast subsystem.
//!
//! # Architecture
//!
//! ```text
//! incoming IGMP → IgmpRegistry → per-interface IgmpState
//!                                  └── MulticastGroup table
//! ```
//!
//! Key components:
//!
//! - [`IgmpType`]: IGMP message type discriminant.
//! - [`IgmpHeader`]: on-wire IGMP message header (8 bytes).
//! - [`FilterMode`]: IGMPv3 include/exclude source filter mode.
//! - [`MulticastGroup`]: per-group membership state with report
//!   timer and member count.
//! - [`IgmpState`]: per-interface IGMP state managing up to
//!   [`MAX_GROUPS_PER_IF`] multicast groups.
//! - [`IgmpRegistry`]: system-wide registry across up to
//!   [`MAX_IGMP_INTERFACES`] interfaces.
//!
//! All multi-byte fields use network byte order (big-endian) via
//! [`u16::from_be_bytes`] / [`u32::from_be_bytes`].
//!
//! Reference: RFC 2236 (IGMPv2), RFC 3376 (IGMPv3).

use oncrix_lib::{Error, Result};

// =========================================================================
// Constants
// =========================================================================

/// Maximum number of interfaces with IGMP support.
const MAX_IGMP_INTERFACES: usize = 16;

/// Maximum number of multicast groups per interface.
const MAX_GROUPS_PER_IF: usize = 8;

/// IGMP header size in bytes (type + max_resp + checksum + group).
const IGMP_HEADER_LEN: usize = 8;

/// IP protocol number for IGMP.
pub const PROTO_IGMP: u8 = 2;

/// Default robustness variable (RFC 2236 section 8.1).
const DEFAULT_ROBUSTNESS: u32 = 2;

/// Default query interval in ticks (RFC 2236 section 8.2).
const DEFAULT_QUERY_INTERVAL: u32 = 125;

// =========================================================================
// IgmpType
// =========================================================================

/// IGMP message type discriminant.
///
/// Values correspond to the on-wire IGMP type field as defined in
/// RFC 2236 (IGMPv2) and RFC 3376 (IGMPv3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IgmpType {
    /// Membership Query (general or group-specific).
    MembershipQuery,
    /// IGMPv2 Membership Report.
    V2MembershipReport,
    /// IGMPv2 Leave Group message.
    LeaveGroup,
    /// IGMPv3 Membership Report.
    V3MembershipReport,
}

impl IgmpType {
    /// Decode an IGMP type from its on-wire byte value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidArgument`] for unrecognised values.
    pub const fn from_wire(value: u8) -> Result<Self> {
        match value {
            0x11 => Ok(Self::MembershipQuery),
            0x16 => Ok(Self::V2MembershipReport),
            0x17 => Ok(Self::LeaveGroup),
            0x22 => Ok(Self::V3MembershipReport),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Encode this IGMP type as its on-wire byte value.
    pub const fn to_wire(self) -> u8 {
        match self {
            Self::MembershipQuery => 0x11,
            Self::V2MembershipReport => 0x16,
            Self::LeaveGroup => 0x17,
            Self::V3MembershipReport => 0x22,
        }
    }
}

// =========================================================================
// IgmpHeader
// =========================================================================

/// On-wire IGMP message header (8 bytes).
///
/// Layout per RFC 2236 section 2:
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Type     | Max Resp Time |           Checksum            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Group Address                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct IgmpHeader {
    /// IGMP message type.
    pub igmp_type: u8,
    /// Maximum response time (in 1/10 second units for IGMPv2).
    pub max_resp_time: u8,
    /// Checksum over the entire IGMP message.
    pub checksum: u16,
    /// Multicast group address (network byte order).
    pub group_address: u32,
}

/// Parse an IGMP header from raw bytes.
///
/// Returns the parsed [`IgmpHeader`] and a slice referencing any
/// remaining payload after the 8-byte header.
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `data` is shorter than
/// [`IGMP_HEADER_LEN`] (8 bytes) or the checksum is invalid.
pub fn parse_igmp(data: &[u8]) -> Result<(IgmpHeader, &[u8])> {
    if data.len() < IGMP_HEADER_LEN {
        return Err(Error::InvalidArgument);
    }

    // Verify checksum over the entire message.
    if internet_checksum(data) != 0 {
        return Err(Error::InvalidArgument);
    }

    let header = IgmpHeader {
        igmp_type: data[0],
        max_resp_time: data[1],
        checksum: u16::from_be_bytes([data[2], data[3]]),
        group_address: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
    };

    Ok((header, &data[IGMP_HEADER_LEN..]))
}

/// Serialise an IGMP header into `buf`.
///
/// The checksum field in `header` is ignored; a fresh checksum is
/// computed over the serialised bytes and written into the output.
///
/// Returns the number of bytes written ([`IGMP_HEADER_LEN`]).
///
/// # Errors
///
/// Returns [`Error::InvalidArgument`] if `buf` is too small.
pub fn write_igmp(buf: &mut [u8], header: &IgmpHeader) -> Result<usize> {
    if buf.len() < IGMP_HEADER_LEN {
        return Err(Error::InvalidArgument);
    }

    buf[0] = header.igmp_type;
    buf[1] = header.max_resp_time;
    // Zero checksum field for computation.
    buf[2] = 0;
    buf[3] = 0;
    let group_bytes = header.group_address.to_be_bytes();
    buf[4] = group_bytes[0];
    buf[5] = group_bytes[1];
    buf[6] = group_bytes[2];
    buf[7] = group_bytes[3];

    // Compute and insert checksum.
    let cksum = internet_checksum(&buf[..IGMP_HEADER_LEN]);
    let cksum_bytes = cksum.to_be_bytes();
    buf[2] = cksum_bytes[0];
    buf[3] = cksum_bytes[1];

    Ok(IGMP_HEADER_LEN)
}

/// Compute the Internet checksum (RFC 1071) over `data`.
///
/// Returns the one's-complement checksum as a `u16` in host byte
/// order.  When verifying a received message the result should be 0.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    // Handle odd trailing byte.
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    // Fold 32-bit sum into 16 bits.
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// =========================================================================
// FilterMode
// =========================================================================

/// IGMPv3 source filter mode.
///
/// Determines whether the multicast group membership includes or
/// excludes specific source addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FilterMode {
    /// Include mode — receive traffic only from listed sources.
    #[default]
    Include,
    /// Exclude mode — receive traffic from all sources except
    /// those listed.
    Exclude,
}

// =========================================================================
// MulticastGroup
// =========================================================================

/// Per-group multicast membership state.
///
/// Tracks the group address, number of local members, a report
/// timer (in ticks remaining), and the IGMPv3 filter mode.
#[derive(Debug, Clone, Copy)]
pub struct MulticastGroup {
    /// Multicast group address (network byte order).
    pub group_addr: u32,
    /// Number of local members that have joined this group.
    pub member_count: u32,
    /// Ticks remaining until the next unsolicited report is due.
    /// Zero means no pending report.
    pub report_timer: u32,
    /// Source filter mode (IGMPv3).
    pub filter_mode: FilterMode,
    /// Whether this group slot is active.
    active: bool,
}

impl Default for MulticastGroup {
    fn default() -> Self {
        Self {
            group_addr: 0,
            member_count: 0,
            report_timer: 0,
            filter_mode: FilterMode::Include,
            active: false,
        }
    }
}

// =========================================================================
// IgmpState
// =========================================================================

/// Per-interface IGMP state.
///
/// Manages multicast group memberships for a single network
/// interface, handling membership queries, report generation,
/// group join/leave operations, and timer expiry.
pub struct IgmpState {
    /// Multicast group table for this interface.
    groups: [MulticastGroup; MAX_GROUPS_PER_IF],
    /// Robustness variable (RFC 2236 section 8.1).
    pub robustness_variable: u32,
    /// Query interval in ticks (RFC 2236 section 8.2).
    pub query_interval: u32,
    /// Whether this interface slot is active.
    active: bool,
}

impl Default for IgmpState {
    fn default() -> Self {
        Self::new()
    }
}

impl IgmpState {
    /// Create a new per-interface IGMP state with default
    /// parameters.
    pub fn new() -> Self {
        Self {
            groups: [MulticastGroup::default(); MAX_GROUPS_PER_IF],
            robustness_variable: DEFAULT_ROBUSTNESS,
            query_interval: DEFAULT_QUERY_INTERVAL,
            active: false,
        }
    }

    /// Process an incoming IGMP Membership Query.
    ///
    /// A General Query (`group_address == 0`) resets the report
    /// timer for all active groups.  A Group-Specific Query resets
    /// only the timer for the targeted group.
    ///
    /// `max_resp_time` is in 1/10-second units; the report timer is
    /// set to a simplified value derived from it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if a group-specific query targets
    /// a group that this interface has not joined.
    pub fn process_query(&mut self, group_address: u32, max_resp_time: u8) -> Result<()> {
        let timer_value = if max_resp_time == 0 {
            self.query_interval
        } else {
            max_resp_time as u32
        };

        if group_address == 0 {
            // General Query — reset timers for all active groups.
            for group in &mut self.groups {
                if group.active {
                    group.report_timer = timer_value;
                }
            }
            Ok(())
        } else {
            // Group-Specific Query.
            let group = self
                .groups
                .iter_mut()
                .find(|g| g.active && g.group_addr == group_address)
                .ok_or(Error::NotFound)?;
            group.report_timer = timer_value;
            Ok(())
        }
    }

    /// Build an IGMPv2 Membership Report for a group.
    ///
    /// Writes the serialised IGMP report into `buf` and returns the
    /// number of bytes written.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if `group_address` is not an active
    ///   group on this interface.
    /// - [`Error::InvalidArgument`] if `buf` is too small.
    pub fn send_report(&self, group_address: u32, buf: &mut [u8]) -> Result<usize> {
        let _group = self
            .groups
            .iter()
            .find(|g| g.active && g.group_addr == group_address)
            .ok_or(Error::NotFound)?;

        let header = IgmpHeader {
            igmp_type: IgmpType::V2MembershipReport.to_wire(),
            max_resp_time: 0,
            checksum: 0,
            group_address,
        };
        write_igmp(buf, &header)
    }

    /// Join a multicast group on this interface.
    ///
    /// If the group is already joined, increments the member count.
    /// Otherwise allocates a new group slot and sets an initial
    /// report timer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if all group slots are
    /// occupied.
    pub fn join_group(&mut self, group_address: u32) -> Result<()> {
        // Check if already joined — just increment member count.
        if let Some(group) = self
            .groups
            .iter_mut()
            .find(|g| g.active && g.group_addr == group_address)
        {
            group.member_count = group.member_count.saturating_add(1);
            return Ok(());
        }

        // Allocate a new slot.
        let slot = self
            .groups
            .iter_mut()
            .find(|g| !g.active)
            .ok_or(Error::OutOfMemory)?;

        slot.group_addr = group_address;
        slot.member_count = 1;
        slot.report_timer = self.robustness_variable;
        slot.filter_mode = FilterMode::Exclude;
        slot.active = true;

        Ok(())
    }

    /// Leave a multicast group on this interface.
    ///
    /// Decrements the member count.  When the count reaches zero the
    /// group slot is deactivated.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NotFound`] if the group is not currently
    /// joined.
    pub fn leave_group(&mut self, group_address: u32) -> Result<()> {
        let group = self
            .groups
            .iter_mut()
            .find(|g| g.active && g.group_addr == group_address)
            .ok_or(Error::NotFound)?;

        group.member_count = group.member_count.saturating_sub(1);
        if group.member_count == 0 {
            group.active = false;
        }

        Ok(())
    }

    /// Advance report timers by one tick.
    ///
    /// Returns the number of groups whose report timers expired
    /// (reached zero) during this tick.  The caller should send
    /// reports for those groups.
    pub fn tick(&mut self) -> u32 {
        let mut expired = 0u32;
        for group in &mut self.groups {
            if group.active && group.report_timer > 0 {
                group.report_timer -= 1;
                if group.report_timer == 0 {
                    expired += 1;
                }
            }
        }
        expired
    }

    /// Return the number of active multicast groups.
    pub fn group_count(&self) -> usize {
        self.groups.iter().filter(|g| g.active).count()
    }
}

// =========================================================================
// IgmpRegistry
// =========================================================================

/// System-wide IGMP multicast registry.
///
/// Manages per-interface IGMP state across up to
/// [`MAX_IGMP_INTERFACES`] network interfaces.
pub struct IgmpRegistry {
    /// Per-interface IGMP state.
    interfaces: [IgmpState; MAX_IGMP_INTERFACES],
}

impl Default for IgmpRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl IgmpRegistry {
    /// Create an empty IGMP registry.
    pub fn new() -> Self {
        Self {
            interfaces: core::array::from_fn(|_| IgmpState::new()),
        }
    }

    /// Register an interface for IGMP multicast management.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `ifindex` is out of range.
    /// - [`Error::AlreadyExists`] if the interface is already
    ///   registered.
    pub fn register(&mut self, ifindex: usize) -> Result<()> {
        let iface = self
            .interfaces
            .get_mut(ifindex)
            .ok_or(Error::InvalidArgument)?;
        if iface.active {
            return Err(Error::AlreadyExists);
        }
        iface.active = true;
        Ok(())
    }

    /// Unregister an interface, clearing all its multicast groups.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `ifindex` is out of range.
    /// - [`Error::NotFound`] if the interface is not registered.
    pub fn unregister(&mut self, ifindex: usize) -> Result<()> {
        let iface = self
            .interfaces
            .get_mut(ifindex)
            .ok_or(Error::InvalidArgument)?;
        if !iface.active {
            return Err(Error::NotFound);
        }
        *iface = IgmpState::new();
        Ok(())
    }

    /// Process an incoming IGMP message on an interface.
    ///
    /// Dispatches to the appropriate handler based on the message
    /// type:
    ///
    /// - **MembershipQuery**: updates report timers.
    /// - **V2MembershipReport**: no-op (we are the host, not a
    ///   querier).
    /// - **LeaveGroup**: no-op for host-side processing.
    /// - **V3MembershipReport**: no-op (future extension).
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `ifindex` is out of range,
    ///   the interface is not registered, or the message cannot be
    ///   parsed.
    pub fn process_igmp(&mut self, ifindex: usize, data: &[u8]) -> Result<()> {
        let iface = self
            .interfaces
            .get_mut(ifindex)
            .ok_or(Error::InvalidArgument)?;
        if !iface.active {
            return Err(Error::InvalidArgument);
        }

        let (header, _payload) = parse_igmp(data)?;
        let msg_type = IgmpType::from_wire(header.igmp_type)?;

        match msg_type {
            IgmpType::MembershipQuery => {
                iface.process_query(header.group_address, header.max_resp_time)
            }
            IgmpType::V2MembershipReport | IgmpType::LeaveGroup | IgmpType::V3MembershipReport => {
                // Host-side: reports and leaves from other hosts are
                // informational — no action required.
                Ok(())
            }
        }
    }

    /// Join a multicast group on an interface.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `ifindex` is out of range or
    ///   the interface is not registered.
    /// - [`Error::OutOfMemory`] if the group table is full.
    pub fn join(&mut self, ifindex: usize, group_address: u32) -> Result<()> {
        let iface = self
            .interfaces
            .get_mut(ifindex)
            .ok_or(Error::InvalidArgument)?;
        if !iface.active {
            return Err(Error::InvalidArgument);
        }
        iface.join_group(group_address)
    }

    /// Leave a multicast group on an interface.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `ifindex` is out of range or
    ///   the interface is not registered.
    /// - [`Error::NotFound`] if the group is not joined.
    pub fn leave(&mut self, ifindex: usize, group_address: u32) -> Result<()> {
        let iface = self
            .interfaces
            .get_mut(ifindex)
            .ok_or(Error::InvalidArgument)?;
        if !iface.active {
            return Err(Error::InvalidArgument);
        }
        iface.leave_group(group_address)
    }

    /// Tick all interface timers, advancing report countdowns.
    ///
    /// Returns the total number of report timers that expired across
    /// all interfaces during this tick.
    pub fn tick(&mut self) -> u32 {
        let mut total_expired = 0u32;
        for iface in &mut self.interfaces {
            if iface.active {
                total_expired += iface.tick();
            }
        }
        total_expired
    }
}
