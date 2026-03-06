// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! /proc/net entries.
//!
//! Implements the kernel-side formatting logic for `/proc/net/` entries:
//! - [`TcpEntry`] — per-socket TCP state row
//! - [`UdpEntry`] — per-socket UDP state row
//! - [`UnixEntry`] — per-socket Unix domain row
//! - [`format_tcp`] — render `/proc/net/tcp` and `/proc/net/tcp6`
//! - [`format_udp`] — render `/proc/net/udp` and `/proc/net/udp6`
//! - [`format_unix`] — render `/proc/net/unix`
//! - [`sockstat_counters`] — render `/proc/net/sockstat`
//! - Network interface statistics for `/proc/net/dev`
//!
//! # References
//! - Linux `net/ipv4/tcp_ipv4.c` (`tcp4_seq_show`)
//! - Linux `net/ipv4/udp.c` (`udp4_seq_show`)
//! - Linux `net/unix/af_unix.c` (`unix_seq_show`)

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum entries in the TCP/UDP tables.
const MAX_SOCK_ENTRIES: usize = 256;

/// Maximum Unix socket entries.
const MAX_UNIX_ENTRIES: usize = 128;

/// Maximum network interfaces.
const MAX_NET_IFACES: usize = 16;

// ---------------------------------------------------------------------------
// TCP socket states
// ---------------------------------------------------------------------------

/// TCP connection states (matching Linux enum tcp_states).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpState {
    Established = 1,
    SynSent = 2,
    SynRecv = 3,
    FinWait1 = 4,
    FinWait2 = 5,
    TimeWait = 6,
    Close = 7,
    CloseWait = 8,
    LastAck = 9,
    Listen = 10,
    Closing = 11,
}

impl TcpState {
    /// Return the hex code used in /proc/net/tcp.
    pub fn as_hex(&self) -> u8 {
        *self as u8
    }
}

// ---------------------------------------------------------------------------
// TcpEntry
// ---------------------------------------------------------------------------

/// A single row in `/proc/net/tcp`.
#[derive(Debug, Clone, Copy)]
pub struct TcpEntry {
    /// Local IPv4 address (network byte order).
    pub local_addr: u32,
    /// Local port.
    pub local_port: u16,
    /// Remote IPv4 address.
    pub rem_addr: u32,
    /// Remote port.
    pub rem_port: u16,
    /// TCP state.
    pub state: TcpState,
    /// Transmit queue length.
    pub tx_queue: u32,
    /// Receive queue length.
    pub rx_queue: u32,
    /// Timer type (0 = no timer).
    pub timer: u8,
    /// Timer expiry jiffies.
    pub jiffies: u32,
    /// Number of retransmissions.
    pub retrans: u8,
    /// Owner UID.
    pub uid: u32,
    /// Socket inode number.
    pub inode: u64,
}

impl TcpEntry {
    /// Create a new TCP entry in LISTEN state.
    pub fn new_listener(local_addr: u32, local_port: u16, uid: u32, inode: u64) -> Self {
        Self {
            local_addr,
            local_port,
            rem_addr: 0,
            rem_port: 0,
            state: TcpState::Listen,
            tx_queue: 0,
            rx_queue: 0,
            timer: 0,
            jiffies: 0,
            retrans: 0,
            uid,
            inode,
        }
    }

    /// Create a new established connection entry.
    pub fn new_connected(
        local_addr: u32,
        local_port: u16,
        rem_addr: u32,
        rem_port: u16,
        uid: u32,
        inode: u64,
    ) -> Self {
        Self {
            local_addr,
            local_port,
            rem_addr,
            rem_port,
            state: TcpState::Established,
            tx_queue: 0,
            rx_queue: 0,
            timer: 0,
            jiffies: 0,
            retrans: 0,
            uid,
            inode,
        }
    }
}

// ---------------------------------------------------------------------------
// UdpEntry
// ---------------------------------------------------------------------------

/// A single row in `/proc/net/udp`.
#[derive(Debug, Clone, Copy)]
pub struct UdpEntry {
    /// Local IPv4 address.
    pub local_addr: u32,
    /// Local port.
    pub local_port: u16,
    /// Remote IPv4 address (usually 0 for UDP).
    pub rem_addr: u32,
    /// Remote port.
    pub rem_port: u16,
    /// Socket state (01 = ESTABLISHED, 07 = CLOSE).
    pub state: u8,
    /// Transmit queue length.
    pub tx_queue: u32,
    /// Receive queue length.
    pub rx_queue: u32,
    /// Owner UID.
    pub uid: u32,
    /// Inode number.
    pub inode: u64,
    /// Number of drops.
    pub drops: u32,
}

impl UdpEntry {
    /// Create a bound UDP socket entry.
    pub fn new_bound(local_addr: u32, local_port: u16, uid: u32, inode: u64) -> Self {
        Self {
            local_addr,
            local_port,
            rem_addr: 0,
            rem_port: 0,
            state: 7, // CLOSE = 7 (socket is bound but not connected)
            tx_queue: 0,
            rx_queue: 0,
            uid,
            inode,
            drops: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// UnixEntry
// ---------------------------------------------------------------------------

/// A single row in `/proc/net/unix`.
#[derive(Debug, Clone)]
pub struct UnixEntry {
    /// Pointer value (kernel address, printed as hex).
    pub ptr: u64,
    /// Reference count.
    pub refcount: u32,
    /// Protocol (always 0 for Unix sockets).
    pub protocol: u32,
    /// Flags.
    pub flags: u32,
    /// Socket type (SOCK_STREAM=1, SOCK_DGRAM=2, SOCK_SEQPACKET=5).
    pub sock_type: u8,
    /// State (SS_UNCONNECTED=1, SS_CONNECTED=3).
    pub state: u8,
    /// Inode number.
    pub inode: u64,
    /// Filesystem path (empty for anonymous sockets).
    pub path: [u8; 108],
    /// Length of path.
    pub path_len: usize,
}

impl UnixEntry {
    /// Create a new abstract Unix socket entry.
    pub fn new_abstract(ptr: u64, inode: u64) -> Self {
        Self {
            ptr,
            refcount: 1,
            protocol: 0,
            flags: 0,
            sock_type: 1,
            state: 1,
            inode,
            path: [0u8; 108],
            path_len: 0,
        }
    }

    /// Create a named Unix socket entry.
    pub fn new_named(ptr: u64, inode: u64, path: &[u8]) -> Result<Self> {
        if path.len() > 108 {
            return Err(Error::InvalidArgument);
        }
        let mut entry = Self::new_abstract(ptr, inode);
        entry.path[..path.len()].copy_from_slice(path);
        entry.path_len = path.len();
        Ok(entry)
    }

    /// Return the path as a byte slice.
    pub fn path_bytes(&self) -> &[u8] {
        &self.path[..self.path_len]
    }
}

// ---------------------------------------------------------------------------
// format_tcp
// ---------------------------------------------------------------------------

/// Format a TCP socket table as `/proc/net/tcp` text.
///
/// Returns a multi-line string with a header followed by one row per entry.
pub fn format_tcp(entries: &[TcpEntry]) -> String {
    let mut out = String::from(
        "  sl  local_address rem_address   st tx_queue rx_queue \
         tr tm->when retrnsmt   uid  timeout inode\n",
    );
    for (i, e) in entries.iter().enumerate() {
        // Format: "   0: LOCALADDR:PORT REMADDR:PORT STATE TX:RX ..."
        let line = alloc::format!(
            "{:4}: {:08X}:{:04X} {:08X}:{:04X} {:02X} {:08X}:{:08X} {:02X}:{:08X} {:08X} {:5} 0 {:8}\n",
            i,
            e.local_addr,
            e.local_port,
            e.rem_addr,
            e.rem_port,
            e.state.as_hex(),
            e.tx_queue,
            e.rx_queue,
            e.timer,
            e.jiffies,
            e.retrans as u32,
            e.uid,
            e.inode,
        );
        out.push_str(&line);
    }
    out
}

// ---------------------------------------------------------------------------
// format_udp
// ---------------------------------------------------------------------------

/// Format a UDP socket table as `/proc/net/udp` text.
pub fn format_udp(entries: &[UdpEntry]) -> String {
    let mut out = String::from(
        "  sl  local_address rem_address   st tx_queue rx_queue \
         tr tm->when retrnsmt   uid  timeout inode\n",
    );
    for (i, e) in entries.iter().enumerate() {
        let line = alloc::format!(
            "{:4}: {:08X}:{:04X} {:08X}:{:04X} {:02X} {:08X}:{:08X} 00:00000000 00000000 {:5} 0 {:8} {} \n",
            i,
            e.local_addr,
            e.local_port,
            e.rem_addr,
            e.rem_port,
            e.state,
            e.tx_queue,
            e.rx_queue,
            e.uid,
            e.inode,
            e.drops,
        );
        out.push_str(&line);
    }
    out
}

// ---------------------------------------------------------------------------
// format_unix
// ---------------------------------------------------------------------------

/// Format a Unix socket table as `/proc/net/unix` text.
pub fn format_unix(entries: &[UnixEntry]) -> String {
    let mut out = String::from("Num       RefCount Protocol Flags    Type St Inode Path\n");
    for e in entries {
        let path_str = core::str::from_utf8(e.path_bytes()).unwrap_or("");
        let line = alloc::format!(
            "{:08X}: {:08X} {:08X} {:08X} {:04X} {:02X} {:8} {}\n",
            e.ptr,
            e.refcount,
            e.protocol,
            e.flags,
            e.sock_type,
            e.state,
            e.inode,
            path_str,
        );
        out.push_str(&line);
    }
    out
}

// ---------------------------------------------------------------------------
// SockstatCounters
// ---------------------------------------------------------------------------

/// Counters for `/proc/net/sockstat`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SockstatCounters {
    /// Total sockets in use.
    pub sockets_used: u32,
    /// TCP sockets: inuse, orphan, tw, alloc, mem.
    pub tcp_inuse: u32,
    pub tcp_orphan: u32,
    pub tcp_tw: u32,
    pub tcp_alloc: u32,
    pub tcp_mem: u32,
    /// UDP sockets: inuse, mem.
    pub udp_inuse: u32,
    pub udp_mem: u32,
    /// UDP-Lite sockets.
    pub udplite_inuse: u32,
    /// Raw sockets.
    pub raw_inuse: u32,
    /// Fragment queues.
    pub frag_inuse: u32,
    pub frag_memory: u32,
}

/// Format `/proc/net/sockstat` output.
pub fn sockstat_counters(c: &SockstatCounters) -> String {
    alloc::format!(
        "sockets: used {}\nTCP: inuse {} orphan {} tw {} alloc {} mem {}\n\
         UDP: inuse {} mem {}\nUDPLITE: inuse {}\nRAW: inuse {}\n\
         FRAG: inuse {} memory {}\n",
        c.sockets_used,
        c.tcp_inuse,
        c.tcp_orphan,
        c.tcp_tw,
        c.tcp_alloc,
        c.tcp_mem,
        c.udp_inuse,
        c.udp_mem,
        c.udplite_inuse,
        c.raw_inuse,
        c.frag_inuse,
        c.frag_memory,
    )
}

// ---------------------------------------------------------------------------
// NetDevStats — /proc/net/dev
// ---------------------------------------------------------------------------

/// Per-interface statistics for `/proc/net/dev`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NetDevStats {
    /// Interface name (up to 15 chars + NUL).
    pub name: [u8; 16],
    pub name_len: usize,
    // Receive
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub rx_errs: u64,
    pub rx_drop: u64,
    pub rx_fifo: u64,
    pub rx_frame: u64,
    pub rx_compressed: u64,
    pub rx_multicast: u64,
    // Transmit
    pub tx_bytes: u64,
    pub tx_packets: u64,
    pub tx_errs: u64,
    pub tx_drop: u64,
    pub tx_fifo: u64,
    pub tx_colls: u64,
    pub tx_carrier: u64,
    pub tx_compressed: u64,
}

impl NetDevStats {
    /// Create a zeroed stats entry with the given interface name.
    pub fn new(name: &[u8]) -> Result<Self> {
        if name.len() > 15 {
            return Err(Error::InvalidArgument);
        }
        let mut s = Self::default();
        s.name[..name.len()].copy_from_slice(name);
        s.name_len = name.len();
        Ok(s)
    }

    /// Return name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

/// Format `/proc/net/dev` output.
pub fn format_dev(stats: &[NetDevStats]) -> String {
    let mut out = String::from(
        "Inter-|   Receive                                                \
         |  Transmit\n \
         face |bytes    packets errs drop fifo frame compressed multicast\
         |bytes    packets errs drop fifo colls carrier compressed\n",
    );
    for s in stats {
        let name = core::str::from_utf8(s.name_bytes()).unwrap_or("?");
        let line = alloc::format!(
            "{:>6}: {:10} {:8} {:4} {:4} {:4} {:4} {:10} {:9}\
             {:10} {:8} {:4} {:4} {:4} {:5} {:7} {:10}\n",
            name,
            s.rx_bytes,
            s.rx_packets,
            s.rx_errs,
            s.rx_drop,
            s.rx_fifo,
            s.rx_frame,
            s.rx_compressed,
            s.rx_multicast,
            s.tx_bytes,
            s.tx_packets,
            s.tx_errs,
            s.tx_drop,
            s.tx_fifo,
            s.tx_colls,
            s.tx_carrier,
            s.tx_compressed,
        );
        out.push_str(&line);
    }
    out
}

// ---------------------------------------------------------------------------
// ProcNetTable — aggregation of all /proc/net socket tables
// ---------------------------------------------------------------------------

/// Registry of /proc/net socket and interface tables.
pub struct ProcNetTable {
    tcp: [Option<TcpEntry>; MAX_SOCK_ENTRIES],
    tcp_count: usize,
    udp: [Option<UdpEntry>; MAX_SOCK_ENTRIES],
    udp_count: usize,
    unix: [Option<UnixEntry>; MAX_UNIX_ENTRIES],
    unix_count: usize,
    dev: [Option<NetDevStats>; MAX_NET_IFACES],
    dev_count: usize,
}

impl ProcNetTable {
    /// Create an empty table.
    pub fn new() -> Self {
        Self {
            tcp: core::array::from_fn(|_| None),
            tcp_count: 0,
            udp: core::array::from_fn(|_| None),
            udp_count: 0,
            unix: core::array::from_fn(|_| None),
            unix_count: 0,
            dev: core::array::from_fn(|_| None),
            dev_count: 0,
        }
    }

    /// Add a TCP socket entry.
    pub fn add_tcp(&mut self, entry: TcpEntry) -> Result<()> {
        if self.tcp_count >= MAX_SOCK_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.tcp[self.tcp_count] = Some(entry);
        self.tcp_count += 1;
        Ok(())
    }

    /// Add a UDP socket entry.
    pub fn add_udp(&mut self, entry: UdpEntry) -> Result<()> {
        if self.udp_count >= MAX_SOCK_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.udp[self.udp_count] = Some(entry);
        self.udp_count += 1;
        Ok(())
    }

    /// Add a Unix socket entry.
    pub fn add_unix(&mut self, entry: UnixEntry) -> Result<()> {
        if self.unix_count >= MAX_UNIX_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.unix[self.unix_count] = Some(entry);
        self.unix_count += 1;
        Ok(())
    }

    /// Register a network interface.
    pub fn add_dev(&mut self, stats: NetDevStats) -> Result<()> {
        if self.dev_count >= MAX_NET_IFACES {
            return Err(Error::OutOfMemory);
        }
        self.dev[self.dev_count] = Some(stats);
        self.dev_count += 1;
        Ok(())
    }

    /// Render `/proc/net/tcp`.
    pub fn render_tcp(&self) -> String {
        let entries: Vec<TcpEntry> = self.tcp[..self.tcp_count]
            .iter()
            .flatten()
            .copied()
            .collect();
        format_tcp(&entries)
    }

    /// Render `/proc/net/udp`.
    pub fn render_udp(&self) -> String {
        let entries: Vec<UdpEntry> = self.udp[..self.udp_count]
            .iter()
            .flatten()
            .copied()
            .collect();
        format_udp(&entries)
    }

    /// Render `/proc/net/unix`.
    pub fn render_unix(&self) -> String {
        let entries: Vec<UnixEntry> = self.unix[..self.unix_count]
            .iter()
            .flatten()
            .cloned()
            .collect();
        format_unix(&entries)
    }
}

impl Default for ProcNetTable {
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

    #[test]
    fn test_format_tcp() {
        let entries = [TcpEntry::new_listener(0x0100007F, 80, 0, 100)];
        let out = format_tcp(&entries);
        assert!(out.contains("0050")); // port 80 in hex
    }

    #[test]
    fn test_format_udp() {
        let entries = [UdpEntry::new_bound(0x0100007F, 53, 0, 200)];
        let out = format_udp(&entries);
        assert!(out.contains("0035")); // port 53 in hex
    }

    #[test]
    fn test_sockstat() {
        let c = SockstatCounters {
            sockets_used: 42,
            tcp_inuse: 5,
            ..Default::default()
        };
        let out = sockstat_counters(&c);
        assert!(out.contains("42"));
    }
}
