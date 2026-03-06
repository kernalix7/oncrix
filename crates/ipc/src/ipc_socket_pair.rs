// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Socket pair implementation (`socketpair(2)`).
//!
//! Creates bidirectional connected socket pairs for local inter-process
//! communication.  Each pair consists of two ends connected by independent
//! ring buffers for each direction, providing full-duplex communication.
//!
//! # Operations
//!
//! | Function       | Purpose                                       |
//! |----------------|-----------------------------------------------|
//! | [`create_pair`]| Create a connected socket pair                |
//! | [`send`]       | Send data through one end of the pair         |
//! | [`recv`]       | Receive data from one end of the pair         |
//! | [`shutdown`]   | Shut down one or both directions              |
//! | [`get_peer`]   | Get the ID of the peer end                    |
//!
//! # Design
//!
//! Each socket pair has two ends (`EndA` and `EndB`).  Data written to
//! EndA is readable from EndB, and vice versa.  Each direction has its
//! own 4 KiB ring buffer, providing full-duplex communication without
//! contention.
//!
//! # POSIX conformance
//!
//! - POSIX.1-2024: `socketpair()`
//! - Supports `SOCK_STREAM` and `SOCK_DGRAM` types
//! - `SOCK_NONBLOCK` and `SOCK_CLOEXEC` flags accepted
//! - Only `AF_UNIX` (AF_LOCAL) domain supported
//!
//! # References
//!
//! - POSIX.1-2024: `socketpair()`
//! - Linux: `net/unix/af_unix.c`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Ring buffer size per direction (4 KiB).
const PAIR_BUFFER_SIZE: usize = 4096;

/// Maximum number of socket pairs in the registry.
const MAX_PAIRS: usize = 64;

/// Socket domain: `AF_UNIX` / `AF_LOCAL`.
pub const AF_UNIX: i32 = 1;
/// Socket domain alias.
pub const AF_LOCAL: i32 = AF_UNIX;

/// Stream socket type.
pub const SOCK_STREAM: i32 = 1;
/// Datagram socket type.
pub const SOCK_DGRAM: i32 = 2;

/// Set non-blocking mode on creation.
pub const SOCK_NONBLOCK: i32 = 0x800;
/// Set close-on-exec on creation.
pub const SOCK_CLOEXEC: i32 = 0x80000;

/// Mask to extract the base socket type (ignoring flags).
const SOCK_TYPE_MASK: i32 = 0xFF;

/// Shut down the read half of the socket.
pub const SHUT_RD: i32 = 0;
/// Shut down the write half of the socket.
pub const SHUT_WR: i32 = 1;
/// Shut down both halves.
pub const SHUT_RDWR: i32 = 2;

// ---------------------------------------------------------------------------
// PairEnd — which end of the socket pair
// ---------------------------------------------------------------------------

/// Identifies which end of a socket pair an operation targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairEnd {
    /// The first socket in the pair (index 0).
    EndA,
    /// The second socket in the pair (index 1).
    EndB,
}

impl PairEnd {
    /// Return the opposite end.
    pub const fn peer(self) -> Self {
        match self {
            Self::EndA => Self::EndB,
            Self::EndB => Self::EndA,
        }
    }
}

// ---------------------------------------------------------------------------
// PairBuffer — ring buffer for one direction
// ---------------------------------------------------------------------------

/// Fixed-size ring buffer for one direction of the socket pair.
struct PairBuffer {
    /// Raw data storage.
    data: [u8; PAIR_BUFFER_SIZE],
    /// Write position.
    head: usize,
    /// Read position.
    tail: usize,
    /// Number of valid bytes in the buffer.
    count: usize,
}

impl PairBuffer {
    /// Create an empty ring buffer.
    const fn new() -> Self {
        Self {
            data: [0u8; PAIR_BUFFER_SIZE],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    /// Write bytes into the buffer.
    ///
    /// Returns the number of bytes actually written (may be less than
    /// `src.len()` if the buffer is nearly full).
    fn write(&mut self, src: &[u8]) -> usize {
        let available = PAIR_BUFFER_SIZE - self.count;
        let to_write = src.len().min(available);

        for &byte in &src[..to_write] {
            self.data[self.head] = byte;
            self.head = (self.head + 1) % PAIR_BUFFER_SIZE;
        }
        self.count += to_write;
        to_write
    }

    /// Read bytes from the buffer.
    ///
    /// Returns the number of bytes actually read.
    fn read(&mut self, dst: &mut [u8]) -> usize {
        let to_read = dst.len().min(self.count);

        for slot in dst.iter_mut().take(to_read) {
            *slot = self.data[self.tail];
            self.tail = (self.tail + 1) % PAIR_BUFFER_SIZE;
        }
        self.count -= to_read;
        to_read
    }

    /// Return `true` if the buffer has data available for reading.
    fn has_data(&self) -> bool {
        self.count > 0
    }

    /// Return `true` if the buffer has room for at least one more byte.
    fn has_space(&self) -> bool {
        self.count < PAIR_BUFFER_SIZE
    }

    /// Return the number of bytes available for reading.
    fn readable(&self) -> usize {
        self.count
    }

    /// Return the number of bytes that can be written.
    fn writable(&self) -> usize {
        PAIR_BUFFER_SIZE - self.count
    }
}

// ---------------------------------------------------------------------------
// SocketPairFlags — validated creation flags
// ---------------------------------------------------------------------------

/// Validated flags for socket pair creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketPairFlags {
    /// Base socket type (SOCK_STREAM or SOCK_DGRAM).
    pub base_type: i32,
    /// Whether non-blocking mode is enabled.
    pub nonblock: bool,
    /// Whether close-on-exec is set.
    pub cloexec: bool,
}

impl SocketPairFlags {
    /// Parse and validate raw `type` and `protocol` arguments.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidArgument`] for unrecognised socket type or flags.
    pub fn from_raw(socket_type: i32, protocol: i32) -> Result<Self> {
        // Protocol must be 0 for AF_UNIX.
        if protocol != 0 {
            return Err(Error::InvalidArgument);
        }

        let base = socket_type & SOCK_TYPE_MASK;
        if base != SOCK_STREAM && base != SOCK_DGRAM {
            return Err(Error::InvalidArgument);
        }

        let extra = socket_type & !SOCK_TYPE_MASK;
        if extra & !(SOCK_NONBLOCK | SOCK_CLOEXEC) != 0 {
            return Err(Error::InvalidArgument);
        }

        Ok(Self {
            base_type: base,
            nonblock: extra & SOCK_NONBLOCK != 0,
            cloexec: extra & SOCK_CLOEXEC != 0,
        })
    }
}

// ---------------------------------------------------------------------------
// SocketPair — a connected pair of sockets
// ---------------------------------------------------------------------------

/// A connected socket pair providing bidirectional communication.
///
/// Each pair has two ring buffers:
/// - `a_to_b`: data written to EndA, readable from EndB
/// - `b_to_a`: data written to EndB, readable from EndA
pub struct SocketPair {
    /// Unique pair ID.
    pair_id: u64,
    /// Socket type (SOCK_STREAM or SOCK_DGRAM).
    socket_type: i32,
    /// Whether non-blocking mode is enabled.
    nonblock: bool,
    /// Whether close-on-exec is set.
    cloexec: bool,
    /// Buffer for data flowing from EndA to EndB.
    a_to_b: PairBuffer,
    /// Buffer for data flowing from EndB to EndA.
    b_to_a: PairBuffer,
    /// Whether EndA's write side is shut down.
    a_wr_shutdown: bool,
    /// Whether EndA's read side is shut down.
    a_rd_shutdown: bool,
    /// Whether EndB's write side is shut down.
    b_wr_shutdown: bool,
    /// Whether EndB's read side is shut down.
    b_rd_shutdown: bool,
    /// Whether EndA is closed.
    a_closed: bool,
    /// Whether EndB is closed.
    b_closed: bool,
}

impl SocketPair {
    /// Create a new socket pair.
    fn new(pair_id: u64, flags: &SocketPairFlags) -> Self {
        Self {
            pair_id,
            socket_type: flags.base_type,
            nonblock: flags.nonblock,
            cloexec: flags.cloexec,
            a_to_b: PairBuffer::new(),
            b_to_a: PairBuffer::new(),
            a_wr_shutdown: false,
            a_rd_shutdown: false,
            b_wr_shutdown: false,
            b_rd_shutdown: false,
            a_closed: false,
            b_closed: false,
        }
    }

    /// Return the pair ID.
    pub fn pair_id(&self) -> u64 {
        self.pair_id
    }

    /// Return the socket type.
    pub fn socket_type(&self) -> i32 {
        self.socket_type
    }

    /// Return `true` if non-blocking mode is enabled.
    pub fn is_nonblock(&self) -> bool {
        self.nonblock
    }

    /// Return `true` if close-on-exec is set.
    pub fn is_cloexec(&self) -> bool {
        self.cloexec
    }

    /// Check if the given end can write.
    fn can_write(&self, end: PairEnd) -> bool {
        match end {
            PairEnd::EndA => !self.a_wr_shutdown && !self.a_closed,
            PairEnd::EndB => !self.b_wr_shutdown && !self.b_closed,
        }
    }

    /// Check if the given end can read.
    fn can_read(&self, end: PairEnd) -> bool {
        match end {
            PairEnd::EndA => !self.a_rd_shutdown && !self.a_closed,
            PairEnd::EndB => !self.b_rd_shutdown && !self.b_closed,
        }
    }

    /// Check if the peer's write side is still open (determines EOF).
    fn peer_can_write(&self, end: PairEnd) -> bool {
        self.can_write(end.peer())
    }

    /// Get the write buffer for an end (data flows to the peer).
    fn write_buf_mut(&mut self, end: PairEnd) -> &mut PairBuffer {
        match end {
            PairEnd::EndA => &mut self.a_to_b,
            PairEnd::EndB => &mut self.b_to_a,
        }
    }

    /// Get the read buffer for an end (data from the peer).
    fn read_buf_mut(&mut self, end: PairEnd) -> &mut PairBuffer {
        match end {
            PairEnd::EndA => &mut self.b_to_a,
            PairEnd::EndB => &mut self.a_to_b,
        }
    }

    /// Get the read buffer for an end (shared reference).
    fn read_buf(&self, end: PairEnd) -> &PairBuffer {
        match end {
            PairEnd::EndA => &self.b_to_a,
            PairEnd::EndB => &self.a_to_b,
        }
    }

    /// Return the number of readable bytes for an end.
    pub fn readable(&self, end: PairEnd) -> usize {
        self.read_buf(end).readable()
    }

    /// Return the number of writable bytes for an end.
    pub fn writable(&self, end: PairEnd) -> usize {
        match end {
            PairEnd::EndA => self.a_to_b.writable(),
            PairEnd::EndB => self.b_to_a.writable(),
        }
    }

    /// Return `true` if the given end is closed.
    pub fn is_closed(&self, end: PairEnd) -> bool {
        match end {
            PairEnd::EndA => self.a_closed,
            PairEnd::EndB => self.b_closed,
        }
    }

    /// Return `true` if both ends are closed.
    pub fn is_fully_closed(&self) -> bool {
        self.a_closed && self.b_closed
    }
}

// ---------------------------------------------------------------------------
// PairRegistry — system-wide socket pair registry
// ---------------------------------------------------------------------------

/// System-wide registry of socket pairs.
pub struct PairRegistry {
    /// Socket pair slots.
    pairs: [Option<SocketPair>; MAX_PAIRS],
    /// Monotonically increasing pair ID counter.
    next_id: u64,
    /// Number of active pairs.
    count: usize,
}

impl PairRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            pairs: [const { None }; MAX_PAIRS],
            next_id: 1,
            count: 0,
        }
    }

    /// Return the number of active pairs.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return `true` if there are no active pairs.
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Find a pair by its ID.
    fn find(&self, pair_id: u64) -> Option<usize> {
        self.pairs
            .iter()
            .position(|p| p.as_ref().is_some_and(|sp| sp.pair_id == pair_id))
    }

    /// Get a shared reference to a pair by ID.
    pub fn get(&self, pair_id: u64) -> Option<&SocketPair> {
        self.find(pair_id).and_then(|idx| self.pairs[idx].as_ref())
    }

    /// Get a mutable reference to a pair by ID.
    pub fn get_mut(&mut self, pair_id: u64) -> Option<&mut SocketPair> {
        let idx = self.find(pair_id)?;
        self.pairs[idx].as_mut()
    }

    /// Remove a pair from the registry (when both ends are closed).
    pub fn remove(&mut self, pair_id: u64) -> Result<()> {
        let idx = self.find(pair_id).ok_or(Error::NotFound)?;
        self.pairs[idx] = None;
        self.count = self.count.saturating_sub(1);
        Ok(())
    }
}

impl Default for PairRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// create_pair — socketpair(2) implementation
// ---------------------------------------------------------------------------

/// Create a connected socket pair.
///
/// Returns the pair ID on success.  The caller should use `PairEnd::EndA`
/// and `PairEnd::EndB` to identify the two ends.
///
/// # Arguments
///
/// * `registry` — The system-wide pair registry.
/// * `domain`   — Socket domain (must be `AF_UNIX`).
/// * `socket_type` — Socket type, optionally OR'd with `SOCK_NONBLOCK`
///                    and/or `SOCK_CLOEXEC`.
/// * `protocol` — Protocol (must be 0 for `AF_UNIX`).
///
/// # Returns
///
/// The pair ID on success.
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — unsupported domain, type, or protocol.
/// * [`Error::OutOfMemory`]      — registry full.
///
/// # POSIX conformance
///
/// Only `AF_UNIX` is supported.  Both `SOCK_STREAM` and `SOCK_DGRAM`
/// types are allowed.  `SOCK_NONBLOCK` and `SOCK_CLOEXEC` flags are
/// accepted per POSIX.1-2024.
pub fn create_pair(
    registry: &mut PairRegistry,
    domain: i32,
    socket_type: i32,
    protocol: i32,
) -> Result<u64> {
    // Only AF_UNIX is supported for socket pairs.
    if domain != AF_UNIX && domain != AF_LOCAL {
        return Err(Error::InvalidArgument);
    }

    let flags = SocketPairFlags::from_raw(socket_type, protocol)?;

    // Find a free slot.
    let free_idx = registry
        .pairs
        .iter()
        .position(|p| p.is_none())
        .ok_or(Error::OutOfMemory)?;

    let pair_id = registry.next_id;
    registry.pairs[free_idx] = Some(SocketPair::new(pair_id, &flags));
    registry.next_id += 1;
    registry.count += 1;

    Ok(pair_id)
}

// ---------------------------------------------------------------------------
// send — write data through one end
// ---------------------------------------------------------------------------

/// Send data through one end of a socket pair.
///
/// Data written to one end is readable from the other end.
///
/// # Arguments
///
/// * `registry` — The pair registry.
/// * `pair_id`  — ID of the socket pair.
/// * `end`      — Which end to write from.
/// * `data`     — Data to send.
///
/// # Returns
///
/// The number of bytes actually written.
///
/// # Errors
///
/// * [`Error::NotFound`]         — pair ID not found.
/// * [`Error::InvalidArgument`]  — write side shut down or end closed.
/// * [`Error::WouldBlock`]       — buffer full (non-blocking mode).
pub fn send(registry: &mut PairRegistry, pair_id: u64, end: PairEnd, data: &[u8]) -> Result<usize> {
    let pair = registry.get_mut(pair_id).ok_or(Error::NotFound)?;

    if !pair.can_write(end) {
        return Err(Error::InvalidArgument);
    }

    // Check if the peer's read side is shut down.
    if !pair.can_read(end.peer()) {
        return Err(Error::InvalidArgument);
    }

    if data.is_empty() {
        return Ok(0);
    }

    let buf = pair.write_buf_mut(end);
    if !buf.has_space() {
        return Err(Error::WouldBlock);
    }

    Ok(buf.write(data))
}

// ---------------------------------------------------------------------------
// recv — read data from one end
// ---------------------------------------------------------------------------

/// Receive data from one end of a socket pair.
///
/// Reads data that was written to the peer end.
///
/// # Arguments
///
/// * `registry` — The pair registry.
/// * `pair_id`  — ID of the socket pair.
/// * `end`      — Which end to read from.
/// * `buf`      — Buffer to read into.
///
/// # Returns
///
/// The number of bytes actually read.  Returns 0 if the peer has
/// shut down its write side and the buffer is empty (EOF).
///
/// # Errors
///
/// * [`Error::NotFound`]         — pair ID not found.
/// * [`Error::InvalidArgument`]  — read side shut down or end closed.
/// * [`Error::WouldBlock`]       — no data available (non-blocking mode).
pub fn recv(
    registry: &mut PairRegistry,
    pair_id: u64,
    end: PairEnd,
    buf: &mut [u8],
) -> Result<usize> {
    let pair = registry.get_mut(pair_id).ok_or(Error::NotFound)?;

    if !pair.can_read(end) {
        return Err(Error::InvalidArgument);
    }

    if buf.is_empty() {
        return Ok(0);
    }

    let read_buf = pair.read_buf_mut(end);
    if read_buf.has_data() {
        return Ok(read_buf.read(buf));
    }

    // No data available: check if peer can still write.
    if !pair.peer_can_write(end) {
        // Peer's write side is shut down / closed: EOF.
        return Ok(0);
    }

    Err(Error::WouldBlock)
}

// ---------------------------------------------------------------------------
// shutdown — shut down one or both directions
// ---------------------------------------------------------------------------

/// Shut down one or both directions of a socket pair end.
///
/// # Arguments
///
/// * `registry` — The pair registry.
/// * `pair_id`  — ID of the socket pair.
/// * `end`      — Which end to shut down.
/// * `how`      — `SHUT_RD`, `SHUT_WR`, or `SHUT_RDWR`.
///
/// # Errors
///
/// * [`Error::NotFound`]         — pair ID not found.
/// * [`Error::InvalidArgument`]  — invalid `how` value or end already closed.
pub fn shutdown(registry: &mut PairRegistry, pair_id: u64, end: PairEnd, how: i32) -> Result<()> {
    let pair = registry.get_mut(pair_id).ok_or(Error::NotFound)?;

    if pair.is_closed(end) {
        return Err(Error::InvalidArgument);
    }

    match (end, how) {
        (PairEnd::EndA, SHUT_RD) => pair.a_rd_shutdown = true,
        (PairEnd::EndA, SHUT_WR) => pair.a_wr_shutdown = true,
        (PairEnd::EndA, SHUT_RDWR) => {
            pair.a_rd_shutdown = true;
            pair.a_wr_shutdown = true;
        }
        (PairEnd::EndB, SHUT_RD) => pair.b_rd_shutdown = true,
        (PairEnd::EndB, SHUT_WR) => pair.b_wr_shutdown = true,
        (PairEnd::EndB, SHUT_RDWR) => {
            pair.b_rd_shutdown = true;
            pair.b_wr_shutdown = true;
        }
        _ => return Err(Error::InvalidArgument),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// get_peer — identify the peer end
// ---------------------------------------------------------------------------

/// Get the peer end of a socket pair.
///
/// Given one end, returns the opposite end.  Also verifies the pair
/// exists and neither end is fully closed.
///
/// # Arguments
///
/// * `registry` — The pair registry.
/// * `pair_id`  — ID of the socket pair.
/// * `end`      — The local end.
///
/// # Returns
///
/// The peer's [`PairEnd`].
///
/// # Errors
///
/// * [`Error::NotFound`]         — pair ID not found.
/// * [`Error::InvalidArgument`]  — the peer end is closed.
pub fn get_peer(registry: &PairRegistry, pair_id: u64, end: PairEnd) -> Result<PairEnd> {
    let pair = registry.get(pair_id).ok_or(Error::NotFound)?;
    let peer = end.peer();
    if pair.is_closed(peer) {
        return Err(Error::InvalidArgument);
    }
    Ok(peer)
}

/// Close one end of a socket pair.
///
/// Marks the end as closed.  If both ends are closed, the pair can
/// be removed from the registry.
///
/// # Arguments
///
/// * `registry` — The pair registry.
/// * `pair_id`  — ID of the socket pair.
/// * `end`      — Which end to close.
///
/// # Returns
///
/// `true` if both ends are now closed (pair can be cleaned up).
///
/// # Errors
///
/// * [`Error::NotFound`] — pair ID not found.
pub fn close_end(registry: &mut PairRegistry, pair_id: u64, end: PairEnd) -> Result<bool> {
    let pair = registry.get_mut(pair_id).ok_or(Error::NotFound)?;
    match end {
        PairEnd::EndA => {
            pair.a_closed = true;
            pair.a_rd_shutdown = true;
            pair.a_wr_shutdown = true;
        }
        PairEnd::EndB => {
            pair.b_closed = true;
            pair.b_rd_shutdown = true;
            pair.b_wr_shutdown = true;
        }
    }
    Ok(pair.is_fully_closed())
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- SocketPairFlags ---

    #[test]
    fn flags_stream_basic() {
        let f = SocketPairFlags::from_raw(SOCK_STREAM, 0).unwrap();
        assert_eq!(f.base_type, SOCK_STREAM);
        assert!(!f.nonblock);
        assert!(!f.cloexec);
    }

    #[test]
    fn flags_dgram_nonblock_cloexec() {
        let f = SocketPairFlags::from_raw(SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0).unwrap();
        assert_eq!(f.base_type, SOCK_DGRAM);
        assert!(f.nonblock);
        assert!(f.cloexec);
    }

    #[test]
    fn flags_bad_protocol() {
        assert_eq!(
            SocketPairFlags::from_raw(SOCK_STREAM, 1),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn flags_bad_type() {
        assert_eq!(
            SocketPairFlags::from_raw(3, 0), // SOCK_RAW not supported
            Err(Error::InvalidArgument)
        );
    }

    // --- create_pair ---

    #[test]
    fn create_pair_basic() {
        let mut reg = PairRegistry::new();
        let id = create_pair(&mut reg, AF_UNIX, SOCK_STREAM, 0).unwrap();
        assert!(id > 0);
        assert_eq!(reg.count(), 1);
    }

    #[test]
    fn create_pair_dgram() {
        let mut reg = PairRegistry::new();
        let id = create_pair(&mut reg, AF_UNIX, SOCK_DGRAM, 0).unwrap();
        let pair = reg.get(id).unwrap();
        assert_eq!(pair.socket_type(), SOCK_DGRAM);
    }

    #[test]
    fn create_pair_bad_domain() {
        let mut reg = PairRegistry::new();
        assert_eq!(
            create_pair(&mut reg, 2, SOCK_STREAM, 0), // AF_INET
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn create_pair_with_flags() {
        let mut reg = PairRegistry::new();
        let id = create_pair(
            &mut reg,
            AF_UNIX,
            SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
            0,
        )
        .unwrap();
        let pair = reg.get(id).unwrap();
        assert!(pair.is_nonblock());
        assert!(pair.is_cloexec());
    }

    // --- send / recv ---

    #[test]
    fn send_recv_a_to_b() {
        let mut reg = PairRegistry::new();
        let id = create_pair(&mut reg, AF_UNIX, SOCK_STREAM, 0).unwrap();
        let n = send(&mut reg, id, PairEnd::EndA, b"hello").unwrap();
        assert_eq!(n, 5);
        let mut buf = [0u8; 16];
        let m = recv(&mut reg, id, PairEnd::EndB, &mut buf).unwrap();
        assert_eq!(m, 5);
        assert_eq!(&buf[..5], b"hello");
    }

    #[test]
    fn send_recv_b_to_a() {
        let mut reg = PairRegistry::new();
        let id = create_pair(&mut reg, AF_UNIX, SOCK_STREAM, 0).unwrap();
        send(&mut reg, id, PairEnd::EndB, b"world").unwrap();
        let mut buf = [0u8; 16];
        let m = recv(&mut reg, id, PairEnd::EndA, &mut buf).unwrap();
        assert_eq!(m, 5);
        assert_eq!(&buf[..5], b"world");
    }

    #[test]
    fn send_recv_bidirectional() {
        let mut reg = PairRegistry::new();
        let id = create_pair(&mut reg, AF_UNIX, SOCK_STREAM, 0).unwrap();
        send(&mut reg, id, PairEnd::EndA, b"ping").unwrap();
        send(&mut reg, id, PairEnd::EndB, b"pong").unwrap();

        let mut buf_b = [0u8; 16];
        let n = recv(&mut reg, id, PairEnd::EndB, &mut buf_b).unwrap();
        assert_eq!(&buf_b[..n], b"ping");

        let mut buf_a = [0u8; 16];
        let m = recv(&mut reg, id, PairEnd::EndA, &mut buf_a).unwrap();
        assert_eq!(&buf_a[..m], b"pong");
    }

    #[test]
    fn send_empty_data() {
        let mut reg = PairRegistry::new();
        let id = create_pair(&mut reg, AF_UNIX, SOCK_STREAM, 0).unwrap();
        let n = send(&mut reg, id, PairEnd::EndA, b"").unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn recv_no_data_wouldblock() {
        let mut reg = PairRegistry::new();
        let id = create_pair(&mut reg, AF_UNIX, SOCK_STREAM, 0).unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(
            recv(&mut reg, id, PairEnd::EndB, &mut buf),
            Err(Error::WouldBlock)
        );
    }

    #[test]
    fn recv_peer_closed_eof() {
        let mut reg = PairRegistry::new();
        let id = create_pair(&mut reg, AF_UNIX, SOCK_STREAM, 0).unwrap();
        shutdown(&mut reg, id, PairEnd::EndA, SHUT_WR).unwrap();
        let mut buf = [0u8; 16];
        // EndB reads: peer (A) has shut down writes, no data => EOF (0 bytes).
        let n = recv(&mut reg, id, PairEnd::EndB, &mut buf).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn send_not_found() {
        let mut reg = PairRegistry::new();
        assert_eq!(
            send(&mut reg, 999, PairEnd::EndA, b"data"),
            Err(Error::NotFound)
        );
    }

    // --- shutdown ---

    #[test]
    fn shutdown_write_prevents_send() {
        let mut reg = PairRegistry::new();
        let id = create_pair(&mut reg, AF_UNIX, SOCK_STREAM, 0).unwrap();
        shutdown(&mut reg, id, PairEnd::EndA, SHUT_WR).unwrap();
        assert_eq!(
            send(&mut reg, id, PairEnd::EndA, b"data"),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn shutdown_read_prevents_recv() {
        let mut reg = PairRegistry::new();
        let id = create_pair(&mut reg, AF_UNIX, SOCK_STREAM, 0).unwrap();
        send(&mut reg, id, PairEnd::EndA, b"data").unwrap();
        shutdown(&mut reg, id, PairEnd::EndB, SHUT_RD).unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(
            recv(&mut reg, id, PairEnd::EndB, &mut buf),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn shutdown_rdwr() {
        let mut reg = PairRegistry::new();
        let id = create_pair(&mut reg, AF_UNIX, SOCK_STREAM, 0).unwrap();
        shutdown(&mut reg, id, PairEnd::EndA, SHUT_RDWR).unwrap();
        assert_eq!(
            send(&mut reg, id, PairEnd::EndA, b"data"),
            Err(Error::InvalidArgument)
        );
        let mut buf = [0u8; 16];
        assert_eq!(
            recv(&mut reg, id, PairEnd::EndA, &mut buf),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn shutdown_invalid_how() {
        let mut reg = PairRegistry::new();
        let id = create_pair(&mut reg, AF_UNIX, SOCK_STREAM, 0).unwrap();
        assert_eq!(
            shutdown(&mut reg, id, PairEnd::EndA, 3),
            Err(Error::InvalidArgument)
        );
    }

    // --- get_peer ---

    #[test]
    fn get_peer_a_returns_b() {
        let mut reg = PairRegistry::new();
        let id = create_pair(&mut reg, AF_UNIX, SOCK_STREAM, 0).unwrap();
        assert_eq!(get_peer(&reg, id, PairEnd::EndA).unwrap(), PairEnd::EndB);
    }

    #[test]
    fn get_peer_b_returns_a() {
        let mut reg = PairRegistry::new();
        let id = create_pair(&mut reg, AF_UNIX, SOCK_STREAM, 0).unwrap();
        assert_eq!(get_peer(&reg, id, PairEnd::EndB).unwrap(), PairEnd::EndA);
    }

    #[test]
    fn get_peer_closed_returns_error() {
        let mut reg = PairRegistry::new();
        let id = create_pair(&mut reg, AF_UNIX, SOCK_STREAM, 0).unwrap();
        close_end(&mut reg, id, PairEnd::EndB).unwrap();
        assert_eq!(
            get_peer(&reg, id, PairEnd::EndA),
            Err(Error::InvalidArgument)
        );
    }

    // --- close_end ---

    #[test]
    fn close_both_ends() {
        let mut reg = PairRegistry::new();
        let id = create_pair(&mut reg, AF_UNIX, SOCK_STREAM, 0).unwrap();
        let fully = close_end(&mut reg, id, PairEnd::EndA).unwrap();
        assert!(!fully);
        let fully = close_end(&mut reg, id, PairEnd::EndB).unwrap();
        assert!(fully);
    }

    #[test]
    fn close_allows_cleanup() {
        let mut reg = PairRegistry::new();
        let id = create_pair(&mut reg, AF_UNIX, SOCK_STREAM, 0).unwrap();
        close_end(&mut reg, id, PairEnd::EndA).unwrap();
        close_end(&mut reg, id, PairEnd::EndB).unwrap();
        reg.remove(id).unwrap();
        assert_eq!(reg.count(), 0);
    }

    // --- PairBuffer ---

    #[test]
    fn buffer_fill_and_drain() {
        let mut reg = PairRegistry::new();
        let id = create_pair(&mut reg, AF_UNIX, SOCK_STREAM, 0).unwrap();

        // Fill the buffer.
        let large = [0xABu8; PAIR_BUFFER_SIZE];
        let n = send(&mut reg, id, PairEnd::EndA, &large).unwrap();
        assert_eq!(n, PAIR_BUFFER_SIZE);

        // Buffer should be full.
        assert_eq!(
            send(&mut reg, id, PairEnd::EndA, b"x"),
            Err(Error::WouldBlock)
        );

        // Drain the buffer.
        let mut out = [0u8; PAIR_BUFFER_SIZE];
        let m = recv(&mut reg, id, PairEnd::EndB, &mut out).unwrap();
        assert_eq!(m, PAIR_BUFFER_SIZE);
        assert_eq!(out[0], 0xAB);
    }

    // --- PairEnd ---

    #[test]
    fn pair_end_peer() {
        assert_eq!(PairEnd::EndA.peer(), PairEnd::EndB);
        assert_eq!(PairEnd::EndB.peer(), PairEnd::EndA);
    }

    // --- readable / writable ---

    #[test]
    fn readable_writable() {
        let mut reg = PairRegistry::new();
        let id = create_pair(&mut reg, AF_UNIX, SOCK_STREAM, 0).unwrap();
        send(&mut reg, id, PairEnd::EndA, b"test").unwrap();

        let pair = reg.get(id).unwrap();
        assert_eq!(pair.readable(PairEnd::EndB), 4);
        assert_eq!(pair.writable(PairEnd::EndA), PAIR_BUFFER_SIZE - 4);
    }

    // --- registry ---

    #[test]
    fn registry_remove_pair() {
        let mut reg = PairRegistry::new();
        let id = create_pair(&mut reg, AF_UNIX, SOCK_STREAM, 0).unwrap();
        reg.remove(id).unwrap();
        assert_eq!(reg.count(), 0);
        assert!(reg.get(id).is_none());
    }

    #[test]
    fn registry_remove_nonexistent() {
        let mut reg = PairRegistry::new();
        assert_eq!(reg.remove(999), Err(Error::NotFound));
    }
}
