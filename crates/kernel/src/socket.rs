// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Unix domain socket (AF_LOCAL) support for the ONCRIX kernel.
//!
//! Provides the kernel-facing socket API that maps POSIX `socket(2)`,
//! `bind(2)`, `listen(2)`, `accept(2)`, `connect(2)`, `sendto(2)`,
//! `recvfrom(2)`, `socketpair(2)`, and `close(2)` onto the IPC
//! crate's [`UnixSocketRegistry`].
//!
//! # Socket domains
//!
//! Only `AF_LOCAL` (`AF_UNIX`, domain = 1) is currently supported.
//! Network socket families (AF_INET, AF_INET6) will be added when the
//! networking stack is implemented.
//!
//! # Design
//!
//! The [`SocketRegistry`] wraps [`oncrix_ipc::unix_socket::UnixSocketRegistry`]
//! and exposes a flat ID-based interface suitable for syscall handlers.
//! Internally, data flows through per-socket ring buffers (4 KiB each,
//! matching `PIPE_BUF`). For connected stream sockets, `send` writes
//! into the **peer's** buffer and `recv` reads from the **local** buffer.

use oncrix_ipc::unix_socket::{SocketAddr, SocketType, UnixSocketRegistry};
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// SocketDomain
// ---------------------------------------------------------------------------

/// Socket address family (domain).
///
/// Corresponds to the first argument of `socket(2)`.
/// Currently only local (Unix) sockets are implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SocketDomain {
    /// Local (Unix domain) socket — `AF_LOCAL` / `AF_UNIX`.
    Local = 1,
}

impl SocketDomain {
    /// Convert a raw integer to a `SocketDomain`.
    ///
    /// Returns `InvalidArgument` for unsupported domains.
    pub fn from_raw(raw: u32) -> Result<Self> {
        match raw {
            1 => Ok(Self::Local),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ---------------------------------------------------------------------------
// SockType (wrapper)
// ---------------------------------------------------------------------------

/// Socket type (second argument to `socket(2)`).
///
/// Maps raw POSIX constants to [`SocketType`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SockType {
    /// `SOCK_STREAM` (1) — connection-oriented byte stream.
    Stream = 1,
    /// `SOCK_DGRAM` (2) — connectionless datagram.
    Dgram = 2,
}

impl SockType {
    /// Convert a raw integer to a `SockType`.
    ///
    /// Returns `InvalidArgument` for unsupported types.
    pub fn from_raw(raw: u32) -> Result<Self> {
        match raw {
            1 => Ok(Self::Stream),
            2 => Ok(Self::Dgram),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Convert to the IPC crate's [`SocketType`].
    fn to_ipc(self) -> SocketType {
        match self {
            Self::Stream => SocketType::Stream,
            Self::Dgram => SocketType::Datagram,
        }
    }
}

// ---------------------------------------------------------------------------
// SocketRegistry
// ---------------------------------------------------------------------------

/// Maximum number of sockets managed by this registry.
const MAX_SOCKETS: usize = 64;

/// Kernel-level socket registry.
///
/// Wraps the IPC crate's [`UnixSocketRegistry`] and provides the full
/// POSIX socket lifecycle: `create`, `bind`, `listen`, `accept`,
/// `connect`, `send`, `recv`, `close`, and `socketpair`.
///
/// Socket IDs are `usize` indices into a flat array. Each slot records
/// the domain and delegates to the appropriate backend registry.
pub struct SocketRegistry {
    /// The underlying Unix socket registry (from the IPC crate).
    unix: UnixSocketRegistry,
    /// Maps our socket IDs to Unix registry IDs.
    ///
    /// `id_map[local_id] = Some(unix_registry_id)` when the slot is in use.
    id_map: [Option<u64>; MAX_SOCKETS],
    /// Reference count per slot: number of open fds aliasing this socket.
    ///
    /// Incremented by `dup`/`dup2`/`fcntl(F_DUPFD)`/`fork`, decremented by
    /// `close`; the underlying Unix socket is freed only when it reaches 0.
    /// Without this, a duplicated socket fd would free the socket on the
    /// first close, leaving the alias dangling (use-after-free).
    refs: [u32; MAX_SOCKETS],
}

impl Default for SocketRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SocketRegistry {
    /// Create an empty socket registry.
    pub const fn new() -> Self {
        const NONE: Option<u64> = None;
        Self {
            unix: UnixSocketRegistry::new(),
            id_map: [NONE; MAX_SOCKETS],
            refs: [0; MAX_SOCKETS],
        }
    }

    /// Increment the reference count for an open socket slot (fd alias).
    ///
    /// Called when a socket fd is duplicated (`dup`/`dup2`/`fcntl`/`fork`).
    pub fn dup(&mut self, id: usize) {
        if id < MAX_SOCKETS && self.id_map[id].is_some() {
            self.refs[id] = self.refs[id].saturating_add(1);
        }
    }

    // -- helpers ----------------------------------------------------------

    /// Find a free local slot index.
    fn alloc_slot(&self) -> Result<usize> {
        for (i, slot) in self.id_map.iter().enumerate() {
            if slot.is_none() {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Resolve a local socket ID to the Unix registry ID.
    fn resolve(&self, id: usize) -> Result<u64> {
        self.id_map
            .get(id)
            .copied()
            .flatten()
            .ok_or(Error::NotFound)
    }

    // -- public API -------------------------------------------------------

    /// Create a new socket.
    ///
    /// `domain` must be [`SocketDomain::Local`]; `sock_type` selects
    /// stream or datagram mode. Returns a local socket ID on success.
    pub fn create(&mut self, domain: SocketDomain, sock_type: SockType) -> Result<usize> {
        if domain != SocketDomain::Local {
            return Err(Error::InvalidArgument);
        }
        let slot = self.alloc_slot()?;
        let unix_id = self.unix.create(sock_type.to_ipc())?;
        self.id_map[slot] = Some(unix_id);
        self.refs[slot] = 1;
        Ok(slot)
    }

    /// Bind a socket to a local address.
    ///
    /// The socket must be unbound. The address must not already be in
    /// use by another socket.
    pub fn bind(&mut self, id: usize, addr: SocketAddr) -> Result<()> {
        // Check for address conflicts first.
        if self.unix.find_by_addr(&addr).is_some() {
            return Err(Error::AlreadyExists);
        }
        let unix_id = self.resolve(id)?;
        let sock = self.unix.get_mut(unix_id).ok_or(Error::NotFound)?;
        sock.bind(addr)
    }

    /// Mark a socket as listening for incoming connections.
    ///
    /// Only valid for stream sockets that have been bound.
    pub fn listen(&mut self, id: usize, backlog: u32) -> Result<()> {
        let unix_id = self.resolve(id)?;
        let sock = self.unix.get_mut(unix_id).ok_or(Error::NotFound)?;
        sock.listen(backlog)
    }

    /// Accept a pending connection on a listening socket.
    ///
    /// Returns the local socket ID of a newly created connected socket
    /// that is paired with the connecting peer. The listening socket
    /// remains in the `Listening` state.
    pub fn accept(&mut self, id: usize) -> Result<usize> {
        let unix_id = self.resolve(id)?;

        // Pop the pending peer from the backlog.
        let peer_unix_id = {
            let sock = self.unix.get_mut(unix_id).ok_or(Error::NotFound)?;
            sock.accept()?
        };

        // Create a new server-side socket, already connected to the peer.
        let peer_type = {
            let peer = self.unix.get(peer_unix_id).ok_or(Error::NotFound)?;
            peer.socket_type()
        };
        let server_unix_id = self.unix.create(peer_type)?;

        // Connect both ends to each other.
        {
            let server_sock = self.unix.get_mut(server_unix_id).ok_or(Error::NotFound)?;
            server_sock.connect(peer_unix_id)?;
        }

        // Also mark the peer as connected to the server socket.
        {
            let peer_sock = self.unix.get_mut(peer_unix_id).ok_or(Error::NotFound)?;
            peer_sock.connect(server_unix_id)?;
        }

        // Allocate a local slot for the new server socket.
        let slot = self.alloc_slot()?;
        self.id_map[slot] = Some(server_unix_id);
        self.refs[slot] = 1;
        Ok(slot)
    }

    /// Connect a socket to a remote address.
    ///
    /// Looks up the target socket by address, enqueues a connection
    /// request into the target's listen backlog, and transitions this
    /// socket to the connecting state.
    pub fn connect(&mut self, id: usize, addr: SocketAddr) -> Result<()> {
        let unix_id = self.resolve(id)?;

        // Find the listening socket bound to the target address.
        let target_unix_id = self.unix.find_by_addr(&addr).ok_or(Error::NotFound)?;

        // Enqueue this socket into the target's backlog.
        {
            let target = self.unix.get_mut(target_unix_id).ok_or(Error::NotFound)?;
            target.enqueue_connection(unix_id)?;
        }

        Ok(())
    }

    /// Return `true` if the peer end of socket `unix_id` is still usable.
    ///
    /// The peer is open while our socket still names a live peer ID *and* that
    /// peer slot exists and has not transitioned to `Closed`. Used by `send`
    /// to surface `EPIPE` instead of spinning on a full buffer whose reader is
    /// gone.
    fn peer_open(&self, unix_id: u64) -> bool {
        match self.unix.get(unix_id).and_then(|s| s.peer_id()) {
            Some(peer_id) => self
                .unix
                .get(peer_id)
                .is_some_and(|p| p.state() != oncrix_ipc::unix_socket::SocketState::Closed),
            None => false,
        }
    }

    /// Send data through a connected socket.
    ///
    /// Writes data into the **peer's** ring buffer so that the peer can read
    /// it via [`recv`](Self::recv). Returns:
    /// - `Ok(n)` — bytes buffered for the peer.
    /// - `Err(WouldBlock)` — the peer's buffer is full; caller may retry or
    ///   map to `EAGAIN`.
    /// - `Err(InvalidArgument)` — the socket was never connected (no peer ID).
    /// - `Err(Busy)` — the peer has closed; the caller maps this to `EPIPE`.
    ///   `Busy` is reused as the broken-pipe sentinel because the kernel
    ///   `Error` enum has no dedicated `BrokenPipe` variant and the socket
    ///   path never otherwise returns `Busy`.
    pub fn send(&mut self, id: usize, data: &[u8]) -> Result<usize> {
        let unix_id = self.resolve(id)?;

        // A socket that never connected has no peer ID — that is EINVAL, not
        // EPIPE. Tell the two apart before deciding the peer is gone.
        let had_peer = self
            .unix
            .get(unix_id)
            .is_some_and(|s| s.peer_id().is_some() || s.peer_closed());
        if !had_peer {
            return Err(Error::InvalidArgument);
        }

        // Peer-gone detection: either our socket was explicitly marked
        // peer-closed (set by `close` on the other end) or the peer ID no
        // longer resolves to a live socket. Either way the reading end is
        // gone, so report a broken pipe rather than EINVAL or an endless spin.
        let peer_closed = self
            .unix
            .get(unix_id)
            .map(|s| s.peer_closed())
            .unwrap_or(true);
        if peer_closed || !self.peer_open(unix_id) {
            return Err(Error::Busy); // -> EPIPE at the syscall layer
        }

        // Resolve the peer and deliver into its buffer. `deliver` only requires
        // the peer to be non-closed (not strictly `Connected`), which keeps the
        // connected happy path working while also allowing pre-accept and
        // datagram delivery.
        let peer_unix_id = {
            let sock = self.unix.get(unix_id).ok_or(Error::NotFound)?;
            sock.peer_id().ok_or(Error::InvalidArgument)?
        };
        let peer = self.unix.get_mut(peer_unix_id).ok_or(Error::NotFound)?;
        peer.deliver(data)
    }

    /// Receive data from a connected socket.
    ///
    /// Reads data from the **local** ring buffer. Returns the number of bytes
    /// read, `WouldBlock` if the buffer is empty but the peer is still open,
    /// or `Ok(0)` (EOF) if the buffer is empty and the peer has closed.
    pub fn recv(&mut self, id: usize, buf: &mut [u8]) -> Result<usize> {
        let unix_id = self.resolve(id)?;
        let sock = self.unix.get_mut(unix_id).ok_or(Error::NotFound)?;
        match sock.recv(buf) {
            // Empty buffer: distinguish "peer gone -> EOF" from "wait".
            Err(Error::WouldBlock) if sock.peer_closed() => Ok(0),
            other => other,
        }
    }

    /// Close a socket and release its resources.
    ///
    /// The socket is marked as closed and removed from the registry. Before
    /// removal, any connected peer is notified via `set_peer_closed` so that a
    /// subsequent `send` on the survivor observes `EPIPE` and a `recv`
    /// observes EOF, instead of resolving a now-stale peer ID to `EINVAL`.
    pub fn close(&mut self, id: usize) -> Result<()> {
        let unix_id = self.resolve(id)?;
        // Decrement the alias refcount; only free the underlying Unix socket
        // and release the slot when the last fd is closed.
        if id < MAX_SOCKETS && self.refs[id] > 1 {
            self.refs[id] -= 1;
            return Ok(());
        }
        // Capture the peer ID (if any) before tearing this socket down.
        let peer_unix_id = self.unix.get(unix_id).and_then(|s| s.peer_id());
        {
            let sock = self.unix.get_mut(unix_id).ok_or(Error::NotFound)?;
            sock.close();
        }
        // Notify the surviving peer that its other end is gone.
        if let Some(peer_id) = peer_unix_id
            && let Some(peer) = self.unix.get_mut(peer_id)
        {
            peer.set_peer_closed();
        }
        self.unix.remove(unix_id)?;
        self.id_map[id] = None;
        self.refs[id] = 0;
        Ok(())
    }

    /// Create a pair of connected sockets (`socketpair(2)`).
    ///
    /// Both sockets are stream-type, unnamed, and immediately
    /// connected to each other. Returns `(id_a, id_b)`.
    pub fn socketpair(&mut self, sock_type: SockType) -> Result<(usize, usize)> {
        // Allocate two local slots.
        let slot_a = self.alloc_slot()?;
        let unix_id_a = self.unix.create(sock_type.to_ipc())?;
        self.id_map[slot_a] = Some(unix_id_a);
        self.refs[slot_a] = 1;

        let slot_b = match self.alloc_slot() {
            Ok(s) => s,
            Err(e) => {
                // Roll back slot_a.
                self.id_map[slot_a] = None;
                let _ = self.unix.remove(unix_id_a);
                return Err(e);
            }
        };
        let unix_id_b = match self.unix.create(sock_type.to_ipc()) {
            Ok(id) => id,
            Err(e) => {
                // Roll back slot_a.
                self.id_map[slot_a] = None;
                let _ = self.unix.remove(unix_id_a);
                return Err(e);
            }
        };
        self.id_map[slot_b] = Some(unix_id_b);
        self.refs[slot_b] = 1;

        // Connect A → B.
        if let Err(e) = self
            .unix
            .get_mut(unix_id_a)
            .ok_or(Error::NotFound)
            .and_then(|s| s.connect(unix_id_b))
        {
            self.id_map[slot_a] = None;
            self.id_map[slot_b] = None;
            let _ = self.unix.remove(unix_id_a);
            let _ = self.unix.remove(unix_id_b);
            return Err(e);
        }

        // Connect B → A.
        if let Err(e) = self
            .unix
            .get_mut(unix_id_b)
            .ok_or(Error::NotFound)
            .and_then(|s| s.connect(unix_id_a))
        {
            self.id_map[slot_a] = None;
            self.id_map[slot_b] = None;
            let _ = self.unix.remove(unix_id_a);
            let _ = self.unix.remove(unix_id_b);
            return Err(e);
        }

        Ok((slot_a, slot_b))
    }

    /// Return the number of active sockets.
    pub fn count(&self) -> usize {
        self.id_map.iter().filter(|s| s.is_some()).count()
    }
}

// ---------------------------------------------------------------------------
// Global socket table
// ---------------------------------------------------------------------------

/// Global socket registry for the current process.
///
/// Phase 18 simplification: a single static registry for the one running
/// process. SMP / multi-process support is deferred.
///
/// # Safety invariant
///
/// Accessed exclusively from the SYSCALL dispatch path where the single CPU
/// is in ring 0 with interrupts effectively disabled (FMASK cleared IF on
/// SYSCALL entry). No concurrent mutation is possible on single-CPU builds.
// SAFETY: Single-CPU SYSCALL context only; see module-level note.
static mut SOCKET_TABLE: SocketRegistry = SocketRegistry::new();

// ---------------------------------------------------------------------------
// Kernel-facing helpers (called from fd_table dispatch)
// ---------------------------------------------------------------------------

/// Send `data` through the socket identified by `handle_id`.
///
/// Returns the number of bytes written, or an error.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn socket_send(handle_id: u32, data: &[u8]) -> Result<usize> {
    // SAFETY: Single-CPU SYSCALL context; no aliased access.
    unsafe {
        #[allow(static_mut_refs)]
        SOCKET_TABLE.send(handle_id as usize, data)
    }
}

/// Receive bytes from the socket identified by `handle_id` into `buf`.
///
/// Returns the number of bytes read, or an error.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn socket_recv(handle_id: u32, buf: &mut [u8]) -> Result<usize> {
    // SAFETY: Single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        SOCKET_TABLE.recv(handle_id as usize, buf)
    }
}

/// Close the socket identified by `handle_id`, releasing its slot.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn socket_close(handle_id: u32) {
    // SAFETY: Single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        let _ = SOCKET_TABLE.close(handle_id as usize);
    }
}

/// Bump the reference count of an open socket handle (fd alias).
///
/// Must be called whenever a `FileBackend::Socket` fd is duplicated
/// (`dup`/`dup2`/`fcntl(F_DUPFD)`/`fork`) so the matching `socket_close`
/// does not free the socket while another fd still references it.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU).
pub unsafe fn socket_dup(handle_id: u32) {
    // SAFETY: Single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        SOCKET_TABLE.dup(handle_id as usize);
    }
}

// ---------------------------------------------------------------------------
// Syscall handlers
// ---------------------------------------------------------------------------

/// Maximum path length for a Unix socket path copied from user space.
const SOCK_PATH_MAX: usize = 108;

/// Copy a null-terminated path from user space.
///
/// Returns the length of the copied path (without null terminator) or
/// `Err(InvalidArgument)` on bad pointer or overlong path.
///
/// # Safety
///
/// `path_ptr` must point into user-space (checked against canonical boundary).
unsafe fn copy_socket_path(path_ptr: u64, buf: &mut [u8; SOCK_PATH_MAX]) -> Result<usize> {
    // Span-verify the full window we may read against the process's backed
    // user mapping so a low/non-canonical/boundary pointer faults here as
    // EINVAL rather than triggering a #GP or a ring-0 fault inside the byte
    // loop below. The kernel only reads here, so `write = false`.
    crate::uaccess::verify_user_access(path_ptr, SOCK_PATH_MAX as u64, false)?;
    // SAFETY: caller guarantees `path_ptr` is below the kernel canonical boundary.
    unsafe {
        let base = path_ptr as *const u8;
        for (i, slot) in buf.iter_mut().enumerate() {
            let byte = base.add(i).read_volatile();
            if byte == 0 {
                return Ok(i);
            }
            *slot = byte;
        }
    }
    Err(Error::InvalidArgument) // path too long
}

/// Kernel handler for `SYS_SOCKET` (Linux number 41).
///
/// POSIX.1-2024 `socket(3p)` semantics.
/// - `domain` — address family (only `AF_UNIX` / 1 supported).
/// - `sock_type` — `SOCK_STREAM` (1) or `SOCK_DGRAM` (2).
/// - `protocol` — ignored (must be 0 for Unix sockets).
///
/// Returns the new fd number on success, or a negative errno.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn sys_socket(domain: u64, sock_type: u64, _protocol: u64) -> i64 {
    let domain = match SocketDomain::from_raw(domain as u32) {
        Ok(d) => d,
        Err(_) => return -97, // EAFNOSUPPORT
    };
    let sock_type = match SockType::from_raw(sock_type as u32 & 0xF) {
        Ok(t) => t,
        Err(_) => return -22, // EINVAL
    };

    // Allocate a socket slot.
    // SAFETY: Single-CPU SYSCALL context.
    let handle_id = unsafe {
        #[allow(static_mut_refs)]
        match SOCKET_TABLE.create(domain, sock_type) {
            Ok(id) => id as u32,
            Err(_) => return -24, // EMFILE
        }
    };

    // Install an fd for this socket.
    let handle = crate::fd_table::FileHandle {
        backend: crate::fd_table::FileBackend::Socket { handle_id },
        offset: 0,
        flags: crate::fd_table::HandleFlags::RDWR,
    };
    // SAFETY: Single-CPU SYSCALL context.
    match unsafe { crate::fd_table::fd_install(handle) } {
        Ok(fd) => fd as i64,
        Err(_) => {
            // Roll back socket allocation.
            unsafe {
                #[allow(static_mut_refs)]
                let _ = SOCKET_TABLE.close(handle_id as usize);
            }
            -24 // EMFILE
        }
    }
}

/// Kernel handler for `SYS_BIND` (Linux number 49).
///
/// POSIX.1-2024 `bind(3p)` — binds a socket to a local address.
///
/// For Phase 18, only `sockaddr_un` (Unix paths) are supported.
/// The `addr_ptr` must point to a structure whose first two bytes
/// are the address family (little-endian `u16`) followed by the
/// null-terminated path.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn sys_bind(sockfd: u64, addr_ptr: u64, _addrlen: u64) -> i64 {
    // Span-verify the 2-byte family read against the backed user mapping
    // before dereferencing. The kernel reads here, so `write = false`.
    if crate::uaccess::verify_user_access(addr_ptr, 2, false).is_err() {
        return -14; // EFAULT
    }

    // Read address family (first 2 bytes of sockaddr).
    // SAFETY: validated above.
    let family = unsafe { (addr_ptr as *const u16).read_volatile() };
    if family != 1 {
        return -97; // EAFNOSUPPORT
    }

    // Read the Unix path (bytes 2..2+SOCK_PATH_MAX). Use checked_add so the
    // path base cannot wrap past the address space.
    let path_ptr = match addr_ptr.checked_add(2) {
        Some(p) => p,
        None => return -14, // EFAULT
    };
    let mut path_buf = [0u8; SOCK_PATH_MAX];
    let path_len = unsafe {
        match copy_socket_path(path_ptr, &mut path_buf) {
            Ok(n) => n,
            Err(_) => return -22, // EINVAL
        }
    };

    let addr = match SocketAddr::from_bytes(&path_buf[..path_len]) {
        Ok(a) => a,
        Err(_) => return -22,
    };

    // Resolve fd → handle_id.
    let handle_id = match get_socket_fd(sockfd) {
        Some(id) => id,
        None => return -9, // EBADF
    };

    // SAFETY: Single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        match SOCKET_TABLE.bind(handle_id as usize, addr) {
            Ok(()) => 0,
            Err(Error::AlreadyExists) => -98, // EADDRINUSE
            Err(_) => -22,                    // EINVAL
        }
    }
}

/// Kernel handler for `SYS_LISTEN` (Linux number 50).
///
/// POSIX.1-2024 `listen(3p)`.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn sys_listen(sockfd: u64, backlog: u64) -> i64 {
    let handle_id = match get_socket_fd(sockfd) {
        Some(id) => id,
        None => return -9, // EBADF
    };
    // SAFETY: Single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        match SOCKET_TABLE.listen(handle_id as usize, backlog as u32) {
            Ok(()) => 0,
            Err(_) => -22, // EINVAL
        }
    }
}

/// Kernel handler for `SYS_ACCEPT` (Linux number 43).
///
/// POSIX.1-2024 `accept(3p)` — accepts a pending connection and returns
/// a new fd for the connected socket.  The `addr_ptr` and `addrlen_ptr`
/// arguments are currently ignored (Phase 18; caller may pass NULL).
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn sys_accept(sockfd: u64, _addr_ptr: u64, _addrlen_ptr: u64) -> i64 {
    let handle_id = match get_socket_fd(sockfd) {
        Some(id) => id,
        None => return -9, // EBADF
    };

    // Block until a connection is pending.
    loop {
        // SAFETY: Single-CPU SYSCALL context.
        let result = unsafe {
            #[allow(static_mut_refs)]
            SOCKET_TABLE.accept(handle_id as usize)
        };
        match result {
            Ok(new_id) => {
                // Install an fd for the new connected socket.
                let new_handle = crate::fd_table::FileHandle {
                    backend: crate::fd_table::FileBackend::Socket {
                        handle_id: new_id as u32,
                    },
                    offset: 0,
                    flags: crate::fd_table::HandleFlags::RDWR,
                };
                // SAFETY: Single-CPU SYSCALL context.
                return match unsafe { crate::fd_table::fd_install(new_handle) } {
                    Ok(fd) => fd as i64,
                    Err(_) => {
                        // Roll back new socket.
                        unsafe {
                            #[allow(static_mut_refs)]
                            let _ = SOCKET_TABLE.close(new_id);
                        }
                        -24 // EMFILE
                    }
                };
            }
            Err(Error::WouldBlock) => {
                // No connection pending — yield and retry.
                // SAFETY: SYSCALL context.
                unsafe {
                    let _ = crate::current::yield_now();
                }
            }
            Err(_) => return -22, // EINVAL
        }
    }
}

/// Kernel handler for `SYS_CONNECT` (Linux number 42).
///
/// POSIX.1-2024 `connect(3p)`.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn sys_connect(sockfd: u64, addr_ptr: u64, _addrlen: u64) -> i64 {
    // Span-verify the 2-byte family read against the backed user mapping
    // before dereferencing. The kernel reads here, so `write = false`.
    if crate::uaccess::verify_user_access(addr_ptr, 2, false).is_err() {
        return -14; // EFAULT
    }

    // Read address family.
    // SAFETY: validated above.
    let family = unsafe { (addr_ptr as *const u16).read_volatile() };
    if family != 1 {
        return -97; // EAFNOSUPPORT
    }

    // Use checked_add so the path base cannot wrap past the address space.
    let path_ptr = match addr_ptr.checked_add(2) {
        Some(p) => p,
        None => return -14, // EFAULT
    };
    let mut path_buf = [0u8; SOCK_PATH_MAX];
    let path_len = unsafe {
        match copy_socket_path(path_ptr, &mut path_buf) {
            Ok(n) => n,
            Err(_) => return -22,
        }
    };
    let addr = match SocketAddr::from_bytes(&path_buf[..path_len]) {
        Ok(a) => a,
        Err(_) => return -22,
    };

    let handle_id = match get_socket_fd(sockfd) {
        Some(id) => id,
        None => return -9,
    };
    // SAFETY: Single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        match SOCKET_TABLE.connect(handle_id as usize, addr) {
            Ok(()) => 0,
            Err(Error::NotFound) => -111, // ECONNREFUSED
            Err(_) => -22,
        }
    }
}

/// Kernel handler for `SYS_SENDTO` (Linux number 44).
///
/// For connected sockets this is equivalent to `send(2)`.  The
/// `dest_addr` and `addrlen` arguments are ignored for connected sockets.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn sys_sendto(
    sockfd: u64,
    buf_ptr: u64,
    len: u64,
    flags: u64,
    _dest: u64,
    _dlen: u64,
) -> i64 {
    /// `MSG_NOSIGNAL` — suppress `SIGPIPE` on a broken-pipe write.
    const MSG_NOSIGNAL: u64 = 0x4000;
    /// Upper bound on `WouldBlock` retries before yielding control back to
    /// the caller as `EAGAIN`. A peer that never drains its buffer must not
    /// pin this CPU forever (DoS); bounding the spin guarantees forward
    /// progress for other work.
    const MAX_SPINS: u32 = 4096;

    let count = (len as usize).min(4096);
    // Span-verify exactly the clamped window we will read against the backed
    // user mapping so a low/non-canonical/boundary pointer faults here as
    // EFAULT rather than in the byte loop. The kernel reads here (`write =
    // false`).
    if crate::uaccess::verify_user_access(buf_ptr, count as u64, false).is_err() {
        return -14; // EFAULT
    }
    let handle_id = match get_socket_fd(sockfd) {
        Some(id) => id,
        None => return -9,
    };
    let nonblock = socket_fd_nonblock(sockfd);

    let mut kbuf = [0u8; 4096];
    // SAFETY: `buf_ptr` validated above; reading `count` bytes.
    unsafe {
        let ptr = buf_ptr as *const u8;
        for (i, b) in kbuf[..count].iter_mut().enumerate() {
            *b = ptr.add(i).read_volatile();
        }
    }

    let mut spins: u32 = 0;
    loop {
        // SAFETY: Single-CPU SYSCALL context.
        let result = unsafe {
            #[allow(static_mut_refs)]
            SOCKET_TABLE.send(handle_id as usize, &kbuf[..count])
        };
        match result {
            Ok(n) => return n as i64,
            // The peer has closed: raise SIGPIPE (unless suppressed) and fail
            // with EPIPE rather than spinning on a buffer no one will drain.
            Err(Error::Busy) => {
                if flags & MSG_NOSIGNAL == 0 {
                    raise_sigpipe();
                }
                return -32; // EPIPE
            }
            Err(Error::WouldBlock) => {
                if nonblock {
                    return -11; // EAGAIN
                }
                spins = spins.saturating_add(1);
                if spins >= MAX_SPINS {
                    return -11; // EAGAIN — bounded spin, surrender the CPU
                }
                // SAFETY: SYSCALL context.
                unsafe {
                    let _ = crate::current::yield_now();
                }
            }
            Err(_) => return -22,
        }
    }
}

/// Kernel handler for `SYS_RECVFROM` (Linux number 45).
///
/// For connected sockets this is equivalent to `recv(2)`.  The
/// `src_addr` and `addrlen` arguments are ignored.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn sys_recvfrom(
    sockfd: u64,
    buf_ptr: u64,
    len: u64,
    _flags: u64,
    _src: u64,
    _slen: u64,
) -> i64 {
    let count = (len as usize).min(4096);
    // Span-verify exactly the clamped window we may write against the backed
    // user mapping so a low/non-canonical/boundary pointer faults here as
    // EFAULT rather than in the write loop. At most `count` bytes (`n <=
    // count`) are written, so this span fully covers it. The kernel writes
    // here (`write = true`).
    if crate::uaccess::verify_user_access(buf_ptr, count as u64, true).is_err() {
        return -14; // EFAULT
    }
    let handle_id = match get_socket_fd(sockfd) {
        Some(id) => id,
        None => return -9,
    };
    let nonblock = socket_fd_nonblock(sockfd);

    let user_ptr = buf_ptr as *mut u8;
    loop {
        let mut kbuf = [0u8; 4096];
        // SAFETY: Single-CPU SYSCALL context.
        let result = unsafe {
            #[allow(static_mut_refs)]
            SOCKET_TABLE.recv(handle_id as usize, &mut kbuf[..count])
        };
        match result {
            Ok(n) if n > 0 => {
                // SAFETY: `buf_ptr` validated above; writing `n` bytes.
                unsafe {
                    for (i, &byte) in kbuf.iter().take(n).enumerate() {
                        user_ptr.add(i).write_volatile(byte);
                    }
                }
                return n as i64;
            }
            // `recv` reports `Ok(0)` only when the buffer is empty *and* the
            // peer has closed: that is end-of-stream, so return EOF instead of
            // yielding forever.
            Ok(_) => return 0,
            // Buffer empty, peer still open: block (or EAGAIN if non-blocking).
            Err(Error::WouldBlock) => {
                if nonblock {
                    return -11; // EAGAIN
                }
                // SAFETY: SYSCALL context.
                unsafe {
                    let _ = crate::current::yield_now();
                }
            }
            Err(_) => return -22,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Resolve an fd number to the socket `handle_id` it references.
///
/// Returns `None` if the fd is not open or does not back a socket.
fn get_socket_fd(fd: u64) -> Option<u32> {
    // SAFETY: Single-CPU SYSCALL context.
    let handle = unsafe { crate::fd_table::fd_get(fd as usize)? };
    if let crate::fd_table::FileBackend::Socket { handle_id } = handle.backend {
        Some(handle_id)
    } else {
        None
    }
}

/// Return `true` if `fd` was opened with `O_NONBLOCK`.
///
/// Used by `sys_sendto` / `sys_recvfrom` to choose between blocking (yield
/// and retry) and returning `EAGAIN`. A missing or non-socket fd is treated
/// as blocking (`false`); the caller has already validated the fd via
/// [`get_socket_fd`].
fn socket_fd_nonblock(fd: u64) -> bool {
    // SAFETY: Single-CPU SYSCALL context.
    match unsafe { crate::fd_table::fd_get(fd as usize) } {
        Some(handle) => handle.flags.is_nonblock(),
        None => false,
    }
}

/// Best-effort `SIGPIPE` delivery to the current thread on a broken-pipe
/// write.
///
/// POSIX requires a write to a socket whose reading end has closed to raise
/// `SIGPIPE` (unless `MSG_NOSIGNAL` is set) in addition to failing with
/// `EPIPE`. Posting a signal to the current thread requires the signal
/// subsystem's per-thread pending state, which is owned outside this module;
/// until that wiring lands this is a deliberate no-op. The `EPIPE` return
/// value is the load-bearing, in-lane part of the contract and is always
/// honoured by the caller.
fn raise_sigpipe() {
    // Intentionally a no-op: see the doc comment. Kept as a named hook so the
    // signal owners can wire delivery without touching the send path.
}
