// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Individual system call handler implementations.
//!
//! Each handler validates user-space arguments and delegates to the
//! appropriate kernel subsystem. Returns a `SyscallResult` that is
//! passed back to user space in the RAX register.

use oncrix_lib::Error;

/// Syscall return value (matches Linux convention: >= 0 success, < 0 error).
pub type SyscallResult = i64;

/// Convert a kernel error to a negative errno.
pub fn error_to_errno(err: Error) -> SyscallResult {
    match err {
        Error::NotFound => -2,          // ENOENT
        Error::PermissionDenied => -13, // EACCES
        Error::OutOfMemory => -12,      // ENOMEM
        Error::InvalidArgument => -22,  // EINVAL
        Error::AlreadyExists => -17,    // EEXIST
        Error::WouldBlock => -11,       // EAGAIN
        Error::Busy => -16,             // EBUSY
        Error::NotImplemented => -38,   // ENOSYS
        Error::Interrupted => -4,       // EINTR
        Error::IoError => -5,           // EIO
    }
}

/// `SYS_EXIT` — Terminate the calling process.
pub fn sys_exit(_status: u64) -> SyscallResult {
    // Stub: in a full implementation this would mark the current
    // process as exited and trigger a reschedule.
    0
}

/// `SYS_GETPID` — Get current process ID.
pub fn sys_getpid() -> SyscallResult {
    // Stub: return kernel PID 0 for now.
    0
}

/// `SYS_WRITE` — Write to a file descriptor.
pub fn sys_write(_fd: u64, _buf: u64, _count: u64) -> SyscallResult {
    // Stub: TODO(#issue) — validate user pointer, dispatch to VFS.
    error_to_errno(Error::NotImplemented)
}

/// `SYS_READ` — Read from a file descriptor.
pub fn sys_read(_fd: u64, _buf: u64, _count: u64) -> SyscallResult {
    // Stub: TODO(#issue) — validate user pointer, dispatch to VFS.
    error_to_errno(Error::NotImplemented)
}

/// `SYS_OPEN` — Open a file.
pub fn sys_open(_pathname: u64, _flags: u64, _mode: u64) -> SyscallResult {
    error_to_errno(Error::NotImplemented)
}

/// `SYS_CLOSE` — Close a file descriptor.
pub fn sys_close(_fd: u64) -> SyscallResult {
    error_to_errno(Error::NotImplemented)
}

/// `SYS_BRK` — Change data segment size.
pub fn sys_brk(_addr: u64) -> SyscallResult {
    error_to_errno(Error::NotImplemented)
}

/// `SYS_MMAP` — Map memory.
///
/// Arguments (x86_64 SYSCALL convention):
/// - `addr`: requested mapping address (0 = kernel chooses)
/// - `length`: mapping size in bytes (rounded up to page boundary)
/// - `prot`: protection flags (PROT_READ/WRITE/EXEC)
/// - `flags`: MAP_PRIVATE|MAP_SHARED, MAP_ANONYMOUS, MAP_FIXED
/// - `fd`: file descriptor (ignored for MAP_ANONYMOUS)
/// - `offset`: file offset (ignored for MAP_ANONYMOUS)
///
/// Returns the mapped address on success, or negative errno.
///
/// Implementation uses `oncrix_kernel::mmap::do_mmap()` for region
/// allocation. Full integration requires the current process's
/// AddressSpace and page fault handler for lazy page allocation.
pub fn sys_mmap(
    addr: u64,
    length: u64,
    _prot: u64,
    _flags: u64,
    _fd: u64,
    _offset: u64,
) -> SyscallResult {
    // Basic validation before delegating to kernel mmap logic.
    if length == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Reject kernel-space addresses.
    if addr >= 0xFFFF_8000_0000_0000 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: full implementation requires current process's AddressSpace.
    // When connected:
    //   1. Get current process AddressSpace
    //   2. Call do_mmap(space, addr, length, prot, flags, fd, offset)
    //   3. Return mapped address on success
    error_to_errno(Error::NotImplemented)
}

/// `SYS_FORK` — Create a child process.
pub fn sys_fork() -> SyscallResult {
    error_to_errno(Error::NotImplemented)
}

/// `SYS_EXECVE` — Replace the current process image with a new program.
///
/// Arguments:
/// - `pathname`: user pointer to null-terminated path string
/// - `argv`: user pointer to null-terminated array of string pointers (ignored for now)
/// - `envp`: user pointer to null-terminated array of string pointers (ignored for now)
///
/// On success, does not return (the old process image is replaced).
/// On failure, returns a negative errno.
pub fn sys_execve(pathname: u64, _argv: u64, _envp: u64) -> SyscallResult {
    // Validate pathname pointer.
    if pathname == 0 {
        return error_to_errno(Error::InvalidArgument);
    }

    // Stub: In a full implementation, this would:
    // 1. Copy the pathname from user space (validate_user_string + copy_from_user)
    // 2. Resolve the path via VFS to locate the ELF binary
    // 3. Read the ELF data into a kernel buffer
    // 4. Call prepare_exec() to parse ELF and set up address space
    // 5. Tear down the old address space (unmap all user regions)
    // 6. Map the new segments into the process's page tables
    // 7. Reset signal handlers to SIG_DFL (except SIG_IGN)
    // 8. Close O_CLOEXEC file descriptors
    // 9. Set up the new user stack with argc/argv/envp
    // 10. Update the process entry in the global process table
    // 11. Return to user space at the new entry point
    //
    // Steps 1-4 are implemented; 5-11 require VFS read integration
    // and page table manipulation that are not yet connected.
    error_to_errno(Error::NotImplemented)
}

// ── Socket syscalls ─────────────────────────────────────────────

/// `SYS_SOCKET` — Create a socket.
///
/// Arguments:
/// - `domain`: address family (`AF_LOCAL` = 1)
/// - `sock_type`: socket type (`SOCK_STREAM` = 1, `SOCK_DGRAM` = 2)
/// - `protocol`: protocol (must be 0 for Unix domain sockets)
///
/// Returns a socket file descriptor on success, or negative errno.
/// Stub: full implementation requires global `SocketRegistry` access.
pub fn sys_socket(domain: u64, sock_type: u64, protocol: u64) -> SyscallResult {
    // AF_LOCAL only.
    if domain != 1 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Protocol must be 0 for Unix sockets.
    if protocol != 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Validate socket type (1 = STREAM, 2 = DGRAM).
    if sock_type != 1 && sock_type != 2 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would call SocketRegistry::create(domain, sock_type).
    error_to_errno(Error::NotImplemented)
}

/// `SYS_BIND` — Bind a socket to a local address.
///
/// Arguments:
/// - `sockfd`: socket file descriptor
/// - `addr`: user pointer to `struct sockaddr_un`
/// - `addrlen`: size of the address structure
///
/// Returns 0 on success, or negative errno.
pub fn sys_bind(sockfd: u64, addr: u64, addrlen: u64) -> SyscallResult {
    if sockfd > 255 {
        return error_to_errno(Error::InvalidArgument);
    }
    if addr == 0 || addrlen == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would copy sockaddr_un from user space, call SocketRegistry::bind.
    error_to_errno(Error::NotImplemented)
}

/// `SYS_LISTEN` — Mark a socket as listening for connections.
///
/// Arguments:
/// - `sockfd`: socket file descriptor
/// - `backlog`: maximum length of the pending connections queue
///
/// Returns 0 on success, or negative errno.
pub fn sys_listen(sockfd: u64, backlog: u64) -> SyscallResult {
    if sockfd > 255 {
        return error_to_errno(Error::InvalidArgument);
    }
    let _ = backlog;
    // Stub: would call SocketRegistry::listen(sockfd, backlog).
    error_to_errno(Error::NotImplemented)
}

/// `SYS_ACCEPT` — Accept a connection on a listening socket.
///
/// Arguments:
/// - `sockfd`: listening socket file descriptor
/// - `addr`: user pointer for the peer's address (may be null)
/// - `addrlen`: user pointer for the address length (may be null)
///
/// Returns a new socket file descriptor on success, or negative errno.
pub fn sys_accept(sockfd: u64, _addr: u64, _addrlen: u64) -> SyscallResult {
    if sockfd > 255 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would call SocketRegistry::accept(sockfd).
    error_to_errno(Error::NotImplemented)
}

/// `SYS_CONNECT` — Connect a socket to a remote address.
///
/// Arguments:
/// - `sockfd`: socket file descriptor
/// - `addr`: user pointer to target `struct sockaddr_un`
/// - `addrlen`: size of the address structure
///
/// Returns 0 on success, or negative errno.
pub fn sys_connect(sockfd: u64, addr: u64, addrlen: u64) -> SyscallResult {
    if sockfd > 255 {
        return error_to_errno(Error::InvalidArgument);
    }
    if addr == 0 || addrlen == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would copy sockaddr_un from user space, call SocketRegistry::connect.
    error_to_errno(Error::NotImplemented)
}

/// `SYS_SENDTO` — Send data through a socket.
///
/// Arguments:
/// - `sockfd`: socket file descriptor
/// - `buf`: user pointer to data buffer
/// - `len`: number of bytes to send
/// - `flags`: send flags (ignored for now)
/// - `dest_addr`: destination address (ignored for connected sockets)
/// - `addrlen`: size of destination address
///
/// Returns the number of bytes sent, or negative errno.
pub fn sys_sendto(
    sockfd: u64,
    buf: u64,
    len: u64,
    _flags: u64,
    _dest_addr: u64,
    _addrlen: u64,
) -> SyscallResult {
    if sockfd > 255 {
        return error_to_errno(Error::InvalidArgument);
    }
    if buf == 0 && len > 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would copy data from user space, call SocketRegistry::send.
    error_to_errno(Error::NotImplemented)
}

/// `SYS_RECVFROM` — Receive data from a socket.
///
/// Arguments:
/// - `sockfd`: socket file descriptor
/// - `buf`: user pointer to receive buffer
/// - `len`: maximum number of bytes to receive
/// - `flags`: receive flags (ignored for now)
/// - `src_addr`: user pointer for source address (may be null)
/// - `addrlen`: user pointer for address length (may be null)
///
/// Returns the number of bytes received, or negative errno.
pub fn sys_recvfrom(
    sockfd: u64,
    buf: u64,
    len: u64,
    _flags: u64,
    _src_addr: u64,
    _addrlen: u64,
) -> SyscallResult {
    if sockfd > 255 {
        return error_to_errno(Error::InvalidArgument);
    }
    if buf == 0 && len > 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would call SocketRegistry::recv, copy data to user space.
    error_to_errno(Error::NotImplemented)
}

/// `SYS_SOCKETPAIR` — Create a pair of connected sockets.
///
/// Arguments:
/// - `domain`: address family (`AF_LOCAL` = 1)
/// - `sock_type`: socket type (`SOCK_STREAM` = 1, `SOCK_DGRAM` = 2)
/// - `protocol`: protocol (must be 0)
/// - `sv`: user pointer to `[i32; 2]` for the two file descriptors
///
/// Returns 0 on success, or negative errno.
pub fn sys_socketpair(domain: u64, sock_type: u64, protocol: u64, sv: u64) -> SyscallResult {
    if domain != 1 {
        return error_to_errno(Error::InvalidArgument);
    }
    if protocol != 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    if sock_type != 1 && sock_type != 2 {
        return error_to_errno(Error::InvalidArgument);
    }
    if sv == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would call SocketRegistry::socketpair, write fds to user space.
    error_to_errno(Error::NotImplemented)
}

// ── poll/select syscalls ────────────────────────────────────────

/// `SYS_POLL` — Wait for events on a set of file descriptors.
///
/// Arguments:
/// - `fds`: user pointer to array of `struct pollfd`
/// - `nfds`: number of entries in the `fds` array
/// - `timeout`: timeout in milliseconds (-1 = block, 0 = immediate)
///
/// Returns the number of fds with non-zero `revents`, 0 on timeout,
/// or negative errno on error.
///
/// Stub: full implementation requires copy_from_user/copy_to_user
/// for the pollfd array and scheduler integration for blocking.
pub fn sys_poll(fds: u64, nfds: u64, _timeout: u64) -> SyscallResult {
    if fds == 0 && nfds > 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    if nfds > 1024 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would copy pollfd array from user space,
    // call oncrix_kernel::poll::do_poll(), then copy back.
    error_to_errno(Error::NotImplemented)
}

/// `SYS_SELECT` — Synchronous I/O multiplexing.
///
/// Arguments:
/// - `nfds`: one more than the highest fd to check
/// - `readfds`: user pointer to read fd_set (may be null)
/// - `writefds`: user pointer to write fd_set (may be null)
/// - `exceptfds`: user pointer to except fd_set (may be null)
/// - `timeout`: user pointer to `struct timeval` (may be null)
///
/// Returns the total number of ready fds across all three sets,
/// 0 on timeout, or negative errno on error.
///
/// Stub: full implementation requires copy_from_user/copy_to_user
/// for the fd_set bitmaps and scheduler integration for blocking.
pub fn sys_select(
    nfds: u64,
    _readfds: u64,
    _writefds: u64,
    _exceptfds: u64,
    _timeout: u64,
) -> SyscallResult {
    if nfds > 1024 {
        return error_to_errno(Error::InvalidArgument);
    }
    // At least one fd set must be non-null.
    if _readfds == 0 && _writefds == 0 && _exceptfds == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would copy fd_set bitmaps from user space,
    // call oncrix_kernel::poll::do_select(), then copy back.
    error_to_errno(Error::NotImplemented)
}

// ── epoll syscalls ──────────────────────────────────────────────

/// `SYS_EPOLL_CREATE1` — Create an epoll instance.
///
/// Arguments:
/// - `flags`: flags (currently must be 0; `EPOLL_CLOEXEC` = 0x80000
///   is accepted but not enforced yet)
///
/// Returns a non-negative epoll file descriptor on success, or
/// negative errno on failure.
///
/// Stub: full implementation requires a global `EpollRegistry`.
pub fn sys_epoll_create1(_flags: u64) -> SyscallResult {
    // Only 0 and EPOLL_CLOEXEC (0x80000) are valid flags.
    if _flags != 0 && _flags != 0x80000 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would call EpollRegistry::create().
    error_to_errno(Error::NotImplemented)
}

/// `SYS_EPOLL_CTL` — Control an epoll instance.
///
/// Arguments:
/// - `epfd`: epoll file descriptor (from `epoll_create1`)
/// - `op`: operation (`EPOLL_CTL_ADD`=1, `_DEL`=2, `_MOD`=3)
/// - `fd`: target file descriptor to add/modify/remove
/// - `event`: user pointer to `struct epoll_event` (ignored for DEL)
///
/// Returns 0 on success, or negative errno.
pub fn sys_epoll_ctl(epfd: u64, op: u64, fd: u64, _event: u64) -> SyscallResult {
    if epfd > 255 || fd > 255 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Validate operation code (1..=3).
    if op == 0 || op > 3 {
        return error_to_errno(Error::InvalidArgument);
    }
    // DEL does not require an event pointer; ADD/MOD do.
    if op != 2 && _event == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would look up EpollInstance via EpollRegistry::get_mut(epfd),
    // copy_from_user the EpollEvent, then call add/modify/delete.
    error_to_errno(Error::NotImplemented)
}

/// `SYS_EPOLL_WAIT` — Wait for I/O events on an epoll instance.
///
/// Arguments:
/// - `epfd`: epoll file descriptor
/// - `events`: user pointer to output `struct epoll_event` array
/// - `maxevents`: maximum number of events to return (must be > 0)
/// - `timeout`: timeout in milliseconds (-1 = block indefinitely,
///   0 = return immediately)
///
/// Returns the number of ready file descriptors, 0 on timeout, or
/// negative errno.
pub fn sys_epoll_wait(epfd: u64, events: u64, maxevents: u64, _timeout: u64) -> SyscallResult {
    if epfd > 255 {
        return error_to_errno(Error::InvalidArgument);
    }
    if events == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    if maxevents == 0 || maxevents > 1024 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would call EpollRegistry::get_mut(epfd),
    // then EpollInstance::wait(), copy_to_user the results.
    error_to_errno(Error::NotImplemented)
}

// ── IPC syscalls ────────────────────────────────────────────────

/// `SYS_IPC_SEND` — Send an IPC message.
///
/// Arguments: endpoint_id (u64), msg_ptr (user pointer to Message).
/// For now, validates arguments but returns NotImplemented since
/// the full user-pointer validation is not yet available.
pub fn sys_ipc_send(_endpoint_id: u64, _msg_ptr: u64) -> SyscallResult {
    error_to_errno(Error::NotImplemented)
}

/// `SYS_IPC_RECEIVE` — Receive an IPC message.
pub fn sys_ipc_receive(_endpoint_id: u64, _msg_ptr: u64) -> SyscallResult {
    error_to_errno(Error::NotImplemented)
}

/// `SYS_IPC_REPLY` — Reply to an IPC call.
pub fn sys_ipc_reply(_endpoint_id: u64, _msg_ptr: u64) -> SyscallResult {
    error_to_errno(Error::NotImplemented)
}

/// `SYS_IPC_CALL` — Synchronous IPC call (send + receive).
pub fn sys_ipc_call(_endpoint_id: u64, _msg_ptr: u64) -> SyscallResult {
    error_to_errno(Error::NotImplemented)
}

/// `SYS_IPC_CREATE_ENDPOINT` — Create a new IPC endpoint.
///
/// Returns the new endpoint ID on success.
pub fn sys_ipc_create_endpoint() -> SyscallResult {
    error_to_errno(Error::NotImplemented)
}

// ── Signal syscalls ─────────────────────────────────────────────

/// `SYS_KILL` — Send a signal to a process.
///
/// Arguments: pid (target process), sig (signal number).
pub fn sys_kill(_pid: u64, _sig: u64) -> SyscallResult {
    // Validate signal number range (1-32).
    if _sig == 0 || _sig > 32 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would look up the target process and call signal.send().
    error_to_errno(Error::NotImplemented)
}

/// `SYS_WAIT4` — Wait for process state change.
///
/// Arguments:
/// - `pid`: target PID (>0 = specific, -1 = any child)
/// - `wstatus`: user pointer to `i32` for exit status (may be null)
/// - `options`: `WNOHANG` (1) to return immediately if no zombie
/// - `rusage`: user pointer to rusage struct (ignored for now)
///
/// Returns the PID of the reaped child, or 0 if WNOHANG and no zombie.
///
/// Implementation uses `oncrix_kernel::wait::do_wait4()` which handles
/// POSIX wstatus encoding and zombie reaping from the ProcessTable.
/// Full integration requires the global process table singleton and
/// copy_to_user for writing wstatus to user space.
pub fn sys_wait4(pid: u64, _wstatus: u64, _options: u64, _rusage: u64) -> SyscallResult {
    // Validate: pid must be > 0 or == -1 (as i64).
    let pid_i64 = pid as i64;
    if pid_i64 == 0 || pid_i64 < -1 {
        // Process group waits not yet supported.
        return error_to_errno(Error::NotImplemented);
    }
    // Stub: full implementation requires global ProcessTable access.
    // When connected:
    //   1. Get current process PID (caller)
    //   2. Call do_wait4(&mut PROCESS_TABLE, caller, pid_i64, options)
    //   3. On success: copy wstatus to user space, return child PID
    //   4. On WouldBlock with WNOHANG: return 0
    //   5. On WouldBlock without WNOHANG: block caller, reschedule
    error_to_errno(Error::NotImplemented)
}

/// `SYS_SIGACTION` — Examine and change a signal action.
///
/// Arguments: sig, act_ptr (new action), oldact_ptr (old action).
/// ONCRIX extension syscall number.
pub fn sys_sigaction(_sig: u64, _act: u64, _oldact: u64) -> SyscallResult {
    if _sig == 0 || _sig > 32 {
        return error_to_errno(Error::InvalidArgument);
    }
    // SIGKILL and SIGSTOP cannot be caught.
    if _sig == 9 || _sig == 19 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would read/write SignalAction from/to user pointers.
    error_to_errno(Error::NotImplemented)
}

/// `SYS_RT_SIGRETURN` — Return from a signal handler.
///
/// Restores the saved register context and signal mask from the
/// `SignalFrame` that was pushed onto the user stack during signal
/// delivery. The frame pointer is taken from the current RSP.
///
/// This syscall does not return in the normal sense; on success
/// the kernel resumes execution at the saved RIP with the saved
/// register state.
pub fn sys_rt_sigreturn(_rsp: u64) -> SyscallResult {
    // Stub: a full implementation reads the SignalFrame from the
    // user stack (at _rsp), restores registers and signal mask
    // via oncrix_kernel::signal_deliver::do_sigreturn(), then
    // resumes the interrupted context instead of returning here.
    error_to_errno(Error::NotImplemented)
}

// ── Device control ───────────────────────────────────────────

/// Well-known ioctl request numbers.
pub mod ioctl_nr {
    /// Get terminal window size.
    pub const TIOCGWINSZ: u64 = 0x5413;
    /// Set terminal window size.
    pub const TIOCSWINSZ: u64 = 0x5414;
    /// Get terminal attributes.
    pub const TCGETS: u64 = 0x5401;
    /// Set terminal attributes.
    pub const TCSETS: u64 = 0x5402;
    /// Check if fd refers to a terminal.
    pub const TIOCISATTY: u64 = 0x5480;
    /// Get block device size in bytes.
    pub const BLKGETSIZE64: u64 = 0x80081272;
    /// Get block device sector size.
    pub const BLKSSZGET: u64 = 0x1268;
    /// Flush block device buffers.
    pub const BLKFLSBUF: u64 = 0x1261;
    /// Generic: get flags.
    pub const FIONREAD: u64 = 0x541B;
}

/// Terminal window size (`struct winsize`), used by `TIOCGWINSZ`/`TIOCSWINSZ`.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Winsize {
    /// Number of rows.
    pub ws_row: u16,
    /// Number of columns.
    pub ws_col: u16,
    /// Horizontal pixel size (unused, set to 0).
    pub ws_xpixel: u16,
    /// Vertical pixel size (unused, set to 0).
    pub ws_ypixel: u16,
}

impl Winsize {
    /// Default terminal size (80x25).
    pub const DEFAULT: Self = Self {
        ws_row: 25,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
}

/// Simplified terminal attributes (`struct termios` subset).
///
/// Provides the minimum fields needed for `TCGETS`/`TCSETS` to work
/// with basic programs that query terminal settings.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Termios {
    /// Input mode flags.
    pub c_iflag: u32,
    /// Output mode flags.
    pub c_oflag: u32,
    /// Control mode flags.
    pub c_cflag: u32,
    /// Local mode flags.
    pub c_lflag: u32,
    /// Line discipline.
    pub c_line: u8,
    /// Control characters.
    pub c_cc: [u8; 32],
    /// Input baud rate.
    pub c_ispeed: u32,
    /// Output baud rate.
    pub c_ospeed: u32,
}

impl Termios {
    /// Sensible defaults (cooked mode, echo on, 115200 baud).
    pub const DEFAULT: Self = Self {
        c_iflag: 0x0500, // ICRNL | IXON
        c_oflag: 0x0005, // OPOST | ONLCR
        c_cflag: 0x00BF, // CS8 | CREAD | HUPCL | B115200
        c_lflag: 0x8A3B, // ECHO | ECHOE | ECHOK | ISIG | ICANON | IEXTEN
        c_line: 0,
        c_cc: [0; 32],
        c_ispeed: 115200,
        c_ospeed: 115200,
    };
}

/// `SYS_IOCTL` — Device-specific control operations.
///
/// Arguments:
/// - `fd`: file descriptor
/// - `request`: ioctl request number (device-specific)
/// - `arg`: optional argument (typically a user pointer)
///
/// Returns 0 on success, or negative errno.
/// The actual behavior depends on the device type behind `fd`.
///
/// For now, file descriptors 0/1/2 (stdin/stdout/stderr) are treated
/// as a virtual TTY for compatibility with programs that call
/// `isatty()` or query terminal attributes.
pub fn sys_ioctl(fd: u64, request: u64, _arg: u64) -> SyscallResult {
    if fd > 255 {
        return error_to_errno(Error::InvalidArgument);
    }
    if request == 0 {
        return error_to_errno(Error::InvalidArgument);
    }

    // Dispatch based on fd type.
    // stdin/stdout/stderr → virtual TTY ioctl.
    if fd <= 2 {
        return ioctl_tty(request, _arg);
    }

    // For other fds, determine device type via FdTable lookup.
    // Stub: full implementation dispatches to devfs IoctlOps.
    error_to_errno(Error::NotImplemented)
}

/// Handle TTY-class ioctl requests.
fn ioctl_tty(request: u64, _arg: u64) -> SyscallResult {
    match request {
        ioctl_nr::TIOCGWINSZ => {
            // Stub: would copy_to_user Winsize::DEFAULT to arg.
            // For now return success — programs only check the return code
            // to determine if this fd is a TTY.
            if _arg == 0 {
                return error_to_errno(Error::InvalidArgument);
            }
            0
        }
        ioctl_nr::TIOCSWINSZ => {
            // Stub: would copy_from_user and store new winsize.
            if _arg == 0 {
                return error_to_errno(Error::InvalidArgument);
            }
            0
        }
        ioctl_nr::TCGETS => {
            // Stub: would copy_to_user Termios::DEFAULT to arg.
            if _arg == 0 {
                return error_to_errno(Error::InvalidArgument);
            }
            0
        }
        ioctl_nr::TCSETS => {
            // Stub: would copy_from_user and apply termios.
            if _arg == 0 {
                return error_to_errno(Error::InvalidArgument);
            }
            0
        }
        ioctl_nr::TIOCISATTY => {
            // fd 0-2 are always a TTY → return 0 (success).
            0
        }
        ioctl_nr::FIONREAD => {
            // Return 0 bytes available in read buffer.
            if _arg == 0 {
                return error_to_errno(Error::InvalidArgument);
            }
            0
        }
        _ => error_to_errno(Error::InvalidArgument),
    }
}

// ── File locking syscalls ──────────────────────────────────────

/// `SYS_FLOCK` — Apply or remove an advisory lock on an open file.
///
/// Arguments:
/// - `fd`: file descriptor of the open file
/// - `operation`: bitmask of `LOCK_SH` (1), `LOCK_EX` (2),
///   `LOCK_UN` (8), optionally OR-ed with `LOCK_NB` (4)
///
/// Returns 0 on success, or negative errno.
///
/// Stub: full implementation requires access to the current
/// process's fd table, the backing inode, and the global
/// `FileLockTable`.
pub fn sys_flock(fd: u64, operation: u64) -> SyscallResult {
    if fd > 255 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Validate that exactly one of SH/EX/UN is set (ignoring NB).
    let base = (operation as u32) & !4;
    if base != 1 && base != 2 && base != 8 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would look up the inode via fd table, then call
    // FileLockTable::flock_lock(inode, current_pid, operation).
    error_to_errno(Error::NotImplemented)
}

/// `SYS_FCNTL` — File control operations.
///
/// Arguments:
/// - `fd`: file descriptor
/// - `cmd`: command constant (e.g. `F_GETLK`, `F_SETLK`, `F_SETLKW`)
/// - `arg`: command-specific argument (value or user pointer)
///
/// Returns 0 on success for most commands, or the requested value
/// for query commands. Returns negative errno on failure.
///
/// Currently only advisory record locking commands (`F_GETLK`,
/// `F_SETLK`, `F_SETLKW`) are recognized; all others return
/// `ENOSYS`.
///
/// Stub: full implementation requires access to the current
/// process's fd table, the backing inode, the global
/// `FileLockTable`, and `copy_from_user`/`copy_to_user` for the
/// `struct flock` argument.
pub fn sys_fcntl(fd: u64, cmd: u64, arg: u64) -> SyscallResult {
    if fd > 255 {
        return error_to_errno(Error::InvalidArgument);
    }
    let cmd32 = cmd as u32;
    match cmd32 {
        // F_GETLK = 5
        5 => {
            if arg == 0 {
                return error_to_errno(Error::InvalidArgument);
            }
            // Stub: would copy_from_user a struct flock from arg,
            // call FileLockTable::fcntl_getlk(inode, &flock),
            // then copy_to_user the result back to arg.
            error_to_errno(Error::NotImplemented)
        }
        // F_SETLK = 6
        6 => {
            if arg == 0 {
                return error_to_errno(Error::InvalidArgument);
            }
            // Stub: would copy_from_user a struct flock from arg,
            // call FileLockTable::fcntl_setlk(inode, pid, &flock).
            error_to_errno(Error::NotImplemented)
        }
        // F_SETLKW = 7
        7 => {
            if arg == 0 {
                return error_to_errno(Error::InvalidArgument);
            }
            // Stub: would copy_from_user a struct flock, then call
            // fcntl_setlk in a loop, blocking the thread if
            // WouldBlock is returned, until the lock is acquired
            // or a signal interrupts.
            error_to_errno(Error::NotImplemented)
        }
        _ => error_to_errno(Error::NotImplemented),
    }
}

// ── File system syscalls ───────────────────────────────────────

/// `SYS_DUP2` — Duplicate a file descriptor.
///
/// Arguments: oldfd, newfd.
/// If newfd is already open, it is silently closed first.
pub fn sys_dup2(_oldfd: u64, _newfd: u64) -> SyscallResult {
    // Validate fd range (0..256).
    if _oldfd > 255 || _newfd > 255 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would call FdTable::dup2 on the current process.
    error_to_errno(Error::NotImplemented)
}

/// `SYS_PIPE` — Create a unidirectional pipe.
///
/// Arguments: pipefd_ptr (user pointer to `[i32; 2]`).
/// On success, pipefd[0] is the read end, pipefd[1] is the write end.
pub fn sys_pipe(_pipefd: u64) -> SyscallResult {
    // Validate the user pointer (must hold 2 × i32 = 8 bytes).
    if _pipefd == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would create a pipe, allocate two fds, write them
    // to user space via copy_to_user.
    error_to_errno(Error::NotImplemented)
}

/// `SYS_LSEEK` — Reposition file read/write offset.
///
/// Arguments: fd, offset, whence.
/// whence: 0 = SEEK_SET, 1 = SEEK_CUR, 2 = SEEK_END.
pub fn sys_lseek(_fd: u64, _offset: u64, _whence: u64) -> SyscallResult {
    if _fd > 255 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Validate whence.
    if _whence > 2 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would update OpenFile::offset in the fd table.
    error_to_errno(Error::NotImplemented)
}

/// POSIX `struct stat` layout for the stat/fstat syscalls.
///
/// This is a simplified version containing the essential fields.
/// The full POSIX stat has more fields (timestamps, etc.).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct StatBuf {
    /// Inode number.
    pub st_ino: u64,
    /// File mode (type + permissions).
    pub st_mode: u32,
    /// Number of hard links.
    pub st_nlink: u32,
    /// Owner UID.
    pub st_uid: u32,
    /// Owner GID.
    pub st_gid: u32,
    /// File size in bytes.
    pub st_size: u64,
}

/// `SYS_STAT` — Get file status by pathname.
///
/// Arguments: pathname_ptr (user pointer), statbuf_ptr (user pointer).
pub fn sys_stat(_pathname: u64, _statbuf: u64) -> SyscallResult {
    if _pathname == 0 || _statbuf == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would resolve pathname via VFS, fill StatBuf,
    // and copy_to_user.
    error_to_errno(Error::NotImplemented)
}

/// `SYS_FSTAT` — Get file status by file descriptor.
///
/// Arguments: fd, statbuf_ptr (user pointer).
pub fn sys_fstat(_fd: u64, _statbuf: u64) -> SyscallResult {
    if _fd > 255 {
        return error_to_errno(Error::InvalidArgument);
    }
    if _statbuf == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would look up the inode via fd table, fill StatBuf,
    // and copy_to_user.
    error_to_errno(Error::NotImplemented)
}

/// POSIX `struct linux_dirent64` layout for getdents64.
///
/// Each entry is variable-length; `d_reclen` gives the total size.
/// The name follows the fixed fields and is null-terminated.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct LinuxDirent64 {
    /// 64-bit inode number.
    pub d_ino: u64,
    /// Offset to next entry (opaque, for seekdir/telldir).
    pub d_off: u64,
    /// Size of this entire entry.
    pub d_reclen: u16,
    /// File type (DT_REG, DT_DIR, etc.).
    pub d_type: u8,
    // Followed by null-terminated d_name[].
}

/// File type constants for `d_type` in dirent.
pub mod d_type {
    /// Unknown.
    pub const DT_UNKNOWN: u8 = 0;
    /// Regular file.
    pub const DT_REG: u8 = 8;
    /// Directory.
    pub const DT_DIR: u8 = 4;
    /// Symbolic link.
    pub const DT_LNK: u8 = 10;
    /// Character device.
    pub const DT_CHR: u8 = 2;
    /// Block device.
    pub const DT_BLK: u8 = 6;
    /// Named pipe (FIFO).
    pub const DT_FIFO: u8 = 1;
    /// Socket.
    pub const DT_SOCK: u8 = 12;
}

/// `SYS_GETDENTS64` — Read directory entries.
///
/// Arguments:
/// - `fd`: file descriptor of an open directory
/// - `dirp`: user pointer to output buffer
/// - `count`: size of the output buffer in bytes
///
/// Returns the number of bytes written to the buffer, or 0 at end
/// of directory, or negative errno on error.
///
/// Each entry is a `LinuxDirent64` followed by a null-terminated name.
/// Entries are packed contiguously (respecting 8-byte alignment).
///
/// Implementation will:
/// 1. Look up the fd in the current process's FdTable
/// 2. Verify the inode is a directory
/// 3. Call the InodeOps readdir method
/// 4. Format entries into LinuxDirent64 structs in user buffer
/// 5. Update the file offset for subsequent calls
pub fn sys_getdents64(fd: u64, dirp: u64, count: u64) -> SyscallResult {
    if fd > 255 {
        return error_to_errno(Error::InvalidArgument);
    }
    if dirp == 0 || count == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Buffer must be large enough for at least one minimal entry.
    // sizeof(LinuxDirent64) = 19 + 1 (null byte) = 20, aligned to 24.
    if count < 24 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: full implementation requires:
    //   1. Current process FdTable access
    //   2. Directory inode readdir operation
    //   3. copy_to_user for writing dirent entries
    error_to_errno(Error::NotImplemented)
}

// ── Process control syscalls ───────────────────────────────────

/// `SYS_PRCTL` — Process control operations.
///
/// Arguments:
/// - `option`: the prctl option constant (e.g., `PR_SET_NAME`)
/// - `arg2`: option-specific argument (value or user pointer)
/// - `arg3`, `arg4`, `arg5`: reserved for future options
///
/// Returns 0 on success for SET operations, or the requested value
/// for GET operations. Returns negative errno on failure.
///
/// Stub: full implementation requires per-process `PrctlState`
/// from `oncrix_kernel::prctl` and `copy_from_user`/`copy_to_user`
/// for pointer-based options (`PR_SET_NAME`, `PR_GET_NAME`,
/// `PR_GET_PDEATHSIG`).
pub fn sys_prctl(_option: u64, _arg2: u64, _arg3: u64, _arg4: u64, _arg5: u64) -> SyscallResult {
    // Stub: would retrieve the current process's PrctlState and
    // call oncrix_kernel::prctl::do_prctl(state, option, arg2).
    error_to_errno(Error::NotImplemented)
}

// ── Architecture / TLS syscalls ────────────────────────────────

/// `SYS_ARCH_PRCTL` — Set or get architecture-specific thread state.
///
/// On x86_64, this controls the FS and GS segment base registers
/// used for thread-local storage (TLS).
///
/// Arguments:
/// - `code`: sub-command (`ARCH_SET_FS`=0x1002, `ARCH_GET_FS`=0x1003,
///   `ARCH_SET_GS`=0x1001, `ARCH_GET_GS`=0x1004)
/// - `addr`: address to set (SET) or user pointer to write to (GET)
///
/// For SET operations, `addr` is the new base address (must be in
/// user-space range). For GET operations, `addr` is a user pointer
/// where the current base is written as a `u64`.
pub fn sys_arch_prctl(code: u64, addr: u64) -> SyscallResult {
    const ARCH_SET_GS: u64 = 0x1001;
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;
    const ARCH_GET_GS: u64 = 0x1004;

    match code {
        ARCH_SET_FS | ARCH_SET_GS => {
            // Reject kernel-space addresses.
            if addr >= 0xFFFF_8000_0000_0000 {
                return error_to_errno(Error::InvalidArgument);
            }
            // Stub: full implementation writes addr to the thread's
            // tls_base field and loads it into MSR_FS_BASE / MSR_GS_BASE
            // via wrmsr on the next context switch (or immediately).
            error_to_errno(Error::NotImplemented)
        }
        ARCH_GET_FS | ARCH_GET_GS => {
            if addr == 0 {
                return error_to_errno(Error::InvalidArgument);
            }
            // Stub: would read the current FS/GS base from the thread
            // struct and copy_to_user.
            error_to_errno(Error::NotImplemented)
        }
        _ => error_to_errno(Error::InvalidArgument),
    }
}

/// `SYS_SET_TID_ADDRESS` — Set the `clear_child_tid` pointer.
///
/// Called by C libraries (glibc, musl) during thread startup to
/// register a user-space address that the kernel clears and
/// futex-wakes on thread exit (`CLONE_CHILD_CLEARTID`).
///
/// Returns the caller's TID.
pub fn sys_set_tid_address(_tidptr: u64) -> SyscallResult {
    // Stub: would store tidptr in the current thread's TCB,
    // then return the calling thread's TID.
    // For now, return TID 0 (kernel thread).
    0
}

// ── Synchronization syscalls ──────────────────────────────────

/// `SYS_FUTEX` — Fast user-space locking.
///
/// Arguments:
/// - `uaddr`: user pointer to a 32-bit futex word
/// - `op`: operation (FUTEX_WAIT=0, FUTEX_WAKE=1, + PRIVATE flag)
/// - `val`: expected value (WAIT) or max wakeups (WAKE)
/// - `timeout`: user pointer to timespec (WAIT only, may be null)
/// - `uaddr2`: second futex address (requeue ops, unused for now)
/// - `val3`: third value (requeue ops, unused for now)
///
/// Implementation uses `oncrix_kernel::futex::FutexTable`.
pub fn sys_futex(
    uaddr: u64,
    op: u64,
    val: u64,
    _timeout: u64,
    _uaddr2: u64,
    _val3: u64,
) -> SyscallResult {
    if uaddr == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Mask out the PRIVATE flag to get the base operation.
    let base_op = (op as u32) & !128;
    match base_op {
        0 => {
            // FUTEX_WAIT: stub — would read *uaddr, compare to val,
            // add to FutexTable, block the calling thread.
            let _ = val;
            error_to_errno(Error::NotImplemented)
        }
        1 => {
            // FUTEX_WAKE: stub — would call FutexTable::futex_wake,
            // then unblock the woken threads via the scheduler.
            // Returns the number of threads woken.
            let _ = val;
            error_to_errno(Error::NotImplemented)
        }
        _ => error_to_errno(Error::InvalidArgument),
    }
}

// ── Time syscalls ─────────────────────────────────────────────

/// `SYS_NANOSLEEP` — High-resolution sleep.
///
/// Arguments:
/// - `req`: user pointer to `struct timespec` (requested duration)
/// - `rem`: user pointer to `struct timespec` (remaining, may be null)
///
/// The calling thread sleeps for the specified duration.
/// On signal interruption, the remaining time is written to `rem`.
pub fn sys_nanosleep(req: u64, _rem: u64) -> SyscallResult {
    if req == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would copy timespec from user space, convert to ns,
    // schedule a timer via TimerWheel, block the calling thread.
    error_to_errno(Error::NotImplemented)
}

/// `SYS_CLOCK_GETTIME` — Get clock time.
///
/// Arguments:
/// - `clk_id`: clock identifier (CLOCK_REALTIME=0, CLOCK_MONOTONIC=1)
/// - `tp`: user pointer to `struct timespec` for the result
pub fn sys_clock_gettime(clk_id: u64, tp: u64) -> SyscallResult {
    if tp == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Only CLOCK_REALTIME (0) and CLOCK_MONOTONIC (1) are supported.
    if clk_id > 1 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would read TimerWheel::now(), convert to timespec,
    // copy_to_user.
    error_to_errno(Error::NotImplemented)
}

// ── Process credential syscalls ───────────────────────────────

/// `SYS_GETUID` — Get real user ID.
///
/// Returns the real UID of the calling process.
pub fn sys_getuid() -> SyscallResult {
    // Stub: would read current process Credentials::uid().
    0
}

/// `SYS_GETGID` — Get real group ID.
///
/// Returns the real GID of the calling process.
pub fn sys_getgid() -> SyscallResult {
    // Stub: would read current process Credentials::gid().
    0
}

/// `SYS_SETUID` — Set user ID.
///
/// Arguments:
/// - `uid`: new user ID
///
/// Per POSIX, if the caller has superuser privileges all three
/// IDs (real, effective, saved) are set. Otherwise only the
/// effective UID may be changed (to the real UID or saved
/// set-user-ID).
///
/// Returns 0 on success, or negative errno.
pub fn sys_setuid(_uid: u64) -> SyscallResult {
    // Stub: would call Credentials::set_uid(uid as u32) on the
    // current process.
    error_to_errno(Error::NotImplemented)
}

/// `SYS_SETGID` — Set group ID.
///
/// Arguments:
/// - `gid`: new group ID
///
/// Same privilege rules as `setuid`, applied to group IDs.
///
/// Returns 0 on success, or negative errno.
pub fn sys_setgid(_gid: u64) -> SyscallResult {
    // Stub: would call Credentials::set_gid(gid as u32) on the
    // current process.
    error_to_errno(Error::NotImplemented)
}

/// `SYS_GETEUID` — Get effective user ID.
///
/// Returns the effective UID of the calling process.
pub fn sys_geteuid() -> SyscallResult {
    // Stub: would read current process Credentials::euid().
    0
}

/// `SYS_GETEGID` — Get effective group ID.
///
/// Returns the effective GID of the calling process.
pub fn sys_getegid() -> SyscallResult {
    // Stub: would read current process Credentials::egid().
    0
}

/// `SYS_GETGROUPS` — Get supplementary group IDs.
///
/// Arguments:
/// - `size`: max number of GIDs to return (0 = query count)
/// - `list`: user pointer to `gid_t[]` output buffer
///
/// If `size` is 0, returns the number of supplementary groups
/// without writing to `list`. Otherwise, copies up to `size`
/// GIDs to the user buffer and returns the count written.
///
/// Returns the number of supplementary groups, or negative
/// errno.
pub fn sys_getgroups(_size: u64, _list: u64) -> SyscallResult {
    // Stub: would read Credentials::groups() from the current
    // process and copy_to_user.
    error_to_errno(Error::NotImplemented)
}

/// `SYS_SETGROUPS` — Set supplementary group IDs.
///
/// Arguments:
/// - `size`: number of GIDs in the list
/// - `list`: user pointer to `gid_t[]` input buffer
///
/// Only the superuser may call `setgroups`.
///
/// Returns 0 on success, or negative errno.
pub fn sys_setgroups(_size: u64, _list: u64) -> SyscallResult {
    // Stub: would validate privilege, copy_from_user, then call
    // Credentials::set_groups().
    error_to_errno(Error::NotImplemented)
}

// ── Process group / session syscalls ──────────────────────────

/// `SYS_SETPGID` — Set process group ID for a process.
///
/// Arguments:
/// - `pid`: target process (0 = calling process)
/// - `pgid`: new process group ID (0 = use target's PID)
///
/// Returns 0 on success, or negative errno.
///
/// Per POSIX, a process may only set its own PGID or the PGID of
/// a child that has not yet called `execve()`.
pub fn sys_setpgid(_pid: u64, _pgid: u64) -> SyscallResult {
    // Stub: would validate that the caller owns the target,
    // then call ProcessGroupTable::create or add_member.
    error_to_errno(Error::NotImplemented)
}

/// `SYS_GETPGID` — Get process group ID of a process.
///
/// Arguments:
/// - `pid`: target process (0 = calling process)
///
/// Returns the PGID on success, or negative errno.
pub fn sys_getpgid(_pid: u64) -> SyscallResult {
    // Stub: would look up the target process and return its pgid.
    error_to_errno(Error::NotImplemented)
}

/// `SYS_SETSID` — Create a new session.
///
/// The calling process becomes the session leader and the process
/// group leader of a new process group. The session has no
/// controlling terminal.
///
/// Returns the new session ID (equal to the caller's PID) on
/// success, or negative errno if the caller is already a process
/// group leader.
pub fn sys_setsid() -> SyscallResult {
    // Stub: would verify the caller is not already a group leader,
    // create a new Session and ProcessGroup via the global tables.
    error_to_errno(Error::NotImplemented)
}

/// `SYS_GETSID` — Get session ID of a process.
///
/// Arguments:
/// - `pid`: target process (0 = calling process)
///
/// Returns the SID on success, or negative errno.
pub fn sys_getsid(_pid: u64) -> SyscallResult {
    // Stub: would look up the target process and return its sid.
    error_to_errno(Error::NotImplemented)
}

// ── timerfd syscalls ──────────────────────────────────────────

/// `SYS_TIMERFD_CREATE` — Create a timerfd file descriptor.
///
/// Arguments:
/// - `clockid`: clock identifier (`CLOCK_REALTIME` = 0,
///   `CLOCK_MONOTONIC` = 1)
/// - `flags`: combination of `TFD_NONBLOCK`, `TFD_CLOEXEC`
///
/// Returns a non-negative timerfd descriptor on success, or
/// negative errno on failure.
///
/// Stub: full implementation requires a global `TimerFdRegistry`.
pub fn sys_timerfd_create(clockid: u64, flags: u64) -> SyscallResult {
    // Only CLOCK_REALTIME (0) and CLOCK_MONOTONIC (1).
    if clockid > 1 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Validate flags: only TFD_NONBLOCK | TFD_CLOEXEC.
    let valid_mask: u64 = 0x80000 | 0x800;
    if flags & !valid_mask != 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would call TimerFdRegistry::create(clockid, flags).
    error_to_errno(Error::NotImplemented)
}

/// `SYS_TIMERFD_SETTIME` — Arm or disarm a timerfd.
///
/// Arguments:
/// - `fd`: timerfd file descriptor
/// - `flags`: `TFD_TIMER_ABSTIME` (1) or 0
/// - `new_value`: user pointer to `struct itimerspec`
/// - `old_value`: user pointer to `struct itimerspec` (may be null)
///
/// Returns 0 on success, or negative errno on failure.
///
/// Stub: full implementation requires a global `TimerFdRegistry`
/// and `copy_from_user`/`copy_to_user`.
pub fn sys_timerfd_settime(fd: u64, flags: u64, new_value: u64, _old_value: u64) -> SyscallResult {
    if fd > 255 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Only 0 and TFD_TIMER_ABSTIME (1) are valid.
    if flags > 1 {
        return error_to_errno(Error::InvalidArgument);
    }
    if new_value == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would copy itimerspec from user space,
    // call TimerFdRegistry::get_mut(fd).settime(),
    // optionally copy old value to user space.
    error_to_errno(Error::NotImplemented)
}

/// `SYS_TIMERFD_GETTIME` — Get remaining time on a timerfd.
///
/// Arguments:
/// - `fd`: timerfd file descriptor
/// - `curr_value`: user pointer to `struct itimerspec` for result
///
/// Returns 0 on success, or negative errno on failure.
///
/// Stub: full implementation requires a global `TimerFdRegistry`
/// and `copy_to_user`.
pub fn sys_timerfd_gettime(fd: u64, curr_value: u64) -> SyscallResult {
    if fd > 255 {
        return error_to_errno(Error::InvalidArgument);
    }
    if curr_value == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would call TimerFdRegistry::get(fd).gettime(),
    // copy result to user space.
    error_to_errno(Error::NotImplemented)
}

// ── Shared memory syscalls ────────────────────────────────────

/// `SYS_MEMFD_CREATE` — Create an anonymous memory file descriptor.
///
/// Arguments:
/// - `name`: user pointer to a null-terminated name string
///   (used only for debugging, e.g. `/proc/self/fd/` symlinks)
/// - `flags`: combination of `MFD_CLOEXEC` (0x1) and
///   `MFD_ALLOW_SEALING` (0x2)
///
/// Returns a non-negative file descriptor on success, or negative
/// errno on failure.
///
/// The returned fd behaves like a regular file backed by anonymous
/// memory. It can be sized via `ftruncate`, read/written, and
/// passed to `mmap`. If `MFD_ALLOW_SEALING` is set, file sealing
/// operations (`F_ADD_SEALS`, `F_GET_SEALS`) are permitted.
///
/// Stub: full implementation requires a global `ShmRegistry` and
/// integration with the fd table.
pub fn sys_memfd_create(name: u64, flags: u64) -> SyscallResult {
    if name == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Only MFD_CLOEXEC (0x1) and MFD_ALLOW_SEALING (0x2) are valid.
    if flags & !0x3 != 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would copy name from user space, call
    // ShmRegistry::create(name, flags), allocate an fd in the
    // current process's FdTable pointing to the new segment.
    error_to_errno(Error::NotImplemented)
}

// ── inotify syscalls ──────────────────────────────────────────

/// `SYS_INOTIFY_INIT1` — Create an inotify instance.
///
/// Arguments:
/// - `flags`: combination of `IN_NONBLOCK` (0x800) and
///   `IN_CLOEXEC` (0x80000)
///
/// Returns a non-negative inotify file descriptor on success, or
/// negative errno on failure.
///
/// Stub: full implementation requires a global `InotifyRegistry`.
pub fn sys_inotify_init1(_flags: u64) -> SyscallResult {
    // Only IN_NONBLOCK (0x800) and IN_CLOEXEC (0x80000) are valid.
    let valid_mask: u64 = 0x80000 | 0x800;
    if _flags & !valid_mask != 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would call InotifyRegistry::create(flags).
    error_to_errno(Error::NotImplemented)
}

/// `SYS_INOTIFY_ADD_WATCH` — Add or update an inotify watch.
///
/// Arguments:
/// - `fd`: inotify file descriptor (from `inotify_init1`)
/// - `pathname`: user pointer to null-terminated path string
/// - `mask`: bitmask of events to watch for
///
/// Returns the watch descriptor on success, or negative errno.
///
/// Stub: full implementation requires a global `InotifyRegistry`,
/// VFS path resolution, and `copy_from_user`.
pub fn sys_inotify_add_watch(fd: u64, pathname: u64, mask: u64) -> SyscallResult {
    if fd > 255 {
        return error_to_errno(Error::InvalidArgument);
    }
    if pathname == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    if mask == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would resolve pathname via VFS to get the inode,
    // then call InotifyRegistry::get_mut(fd).add_watch(inode, mask).
    error_to_errno(Error::NotImplemented)
}

/// `SYS_INOTIFY_RM_WATCH` — Remove an inotify watch.
///
/// Arguments:
/// - `fd`: inotify file descriptor
/// - `wd`: watch descriptor to remove
///
/// Returns 0 on success, or negative errno.
///
/// Stub: full implementation requires a global `InotifyRegistry`.
pub fn sys_inotify_rm_watch(fd: u64, wd: u64) -> SyscallResult {
    if fd > 255 {
        return error_to_errno(Error::InvalidArgument);
    }
    // wd is signed (i32) in the Linux API; 0 is invalid because
    // watch descriptors start at 1.
    let wd_i32 = wd as i32;
    if wd_i32 < 1 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would call
    // InotifyRegistry::get_mut(fd).remove_watch(wd_i32).
    error_to_errno(Error::NotImplemented)
}

// ── eventfd / signalfd syscalls ───────────────────────────────

/// `SYS_EVENTFD2` — Create an eventfd file descriptor.
///
/// Arguments:
/// - `initval`: initial counter value
/// - `flags`: combination of `EFD_SEMAPHORE`, `EFD_NONBLOCK`,
///   `EFD_CLOEXEC`
///
/// Returns a non-negative eventfd descriptor on success, or
/// negative errno on failure.
///
/// Stub: full implementation requires a global `EventFdRegistry`.
pub fn sys_eventfd2(_initval: u64, _flags: u64) -> SyscallResult {
    // Validate flags: only EFD_SEMAPHORE|EFD_NONBLOCK|EFD_CLOEXEC.
    let valid_mask: u64 = 0x80000 | 0x800 | 1;
    if _flags & !valid_mask != 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would call EventFdRegistry::create(initval, flags).
    error_to_errno(Error::NotImplemented)
}

/// `SYS_SIGNALFD4` — Create or update a signalfd file descriptor.
///
/// Arguments:
/// - `fd`: existing signalfd to update (-1 to create a new one)
/// - `mask`: bitmask of signals to accept
/// - `flags`: combination of `SFD_NONBLOCK`, `SFD_CLOEXEC`
///
/// Returns a non-negative signalfd descriptor on success, or
/// negative errno on failure.
///
/// Stub: full implementation requires a global `SignalFdRegistry`.
pub fn sys_signalfd4(_fd: u64, _mask: u64, _flags: u64) -> SyscallResult {
    // Validate flags: only SFD_NONBLOCK|SFD_CLOEXEC.
    let valid_mask: u64 = 0x80000 | 0x800;
    if _flags & !valid_mask != 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would call SignalFdRegistry::create(mask, flags)
    // or SignalFdRegistry::get_mut(fd).update_mask(mask).
    error_to_errno(Error::NotImplemented)
}

// ── Resource limit syscalls ───────────────────────────────────

/// `SYS_GETRLIMIT` — Get resource limits for the calling process.
///
/// Arguments:
/// - `resource`: resource type (e.g. `RLIMIT_NOFILE`)
/// - `rlim`: user pointer to `struct rlimit` to fill
///
/// Returns 0 on success, or negative errno.
///
/// Stub: full implementation requires access to the current
/// process's `RlimitSet` and `copy_to_user`.
pub fn sys_getrlimit(resource: u64, rlim: u64) -> SyscallResult {
    if rlim == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Validate resource range (0..RLIM_NLIMITS).
    if resource >= 16 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would call current_process().rlimits.get(resource),
    // then copy_to_user the Rlimit to `rlim`.
    error_to_errno(Error::NotImplemented)
}

/// `SYS_SETRLIMIT` — Set resource limits for the calling process.
///
/// Arguments:
/// - `resource`: resource type (e.g. `RLIMIT_NOFILE`)
/// - `rlim`: user pointer to `struct rlimit` with new values
///
/// Returns 0 on success, or negative errno.
///
/// The soft limit must not exceed the hard limit. An unprivileged
/// process may lower the hard limit but may not raise it.
///
/// Stub: full implementation requires access to the current
/// process's `RlimitSet` and `copy_from_user`.
pub fn sys_setrlimit(resource: u64, rlim: u64) -> SyscallResult {
    if rlim == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Validate resource range (0..RLIM_NLIMITS).
    if resource >= 16 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would copy_from_user the Rlimit from `rlim`,
    // validate cur <= max, then call
    // current_process().rlimits.set(resource, &new_rlim).
    error_to_errno(Error::NotImplemented)
}

/// `SYS_PRLIMIT64` — Get and/or set resource limits for a process.
///
/// Arguments:
/// - `pid`: target process (0 = calling process)
/// - `resource`: resource type (e.g. `RLIMIT_NOFILE`)
/// - `new_rlim`: user pointer to new `struct rlimit64` (may be
///   null to only query)
/// - `old_rlim`: user pointer to receive old `struct rlimit64`
///   (may be null to only set)
///
/// Returns 0 on success, or negative errno.
///
/// When both `new_rlim` and `old_rlim` are non-null, the old
/// value is stored before the new value is applied (atomic
/// get-and-set).
///
/// Stub: full implementation requires process lookup, capability
/// checks, `copy_from_user` / `copy_to_user`, and access to the
/// target process's `RlimitSet`.
pub fn sys_prlimit64(_pid: u64, resource: u64, new_rlim: u64, old_rlim: u64) -> SyscallResult {
    // At least one of the pointers must be non-null.
    if new_rlim == 0 && old_rlim == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Validate resource range (0..RLIM_NLIMITS).
    if resource >= 16 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would look up the target process by pid (0 = self),
    // optionally copy old limits to old_rlim via copy_to_user,
    // optionally copy new limits from new_rlim via copy_from_user
    // and call RlimitSet::set().
    error_to_errno(Error::NotImplemented)
}

// ── Memory protection / advisory ────────────────────────────────

/// `SYS_MPROTECT` — Set protection on a region of memory.
///
/// Arguments:
/// - `addr`: start address (must be page-aligned)
/// - `len`: length of the region in bytes
/// - `prot`: desired protection flags (`PROT_*` bitmask)
///
/// Returns 0 on success, or negative errno.
pub fn sys_mprotect(addr: u64, len: u64, prot: u64) -> SyscallResult {
    // Reject kernel-space addresses.
    if addr >= 0xFFFF_8000_0000_0000 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Truncate prot to u32 (upper bits are unused).
    let prot32 = prot as u32;
    match oncrix_mm::mprotect::do_mprotect(addr, len, prot32) {
        Ok(()) => 0,
        Err(e) => error_to_errno(e),
    }
}

/// `SYS_MADVISE` — Give advice about use of memory.
///
/// Arguments:
/// - `addr`: start address (must be page-aligned)
/// - `len`: length of the region in bytes
/// - `advice`: advisory hint (`MADV_*` constant)
///
/// Returns 0 on success, or negative errno.
pub fn sys_madvise(addr: u64, len: u64, advice: u64) -> SyscallResult {
    // Reject kernel-space addresses.
    if addr >= 0xFFFF_8000_0000_0000 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Truncate to i32 for the advice constant.
    let advice_i32 = advice as i32;
    match oncrix_mm::mprotect::do_madvise(addr, len, advice_i32) {
        Ok(()) => 0,
        Err(e) => error_to_errno(e),
    }
}

/// `SYS_MSYNC` — Synchronize a mapped region with storage.
///
/// Arguments:
/// - `addr`: start address (must be page-aligned)
/// - `len`: length of the region in bytes
/// - `flags`: synchronization flags (`MS_ASYNC`, `MS_SYNC`, etc.)
///
/// Returns 0 on success, or negative errno.
pub fn sys_msync(_addr: u64, _len: u64, _flags: u64) -> SyscallResult {
    // Stub: full implementation requires VMA lookup and dirty-page
    // writeback to the backing store.
    error_to_errno(Error::NotImplemented)
}

// ── seccomp syscall ──────────────────────────────────────────────

/// `SYS_SECCOMP` — Operate on the secure computing state.
///
/// Arguments:
/// - `operation`: `SECCOMP_SET_MODE_STRICT` (0),
///   `SECCOMP_SET_MODE_FILTER` (1), or
///   `SECCOMP_GET_ACTION_AVAIL` (2)
/// - `flags`: operation-specific flags (must be 0 for now)
/// - `args`: user pointer to operation-specific data (e.g.,
///   `struct sock_fprog` for filter mode)
///
/// Returns 0 on success, or negative errno.
///
/// Stub: full implementation requires access to the current
/// process's `SeccompState` and `copy_from_user` for BPF
/// programs.
pub fn sys_seccomp(_operation: u64, _flags: u64, _args: u64) -> SyscallResult {
    // Stub: would call oncrix_kernel::seccomp::do_seccomp() on
    // the current process's SeccompState.
    error_to_errno(Error::NotImplemented)
}

// ── Random number syscalls ───────────────────────────────────────

/// `SYS_GETRANDOM` — Obtain random bytes.
///
/// Arguments:
/// - `buf`: user pointer to output buffer
/// - `buflen`: number of bytes requested
/// - `flags`: combination of `GRND_NONBLOCK` (1) and
///   `GRND_RANDOM` (2)
///
/// If `GRND_RANDOM` is set, uses the blocking `/dev/random` pool
/// (returns `EAGAIN` when `GRND_NONBLOCK` is also set and entropy
/// is insufficient). Otherwise uses `/dev/urandom` semantics.
///
/// Returns the number of bytes written on success, or negative
/// errno on failure.
///
/// Stub: full implementation requires a global `KernelRng`
/// instance and `copy_to_user`.
pub fn sys_getrandom(buf: u64, buflen: u64, flags: u64) -> SyscallResult {
    if buf == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Validate flags: only GRND_NONBLOCK (1) | GRND_RANDOM (2).
    if flags & !0x3 != 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Cap buflen to a reasonable maximum (256 MiB).
    if buflen > 0x1000_0000 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would acquire the global KernelRng lock, call
    // get_random_bytes or get_urandom_bytes depending on
    // GRND_RANDOM flag, then copy_to_user.
    let _ = buflen;
    error_to_errno(Error::NotImplemented)
}

// ── Resource accounting syscalls ────────────────────────────────

/// `SYS_GETRUSAGE` — Get resource usage statistics.
///
/// Arguments:
/// - `who`: `RUSAGE_SELF` (0), `RUSAGE_CHILDREN` (-1), or
///   `RUSAGE_THREAD` (1)
/// - `usage`: user pointer to `struct rusage` to fill
///
/// Returns 0 on success, or negative errno.
///
/// Stub: full implementation requires access to the current
/// process's `ProcessAccounting` and `copy_to_user`.
pub fn sys_getrusage(who: u64, usage: u64) -> SyscallResult {
    if usage == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Validate `who` by interpreting as signed i32.
    let who_i32 = who as i32;
    if oncrix_process::rusage::RusageWho::from_raw(who_i32).is_none() {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would retrieve the current process's
    // ProcessAccounting, call get_rusage(who), and copy_to_user
    // the resulting Rusage to `usage`.
    error_to_errno(Error::NotImplemented)
}

/// `SYS_TIMES` — Get process and waited-children CPU times.
///
/// Arguments:
/// - `buf`: user pointer to `struct tms` to fill
///
/// Returns the elapsed real time (in ticks) since an arbitrary
/// point in the past, or negative errno on failure.
///
/// Stub: full implementation requires access to the current
/// process's `ProcessAccounting` and `copy_to_user`.
pub fn sys_times(buf: u64) -> SyscallResult {
    if buf == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would call get_process_times() on the current
    // process's ProcessAccounting, copy_to_user the
    // ProcessTimes to `buf`, and return the monotonic tick count.
    error_to_errno(Error::NotImplemented)
}

// ── Input devices ──────────────────────────────────────────────

/// `SYS_MOUSE_READ` — Read mouse events into a user-space buffer.
///
/// Copies pending `MouseEvent`s from the kernel mouse driver queue
/// into the buffer at `buf`. `count` specifies the maximum number
/// of bytes available. Returns the number of bytes written, or a
/// negative errno on failure.
///
/// Stub: full implementation requires access to the global
/// `MouseDriver` instance and `copy_to_user`.
pub fn sys_mouse_read(buf: u64, count: u64) -> SyscallResult {
    if buf == 0 || count == 0 {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would dequeue events from the global MouseDriver,
    // serialise them into the user buffer, and return the byte
    // count written.
    error_to_errno(Error::NotImplemented)
}

/// `SYS_SYSLOG` — Read and/or clear kernel message ring buffer.
///
/// Arguments:
/// - `action`: syslog action type (see `SyslogAction`)
/// - `bufp`: user pointer to output buffer (may be null for
///   non-read actions)
/// - `len`: size of the output buffer in bytes
///
/// Returns a non-negative value on success (meaning depends on
/// the action), or negative errno on failure.
///
/// Stub: full implementation requires access to the global
/// `DmesgBuffer` instance and `copy_to_user`.
pub fn sys_syslog(action: u64, _bufp: u64, _len: u64) -> SyscallResult {
    // Validate the action code (matches SyslogAction variants:
    // 2=Read, 3=ReadAll, 4=ReadClear, 5=Clear, 9=SizeUnread,
    // 10=SizeBuffer).
    let action_u32 = action as u32;
    if !matches!(action_u32, 2..=5 | 9 | 10) {
        return error_to_errno(Error::InvalidArgument);
    }
    // Stub: would acquire the global DmesgBuffer lock, call
    // do_syslog with the appropriate action, and copy_to_user
    // the results to `bufp`.
    error_to_errno(Error::NotImplemented)
}
