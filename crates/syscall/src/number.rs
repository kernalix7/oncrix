// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX system call numbers.
//!
//! These follow the Linux x86_64 ABI numbering for POSIX-compatible
//! calls. ONCRIX-specific extensions use numbers starting at 512.

/// System call number type.
pub type SyscallNumber = u64;

// ── Process management ──────────────────────────────────────────

/// `read(fd, buf, count)` — Read from a file descriptor.
pub const SYS_READ: SyscallNumber = 0;
/// `write(fd, buf, count)` — Write to a file descriptor.
pub const SYS_WRITE: SyscallNumber = 1;
/// `open(pathname, flags, mode)` — Open a file.
pub const SYS_OPEN: SyscallNumber = 2;
/// `close(fd)` — Close a file descriptor.
pub const SYS_CLOSE: SyscallNumber = 3;

// ── Memory management ───────────────────────────────────────────

/// `mmap(addr, length, prot, flags, fd, offset)` — Map memory.
pub const SYS_MMAP: SyscallNumber = 9;
/// `mprotect(addr, len, prot)` — Set memory protection.
pub const SYS_MPROTECT: SyscallNumber = 10;
/// `munmap(addr, length)` — Unmap memory.
pub const SYS_MUNMAP: SyscallNumber = 11;
/// `brk(addr)` — Change data segment size.
pub const SYS_BRK: SyscallNumber = 12;

/// `msync(addr, length, flags)` — Synchronize memory with storage.
pub const SYS_MSYNC: SyscallNumber = 26;
/// `madvise(addr, length, advice)` — Advise on memory usage.
pub const SYS_MADVISE: SyscallNumber = 28;

/// `memfd_create(name, flags)` — Create anonymous memory file.
pub const SYS_MEMFD_CREATE: SyscallNumber = 319;

// ── Process lifecycle ───────────────────────────────────────────

/// `getpid()` — Get process ID.
pub const SYS_GETPID: SyscallNumber = 39;
/// `fork()` — Create a child process.
pub const SYS_FORK: SyscallNumber = 57;
/// `execve(pathname, argv, envp)` — Execute a program.
pub const SYS_EXECVE: SyscallNumber = 59;
/// `exit(status)` — Terminate the calling process.
pub const SYS_EXIT: SyscallNumber = 60;
/// `wait4(pid, wstatus, options, rusage)` — Wait for process state change.
pub const SYS_WAIT4: SyscallNumber = 61;
/// `kill(pid, sig)` — Send signal to a process.
pub const SYS_KILL: SyscallNumber = 62;
/// `waitid(idtype, id, infop, options)` — Wait for a child process (extended).
pub const SYS_WAITID: SyscallNumber = 247;
/// `execveat(dirfd, pathname, argv, envp, flags)` — Execute a program relative to a dirfd.
pub const SYS_EXECVEAT: SyscallNumber = 322;

// ── Process groups / sessions ──────────────────────────────────

/// `setpgid(pid, pgid)` — Set process group ID.
pub const SYS_SETPGID: SyscallNumber = 109;
/// `getpgrp()` — Get process group ID of the calling process.
pub const SYS_GETPGRP: SyscallNumber = 111;
/// `setsid()` — Create a new session.
pub const SYS_SETSID: SyscallNumber = 112;
/// `getpgid(pid)` — Get process group ID of a process.
pub const SYS_GETPGID: SyscallNumber = 121;
/// `getsid(pid)` — Get session ID.
pub const SYS_GETSID: SyscallNumber = 124;

// ── Process credentials ───────────────────────────────────────

/// `getuid()` — Get real user ID.
pub const SYS_GETUID: SyscallNumber = 102;
/// `getgid()` — Get real group ID.
pub const SYS_GETGID: SyscallNumber = 104;
/// `setuid(uid)` — Set user ID.
pub const SYS_SETUID: SyscallNumber = 105;
/// `setgid(gid)` — Set group ID.
pub const SYS_SETGID: SyscallNumber = 106;
/// `geteuid()` — Get effective user ID.
pub const SYS_GETEUID: SyscallNumber = 107;
/// `getegid()` — Get effective group ID.
pub const SYS_GETEGID: SyscallNumber = 108;
/// `getgroups(size, list)` — Get supplementary group IDs.
pub const SYS_GETGROUPS: SyscallNumber = 115;
/// `setgroups(size, list)` — Set supplementary group IDs.
pub const SYS_SETGROUPS: SyscallNumber = 116;

// ── File system ─────────────────────────────────────────────────

/// `stat(pathname, statbuf)` — Get file status.
pub const SYS_STAT: SyscallNumber = 4;
/// `fstat(fd, statbuf)` — Get file status by fd.
pub const SYS_FSTAT: SyscallNumber = 5;
/// `lseek(fd, offset, whence)` — Reposition file offset.
pub const SYS_LSEEK: SyscallNumber = 8;
/// `dup2(oldfd, newfd)` — Duplicate a file descriptor.
pub const SYS_DUP2: SyscallNumber = 33;
/// `pipe(pipefd)` — Create a pipe.
pub const SYS_PIPE: SyscallNumber = 22;
/// `mkdir(pathname, mode)` — Create a directory.
pub const SYS_MKDIR: SyscallNumber = 83;
/// `rmdir(pathname)` — Remove a directory.
pub const SYS_RMDIR: SyscallNumber = 84;
/// `unlink(pathname)` — Delete a name from the filesystem.
pub const SYS_UNLINK: SyscallNumber = 87;
/// `openat(dirfd, pathname, flags, mode)` — Open a file relative to a directory fd.
pub const SYS_OPENAT: SyscallNumber = 257;
/// `getdents64(fd, dirp, count)` — Read directory entries.
pub const SYS_GETDENTS64: SyscallNumber = 217;
/// `getcwd(buf, size)` — Get current working directory.
pub const SYS_GETCWD: SyscallNumber = 79;
/// `chdir(path)` — Change working directory.
pub const SYS_CHDIR: SyscallNumber = 80;
/// `ioctl(fd, request, arg)` — Device control.
pub const SYS_IOCTL: SyscallNumber = 16;

// ── File locking ─────────────────────────────────────────────────

/// `fcntl(fd, cmd, ...)` — File control (including advisory record locking).
pub const SYS_FCNTL: SyscallNumber = 72;
/// `flock(fd, operation)` — Apply or remove an advisory lock on an open file.
pub const SYS_FLOCK: SyscallNumber = 73;

// ── Sockets ──────────────────────────────────────────────────────

/// `socket(domain, type, protocol)` — Create a socket.
pub const SYS_SOCKET: SyscallNumber = 41;
/// `connect(sockfd, addr, addrlen)` — Connect a socket.
pub const SYS_CONNECT: SyscallNumber = 42;
/// `accept(sockfd, addr, addrlen)` — Accept a connection.
pub const SYS_ACCEPT: SyscallNumber = 43;
/// `sendto(sockfd, buf, len, flags, dest_addr, addrlen)` — Send a message.
pub const SYS_SENDTO: SyscallNumber = 44;
/// `recvfrom(sockfd, buf, len, flags, src_addr, addrlen)` — Receive a message.
pub const SYS_RECVFROM: SyscallNumber = 45;
/// `bind(sockfd, addr, addrlen)` — Bind a socket to an address.
pub const SYS_BIND: SyscallNumber = 49;
/// `listen(sockfd, backlog)` — Listen for connections.
pub const SYS_LISTEN: SyscallNumber = 50;
/// `socketpair(domain, type, protocol, sv)` — Create a pair of connected sockets.
pub const SYS_SOCKETPAIR: SyscallNumber = 53;

// ── IPC (ONCRIX extensions) ─────────────────────────────────────

/// `ipc_send(endpoint, msg)` — Send an IPC message.
pub const SYS_IPC_SEND: SyscallNumber = 512;
/// `ipc_receive(endpoint, msg)` — Receive an IPC message.
pub const SYS_IPC_RECEIVE: SyscallNumber = 513;
/// `ipc_reply(endpoint, msg)` — Reply to an IPC call.
pub const SYS_IPC_REPLY: SyscallNumber = 514;
/// `ipc_call(endpoint, msg)` — Synchronous IPC call (send + receive).
pub const SYS_IPC_CALL: SyscallNumber = 515;
/// `ipc_create_endpoint()` — Create a new IPC endpoint.
pub const SYS_IPC_CREATE_ENDPOINT: SyscallNumber = 516;

// ── I/O multiplexing ──────────────────────────────────────────

/// `poll(fds, nfds, timeout)` — Wait for events on file descriptors.
pub const SYS_POLL: SyscallNumber = 7;
/// `select(nfds, readfds, writefds, exceptfds, timeout)` — Synchronous I/O multiplexing.
pub const SYS_SELECT: SyscallNumber = 23;
/// `pselect6(nfds, readfds, writefds, exceptfds, timeout, sigmask)` — Synchronous I/O multiplexing with signal mask.
pub const SYS_PSELECT6: SyscallNumber = 270;
/// `ppoll(fds, nfds, timeout, sigmask, sigsetsize)` — Wait for events with signal mask.
pub const SYS_PPOLL: SyscallNumber = 271;

// ── Event / signal / timer file descriptors ───────────────────

/// `timerfd_create(clockid, flags)` — Create a timerfd.
pub const SYS_TIMERFD_CREATE: SyscallNumber = 283;
/// `timerfd_settime(fd, flags, new_value, old_value)` — Arm/disarm a timerfd.
pub const SYS_TIMERFD_SETTIME: SyscallNumber = 286;
/// `timerfd_gettime(fd, curr_value)` — Get timerfd remaining time.
pub const SYS_TIMERFD_GETTIME: SyscallNumber = 287;
/// `signalfd4(fd, mask, flags)` — Create or update a signalfd.
pub const SYS_SIGNALFD4: SyscallNumber = 289;
/// `eventfd2(initval, flags)` — Create an eventfd.
pub const SYS_EVENTFD2: SyscallNumber = 290;

// ── I/O event notification ─────────────────────────────────────

/// `epoll_wait(epfd, events, maxevents, timeout)` — Wait for events.
pub const SYS_EPOLL_WAIT: SyscallNumber = 232;
/// `epoll_ctl(epfd, op, fd, event)` — Control an epoll instance.
pub const SYS_EPOLL_CTL: SyscallNumber = 233;
/// `epoll_create1(flags)` — Create an epoll instance.
pub const SYS_EPOLL_CREATE1: SyscallNumber = 291;

// ── Filesystem event monitoring ────────────────────────────────

/// `inotify_add_watch(fd, pathname, mask)` — Add a watch.
pub const SYS_INOTIFY_ADD_WATCH: SyscallNumber = 254;
/// `inotify_rm_watch(fd, wd)` — Remove a watch.
pub const SYS_INOTIFY_RM_WATCH: SyscallNumber = 255;
/// `inotify_init1(flags)` — Create an inotify instance.
pub const SYS_INOTIFY_INIT1: SyscallNumber = 294;

// ── Synchronization ───────────────────────────────────────────

/// `futex(uaddr, op, val, timeout, uaddr2, val3)` — Fast user-space locking.
pub const SYS_FUTEX: SyscallNumber = 202;

// ── Time ──────────────────────────────────────────────────────

/// `nanosleep(req, rem)` — High-resolution sleep.
pub const SYS_NANOSLEEP: SyscallNumber = 35;
/// `clock_gettime(clk_id, tp)` — Get clock time.
pub const SYS_CLOCK_GETTIME: SyscallNumber = 228;

// ── Signal (POSIX) ──────────────────────────────────────────────

/// `rt_sigaction(sig, act, oldact)` — Set signal action.
pub const SYS_RT_SIGACTION: SyscallNumber = 13;
/// `rt_sigreturn()` — Return from signal handler.
pub const SYS_RT_SIGRETURN: SyscallNumber = 15;

// ── Resource accounting ──────────────────────────────────────────

/// `getrusage(who, usage)` — Get resource usage.
pub const SYS_GETRUSAGE: SyscallNumber = 98;
/// `times(buf)` — Get process and child CPU times.
pub const SYS_TIMES: SyscallNumber = 100;

// ── Resource limits ────────────────────────────────────────────

/// `getrlimit(resource, rlim)` — Get resource limits.
pub const SYS_GETRLIMIT: SyscallNumber = 97;
/// `setrlimit(resource, rlim)` — Set resource limits.
pub const SYS_SETRLIMIT: SyscallNumber = 160;
/// `prlimit64(pid, resource, new_rlim, old_rlim)` — Get/set resource limits.
pub const SYS_PRLIMIT64: SyscallNumber = 302;

// ── Security ────────────────────────────────────────────────────

/// `seccomp(operation, flags, args)` — Secure computing filter.
pub const SYS_SECCOMP: SyscallNumber = 317;
/// `getrandom(buf, buflen, flags)` — Obtain random bytes.
pub const SYS_GETRANDOM: SyscallNumber = 318;

// ── Process control ──────────────────────────────────────────────

/// `prctl(option, arg2, arg3, arg4, arg5)` — Process control.
pub const SYS_PRCTL: SyscallNumber = 157;

// ── Architecture ────────────────────────────────────────────────

/// `arch_prctl(code, addr)` — Set/get architecture-specific state (x86_64 TLS).
pub const SYS_ARCH_PRCTL: SyscallNumber = 158;

// ── Thread ──────────────────────────────────────────────────────

/// `set_tid_address(tidptr)` — Set pointer for `CLONE_CHILD_CLEARTID`.
pub const SYS_SET_TID_ADDRESS: SyscallNumber = 218;

// ── Input devices (ONCRIX extensions) ────────────────────────────

/// `mouse_read(buf, count)` — Read mouse events.
pub const SYS_MOUSE_READ: SyscallNumber = 517;
/// `syslog(type, bufp, len)` — Read and/or clear kernel message ring buffer.
pub const SYS_SYSLOG: SyscallNumber = 103;
