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
/// `mlock(addr, len)` — Lock pages in memory (no-op; ONCRIX does not page out).
pub const SYS_MLOCK: SyscallNumber = 149;
/// `munlock(addr, len)` — Unlock pages (no-op).
pub const SYS_MUNLOCK: SyscallNumber = 150;
/// `mlockall(flags)` — Lock all current/future pages (no-op).
pub const SYS_MLOCKALL: SyscallNumber = 151;
/// `munlockall()` — Unlock all pages (no-op).
pub const SYS_MUNLOCKALL: SyscallNumber = 152;

// ── Scheduler / CPU queries ──────────────────────────────────────

/// `sched_get_priority_max(policy)` — Max static priority for a policy.
pub const SYS_SCHED_GET_PRIORITY_MAX: SyscallNumber = 146;
/// `sched_get_priority_min(policy)` — Min static priority for a policy.
pub const SYS_SCHED_GET_PRIORITY_MIN: SyscallNumber = 147;
/// `getcpu(cpu, node, tcache)` — Query current CPU + NUMA node.
pub const SYS_GETCPU: SyscallNumber = 309;

// ── I/O advisory / allocation ────────────────────────────────────

/// `readahead(fd, offset, count)` — Initiate file read-ahead (no-op on ramfs).
pub const SYS_READAHEAD: SyscallNumber = 187;
/// `posix_fadvise64(fd, offset, len, advice)` — Access-pattern hint.
pub const SYS_FADVISE64: SyscallNumber = 221;
/// `sync_file_range(fd, offset, nbytes, flags)` — Sync a file segment.
pub const SYS_SYNC_FILE_RANGE: SyscallNumber = 277;
/// `fallocate(fd, mode, offset, len)` — Manipulate file space allocation.
pub const SYS_FALLOCATE: SyscallNumber = 285;

/// `memfd_create(name, flags)` — Create anonymous memory file.
pub const SYS_MEMFD_CREATE: SyscallNumber = 319;

/// `dup(oldfd)` — Duplicate a file descriptor to the lowest available slot.
pub const SYS_DUP: SyscallNumber = 32;
/// `close_range(first, last, flags)` — Close all open fds in [first, last].
pub const SYS_CLOSE_RANGE: SyscallNumber = 436;
// ── Extended attributes ──────────────────────────────────────────

/// `setxattr(path, name, value, size, flags)` — Set an extended attribute by path.
pub const SYS_SETXATTR: SyscallNumber = 188;
/// `lsetxattr(path, name, value, size, flags)` — Set an extended attribute (no symlink follow).
pub const SYS_LSETXATTR: SyscallNumber = 189;
/// `fsetxattr(fd, name, value, size, flags)` — Set an extended attribute by descriptor.
pub const SYS_FSETXATTR: SyscallNumber = 190;
/// `getxattr(path, name, value, size)` — Get an extended attribute by path.
pub const SYS_GETXATTR: SyscallNumber = 191;
/// `lgetxattr(path, name, value, size)` — Get an extended attribute (no symlink follow).
pub const SYS_LGETXATTR: SyscallNumber = 192;
/// `fgetxattr(fd, name, value, size)` — Get an extended attribute by descriptor.
pub const SYS_FGETXATTR: SyscallNumber = 193;
/// `listxattr(path, list, size)` — List extended attribute names by path.
pub const SYS_LISTXATTR: SyscallNumber = 194;
/// `llistxattr(path, list, size)` — List extended attribute names (no symlink follow).
pub const SYS_LLISTXATTR: SyscallNumber = 195;
/// `flistxattr(fd, list, size)` — List extended attribute names by descriptor.
pub const SYS_FLISTXATTR: SyscallNumber = 196;
/// `removexattr(path, name)` — Remove an extended attribute by path.
pub const SYS_REMOVEXATTR: SyscallNumber = 197;
/// `lremovexattr(path, name)` — Remove an extended attribute (no symlink follow).
pub const SYS_LREMOVEXATTR: SyscallNumber = 198;
/// `fremovexattr(fd, name)` — Remove an extended attribute by descriptor.
pub const SYS_FREMOVEXATTR: SyscallNumber = 199;
/// `sendfile(out_fd, in_fd, offset, count)` — copy data between file
/// descriptors in the kernel, bypassing user-space buffers.
/// Linux / ONCRIX syscall number 40.
pub const SYS_SENDFILE: SyscallNumber = 40;

/// `copy_file_range(fd_in, off_in, fd_out, off_out, len, flags)` — copy a
/// range of data from one file descriptor to another within the kernel.
/// Linux / ONCRIX syscall number 326.
pub const SYS_COPY_FILE_RANGE: SyscallNumber = 326;

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

/// `tkill(tid, sig)` — send signal to a specific thread (Linux 200).
///
/// In ONCRIX each thread is its own process (tid == pid), so this is
/// equivalent to `kill(tid, sig)`.  Deprecated in favour of `tgkill`.
pub const SYS_TKILL: SyscallNumber = 200;

/// `tgkill(tgid, tid, sig)` — send signal to a thread within a thread group (Linux 234).
///
/// ONCRIX is single-thread-per-process, so `tgid == tid == pid` always.
/// If `tgid != tid` the call returns `-ESRCH`; otherwise delegates to
/// `kill(tid, sig)`.
pub const SYS_TGKILL: SyscallNumber = 234;
/// `rt_sigpending(set, sigsetsize)` — Get the set of pending signals.
pub const SYS_RT_SIGPENDING: SyscallNumber = 127;
/// `rt_sigqueueinfo(tgid, sig, uinfo)` — Queue a signal with siginfo.
pub const SYS_RT_SIGQUEUEINFO: SyscallNumber = 129;
/// `sigaltstack(ss, old_ss)` — Set/get the alternate signal stack.
pub const SYS_SIGALTSTACK: SyscallNumber = 131;

/// `sched_rr_get_interval(pid, tp)` — write the round-robin time quantum into `*tp`.
pub const SYS_SCHED_RR_GET_INTERVAL: SyscallNumber = 148;
/// `waitid(idtype, id, infop, options)` — Wait for a child process (extended).
pub const SYS_WAITID: SyscallNumber = 247;
/// `execveat(dirfd, pathname, argv, envp, flags)` — Execute a program relative to a dirfd.
pub const SYS_EXECVEAT: SyscallNumber = 322;

// ── Process groups / sessions ──────────────────────────────────

/// `getppid()` — Get parent process ID.
pub const SYS_GETPPID: SyscallNumber = 110;
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
/// `lstat(pathname, statbuf)` — Get file status, not following symlinks.
pub const SYS_LSTAT: SyscallNumber = 6;
/// `lseek(fd, offset, whence)` — Reposition file offset.
pub const SYS_LSEEK: SyscallNumber = 8;
/// `pread64(fd, buf, count, offset)` — Read at an offset without moving
/// the file position.
pub const SYS_PREAD64: SyscallNumber = 17;
/// `pwrite64(fd, buf, count, offset)` — Write at an offset without moving
/// the file position.
pub const SYS_PWRITE64: SyscallNumber = 18;
/// `readv(fd, iov, iovcnt)` — Read into multiple buffers (scatter input).
pub const SYS_READV: SyscallNumber = 19;
/// `writev(fd, iov, iovcnt)` — Write from multiple buffers (gather output).
pub const SYS_WRITEV: SyscallNumber = 20;
/// `dup2(oldfd, newfd)` — Duplicate a file descriptor.
pub const SYS_DUP2: SyscallNumber = 33;
/// `dup3(oldfd, newfd, flags)` — Duplicate a fd, optionally setting
/// `O_CLOEXEC` on the new descriptor.
pub const SYS_DUP3: SyscallNumber = 292;
/// `pipe(pipefd)` — Create a pipe.
pub const SYS_PIPE: SyscallNumber = 22;
/// `pipe2(pipefd, flags)` — Create a pipe with flags.
pub const SYS_PIPE2: SyscallNumber = 293;
/// `mkdir(pathname, mode)` — Create a directory.
pub const SYS_MKDIR: SyscallNumber = 83;
/// `rmdir(pathname)` — Remove a directory.
pub const SYS_RMDIR: SyscallNumber = 84;
/// `unlink(pathname)` — Delete a name from the filesystem.
pub const SYS_UNLINK: SyscallNumber = 87;
/// `rename(oldpath, newpath)` — Rename/move a filesystem name.
pub const SYS_RENAME: SyscallNumber = 82;
/// `chmod(pathname, mode)` — Change file permission bits.
pub const SYS_CHMOD: SyscallNumber = 90;
/// `fchmod(fd, mode)` — Change file permission bits by descriptor.
pub const SYS_FCHMOD: SyscallNumber = 91;
/// `link(oldpath, newpath)` — Create a hard link.
pub const SYS_LINK: SyscallNumber = 86;
/// `chown(pathname, uid, gid)` — Change file owner/group.
pub const SYS_CHOWN: SyscallNumber = 92;
/// `fchown(fd, uid, gid)` — Change file owner/group by descriptor.
pub const SYS_FCHOWN: SyscallNumber = 93;
/// `access(pathname, mode)` — Check file accessibility.
pub const SYS_ACCESS: SyscallNumber = 21;
/// `sync()` — Flush filesystem buffers to backing store.
pub const SYS_SYNC: SyscallNumber = 162;
/// `fsync(fd)` — Synchronize file state with backing store.
pub const SYS_FSYNC: SyscallNumber = 74;
/// `fdatasync(fd)` — Synchronize file data (not metadata) with backing store.
pub const SYS_FDATASYNC: SyscallNumber = 75;
/// `statfs(pathname, buf)` — Get filesystem statistics by path.
pub const SYS_STATFS: SyscallNumber = 137;
/// `fstatfs(fd, buf)` — Get filesystem statistics by descriptor.
pub const SYS_FSTATFS: SyscallNumber = 138;
/// `sysinfo(info)` — Get system + memory statistics.
pub const SYS_SYSINFO: SyscallNumber = 99;
/// `symlink(target, linkpath)` — Create a symbolic link.
pub const SYS_SYMLINK: SyscallNumber = 88;
/// `readlink(pathname, buf, bufsiz)` — Read a symbolic link target.
pub const SYS_READLINK: SyscallNumber = 89;
/// `truncate(pathname, length)` — Set file length.
pub const SYS_TRUNCATE: SyscallNumber = 76;
/// `ftruncate(fd, length)` — Set file length by descriptor.
pub const SYS_FTRUNCATE: SyscallNumber = 77;
/// `mknod(pathname, mode, dev)` — Create a special file (FIFO subset).
pub const SYS_MKNOD: SyscallNumber = 133;
/// `openat(dirfd, pathname, flags, mode)` — Open a file relative to a directory fd.
pub const SYS_OPENAT: SyscallNumber = 257;

// ── *at family (AT_FDCWD delegation to path handlers) ────────────

/// `mkdirat(dirfd, pathname, mode)` — Create a directory relative to a directory fd.
pub const SYS_MKDIRAT: SyscallNumber = 258;
/// `fchownat(dirfd, pathname, uid, gid, flags)` — Change owner/group relative to a directory fd.
pub const SYS_FCHOWNAT: SyscallNumber = 260;
/// `newfstatat(dirfd, pathname, statbuf, flags)` — Get file status relative to a directory fd.
pub const SYS_NEWFSTATAT: SyscallNumber = 262;
/// `unlinkat(dirfd, pathname, flags)` — Remove a directory entry relative to a directory fd.
pub const SYS_UNLINKAT: SyscallNumber = 263;
/// `renameat(olddirfd, oldpath, newdirfd, newpath)` — Rename relative to directory fds.
pub const SYS_RENAMEAT: SyscallNumber = 264;
/// `symlinkat(target, newdirfd, linkpath)` — Create a symbolic link relative to a directory fd.
pub const SYS_SYMLINKAT: SyscallNumber = 266;
/// `readlinkat(dirfd, pathname, buf, bufsiz)` — Read a symlink target relative to a directory fd.
pub const SYS_READLINKAT: SyscallNumber = 267;
/// `fchmodat(dirfd, pathname, mode, flags)` — Change permission bits relative to a directory fd.
pub const SYS_FCHMODAT: SyscallNumber = 268;
/// `faccessat(dirfd, pathname, mode, flags)` — Check accessibility relative to a directory fd.
pub const SYS_FACCESSAT: SyscallNumber = 269;
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

// ── Scheduling priority ──────────────────────────────────────────

/// `getpriority(which, who)` — Get the scheduling priority (nice value).
pub const SYS_GETPRIORITY: SyscallNumber = 140;
/// `setpriority(which, who, prio)` — Set the scheduling priority (nice value).
pub const SYS_SETPRIORITY: SyscallNumber = 141;
/// `nice(inc)` — Add `inc` to the calling thread's nice value.
pub const SYS_NICE: SyscallNumber = 34;
/// `sched_yield()` — Yield the processor to another runnable thread.
pub const SYS_SCHED_YIELD: SyscallNumber = 24;
/// `sched_setparam(pid, param)` — Set scheduling parameters.
pub const SYS_SCHED_SETPARAM: SyscallNumber = 142;
/// `sched_getparam(pid, param)` — Get scheduling parameters.
pub const SYS_SCHED_GETPARAM: SyscallNumber = 143;
/// `sched_setscheduler(pid, policy, param)` — Set scheduling policy + params.
pub const SYS_SCHED_SETSCHEDULER: SyscallNumber = 144;
/// `sched_getscheduler(pid)` — Get scheduling policy.
pub const SYS_SCHED_GETSCHEDULER: SyscallNumber = 145;
/// `sched_setaffinity(pid, cpusetsize, mask)` — Set CPU affinity mask.
pub const SYS_SCHED_SETAFFINITY: SyscallNumber = 203;
/// `sched_getaffinity(pid, cpusetsize, mask)` — Get CPU affinity mask.
pub const SYS_SCHED_GETAFFINITY: SyscallNumber = 204;

// ── Time ──────────────────────────────────────────────────────

/// `nanosleep(req, rem)` — High-resolution sleep.
pub const SYS_NANOSLEEP: SyscallNumber = 35;
/// `clock_gettime(clk_id, tp)` — Get clock time.
pub const SYS_CLOCK_GETTIME: SyscallNumber = 228;
/// `clock_nanosleep(clk_id, flags, request, remain)` — High-resolution
/// sleep against a specific clock (relative or `TIMER_ABSTIME`).
pub const SYS_CLOCK_NANOSLEEP: SyscallNumber = 230;

// ── Interval timers ──────────────────────────────────────────────

/// `getitimer(which, curr_value)` — Get an interval timer.
pub const SYS_GETITIMER: SyscallNumber = 36;
/// `alarm(seconds)` — Schedule a one-shot `SIGALRM`.
pub const SYS_ALARM: SyscallNumber = 37;
/// `setitimer(which, new_value, old_value)` — Set an interval timer.
pub const SYS_SETITIMER: SyscallNumber = 38;
/// `time(tloc)` — Seconds since the Epoch (or boot, on systems without RTC).
pub const SYS_TIME: SyscallNumber = 201;

/// `sched_setattr(pid, attr, flags)` — Set extended scheduling attributes.
pub const SYS_SCHED_SETATTR: SyscallNumber = 314;
/// `sched_getattr(pid, attr, size, flags)` — Get extended scheduling attributes.
pub const SYS_SCHED_GETATTR: SyscallNumber = 315;

/// `adjtimex(buf)` — query or adjust kernel clock parameters (NTP).
///
/// ONCRIX performs no NTP discipline; the call validates the pointer and
/// returns `TIME_OK` (0) without modifying any state.
pub const SYS_ADJTIMEX: SyscallNumber = 159;

/// `clock_settime(clk_id, tp)` — set the time of a POSIX clock.
///
/// ONCRIX has no settable clock source; always returns `-EPERM` (-1) for a
/// known `clk_id` (`CLOCK_REALTIME` = 0, `CLOCK_MONOTONIC` = 1) after
/// validating both arguments, and `-EINVAL` (-22) for an unknown clock ID.
pub const SYS_CLOCK_SETTIME: SyscallNumber = 227;

/// `clock_adjtime(clk_id, buf)` — adjust the time of a specific POSIX clock.
///
/// ONCRIX performs no NTP discipline; the call validates the pointer and
/// returns `TIME_OK` (0) without modifying any state.
pub const SYS_CLOCK_ADJTIME: SyscallNumber = 305;

/// `uname(buf)` — fill `struct utsname` with system identification.
pub const SYS_UNAME: SyscallNumber = 63;
/// `sethostname(name, len)` — set the system hostname.
pub const SYS_SETHOSTNAME: SyscallNumber = 170;
/// `setdomainname(name, len)` — set the NIS/YP domain name.
pub const SYS_SETDOMAINNAME: SyscallNumber = 171;
/// `gettimeofday(tv, tz)` — get wall-clock time as `struct timeval`.
pub const SYS_GETTIMEOFDAY: SyscallNumber = 96;
/// `settimeofday(tv, tz)` — set wall-clock time (requires privilege).
pub const SYS_SETTIMEOFDAY: SyscallNumber = 164;
/// `clock_getres(clk_id, res)` — query clock resolution.
pub const SYS_CLOCK_GETRES: SyscallNumber = 229;
/// `capget(header, data)` — get the capability sets of a thread.
pub const SYS_CAPGET: SyscallNumber = 125;
/// `capset(header, data)` — set the capability sets of a thread.
pub const SYS_CAPSET: SyscallNumber = 126;
/// `personality(persona)` — query or set the execution domain.
pub const SYS_PERSONALITY: SyscallNumber = 135;

// ── Signal (POSIX) ──────────────────────────────────────────────

/// `rt_sigaction(sig, act, oldact)` — Set signal action.
pub const SYS_RT_SIGACTION: SyscallNumber = 13;
/// `rt_sigprocmask(how, set, oldset, sigsetsize)` — Examine/change blocked
/// signal mask.
pub const SYS_RT_SIGPROCMASK: SyscallNumber = 14;
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

/// `umask(mask)` — Set the file mode creation mask.
pub const SYS_UMASK: SyscallNumber = 95;

// ── Architecture ────────────────────────────────────────────────

/// `arch_prctl(code, addr)` — Set/get architecture-specific state (x86_64 TLS).
pub const SYS_ARCH_PRCTL: SyscallNumber = 158;

// ── Thread ──────────────────────────────────────────────────────

/// `gettid()` — Get thread ID.
pub const SYS_GETTID: SyscallNumber = 186;
/// `set_tid_address(tidptr)` — Set pointer for `CLONE_CHILD_CLEARTID`.
pub const SYS_SET_TID_ADDRESS: SyscallNumber = 218;

// ── Input devices (ONCRIX extensions) ────────────────────────────

/// `mouse_read(buf, count)` — Read mouse events.
pub const SYS_MOUSE_READ: SyscallNumber = 517;
/// `syslog(type, bufp, len)` — Read and/or clear kernel message ring buffer.
pub const SYS_SYSLOG: SyscallNumber = 103;
