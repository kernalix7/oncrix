// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! System call dispatcher.
//!
//! Maps syscall numbers to handler functions. Called from the
//! architecture-specific syscall entry point after saving registers.

use crate::handler::{self, SyscallResult};
use crate::number::*;

/// System call register frame (x86_64 SYSCALL convention).
///
/// On `SYSCALL`, the kernel receives arguments in:
/// - RAX = syscall number
/// - RDI = arg0, RSI = arg1, RDX = arg2
/// - R10 = arg3, R8 = arg4, R9 = arg5
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SyscallArgs {
    /// Syscall number (RAX).
    pub number: u64,
    /// First argument (RDI).
    pub arg0: u64,
    /// Second argument (RSI).
    pub arg1: u64,
    /// Third argument (RDX).
    pub arg2: u64,
    /// Fourth argument (R10).
    pub arg3: u64,
    /// Fifth argument (R8).
    pub arg4: u64,
    /// Sixth argument (R9).
    pub arg5: u64,
}

/// Dispatch a system call by number.
///
/// Returns the result to be placed in RAX on return to user space.
pub fn dispatch(args: &SyscallArgs) -> SyscallResult {
    match args.number {
        SYS_READ => handler::sys_read(args.arg0, args.arg1, args.arg2),
        SYS_WRITE => handler::sys_write(args.arg0, args.arg1, args.arg2),
        SYS_OPEN => handler::sys_open(args.arg0, args.arg1, args.arg2),
        SYS_CLOSE => handler::sys_close(args.arg0),
        SYS_MMAP => handler::sys_mmap(
            args.arg0, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5,
        ),
        SYS_MPROTECT => handler::sys_mprotect(args.arg0, args.arg1, args.arg2),
        SYS_BRK => handler::sys_brk(args.arg0),
        SYS_MSYNC => handler::sys_msync(args.arg0, args.arg1, args.arg2),
        SYS_MADVISE => handler::sys_madvise(args.arg0, args.arg1, args.arg2),
        SYS_GETPID => handler::sys_getpid(),
        SYS_FORK => handler::sys_fork(),
        SYS_EXECVE => handler::sys_execve(args.arg0, args.arg1, args.arg2),
        SYS_EXIT => handler::sys_exit(args.arg0),
        SYS_IPC_SEND => handler::sys_ipc_send(args.arg0, args.arg1),
        SYS_IPC_RECEIVE => handler::sys_ipc_receive(args.arg0, args.arg1),
        SYS_IPC_REPLY => handler::sys_ipc_reply(args.arg0, args.arg1),
        SYS_IPC_CALL => handler::sys_ipc_call(args.arg0, args.arg1),
        SYS_IPC_CREATE_ENDPOINT => handler::sys_ipc_create_endpoint(),
        SYS_RT_SIGACTION => handler::sys_sigaction(args.arg0, args.arg1, args.arg2),
        SYS_RT_SIGRETURN => handler::sys_rt_sigreturn(args.arg0),
        SYS_KILL => handler::sys_kill(args.arg0, args.arg1),
        SYS_WAIT4 => handler::sys_wait4(args.arg0, args.arg1, args.arg2, args.arg3),
        SYS_STAT => handler::sys_stat(args.arg0, args.arg1),
        SYS_FSTAT => handler::sys_fstat(args.arg0, args.arg1),
        SYS_LSEEK => handler::sys_lseek(args.arg0, args.arg1, args.arg2),
        SYS_PIPE => handler::sys_pipe(args.arg0),
        SYS_DUP2 => handler::sys_dup2(args.arg0, args.arg1),
        SYS_FUTEX => handler::sys_futex(
            args.arg0, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5,
        ),
        SYS_NANOSLEEP => handler::sys_nanosleep(args.arg0, args.arg1),
        SYS_CLOCK_GETTIME => handler::sys_clock_gettime(args.arg0, args.arg1),
        SYS_GETDENTS64 => handler::sys_getdents64(args.arg0, args.arg1, args.arg2),
        SYS_IOCTL => handler::sys_ioctl(args.arg0, args.arg1, args.arg2),
        SYS_FCNTL => handler::sys_fcntl(args.arg0, args.arg1, args.arg2),
        SYS_FLOCK => handler::sys_flock(args.arg0, args.arg1),
        SYS_SOCKET => handler::sys_socket(args.arg0, args.arg1, args.arg2),
        SYS_CONNECT => handler::sys_connect(args.arg0, args.arg1, args.arg2),
        SYS_ACCEPT => handler::sys_accept(args.arg0, args.arg1, args.arg2),
        SYS_SENDTO => handler::sys_sendto(
            args.arg0, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5,
        ),
        SYS_RECVFROM => handler::sys_recvfrom(
            args.arg0, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5,
        ),
        SYS_BIND => handler::sys_bind(args.arg0, args.arg1, args.arg2),
        SYS_LISTEN => handler::sys_listen(args.arg0, args.arg1),
        SYS_SOCKETPAIR => handler::sys_socketpair(args.arg0, args.arg1, args.arg2, args.arg3),
        SYS_PRCTL => handler::sys_prctl(args.arg0, args.arg1, args.arg2, args.arg3, args.arg4),
        SYS_ARCH_PRCTL => handler::sys_arch_prctl(args.arg0, args.arg1),
        SYS_SET_TID_ADDRESS => handler::sys_set_tid_address(args.arg0),
        SYS_POLL => handler::sys_poll(args.arg0, args.arg1, args.arg2),
        SYS_SELECT => handler::sys_select(args.arg0, args.arg1, args.arg2, args.arg3, args.arg4),
        SYS_EPOLL_CREATE1 => handler::sys_epoll_create1(args.arg0),
        SYS_EPOLL_CTL => handler::sys_epoll_ctl(args.arg0, args.arg1, args.arg2, args.arg3),
        SYS_EPOLL_WAIT => handler::sys_epoll_wait(args.arg0, args.arg1, args.arg2, args.arg3),
        SYS_GETUID => handler::sys_getuid(),
        SYS_GETGID => handler::sys_getgid(),
        SYS_SETUID => handler::sys_setuid(args.arg0),
        SYS_SETGID => handler::sys_setgid(args.arg0),
        SYS_GETEUID => handler::sys_geteuid(),
        SYS_GETEGID => handler::sys_getegid(),
        SYS_GETGROUPS => handler::sys_getgroups(args.arg0, args.arg1),
        SYS_SETGROUPS => handler::sys_setgroups(args.arg0, args.arg1),
        SYS_SETPGID => handler::sys_setpgid(args.arg0, args.arg1),
        SYS_GETPGID => handler::sys_getpgid(args.arg0),
        SYS_GETPGRP => handler::sys_getpgid(0),
        SYS_SETSID => handler::sys_setsid(),
        SYS_GETSID => handler::sys_getsid(args.arg0),
        SYS_TIMERFD_CREATE => handler::sys_timerfd_create(args.arg0, args.arg1),
        SYS_TIMERFD_SETTIME => {
            handler::sys_timerfd_settime(args.arg0, args.arg1, args.arg2, args.arg3)
        }
        SYS_TIMERFD_GETTIME => handler::sys_timerfd_gettime(args.arg0, args.arg1),
        SYS_MEMFD_CREATE => handler::sys_memfd_create(args.arg0, args.arg1),
        SYS_EVENTFD2 => handler::sys_eventfd2(args.arg0, args.arg1),
        SYS_SIGNALFD4 => handler::sys_signalfd4(args.arg0, args.arg1, args.arg2),
        SYS_INOTIFY_INIT1 => handler::sys_inotify_init1(args.arg0),
        SYS_INOTIFY_ADD_WATCH => handler::sys_inotify_add_watch(args.arg0, args.arg1, args.arg2),
        SYS_INOTIFY_RM_WATCH => handler::sys_inotify_rm_watch(args.arg0, args.arg1),
        SYS_GETRLIMIT => handler::sys_getrlimit(args.arg0, args.arg1),
        SYS_SETRLIMIT => handler::sys_setrlimit(args.arg0, args.arg1),
        SYS_PRLIMIT64 => handler::sys_prlimit64(args.arg0, args.arg1, args.arg2, args.arg3),
        SYS_SECCOMP => handler::sys_seccomp(args.arg0, args.arg1, args.arg2),
        SYS_GETRANDOM => handler::sys_getrandom(args.arg0, args.arg1, args.arg2),
        SYS_GETRUSAGE => handler::sys_getrusage(args.arg0, args.arg1),
        SYS_TIMES => handler::sys_times(args.arg0),
        SYS_MOUSE_READ => handler::sys_mouse_read(args.arg0, args.arg1),
        SYS_SYSLOG => handler::sys_syslog(args.arg0, args.arg1, args.arg2),
        _ => -38, // ENOSYS
    }
}
