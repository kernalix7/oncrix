// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! POSIX-compatible system call interface for the ONCRIX operating system.
//!
//! Defines the system call ABI, argument validation, and dispatching.
//! All user-space pointers are validated before kernel-space access.
//! Implements POSIX-compliant syscall semantics for compatibility.
//!
//! # Modules
//!
//! - [`number`] — POSIX syscall number constants
//! - [`dispatch`] — Syscall dispatcher (number → handler)
//! - [`handler`] — Individual syscall implementations

#![no_std]

pub mod clock;
pub mod copy_range;
pub mod dispatch;
pub mod epoll_calls;
pub mod execveat;
pub mod handler;
pub mod ioctl;
pub mod libc;
pub mod memfd;
pub mod mmap_calls;
#[allow(dead_code, clippy::all)]
pub mod mount_api;
pub mod number;
pub mod poll;
pub mod prctl;
pub mod process_calls;
pub mod rename;
pub mod resource;
pub mod signalfd;
pub mod socket_calls;
pub mod statx;
pub mod waitid;

#[allow(dead_code, clippy::all)]
pub mod close_range;
#[allow(dead_code, clippy::all)]
pub mod openat2;

#[allow(dead_code, clippy::all)]
pub mod futex2;
#[allow(dead_code, clippy::all)]
pub mod io_uring_setup;
#[allow(dead_code, clippy::all)]
pub mod landlock_calls;

#[allow(dead_code, clippy::all)]
pub mod faccessat2;
#[allow(dead_code, clippy::all)]
pub mod pidfd_calls;
#[allow(dead_code, clippy::all)]
pub mod sched_calls;

#[allow(dead_code, clippy::all)]
pub mod io_pgetevents;
#[allow(dead_code, clippy::all)]
pub mod preadwritev2;
#[allow(dead_code, clippy::all)]
pub mod process_madvise;

#[allow(dead_code, clippy::all)]
pub mod pkey;
#[allow(dead_code, clippy::all)]
pub mod process_vm;
#[allow(dead_code, clippy::all)]
pub mod userfaultfd_calls;

#[allow(dead_code, clippy::all)]
pub mod mount_new_api;
#[allow(dead_code, clippy::all)]
pub mod pidfd_ext_calls;
#[allow(dead_code, clippy::all)]
pub mod splice_calls;

#[allow(dead_code, clippy::all)]
pub mod cachestat;
#[allow(dead_code, clippy::all)]
pub mod io_uring_enter;

#[allow(dead_code, clippy::all)]
pub mod epoll_pwait2;
#[allow(dead_code, clippy::all)]
pub mod listxattr_calls;
#[allow(dead_code, clippy::all)]
pub mod quotactl;

#[allow(dead_code, clippy::all)]
pub mod fchmodat2;
#[allow(dead_code, clippy::all)]
pub mod io_uring_cmd;
#[allow(dead_code, clippy::all)]
pub mod mseal;

#[allow(dead_code, clippy::all)]
pub mod eventfd_calls;
#[allow(dead_code, clippy::all)]
pub mod futex_waitv;
#[allow(dead_code, clippy::all)]
pub mod map_shadow_stack;
#[allow(dead_code, clippy::all)]
pub mod membarrier;
#[allow(dead_code, clippy::all)]
pub mod signalfd_ext;
#[allow(dead_code, clippy::all)]
pub mod timerfd_calls;

#[allow(dead_code, clippy::all)]
pub mod bpf_calls;
#[allow(dead_code, clippy::all)]
pub mod io_uring_register;
#[allow(dead_code, clippy::all)]
pub mod kcmp;
#[allow(dead_code, clippy::all)]
pub mod mempolicy;
#[allow(dead_code, clippy::all)]
pub mod perf_event_open;
#[allow(dead_code, clippy::all)]
pub mod rseq_calls;

#[allow(dead_code, clippy::all)]
pub mod clone3;
#[allow(dead_code, clippy::all)]
pub mod copy_file_range_call;
#[allow(dead_code, clippy::all)]
pub mod futex_requeue;
#[allow(dead_code, clippy::all)]
pub mod mount_setattr;
#[allow(dead_code, clippy::all)]
pub mod sched_getattr;
#[allow(dead_code, clippy::all)]
pub mod seccomp_calls;

#[allow(dead_code, clippy::all)]
pub mod cred_calls;
#[allow(dead_code, clippy::all)]
pub mod ioprio_calls;
#[allow(dead_code, clippy::all)]
pub mod prctl_ops;
#[allow(dead_code, clippy::all)]
pub mod rlimit_calls;
#[allow(dead_code, clippy::all)]
pub mod wait_calls;

#[allow(dead_code, clippy::all)]
pub mod pivot_root;
#[allow(dead_code, clippy::all)]
pub mod ptrace_calls;
#[allow(dead_code, clippy::all)]
pub mod reboot_call;
#[allow(dead_code, clippy::all)]
pub mod timer_calls;

#[allow(dead_code, clippy::all)]
pub mod chroot_call;
#[allow(dead_code, clippy::all)]
pub mod personality_call;
#[allow(dead_code, clippy::all)]
pub mod syslog_call;
#[allow(dead_code, clippy::all)]
pub mod umask_call;

#[allow(dead_code, clippy::all)]
pub mod fadvise_call;
#[allow(dead_code, clippy::all)]
pub mod getdents_ext;
#[allow(dead_code, clippy::all)]
pub mod getrandom_call;
#[allow(dead_code, clippy::all)]
pub mod sync_calls;

#[allow(dead_code, clippy::all)]
pub mod clock_nanosleep_call;
#[allow(dead_code, clippy::all)]
pub mod prlimit_call;
#[allow(dead_code, clippy::all)]
pub mod sched_setattr_call;
#[allow(dead_code, clippy::all)]
pub mod waitid_call;

#[allow(dead_code, clippy::all)]
pub mod name_to_handle_call;
#[allow(dead_code, clippy::all)]
pub mod sendfile_call;
#[allow(dead_code, clippy::all)]
pub mod splice_tee_call;

#[allow(dead_code, clippy::all)]
pub mod io_uring_call;
#[allow(dead_code, clippy::all)]
pub mod perf_event_open_call;

#[allow(dead_code, clippy::all)]
pub mod accept_call;
#[allow(dead_code, clippy::all)]
pub mod dup_call;
#[allow(dead_code, clippy::all)]
pub mod fanotify_call;
#[allow(dead_code, clippy::all)]
pub mod flock_call;
#[allow(dead_code, clippy::all)]
pub mod getsockopt_call;
#[allow(dead_code, clippy::all)]
pub mod inotify_call;
#[allow(dead_code, clippy::all)]
pub mod io_uring_sqpoll;
#[allow(dead_code, clippy::all)]
pub mod ioprio_call;
#[allow(dead_code, clippy::all)]
pub mod membarrier_call;
#[allow(dead_code, clippy::all)]
pub mod mknod_call;
#[allow(dead_code, clippy::all)]
pub mod pipe_call;
#[allow(dead_code, clippy::all)]
pub mod sched_affinity_call;
#[allow(dead_code, clippy::all)]
pub mod sendmsg_call;
#[allow(dead_code, clippy::all)]
pub mod socket_create_call;
#[allow(dead_code, clippy::all)]
pub mod tgkill_call;

#[allow(dead_code, clippy::all)]
pub mod chmod_call;
#[allow(dead_code, clippy::all)]
pub mod readlink_call;
#[allow(dead_code, clippy::all)]
pub mod recvmsg_call;
#[allow(dead_code, clippy::all)]
pub mod select_call;
#[allow(dead_code, clippy::all)]
pub mod truncate_call;
#[allow(dead_code, clippy::all)]
pub mod utimes_call;

#[allow(dead_code, clippy::all)]
pub mod access_call;
#[allow(dead_code, clippy::all)]
pub mod chown_call;
#[allow(dead_code, clippy::all)]
pub mod close_call;
#[allow(dead_code, clippy::all)]
pub mod fcntl_call;
#[allow(dead_code, clippy::all)]
pub mod getdents_call;
#[allow(dead_code, clippy::all)]
pub mod getxattr_call;
#[allow(dead_code, clippy::all)]
pub mod link_call;
#[allow(dead_code, clippy::all)]
pub mod lseek_call;
#[allow(dead_code, clippy::all)]
pub mod mkdir_call;
#[allow(dead_code, clippy::all)]
pub mod mmap_anon_call;
#[allow(dead_code, clippy::all)]
pub mod open_call;
#[allow(dead_code, clippy::all)]
pub mod read_call;
#[allow(dead_code, clippy::all)]
pub mod removexattr_call;
#[allow(dead_code, clippy::all)]
pub mod rename_call;
#[allow(dead_code, clippy::all)]
pub mod rmdir_call;
#[allow(dead_code, clippy::all)]
pub mod setxattr_call;
#[allow(dead_code, clippy::all)]
pub mod stat_call;
#[allow(dead_code, clippy::all)]
pub mod symlink_call;
#[allow(dead_code, clippy::all)]
pub mod unlink_call;
#[allow(dead_code, clippy::all)]
pub mod write_call;

#[allow(dead_code, clippy::all)]
pub mod chdir_call;
#[allow(dead_code, clippy::all)]
pub mod fallocate_call;
#[allow(dead_code, clippy::all)]
pub mod fstatfs_call;
#[allow(dead_code, clippy::all)]
pub mod getcwd_call;
#[allow(dead_code, clippy::all)]
pub mod getpeername_call;
#[allow(dead_code, clippy::all)]
pub mod getrusage_call;
#[allow(dead_code, clippy::all)]
pub mod getsockname_call;
#[allow(dead_code, clippy::all)]
pub mod kill_call;
#[allow(dead_code, clippy::all)]
pub mod preadv_call;
#[allow(dead_code, clippy::all)]
pub mod readv_call;
#[allow(dead_code, clippy::all)]
pub mod setpgid_call;
#[allow(dead_code, clippy::all)]
pub mod setsockopt_call;
#[allow(dead_code, clippy::all)]
pub mod sigaction_call;
#[allow(dead_code, clippy::all)]
pub mod socket_bind_call;
#[allow(dead_code, clippy::all)]
pub mod socket_connect_call;
#[allow(dead_code, clippy::all)]
pub mod socket_listen_call;
#[allow(dead_code, clippy::all)]
pub mod socket_shutdown_call;
#[allow(dead_code, clippy::all)]
pub mod sysinfo_call;
#[allow(dead_code, clippy::all)]
pub mod times_call;

#[allow(dead_code, clippy::all)]
pub mod capget_call;
#[allow(dead_code, clippy::all)]
pub mod clock_gettime_call;
#[allow(dead_code, clippy::all)]
pub mod epoll_create_call;
#[allow(dead_code, clippy::all)]
pub mod eventfd_create_call;
#[allow(dead_code, clippy::all)]
pub mod getpid_call;
#[allow(dead_code, clippy::all)]
pub mod getuid_call;
#[allow(dead_code, clippy::all)]
pub mod inotify_init_call;
#[allow(dead_code, clippy::all)]
pub mod mlock_call;
#[allow(dead_code, clippy::all)]
pub mod mount_call;
#[allow(dead_code, clippy::all)]
pub mod msgget_call;
#[allow(dead_code, clippy::all)]
pub mod nanosleep_call;
#[allow(dead_code, clippy::all)]
pub mod pivot_root_call;
#[allow(dead_code, clippy::all)]
pub mod semget_call;
#[allow(dead_code, clippy::all)]
pub mod sethostname_call;
#[allow(dead_code, clippy::all)]
pub mod setuid_call;
#[allow(dead_code, clippy::all)]
pub mod shmget_call;
#[allow(dead_code, clippy::all)]
pub mod signalfd_create_call;
#[allow(dead_code, clippy::all)]
pub mod timer_create_call;
#[allow(dead_code, clippy::all)]
pub mod timerfd_create_call;
#[allow(dead_code, clippy::all)]
pub mod uname_call;

#[allow(dead_code, clippy::all)]
pub mod brk_call;
#[allow(dead_code, clippy::all)]
pub mod clone_call;
#[allow(dead_code, clippy::all)]
pub mod execve_call;
#[allow(dead_code, clippy::all)]
pub mod exit_call;
#[allow(dead_code, clippy::all)]
pub mod futex_call;
#[allow(dead_code, clippy::all)]
pub mod ioctl_generic_call;
#[allow(dead_code, clippy::all)]
pub mod mincore_call;
#[allow(dead_code, clippy::all)]
pub mod mmap_file_call;
#[allow(dead_code, clippy::all)]
pub mod mprotect_call;
#[allow(dead_code, clippy::all)]
pub mod mremap_call;
#[allow(dead_code, clippy::all)]
pub mod msync_call;
#[allow(dead_code, clippy::all)]
pub mod munmap_call;
#[allow(dead_code, clippy::all)]
pub mod ppoll_call;
#[allow(dead_code, clippy::all)]
pub mod pselect_call;
#[allow(dead_code, clippy::all)]
pub mod recvfrom_call;
#[allow(dead_code, clippy::all)]
pub mod sched_yield_call;
#[allow(dead_code, clippy::all)]
pub mod sendto_call;
#[allow(dead_code, clippy::all)]
pub mod socketpair_call;
#[allow(dead_code, clippy::all)]
pub mod wait4_call;
#[allow(dead_code, clippy::all)]
pub mod writev_call;

#[allow(dead_code, clippy::all)]
pub mod accept4_call;
#[allow(dead_code, clippy::all)]
pub mod bind_call;
#[allow(dead_code, clippy::all)]
pub mod connect_call;
#[allow(dead_code, clippy::all)]
pub mod epoll_ctl_call;
#[allow(dead_code, clippy::all)]
pub mod epoll_wait_call;
#[allow(dead_code, clippy::all)]
pub mod eventfd_call;
#[allow(dead_code, clippy::all)]
pub mod listen_call;
#[allow(dead_code, clippy::all)]
pub mod shutdown_call;
#[allow(dead_code, clippy::all)]
pub mod signalfd_call;
#[allow(dead_code, clippy::all)]
pub mod splice_call;
#[allow(dead_code, clippy::all)]
pub mod tee_call;
#[allow(dead_code, clippy::all)]
pub mod timerfd_settime_call;

#[allow(dead_code, clippy::all)]
pub mod bpf_call;
#[allow(dead_code, clippy::all)]
pub mod getrlimit_call;
#[allow(dead_code, clippy::all)]
pub mod io_uring_enter_call;
#[allow(dead_code, clippy::all)]
pub mod io_uring_register_call;
#[allow(dead_code, clippy::all)]
pub mod io_uring_setup_call;
#[allow(dead_code, clippy::all)]
pub mod keyctl_call;
#[allow(dead_code, clippy::all)]
pub mod prctl_call;
#[allow(dead_code, clippy::all)]
pub mod ptrace_call;
#[allow(dead_code, clippy::all)]
pub mod quotactl_call;
#[allow(dead_code, clippy::all)]
pub mod seccomp_call;

#[allow(dead_code, clippy::all)]
pub mod faccessat_call;
#[allow(dead_code, clippy::all)]
pub mod fchmodat_call;
#[allow(dead_code, clippy::all)]
pub mod fchownat_call;
#[allow(dead_code, clippy::all)]
pub mod linkat_call;
#[allow(dead_code, clippy::all)]
pub mod mkdirat_call;
#[allow(dead_code, clippy::all)]
pub mod mknodat_call;
#[allow(dead_code, clippy::all)]
pub mod readlinkat_call;
#[allow(dead_code, clippy::all)]
pub mod renameat2_call;
#[allow(dead_code, clippy::all)]
pub mod symlinkat_call;
#[allow(dead_code, clippy::all)]
pub mod unlinkat_call;

#[allow(dead_code, clippy::all)]
pub mod clone3_call;
#[allow(dead_code, clippy::all)]
pub mod close_range_call;
#[allow(dead_code, clippy::all)]
pub mod landlock_call;
#[allow(dead_code, clippy::all)]
pub mod memfd_create_call;
#[allow(dead_code, clippy::all)]
pub mod memfd_secret_call;
#[allow(dead_code, clippy::all)]
pub mod openat2_call;
#[allow(dead_code, clippy::all)]
pub mod pidfd_getfd_call;
#[allow(dead_code, clippy::all)]
pub mod pidfd_open_call;
#[allow(dead_code, clippy::all)]
pub mod pidfd_send_signal_call;
#[allow(dead_code, clippy::all)]
pub mod process_madvise_call;
#[allow(dead_code, clippy::all)]
pub mod set_tid_address_call;
#[allow(dead_code, clippy::all)]
pub mod statx_call;
#[allow(dead_code, clippy::all)]
pub mod sync_file_range_call;
#[allow(dead_code, clippy::all)]
pub mod utimensat_call;

#[allow(dead_code, clippy::all)]
pub mod alarm_call;
#[allow(dead_code, clippy::all)]
pub mod arch_prctl_call;
#[allow(dead_code, clippy::all)]
pub mod clock_getres_call;
#[allow(dead_code, clippy::all)]
pub mod clock_settime_call;
#[allow(dead_code, clippy::all)]
pub mod epoll_create1_call;
#[allow(dead_code, clippy::all)]
pub mod eventfd2_call;
#[allow(dead_code, clippy::all)]
pub mod fanotify_init_call;
#[allow(dead_code, clippy::all)]
pub mod fanotify_mark_call;
#[allow(dead_code, clippy::all)]
pub mod fdatasync_call;
#[allow(dead_code, clippy::all)]
pub mod fsconfig_call;
#[allow(dead_code, clippy::all)]
pub mod fsmount_call;
#[allow(dead_code, clippy::all)]
pub mod fsopen_call;
#[allow(dead_code, clippy::all)]
pub mod fspick_call;
#[allow(dead_code, clippy::all)]
pub mod fsync_call;
#[allow(dead_code, clippy::all)]
pub mod ftruncate_call;
#[allow(dead_code, clippy::all)]
pub mod getgroups_call;
#[allow(dead_code, clippy::all)]
pub mod getitimer_call;
#[allow(dead_code, clippy::all)]
pub mod getpgrp_call;
#[allow(dead_code, clippy::all)]
pub mod getppid_call;
#[allow(dead_code, clippy::all)]
pub mod getrandom_ext_call;
#[allow(dead_code, clippy::all)]
pub mod getsid_call;
#[allow(dead_code, clippy::all)]
pub mod gettid_call;
#[allow(dead_code, clippy::all)]
pub mod inotify_add_watch_call;
#[allow(dead_code, clippy::all)]
pub mod inotify_init1_call;
#[allow(dead_code, clippy::all)]
pub mod inotify_rm_watch_call;
#[allow(dead_code, clippy::all)]
pub mod kcmp_ext_call;
#[allow(dead_code, clippy::all)]
pub mod madvise_call;
#[allow(dead_code, clippy::all)]
pub mod mlock2_call;
#[allow(dead_code, clippy::all)]
pub mod mount_setattr_call;
#[allow(dead_code, clippy::all)]
pub mod move_mount_call;
#[allow(dead_code, clippy::all)]
pub mod open_tree_call;
#[allow(dead_code, clippy::all)]
pub mod pause_call;
#[allow(dead_code, clippy::all)]
pub mod process_vm_readv_call;
#[allow(dead_code, clippy::all)]
pub mod process_vm_writev_call;
#[allow(dead_code, clippy::all)]
pub mod pwrite_call;
#[allow(dead_code, clippy::all)]
pub mod pwritev_call;
#[allow(dead_code, clippy::all)]
pub mod recvmmsg_call;
#[allow(dead_code, clippy::all)]
pub mod sendmmsg_call;
#[allow(dead_code, clippy::all)]
pub mod setgroups_call;
#[allow(dead_code, clippy::all)]
pub mod setsid_call;
#[allow(dead_code, clippy::all)]
pub mod signalfd4_call;
#[allow(dead_code, clippy::all)]
pub mod sigpending_call;
#[allow(dead_code, clippy::all)]
pub mod sigprocmask_call;
#[allow(dead_code, clippy::all)]
pub mod sigsuspend_call;
#[allow(dead_code, clippy::all)]
pub mod timer_gettime_call;
#[allow(dead_code, clippy::all)]
pub mod timerfd_gettime_call;

#[allow(dead_code, clippy::all)]
pub mod capset_call;
#[allow(dead_code, clippy::all)]
pub mod close_range_ext_call;
#[allow(dead_code, clippy::all)]
pub mod copy_file_range_ext_call;
#[allow(dead_code, clippy::all)]
pub mod getegid_call;
#[allow(dead_code, clippy::all)]
pub mod geteuid_call;
#[allow(dead_code, clippy::all)]
pub mod io_pgetevents_call;
#[allow(dead_code, clippy::all)]
pub mod msgctl_call;
#[allow(dead_code, clippy::all)]
pub mod name_to_handle_at_call;
#[allow(dead_code, clippy::all)]
pub mod open_by_handle_at_call;
#[allow(dead_code, clippy::all)]
pub mod pidfd_getfd_ext_call;
#[allow(dead_code, clippy::all)]
pub mod pkey_alloc_call;
#[allow(dead_code, clippy::all)]
pub mod quotactl_fd_call;
#[allow(dead_code, clippy::all)]
pub mod rseq_call;
#[allow(dead_code, clippy::all)]
pub mod semctl_call;
#[allow(dead_code, clippy::all)]
pub mod semop_call;
#[allow(dead_code, clippy::all)]
pub mod vmsplice_call;

#[allow(dead_code, clippy::all)]
pub mod epoll_pwait_call;
#[allow(dead_code, clippy::all)]
pub mod pkey_free_call;
#[allow(dead_code, clippy::all)]
pub mod setgid_call;
#[allow(dead_code, clippy::all)]
pub mod setitimer_call;

#[allow(dead_code, clippy::all)]
pub mod acct_call;
#[allow(dead_code, clippy::all)]
pub mod add_key_call;
#[allow(dead_code, clippy::all)]
pub mod adjtimex_call;
#[allow(dead_code, clippy::all)]
pub mod delete_module_call;
#[allow(dead_code, clippy::all)]
pub mod get_mempolicy_call;
#[allow(dead_code, clippy::all)]
pub mod getdomainname_call;
#[allow(dead_code, clippy::all)]
pub mod getresuid_call;
#[allow(dead_code, clippy::all)]
pub mod init_module_call;
#[allow(dead_code, clippy::all)]
pub mod io_setup_call;
#[allow(dead_code, clippy::all)]
pub mod ioperm_call;
#[allow(dead_code, clippy::all)]
pub mod kexec_load_call;
#[allow(dead_code, clippy::all)]
pub mod lookup_dcookie_call;
#[allow(dead_code, clippy::all)]
pub mod mbind_call;
#[allow(dead_code, clippy::all)]
pub mod migrate_pages_call;
#[allow(dead_code, clippy::all)]
pub mod modify_ldt_call;
#[allow(dead_code, clippy::all)]
pub mod move_pages_call;
#[allow(dead_code, clippy::all)]
pub mod msgrcv_call;
#[allow(dead_code, clippy::all)]
pub mod msgsnd_call;
#[allow(dead_code, clippy::all)]
pub mod nfsservctl_call;
#[allow(dead_code, clippy::all)]
pub mod pkey_mprotect_call;
#[allow(dead_code, clippy::all)]
pub mod request_key_call;
#[allow(dead_code, clippy::all)]
pub mod set_mempolicy_call;
#[allow(dead_code, clippy::all)]
pub mod setresuid_call;
#[allow(dead_code, clippy::all)]
pub mod setreuid_call;
#[allow(dead_code, clippy::all)]
pub mod settimeofday_call;
#[allow(dead_code, clippy::all)]
pub mod shmat_call;
#[allow(dead_code, clippy::all)]
pub mod shmctl_call;
#[allow(dead_code, clippy::all)]
pub mod shmdt_call;
#[allow(dead_code, clippy::all)]
pub mod swapoff_call;
#[allow(dead_code, clippy::all)]
pub mod swapon_call;
#[allow(dead_code, clippy::all)]
pub mod userfaultfd_call;
#[allow(dead_code, clippy::all)]
pub mod vhangup_call;

#[allow(dead_code, clippy::all)]
pub mod accept_ext_call;
#[allow(dead_code, clippy::all)]
pub mod capget_ext_call;
#[allow(dead_code, clippy::all)]
pub mod connect_ext_call;
#[allow(dead_code, clippy::all)]
pub mod exec_common;
#[allow(dead_code, clippy::all)]
pub mod exec_elf_call;
#[allow(dead_code, clippy::all)]
pub mod execveat_call;
#[allow(dead_code, clippy::all)]
pub mod exit_group_call;
#[allow(dead_code, clippy::all)]
pub mod fgetxattr_call;
#[allow(dead_code, clippy::all)]
pub mod flistxattr_call;
#[allow(dead_code, clippy::all)]
pub mod fremovexattr_call;
#[allow(dead_code, clippy::all)]
pub mod fsetxattr_call;
#[allow(dead_code, clippy::all)]
pub mod futex_op_call;
#[allow(dead_code, clippy::all)]
pub mod futex_waitv_call;
#[allow(dead_code, clippy::all)]
pub mod get_robust_list_call;
#[allow(dead_code, clippy::all)]
pub mod getcpu_call;
#[allow(dead_code, clippy::all)]
pub mod getgid_call;
#[allow(dead_code, clippy::all)]
pub mod getitimer_ext_call;
#[allow(dead_code, clippy::all)]
pub mod getresgid_call;
#[allow(dead_code, clippy::all)]
pub mod getresuid_ext_call;
#[allow(dead_code, clippy::all)]
pub mod getrlimit_ext_call;
#[allow(dead_code, clippy::all)]
pub mod gettimeofday_call;
#[allow(dead_code, clippy::all)]
pub mod io_cancel_call;
#[allow(dead_code, clippy::all)]
pub mod iopl_call;
#[allow(dead_code, clippy::all)]
pub mod lgetxattr_call;
#[allow(dead_code, clippy::all)]
pub mod listen_ext_call;
#[allow(dead_code, clippy::all)]
pub mod llistxattr_call;
#[allow(dead_code, clippy::all)]
pub mod lremovexattr_call;
#[allow(dead_code, clippy::all)]
pub mod lsetxattr_call;
#[allow(dead_code, clippy::all)]
pub mod mlockall_call;
#[allow(dead_code, clippy::all)]
pub mod nanosleep_ext_call;
#[allow(dead_code, clippy::all)]
pub mod preadv2_call;
#[allow(dead_code, clippy::all)]
pub mod prlimit64_call;
#[allow(dead_code, clippy::all)]
pub mod process_cred_call;
#[allow(dead_code, clippy::all)]
pub mod ptrace_ext_call;
#[allow(dead_code, clippy::all)]
pub mod pwritev2_call;
#[allow(dead_code, clippy::all)]
pub mod remap_file_pages_call;
#[allow(dead_code, clippy::all)]
pub mod renameat_call;
#[allow(dead_code, clippy::all)]
pub mod rlimit_query_call;
#[allow(dead_code, clippy::all)]
pub mod rusage_ext_call;
#[allow(dead_code, clippy::all)]
pub mod sched_get_priority_call;
#[allow(dead_code, clippy::all)]
pub mod sched_getattr_call;
#[allow(dead_code, clippy::all)]
pub mod sched_getparam_call;
#[allow(dead_code, clippy::all)]
pub mod sched_getscheduler_call;
#[allow(dead_code, clippy::all)]
pub mod sched_param_call;
#[allow(dead_code, clippy::all)]
pub mod sched_policy_call;
#[allow(dead_code, clippy::all)]
pub mod sched_rr_getinterval_call;
#[allow(dead_code, clippy::all)]
pub mod sched_rr_interval_call;
#[allow(dead_code, clippy::all)]
pub mod sched_setparam_call;
#[allow(dead_code, clippy::all)]
pub mod sched_setscheduler_call;
#[allow(dead_code, clippy::all)]
pub mod semtimedop_call;
#[allow(dead_code, clippy::all)]
pub mod set_robust_list_call;
#[allow(dead_code, clippy::all)]
pub mod setdomainname_call;
#[allow(dead_code, clippy::all)]
pub mod setfsgid_call;
#[allow(dead_code, clippy::all)]
pub mod setfsuid_call;
#[allow(dead_code, clippy::all)]
pub mod setns_call;
#[allow(dead_code, clippy::all)]
pub mod setresgid_call;
#[allow(dead_code, clippy::all)]
pub mod setrlimit_call;
#[allow(dead_code, clippy::all)]
pub mod shutdown_ext_call;
#[allow(dead_code, clippy::all)]
pub mod sock_addr_call;
#[allow(dead_code, clippy::all)]
pub mod sock_opt_ext_call;
#[allow(dead_code, clippy::all)]
pub mod sock_recv_call;
#[allow(dead_code, clippy::all)]
pub mod socket_call;
#[allow(dead_code, clippy::all)]
pub mod socketpair_ext_call;
#[allow(dead_code, clippy::all)]
pub mod sysfs_call;
#[allow(dead_code, clippy::all)]
pub mod sysinfo_ext_call;
#[allow(dead_code, clippy::all)]
pub mod syslog_ext_call;
#[allow(dead_code, clippy::all)]
pub mod timer_delete_call;
#[allow(dead_code, clippy::all)]
pub mod timer_getoverrun_call;
#[allow(dead_code, clippy::all)]
pub mod times_ext_call;
#[allow(dead_code, clippy::all)]
pub mod umount2_call;
#[allow(dead_code, clippy::all)]
pub mod unshare_call;
#[allow(dead_code, clippy::all)]
pub mod utime_call;
#[allow(dead_code, clippy::all)]
pub mod utsname_call;
#[allow(dead_code, clippy::all)]
pub mod wait_ext_call;
#[allow(dead_code, clippy::all)]
pub mod wait_signal_call;

#[allow(dead_code, clippy::all)]
pub mod dup2_call;
#[allow(dead_code, clippy::all)]
pub mod dup3_call;
#[allow(dead_code, clippy::all)]
pub mod io_destroy_call;
#[allow(dead_code, clippy::all)]
pub mod io_getevents_call;
#[allow(dead_code, clippy::all)]
pub mod io_submit_call;
#[allow(dead_code, clippy::all)]
pub mod mq_getsetattr_call;
#[allow(dead_code, clippy::all)]
pub mod mq_notify_call;
#[allow(dead_code, clippy::all)]
pub mod mq_open_call;
#[allow(dead_code, clippy::all)]
pub mod mq_receive_call;
#[allow(dead_code, clippy::all)]
pub mod mq_send_call;
#[allow(dead_code, clippy::all)]
pub mod mq_unlink_call;
#[allow(dead_code, clippy::all)]
pub mod pipe2_call;
#[allow(dead_code, clippy::all)]
pub mod timer_settime_call;

#[allow(dead_code, clippy::all)]
pub mod sys_clock_nanosleep;
#[allow(dead_code, clippy::all)]
pub mod sys_copy_file_range;
#[allow(dead_code, clippy::all)]
pub mod sys_getrandom;
#[allow(dead_code, clippy::all)]
pub mod sys_io_uring_enter;
#[allow(dead_code, clippy::all)]
pub mod sys_prlimit;
#[allow(dead_code, clippy::all)]
pub mod sys_reboot;

#[allow(dead_code, clippy::all)]
pub mod sys_fanotify_init;
#[allow(dead_code, clippy::all)]
pub mod sys_kcmp;
#[allow(dead_code, clippy::all)]
pub mod sys_membarrier;
#[allow(dead_code, clippy::all)]
pub mod sys_name_to_handle;
#[allow(dead_code, clippy::all)]
pub mod sys_open_by_handle;
#[allow(dead_code, clippy::all)]
pub mod sys_perf_event_open;

#[allow(dead_code, clippy::all)]
pub mod sys_close_range;
#[allow(dead_code, clippy::all)]
pub mod sys_landlock_create;
#[allow(dead_code, clippy::all)]
pub mod sys_mount_setattr;
#[allow(dead_code, clippy::all)]
pub mod sys_pidfd_send_signal;
#[allow(dead_code, clippy::all)]
pub mod sys_quotactl;
#[allow(dead_code, clippy::all)]
pub mod sys_seccomp_notify;

#[allow(dead_code, clippy::all)]
pub mod sys_cachestat;
#[allow(dead_code, clippy::all)]
pub mod sys_futex_waitv;
#[allow(dead_code, clippy::all)]
pub mod sys_map_shadow_stack;
#[allow(dead_code, clippy::all)]
pub mod sys_mseal;
#[allow(dead_code, clippy::all)]
pub mod sys_process_mrelease;
#[allow(dead_code, clippy::all)]
pub mod sys_set_mempolicy_home;

#[allow(dead_code, clippy::all)]
pub mod sys_landlock;
#[allow(dead_code, clippy::all)]
pub mod sys_pidfd_open;
#[allow(dead_code, clippy::all)]
pub mod sys_statx;
