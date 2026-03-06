// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX microkernel core.
//!
//! The microkernel provides only the essential services: scheduling,
//! inter-process communication, and basic memory management.
//! All other OS services (drivers, file systems, networking) run
//! as isolated user-space processes communicating via IPC.

#![no_std]
#![feature(abi_x86_interrupt)]

pub mod aio;
pub mod apparmor;
pub mod arch;
pub mod audit;
pub mod audit_rules;
pub mod bpf;
pub mod bpf_maps;
pub mod bpf_prog;
pub mod bpf_verifier;
pub mod bridge;
pub mod cap;
pub mod cgroup;
pub mod cgroup_cpu;
pub mod cgroup_cpuset;
pub mod cgroup_freezer;
pub mod cgroup_io;
pub mod cgroup_pids;
pub mod cmdline;
pub mod cmwq;
pub mod cpu_hotplug;
pub mod cputime;
pub mod crypto;
pub mod dhcp;
pub mod dm_verity;
pub mod dmesg;
pub mod dns;
pub mod dynlink;
pub mod elf;
pub mod epoll;
pub mod eventfd;
pub mod evm;
pub mod exec;
pub mod ftrace;
pub mod futex;
pub mod futex_pi;
pub mod gre;
pub mod igmp;
pub mod ima;
pub mod init;
pub mod inotify;
pub mod integrity;
pub mod io_uring;
pub mod io_uring_ext;
pub mod ipv6;
pub mod kaslr;
#[allow(dead_code, clippy::all)]
pub mod kcov;
pub mod kdb;
pub mod kexec;
pub mod keyring;
pub mod klp_apply;
pub mod kmod;
pub mod kprobes;
pub mod kthread;
pub mod kvm;
pub mod landlock;
pub mod ldso;
pub mod livepatch;
#[allow(dead_code, clippy::all)]
pub mod loadpin;
pub mod lockdown;
pub mod log;
pub mod mac;
pub mod mmap;
pub mod net;
pub mod netfilter;
pub mod netlink;
pub mod netns;
#[allow(dead_code, clippy::all)]
pub mod nf_conntrack;
pub mod panic_info;
pub mod panic_notifier;
pub mod perf;
pub mod pidfd;
pub mod pidfd_ext;
pub mod poll;
pub mod posix_timer;
pub mod prctl;
pub mod printk;
pub mod printk_ratelimit;
pub mod quic;
pub mod random;
pub mod rcu;
pub mod rcu_tree;
pub mod rlimit;
pub mod route;
pub mod rseq;
#[allow(dead_code, clippy::all)]
pub mod safesetid;
pub mod sched;
pub mod sctp;
pub mod seccomp;
pub mod seccomp_filter;
pub mod seccomp_notifier;
pub mod secure_boot;
pub mod shmem;
pub mod signal_deliver;
pub mod signalfd;
pub mod smack;
pub mod socket;
pub mod splice;
#[allow(dead_code, clippy::all)]
pub mod suspend;
pub mod sysctl;
pub mod tc;
pub mod tc_htb;
pub mod tc_police;
pub mod tc_sfq;
pub mod tcp;
pub mod tcp_congestion;
pub mod tcp_fastopen;
pub mod termios;
pub mod timer;
pub mod timerfd;
pub mod tls;
pub mod tomoyo;
pub mod tpm;
pub mod trace;
#[allow(dead_code, clippy::all)]
pub mod tun_tap;
pub mod uaccess;
pub mod udp;
pub mod unix_socket;
pub mod userfaultfd;
pub mod veth;
pub mod wait;
pub mod wifi;
#[allow(dead_code, clippy::all)]
pub mod wireguard;
pub mod workqueue;
pub mod xattr;
pub mod xdp;
#[allow(dead_code, clippy::all)]
pub mod xfrm;
#[allow(dead_code, clippy::all)]
pub mod yama;

// --- Batch 5 ---
#[allow(dead_code, clippy::all)]
pub mod core_sched;
#[allow(dead_code, clippy::all)]
pub mod energy_aware_sched;
#[allow(dead_code, clippy::all)]
pub mod psi;

// --- Batch 6 ---
#[allow(dead_code, clippy::all)]
pub mod hung_task;
#[allow(dead_code, clippy::all)]
pub mod sched_deadline;
#[allow(dead_code, clippy::all)]
pub mod softlockup;

// --- Batch 7 ---
#[allow(dead_code, clippy::all)]
pub mod cgroup_device;
#[allow(dead_code, clippy::all)]
pub mod nfqueue;
#[allow(dead_code, clippy::all)]
pub mod sched_rt;

// --- Batch 8 ---
#[allow(dead_code, clippy::all)]
pub mod cgroup_memory;
#[allow(dead_code, clippy::all)]
pub mod kdump;

// --- Batch 9 ---
#[allow(dead_code, clippy::all)]
pub mod cgroup_hugetlb;
#[allow(dead_code, clippy::all)]
pub mod kexec_reboot;
#[allow(dead_code, clippy::all)]
pub mod srcu;

// --- Batch 10 ---
#[allow(dead_code, clippy::all)]
pub mod bpf_map_types;
#[allow(dead_code, clippy::all)]
pub mod cgroup_cpuset_v2;
#[allow(dead_code, clippy::all)]
pub mod klp_core;

// --- Batch 11 ---
#[allow(dead_code, clippy::all)]
pub mod bpf_btf;
#[allow(dead_code, clippy::all)]
pub mod lockdep;
#[allow(dead_code, clippy::all)]
pub mod sched_ext;
