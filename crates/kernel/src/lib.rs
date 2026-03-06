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

#[allow(dead_code, clippy::all)]
pub mod core_sched;
#[allow(dead_code, clippy::all)]
pub mod energy_aware_sched;
#[allow(dead_code, clippy::all)]
pub mod psi;

#[allow(dead_code, clippy::all)]
pub mod hung_task;
#[allow(dead_code, clippy::all)]
pub mod sched_deadline;
#[allow(dead_code, clippy::all)]
pub mod softlockup;

#[allow(dead_code, clippy::all)]
pub mod cgroup_device;
#[allow(dead_code, clippy::all)]
pub mod nfqueue;
#[allow(dead_code, clippy::all)]
pub mod sched_rt;

#[allow(dead_code, clippy::all)]
pub mod cgroup_memory;
#[allow(dead_code, clippy::all)]
pub mod kdump;

#[allow(dead_code, clippy::all)]
pub mod cgroup_hugetlb;
#[allow(dead_code, clippy::all)]
pub mod kexec_reboot;
#[allow(dead_code, clippy::all)]
pub mod srcu;

#[allow(dead_code, clippy::all)]
pub mod bpf_map_types;
#[allow(dead_code, clippy::all)]
pub mod cgroup_cpuset_v2;
#[allow(dead_code, clippy::all)]
pub mod klp_core;

#[allow(dead_code, clippy::all)]
pub mod bpf_btf;
#[allow(dead_code, clippy::all)]
pub mod lockdep;
#[allow(dead_code, clippy::all)]
pub mod sched_ext;

#[allow(dead_code, clippy::all)]
pub mod bpf_ringbuf;
#[allow(dead_code, clippy::all)]
pub mod cgroup_net_cls;
#[allow(dead_code, clippy::all)]
pub mod tcp_bbr;

#[allow(dead_code, clippy::all)]
pub mod bpf_lsm;
#[allow(dead_code, clippy::all)]
pub mod cgroup_rdma;
#[allow(dead_code, clippy::all)]
pub mod nftables;

#[allow(dead_code, clippy::all)]
pub mod bpf_cgroup;
#[allow(dead_code, clippy::all)]
pub mod cgroup_misc;
#[allow(dead_code, clippy::all)]
pub mod perf_event;
#[allow(dead_code, clippy::all)]
pub mod rcu_nocb;
#[allow(dead_code, clippy::all)]
pub mod sched_autogroup;
#[allow(dead_code, clippy::all)]
pub mod tcp_cubic;

#[allow(dead_code, clippy::all)]
pub mod bpf_trampoline;
#[allow(dead_code, clippy::all)]
pub mod cgroup_v2;
#[allow(dead_code, clippy::all)]
pub mod ipvlan;
#[allow(dead_code, clippy::all)]
pub mod sched_idle_class;
#[allow(dead_code, clippy::all)]
pub mod tcp_metrics;
#[allow(dead_code, clippy::all)]
pub mod tcp_vegas;

#[allow(dead_code, clippy::all)]
pub mod bpf_struct_ops;
#[allow(dead_code, clippy::all)]
pub mod cgroup_blkio;
#[allow(dead_code, clippy::all)]
pub mod kthread_worker;
#[allow(dead_code, clippy::all)]
pub mod net_sched_fq;
#[allow(dead_code, clippy::all)]
pub mod sched_bandwidth;
#[allow(dead_code, clippy::all)]
pub mod tcp_mptcp;

#[allow(dead_code, clippy::all)]
pub mod xdp_core;

#[allow(dead_code, clippy::all)]
pub mod irq_work;
#[allow(dead_code, clippy::all)]
pub mod kcsan;
#[allow(dead_code, clippy::all)]
pub mod oom_reaper;
#[allow(dead_code, clippy::all)]
pub mod softirq;
#[allow(dead_code, clippy::all)]
pub mod sysrq;
#[allow(dead_code, clippy::all)]
pub mod time_ns;

#[allow(dead_code, clippy::all)]
pub mod bpf_helpers;
#[allow(dead_code, clippy::all)]
pub mod cgroup_v2_events;
#[allow(dead_code, clippy::all)]
pub mod cpu_idle;
#[allow(dead_code, clippy::all)]
pub mod kernel_locking;
#[allow(dead_code, clippy::all)]
pub mod sched_stats;
#[allow(dead_code, clippy::all)]
pub mod workqueue_ext;

#[allow(dead_code, clippy::all)]
pub mod bpf_sockops;
#[allow(dead_code, clippy::all)]
pub mod membarrier;
#[allow(dead_code, clippy::all)]
pub mod netpoll;
#[allow(dead_code, clippy::all)]
pub mod sched_fair;
#[allow(dead_code, clippy::all)]
pub mod task_work;
#[allow(dead_code, clippy::all)]
pub mod tcp_ulp;

#[allow(dead_code, clippy::all)]
pub mod jump_label;
#[allow(dead_code, clippy::all)]
pub mod panic_handler;
#[allow(dead_code, clippy::all)]
pub mod perf_events;
#[allow(dead_code, clippy::all)]
pub mod tracepoint;

#[allow(dead_code, clippy::all)]
pub mod energy_model;
#[allow(dead_code, clippy::all)]
pub mod oom_notifier;
#[allow(dead_code, clippy::all)]
pub mod rcu_segcb;
#[allow(dead_code, clippy::all)]
pub mod smpboot;
#[allow(dead_code, clippy::all)]
pub mod stack_protector;
#[allow(dead_code, clippy::all)]
pub mod task_io_accounting;

#[allow(dead_code, clippy::all)]
pub mod cpu_topology;
#[allow(dead_code, clippy::all)]
pub mod module_loader;
#[allow(dead_code, clippy::all)]
pub mod stop_machine;

#[allow(dead_code, clippy::all)]
pub mod audit_watch;
#[allow(dead_code, clippy::all)]
pub mod clockevent;
#[allow(dead_code, clippy::all)]
pub mod cred_mgmt;
#[allow(dead_code, clippy::all)]
pub mod irq_affinity;
#[allow(dead_code, clippy::all)]
pub mod kernel_params;
#[allow(dead_code, clippy::all)]
pub mod kernel_restart;
#[allow(dead_code, clippy::all)]
pub mod kobj_uevent;
#[allow(dead_code, clippy::all)]
pub mod net_cls_cgroup;
#[allow(dead_code, clippy::all)]
pub mod notifier_block;
#[allow(dead_code, clippy::all)]
pub mod nsproxy;
#[allow(dead_code, clippy::all)]
pub mod pid_namespace;
#[allow(dead_code, clippy::all)]
pub mod posix_cpu_timers;
#[allow(dead_code, clippy::all)]
pub mod power_management;
#[allow(dead_code, clippy::all)]
pub mod sched_numa_balance;
#[allow(dead_code, clippy::all)]
pub mod sys_info;
#[allow(dead_code, clippy::all)]
pub mod task_cputime;
#[allow(dead_code, clippy::all)]
pub mod task_delay_acct;
#[allow(dead_code, clippy::all)]
pub mod tasklet_hrtimer;

#[allow(dead_code, clippy::all)]
pub mod crash_dump;
#[allow(dead_code, clippy::all)]
pub mod kgdb;
#[allow(dead_code, clippy::all)]
pub mod sched_topology;
#[allow(dead_code, clippy::all)]
pub mod static_key;
#[allow(dead_code, clippy::all)]
pub mod tick_sched;
#[allow(dead_code, clippy::all)]
pub mod watch_queue;

#[allow(dead_code, clippy::all)]
pub mod cgroup_pressure;
#[allow(dead_code, clippy::all)]
pub mod completion;
#[allow(dead_code, clippy::all)]
pub mod cpu_accounting;
#[allow(dead_code, clippy::all)]
pub mod idr_alloc;
#[allow(dead_code, clippy::all)]
pub mod kernel_stack;
#[allow(dead_code, clippy::all)]
pub mod kprobe_event;
#[allow(dead_code, clippy::all)]
pub mod maple_tree_core;
#[allow(dead_code, clippy::all)]
pub mod percpu_counter;
#[allow(dead_code, clippy::all)]
pub mod pid_alloc;
#[allow(dead_code, clippy::all)]
pub mod radix_tree;
#[allow(dead_code, clippy::all)]
pub mod rcu_callback;
#[allow(dead_code, clippy::all)]
pub mod refcount_t;
#[allow(dead_code, clippy::all)]
pub mod sched_debug;
#[allow(dead_code, clippy::all)]
pub mod signal_pending;
#[allow(dead_code, clippy::all)]
pub mod task_struct_ext;
#[allow(dead_code, clippy::all)]
pub mod thread_info;
#[allow(dead_code, clippy::all)]
pub mod timer_migration;
#[allow(dead_code, clippy::all)]
pub mod uprobe;
#[allow(dead_code, clippy::all)]
pub mod wait_bit;
#[allow(dead_code, clippy::all)]
pub mod xarray;

#[allow(dead_code, clippy::all)]
pub mod bitfield;
#[allow(dead_code, clippy::all)]
pub mod bitmap_ops;
#[allow(dead_code, clippy::all)]
pub mod bus_type;
#[allow(dead_code, clippy::all)]
pub mod class_dev;
#[allow(dead_code, clippy::all)]
pub mod clock_event_dev;
#[allow(dead_code, clippy::all)]
pub mod cpu_freq_policy;
#[allow(dead_code, clippy::all)]
pub mod firmware_request;
#[allow(dead_code, clippy::all)]
pub mod hashtable_kern;
#[allow(dead_code, clippy::all)]
pub mod kfifo;
#[allow(dead_code, clippy::all)]
pub mod kobject_core;
#[allow(dead_code, clippy::all)]
pub mod kref;
#[allow(dead_code, clippy::all)]
pub mod kset;
#[allow(dead_code, clippy::all)]
pub mod llist;
#[allow(dead_code, clippy::all)]
pub mod mutex_kern;
#[allow(dead_code, clippy::all)]
pub mod power_domain;
#[allow(dead_code, clippy::all)]
pub mod rbtree;
#[allow(dead_code, clippy::all)]
pub mod rwsem;
#[allow(dead_code, clippy::all)]
pub mod spinlock_kern;
#[allow(dead_code, clippy::all)]
pub mod sys_resource;
#[allow(dead_code, clippy::all)]
pub mod wait_queue_head;

#[allow(dead_code, clippy::all)]
pub mod cpu_mask;
#[allow(dead_code, clippy::all)]
pub mod module_kern;
#[allow(dead_code, clippy::all)]
pub mod notifier_chain;
#[allow(dead_code, clippy::all)]
pub mod numa_node;
#[allow(dead_code, clippy::all)]
pub mod panic_kern;
#[allow(dead_code, clippy::all)]
pub mod preempt_kern;
#[allow(dead_code, clippy::all)]
pub mod printk_kern;
#[allow(dead_code, clippy::all)]
pub mod random_kern;
#[allow(dead_code, clippy::all)]
pub mod smp_call;
#[allow(dead_code, clippy::all)]
pub mod softirq_kern;
#[allow(dead_code, clippy::all)]
pub mod static_call;
#[allow(dead_code, clippy::all)]
pub mod tasklet_kern;
#[allow(dead_code, clippy::all)]
pub mod time_kern;
#[allow(dead_code, clippy::all)]
pub mod tracepoint_kern;
#[allow(dead_code, clippy::all)]
pub mod workqueue_kern;

#[allow(dead_code, clippy::all)]
pub mod rcu_core;
#[allow(dead_code, clippy::all)]
pub mod sched_core;
#[allow(dead_code, clippy::all)]
pub mod sched_idle;

#[allow(dead_code, clippy::all)]
pub mod hrtimer;
#[allow(dead_code, clippy::all)]
pub mod idr;
#[allow(dead_code, clippy::all)]
pub mod maple_tree;
#[allow(dead_code, clippy::all)]
pub mod refcount;
#[allow(dead_code, clippy::all)]
pub mod sched_dl;
#[allow(dead_code, clippy::all)]
pub mod sched_stop;
#[allow(dead_code, clippy::all)]
pub mod seqlock;
#[allow(dead_code, clippy::all)]
pub mod stacktrace;
#[allow(dead_code, clippy::all)]
pub mod tasklet;
#[allow(dead_code, clippy::all)]
pub mod wait_queue;

#[allow(dead_code, clippy::all)]
pub mod alarmtimer;
#[allow(dead_code, clippy::all)]
pub mod cgroup_core;
#[allow(dead_code, clippy::all)]
pub mod kernel_thread;
#[allow(dead_code, clippy::all)]
pub mod timer_list;

#[allow(dead_code, clippy::all)]
pub mod audit_core;
#[allow(dead_code, clippy::all)]
pub mod bpf_core;
#[allow(dead_code, clippy::all)]
pub mod bpf_map;
#[allow(dead_code, clippy::all)]
pub mod capability;
#[allow(dead_code, clippy::all)]
pub mod kallsyms;
#[allow(dead_code, clippy::all)]
pub mod lsm_hooks;
#[allow(dead_code, clippy::all)]
pub mod numa_balancing;
#[allow(dead_code, clippy::all)]
pub mod params;
#[allow(dead_code, clippy::all)]
pub mod watchdog_core;

#[allow(dead_code, clippy::all)]
pub mod cgroup_events;
#[allow(dead_code, clippy::all)]
pub mod cpu_affinity;
#[allow(dead_code, clippy::all)]
pub mod cpu_freq_gov;
#[allow(dead_code, clippy::all)]
pub mod cpu_park;
#[allow(dead_code, clippy::all)]
pub mod kasan;
#[allow(dead_code, clippy::all)]
pub mod kernel_signal;
#[allow(dead_code, clippy::all)]
pub mod khugepaged;
#[allow(dead_code, clippy::all)]
pub mod ksm;
#[allow(dead_code, clippy::all)]
pub mod memcg_swap;
#[allow(dead_code, clippy::all)]
pub mod ptrace_core;
#[allow(dead_code, clippy::all)]
pub mod rcu_barrier;
#[allow(dead_code, clippy::all)]
pub mod rcu_expedited;
#[allow(dead_code, clippy::all)]
pub mod sched_batch;
#[allow(dead_code, clippy::all)]
pub mod sched_migrate;
#[allow(dead_code, clippy::all)]
pub mod sched_pelt;
#[allow(dead_code, clippy::all)]
pub mod secid_alloc;
#[allow(dead_code, clippy::all)]
pub mod task_group;
#[allow(dead_code, clippy::all)]
pub mod tick_broadcast;
#[allow(dead_code, clippy::all)]
pub mod timer_slack;
#[allow(dead_code, clippy::all)]
pub mod workqueue_pool;

#[allow(dead_code, clippy::all)]
pub mod affinity_mask;
#[allow(dead_code, clippy::all)]
pub mod context_switch;
#[allow(dead_code, clippy::all)]
pub mod cpu_cacheinfo;
#[allow(dead_code, clippy::all)]
pub mod cpu_freq_scaling;
#[allow(dead_code, clippy::all)]
pub mod cpu_isolate;
#[allow(dead_code, clippy::all)]
pub mod hardirq;
#[allow(dead_code, clippy::all)]
pub mod kernel_cred;
#[allow(dead_code, clippy::all)]
pub mod kernel_printk_buf;
#[allow(dead_code, clippy::all)]
pub mod kmemleak;
#[allow(dead_code, clippy::all)]
pub mod oom_kill;
#[allow(dead_code, clippy::all)]
pub mod oom_score;
#[allow(dead_code, clippy::all)]
pub mod pid_controller;
#[allow(dead_code, clippy::all)]
pub mod preempt_notifier;
#[allow(dead_code, clippy::all)]
pub mod rcu_sync;
#[allow(dead_code, clippy::all)]
pub mod sched_load;
#[allow(dead_code, clippy::all)]
pub mod sched_wait;
#[allow(dead_code, clippy::all)]
pub mod softlockup_detector;
#[allow(dead_code, clippy::all)]
pub mod task_migration;
#[allow(dead_code, clippy::all)]
pub mod tick_oneshot;
#[allow(dead_code, clippy::all)]
pub mod timer_wheel;

#[allow(dead_code, clippy::all)]
pub mod cgroup_stat;
#[allow(dead_code, clippy::all)]
pub mod cpu_freq_driver;
#[allow(dead_code, clippy::all)]
pub mod cpu_hotplug_state;
#[allow(dead_code, clippy::all)]
pub mod cpuset_partition;
#[allow(dead_code, clippy::all)]
pub mod ftrace_filter;
#[allow(dead_code, clippy::all)]
pub mod hung_task_watchdog;
#[allow(dead_code, clippy::all)]
pub mod kexec_file;
#[allow(dead_code, clippy::all)]
pub mod kretprobe;
#[allow(dead_code, clippy::all)]
pub mod kthread_park;
#[allow(dead_code, clippy::all)]
pub mod lockstat;
#[allow(dead_code, clippy::all)]
pub mod module_sig;
#[allow(dead_code, clippy::all)]
pub mod panic_reboot;
#[allow(dead_code, clippy::all)]
pub mod perf_callchain;
#[allow(dead_code, clippy::all)]
pub mod rcu_grace_period;
#[allow(dead_code, clippy::all)]
pub mod rcu_stall;
#[allow(dead_code, clippy::all)]
pub mod sched_accounting;
#[allow(dead_code, clippy::all)]
pub mod sched_clock;
#[allow(dead_code, clippy::all)]
pub mod sched_domain;
#[allow(dead_code, clippy::all)]
pub mod sched_energy;
#[allow(dead_code, clippy::all)]
pub mod stackdepot;
#[allow(dead_code, clippy::all)]
pub mod sysrq_handler;
#[allow(dead_code, clippy::all)]
pub mod tasklet_softirq;
#[allow(dead_code, clippy::all)]
pub mod trace_event;
#[allow(dead_code, clippy::all)]
pub mod workqueue_affinity;

#[allow(dead_code, clippy::all)]
pub mod bpf_jit;
#[allow(dead_code, clippy::all)]
pub mod bpf_map_array;
#[allow(dead_code, clippy::all)]
pub mod bpf_prog_attach;
#[allow(dead_code, clippy::all)]
pub mod bpf_verifier_log;
#[allow(dead_code, clippy::all)]
pub mod cgroup_freezer_v2;
#[allow(dead_code, clippy::all)]
pub mod cgroup_memory_v2;
#[allow(dead_code, clippy::all)]
pub mod cgroup_net_prio;
#[allow(dead_code, clippy::all)]
pub mod cgroup_pids_v2;
#[allow(dead_code, clippy::all)]
pub mod clocksource_core;
#[allow(dead_code, clippy::all)]
pub mod cpu_freq_governor;
#[allow(dead_code, clippy::all)]
pub mod cpu_hotplug_ctrl;
#[allow(dead_code, clippy::all)]
pub mod cpu_hotplug_notify;
#[allow(dead_code, clippy::all)]
pub mod cpu_idle_poll;
#[allow(dead_code, clippy::all)]
pub mod crypto_hash;
#[allow(dead_code, clippy::all)]
pub mod crypto_skcipher;
#[allow(dead_code, clippy::all)]
pub mod energy_perf_bias;
#[allow(dead_code, clippy::all)]
pub mod ftrace_event;
#[allow(dead_code, clippy::all)]
pub mod ftrace_graph;
#[allow(dead_code, clippy::all)]
pub mod futex_waitv;
#[allow(dead_code, clippy::all)]
pub mod hung_task_panic;
#[allow(dead_code, clippy::all)]
pub mod irq_domain;
#[allow(dead_code, clippy::all)]
pub mod irq_work_queue;
#[allow(dead_code, clippy::all)]
pub mod kexec_load;
#[allow(dead_code, clippy::all)]
pub mod keyring_request;
#[allow(dead_code, clippy::all)]
pub mod kprobe_core;
#[allow(dead_code, clippy::all)]
pub mod ksoftirqd;
#[allow(dead_code, clippy::all)]
pub mod kthread_pool;
#[allow(dead_code, clippy::all)]
pub mod ktime_core;
#[allow(dead_code, clippy::all)]
pub mod landlock_core;
#[allow(dead_code, clippy::all)]
pub mod lockdep_chain;
#[allow(dead_code, clippy::all)]
pub mod lockdep_classes;
#[allow(dead_code, clippy::all)]
pub mod locking_rwsem;
#[allow(dead_code, clippy::all)]
pub mod module_unload;
#[allow(dead_code, clippy::all)]
pub mod net_namespace;
#[allow(dead_code, clippy::all)]
pub mod nmi_watchdog;
#[allow(dead_code, clippy::all)]
pub mod numa_migrate;
#[allow(dead_code, clippy::all)]
pub mod percpu_alloc;
#[allow(dead_code, clippy::all)]
pub mod perf_event_core;
#[allow(dead_code, clippy::all)]
pub mod perf_pmu;
#[allow(dead_code, clippy::all)]
pub mod power_supply;
#[allow(dead_code, clippy::all)]
pub mod rcu_preempt;
#[allow(dead_code, clippy::all)]
pub mod rcu_tree_node;
#[allow(dead_code, clippy::all)]
pub mod ring_buffer_core;
#[allow(dead_code, clippy::all)]
pub mod sched_cfs_bandwidth;
#[allow(dead_code, clippy::all)]
pub mod sched_group;
#[allow(dead_code, clippy::all)]
pub mod sched_group_rt;
#[allow(dead_code, clippy::all)]
pub mod seccomp_cache;
#[allow(dead_code, clippy::all)]
pub mod signal_queue;
#[allow(dead_code, clippy::all)]
pub mod softirq_tasklet;
#[allow(dead_code, clippy::all)]
pub mod softirq_vec;
#[allow(dead_code, clippy::all)]
pub mod stacktrace_save;
#[allow(dead_code, clippy::all)]
pub mod sysrq_key;
#[allow(dead_code, clippy::all)]
pub mod tasklet_action;
#[allow(dead_code, clippy::all)]
pub mod thermal_zone;
#[allow(dead_code, clippy::all)]
pub mod tick_nohz;
#[allow(dead_code, clippy::all)]
pub mod tracepoint_iter;
#[allow(dead_code, clippy::all)]
pub mod tracing_buffer;
#[allow(dead_code, clippy::all)]
pub mod uprobe_core;
#[allow(dead_code, clippy::all)]
pub mod workqueue_drain;
#[allow(dead_code, clippy::all)]
pub mod workqueue_high_prio;

#[allow(dead_code, clippy::all)]
pub mod cpu_topology_parse;
#[allow(dead_code, clippy::all)]
pub mod itimer_real;
#[allow(dead_code, clippy::all)]
pub mod oops_handler;
#[allow(dead_code, clippy::all)]
pub mod posix_timer_core;
#[allow(dead_code, clippy::all)]
pub mod printk_ringbuf;
#[allow(dead_code, clippy::all)]
pub mod uevent_netlink;

#[allow(dead_code, clippy::all)]
pub mod kasan_init;
#[allow(dead_code, clippy::all)]
pub mod panic_reboot_cpu;
#[allow(dead_code, clippy::all)]
pub mod printk_console;
#[allow(dead_code, clippy::all)]
pub mod smp_call_func;
#[allow(dead_code, clippy::all)]
pub mod stack_depot;
#[allow(dead_code, clippy::all)]
pub mod task_rcu_free;

#[allow(dead_code, clippy::all)]
pub mod kernel_module_load;
#[allow(dead_code, clippy::all)]
pub mod kernel_module_sig;
#[allow(dead_code, clippy::all)]
pub mod notifier_call_chain;
#[allow(dead_code, clippy::all)]
pub mod radix_tree_ops;
#[allow(dead_code, clippy::all)]
pub mod srcu_core;
#[allow(dead_code, clippy::all)]
pub mod xarray_core;

#[allow(dead_code, clippy::all)]
pub mod coredump_write;
#[allow(dead_code, clippy::all)]
pub mod cred_alloc;
#[allow(dead_code, clippy::all)]
pub mod exec_binprm;
#[allow(dead_code, clippy::all)]
pub mod namespace_mnt;
#[allow(dead_code, clippy::all)]
pub mod rlimit_check;
#[allow(dead_code, clippy::all)]
pub mod user_namespace;

#[allow(dead_code, clippy::all)]
pub mod kernel_module_loader;
