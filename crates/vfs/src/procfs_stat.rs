// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! /proc/stat implementation.
//!
//! Provides the data structures and text-generation logic for the Linux-style
//! `/proc/stat` file, which exposes per-CPU time accounting, context switches,
//! boot time, process fork counters, run-queue lengths, and per-vector softirq
//! counters.
//!
//! # Design
//!
//! - [`CpuTimes`] — per-CPU time fields (user, nice, system, idle, …)
//! - [`SoftirqCounters`] — per-vector softirq event counts
//! - [`ProcStat`] — full /proc/stat state (up to 32 CPUs)
//! - [`format_stat_output`] — render ProcStat to ASCII text

use oncrix_lib::{Error, Result};

extern crate alloc;
use alloc::vec::Vec;

// ── Constants ───────────────────────────────────────────────────────────────

/// Maximum number of CPUs tracked.
const MAX_CPUS: usize = 32;

/// Number of softirq vectors (matches Linux NR_SOFTIRQS).
const NR_SOFTIRQS: usize = 10;

// ── Softirq vector indices ────────────────────────────────────────────────────

pub const SOFTIRQ_HI: usize = 0;
pub const SOFTIRQ_TIMER: usize = 1;
pub const SOFTIRQ_NET_TX: usize = 2;
pub const SOFTIRQ_NET_RX: usize = 3;
pub const SOFTIRQ_BLOCK: usize = 4;
pub const SOFTIRQ_IRQ_POLL: usize = 5;
pub const SOFTIRQ_TASKLET: usize = 6;
pub const SOFTIRQ_SCHED: usize = 7;
pub const SOFTIRQ_HRTIMER: usize = 8;
pub const SOFTIRQ_RCU: usize = 9;

// ── CpuTimes ─────────────────────────────────────────────────────────────────

/// Per-CPU time accounting in jiffies (USER_HZ ticks).
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuTimes {
    /// Time spent in user mode.
    pub user: u64,
    /// Time spent in user mode with low priority (nice > 0).
    pub nice: u64,
    /// Time spent in kernel mode.
    pub system: u64,
    /// Time spent doing nothing.
    pub idle: u64,
    /// Time waiting for I/O to complete (not reliable on SMP).
    pub iowait: u64,
    /// Time servicing hardware interrupts.
    pub irq: u64,
    /// Time servicing software interrupts.
    pub softirq: u64,
    /// Involuntary wait time stolen by a hypervisor.
    pub steal: u64,
    /// Time spent running a virtual CPU (guest OS).
    pub guest: u64,
    /// Time spent running a niced virtual CPU.
    pub guest_nice: u64,
}

impl CpuTimes {
    /// Create zeroed CPU times.
    pub fn zero() -> Self {
        Self::default()
    }

    /// Compute the total time across all states.
    pub fn total(&self) -> u64 {
        self.user
            + self.nice
            + self.system
            + self.idle
            + self.iowait
            + self.irq
            + self.softirq
            + self.steal
            + self.guest
            + self.guest_nice
    }

    /// Account a user-mode tick.
    pub fn tick_user(&mut self) {
        self.user += 1;
    }

    /// Account a system-mode tick.
    pub fn tick_system(&mut self) {
        self.system += 1;
    }

    /// Account an idle tick.
    pub fn tick_idle(&mut self) {
        self.idle += 1;
    }

    /// Account an iowait tick.
    pub fn tick_iowait(&mut self) {
        self.iowait += 1;
    }

    /// Add two CpuTimes together (aggregate across CPUs).
    pub fn add(&self, other: &CpuTimes) -> CpuTimes {
        CpuTimes {
            user: self.user + other.user,
            nice: self.nice + other.nice,
            system: self.system + other.system,
            idle: self.idle + other.idle,
            iowait: self.iowait + other.iowait,
            irq: self.irq + other.irq,
            softirq: self.softirq + other.softirq,
            steal: self.steal + other.steal,
            guest: self.guest + other.guest,
            guest_nice: self.guest_nice + other.guest_nice,
        }
    }
}

// ── SoftirqCounters ──────────────────────────────────────────────────────────

/// Per-vector softirq event counters.
#[derive(Debug, Clone, Copy, Default)]
pub struct SoftirqCounters {
    /// Counts for each softirq vector (indexed by SOFTIRQ_* constants).
    pub counts: [u64; NR_SOFTIRQS],
}

impl SoftirqCounters {
    /// Create zeroed softirq counters.
    pub fn zero() -> Self {
        Self::default()
    }

    /// Increment the counter for a softirq vector.
    pub fn inc(&mut self, vec: usize) {
        if vec < NR_SOFTIRQS {
            self.counts[vec] += 1;
        }
    }

    /// Add a value to a softirq vector counter.
    pub fn add(&mut self, vec: usize, delta: u64) {
        if vec < NR_SOFTIRQS {
            self.counts[vec] += delta;
        }
    }

    /// Return the total across all vectors.
    pub fn total(&self) -> u64 {
        self.counts.iter().sum()
    }
}

// ── ProcStat ─────────────────────────────────────────────────────────────────

/// Full /proc/stat state.
pub struct ProcStat {
    /// Per-CPU time counters. Index 0 = cpu0, etc.
    per_cpu: [CpuTimes; MAX_CPUS],
    /// Number of online CPUs.
    num_cpus: usize,
    /// Total context switches since boot.
    pub ctxt: u64,
    /// Boot time (seconds since Unix epoch).
    pub btime: u64,
    /// Total number of processes created (fork/clone).
    pub processes: u64,
    /// Number of processes currently in the run queue.
    pub procs_running: u32,
    /// Number of processes currently blocked on I/O.
    pub procs_blocked: u32,
    /// Softirq counters (aggregate across all CPUs).
    pub softirq: SoftirqCounters,
}

impl ProcStat {
    /// Create a new ProcStat with `num_cpus` online CPUs.
    pub fn new(num_cpus: usize, btime: u64) -> Self {
        let num_cpus = num_cpus.min(MAX_CPUS).max(1);
        Self {
            per_cpu: [CpuTimes::zero(); MAX_CPUS],
            num_cpus,
            ctxt: 0,
            btime,
            processes: 0,
            procs_running: 0,
            procs_blocked: 0,
            softirq: SoftirqCounters::zero(),
        }
    }

    /// Return the CPU times for a specific CPU.
    pub fn cpu_times(&self, cpu: usize) -> Option<&CpuTimes> {
        if cpu < self.num_cpus {
            Some(&self.per_cpu[cpu])
        } else {
            None
        }
    }

    /// Return mutable CPU times for a specific CPU.
    pub fn cpu_times_mut(&mut self, cpu: usize) -> Option<&mut CpuTimes> {
        if cpu < self.num_cpus {
            Some(&mut self.per_cpu[cpu])
        } else {
            None
        }
    }

    /// Aggregate times across all CPUs.
    pub fn aggregate_times(&self) -> CpuTimes {
        let mut agg = CpuTimes::zero();
        for i in 0..self.num_cpus {
            agg = agg.add(&self.per_cpu[i]);
        }
        agg
    }

    /// Record a context switch (called from the scheduler).
    pub fn record_context_switch(&mut self) {
        self.ctxt += 1;
    }

    /// Record a process creation (called from fork/clone).
    pub fn record_fork(&mut self) {
        self.processes += 1;
    }

    /// Increment the running processes counter.
    pub fn inc_running(&mut self) {
        self.procs_running = self.procs_running.saturating_add(1);
    }

    /// Decrement the running processes counter.
    pub fn dec_running(&mut self) {
        self.procs_running = self.procs_running.saturating_sub(1);
    }

    /// Increment the blocked processes counter.
    pub fn inc_blocked(&mut self) {
        self.procs_blocked = self.procs_blocked.saturating_add(1);
    }

    /// Decrement the blocked processes counter.
    pub fn dec_blocked(&mut self) {
        self.procs_blocked = self.procs_blocked.saturating_sub(1);
    }

    /// Increment a softirq vector counter.
    pub fn inc_softirq(&mut self, vec: usize) {
        self.softirq.inc(vec);
    }

    /// Number of online CPUs.
    pub fn num_cpus(&self) -> usize {
        self.num_cpus
    }
}

// ── format_stat_output ───────────────────────────────────────────────────────

/// Render `/proc/stat` output to a byte buffer.
///
/// The output follows the Linux /proc/stat format exactly:
/// ```text
/// cpu  user nice system idle iowait irq softirq steal guest guest_nice
/// cpu0 ...
/// cpu1 ...
/// intr <total> ...
/// ctxt <count>
/// btime <seconds>
/// processes <count>
/// procs_running <count>
/// procs_blocked <count>
/// softirq <total> hi timer net_tx net_rx block irq_poll tasklet sched hrtimer rcu
/// ```
pub fn format_stat_output(stat: &ProcStat) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);

    // Aggregate "cpu" line
    let agg = stat.aggregate_times();
    write_cpu_line(&mut buf, b"cpu ", &agg)?;

    // Per-CPU lines
    for i in 0..stat.num_cpus {
        let label = format_cpu_label(i)?;
        write_cpu_line(&mut buf, &label, &stat.per_cpu[i])?;
    }

    // intr line (simplified: just total)
    buf.extend_from_slice(b"intr 0\n");

    // ctxt
    buf.extend_from_slice(b"ctxt ");
    write_u64(&mut buf, stat.ctxt);
    buf.push(b'\n');

    // btime
    buf.extend_from_slice(b"btime ");
    write_u64(&mut buf, stat.btime);
    buf.push(b'\n');

    // processes
    buf.extend_from_slice(b"processes ");
    write_u64(&mut buf, stat.processes);
    buf.push(b'\n');

    // procs_running
    buf.extend_from_slice(b"procs_running ");
    write_u64(&mut buf, stat.procs_running as u64);
    buf.push(b'\n');

    // procs_blocked
    buf.extend_from_slice(b"procs_blocked ");
    write_u64(&mut buf, stat.procs_blocked as u64);
    buf.push(b'\n');

    // softirq line
    buf.extend_from_slice(b"softirq ");
    write_u64(&mut buf, stat.softirq.total());
    for &c in &stat.softirq.counts {
        buf.push(b' ');
        write_u64(&mut buf, c);
    }
    buf.push(b'\n');

    Ok(buf)
}

// ── Private helpers ──────────────────────────────────────────────────────────

fn write_cpu_line(buf: &mut Vec<u8>, label: &[u8], t: &CpuTimes) -> Result<()> {
    buf.extend_from_slice(label);
    buf.push(b' ');
    write_u64(buf, t.user);
    buf.push(b' ');
    write_u64(buf, t.nice);
    buf.push(b' ');
    write_u64(buf, t.system);
    buf.push(b' ');
    write_u64(buf, t.idle);
    buf.push(b' ');
    write_u64(buf, t.iowait);
    buf.push(b' ');
    write_u64(buf, t.irq);
    buf.push(b' ');
    write_u64(buf, t.softirq);
    buf.push(b' ');
    write_u64(buf, t.steal);
    buf.push(b' ');
    write_u64(buf, t.guest);
    buf.push(b' ');
    write_u64(buf, t.guest_nice);
    buf.push(b'\n');
    Ok(())
}

/// Format "cpu<N> " label bytes.
fn format_cpu_label(cpu: usize) -> Result<Vec<u8>> {
    if cpu >= MAX_CPUS {
        return Err(Error::InvalidArgument);
    }
    let mut label = Vec::with_capacity(8);
    label.extend_from_slice(b"cpu");
    // Write decimal CPU number
    write_usize_into(&mut label, cpu);
    label.push(b' ');
    Ok(label)
}

/// Write a u64 as ASCII decimal digits into a buffer.
fn write_u64(buf: &mut Vec<u8>, v: u64) {
    if v == 0 {
        buf.push(b'0');
        return;
    }
    let mut tmp = [0u8; 20];
    let mut len = 0usize;
    let mut n = v;
    while n > 0 {
        tmp[len] = b'0' + (n % 10) as u8;
        n /= 10;
        len += 1;
    }
    for i in (0..len).rev() {
        buf.push(tmp[i]);
    }
}

/// Write a usize as ASCII decimal digits into a buffer.
fn write_usize_into(buf: &mut Vec<u8>, v: usize) {
    write_u64(buf, v as u64);
}

// ── Convenience builder ───────────────────────────────────────────────────────

/// Populate a `ProcStat` with sample workload data for testing.
pub fn sample_stat(num_cpus: usize, btime: u64) -> ProcStat {
    let mut stat = ProcStat::new(num_cpus, btime);
    for i in 0..num_cpus {
        if let Some(t) = stat.cpu_times_mut(i) {
            t.user = 1000 * (i as u64 + 1);
            t.system = 200 * (i as u64 + 1);
            t.idle = 50000 * (i as u64 + 1);
            t.iowait = 50 * (i as u64 + 1);
            t.irq = 10;
            t.softirq = 5;
        }
    }
    stat.ctxt = 4_000_000;
    stat.processes = 10_000;
    stat.procs_running = 2;
    stat.procs_blocked = 0;
    stat.softirq.add(SOFTIRQ_TIMER, 1_000_000);
    stat.softirq.add(SOFTIRQ_NET_RX, 500_000);
    stat.softirq.add(SOFTIRQ_NET_TX, 200_000);
    stat.softirq.add(SOFTIRQ_SCHED, 800_000);
    stat.softirq.add(SOFTIRQ_RCU, 300_000);
    stat
}
