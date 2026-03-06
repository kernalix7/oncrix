// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! System information — uname and sysinfo interfaces.
//!
//! Provides the kernel-side implementation of:
//! - `uname(2)` — system identification (OS name, hostname, release,
//!   version, machine architecture)
//! - `sysinfo(2)` — system statistics (uptime, load averages, memory
//!   usage, process counts)
//!
//! All strings are stored in fixed-size byte arrays to avoid heap
//! allocation. The uname structure follows POSIX.1-2024 requirements
//! (see `<sys/utsname.h>`).
//!
//! # Architecture
//!
//! ```text
//!  User-space
//!    │ uname(buf)              │ sysinfo(buf)
//!    ▼                         ▼
//!  syscall dispatcher          syscall dispatcher
//!    │                         │
//!    ▼                         ▼
//!  UtsName::copy_to_user()    SystemInfo::snapshot()
//!    │                         │
//!    ▼                         ▼
//!  Static UtsName instance     Dynamic counters from
//!  (set during boot)           scheduler, mm, timer
//! ```
//!
//! Reference: POSIX.1-2024 `<sys/utsname.h>`,
//! Linux `kernel/sys.c` (`uname`, `sysinfo`).

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum length for each utsname field (POSIX minimum is 256
/// for domainname; we use 65 like Linux for the primary fields).
const UTS_FIELD_LEN: usize = 65;

/// Length of the domain name field.
const UTS_DOMAIN_LEN: usize = 65;

/// Number of load average samples (1, 5, 15 minutes).
const LOAD_AVG_SAMPLES: usize = 3;

/// Fixed-point shift for load averages (11 bits fractional).
const LOAD_FSHIFT: u32 = 11;

/// Scale factor for load averages: 1.0 = 1 << LOAD_FSHIFT.
const _LOAD_SCALE: u64 = 1 << LOAD_FSHIFT;

/// Maximum hostname length for `sethostname`.
const MAX_HOSTNAME_LEN: usize = 64;

/// Maximum domain name length for `setdomainname`.
const MAX_DOMAINNAME_LEN: usize = 64;

/// Number of memory zone types tracked.
const NUM_MEM_ZONES: usize = 4;

/// Maximum number of CPU entries for per-CPU statistics.
const MAX_CPUS: usize = 256;

// -------------------------------------------------------------------
// UtsName — POSIX uname structure
// -------------------------------------------------------------------

/// POSIX `utsname` structure.
///
/// Contains system identification strings returned by `uname(2)`.
/// All fields are null-terminated byte arrays.
///
/// See POSIX.1-2024 `<sys/utsname.h>`.
#[derive(Clone)]
#[repr(C)]
pub struct UtsName {
    /// Operating system name (e.g., "ONCRIX").
    pub sysname: [u8; UTS_FIELD_LEN],
    /// Network node hostname.
    pub nodename: [u8; UTS_FIELD_LEN],
    /// Operating system release (e.g., "0.1.0").
    pub release: [u8; UTS_FIELD_LEN],
    /// Operating system version string.
    pub version: [u8; UTS_FIELD_LEN],
    /// Hardware architecture (e.g., "x86_64").
    pub machine: [u8; UTS_FIELD_LEN],
    /// NIS/YP domain name (Linux extension).
    pub domainname: [u8; UTS_DOMAIN_LEN],
}

impl UtsName {
    /// Create a new UtsName with default ONCRIX values.
    pub const fn new() -> Self {
        Self {
            sysname: Self::init_field(b"ONCRIX"),
            nodename: Self::init_field(b"localhost"),
            release: Self::init_field(b"0.1.0"),
            version: Self::init_field(b"#1 SMP PREEMPT_DYNAMIC"),
            machine: Self::init_field(b"x86_64"),
            domainname: Self::init_domain(b"(none)"),
        }
    }

    /// Initialize a UTS_FIELD_LEN field from a byte literal.
    const fn init_field(src: &[u8]) -> [u8; UTS_FIELD_LEN] {
        let mut buf = [0u8; UTS_FIELD_LEN];
        let len = if src.len() < UTS_FIELD_LEN - 1 {
            src.len()
        } else {
            UTS_FIELD_LEN - 1
        };
        let mut i = 0;
        while i < len {
            buf[i] = src[i];
            i += 1;
        }
        buf
    }

    /// Initialize a UTS_DOMAIN_LEN field from a byte literal.
    const fn init_domain(src: &[u8]) -> [u8; UTS_DOMAIN_LEN] {
        let mut buf = [0u8; UTS_DOMAIN_LEN];
        let len = if src.len() < UTS_DOMAIN_LEN - 1 {
            src.len()
        } else {
            UTS_DOMAIN_LEN - 1
        };
        let mut i = 0;
        while i < len {
            buf[i] = src[i];
            i += 1;
        }
        buf
    }

    /// Set the hostname (nodename).
    pub fn set_hostname(&mut self, name: &[u8]) -> Result<()> {
        if name.is_empty() || name.len() > MAX_HOSTNAME_LEN {
            return Err(Error::InvalidArgument);
        }
        self.nodename = [0u8; UTS_FIELD_LEN];
        self.nodename[..name.len()].copy_from_slice(name);
        Ok(())
    }

    /// Set the domain name.
    pub fn set_domainname(&mut self, name: &[u8]) -> Result<()> {
        if name.len() > MAX_DOMAINNAME_LEN {
            return Err(Error::InvalidArgument);
        }
        self.domainname = [0u8; UTS_DOMAIN_LEN];
        if !name.is_empty() {
            self.domainname[..name.len()].copy_from_slice(name);
        }
        Ok(())
    }

    /// Set the release string.
    pub fn set_release(&mut self, rel: &[u8]) -> Result<()> {
        if rel.is_empty() || rel.len() >= UTS_FIELD_LEN {
            return Err(Error::InvalidArgument);
        }
        self.release = [0u8; UTS_FIELD_LEN];
        self.release[..rel.len()].copy_from_slice(rel);
        Ok(())
    }

    /// Set the version string.
    pub fn set_version(&mut self, ver: &[u8]) -> Result<()> {
        if ver.is_empty() || ver.len() >= UTS_FIELD_LEN {
            return Err(Error::InvalidArgument);
        }
        self.version = [0u8; UTS_FIELD_LEN];
        self.version[..ver.len()].copy_from_slice(ver);
        Ok(())
    }

    /// Set the machine architecture string.
    pub fn set_machine(&mut self, arch: &[u8]) -> Result<()> {
        if arch.is_empty() || arch.len() >= UTS_FIELD_LEN {
            return Err(Error::InvalidArgument);
        }
        self.machine = [0u8; UTS_FIELD_LEN];
        self.machine[..arch.len()].copy_from_slice(arch);
        Ok(())
    }

    /// Return the sysname as a byte slice (up to first NUL).
    pub fn sysname_str(&self) -> &[u8] {
        field_to_str(&self.sysname)
    }

    /// Return the nodename as a byte slice.
    pub fn nodename_str(&self) -> &[u8] {
        field_to_str(&self.nodename)
    }

    /// Return the release as a byte slice.
    pub fn release_str(&self) -> &[u8] {
        field_to_str(&self.release)
    }

    /// Return the version as a byte slice.
    pub fn version_str(&self) -> &[u8] {
        field_to_str(&self.version)
    }

    /// Return the machine as a byte slice.
    pub fn machine_str(&self) -> &[u8] {
        field_to_str(&self.machine)
    }

    /// Return the domain name as a byte slice.
    pub fn domainname_str(&self) -> &[u8] {
        field_to_str(&self.domainname)
    }

    /// Copy the UtsName into a user-space buffer.
    ///
    /// The buffer must be at least `UtsName::SIZE` bytes.
    pub fn copy_to_buffer(&self, buf: &mut [u8]) -> Result<usize> {
        let size = Self::SIZE;
        if buf.len() < size {
            return Err(Error::InvalidArgument);
        }
        let mut off = 0;
        buf[off..off + UTS_FIELD_LEN].copy_from_slice(&self.sysname);
        off += UTS_FIELD_LEN;
        buf[off..off + UTS_FIELD_LEN].copy_from_slice(&self.nodename);
        off += UTS_FIELD_LEN;
        buf[off..off + UTS_FIELD_LEN].copy_from_slice(&self.release);
        off += UTS_FIELD_LEN;
        buf[off..off + UTS_FIELD_LEN].copy_from_slice(&self.version);
        off += UTS_FIELD_LEN;
        buf[off..off + UTS_FIELD_LEN].copy_from_slice(&self.machine);
        off += UTS_FIELD_LEN;
        buf[off..off + UTS_DOMAIN_LEN].copy_from_slice(&self.domainname);
        Ok(size)
    }

    /// Total byte size of the serialized UtsName.
    pub const SIZE: usize = UTS_FIELD_LEN * 5 + UTS_DOMAIN_LEN;
}

impl Default for UtsName {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// MemoryZone — tracked memory regions
// -------------------------------------------------------------------

/// Memory zone type identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryZoneType {
    /// DMA-capable memory (< 16 MiB on x86).
    Dma,
    /// DMA32-capable memory (< 4 GiB on x86_64).
    Dma32,
    /// Normal memory.
    Normal,
    /// High memory (32-bit only, not used on x86_64).
    HighMem,
}

/// Per-zone memory statistics.
#[derive(Debug, Clone, Copy)]
pub struct MemoryZoneInfo {
    /// Zone type.
    pub zone_type: MemoryZoneType,
    /// Total pages in this zone.
    pub total_pages: u64,
    /// Free pages in this zone.
    pub free_pages: u64,
    /// Pages used by the kernel/slab.
    pub kernel_pages: u64,
    /// Pages used as page cache.
    pub cached_pages: u64,
}

impl MemoryZoneInfo {
    /// Create an empty zone info.
    const fn empty() -> Self {
        Self {
            zone_type: MemoryZoneType::Normal,
            total_pages: 0,
            free_pages: 0,
            kernel_pages: 0,
            cached_pages: 0,
        }
    }
}

// -------------------------------------------------------------------
// CpuInfo — per-CPU statistics
// -------------------------------------------------------------------

/// Per-CPU time accounting (in clock ticks).
#[derive(Debug, Clone, Copy)]
pub struct CpuTimeInfo {
    /// Time spent in user mode.
    pub user_ticks: u64,
    /// Time spent in user mode with low priority (nice).
    pub nice_ticks: u64,
    /// Time spent in system (kernel) mode.
    pub system_ticks: u64,
    /// Time spent idle.
    pub idle_ticks: u64,
    /// Time spent waiting for I/O.
    pub iowait_ticks: u64,
    /// Time servicing hardware interrupts.
    pub irq_ticks: u64,
    /// Time servicing softirqs.
    pub softirq_ticks: u64,
}

impl CpuTimeInfo {
    /// Create zeroed CPU time info.
    const fn new() -> Self {
        Self {
            user_ticks: 0,
            nice_ticks: 0,
            system_ticks: 0,
            idle_ticks: 0,
            iowait_ticks: 0,
            irq_ticks: 0,
            softirq_ticks: 0,
        }
    }

    /// Total time across all categories.
    pub const fn total(&self) -> u64 {
        self.user_ticks
            + self.nice_ticks
            + self.system_ticks
            + self.idle_ticks
            + self.iowait_ticks
            + self.irq_ticks
            + self.softirq_ticks
    }
}

// -------------------------------------------------------------------
// SystemInfo — sysinfo(2) equivalent
// -------------------------------------------------------------------

/// System-wide statistics returned by `sysinfo(2)`.
///
/// All memory values are in bytes. Load averages use fixed-point
/// representation with `LOAD_FSHIFT` fractional bits.
///
/// Reference: Linux `struct sysinfo` in `<linux/sysinfo.h>`.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct SystemInfo {
    /// Seconds since boot.
    pub uptime: u64,
    /// 1, 5, and 15-minute load averages (fixed-point).
    pub loads: [u64; LOAD_AVG_SAMPLES],
    /// Total usable main memory (bytes).
    pub totalram: u64,
    /// Available main memory (bytes).
    pub freeram: u64,
    /// Amount of shared memory (bytes).
    pub sharedram: u64,
    /// Memory used by buffers (bytes).
    pub bufferram: u64,
    /// Total swap space (bytes).
    pub totalswap: u64,
    /// Available swap space (bytes).
    pub freeswap: u64,
    /// Number of current processes/threads.
    pub procs: u32,
    /// Total high memory (bytes, 0 on 64-bit).
    pub totalhigh: u64,
    /// Available high memory (bytes, 0 on 64-bit).
    pub freehigh: u64,
    /// Memory unit size (bytes per unit, usually 1).
    pub mem_unit: u32,
}

impl SystemInfo {
    /// Create a zeroed system info.
    pub const fn new() -> Self {
        Self {
            uptime: 0,
            loads: [0; LOAD_AVG_SAMPLES],
            totalram: 0,
            freeram: 0,
            sharedram: 0,
            bufferram: 0,
            totalswap: 0,
            freeswap: 0,
            procs: 0,
            totalhigh: 0,
            freehigh: 0,
            mem_unit: 1,
        }
    }

    /// Return the 1-minute load average as a floating-point-like
    /// pair (integer part, fractional thousandths).
    pub const fn load_1min(&self) -> (u64, u64) {
        fixed_to_parts(self.loads[0])
    }

    /// Return the 5-minute load average.
    pub const fn load_5min(&self) -> (u64, u64) {
        fixed_to_parts(self.loads[1])
    }

    /// Return the 15-minute load average.
    pub const fn load_15min(&self) -> (u64, u64) {
        fixed_to_parts(self.loads[2])
    }

    /// Memory utilization percentage (0-100).
    pub const fn mem_used_percent(&self) -> u64 {
        if self.totalram == 0 {
            return 0;
        }
        let used = self.totalram - self.freeram;
        (used * 100) / self.totalram
    }

    /// Swap utilization percentage (0-100).
    pub const fn swap_used_percent(&self) -> u64 {
        if self.totalswap == 0 {
            return 0;
        }
        let used = self.totalswap - self.freeswap;
        (used * 100) / self.totalswap
    }
}

impl Default for SystemInfo {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// SystemInfoCollector
// -------------------------------------------------------------------

/// Aggregates system information from various kernel subsystems.
///
/// The collector holds references to the current state and can
/// produce a `SystemInfo` snapshot on demand.
pub struct SystemInfoCollector {
    /// UTS name data.
    utsname: UtsName,
    /// Current system info (updated periodically).
    info: SystemInfo,
    /// Per-zone memory info.
    zones: [MemoryZoneInfo; NUM_MEM_ZONES],
    /// Number of active zones.
    zone_count: usize,
    /// Per-CPU time accounting.
    cpu_times: [CpuTimeInfo; MAX_CPUS],
    /// Number of online CPUs.
    online_cpus: usize,
    /// Number of possible CPUs (hardware).
    possible_cpus: usize,
    /// Boot time in seconds since epoch.
    boot_time_secs: u64,
    /// Monotonic tick counter.
    tick_count: u64,
    /// Ticks per second (HZ).
    ticks_per_sec: u64,
    /// Total context switches since boot.
    context_switches: u64,
    /// Total interrupts since boot.
    total_interrupts: u64,
    /// Total forks since boot.
    total_forks: u64,
    /// Running process count.
    running_procs: u32,
    /// Blocked process count.
    blocked_procs: u32,
}

impl Default for SystemInfoCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemInfoCollector {
    /// Create a new collector with default values.
    pub const fn new() -> Self {
        Self {
            utsname: UtsName::new(),
            info: SystemInfo::new(),
            zones: [const { MemoryZoneInfo::empty() }; NUM_MEM_ZONES],
            zone_count: 0,
            cpu_times: [const { CpuTimeInfo::new() }; MAX_CPUS],
            online_cpus: 1,
            possible_cpus: 1,
            boot_time_secs: 0,
            tick_count: 0,
            ticks_per_sec: 100,
            context_switches: 0,
            total_interrupts: 0,
            total_forks: 0,
            running_procs: 0,
            blocked_procs: 0,
        }
    }

    /// Return a reference to the UTS name.
    pub const fn utsname(&self) -> &UtsName {
        &self.utsname
    }

    /// Return a mutable reference to the UTS name.
    pub fn utsname_mut(&mut self) -> &mut UtsName {
        &mut self.utsname
    }

    /// Set the boot time (seconds since UNIX epoch).
    pub fn set_boot_time(&mut self, epoch_secs: u64) {
        self.boot_time_secs = epoch_secs;
    }

    /// Set the ticks-per-second value (HZ).
    pub fn set_ticks_per_sec(&mut self, hz: u64) {
        if hz > 0 {
            self.ticks_per_sec = hz;
        }
    }

    /// Set the number of possible CPUs.
    pub fn set_possible_cpus(&mut self, count: usize) {
        let capped = if count > MAX_CPUS {
            MAX_CPUS
        } else if count == 0 {
            1
        } else {
            count
        };
        self.possible_cpus = capped;
    }

    /// Set the number of online CPUs.
    pub fn set_online_cpus(&mut self, count: usize) {
        let capped = if count > self.possible_cpus {
            self.possible_cpus
        } else if count == 0 {
            1
        } else {
            count
        };
        self.online_cpus = capped;
    }

    /// Update the tick counter (called from the timer tick handler).
    pub fn tick(&mut self) {
        self.tick_count += 1;
    }

    /// Record a context switch.
    pub fn record_context_switch(&mut self) {
        self.context_switches += 1;
    }

    /// Record an interrupt.
    pub fn record_interrupt(&mut self) {
        self.total_interrupts += 1;
    }

    /// Record a fork (new process/thread created).
    pub fn record_fork(&mut self) {
        self.total_forks += 1;
    }

    /// Update running/blocked process counts.
    pub fn update_proc_counts(&mut self, running: u32, blocked: u32) {
        self.running_procs = running;
        self.blocked_procs = blocked;
    }

    /// Update memory statistics for the sysinfo structure.
    pub fn update_memory(
        &mut self,
        total_bytes: u64,
        free_bytes: u64,
        shared_bytes: u64,
        buffer_bytes: u64,
    ) {
        self.info.totalram = total_bytes;
        self.info.freeram = free_bytes;
        self.info.sharedram = shared_bytes;
        self.info.bufferram = buffer_bytes;
    }

    /// Update swap statistics.
    pub fn update_swap(&mut self, total_bytes: u64, free_bytes: u64) {
        self.info.totalswap = total_bytes;
        self.info.freeswap = free_bytes;
    }

    /// Update load averages (fixed-point values).
    pub fn update_loads(&mut self, loads: [u64; LOAD_AVG_SAMPLES]) {
        self.info.loads = loads;
    }

    /// Update the process count.
    pub fn update_procs(&mut self, count: u32) {
        self.info.procs = count;
    }

    /// Register a memory zone.
    pub fn register_zone(&mut self, zone_type: MemoryZoneType, total_pages: u64) -> Result<()> {
        if self.zone_count >= NUM_MEM_ZONES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.zone_count;
        self.zones[idx].zone_type = zone_type;
        self.zones[idx].total_pages = total_pages;
        self.zones[idx].free_pages = total_pages;
        self.zones[idx].kernel_pages = 0;
        self.zones[idx].cached_pages = 0;
        self.zone_count += 1;
        Ok(())
    }

    /// Update zone statistics.
    pub fn update_zone(
        &mut self,
        zone_type: MemoryZoneType,
        free_pages: u64,
        kernel_pages: u64,
        cached_pages: u64,
    ) -> Result<()> {
        for i in 0..self.zone_count {
            if self.zones[i].zone_type == zone_type {
                self.zones[i].free_pages = free_pages;
                self.zones[i].kernel_pages = kernel_pages;
                self.zones[i].cached_pages = cached_pages;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Update per-CPU time accounting.
    pub fn update_cpu_time(&mut self, cpu_id: usize, times: CpuTimeInfo) -> Result<()> {
        if cpu_id >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.cpu_times[cpu_id] = times;
        Ok(())
    }

    /// Take a snapshot of the current system info.
    ///
    /// Computes uptime from tick counter and fills in the
    /// `SystemInfo` structure.
    pub fn snapshot(&self) -> SystemInfo {
        let mut info = self.info;

        // Compute uptime from ticks.
        if self.ticks_per_sec > 0 {
            info.uptime = self.tick_count / self.ticks_per_sec;
        }

        // Process count.
        if info.procs == 0 {
            info.procs = self.running_procs + self.blocked_procs;
        }

        info
    }

    /// Return aggregate CPU times (sum of all CPUs).
    pub fn aggregate_cpu_times(&self) -> CpuTimeInfo {
        let mut agg = CpuTimeInfo::new();
        for i in 0..self.online_cpus {
            agg.user_ticks += self.cpu_times[i].user_ticks;
            agg.nice_ticks += self.cpu_times[i].nice_ticks;
            agg.system_ticks += self.cpu_times[i].system_ticks;
            agg.idle_ticks += self.cpu_times[i].idle_ticks;
            agg.iowait_ticks += self.cpu_times[i].iowait_ticks;
            agg.irq_ticks += self.cpu_times[i].irq_ticks;
            agg.softirq_ticks += self.cpu_times[i].softirq_ticks;
        }
        agg
    }

    /// Return the number of online CPUs.
    pub const fn online_cpus(&self) -> usize {
        self.online_cpus
    }

    /// Return the number of possible CPUs.
    pub const fn possible_cpus(&self) -> usize {
        self.possible_cpus
    }

    /// Return the boot time in seconds since epoch.
    pub const fn boot_time_secs(&self) -> u64 {
        self.boot_time_secs
    }

    /// Return the total context switches.
    pub const fn context_switches(&self) -> u64 {
        self.context_switches
    }

    /// Return the total interrupts.
    pub const fn total_interrupts(&self) -> u64 {
        self.total_interrupts
    }

    /// Return the total forks.
    pub const fn total_forks(&self) -> u64 {
        self.total_forks
    }

    /// Return the tick count.
    pub const fn tick_count(&self) -> u64 {
        self.tick_count
    }

    /// Return zone info by index.
    pub fn zone_info(&self, index: usize) -> Option<&MemoryZoneInfo> {
        if index < self.zone_count {
            Some(&self.zones[index])
        } else {
            None
        }
    }

    /// Return the number of active memory zones.
    pub const fn zone_count(&self) -> usize {
        self.zone_count
    }

    /// Return CPU time info for a specific CPU.
    pub fn cpu_time(&self, cpu_id: usize) -> Option<&CpuTimeInfo> {
        if cpu_id < self.online_cpus {
            Some(&self.cpu_times[cpu_id])
        } else {
            None
        }
    }

    /// Format /proc/stat-like output into a buffer.
    ///
    /// Returns the number of bytes written.
    pub fn format_proc_stat(&self, buf: &mut [u8]) -> usize {
        let agg = self.aggregate_cpu_times();
        let mut offset = 0;

        // Write "cpu  " prefix.
        let prefix = b"cpu  ";
        if offset + prefix.len() > buf.len() {
            return offset;
        }
        buf[offset..offset + prefix.len()].copy_from_slice(prefix);
        offset += prefix.len();

        // Write aggregate times.
        offset = write_u64(buf, offset, agg.user_ticks);
        offset = write_space(buf, offset);
        offset = write_u64(buf, offset, agg.nice_ticks);
        offset = write_space(buf, offset);
        offset = write_u64(buf, offset, agg.system_ticks);
        offset = write_space(buf, offset);
        offset = write_u64(buf, offset, agg.idle_ticks);
        offset = write_space(buf, offset);
        offset = write_u64(buf, offset, agg.iowait_ticks);
        offset = write_space(buf, offset);
        offset = write_u64(buf, offset, agg.irq_ticks);
        offset = write_space(buf, offset);
        offset = write_u64(buf, offset, agg.softirq_ticks);

        if offset < buf.len() {
            buf[offset] = b'\n';
            offset += 1;
        }
        offset
    }

    /// Format /proc/meminfo-like output into a buffer.
    ///
    /// Returns the number of bytes written.
    pub fn format_proc_meminfo(&self, buf: &mut [u8]) -> usize {
        let info = self.snapshot();
        let mut offset = 0;

        // MemTotal.
        offset = write_label_kb(buf, offset, b"MemTotal:       ", info.totalram / 1024);
        // MemFree.
        offset = write_label_kb(buf, offset, b"MemFree:        ", info.freeram / 1024);
        // Buffers.
        offset = write_label_kb(buf, offset, b"Buffers:        ", info.bufferram / 1024);
        // SwapTotal.
        offset = write_label_kb(buf, offset, b"SwapTotal:      ", info.totalswap / 1024);
        // SwapFree.
        offset = write_label_kb(buf, offset, b"SwapFree:       ", info.freeswap / 1024);
        offset
    }
}

// -------------------------------------------------------------------
// Helper functions
// -------------------------------------------------------------------

/// Extract the string portion up to the first NUL byte.
fn field_to_str(field: &[u8]) -> &[u8] {
    for (i, &b) in field.iter().enumerate() {
        if b == 0 {
            return &field[..i];
        }
    }
    field
}

/// Convert a fixed-point load average to (integer, thousandths).
const fn fixed_to_parts(val: u64) -> (u64, u64) {
    let integer = val >> LOAD_FSHIFT;
    let frac = val & ((1 << LOAD_FSHIFT) - 1);
    // Scale fractional part to thousandths.
    let thousandths = (frac * 1000) >> LOAD_FSHIFT;
    (integer, thousandths)
}

/// Write a u64 decimal to a buffer, return new offset.
fn write_u64(buf: &mut [u8], offset: usize, val: u64) -> usize {
    if val == 0 {
        if offset < buf.len() {
            buf[offset] = b'0';
            return offset + 1;
        }
        return offset;
    }
    let mut tmp = [0u8; 20];
    let mut n = val;
    let mut count = 0;
    while n > 0 {
        tmp[count] = b'0' + (n % 10) as u8;
        n /= 10;
        count += 1;
    }
    if offset + count > buf.len() {
        return offset;
    }
    for i in 0..count {
        buf[offset + i] = tmp[count - 1 - i];
    }
    offset + count
}

/// Write a space character to a buffer.
fn write_space(buf: &mut [u8], offset: usize) -> usize {
    if offset < buf.len() {
        buf[offset] = b' ';
        offset + 1
    } else {
        offset
    }
}

/// Write a label + KB value + " kB\n" to a buffer.
fn write_label_kb(buf: &mut [u8], offset: usize, label: &[u8], kb: u64) -> usize {
    if offset + label.len() > buf.len() {
        return offset;
    }
    let mut off = offset;
    buf[off..off + label.len()].copy_from_slice(label);
    off += label.len();
    off = write_u64(buf, off, kb);
    let suffix = b" kB\n";
    if off + suffix.len() <= buf.len() {
        buf[off..off + suffix.len()].copy_from_slice(suffix);
        off += suffix.len();
    }
    off
}
