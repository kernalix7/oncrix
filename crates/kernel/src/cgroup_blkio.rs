// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Block I/O cgroup controller (blkio / io).
//!
//! Implements the cgroups v2 `io` controller for regulating block
//! device I/O bandwidth and IOPS per cgroup:
//!
//! - **Device rules** ([`BlkioDeviceRule`]): per-device bandwidth
//!   and IOPS limits with read/write granularity.
//! - **I/O accounting** ([`BlkioStats`]): tracks bytes and
//!   operations per device with read/write/discard breakdown.
//! - **Weight-based scheduling** ([`BlkioWeight`]): proportional
//!   I/O scheduling weight (1-10000, default 100).
//! - **Throttling** ([`BlkioThrottle`]): absolute BPS/IOPS caps
//!   with token-bucket enforcement.
//! - **Latency target** ([`BlkioLatency`]): I/O latency QoS
//!   target per device for latency-sensitive workloads.
//! - **Controller** ([`BlkioCgroupController`]): per-cgroup
//!   controller with device rules and cumulative statistics.
//! - **Registry** ([`BlkioCgroupRegistry`]): system-wide
//!   registry of up to 64 blkio cgroup controllers.
//!
//! Reference: Linux `block/blk-cgroup.c`, `block/blk-throttle.c`,
//! `block/blk-iolatency.c`.

use oncrix_lib::{Error, Result};

// ── Constants ──────────────────────────────────────────────────────

/// Maximum number of blkio cgroup controllers.
const MAX_BLKIO_CGROUPS: usize = 64;

/// Maximum device rules per controller.
const MAX_DEVICE_RULES: usize = 16;

/// Maximum PIDs per controller.
const MAX_PIDS: usize = 32;

/// Maximum name length.
const MAX_NAME_LEN: usize = 64;

/// Default I/O weight (cgroups v2 range: 1-10000).
const DEFAULT_WEIGHT: u32 = 100;

/// Minimum I/O weight.
const MIN_WEIGHT: u32 = 1;

/// Maximum I/O weight.
const MAX_WEIGHT: u32 = 10_000;

/// Unlimited BPS / IOPS sentinel.
const LIMIT_UNLIMITED: u64 = u64::MAX;

/// Token bucket refill interval (microseconds, 10ms).
const TOKEN_REFILL_INTERVAL_US: u64 = 10_000;

/// Maximum token accumulation factor.
const MAX_TOKEN_BURST_FACTOR: u64 = 4;

/// Default latency target (microseconds, 0 = no target).
const DEFAULT_LATENCY_TARGET_US: u64 = 0;

/// Maximum tracked I/O latency percentiles.
const MAX_LATENCY_BUCKETS: usize = 16;

/// Latency bucket boundaries in microseconds.
const LATENCY_BUCKET_BOUNDS_US: [u64; MAX_LATENCY_BUCKETS] = [
    10,
    50,
    100,
    250,
    500,
    1_000,
    2_500,
    5_000,
    10_000,
    25_000,
    50_000,
    100_000,
    250_000,
    500_000,
    1_000_000,
    u64::MAX,
];

// ── IoDirection ────────────────────────────────────────────────────

/// Direction of an I/O operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoDirection {
    /// Read operation.
    Read,
    /// Write operation.
    Write,
    /// Discard / trim operation.
    Discard,
}

// ── DeviceId ───────────────────────────────────────────────────────

/// Block device identifier (major:minor pair).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceId {
    /// Major device number.
    pub major: u32,
    /// Minor device number.
    pub minor: u32,
}

impl DeviceId {
    /// Create a new device ID.
    pub const fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }

    /// Encode as a single u64 (major << 32 | minor).
    pub const fn encode(&self) -> u64 {
        ((self.major as u64) << 32) | (self.minor as u64)
    }
}

impl Default for DeviceId {
    fn default() -> Self {
        Self::new(0, 0)
    }
}

// ── BlkioWeight ────────────────────────────────────────────────────

/// Proportional I/O scheduling weight.
#[derive(Debug, Clone, Copy)]
pub struct BlkioWeight {
    /// Default weight for all devices.
    pub default_weight: u32,
    /// Per-device weight overrides.
    device_weights: [(DeviceId, u32); MAX_DEVICE_RULES],
    /// Number of per-device overrides.
    override_count: usize,
}

impl BlkioWeight {
    /// Create weight config with default value.
    pub const fn new() -> Self {
        Self {
            default_weight: DEFAULT_WEIGHT,
            device_weights: [(DeviceId::new(0, 0), 0); MAX_DEVICE_RULES],
            override_count: 0,
        }
    }

    /// Set the default weight.
    pub fn set_default(&mut self, weight: u32) -> Result<()> {
        if weight < MIN_WEIGHT || weight > MAX_WEIGHT {
            return Err(Error::InvalidArgument);
        }
        self.default_weight = weight;
        Ok(())
    }

    /// Set a per-device weight override.
    pub fn set_device_weight(&mut self, dev: DeviceId, weight: u32) -> Result<()> {
        if weight < MIN_WEIGHT || weight > MAX_WEIGHT {
            return Err(Error::InvalidArgument);
        }
        // Update existing override
        for (d, w) in &mut self.device_weights[..self.override_count] {
            if *d == dev {
                *w = weight;
                return Ok(());
            }
        }
        // Add new override
        if self.override_count >= MAX_DEVICE_RULES {
            return Err(Error::OutOfMemory);
        }
        self.device_weights[self.override_count] = (dev, weight);
        self.override_count += 1;
        Ok(())
    }

    /// Get the effective weight for a device.
    pub fn effective_weight(&self, dev: DeviceId) -> u32 {
        for &(d, w) in &self.device_weights[..self.override_count] {
            if d == dev {
                return w;
            }
        }
        self.default_weight
    }
}

impl Default for BlkioWeight {
    fn default() -> Self {
        Self::new()
    }
}

// ── ThrottleLimit ──────────────────────────────────────────────────

/// BPS and IOPS limits for a single direction.
#[derive(Debug, Clone, Copy)]
pub struct ThrottleLimit {
    /// Maximum bytes per second (u64::MAX = unlimited).
    pub bps: u64,
    /// Maximum I/O operations per second (u64::MAX = unlimited).
    pub iops: u64,
}

impl ThrottleLimit {
    /// Create an unlimited limit.
    pub const fn unlimited() -> Self {
        Self {
            bps: LIMIT_UNLIMITED,
            iops: LIMIT_UNLIMITED,
        }
    }

    /// Whether this limit is effectively unlimited.
    pub fn is_unlimited(&self) -> bool {
        self.bps == LIMIT_UNLIMITED && self.iops == LIMIT_UNLIMITED
    }
}

impl Default for ThrottleLimit {
    fn default() -> Self {
        Self::unlimited()
    }
}

// ── BlkioDeviceRule ────────────────────────────────────────────────

/// Per-device I/O throttle and latency rules.
#[derive(Debug, Clone, Copy)]
pub struct BlkioDeviceRule {
    /// Device identifier.
    pub device: DeviceId,
    /// Read throttle limits.
    pub read_limit: ThrottleLimit,
    /// Write throttle limits.
    pub write_limit: ThrottleLimit,
    /// Discard throttle limits.
    pub discard_limit: ThrottleLimit,
    /// Latency target in microseconds (0 = no target).
    pub latency_target_us: u64,
    /// Whether this rule is active.
    pub active: bool,
}

impl BlkioDeviceRule {
    /// Create an empty device rule.
    pub const fn new() -> Self {
        Self {
            device: DeviceId::new(0, 0),
            read_limit: ThrottleLimit::unlimited(),
            write_limit: ThrottleLimit::unlimited(),
            discard_limit: ThrottleLimit::unlimited(),
            latency_target_us: DEFAULT_LATENCY_TARGET_US,
            active: false,
        }
    }

    /// Initialize a device rule.
    pub fn init(&mut self, device: DeviceId) {
        self.device = device;
        self.read_limit = ThrottleLimit::unlimited();
        self.write_limit = ThrottleLimit::unlimited();
        self.discard_limit = ThrottleLimit::unlimited();
        self.latency_target_us = DEFAULT_LATENCY_TARGET_US;
        self.active = true;
    }

    /// Set read BPS limit.
    pub fn set_read_bps(&mut self, bps: u64) {
        self.read_limit.bps = bps;
    }

    /// Set write BPS limit.
    pub fn set_write_bps(&mut self, bps: u64) {
        self.write_limit.bps = bps;
    }

    /// Set read IOPS limit.
    pub fn set_read_iops(&mut self, iops: u64) {
        self.read_limit.iops = iops;
    }

    /// Set write IOPS limit.
    pub fn set_write_iops(&mut self, iops: u64) {
        self.write_limit.iops = iops;
    }

    /// Get the limit for a given direction.
    pub fn limit_for(&self, dir: IoDirection) -> &ThrottleLimit {
        match dir {
            IoDirection::Read => &self.read_limit,
            IoDirection::Write => &self.write_limit,
            IoDirection::Discard => &self.discard_limit,
        }
    }

    /// Whether any limit is active (not unlimited).
    pub fn has_limits(&self) -> bool {
        !self.read_limit.is_unlimited()
            || !self.write_limit.is_unlimited()
            || !self.discard_limit.is_unlimited()
    }
}

impl Default for BlkioDeviceRule {
    fn default() -> Self {
        Self::new()
    }
}

// ── BlkioThrottle ──────────────────────────────────────────────────

/// Token-bucket throttle state for a single device+direction.
#[derive(Debug, Clone, Copy)]
pub struct BlkioThrottle {
    /// Available byte tokens.
    pub byte_tokens: u64,
    /// Available I/O operation tokens.
    pub io_tokens: u64,
    /// Maximum byte tokens (burst capacity).
    pub max_byte_tokens: u64,
    /// Maximum I/O tokens (burst capacity).
    pub max_io_tokens: u64,
    /// Timestamp of last refill (microseconds since boot).
    pub last_refill_us: u64,
    /// Total bytes throttled (delayed).
    pub bytes_throttled: u64,
    /// Total ops throttled.
    pub ops_throttled: u64,
    /// Whether throttling is currently active.
    pub is_throttled: bool,
}

impl BlkioThrottle {
    /// Create a new throttle state for the given limits.
    pub fn new_for_limits(limit: &ThrottleLimit) -> Self {
        let bps_per_interval = if limit.bps == LIMIT_UNLIMITED {
            LIMIT_UNLIMITED
        } else {
            (limit.bps * TOKEN_REFILL_INTERVAL_US) / 1_000_000
        };
        let iops_per_interval = if limit.iops == LIMIT_UNLIMITED {
            LIMIT_UNLIMITED
        } else {
            (limit.iops * TOKEN_REFILL_INTERVAL_US) / 1_000_000
        };
        let max_bytes = if bps_per_interval == LIMIT_UNLIMITED {
            LIMIT_UNLIMITED
        } else {
            bps_per_interval.saturating_mul(MAX_TOKEN_BURST_FACTOR)
        };
        let max_ops = if iops_per_interval == LIMIT_UNLIMITED {
            LIMIT_UNLIMITED
        } else {
            iops_per_interval.saturating_mul(MAX_TOKEN_BURST_FACTOR)
        };
        Self {
            byte_tokens: bps_per_interval,
            io_tokens: iops_per_interval,
            max_byte_tokens: max_bytes,
            max_io_tokens: max_ops,
            last_refill_us: 0,
            bytes_throttled: 0,
            ops_throttled: 0,
            is_throttled: false,
        }
    }

    /// Refill tokens based on elapsed time.
    pub fn refill(&mut self, now_us: u64, limit: &ThrottleLimit) {
        let elapsed = now_us.saturating_sub(self.last_refill_us);
        if elapsed < TOKEN_REFILL_INTERVAL_US {
            return;
        }
        let intervals = elapsed / TOKEN_REFILL_INTERVAL_US;
        self.last_refill_us = now_us;

        if limit.bps != LIMIT_UNLIMITED {
            let refill_bytes =
                (limit.bps * TOKEN_REFILL_INTERVAL_US / 1_000_000).saturating_mul(intervals);
            self.byte_tokens = self
                .byte_tokens
                .saturating_add(refill_bytes)
                .min(self.max_byte_tokens);
        }

        if limit.iops != LIMIT_UNLIMITED {
            let refill_ops =
                (limit.iops * TOKEN_REFILL_INTERVAL_US / 1_000_000).saturating_mul(intervals);
            self.io_tokens = self
                .io_tokens
                .saturating_add(refill_ops)
                .min(self.max_io_tokens);
        }

        if self.byte_tokens > 0 && self.io_tokens > 0 {
            self.is_throttled = false;
        }
    }

    /// Try to consume tokens for an I/O operation.
    ///
    /// Returns `true` if the operation is allowed, `false` if
    /// it should be throttled.
    pub fn try_consume(&mut self, bytes: u64, limit: &ThrottleLimit) -> bool {
        let bytes_ok = limit.bps == LIMIT_UNLIMITED || self.byte_tokens >= bytes;
        let iops_ok = limit.iops == LIMIT_UNLIMITED || self.io_tokens >= 1;

        if bytes_ok && iops_ok {
            if limit.bps != LIMIT_UNLIMITED {
                self.byte_tokens = self.byte_tokens.saturating_sub(bytes);
            }
            if limit.iops != LIMIT_UNLIMITED {
                self.io_tokens = self.io_tokens.saturating_sub(1);
            }
            true
        } else {
            self.is_throttled = true;
            self.bytes_throttled = self.bytes_throttled.saturating_add(bytes);
            self.ops_throttled += 1;
            false
        }
    }
}

impl Default for BlkioThrottle {
    fn default() -> Self {
        Self::new_for_limits(&ThrottleLimit::unlimited())
    }
}

// ── BlkioLatency ───────────────────────────────────────────────────

/// I/O latency tracking and QoS enforcement.
#[derive(Debug, Clone, Copy)]
pub struct BlkioLatency {
    /// Target latency in microseconds (0 = no target).
    pub target_us: u64,
    /// Histogram of I/O latencies (bucket counts).
    pub buckets: [u64; MAX_LATENCY_BUCKETS],
    /// Total I/O operations tracked.
    pub total_ops: u64,
    /// Sum of all latencies (for average calculation).
    pub total_latency_us: u64,
    /// Maximum observed latency.
    pub max_latency_us: u64,
    /// Number of operations exceeding target.
    pub exceeding_count: u64,
}

impl BlkioLatency {
    /// Create a new latency tracker.
    pub const fn new() -> Self {
        Self {
            target_us: DEFAULT_LATENCY_TARGET_US,
            buckets: [0u64; MAX_LATENCY_BUCKETS],
            total_ops: 0,
            total_latency_us: 0,
            max_latency_us: 0,
            exceeding_count: 0,
        }
    }

    /// Record an I/O latency observation.
    pub fn record(&mut self, latency_us: u64) {
        self.total_ops += 1;
        self.total_latency_us = self.total_latency_us.saturating_add(latency_us);
        if latency_us > self.max_latency_us {
            self.max_latency_us = latency_us;
        }
        if self.target_us > 0 && latency_us > self.target_us {
            self.exceeding_count += 1;
        }
        // Update histogram
        for (i, &bound) in LATENCY_BUCKET_BOUNDS_US.iter().enumerate() {
            if latency_us <= bound {
                self.buckets[i] += 1;
                break;
            }
        }
    }

    /// Return average latency in microseconds.
    pub fn avg_latency_us(&self) -> u64 {
        if self.total_ops > 0 {
            self.total_latency_us / self.total_ops
        } else {
            0
        }
    }

    /// Return the percentage of ops exceeding target.
    pub fn exceeding_pct(&self) -> u64 {
        if self.total_ops > 0 {
            (self.exceeding_count * 100) / self.total_ops
        } else {
            0
        }
    }

    /// Reset statistics.
    pub fn reset(&mut self) {
        self.buckets = [0u64; MAX_LATENCY_BUCKETS];
        self.total_ops = 0;
        self.total_latency_us = 0;
        self.max_latency_us = 0;
        self.exceeding_count = 0;
    }
}

impl Default for BlkioLatency {
    fn default() -> Self {
        Self::new()
    }
}

// ── BlkioStats ─────────────────────────────────────────────────────

/// Cumulative I/O statistics per device.
#[derive(Debug, Clone, Copy)]
pub struct BlkioStats {
    /// Device identifier.
    pub device: DeviceId,
    /// Bytes read.
    pub bytes_read: u64,
    /// Bytes written.
    pub bytes_written: u64,
    /// Bytes discarded.
    pub bytes_discarded: u64,
    /// Read operations.
    pub ops_read: u64,
    /// Write operations.
    pub ops_write: u64,
    /// Discard operations.
    pub ops_discard: u64,
    /// Time spent in I/O queue (microseconds).
    pub queue_time_us: u64,
    /// Time spent servicing I/O (microseconds).
    pub service_time_us: u64,
    /// Whether this entry is in use.
    pub active: bool,
}

impl BlkioStats {
    /// Create empty statistics.
    pub const fn new() -> Self {
        Self {
            device: DeviceId::new(0, 0),
            bytes_read: 0,
            bytes_written: 0,
            bytes_discarded: 0,
            ops_read: 0,
            ops_write: 0,
            ops_discard: 0,
            queue_time_us: 0,
            service_time_us: 0,
            active: false,
        }
    }

    /// Record an I/O operation.
    pub fn record(&mut self, dir: IoDirection, bytes: u64, queue_us: u64, service_us: u64) {
        match dir {
            IoDirection::Read => {
                self.bytes_read = self.bytes_read.saturating_add(bytes);
                self.ops_read += 1;
            }
            IoDirection::Write => {
                self.bytes_written = self.bytes_written.saturating_add(bytes);
                self.ops_write += 1;
            }
            IoDirection::Discard => {
                self.bytes_discarded = self.bytes_discarded.saturating_add(bytes);
                self.ops_discard += 1;
            }
        }
        self.queue_time_us = self.queue_time_us.saturating_add(queue_us);
        self.service_time_us = self.service_time_us.saturating_add(service_us);
    }

    /// Total bytes across all directions.
    pub fn total_bytes(&self) -> u64 {
        self.bytes_read
            .saturating_add(self.bytes_written)
            .saturating_add(self.bytes_discarded)
    }

    /// Total operations across all directions.
    pub fn total_ops(&self) -> u64 {
        self.ops_read + self.ops_write + self.ops_discard
    }
}

impl Default for BlkioStats {
    fn default() -> Self {
        Self::new()
    }
}

// ── BlkioCgroupController ──────────────────────────────────────────

/// A single blkio cgroup controller instance.
///
/// Manages per-device I/O rules, throttling, latency tracking,
/// and statistics for a cgroup.
pub struct BlkioCgroupController {
    /// Controller ID.
    pub id: u32,
    /// Controller name.
    name: [u8; MAX_NAME_LEN],
    /// Name length.
    name_len: usize,
    /// I/O weight configuration.
    pub weight: BlkioWeight,
    /// Per-device rules.
    pub rules: [BlkioDeviceRule; MAX_DEVICE_RULES],
    /// Number of active rules.
    rule_count: usize,
    /// Per-device statistics.
    pub stats: [BlkioStats; MAX_DEVICE_RULES],
    /// Per-device latency trackers.
    pub latency: [BlkioLatency; MAX_DEVICE_RULES],
    /// Read throttle state per device.
    read_throttles: [BlkioThrottle; MAX_DEVICE_RULES],
    /// Write throttle state per device.
    write_throttles: [BlkioThrottle; MAX_DEVICE_RULES],
    /// Attached PIDs.
    pids: [u64; MAX_PIDS],
    /// Number of attached PIDs.
    pid_count: usize,
    /// Whether this controller is active.
    active: bool,
    /// Generation counter.
    generation: u64,
}

impl BlkioCgroupController {
    /// Create a new empty controller.
    pub const fn new() -> Self {
        Self {
            id: 0,
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            weight: BlkioWeight::new(),
            rules: [const { BlkioDeviceRule::new() }; MAX_DEVICE_RULES],
            rule_count: 0,
            stats: [const { BlkioStats::new() }; MAX_DEVICE_RULES],
            latency: [const { BlkioLatency::new() }; MAX_DEVICE_RULES],
            read_throttles: [const {
                BlkioThrottle {
                    byte_tokens: LIMIT_UNLIMITED,
                    io_tokens: LIMIT_UNLIMITED,
                    max_byte_tokens: LIMIT_UNLIMITED,
                    max_io_tokens: LIMIT_UNLIMITED,
                    last_refill_us: 0,
                    bytes_throttled: 0,
                    ops_throttled: 0,
                    is_throttled: false,
                }
            }; MAX_DEVICE_RULES],
            write_throttles: [const {
                BlkioThrottle {
                    byte_tokens: LIMIT_UNLIMITED,
                    io_tokens: LIMIT_UNLIMITED,
                    max_byte_tokens: LIMIT_UNLIMITED,
                    max_io_tokens: LIMIT_UNLIMITED,
                    last_refill_us: 0,
                    bytes_throttled: 0,
                    ops_throttled: 0,
                    is_throttled: false,
                }
            }; MAX_DEVICE_RULES],
            pids: [0u64; MAX_PIDS],
            pid_count: 0,
            active: false,
            generation: 0,
        }
    }

    /// Initialize a controller.
    pub fn init(&mut self, id: u32, name: &[u8]) -> Result<()> {
        if name.len() > MAX_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        self.id = id;
        self.name[..name.len()].copy_from_slice(name);
        self.name_len = name.len();
        self.weight = BlkioWeight::new();
        self.rule_count = 0;
        self.pid_count = 0;
        self.active = true;
        self.generation = self.generation.wrapping_add(1);
        Ok(())
    }

    /// Return the controller name.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }

    /// Add a device rule.
    pub fn add_device_rule(&mut self, device: DeviceId) -> Result<usize> {
        if self.rule_count >= MAX_DEVICE_RULES {
            return Err(Error::OutOfMemory);
        }
        // Check for existing rule
        for (i, rule) in self.rules[..self.rule_count].iter().enumerate() {
            if rule.active && rule.device == device {
                return Ok(i);
            }
        }
        let idx = self.rule_count;
        self.rules[idx].init(device);
        self.stats[idx].device = device;
        self.stats[idx].active = true;
        self.rule_count += 1;
        Ok(idx)
    }

    /// Set a read BPS limit for a device.
    pub fn set_read_bps(&mut self, device: DeviceId, bps: u64) -> Result<()> {
        let idx = self.find_or_add_rule(device)?;
        self.rules[idx].set_read_bps(bps);
        self.read_throttles[idx] = BlkioThrottle::new_for_limits(&self.rules[idx].read_limit);
        Ok(())
    }

    /// Set a write BPS limit for a device.
    pub fn set_write_bps(&mut self, device: DeviceId, bps: u64) -> Result<()> {
        let idx = self.find_or_add_rule(device)?;
        self.rules[idx].set_write_bps(bps);
        self.write_throttles[idx] = BlkioThrottle::new_for_limits(&self.rules[idx].write_limit);
        Ok(())
    }

    /// Set a read IOPS limit for a device.
    pub fn set_read_iops(&mut self, device: DeviceId, iops: u64) -> Result<()> {
        let idx = self.find_or_add_rule(device)?;
        self.rules[idx].set_read_iops(iops);
        self.read_throttles[idx] = BlkioThrottle::new_for_limits(&self.rules[idx].read_limit);
        Ok(())
    }

    /// Set a write IOPS limit for a device.
    pub fn set_write_iops(&mut self, device: DeviceId, iops: u64) -> Result<()> {
        let idx = self.find_or_add_rule(device)?;
        self.rules[idx].set_write_iops(iops);
        self.write_throttles[idx] = BlkioThrottle::new_for_limits(&self.rules[idx].write_limit);
        Ok(())
    }

    /// Set a latency target for a device.
    pub fn set_latency_target(&mut self, device: DeviceId, target_us: u64) -> Result<()> {
        let idx = self.find_or_add_rule(device)?;
        self.rules[idx].latency_target_us = target_us;
        self.latency[idx].target_us = target_us;
        Ok(())
    }

    /// Submit an I/O operation for throttle checking.
    ///
    /// Returns `true` if the operation is allowed, `false` if
    /// it should be delayed.
    pub fn submit_io(
        &mut self,
        device: DeviceId,
        dir: IoDirection,
        bytes: u64,
        now_us: u64,
    ) -> Result<bool> {
        let idx = self.find_rule_index(device)?;
        let limit = self.rules[idx].limit_for(dir);

        if limit.is_unlimited() {
            return Ok(true);
        }

        let throttle = match dir {
            IoDirection::Read | IoDirection::Discard => &mut self.read_throttles[idx],
            IoDirection::Write => &mut self.write_throttles[idx],
        };

        throttle.refill(now_us, limit);
        Ok(throttle.try_consume(bytes, limit))
    }

    /// Record a completed I/O operation.
    pub fn complete_io(
        &mut self,
        device: DeviceId,
        dir: IoDirection,
        bytes: u64,
        queue_us: u64,
        service_us: u64,
    ) -> Result<()> {
        let idx = self.find_rule_index(device)?;
        self.stats[idx].record(dir, bytes, queue_us, service_us);
        self.latency[idx].record(queue_us.saturating_add(service_us));
        Ok(())
    }

    /// Attach a PID to this controller.
    pub fn attach_pid(&mut self, pid: u64) -> Result<()> {
        if self.pids[..self.pid_count].contains(&pid) {
            return Err(Error::AlreadyExists);
        }
        if self.pid_count >= MAX_PIDS {
            return Err(Error::OutOfMemory);
        }
        self.pids[self.pid_count] = pid;
        self.pid_count += 1;
        Ok(())
    }

    /// Detach a PID from this controller.
    pub fn detach_pid(&mut self, pid: u64) -> Result<()> {
        let pos = self.pids[..self.pid_count]
            .iter()
            .position(|&p| p == pid)
            .ok_or(Error::NotFound)?;
        self.pids[pos] = self.pids[self.pid_count - 1];
        self.pid_count -= 1;
        Ok(())
    }

    /// Whether this controller is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Deactivate this controller.
    pub fn deactivate(&mut self) {
        self.active = false;
    }

    /// Return the generation counter.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Return the number of device rules.
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Return the number of attached PIDs.
    pub fn pid_count(&self) -> usize {
        self.pid_count
    }

    /// Perform periodic token refill for all throttles.
    pub fn tick(&mut self, now_us: u64) {
        for idx in 0..self.rule_count {
            let read_limit = self.rules[idx].read_limit;
            let write_limit = self.rules[idx].write_limit;
            self.read_throttles[idx].refill(now_us, &read_limit);
            self.write_throttles[idx].refill(now_us, &write_limit);
        }
    }

    /// Find or create a rule for a device.
    fn find_or_add_rule(&mut self, device: DeviceId) -> Result<usize> {
        for (i, rule) in self.rules[..self.rule_count].iter().enumerate() {
            if rule.active && rule.device == device {
                return Ok(i);
            }
        }
        self.add_device_rule(device)
    }

    /// Find the rule index for a device.
    fn find_rule_index(&self, device: DeviceId) -> Result<usize> {
        self.rules[..self.rule_count]
            .iter()
            .position(|r| r.active && r.device == device)
            .ok_or(Error::NotFound)
    }
}

impl Default for BlkioCgroupController {
    fn default() -> Self {
        Self::new()
    }
}

// ── BlkioCgroupRegistry ────────────────────────────────────────────

/// System-wide registry of blkio cgroup controllers.
pub struct BlkioCgroupRegistry {
    /// All controller slots.
    controllers: [BlkioCgroupController; MAX_BLKIO_CGROUPS],
    /// Next controller ID.
    next_id: u32,
    /// Number of active controllers.
    active_count: usize,
    /// Whether the registry is initialized.
    initialized: bool,
}

impl BlkioCgroupRegistry {
    /// Create a new uninitialized registry.
    pub const fn new() -> Self {
        Self {
            controllers: [const { BlkioCgroupController::new() }; MAX_BLKIO_CGROUPS],
            next_id: 1,
            active_count: 0,
            initialized: false,
        }
    }

    /// Initialize the registry.
    pub fn init(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }
        self.initialized = true;
        Ok(())
    }

    /// Create a new blkio cgroup controller.
    pub fn create(&mut self, name: &[u8]) -> Result<u32> {
        if !self.initialized {
            return Err(Error::NotImplemented);
        }
        if self.active_count >= MAX_BLKIO_CGROUPS {
            return Err(Error::OutOfMemory);
        }
        let slot = self
            .controllers
            .iter()
            .position(|c| !c.is_active())
            .ok_or(Error::OutOfMemory)?;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.controllers[slot].init(id, name)?;
        self.active_count += 1;
        Ok(id)
    }

    /// Destroy a blkio cgroup controller.
    pub fn destroy(&mut self, id: u32) -> Result<()> {
        let ctrl = self
            .controllers
            .iter_mut()
            .find(|c| c.is_active() && c.id == id)
            .ok_or(Error::NotFound)?;
        ctrl.deactivate();
        self.active_count = self.active_count.saturating_sub(1);
        Ok(())
    }

    /// Look up a controller by ID.
    pub fn get(&self, id: u32) -> Result<&BlkioCgroupController> {
        self.controllers
            .iter()
            .find(|c| c.is_active() && c.id == id)
            .ok_or(Error::NotFound)
    }

    /// Look up a mutable controller by ID.
    pub fn get_mut(&mut self, id: u32) -> Result<&mut BlkioCgroupController> {
        self.controllers
            .iter_mut()
            .find(|c| c.is_active() && c.id == id)
            .ok_or(Error::NotFound)
    }

    /// Perform periodic maintenance on all controllers.
    pub fn tick(&mut self, now_us: u64) {
        for ctrl in &mut self.controllers {
            if ctrl.is_active() {
                ctrl.tick(now_us);
            }
        }
    }

    /// Return the number of active controllers.
    pub fn active_count(&self) -> usize {
        self.active_count
    }
}

impl Default for BlkioCgroupRegistry {
    fn default() -> Self {
        Self::new()
    }
}
