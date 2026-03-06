// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Perf callchain collection.
//!
//! Collects stack traces (callchains) for the perf event subsystem.
//! Supports both kernel-space and user-space callchain unwinding,
//! with configurable depth limits and context markers to separate
//! kernel and user frames.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────────

/// Maximum callchain depth (frames per chain).
const MAX_CALLCHAIN_DEPTH: usize = 128;

/// Maximum number of cached callchains.
const MAX_CACHED_CHAINS: usize = 256;

/// Context markers inserted between kernel and user frames.
const PERF_CONTEXT_KERNEL: u64 = 0xFFFF_FFFF_FFFF_FF80;
const PERF_CONTEXT_USER: u64 = 0xFFFF_FFFF_FFFF_FF60;
const PERF_CONTEXT_GUEST: u64 = 0xFFFF_FFFF_FFFF_FF40;

/// Callchain collection flags.
const CALLCHAIN_KERNEL: u32 = 1 << 0;
const CALLCHAIN_USER: u32 = 1 << 1;
const _CALLCHAIN_GUEST: u32 = 1 << 2;

// ── Types ────────────────────────────────────────────────────────────

/// Represents a single collected callchain.
#[derive(Debug, Clone)]
pub struct PerfCallchain {
    /// Instruction pointer frames.
    frames: [u64; MAX_CALLCHAIN_DEPTH],
    /// Number of valid frames.
    frame_count: usize,
    /// Collection flags indicating which contexts were sampled.
    flags: u32,
    /// CPU on which the callchain was collected.
    cpu: u32,
    /// PID of the task.
    pid: u64,
    /// Timestamp in nanoseconds.
    timestamp_ns: u64,
}

impl PerfCallchain {
    /// Creates an empty callchain.
    pub const fn new() -> Self {
        Self {
            frames: [0u64; MAX_CALLCHAIN_DEPTH],
            frame_count: 0,
            flags: 0,
            cpu: 0,
            pid: 0,
            timestamp_ns: 0,
        }
    }

    /// Returns the number of frames in this callchain.
    pub const fn frame_count(&self) -> usize {
        self.frame_count
    }

    /// Returns a frame at the given index.
    pub fn frame(&self, index: usize) -> Result<u64> {
        if index >= self.frame_count {
            return Err(Error::InvalidArgument);
        }
        Ok(self.frames[index])
    }

    /// Returns whether this callchain includes kernel frames.
    pub const fn has_kernel_frames(&self) -> bool {
        self.flags & CALLCHAIN_KERNEL != 0
    }

    /// Returns whether this callchain includes user frames.
    pub const fn has_user_frames(&self) -> bool {
        self.flags & CALLCHAIN_USER != 0
    }
}

impl Default for PerfCallchain {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for callchain collection.
#[derive(Debug, Clone)]
pub struct CallchainConfig {
    /// Maximum depth to unwind.
    pub max_depth: usize,
    /// Whether to collect kernel frames.
    pub collect_kernel: bool,
    /// Whether to collect user-space frames.
    pub collect_user: bool,
    /// Whether to insert context markers.
    pub insert_context_markers: bool,
    /// Whether to skip the leaf frame.
    pub skip_leaf: bool,
}

impl Default for CallchainConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl CallchainConfig {
    /// Creates a default callchain configuration.
    pub const fn new() -> Self {
        Self {
            max_depth: 64,
            collect_kernel: true,
            collect_user: true,
            insert_context_markers: true,
            skip_leaf: false,
        }
    }
}

/// Per-CPU callchain buffer for non-blocking collection.
#[derive(Debug)]
pub struct CallchainBuffer {
    /// CPU this buffer belongs to.
    cpu_id: u32,
    /// Pre-allocated callchain storage.
    chain: PerfCallchain,
    /// Whether the buffer is in use.
    in_use: bool,
    /// Nesting depth (for NMI re-entrance).
    nesting: u32,
}

impl CallchainBuffer {
    /// Creates a new per-CPU callchain buffer.
    pub const fn new(cpu_id: u32) -> Self {
        Self {
            cpu_id,
            chain: PerfCallchain::new(),
            in_use: false,
            nesting: 0,
        }
    }

    /// Returns the CPU identifier.
    pub const fn cpu_id(&self) -> u32 {
        self.cpu_id
    }

    /// Returns whether the buffer is currently in use.
    pub const fn is_in_use(&self) -> bool {
        self.in_use
    }
}

/// Statistics for callchain collection.
#[derive(Debug, Clone)]
pub struct CallchainStats {
    /// Total callchains collected.
    pub total_collected: u64,
    /// Total frames across all collections.
    pub total_frames: u64,
    /// Collections that hit the depth limit.
    pub depth_truncated: u64,
    /// Collections that failed.
    pub collection_failures: u64,
    /// Average frames per collection.
    pub avg_depth: u32,
}

impl Default for CallchainStats {
    fn default() -> Self {
        Self::new()
    }
}

impl CallchainStats {
    /// Creates zeroed statistics.
    pub const fn new() -> Self {
        Self {
            total_collected: 0,
            total_frames: 0,
            depth_truncated: 0,
            collection_failures: 0,
            avg_depth: 0,
        }
    }
}

/// Central callchain collector.
#[derive(Debug)]
pub struct CallchainCollector {
    /// Configuration.
    config: CallchainConfig,
    /// Cached callchains ring buffer.
    cache: [Option<PerfCallchain>; MAX_CACHED_CHAINS],
    /// Write position in cache ring.
    cache_write_pos: usize,
    /// Total collected.
    total_collected: u64,
    /// Total frames.
    total_frames: u64,
    /// Truncated collections.
    depth_truncated: u64,
    /// Failed collections.
    failures: u64,
}

impl Default for CallchainCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl CallchainCollector {
    /// Creates a new callchain collector.
    pub const fn new() -> Self {
        Self {
            config: CallchainConfig::new(),
            cache: [const { None }; MAX_CACHED_CHAINS],
            cache_write_pos: 0,
            total_collected: 0,
            total_frames: 0,
            depth_truncated: 0,
            failures: 0,
        }
    }

    /// Updates the callchain collection configuration.
    pub fn set_config(&mut self, config: CallchainConfig) {
        self.config = config;
    }

    /// Collects a callchain from the given frame pointer chain.
    pub fn collect(
        &mut self,
        kernel_frames: &[u64],
        user_frames: &[u64],
        cpu: u32,
        pid: u64,
        timestamp_ns: u64,
    ) -> Result<usize> {
        let mut chain = PerfCallchain::new();
        chain.cpu = cpu;
        chain.pid = pid;
        chain.timestamp_ns = timestamp_ns;
        let max = self.config.max_depth.min(MAX_CALLCHAIN_DEPTH);
        let mut pos = 0usize;
        // Kernel frames.
        if self.config.collect_kernel && !kernel_frames.is_empty() {
            if self.config.insert_context_markers && pos < max {
                chain.frames[pos] = PERF_CONTEXT_KERNEL;
                pos += 1;
            }
            for &frame in kernel_frames {
                if pos >= max {
                    self.depth_truncated += 1;
                    break;
                }
                chain.frames[pos] = frame;
                pos += 1;
            }
            chain.flags |= CALLCHAIN_KERNEL;
        }
        // User frames.
        if self.config.collect_user && !user_frames.is_empty() {
            if self.config.insert_context_markers && pos < max {
                chain.frames[pos] = PERF_CONTEXT_USER;
                pos += 1;
            }
            for &frame in user_frames {
                if pos >= max {
                    self.depth_truncated += 1;
                    break;
                }
                chain.frames[pos] = frame;
                pos += 1;
            }
            chain.flags |= CALLCHAIN_USER;
        }
        chain.frame_count = pos;
        self.total_collected += 1;
        self.total_frames += pos as u64;
        // Store in cache ring.
        self.cache[self.cache_write_pos] = Some(chain);
        self.cache_write_pos = (self.cache_write_pos + 1) % MAX_CACHED_CHAINS;
        Ok(pos)
    }

    /// Returns the most recently collected callchain.
    pub fn last_callchain(&self) -> Option<&PerfCallchain> {
        let idx = if self.cache_write_pos == 0 {
            MAX_CACHED_CHAINS - 1
        } else {
            self.cache_write_pos - 1
        };
        self.cache[idx].as_ref()
    }

    /// Clears the callchain cache.
    pub fn clear_cache(&mut self) {
        for slot in self.cache.iter_mut() {
            *slot = None;
        }
        self.cache_write_pos = 0;
    }

    /// Returns collection statistics.
    pub fn stats(&self) -> CallchainStats {
        let avg = if self.total_collected > 0 {
            (self.total_frames / self.total_collected) as u32
        } else {
            0
        };
        CallchainStats {
            total_collected: self.total_collected,
            total_frames: self.total_frames,
            depth_truncated: self.depth_truncated,
            collection_failures: self.failures,
            avg_depth: avg,
        }
    }

    /// Returns the total number of collected callchains.
    pub const fn total_collected(&self) -> u64 {
        self.total_collected
    }
}
