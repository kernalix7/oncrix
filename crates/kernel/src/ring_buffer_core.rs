// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Ring buffer core — lock-free per-CPU trace ring buffer.
//!
//! Provides a fixed-size circular buffer for efficient trace data
//! collection. Each CPU has its own buffer to avoid lock contention.
//! Writers append events; readers consume them in FIFO order.
//!
//! # Architecture
//!
//! ```text
//! RingBufferManager
//!  ├── buffers[MAX_CPUS]
//!  │    ├── data[BUFFER_SIZE]  (event storage)
//!  │    ├── head, tail         (read/write cursors)
//!  │    ├── overflows          (drops due to full buffer)
//!  │    └── total_events
//!  └── stats: RingBufStats
//! ```
//!
//! # Reference
//!
//! Linux `kernel/trace/ring_buffer.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum CPUs.
const MAX_CPUS: usize = 16;

/// Per-CPU buffer size in u64 words.
const BUFFER_SIZE: usize = 512;

/// Maximum event payload size in u64 words.
const MAX_EVENT_WORDS: usize = 8;

// ══════════════════════════════════════════════════════════════
// RingBufEvent — event header
// ══════════════════════════════════════════════════════════════

/// A ring buffer event read back to the consumer.
#[derive(Debug, Clone, Copy)]
pub struct RingBufEvent {
    /// Timestamp (monotonic nanoseconds).
    pub timestamp: u64,
    /// Event type identifier.
    pub event_type: u32,
    /// Payload length in u64 words.
    pub payload_len: u32,
    /// Payload data.
    pub payload: [u64; MAX_EVENT_WORDS],
}

impl RingBufEvent {
    /// Create an empty event.
    const fn empty() -> Self {
        Self {
            timestamp: 0,
            event_type: 0,
            payload_len: 0,
            payload: [0u64; MAX_EVENT_WORDS],
        }
    }
}

// ══════════════════════════════════════════════════════════════
// PerCpuBuffer
// ══════════════════════════════════════════════════════════════

/// Per-CPU ring buffer.
pub struct PerCpuBuffer {
    /// Circular storage.
    data: [u64; BUFFER_SIZE],
    /// Write cursor (next write position).
    head: usize,
    /// Read cursor (next read position).
    tail: usize,
    /// Total events written.
    pub total_events: u64,
    /// Events dropped due to buffer full.
    pub overflows: u64,
    /// Total bytes written.
    pub total_words: u64,
    /// Whether this buffer is online.
    pub online: bool,
}

impl PerCpuBuffer {
    /// Create an offline buffer.
    const fn new() -> Self {
        Self {
            data: [0u64; BUFFER_SIZE],
            head: 0,
            tail: 0,
            total_events: 0,
            overflows: 0,
            total_words: 0,
            online: false,
        }
    }

    /// Available space in words.
    fn available(&self) -> usize {
        if self.head >= self.tail {
            BUFFER_SIZE - (self.head - self.tail) - 1
        } else {
            self.tail - self.head - 1
        }
    }

    /// Write an event into the buffer.
    ///
    /// Event format: [timestamp, type_and_len, payload...]
    fn write_event(&mut self, timestamp: u64, event_type: u32, payload: &[u64]) -> Result<()> {
        let total_words = 2 + payload.len(); // header + payload
        if total_words > self.available() {
            self.overflows += 1;
            return Err(Error::OutOfMemory);
        }

        // Write header.
        self.data[self.head] = timestamp;
        self.head = (self.head + 1) % BUFFER_SIZE;

        let type_and_len = ((event_type as u64) << 32) | (payload.len() as u64);
        self.data[self.head] = type_and_len;
        self.head = (self.head + 1) % BUFFER_SIZE;

        // Write payload.
        for &word in payload {
            self.data[self.head] = word;
            self.head = (self.head + 1) % BUFFER_SIZE;
        }

        self.total_events += 1;
        self.total_words += total_words as u64;
        Ok(())
    }

    /// Read and consume the next event from the buffer.
    fn read_event(&mut self) -> Option<RingBufEvent> {
        if self.tail == self.head {
            return None;
        }

        let timestamp = self.data[self.tail];
        self.tail = (self.tail + 1) % BUFFER_SIZE;

        let type_and_len = self.data[self.tail];
        self.tail = (self.tail + 1) % BUFFER_SIZE;

        let event_type = (type_and_len >> 32) as u32;
        let payload_len = (type_and_len & 0xFFFF_FFFF) as u32;

        let mut event = RingBufEvent::empty();
        event.timestamp = timestamp;
        event.event_type = event_type;
        event.payload_len = payload_len;

        let words = (payload_len as usize).min(MAX_EVENT_WORDS);
        for i in 0..words {
            event.payload[i] = self.data[self.tail];
            self.tail = (self.tail + 1) % BUFFER_SIZE;
        }
        // Skip remaining if payload_len > MAX_EVENT_WORDS.
        for _ in words..(payload_len as usize) {
            self.tail = (self.tail + 1) % BUFFER_SIZE;
        }

        Some(event)
    }

    /// Reset the buffer.
    fn reset(&mut self) {
        self.head = 0;
        self.tail = 0;
    }
}

// ══════════════════════════════════════════════════════════════
// RingBufStats
// ══════════════════════════════════════════════════════════════

/// Global ring buffer statistics.
#[derive(Debug, Clone, Copy)]
pub struct RingBufStats {
    /// Total events across all CPUs.
    pub total_events: u64,
    /// Total overflows across all CPUs.
    pub total_overflows: u64,
    /// Total reads across all CPUs.
    pub total_reads: u64,
}

impl RingBufStats {
    /// Create zeroed stats.
    const fn new() -> Self {
        Self {
            total_events: 0,
            total_overflows: 0,
            total_reads: 0,
        }
    }
}

// ══════════════════════════════════════════════════════════════
// RingBufferManager
// ══════════════════════════════════════════════════════════════

/// Manages per-CPU trace ring buffers.
pub struct RingBufferManager {
    /// Per-CPU buffers.
    buffers: [PerCpuBuffer; MAX_CPUS],
    /// Number of online CPUs.
    nr_cpus: u32,
    /// Statistics.
    stats: RingBufStats,
}

impl RingBufferManager {
    /// Create a new ring buffer manager.
    pub const fn new() -> Self {
        Self {
            buffers: [const { PerCpuBuffer::new() }; MAX_CPUS],
            nr_cpus: 0,
            stats: RingBufStats::new(),
        }
    }

    /// Bring a CPU buffer online.
    pub fn cpu_online(&mut self, cpu: u32) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.buffers[c].online = true;
        if cpu >= self.nr_cpus {
            self.nr_cpus = cpu + 1;
        }
        Ok(())
    }

    /// Write a trace event to a CPU's buffer.
    pub fn write(
        &mut self,
        cpu: u32,
        timestamp: u64,
        event_type: u32,
        payload: &[u64],
    ) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS || !self.buffers[c].online {
            return Err(Error::InvalidArgument);
        }
        if payload.len() > MAX_EVENT_WORDS {
            return Err(Error::InvalidArgument);
        }
        let result = self.buffers[c].write_event(timestamp, event_type, payload);
        if result.is_ok() {
            self.stats.total_events += 1;
        } else {
            self.stats.total_overflows += 1;
        }
        result
    }

    /// Read the next event from a CPU's buffer.
    pub fn read(&mut self, cpu: u32) -> Result<Option<RingBufEvent>> {
        let c = cpu as usize;
        if c >= MAX_CPUS || !self.buffers[c].online {
            return Err(Error::InvalidArgument);
        }
        let event = self.buffers[c].read_event();
        if event.is_some() {
            self.stats.total_reads += 1;
        }
        Ok(event)
    }

    /// Reset a CPU's buffer.
    pub fn reset(&mut self, cpu: u32) -> Result<()> {
        let c = cpu as usize;
        if c >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.buffers[c].reset();
        Ok(())
    }

    /// Return statistics.
    pub fn stats(&self) -> RingBufStats {
        self.stats
    }
}
