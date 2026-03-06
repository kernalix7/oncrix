// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! IOMMU fault reporting and handling.
//!
//! Provides a platform-independent interface for receiving and processing
//! IOMMU page faults (also called DMA remapping faults or translation faults).
//!
//! # Architecture
//!
//! When a device performs a DMA transaction that violates the IOMMU
//! mapping (unmapped address, permission violation, or invalid stream ID),
//! the IOMMU generates a fault event. This module:
//!
//! - Defines [`IommuFault`] — the canonical fault descriptor
//! - Provides [`FaultQueue`] — a ring buffer of recent faults
//! - Defines [`FaultHandler`] trait for platform-specific handlers
//! - Offers [`FaultReporter`] — aggregates faults from multiple IOMMU instances

use oncrix_lib::{Error, Result};

/// Maximum faults stored in the ring buffer.
const FAULT_QUEUE_SIZE: usize = 64;

// ── Fault Reason ───────────────────────────────────────────────────────────

/// Classification of an IOMMU fault reason.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultReason {
    /// Translation fault — address not mapped.
    TranslationFault,
    /// Access flag fault — page not marked accessible.
    AccessFlagFault,
    /// Permission fault — R/W/X permission violation.
    PermissionFault,
    /// Stream ID not found in the stream table.
    StreamIdFault,
    /// Internal hardware error.
    InternalError,
    /// Unknown or platform-specific fault.
    Unknown(u32),
}

// ── Fault Severity ─────────────────────────────────────────────────────────

/// Fault severity level.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FaultSeverity {
    /// Recoverable fault — transaction was aborted with AXI error response.
    Recoverable,
    /// Unrecoverable fault — hardware may be in undefined state.
    Unrecoverable,
}

// ── IOMMU Fault Descriptor ─────────────────────────────────────────────────

/// A single IOMMU fault event.
#[derive(Clone, Copy)]
pub struct IommuFault {
    /// The input (device-visible) address that faulted.
    pub input_addr: u64,
    /// Stream ID (RID/DevSID) of the faulting device.
    pub stream_id: u32,
    /// Substrate ID (PASID) if sub-stream is valid.
    pub pasid: Option<u32>,
    /// Fault reason classification.
    pub reason: FaultReason,
    /// Fault severity.
    pub severity: FaultSeverity,
    /// True if the fault was a read transaction; false for write.
    pub is_read: bool,
    /// IOMMU instance index that reported this fault.
    pub iommu_idx: u8,
}

impl IommuFault {
    /// Create a new fault descriptor.
    pub fn new(
        iommu_idx: u8,
        stream_id: u32,
        input_addr: u64,
        reason: FaultReason,
        is_read: bool,
    ) -> Self {
        Self {
            input_addr,
            stream_id,
            pasid: None,
            reason,
            severity: FaultSeverity::Recoverable,
            is_read,
            iommu_idx,
        }
    }

    /// Attach a PASID to this fault.
    pub fn with_pasid(mut self, pasid: u32) -> Self {
        self.pasid = Some(pasid);
        self
    }

    /// Mark the fault as unrecoverable.
    pub fn mark_unrecoverable(mut self) -> Self {
        self.severity = FaultSeverity::Unrecoverable;
        self
    }
}

// ── Fault Queue ─────────────────────────────────────────────────────────────

/// Ring buffer of recent IOMMU faults.
pub struct FaultQueue {
    entries: [Option<IommuFault>; FAULT_QUEUE_SIZE],
    head: usize,
    tail: usize,
    count: usize,
    dropped: u64,
}

impl Default for FaultQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl FaultQueue {
    /// Create an empty fault queue.
    pub fn new() -> Self {
        Self {
            entries: [const { None }; FAULT_QUEUE_SIZE],
            head: 0,
            tail: 0,
            count: 0,
            dropped: 0,
        }
    }

    /// Push a fault into the queue. If full, the oldest entry is overwritten.
    pub fn push(&mut self, fault: IommuFault) {
        if self.count == FAULT_QUEUE_SIZE {
            // Overwrite oldest entry (advance tail).
            self.tail = (self.tail + 1) % FAULT_QUEUE_SIZE;
            self.dropped += 1;
        } else {
            self.count += 1;
        }
        self.entries[self.head] = Some(fault);
        self.head = (self.head + 1) % FAULT_QUEUE_SIZE;
    }

    /// Pop the oldest fault from the queue.
    pub fn pop(&mut self) -> Option<IommuFault> {
        if self.count == 0 {
            return None;
        }
        let fault = self.entries[self.tail].take();
        self.tail = (self.tail + 1) % FAULT_QUEUE_SIZE;
        self.count -= 1;
        fault
    }

    /// Returns the number of faults currently queued.
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no faults are queued.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the number of faults dropped due to queue overflow.
    pub fn dropped_count(&self) -> u64 {
        self.dropped
    }

    /// Clear all pending faults.
    pub fn clear(&mut self) {
        for slot in self.entries.iter_mut() {
            *slot = None;
        }
        self.head = 0;
        self.tail = 0;
        self.count = 0;
    }
}

// ── Fault Statistics ───────────────────────────────────────────────────────

/// Aggregated fault statistics for an IOMMU instance.
#[derive(Default)]
pub struct FaultStats {
    /// Total faults received.
    pub total: u64,
    /// Translation faults.
    pub translation: u64,
    /// Permission faults.
    pub permission: u64,
    /// Stream ID faults.
    pub stream_id: u64,
    /// Unrecoverable faults.
    pub unrecoverable: u64,
}

impl FaultStats {
    /// Create zeroed statistics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a fault and update counters.
    pub fn record(&mut self, fault: &IommuFault) {
        self.total += 1;
        match fault.reason {
            FaultReason::TranslationFault | FaultReason::AccessFlagFault => self.translation += 1,
            FaultReason::PermissionFault => self.permission += 1,
            FaultReason::StreamIdFault => self.stream_id += 1,
            _ => {}
        }
        if fault.severity == FaultSeverity::Unrecoverable {
            self.unrecoverable += 1;
        }
    }
}

// ── Fault Reporter ─────────────────────────────────────────────────────────

/// Maximum IOMMU instances tracked.
const MAX_IOMMU_INSTANCES: usize = 8;

/// Central IOMMU fault reporter that aggregates faults from multiple instances.
pub struct FaultReporter {
    queue: FaultQueue,
    stats: [FaultStats; MAX_IOMMU_INSTANCES],
    instance_count: usize,
}

impl FaultReporter {
    /// Create a new fault reporter.
    pub fn new() -> Self {
        Self {
            queue: FaultQueue::new(),
            stats: [const {
                FaultStats {
                    total: 0,
                    translation: 0,
                    permission: 0,
                    stream_id: 0,
                    unrecoverable: 0,
                }
            }; MAX_IOMMU_INSTANCES],
            instance_count: 0,
        }
    }

    /// Register an IOMMU instance and return its assigned index.
    pub fn register_instance(&mut self) -> Result<u8> {
        if self.instance_count >= MAX_IOMMU_INSTANCES {
            return Err(Error::OutOfMemory);
        }
        let idx = self.instance_count;
        self.instance_count += 1;
        Ok(idx as u8)
    }

    /// Report a fault from an IOMMU instance.
    pub fn report(&mut self, fault: IommuFault) {
        let idx = fault.iommu_idx as usize;
        if idx < self.instance_count {
            self.stats[idx].record(&fault);
        }
        self.queue.push(fault);
    }

    /// Drain the next fault from the queue.
    pub fn next_fault(&mut self) -> Option<IommuFault> {
        self.queue.pop()
    }

    /// Get statistics for a specific IOMMU instance.
    pub fn stats(&self, idx: usize) -> Option<&FaultStats> {
        if idx < self.instance_count {
            Some(&self.stats[idx])
        } else {
            None
        }
    }

    /// Returns true if any faults are pending.
    pub fn has_faults(&self) -> bool {
        !self.queue.is_empty()
    }
}

impl Default for FaultReporter {
    fn default() -> Self {
        Self::new()
    }
}
