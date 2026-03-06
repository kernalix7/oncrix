// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Hardware poison injection for testing.
//!
//! Provides a debugfs interface to inject hardware memory errors
//! (soft-offline, hard-offline) into specific pages for testing the
//! memory-failure recovery path. Injection rules specify PFN ranges
//! and error types.
//!
//! # Design
//!
//! ```text
//!  echo <pfn> > /sys/kernel/debug/hwpoison/inject
//!     │
//!     ├─ mark page as HWPoisoned
//!     ├─ trigger memory_failure(pfn) handler
//!     └─ observe recovery behaviour
//!
//!  echo <pfn> > /sys/kernel/debug/hwpoison/unpoison
//!     │
//!     └─ clear HWPoison, restore page
//! ```
//!
//! # Key Types
//!
//! - [`InjectType`] — type of poison injection
//! - [`InjectRequest`] — a single injection request
//! - [`HwPoisonInjector`] — manages injection requests
//! - [`InjectStats`] — injection statistics
//!
//! Reference: Linux `mm/hwpoison-inject.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum injection requests.
const MAX_REQUESTS: usize = 512;

/// Maximum PFN range per injection.
const MAX_PFN_RANGE: u64 = 4096;

/// Page size.
const PAGE_SIZE: u64 = 4096;

// -------------------------------------------------------------------
// InjectType
// -------------------------------------------------------------------

/// Type of poison injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InjectType {
    /// Soft-offline: migrate data.
    SoftOffline,
    /// Hard-offline: page is dead.
    HardOffline,
    /// Unpoison: reverse a previous injection.
    Unpoison,
}

impl InjectType {
    /// Return a label string.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::SoftOffline => "soft-offline",
            Self::HardOffline => "hard-offline",
            Self::Unpoison => "unpoison",
        }
    }

    /// Check whether this is destructive.
    pub const fn is_destructive(&self) -> bool {
        matches!(self, Self::HardOffline)
    }
}

// -------------------------------------------------------------------
// InjectRequest
// -------------------------------------------------------------------

/// A single injection request.
#[derive(Debug, Clone, Copy)]
pub struct InjectRequest {
    /// Request ID.
    request_id: u64,
    /// Start PFN.
    pfn: u64,
    /// Number of pages (1 for single-page inject).
    page_count: u64,
    /// Injection type.
    inject_type: InjectType,
    /// Whether the injection was applied.
    applied: bool,
    /// Whether recovery was triggered.
    recovery_triggered: bool,
    /// Timestamp.
    timestamp: u64,
}

impl InjectRequest {
    /// Create a new request.
    pub const fn new(
        request_id: u64,
        pfn: u64,
        page_count: u64,
        inject_type: InjectType,
        timestamp: u64,
    ) -> Self {
        Self {
            request_id,
            pfn,
            page_count,
            inject_type,
            applied: false,
            recovery_triggered: false,
            timestamp,
        }
    }

    /// Return the request ID.
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    /// Return the PFN.
    pub const fn pfn(&self) -> u64 {
        self.pfn
    }

    /// Return the page count.
    pub const fn page_count(&self) -> u64 {
        self.page_count
    }

    /// Return the injection type.
    pub const fn inject_type(&self) -> InjectType {
        self.inject_type
    }

    /// Check whether applied.
    pub const fn applied(&self) -> bool {
        self.applied
    }

    /// Check whether recovery was triggered.
    pub const fn recovery_triggered(&self) -> bool {
        self.recovery_triggered
    }

    /// Return the timestamp.
    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Mark as applied.
    pub fn apply(&mut self) {
        self.applied = true;
    }

    /// Mark recovery as triggered.
    pub fn trigger_recovery(&mut self) {
        self.recovery_triggered = true;
    }

    /// Size in bytes.
    pub const fn size_bytes(&self) -> u64 {
        self.page_count * PAGE_SIZE
    }
}

impl Default for InjectRequest {
    fn default() -> Self {
        Self {
            request_id: 0,
            pfn: 0,
            page_count: 0,
            inject_type: InjectType::SoftOffline,
            applied: false,
            recovery_triggered: false,
            timestamp: 0,
        }
    }
}

// -------------------------------------------------------------------
// InjectStats
// -------------------------------------------------------------------

/// Injection statistics.
#[derive(Debug, Clone, Copy)]
pub struct InjectStats {
    /// Total injections.
    pub total_injections: u64,
    /// Soft-offline injections.
    pub soft_offlines: u64,
    /// Hard-offline injections.
    pub hard_offlines: u64,
    /// Unpoison injections.
    pub unpoisons: u64,
    /// Recoveries triggered.
    pub recoveries: u64,
    /// Injection failures.
    pub failures: u64,
}

impl InjectStats {
    /// Create zero stats.
    pub const fn new() -> Self {
        Self {
            total_injections: 0,
            soft_offlines: 0,
            hard_offlines: 0,
            unpoisons: 0,
            recoveries: 0,
            failures: 0,
        }
    }
}

impl Default for InjectStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// HwPoisonInjector
// -------------------------------------------------------------------

/// Manages poison injection requests.
pub struct HwPoisonInjector {
    /// Requests.
    requests: [InjectRequest; MAX_REQUESTS],
    /// Number of requests.
    count: usize,
    /// Next request ID.
    next_id: u64,
    /// Whether injection is enabled.
    enabled: bool,
    /// Statistics.
    stats: InjectStats,
}

impl HwPoisonInjector {
    /// Create a new injector.
    pub const fn new() -> Self {
        Self {
            requests: [const {
                InjectRequest {
                    request_id: 0,
                    pfn: 0,
                    page_count: 0,
                    inject_type: InjectType::SoftOffline,
                    applied: false,
                    recovery_triggered: false,
                    timestamp: 0,
                }
            }; MAX_REQUESTS],
            count: 0,
            next_id: 1,
            enabled: false,
            stats: InjectStats::new(),
        }
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &InjectStats {
        &self.stats
    }

    /// Return the count.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Check whether enabled.
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Enable injection.
    pub fn enable(&mut self) {
        self.enabled = true;
    }

    /// Disable injection.
    pub fn disable(&mut self) {
        self.enabled = false;
    }

    /// Submit an injection request.
    pub fn inject(
        &mut self,
        pfn: u64,
        page_count: u64,
        inject_type: InjectType,
        timestamp: u64,
    ) -> Result<u64> {
        if !self.enabled {
            return Err(Error::PermissionDenied);
        }
        if page_count == 0 || page_count > MAX_PFN_RANGE {
            return Err(Error::InvalidArgument);
        }
        if self.count >= MAX_REQUESTS {
            self.stats.failures += 1;
            return Err(Error::OutOfMemory);
        }

        let rid = self.next_id;
        self.requests[self.count] =
            InjectRequest::new(rid, pfn, page_count, inject_type, timestamp);
        self.requests[self.count].apply();
        self.count += 1;
        self.next_id += 1;

        self.stats.total_injections += 1;
        match inject_type {
            InjectType::SoftOffline => self.stats.soft_offlines += 1,
            InjectType::HardOffline => self.stats.hard_offlines += 1,
            InjectType::Unpoison => self.stats.unpoisons += 1,
        }
        Ok(rid)
    }

    /// Trigger recovery for a request.
    pub fn trigger_recovery(&mut self, request_id: u64) -> Result<()> {
        for idx in 0..self.count {
            if self.requests[idx].request_id() == request_id {
                self.requests[idx].trigger_recovery();
                self.stats.recoveries += 1;
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Find a request by ID.
    pub fn find(&self, request_id: u64) -> Option<&InjectRequest> {
        for idx in 0..self.count {
            if self.requests[idx].request_id() == request_id {
                return Some(&self.requests[idx]);
            }
        }
        None
    }
}

impl Default for HwPoisonInjector {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Return the maximum requests.
pub const fn max_requests() -> usize {
    MAX_REQUESTS
}

/// Return the maximum PFN range.
pub const fn max_pfn_range() -> u64 {
    MAX_PFN_RANGE
}
