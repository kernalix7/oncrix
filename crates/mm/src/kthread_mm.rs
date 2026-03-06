// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel thread memory context management.
//!
//! Kernel threads run in kernel address space and do not have their
//! own user-space address space. However they still need a memory
//! management context for page table access, lazy TLB switching, and
//! temporary borrows of a user process mm for copy_to_user/copy_from_user.
//!
//! This module manages the init_mm reference (the kernel page tables),
//! lazy TLB state, and the ability for kernel threads to temporarily
//! adopt another task's mm.
//!
//! # Design
//!
//! ```text
//!  kthread_create() → KthreadMm::new()  (points to init_mm)
//!
//!  kthread needs user access:
//!    use_mm(target_mm)  → borrow target's page tables
//!    copy_to_user(...)  → works with borrowed mm
//!    unuse_mm()         → restore init_mm reference
//! ```
//!
//! # Key Types
//!
//! - [`KthreadMm`] — memory context for a kernel thread
//! - [`KthreadMmState`] — current state of the kthread mm
//! - [`KthreadMmStats`] — usage statistics
//!
//! Reference: Linux `kernel/kthread.c`, `mm/mmu_context.c`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum depth of nested use_mm calls.
const MAX_BORROW_DEPTH: usize = 4;

/// Sentinel value for the kernel init_mm identifier.
const INIT_MM_ID: u64 = 0;

/// Maximum concurrent kthread mm contexts.
const MAX_CONTEXTS: usize = 256;

// -------------------------------------------------------------------
// KthreadMmState
// -------------------------------------------------------------------

/// Current state of a kernel thread's memory context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KthreadMmState {
    /// Using init_mm (kernel page tables only).
    InitMm,
    /// Borrowing a user process mm.
    Borrowed,
    /// Lazy TLB mode (no mm active, using stale TLB).
    LazyTlb,
}

impl KthreadMmState {
    /// Return a label.
    pub const fn label(&self) -> &'static str {
        match self {
            Self::InitMm => "init_mm",
            Self::Borrowed => "borrowed",
            Self::LazyTlb => "lazy_tlb",
        }
    }

    /// Check whether user-space access is available.
    pub const fn can_access_user(&self) -> bool {
        matches!(self, Self::Borrowed)
    }
}

// -------------------------------------------------------------------
// BorrowEntry
// -------------------------------------------------------------------

/// A record of a borrowed mm context.
#[derive(Debug, Clone, Copy)]
struct BorrowEntry {
    /// The mm identifier being borrowed.
    mm_id: u64,
    /// Whether this entry is valid.
    valid: bool,
}

impl BorrowEntry {
    const fn empty() -> Self {
        Self {
            mm_id: 0,
            valid: false,
        }
    }
}

// -------------------------------------------------------------------
// KthreadMm
// -------------------------------------------------------------------

/// Memory context for a kernel thread.
///
/// Kernel threads do not own a user-space address space. They reference
/// the kernel's `init_mm` and can temporarily borrow a user process mm
/// for operations like `copy_to_user`.
pub struct KthreadMm {
    /// Kernel thread identifier.
    kthread_id: u64,
    /// Current state.
    state: KthreadMmState,
    /// Stack of borrowed mm identifiers.
    borrow_stack: [BorrowEntry; MAX_BORROW_DEPTH],
    /// Current borrow depth.
    borrow_depth: usize,
    /// Total borrow operations.
    total_borrows: u64,
    /// Whether lazy TLB mode is requested.
    lazy_tlb: bool,
}

impl KthreadMm {
    /// Create a new kernel thread mm context.
    pub const fn new(kthread_id: u64) -> Self {
        Self {
            kthread_id,
            state: KthreadMmState::InitMm,
            borrow_stack: [const { BorrowEntry::empty() }; MAX_BORROW_DEPTH],
            borrow_depth: 0,
            total_borrows: 0,
            lazy_tlb: false,
        }
    }

    /// Return the kernel thread identifier.
    pub const fn kthread_id(&self) -> u64 {
        self.kthread_id
    }

    /// Return the current state.
    pub const fn state(&self) -> KthreadMmState {
        self.state
    }

    /// Return the current borrow depth.
    pub const fn borrow_depth(&self) -> usize {
        self.borrow_depth
    }

    /// Return the currently active mm identifier.
    pub const fn active_mm_id(&self) -> u64 {
        if self.borrow_depth == 0 {
            INIT_MM_ID
        } else {
            self.borrow_stack[self.borrow_depth - 1].mm_id
        }
    }

    /// Borrow another task's mm for user-space access.
    pub fn use_mm(&mut self, mm_id: u64) -> Result<()> {
        if self.borrow_depth >= MAX_BORROW_DEPTH {
            return Err(Error::InvalidArgument);
        }
        if mm_id == INIT_MM_ID {
            return Err(Error::InvalidArgument);
        }

        self.borrow_stack[self.borrow_depth] = BorrowEntry { mm_id, valid: true };
        self.borrow_depth += 1;
        self.state = KthreadMmState::Borrowed;
        self.total_borrows += 1;
        Ok(())
    }

    /// Release the most recently borrowed mm.
    pub fn unuse_mm(&mut self) -> Result<u64> {
        if self.borrow_depth == 0 {
            return Err(Error::InvalidArgument);
        }
        self.borrow_depth -= 1;
        let entry = self.borrow_stack[self.borrow_depth];
        self.borrow_stack[self.borrow_depth] = BorrowEntry::empty();

        self.state = if self.borrow_depth > 0 {
            KthreadMmState::Borrowed
        } else if self.lazy_tlb {
            KthreadMmState::LazyTlb
        } else {
            KthreadMmState::InitMm
        };

        Ok(entry.mm_id)
    }

    /// Enter lazy TLB mode.
    pub fn enter_lazy_tlb(&mut self) -> Result<()> {
        if self.borrow_depth > 0 {
            return Err(Error::Busy);
        }
        self.lazy_tlb = true;
        self.state = KthreadMmState::LazyTlb;
        Ok(())
    }

    /// Exit lazy TLB mode.
    pub fn exit_lazy_tlb(&mut self) {
        self.lazy_tlb = false;
        if self.borrow_depth == 0 {
            self.state = KthreadMmState::InitMm;
        }
    }

    /// Check whether user-space access is currently available.
    pub const fn can_access_user(&self) -> bool {
        self.state.can_access_user()
    }

    /// Return the total borrow count.
    pub const fn total_borrows(&self) -> u64 {
        self.total_borrows
    }
}

impl Default for KthreadMm {
    fn default() -> Self {
        Self::new(0)
    }
}

// -------------------------------------------------------------------
// KthreadMmStats
// -------------------------------------------------------------------

/// Aggregate statistics for kernel thread mm usage.
#[derive(Debug, Clone, Copy)]
pub struct KthreadMmStats {
    /// Number of active kthread mm contexts.
    pub active_contexts: u64,
    /// Number of contexts currently borrowing.
    pub borrowing_count: u64,
    /// Number of contexts in lazy TLB mode.
    pub lazy_tlb_count: u64,
    /// Total borrow operations system-wide.
    pub total_borrows: u64,
}

impl KthreadMmStats {
    /// Create zero statistics.
    pub const fn new() -> Self {
        Self {
            active_contexts: 0,
            borrowing_count: 0,
            lazy_tlb_count: 0,
            total_borrows: 0,
        }
    }
}

impl Default for KthreadMmStats {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// KthreadMmRegistry
// -------------------------------------------------------------------

/// Registry of all kernel thread mm contexts.
pub struct KthreadMmRegistry {
    /// Registered contexts (kthread_id → active flag).
    ids: [u64; MAX_CONTEXTS],
    /// Number of registered contexts.
    count: usize,
    /// Statistics.
    stats: KthreadMmStats,
}

impl KthreadMmRegistry {
    /// Create an empty registry.
    pub const fn new() -> Self {
        Self {
            ids: [0u64; MAX_CONTEXTS],
            count: 0,
            stats: KthreadMmStats::new(),
        }
    }

    /// Register a new kthread mm context.
    pub fn register(&mut self, kthread_id: u64) -> Result<()> {
        if self.count >= MAX_CONTEXTS {
            return Err(Error::OutOfMemory);
        }
        self.ids[self.count] = kthread_id;
        self.count += 1;
        self.stats.active_contexts += 1;
        Ok(())
    }

    /// Unregister a kthread mm context.
    pub fn unregister(&mut self, kthread_id: u64) -> Result<()> {
        for idx in 0..self.count {
            if self.ids[idx] == kthread_id {
                self.ids[idx] = self.ids[self.count - 1];
                self.ids[self.count - 1] = 0;
                self.count -= 1;
                self.stats.active_contexts = self.stats.active_contexts.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Return the count of registered contexts.
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Return the statistics.
    pub const fn stats(&self) -> &KthreadMmStats {
        &self.stats
    }
}

impl Default for KthreadMmRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------
// Public helpers
// -------------------------------------------------------------------

/// Create a new kernel thread mm context and register it.
pub fn create_kthread_mm(registry: &mut KthreadMmRegistry, kthread_id: u64) -> Result<KthreadMm> {
    registry.register(kthread_id)?;
    Ok(KthreadMm::new(kthread_id))
}

/// Destroy a kernel thread mm context and unregister it.
pub fn destroy_kthread_mm(registry: &mut KthreadMmRegistry, ctx: &KthreadMm) -> Result<()> {
    registry.unregister(ctx.kthread_id())
}

/// Check whether a given mm_id is the init_mm.
pub const fn is_init_mm(mm_id: u64) -> bool {
    mm_id == INIT_MM_ID
}
