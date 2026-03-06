// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SMP-safe synchronization primitives.
//!
//! Provides a ticket spinlock and a sleeping mutex for the kernel.
//! These are the foundational locking primitives used by all other
//! kernel subsystems to protect shared mutable state.
//!
//! # Spinlock
//!
//! A ticket-based spinlock providing fair (FIFO) acquisition.
//! Should be held for very short durations only. Interrupts should
//! be disabled while holding a spinlock to avoid deadlocks from
//! interrupt handlers.
//!
//! # Mutex
//!
//! A sleeping mutex that spins briefly then conceptually yields.
//! Suitable for longer critical sections where sleeping is acceptable.
//!
//! Reference: Linux `include/linux/spinlock.h`, `kernel/locking/mutex.c`.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

// ---------------------------------------------------------------------------
// SpinLock (ticket-based)
// ---------------------------------------------------------------------------

/// A ticket-based spinlock.
///
/// Guarantees FIFO ordering: waiters acquire the lock in the order
/// they requested it, preventing starvation.
///
/// # Example
///
/// ```ignore
/// static COUNTER: SpinLock<u64> = SpinLock::new(0);
///
/// let mut guard = COUNTER.lock();
/// *guard += 1;
/// // lock is released when `guard` is dropped
/// ```
pub struct SpinLock<T> {
    /// Next ticket to hand out.
    next: AtomicU32,
    /// Currently serving ticket.
    serving: AtomicU32,
    /// Protected data.
    data: UnsafeCell<T>,
}

// SAFETY: SpinLock provides mutual exclusion, making the inner T
// safe to share across threads (provided T is Send).
unsafe impl<T: Send> Sync for SpinLock<T> {}
unsafe impl<T: Send> Send for SpinLock<T> {}

impl<T> SpinLock<T> {
    /// Create a new spinlock protecting `value`.
    pub const fn new(value: T) -> Self {
        Self {
            next: AtomicU32::new(0),
            serving: AtomicU32::new(0),
            data: UnsafeCell::new(value),
        }
    }

    /// Acquire the lock, spinning until available.
    ///
    /// Returns a guard that releases the lock on drop.
    pub fn lock(&self) -> SpinLockGuard<'_, T> {
        let ticket = self.next.fetch_add(1, Ordering::Relaxed);
        while self.serving.load(Ordering::Acquire) != ticket {
            core::hint::spin_loop();
        }
        SpinLockGuard { lock: self }
    }

    /// Try to acquire the lock without spinning.
    ///
    /// Returns `Some(guard)` if the lock was free, `None` otherwise.
    pub fn try_lock(&self) -> Option<SpinLockGuard<'_, T>> {
        let current = self.serving.load(Ordering::Relaxed);
        if self
            .next
            .compare_exchange(current, current + 1, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(SpinLockGuard { lock: self })
        } else {
            None
        }
    }

    /// Check if the lock is currently held (non-binding, racy check).
    pub fn is_locked(&self) -> bool {
        self.next.load(Ordering::Relaxed) != self.serving.load(Ordering::Relaxed)
    }
}

impl<T: core::fmt::Debug> core::fmt::Debug for SpinLock<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.try_lock() {
            Some(guard) => f.debug_struct("SpinLock").field("data", &*guard).finish(),
            None => f
                .debug_struct("SpinLock")
                .field("data", &"<locked>")
                .finish(),
        }
    }
}

/// RAII guard for [`SpinLock`]. Releases the lock on drop.
pub struct SpinLockGuard<'a, T> {
    lock: &'a SpinLock<T>,
}

impl<T> core::ops::Deref for SpinLockGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: We hold the lock, so exclusive access is guaranteed.
        unsafe { &*self.lock.data.get() }
    }
}

impl<T> core::ops::DerefMut for SpinLockGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: We hold the lock, so exclusive access is guaranteed.
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T> Drop for SpinLockGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.serving.fetch_add(1, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// Mutex (spinning with backoff)
// ---------------------------------------------------------------------------

/// A mutual exclusion lock with brief spinning.
///
/// Unlike [`SpinLock`], the mutex uses a simple flag with exponential
/// backoff, suitable for slightly longer critical sections. In a full
/// kernel, waiters would be placed on a wait queue and descheduled;
/// here we spin with increasing pauses.
///
/// Guarantees exclusive access but does NOT guarantee FIFO ordering.
pub struct Mutex<T> {
    /// Lock flag (true = held).
    locked: AtomicBool,
    /// Protected data.
    data: UnsafeCell<T>,
}

// SAFETY: Same reasoning as SpinLock.
unsafe impl<T: Send> Sync for Mutex<T> {}
unsafe impl<T: Send> Send for Mutex<T> {}

/// Maximum number of spin iterations before yielding a hint.
const MAX_SPIN_ITERS: u32 = 1000;

impl<T> Mutex<T> {
    /// Create a new unlocked mutex protecting `value`.
    pub const fn new(value: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(value),
        }
    }

    /// Acquire the mutex.
    ///
    /// Spins with backoff until the lock becomes available.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        let mut spins = 0u32;
        loop {
            if self
                .locked
                .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return MutexGuard { mutex: self };
            }
            // Back off: spin_loop hint, increasing pause.
            spins = spins.saturating_add(1);
            for _ in 0..spins.min(MAX_SPIN_ITERS) {
                core::hint::spin_loop();
            }
        }
    }

    /// Try to acquire the mutex without blocking.
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Some(MutexGuard { mutex: self })
        } else {
            None
        }
    }

    /// Check if the mutex is currently held.
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::Relaxed)
    }
}

impl<T: core::fmt::Debug> core::fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.try_lock() {
            Some(guard) => f.debug_struct("Mutex").field("data", &*guard).finish(),
            None => f.debug_struct("Mutex").field("data", &"<locked>").finish(),
        }
    }
}

/// RAII guard for [`Mutex`]. Releases the lock on drop.
pub struct MutexGuard<'a, T> {
    mutex: &'a Mutex<T>,
}

impl<T> core::ops::Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: We hold the lock.
        unsafe { &*self.mutex.data.get() }
    }
}

impl<T> core::ops::DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: We hold the lock.
        unsafe { &mut *self.mutex.data.get() }
    }
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.mutex.locked.store(false, Ordering::Release);
    }
}

// ---------------------------------------------------------------------------
// Once (one-time initialization)
// ---------------------------------------------------------------------------

/// A cell that can be initialized exactly once.
///
/// Useful for lazy static initialization of kernel subsystems.
pub struct Once<T> {
    /// Initialization state: 0 = uninit, 1 = initializing, 2 = done.
    state: AtomicU32,
    /// The stored value.
    data: UnsafeCell<Option<T>>,
}

// SAFETY: Once guarantees single-initialization and read-only access afterward.
unsafe impl<T: Send + Sync> Sync for Once<T> {}
unsafe impl<T: Send> Send for Once<T> {}

const ONCE_UNINIT: u32 = 0;
const ONCE_RUNNING: u32 = 1;
const ONCE_DONE: u32 = 2;

impl<T> Default for Once<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> Once<T> {
    /// Create a new uninitialized `Once`.
    pub const fn new() -> Self {
        Self {
            state: AtomicU32::new(ONCE_UNINIT),
            data: UnsafeCell::new(None),
        }
    }

    /// Initialize the value, or return the existing value if already initialized.
    ///
    /// `f` is called at most once. Concurrent callers will spin until
    /// initialization completes.
    pub fn call_once<F: FnOnce() -> T>(&self, f: F) -> &T {
        match self.state.compare_exchange(
            ONCE_UNINIT,
            ONCE_RUNNING,
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(_) => {
                // We won the race — initialize.
                // SAFETY: We are the only writer (state was UNINIT → RUNNING).
                unsafe {
                    (*self.data.get()) = Some(f());
                }
                self.state.store(ONCE_DONE, Ordering::Release);
            }
            Err(_) => {
                // Someone else is initializing or already done — wait.
                while self.state.load(Ordering::Acquire) != ONCE_DONE {
                    core::hint::spin_loop();
                }
            }
        }
        // SAFETY: state == DONE means data is initialized and immutable.
        unsafe { (*self.data.get()).as_ref().unwrap_unchecked() }
    }

    /// Get a reference to the value if it has been initialized.
    pub fn get(&self) -> Option<&T> {
        if self.state.load(Ordering::Acquire) == ONCE_DONE {
            // SAFETY: state == DONE means data is initialized and immutable.
            unsafe { (*self.data.get()).as_ref() }
        } else {
            None
        }
    }

    /// Check if the value has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.state.load(Ordering::Acquire) == ONCE_DONE
    }
}

impl<T: core::fmt::Debug> core::fmt::Debug for Once<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.get() {
            Some(val) => f.debug_struct("Once").field("data", val).finish(),
            None => f.debug_struct("Once").field("data", &"<uninit>").finish(),
        }
    }
}
