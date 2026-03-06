// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Sequence lock (seqcount + spinlock).
//!
//! A seqlock allows concurrent readers without blocking writers. Readers
//! detect concurrent writes by observing an odd sequence counter during the
//! read window, and retry. Writers increment the counter before and after
//! their update, ensuring readers see an even value only for consistent data.
//!
//! Two types are provided:
//! - `SeqCount`: raw sequence counter (no writer lock, caller must ensure
//!   single-writer invariant).
//! - `SeqLock<T>`: sequence counter combined with writer-side exclusive access.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering, fence};

use oncrix_lib::Result;

/// Raw sequence counter.
///
/// The caller is responsible for mutual exclusion among writers.
pub struct SeqCount {
    seq: AtomicU64,
}

impl SeqCount {
    /// Creates a new sequence counter initialized to 0.
    pub const fn new() -> Self {
        Self {
            seq: AtomicU64::new(0),
        }
    }

    /// Reads the current sequence value for a reader snapshot.
    ///
    /// If the returned value is odd, a write is in progress — the caller
    /// should spin and re-read.
    #[inline]
    pub fn read_begin(&self) -> u64 {
        loop {
            let seq = self.seq.load(Ordering::Acquire);
            if seq & 1 == 0 {
                return seq;
            }
            core::hint::spin_loop();
        }
    }

    /// Returns `true` if the sequence has changed since `old_seq`, meaning
    /// the data read between `read_begin` and `read_retry` is inconsistent.
    #[inline]
    pub fn read_retry(&self, old_seq: u64) -> bool {
        fence(Ordering::Acquire);
        self.seq.load(Ordering::Relaxed) != old_seq
    }

    /// Called by the writer before modifying guarded data.
    ///
    /// # Safety
    ///
    /// Only one writer may hold the lock at a time.
    #[inline]
    pub unsafe fn write_begin(&self) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let _ = seq;
        fence(Ordering::Release);
    }

    /// Called by the writer after modifying guarded data.
    ///
    /// # Safety
    ///
    /// Must be called after `write_begin` and after all mutations are complete.
    #[inline]
    pub unsafe fn write_end(&self) {
        fence(Ordering::Release);
        self.seq.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the raw sequence value (for diagnostics).
    #[inline]
    pub fn raw(&self) -> u64 {
        self.seq.load(Ordering::Relaxed)
    }
}

impl Default for SeqCount {
    fn default() -> Self {
        Self::new()
    }
}

/// A sequence lock combining a `SeqCount` with protected data.
///
/// Writers use `write()` which holds exclusive access.
/// Readers call `read()` which retries on conflict.
pub struct SeqLock<T: Copy> {
    seq: SeqCount,
    data: UnsafeCell<T>,
    /// Writer "lock" bit: 0 = unlocked, 1 = locked.
    writer: AtomicU64,
}

// SAFETY: SeqLock provides its own synchronization via atomics.
unsafe impl<T: Copy + Send> Send for SeqLock<T> {}
// SAFETY: Readers are lock-free; writers use writer token.
unsafe impl<T: Copy + Send> Sync for SeqLock<T> {}

impl<T: Copy + Default> SeqLock<T> {
    /// Creates a new `SeqLock` with the default value for `T`.
    pub fn new_default() -> Self {
        Self {
            seq: SeqCount::new(),
            data: UnsafeCell::new(T::default()),
            writer: AtomicU64::new(0),
        }
    }
}

impl<T: Copy> SeqLock<T> {
    /// Creates a new `SeqLock` with the provided initial value.
    pub const fn new(value: T) -> Self {
        Self {
            seq: SeqCount::new(),
            data: UnsafeCell::new(value),
            writer: AtomicU64::new(0),
        }
    }

    /// Reads the protected data with retry on concurrent writes.
    ///
    /// The closure `f` is called with a copy of `T` obtained under a
    /// consistent read window. It may be called multiple times on contention.
    pub fn read<F, R>(&self, f: F) -> R
    where
        F: Fn(T) -> R,
    {
        loop {
            let seq = self.seq.read_begin();
            // SAFETY: We checked that no write is in progress (seq is even).
            // The fence in read_begin ensures visibility of data written before
            // the writer incremented the sequence counter to even.
            let val = unsafe { *self.data.get() };
            if !self.seq.read_retry(seq) {
                return f(val);
            }
            core::hint::spin_loop();
        }
    }

    /// Acquires the writer lock and applies `f` to modify the data.
    ///
    /// Returns `Err(Busy)` if another writer is active.
    pub fn try_write<F>(&self, f: F) -> Result<()>
    where
        F: FnOnce(&mut T),
    {
        // Try to claim writer token.
        if self
            .writer
            .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return Err(oncrix_lib::Error::Busy);
        }

        // SAFETY: We hold the writer token (writer == 1), ensuring exclusion.
        unsafe {
            self.seq.write_begin();
            f(&mut *self.data.get());
            self.seq.write_end();
        }

        self.writer.store(0, Ordering::Release);
        Ok(())
    }

    /// Blocking writer: spins until the writer lock is available.
    pub fn write<F>(&self, f: F)
    where
        F: FnOnce(&mut T),
    {
        loop {
            if self
                .writer
                .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
            core::hint::spin_loop();
        }

        // SAFETY: Writer token held exclusively.
        unsafe {
            self.seq.write_begin();
            f(&mut *self.data.get());
            self.seq.write_end();
        }

        self.writer.store(0, Ordering::Release);
    }
}
