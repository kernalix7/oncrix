// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Reference counting with saturation semantics.
//!
//! `Refcount` mirrors the Linux kernel's `refcount_t`: once the counter
//! saturates at `REFCOUNT_SATURATED`, it never returns to zero — preventing
//! use-after-free exploits that rely on reference counter overflow.
//!
//! The API intentionally does not expose the raw value; callers operate only
//! through `inc`, `dec`, `try_inc`, and `is_zero`.

use core::sync::atomic::{AtomicU32, Ordering};

use oncrix_lib::{Error, Result};

/// Value at which the refcount saturates and can no longer be decremented.
pub const REFCOUNT_SATURATED: u32 = u32::MAX / 2;

/// Saturating reference counter.
///
/// - `inc()` increments unless already saturated.
/// - `dec()` decrements and returns whether the count reached zero.
/// - Saturated counts never reach zero; this prevents counter-overflow attacks.
pub struct Refcount {
    refs: AtomicU32,
}

impl Refcount {
    /// Creates a new `Refcount` initialized to `1`.
    pub const fn new() -> Self {
        Self {
            refs: AtomicU32::new(1),
        }
    }

    /// Creates a `Refcount` with a specific initial value (for testing).
    pub const fn new_with(val: u32) -> Self {
        Self {
            refs: AtomicU32::new(val),
        }
    }

    /// Increments the reference count.
    ///
    /// Panics in debug builds if the count was zero (incrementing a dead object).
    #[inline]
    pub fn inc(&self) {
        let old = self.refs.fetch_add(1, Ordering::Relaxed);
        debug_assert!(old != 0, "refcount: increment of zero");
        // Saturate to prevent overflow attacks.
        if old > REFCOUNT_SATURATED {
            self.refs.store(REFCOUNT_SATURATED, Ordering::Relaxed);
        }
    }

    /// Tries to increment the refcount only if it is currently non-zero.
    ///
    /// Returns `Ok(())` on success, `Err(NotFound)` if the count was already zero.
    pub fn try_inc(&self) -> Result<()> {
        let mut old = self.refs.load(Ordering::Relaxed);
        loop {
            if old == 0 {
                return Err(Error::NotFound);
            }
            if old >= REFCOUNT_SATURATED {
                // Already saturated — increment is a no-op.
                return Ok(());
            }
            match self.refs.compare_exchange_weak(
                old,
                old + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => old = actual,
            }
        }
    }

    /// Decrements the reference count.
    ///
    /// Returns `true` when the count reaches zero, indicating the object
    /// should be freed. Saturated counts never return `true`.
    #[inline]
    pub fn dec(&self) -> bool {
        if self.refs.load(Ordering::Relaxed) >= REFCOUNT_SATURATED {
            // Saturated — do not decrement.
            return false;
        }
        // Use Release so prior accesses to the object are visible to the thread
        // that observes the zero.
        let old = self.refs.fetch_sub(1, Ordering::Release);
        if old == 1 {
            // Ensure all prior stores are visible before the caller frees the object.
            core::sync::atomic::fence(Ordering::Acquire);
            return true;
        }
        false
    }

    /// Decrements the refcount. Returns `Err(InvalidArgument)` if it was already zero.
    pub fn dec_checked(&self) -> Result<bool> {
        let old = self.refs.load(Ordering::Relaxed);
        if old == 0 {
            return Err(Error::InvalidArgument);
        }
        Ok(self.dec())
    }

    /// Returns `true` if the count is zero.
    ///
    /// This is primarily useful after `dec()` to check whether cleanup is needed
    /// in contexts where `dec()` itself is insufficient.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.refs.load(Ordering::Acquire) == 0
    }

    /// Returns `true` if the count is saturated (infinite / immortal object).
    #[inline]
    pub fn is_saturated(&self) -> bool {
        self.refs.load(Ordering::Relaxed) >= REFCOUNT_SATURATED
    }

    /// Returns the raw count. Use only for diagnostics/debugging.
    #[inline]
    pub fn raw(&self) -> u32 {
        self.refs.load(Ordering::Relaxed)
    }
}

impl Default for Refcount {
    fn default() -> Self {
        Self::new()
    }
}

/// A wrapper that automatically decrements a `Refcount` when dropped.
///
/// Useful for scope-based reference management.
pub struct RefGuard<'a, T, F>
where
    F: FnOnce(),
{
    _refcount: &'a Refcount,
    value: &'a T,
    on_drop: Option<F>,
}

impl<'a, T, F: FnOnce()> RefGuard<'a, T, F> {
    /// Creates a new `RefGuard`. Caller must have already called `inc()`.
    pub fn new(refcount: &'a Refcount, value: &'a T, on_drop: F) -> Self {
        Self {
            _refcount: refcount,
            value,
            on_drop: Some(on_drop),
        }
    }

    /// Returns a reference to the guarded value.
    pub fn get(&self) -> &T {
        self.value
    }
}

impl<T, F: FnOnce()> Drop for RefGuard<'_, T, F> {
    fn drop(&mut self) {
        if let Some(f) = self.on_drop.take() {
            f();
        }
    }
}
