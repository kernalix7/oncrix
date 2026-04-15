// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel heap allocator.
//!
//! Provides a simple linked-list free-list allocator for the kernel heap.
//! The heap region is initialized once during boot with a contiguous
//! virtual memory range.
//!
//! # Synchronization
//!
//! All heap operations are protected by an interrupt-disabling lock
//! ([`HeapLock`]). This prevents re-entrant allocations from interrupt
//! handlers and ensures mutual exclusion on single-core systems.
//! For SMP, a true spinlock should be layered on top.
//!
//! # Allocation Headers
//!
//! Each allocation stores a small [`AllocHeader`] immediately before the
//! returned pointer. The header records the original block start address
//! and the total number of bytes consumed (including alignment padding
//! and the header itself). This allows `dealloc` to correctly reclaim
//! all bytes, even when alignment padding was inserted during `alloc`.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr;

/// Default kernel heap size (256 KiB).
pub const DEFAULT_HEAP_SIZE: usize = 256 * 1024;

/// Header stored before each allocation to track the real block
/// boundaries for correct deallocation.
#[repr(C)]
struct AllocHeader {
    /// Original unaligned block address returned by the free-list.
    block_start: usize,
    /// Total bytes consumed from the free block, including the header
    /// and alignment padding.
    total_size: usize,
}

/// Size of the allocation header in bytes.
const HEADER_SIZE: usize = core::mem::size_of::<AllocHeader>();

/// A free block in the linked-list allocator.
#[repr(C)]
struct FreeBlock {
    /// Size of this free block (including the header).
    size: usize,
    /// Pointer to the next free block, or null.
    next: *mut FreeBlock,
}

// -------------------------------------------------------------------
// Interrupt-disabling lock
// -------------------------------------------------------------------

/// Simple interrupt-disabling lock for heap protection.
///
/// On x86_64, this saves RFLAGS, clears IF (disabling interrupts),
/// and restores IF state on drop. This prevents re-entrant
/// allocations from interrupt handlers.
struct HeapLock;

impl HeapLock {
    /// Acquire the lock by disabling interrupts.
    ///
    /// Returns a [`HeapGuard`] that restores interrupts on drop.
    #[inline]
    fn acquire() -> HeapGuard {
        let flags: u64;
        // SAFETY: pushfq/pop reads RFLAGS (no side effects beyond
        // reading the register). cli disables interrupts, which is
        // required to prevent re-entrant allocations.
        #[cfg(target_arch = "x86_64")]
        unsafe {
            core::arch::asm!(
                "pushfq; pop {}; cli",
                out(reg) flags,
                options(preserves_flags)
            );
        }
        #[cfg(not(target_arch = "x86_64"))]
        let flags = 0u64;
        HeapGuard { flags }
    }
}

/// RAII guard that restores interrupt state on drop.
struct HeapGuard {
    /// Saved RFLAGS value from before the lock was acquired.
    flags: u64,
}

impl Drop for HeapGuard {
    fn drop(&mut self) {
        // Only re-enable interrupts if they were enabled before.
        // Bit 9 of RFLAGS is IF (Interrupt Flag).
        #[cfg(target_arch = "x86_64")]
        if self.flags & 0x200 != 0 {
            // SAFETY: Restoring the interrupt flag to its previous
            // state. sti is safe because we previously disabled
            // interrupts with cli.
            unsafe {
                core::arch::asm!("sti", options(preserves_flags, nomem, nostack));
            }
        }
    }
}

/// A simple linked-list heap allocator.
///
/// Thread safety is achieved via an interrupt-disabling lock
/// ([`HeapLock`]) that wraps every allocation and deallocation.
/// This allocator is intentionally simple; it will be replaced by
/// a more sophisticated slab allocator once the kernel matures.
pub struct LinkedListAllocator {
    inner: UnsafeCell<LinkedListInner>,
}

struct LinkedListInner {
    /// Head of the free list.
    head: *mut FreeBlock,
    /// Total heap size.
    total_size: usize,
    /// Total allocated bytes (for diagnostics).
    allocated: usize,
}

// SAFETY: All mutable access to the inner allocator is protected by
// the interrupt-disabling HeapLock. On single-core, disabling
// interrupts guarantees mutual exclusion (no re-entrant access from
// ISRs). On SMP, an additional spinlock must be added before
// enabling secondary cores.
unsafe impl Sync for LinkedListAllocator {}

impl LinkedListAllocator {
    /// Create an uninitialized allocator.
    ///
    /// Call [`init`](Self::init) before any allocation.
    pub const fn empty() -> Self {
        Self {
            inner: UnsafeCell::new(LinkedListInner {
                head: ptr::null_mut(),
                total_size: 0,
                allocated: 0,
            }),
        }
    }

    /// Initialize the allocator with a heap memory region.
    ///
    /// # Safety
    ///
    /// - `heap_start` must be a valid, writable memory region of
    ///   `heap_size` bytes.
    /// - This must be called exactly once before any allocation.
    /// - The memory must not overlap with any other active allocation.
    pub unsafe fn init(&self, heap_start: *mut u8, heap_size: usize) {
        let _guard = HeapLock::acquire();
        // SAFETY: Caller guarantees this is called once before any
        // allocation, and the guard ensures exclusive access.
        let inner = unsafe { &mut *self.inner.get() };
        let block = heap_start as *mut FreeBlock;
        // SAFETY: We own this memory region and it is large enough
        // for a FreeBlock header.
        unsafe {
            (*block).size = heap_size;
            (*block).next = ptr::null_mut();
        }
        inner.head = block;
        inner.total_size = heap_size;
        inner.allocated = 0;
    }

    /// Return total heap size and currently allocated bytes.
    pub fn stats(&self) -> (usize, usize) {
        let _guard = HeapLock::acquire();
        // SAFETY: Read-only access under the interrupt-disable guard.
        let inner = unsafe { &*self.inner.get() };
        (inner.total_size, inner.allocated)
    }
}

unsafe impl GlobalAlloc for LinkedListAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let _guard = HeapLock::acquire();
        // SAFETY: Exclusive access is guaranteed by the HeapLock guard.
        let inner = unsafe { &mut *self.inner.get() };
        let size = layout.size().max(core::mem::size_of::<FreeBlock>());
        let align = layout.align().max(core::mem::align_of::<FreeBlock>());

        // Walk the free list looking for a suitable block.
        let mut prev: *mut FreeBlock = ptr::null_mut();
        let mut current = inner.head;

        while !current.is_null() {
            // SAFETY: `current` is non-null and points into the
            // heap region managed by this allocator.
            let block = unsafe { &mut *current };
            let block_addr = current as usize;

            // We need space for: [padding] [AllocHeader] [user data]
            // The user pointer must be aligned to `align`.
            // The header sits immediately before the user pointer.
            let user_addr = match align_up_usize(block_addr + HEADER_SIZE, align) {
                Some(addr) => addr,
                None => {
                    prev = current;
                    current = block.next;
                    continue;
                }
            };
            let total_needed = match (user_addr + size).checked_sub(block_addr) {
                Some(n) => n,
                None => {
                    prev = current;
                    current = block.next;
                    continue;
                }
            };

            if block.size >= total_needed {
                let remaining = block.size - total_needed;

                if remaining >= core::mem::size_of::<FreeBlock>() {
                    // Split: create a new free block after the allocation.
                    let new_block = (block_addr + total_needed) as *mut FreeBlock;
                    // SAFETY: `new_block` lies within the current
                    // free block and has enough space for a header.
                    unsafe {
                        (*new_block).size = remaining;
                        (*new_block).next = block.next;
                    }
                    if prev.is_null() {
                        inner.head = new_block;
                    } else {
                        // SAFETY: `prev` is non-null (checked above)
                        // and points to a valid free-list node.
                        unsafe {
                            (*prev).next = new_block;
                        }
                    }
                } else {
                    // Use the entire block (no split — remainder too
                    // small for a FreeBlock header).
                    if prev.is_null() {
                        inner.head = block.next;
                    } else {
                        // SAFETY: `prev` is non-null (checked above)
                        // and points to a valid free-list node.
                        unsafe {
                            (*prev).next = block.next;
                        }
                    }
                }

                // Write the allocation header just before the user
                // pointer so dealloc can recover the block boundaries.
                let header_ptr = (user_addr - HEADER_SIZE) as *mut AllocHeader;
                // SAFETY: header_ptr is within the allocated region
                // (between block_addr and user_addr) and is properly
                // aligned for AllocHeader (usize-aligned, which is
                // guaranteed because user_addr is at least
                // pointer-aligned and HEADER_SIZE is a multiple of
                // the pointer size).
                unsafe {
                    (*header_ptr).block_start = block_addr;
                    (*header_ptr).total_size = total_needed;
                }

                inner.allocated += total_needed;
                return user_addr as *mut u8;
            }

            prev = current;
            current = block.next;
        }

        ptr::null_mut()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        let _guard = HeapLock::acquire();
        // SAFETY: Exclusive access is guaranteed by the HeapLock guard.
        let inner = unsafe { &mut *self.inner.get() };

        // Read the allocation header placed by alloc() to recover the
        // original block start and total size.
        let header_ptr = (ptr as usize - HEADER_SIZE) as *const AllocHeader;
        // SAFETY: ptr was returned by alloc(), which wrote a valid
        // AllocHeader at this location.
        let block_addr = unsafe { (*header_ptr).block_start };
        let total_size = unsafe { (*header_ptr).total_size };

        // Return the entire block (from block_start, not from ptr)
        // back to the free list. This correctly reclaims padding and
        // header bytes that alloc() consumed.
        let block = block_addr as *mut FreeBlock;
        // SAFETY: block_addr was the start of a free-list block
        // allocated by alloc(), so it is valid and large enough for
        // a FreeBlock header.
        unsafe {
            (*block).size = total_size;
            (*block).next = inner.head;
        }
        inner.head = block;
        inner.allocated = inner.allocated.saturating_sub(total_size);
    }
}

/// Align `value` up to the next multiple of `align`.
///
/// `align` must be a power of two. Returns `None` on overflow.
const fn align_up_usize(value: usize, align: usize) -> Option<usize> {
    let mask = align - 1;
    match value.checked_add(mask) {
        Some(v) => Some(v & !mask),
        None => None,
    }
}
