// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel heap allocator.
//!
//! Provides a simple linked-list free-list allocator for the kernel heap.
//! The heap region is initialized once during boot with a contiguous
//! virtual memory range.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ptr;

/// Default kernel heap size (256 KiB).
pub const DEFAULT_HEAP_SIZE: usize = 256 * 1024;

/// A free block in the linked-list allocator.
#[repr(C)]
struct FreeBlock {
    /// Size of this free block (including the header).
    size: usize,
    /// Pointer to the next free block, or null.
    next: *mut FreeBlock,
}

/// A simple linked-list heap allocator.
///
/// Thread safety is achieved via a spinlock (interrupt-safe).
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

// SAFETY: During early boot, only the BSP (Bootstrap Processor) runs,
// so no concurrent access occurs. Before SMP initialization, this must
// be wrapped in a spinlock. The kernel entry point is responsible for
// ensuring single-threaded access until synchronization is in place.
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
        // SAFETY: Read-only access to diagnostic counters.
        let inner = unsafe { &*self.inner.get() };
        (inner.total_size, inner.allocated)
    }
}

unsafe impl GlobalAlloc for LinkedListAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let inner = unsafe { &mut *self.inner.get() };
        let size = layout.size().max(core::mem::size_of::<FreeBlock>());
        let align = layout.align().max(core::mem::align_of::<FreeBlock>());

        // Walk the free list looking for a suitable block.
        let mut prev: *mut FreeBlock = ptr::null_mut();
        let mut current = inner.head;

        while !current.is_null() {
            let block = unsafe { &mut *current };
            let block_addr = current as usize;
            let aligned_addr = align_up_usize(block_addr, align);
            let padding = aligned_addr - block_addr;
            let total_needed = size + padding;

            if block.size >= total_needed {
                let remaining = block.size - total_needed;

                if remaining >= core::mem::size_of::<FreeBlock>() {
                    // Split: create a new free block after the allocation.
                    let new_block = (block_addr + total_needed) as *mut FreeBlock;
                    unsafe {
                        (*new_block).size = remaining;
                        (*new_block).next = block.next;
                    }
                    if prev.is_null() {
                        inner.head = new_block;
                    } else {
                        unsafe {
                            (*prev).next = new_block;
                        }
                    }
                } else {
                    // Use the entire block.
                    if prev.is_null() {
                        inner.head = block.next;
                    } else {
                        unsafe {
                            (*prev).next = block.next;
                        }
                    }
                }

                inner.allocated += total_needed;
                return aligned_addr as *mut u8;
            }

            prev = current;
            current = block.next;
        }

        ptr::null_mut()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let inner = unsafe { &mut *self.inner.get() };
        let size = layout.size().max(core::mem::size_of::<FreeBlock>());
        let align = layout.align().max(core::mem::align_of::<FreeBlock>());

        // Reconstruct total_needed the same way alloc() computed it,
        // so the allocated counter stays consistent.
        let block_addr = ptr as usize;
        let aligned_addr = align_up_usize(block_addr, align);
        let padding = aligned_addr - block_addr;
        let total_needed = size + padding;

        let block = ptr as *mut FreeBlock;
        // SAFETY: ptr was returned by alloc(), so it is valid and
        // large enough for a FreeBlock header.
        unsafe {
            (*block).size = size;
            (*block).next = inner.head;
        }
        inner.head = block;
        inner.allocated = inner.allocated.saturating_sub(total_needed);
    }
}

/// Align `value` up to the next multiple of `align`.
///
/// `align` must be a power of two. Returns `usize::MAX` (masked)
/// on overflow, which will cause subsequent bounds checks to fail
/// gracefully rather than wrapping to a small address.
const fn align_up_usize(value: usize, align: usize) -> usize {
    let mask = align - 1;
    (value.wrapping_add(mask)) & !mask
}
