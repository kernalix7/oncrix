// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Per-thread kernel stack.
//!
//! Each [`Thread`](crate::thread::Thread) owns a heap-allocated
//! kernel stack that is installed in `TSS.RSP0` whenever the thread
//! is selected to run (so that any ring 3 → 0 trap — interrupt,
//! exception, or IRETQ fallback — lands on the correct private
//! stack). Without per-thread kernel stacks, forking a second
//! process that traps concurrently with its parent would clobber a
//! shared stack and triple-fault.
//!
//! The buffer is 32 KiB and 16-byte aligned so the initial RSP is
//! ABI-compliant for a `call` instruction.
//!
//! # Why 32 KiB, not Linux's 16 KiB `THREAD_SIZE`
//!
//! ONCRIX has no kernel-stack guard pages: per-thread stacks are
//! plain heap `Box` allocations placed adjacent to one another. A
//! deep syscall (notably `sys_execve`, whose ELF-parse + per-process
//! `UserAddressSpace` rebuild call chain is stack-heavy) overflowed a
//! 16 KiB stack and underflowed into the *neighbouring* thread's
//! stack, zeroing that thread's saved `switch_context` return address
//! and faulting (`#UD`/`#GP` at a tiny RIP) the next time it was
//! resumed. 32 KiB restores headroom. The proper long-term fix is a
//! guard page per stack plus trimming `sys_execve`'s frame.

extern crate alloc;

use alloc::boxed::Box;
use oncrix_lib::{Error, Result};

/// Kernel stack size for every thread (32 KiB).
pub const KSTACK_SIZE: usize = 32 * 1024;

/// 16-byte aligned backing buffer.
///
/// The System V AMD64 ABI requires `RSP` to be 16-byte aligned
/// just before a `call` instruction. Allocating a `[u8; N]`
/// provides no alignment guarantee stronger than 1, so we wrap
/// it in a `#[repr(C, align(16))]` struct.
#[repr(C, align(16))]
struct KStackBuf([u8; KSTACK_SIZE]);

/// Owning handle for a thread's kernel stack.
///
/// Dropping a `KernelStack` frees the 16 KiB buffer. The top of
/// the stack (highest address, since x86_64 stacks grow down)
/// is exposed via [`top`](Self::top) for `TSS.RSP0` installation.
pub struct KernelStack {
    buf: Box<KStackBuf>,
}

impl KernelStack {
    /// Allocate a fresh 16 KiB kernel stack on the kernel heap.
    ///
    /// Returns `Err(OutOfMemory)` if the heap is exhausted.
    pub fn allocate() -> Result<Self> {
        // Allocate uninitialized so the 16 KiB array is NOT materialized
        // on the caller's kernel stack before being copied into the Box.
        // `Box::try_new(KStackBuf([0; N]))` forces the compiler to build
        // the zero buffer on the stack first — which easily overflows the
        // 32 KiB SYSCALL kernel stack when a fork path layers its own
        // local frames on top. `try_new_uninit` allocates directly from
        // the heap and we zero in place afterward.
        let mut buf: Box<core::mem::MaybeUninit<KStackBuf>> =
            Box::try_new_uninit().map_err(|_| Error::OutOfMemory)?;
        // SAFETY: `buf` points at an allocation sized/aligned for
        // `KStackBuf`. `write_bytes` zeroes exactly that region.
        unsafe {
            core::ptr::write_bytes(buf.as_mut_ptr().cast::<u8>(), 0, KSTACK_SIZE);
        }
        // SAFETY: All bytes of the allocation were just zeroed; the
        // all-zero bit pattern is a valid value for `KStackBuf`
        // (a repr(C, align(16)) wrapper around `[u8; N]`).
        let buf = unsafe { buf.assume_init() };
        Ok(Self { buf })
    }

    /// Return the bottom (lowest address) of the stack as a `u64`.
    pub fn bottom(&self) -> u64 {
        core::ptr::addr_of!(self.buf.0) as u64
    }

    /// Return the top of the stack (initial `RSP`).
    ///
    /// x86_64 stacks grow downward; `top` is `bottom + KSTACK_SIZE`
    /// and is 16-byte aligned by construction.
    pub fn top(&self) -> u64 {
        self.bottom() + KSTACK_SIZE as u64
    }

    /// Write a 64-bit word at `offset_from_top` bytes below the
    /// stack top and return the absolute address that was written.
    ///
    /// Used by arch-specific clone code to pre-seed an `iretq`
    /// frame on a freshly-allocated child stack.
    ///
    /// # Errors
    ///
    /// Returns `InvalidArgument` if `offset_from_top` is not a
    /// multiple of 8 or would write outside the stack buffer.
    pub fn write_u64_from_top(&mut self, offset_from_top: usize, value: u64) -> Result<u64> {
        if offset_from_top % 8 != 0 || !(8..=KSTACK_SIZE).contains(&offset_from_top) {
            return Err(Error::InvalidArgument);
        }
        let addr = self.top() - offset_from_top as u64;
        // SAFETY: `addr` lies within `self.buf` because `offset_from_top`
        // is in `[8, KSTACK_SIZE]`. The buffer is exclusively owned
        // through `&mut self` and is 16-byte aligned, so an 8-byte
        // aligned write is valid.
        unsafe {
            let ptr = addr as *mut u64;
            ptr.write(value);
        }
        Ok(addr)
    }
}

impl core::fmt::Debug for KernelStack {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KernelStack")
            .field("bottom", &format_args!("{:#x}", self.bottom()))
            .field("top", &format_args!("{:#x}", self.top()))
            .field("size", &KSTACK_SIZE)
            .finish()
    }
}
