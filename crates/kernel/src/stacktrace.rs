// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Stack trace capture and storage.
//!
//! Provides `StackTrace` for capturing and storing kernel stack frames.
//! Frame addresses are stored as raw `u64` values; a symbol resolver can
//! be hooked in to render human-readable names.
//!
//! On x86-64, frame walking uses the frame pointer chain (`%rbp → return
//! address`). The implementation is architecture-gated so that non-x86
//! targets compile without inline assembly.

use oncrix_lib::{Error, Result};

/// Maximum number of stack frames captured per trace.
pub const STACK_MAX_FRAMES: usize = 64;

/// Maximum length of a symbolized function name.
pub const STACK_MAX_SYMBOL_LEN: usize = 64;

/// Symbol resolver callback type.
pub type SymbolResolver = fn(addr: u64, buf: &mut [u8; STACK_MAX_SYMBOL_LEN]) -> usize;

/// Global symbol resolver (set once at init time).
static mut SYMBOL_RESOLVER: Option<SymbolResolver> = None;

/// Registers a symbol resolver for stack trace rendering.
///
/// # Safety
///
/// Must be called exactly once before any stack trace is printed.
/// Concurrent calls are not safe.
pub unsafe fn register_symbol_resolver(resolver: SymbolResolver) {
    // SAFETY: Caller guarantees single-threaded initialization.
    unsafe {
        SYMBOL_RESOLVER = Some(resolver);
    }
}

/// A captured kernel stack trace.
pub struct StackTrace {
    /// Captured return addresses, most recent first.
    frames: [u64; STACK_MAX_FRAMES],
    /// Number of valid frames in `frames`.
    depth: usize,
    /// Optional PID of the task that was traced.
    pub pid: u32,
}

impl StackTrace {
    /// Creates an empty stack trace.
    pub const fn new() -> Self {
        Self {
            frames: [0u64; STACK_MAX_FRAMES],
            depth: 0,
            pid: 0,
        }
    }

    /// Returns the number of captured frames.
    #[inline]
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Returns the captured frame addresses (most recent first).
    #[inline]
    pub fn frames(&self) -> &[u64] {
        &self.frames[..self.depth]
    }

    /// Pushes a frame address onto the trace. Returns `Err(OutOfMemory)` when full.
    pub fn push(&mut self, addr: u64) -> Result<()> {
        if self.depth >= STACK_MAX_FRAMES {
            return Err(Error::OutOfMemory);
        }
        self.frames[self.depth] = addr;
        self.depth += 1;
        Ok(())
    }

    /// Clears all captured frames.
    pub fn clear(&mut self) {
        self.depth = 0;
        self.frames = [0u64; STACK_MAX_FRAMES];
    }

    /// Resolves frame `idx` to a symbol name using the registered resolver.
    ///
    /// Returns the number of bytes written into `buf`, or 0 if no resolver is set.
    pub fn resolve_frame(&self, idx: usize, buf: &mut [u8; STACK_MAX_SYMBOL_LEN]) -> usize {
        if idx >= self.depth {
            return 0;
        }
        // SAFETY: SYMBOL_RESOLVER is set once at init and never mutated after.
        let resolver = unsafe { SYMBOL_RESOLVER };
        if let Some(f) = resolver {
            f(self.frames[idx], buf)
        } else {
            0
        }
    }
}

impl Default for StackTrace {
    fn default() -> Self {
        Self::new()
    }
}

/// Captures the current kernel stack trace using frame pointer unwinding.
///
/// `skip` frames at the top of the stack are discarded (to hide the
/// `capture_stack_trace` call itself from the output).
///
/// # Safety
///
/// Reads the frame pointer chain. Caller must ensure frames are not
/// corrupted (e.g., compiled with `-C force-frame-pointers=yes`).
#[cfg(target_arch = "x86_64")]
pub unsafe fn capture_stack_trace(skip: usize) -> StackTrace {
    let mut trace = StackTrace::new();
    let mut fp: u64;

    // SAFETY: Reading %rbp is always safe in kernel context.
    unsafe {
        core::arch::asm!(
            "mov {fp}, rbp",
            fp = out(reg) fp,
            options(nostack, nomem)
        );
    }

    let mut frames_seen = 0usize;

    while fp != 0 && trace.depth < STACK_MAX_FRAMES {
        // Each frame: [saved_rbp][return_address]
        // SAFETY: We trust the kernel frame pointer chain. Frames are
        // kernel-mode pointers; if fp is invalid, this faults in kernel context.
        let saved_fp = unsafe { *(fp as *const u64) };
        let ret_addr = unsafe { *((fp + 8) as *const u64) };

        if ret_addr < 0xFFFF_8000_0000_0000 {
            // Crossed into user space — stop.
            break;
        }

        if frames_seen >= skip {
            let _ = trace.push(ret_addr);
        }
        frames_seen += 1;
        fp = saved_fp;
    }

    trace
}

/// Non-x86 stub: returns an empty trace.
#[cfg(not(target_arch = "x86_64"))]
pub unsafe fn capture_stack_trace(_skip: usize) -> StackTrace {
    StackTrace::new()
}

/// Captures a stack trace and records it with the given `pid` label.
pub fn snapshot(pid: u32, skip: usize) -> StackTrace {
    // SAFETY: Stack capture reads frame pointer chain in kernel context.
    let mut t = unsafe { capture_stack_trace(skip + 1) };
    t.pid = pid;
    t
}

/// Stack entry used in a ring buffer of recent traces.
pub struct StackEntry {
    /// The captured trace.
    pub trace: StackTrace,
    /// Monotonic timestamp (nanoseconds) when the trace was taken.
    pub timestamp_ns: u64,
}

impl StackEntry {
    /// Creates a new entry.
    pub const fn new() -> Self {
        Self {
            trace: StackTrace::new(),
            timestamp_ns: 0,
        }
    }
}

impl Default for StackEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Ring buffer storing the last `N` stack traces.
pub struct StackRingBuffer<const N: usize> {
    entries: [StackEntry; N],
    head: usize,
    count: usize,
}

impl<const N: usize> StackRingBuffer<N> {
    /// Creates an empty ring buffer.
    pub fn new() -> Self
    where
        [StackEntry; N]: Sized,
    {
        // N <= 32 variant; for larger N the const initializer is needed.
        Self {
            entries: core::array::from_fn(|_| StackEntry::new()),
            head: 0,
            count: 0,
        }
    }

    /// Records a new stack trace in the ring buffer.
    pub fn record(&mut self, trace: StackTrace, timestamp_ns: u64) {
        self.entries[self.head] = StackEntry {
            trace,
            timestamp_ns,
        };
        self.head = (self.head + 1) % N;
        if self.count < N {
            self.count += 1;
        }
    }

    /// Returns the number of valid entries.
    #[inline]
    pub fn count(&self) -> usize {
        self.count
    }
}

impl<const N: usize> Default for StackRingBuffer<N> {
    fn default() -> Self {
        Self {
            entries: core::array::from_fn(|_| StackEntry::new()),
            head: 0,
            count: 0,
        }
    }
}
