// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Saved interrupt-return frame for preemptive scheduling (Phase 20 prep).
//!
//! When a true preemptive timer interrupt eventually replaces the current
//! cooperative `yield_now()` model, the timer ISR will:
//!
//! 1. Capture the user-mode trap frame the CPU pushed on entry (`rip`,
//!    `cs`, `rflags`, `rsp`, `ss`).
//! 2. Capture six general-purpose scratch registers it needed to spill
//!    before calling Rust code.
//! 3. Stash all eleven words on the *outgoing* thread.
//! 4. Pop the *incoming* thread's previously-saved frame back into the
//!    iretq buffer and the scratch registers.
//! 5. Issue `iretq` to resume that thread on its own user-mode stack.
//!
//! This module provides the typed [`IretFrame`] container plus the two
//! conversion helpers ([`IretFrame::from_irq_stack`] and
//! [`IretFrame::apply_to_iretq_buffer`]) used by that future ISR. **No
//! interrupt handler in this batch is wired to use it yet** — the
//! activation step (rewriting `timer_handler` as a naked function) is
//! intentionally a separate commit so the new datapath can be QEMU-
//! verified in isolation without disturbing the Phase 14 keyboard work.
//!
//! # Layout
//!
//! `IretFrame` is `#[repr(C)]` and convertible to/from a raw `[u64; 11]`
//! buffer (see [`IretFrame::SLOTS`]). The raw form is what the
//! [`oncrix_process::thread::Thread`] holds, because the process crate
//! cannot depend on `oncrix-kernel` (that direction would form a cycle:
//! `kernel → process → kernel`). Conversion is zero-cost.
//!
//! # References
//!
//! Inspired by Linux's `struct pt_regs` (see
//! `.priv-storage/.kernelORG/Documentation/x86/entry_64.html`); the
//! ONCRIX variant keeps only the bits we actually need to round-trip an
//! `iretq` plus a fixed-size scratch slab.

use oncrix_hal::arch::x86_64::idt::InterruptStackFrame;

/// Saved interrupt-return frame for one preempted thread.
///
/// Holds the five hardware-pushed words (`rip`, `cs`, `rflags`, `rsp`,
/// `ss`) and a six-slot scratch slab for general-purpose registers the
/// ISR spills before calling into Rust. See the module doc for the
/// expected save/restore sequence.
///
/// `IretFrame` is `Copy`, `repr(C)`, and trivially serialisable to
/// `[u64; 11]` via [`IretFrame::into_raw`] / [`IretFrame::from_raw`] —
/// the latter pair is how `Thread` stores the frame without taking a
/// dependency on this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(C)]
pub struct IretFrame {
    /// Faulting / preempted instruction pointer. Pushed by CPU.
    pub rip: u64,
    /// Code segment selector at preemption. Pushed by CPU.
    pub cs: u64,
    /// `RFLAGS` snapshot (including `IF`). Pushed by CPU.
    pub rflags: u64,
    /// User-mode stack pointer at preemption. Pushed by CPU.
    pub rsp: u64,
    /// Stack segment selector at preemption. Pushed by CPU.
    pub ss: u64,
    /// Six-slot scratch slab for general-purpose registers the
    /// preemption ISR needs to spill before calling Rust. The exact
    /// register-to-slot mapping is owned by the (future) naked
    /// `timer_handler`; this module treats them as opaque words.
    pub saved: [u64; 6],
}

impl IretFrame {
    /// Number of `u64` slots in the raw representation
    /// (5 hardware-pushed + 6 scratch).
    pub const SLOTS: usize = 11;

    /// Construct a zeroed frame.
    ///
    /// Prefer [`Self::from_irq_stack`] when the source is an actual
    /// CPU-pushed trap frame. The all-zero variant exists for use as
    /// a sentinel inside `Option<IretFrame>` and for the initial
    /// per-thread slot that is filled in on the first preemption.
    pub const fn zeroed() -> Self {
        Self {
            rip: 0,
            cs: 0,
            rflags: 0,
            rsp: 0,
            ss: 0,
            saved: [0; 6],
        }
    }

    /// Build an `IretFrame` from the CPU-pushed trap frame.
    ///
    /// The scratch slab is left zeroed; the ISR fills it in with the
    /// actual general-purpose register values it spilled. Cheap copy of
    /// five `u64`s.
    pub const fn from_irq_stack(frame: &InterruptStackFrame) -> Self {
        Self {
            rip: frame.rip,
            cs: frame.cs,
            rflags: frame.rflags,
            rsp: frame.rsp,
            ss: frame.ss,
            saved: [0; 6],
        }
    }

    /// Write the five hardware-restored words into a buffer the ISR
    /// will pop with `iretq`.
    ///
    /// The buffer layout matches what the CPU consumes on `iretq`:
    /// `[rip, cs, rflags, rsp, ss]` in ascending memory order
    /// (lowest address first). The scratch slab is **not** copied —
    /// the ISR is responsible for restoring those into real registers
    /// before issuing `iretq`.
    pub const fn apply_to_iretq_buffer(&self, buf: &mut [u64; 5]) {
        buf[0] = self.rip;
        buf[1] = self.cs;
        buf[2] = self.rflags;
        buf[3] = self.rsp;
        buf[4] = self.ss;
    }

    /// Pack the frame into the raw `[u64; 11]` form held by
    /// [`oncrix_process::thread::Thread::saved_irq_frame_raw`].
    ///
    /// Slot order: `rip, cs, rflags, rsp, ss, saved[0..6]`.
    pub const fn into_raw(self) -> [u64; Self::SLOTS] {
        [
            self.rip,
            self.cs,
            self.rflags,
            self.rsp,
            self.ss,
            self.saved[0],
            self.saved[1],
            self.saved[2],
            self.saved[3],
            self.saved[4],
            self.saved[5],
        ]
    }

    /// Reconstruct the typed frame from the raw `[u64; 11]` form held
    /// by `Thread`. Inverse of [`Self::into_raw`].
    pub const fn from_raw(raw: [u64; Self::SLOTS]) -> Self {
        Self {
            rip: raw[0],
            cs: raw[1],
            rflags: raw[2],
            rsp: raw[3],
            ss: raw[4],
            saved: [raw[5], raw[6], raw[7], raw[8], raw[9], raw[10]],
        }
    }
}
