// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Dynamic kernel tracing probes (kprobes).
//!
//! Kprobes enable dynamic instrumentation of kernel code at
//! arbitrary instruction addresses. A kprobe replaces the first
//! byte of the target instruction with an INT3 breakpoint. When
//! the breakpoint fires, the pre-handler executes, the original
//! instruction is single-stepped, and then the post-handler runs.
//!
//! Kretprobes extend kprobes to also intercept function returns
//! by temporarily replacing the return address on the stack.
//!
//! # Architecture
//!
//! ```text
//!  register_kprobe(addr)
//!        │
//!        ▼
//!  arm_kprobe() ──► save opcode, write INT3
//!        │
//!        ▼
//!  CPU hits INT3 ──► on_breakpoint() ──► pre_handler
//!        │
//!        ▼
//!  single-step ──► on_single_step() ──► post_handler
//!        │
//!        ▼
//!  restore original flow
//! ```
//!
//! Reference: Linux `kernel/kprobes.c`,
//! `include/linux/kprobes.h`.

use oncrix_lib::{Error, Result};

/// Maximum number of kprobes that can be registered.
const MAX_KPROBES: usize = 128;

/// Maximum number of kretprobes that can be registered.
const MAX_KRETPROBES: usize = 64;

/// x86 INT3 software breakpoint opcode.
const _BREAKPOINT_INT3: u8 = 0xCC;

/// Maximum length of a probe symbol name in bytes.
const MAX_SYMBOL_LEN: usize = 64;

/// Maximum number of simultaneous kretprobe instances.
const MAX_KRETPROBE_INSTANCES: usize = 16;

// -------------------------------------------------------------------
// KprobeState
// -------------------------------------------------------------------

/// Lifecycle state of a kprobe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KprobeState {
    /// Probe is registered but not yet armed (INT3 not written).
    #[default]
    Disabled,
    /// Probe is armed — the original opcode has been replaced
    /// with INT3.
    Armed,
    /// Probe is currently executing its handler (breakpoint hit).
    Firing,
    /// Probe has been logically removed and is awaiting cleanup.
    Gone,
}

// -------------------------------------------------------------------
// ProbeRegisters
// -------------------------------------------------------------------

/// Snapshot of x86_64 general-purpose registers captured when a
/// kprobe fires.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ProbeRegisters {
    /// RAX — accumulator.
    pub rax: u64,
    /// RBX — base register.
    pub rbx: u64,
    /// RCX — counter register.
    pub rcx: u64,
    /// RDX — data register.
    pub rdx: u64,
    /// RSI — source index.
    pub rsi: u64,
    /// RDI — destination index.
    pub rdi: u64,
    /// RBP — base pointer.
    pub rbp: u64,
    /// RSP — stack pointer.
    pub rsp: u64,
    /// R8 — extended register 8.
    pub r8: u64,
    /// R9 — extended register 9.
    pub r9: u64,
    /// R10 — extended register 10.
    pub r10: u64,
    /// R11 — extended register 11.
    pub r11: u64,
    /// R12 — extended register 12.
    pub r12: u64,
    /// R13 — extended register 13.
    pub r13: u64,
    /// R14 — extended register 14.
    pub r14: u64,
    /// R15 — extended register 15.
    pub r15: u64,
    /// RIP — instruction pointer at probe site.
    pub rip: u64,
    /// RFLAGS — processor flags.
    pub rflags: u64,
}

// -------------------------------------------------------------------
// Kprobe
// -------------------------------------------------------------------

/// A single kernel probe attached to an instruction address.
///
/// When armed, the first byte at `addr` is replaced with INT3.
/// On the resulting breakpoint, the registered handlers are
/// invoked and the original opcode is restored for
/// single-stepping.
#[derive(Clone, Copy)]
pub struct Kprobe {
    /// Virtual address of the probed instruction.
    pub addr: u64,
    /// Null-terminated symbol name for display/lookup.
    pub symbol: [u8; MAX_SYMBOL_LEN],
    /// Length of the symbol name (excluding null terminator).
    pub symbol_len: usize,
    /// Original first byte of the probed instruction, saved
    /// before INT3 is written.
    pub saved_opcode: u8,
    /// Current lifecycle state of this probe.
    pub state: KprobeState,
    /// Callback identifier for the pre-handler (invoked before
    /// the original instruction executes).
    pub pre_handler_id: u32,
    /// Callback identifier for the post-handler (invoked after
    /// single-stepping the original instruction).
    pub post_handler_id: u32,
    /// Number of times this probe has fired successfully.
    pub hit_count: u64,
    /// Number of times this probe could not fire (e.g., due to
    /// reentrancy or resource exhaustion).
    pub miss_count: u64,
    /// Whether this probe slot is in use.
    pub active: bool,
    /// Unique probe identifier.
    pub id: u32,
}

impl Default for Kprobe {
    fn default() -> Self {
        Self {
            addr: 0,
            symbol: [0u8; MAX_SYMBOL_LEN],
            symbol_len: 0,
            saved_opcode: 0,
            state: KprobeState::Disabled,
            pre_handler_id: 0,
            post_handler_id: 0,
            hit_count: 0,
            miss_count: 0,
            active: false,
            id: 0,
        }
    }
}

// -------------------------------------------------------------------
// KretprobeInstance
// -------------------------------------------------------------------

/// A single active instance of a kretprobe, tracking one
/// in-flight function call whose return will be intercepted.
#[derive(Debug, Clone, Copy, Default)]
pub struct KretprobeInstance {
    /// Task/thread identifier that entered the probed function.
    pub task_id: u64,
    /// Original return address that was replaced on the stack.
    pub return_addr: u64,
    /// Address of the probed function entry point.
    pub entry_addr: u64,
    /// Whether this instance slot is in use.
    pub occupied: bool,
}

// -------------------------------------------------------------------
// Kretprobe
// -------------------------------------------------------------------

/// A return probe that intercepts both function entry and return.
///
/// On entry the original return address is saved and replaced
/// with a trampoline. When the function returns, the trampoline
/// fires the return handler and then jumps back to the original
/// caller.
#[derive(Clone, Copy)]
pub struct Kretprobe {
    /// Underlying kprobe at the function entry point.
    pub kp: Kprobe,
    /// Callback identifier for the return handler.
    pub handler_id: u32,
    /// Maximum number of simultaneously active instances.
    pub max_active: usize,
    /// Number of entry events that could not be recorded
    /// because all instance slots were occupied.
    pub nmissed: u64,
    /// Fixed-size pool of active return-probe instances.
    pub instances: [KretprobeInstance; MAX_KRETPROBE_INSTANCES],
    /// Number of currently occupied instance slots.
    pub instance_count: usize,
}

impl Default for Kretprobe {
    fn default() -> Self {
        Self {
            kp: Kprobe::default(),
            handler_id: 0,
            max_active: MAX_KRETPROBE_INSTANCES,
            nmissed: 0,
            instances: [KretprobeInstance::default(); MAX_KRETPROBE_INSTANCES],
            instance_count: 0,
        }
    }
}

// -------------------------------------------------------------------
// KprobeStats
// -------------------------------------------------------------------

/// Runtime statistics for a registered kprobe.
#[derive(Debug, Clone, Copy)]
pub struct KprobeStats {
    /// Total number of successful probe hits.
    pub hit_count: u64,
    /// Total number of missed probe opportunities.
    pub miss_count: u64,
    /// Current lifecycle state.
    pub state: KprobeState,
}

// -------------------------------------------------------------------
// KprobeRegistry
// -------------------------------------------------------------------

/// Central registry that manages all kprobes and kretprobes.
pub struct KprobeRegistry {
    /// Registered kprobes (fixed-size array).
    kprobes: [Kprobe; MAX_KPROBES],
    /// Registered kretprobes (fixed-size array).
    kretprobes: [Kretprobe; MAX_KRETPROBES],
    /// Next unique probe identifier to assign.
    next_id: u32,
    /// Number of active kprobes.
    kprobe_count: usize,
    /// Number of active kretprobes.
    kretprobe_count: usize,
}

impl Default for KprobeRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl KprobeRegistry {
    /// Creates a new, empty kprobe registry.
    pub const fn new() -> Self {
        // const context requires inline initialization rather
        // than Default::default().
        const KPROBE_INIT: Kprobe = Kprobe {
            addr: 0,
            symbol: [0u8; MAX_SYMBOL_LEN],
            symbol_len: 0,
            saved_opcode: 0,
            state: KprobeState::Disabled,
            pre_handler_id: 0,
            post_handler_id: 0,
            hit_count: 0,
            miss_count: 0,
            active: false,
            id: 0,
        };
        const INSTANCE_INIT: KretprobeInstance = KretprobeInstance {
            task_id: 0,
            return_addr: 0,
            entry_addr: 0,
            occupied: false,
        };
        const KRETPROBE_INIT: Kretprobe = Kretprobe {
            kp: KPROBE_INIT,
            handler_id: 0,
            max_active: MAX_KRETPROBE_INSTANCES,
            nmissed: 0,
            instances: [INSTANCE_INIT; MAX_KRETPROBE_INSTANCES],
            instance_count: 0,
        };
        Self {
            kprobes: [KPROBE_INIT; MAX_KPROBES],
            kretprobes: [KRETPROBE_INIT; MAX_KRETPROBES],
            next_id: 1,
            kprobe_count: 0,
            kretprobe_count: 0,
        }
    }

    /// Registers a new kprobe at the given address.
    ///
    /// Returns the unique probe identifier on success.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the registry is full.
    /// - [`Error::AlreadyExists`] if a probe already exists
    ///   at `addr`.
    /// - [`Error::InvalidArgument`] if `symbol` exceeds
    ///   [`MAX_SYMBOL_LEN`].
    pub fn register_kprobe(
        &mut self,
        addr: u64,
        symbol: &[u8],
        pre_handler: u32,
        post_handler: u32,
    ) -> Result<u32> {
        if symbol.len() > MAX_SYMBOL_LEN {
            return Err(Error::InvalidArgument);
        }
        // Reject duplicate addresses.
        let dup = self.kprobes.iter().any(|kp| kp.active && kp.addr == addr);
        if dup {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .kprobes
            .iter_mut()
            .find(|kp| !kp.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        slot.addr = addr;
        slot.symbol = [0u8; MAX_SYMBOL_LEN];
        slot.symbol[..symbol.len()].copy_from_slice(symbol);
        slot.symbol_len = symbol.len();
        slot.saved_opcode = 0;
        slot.state = KprobeState::Disabled;
        slot.pre_handler_id = pre_handler;
        slot.post_handler_id = post_handler;
        slot.hit_count = 0;
        slot.miss_count = 0;
        slot.active = true;
        slot.id = id;
        self.kprobe_count += 1;
        Ok(id)
    }

    /// Unregisters the kprobe with the given `id`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no active probe has this `id`.
    /// - [`Error::Busy`] if the probe is currently firing.
    pub fn unregister_kprobe(&mut self, id: u32) -> Result<()> {
        let kp = self
            .kprobes
            .iter_mut()
            .find(|kp| kp.active && kp.id == id)
            .ok_or(Error::NotFound)?;

        if kp.state == KprobeState::Firing {
            return Err(Error::Busy);
        }
        kp.state = KprobeState::Gone;
        kp.active = false;
        self.kprobe_count = self.kprobe_count.saturating_sub(1);
        Ok(())
    }

    /// Arms the kprobe with the given `id`, transitioning it
    /// from [`KprobeState::Disabled`] to
    /// [`KprobeState::Armed`].
    ///
    /// Returns the saved opcode that was at the probe address
    /// so the caller can write INT3 in its place.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no active probe has this `id`.
    /// - [`Error::InvalidArgument`] if the probe is not in
    ///   the [`KprobeState::Disabled`] state.
    pub fn arm_kprobe(&mut self, id: u32) -> Result<u8> {
        let kp = self
            .kprobes
            .iter_mut()
            .find(|kp| kp.active && kp.id == id)
            .ok_or(Error::NotFound)?;

        if kp.state != KprobeState::Disabled {
            return Err(Error::InvalidArgument);
        }
        kp.state = KprobeState::Armed;
        Ok(kp.saved_opcode)
    }

    /// Disarms the kprobe with the given `id`, transitioning
    /// it back to [`KprobeState::Disabled`].
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no active probe has this `id`.
    /// - [`Error::Busy`] if the probe is currently firing.
    pub fn disarm_kprobe(&mut self, id: u32) -> Result<()> {
        let kp = self
            .kprobes
            .iter_mut()
            .find(|kp| kp.active && kp.id == id)
            .ok_or(Error::NotFound)?;

        if kp.state == KprobeState::Firing {
            return Err(Error::Busy);
        }
        kp.state = KprobeState::Disabled;
        Ok(())
    }

    /// Called when the CPU hits an INT3 breakpoint at `addr`.
    ///
    /// If a kprobe is registered and armed at that address,
    /// increments its hit count, transitions it to
    /// [`KprobeState::Firing`], and returns the
    /// `pre_handler_id`. Returns `None` if no matching probe
    /// is found.
    pub fn on_breakpoint(&mut self, addr: u64, _regs: &ProbeRegisters) -> Option<u32> {
        let kp = self
            .kprobes
            .iter_mut()
            .find(|kp| kp.active && kp.addr == addr && kp.state == KprobeState::Armed)?;
        kp.hit_count += 1;
        kp.state = KprobeState::Firing;
        Some(kp.pre_handler_id)
    }

    /// Called after single-stepping the original instruction
    /// for probe `id`.
    ///
    /// Transitions the probe back to [`KprobeState::Armed`]
    /// and returns the `post_handler_id`. Returns `None` if
    /// the probe is not found or not in the firing state.
    pub fn on_single_step(&mut self, id: u32) -> Option<u32> {
        let kp = self
            .kprobes
            .iter_mut()
            .find(|kp| kp.active && kp.id == id && kp.state == KprobeState::Firing)?;
        kp.state = KprobeState::Armed;
        Some(kp.post_handler_id)
    }

    /// Registers a new kretprobe at the given function address.
    ///
    /// Returns the unique probe identifier on success.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the registry is full.
    /// - [`Error::AlreadyExists`] if a kretprobe already
    ///   exists at `addr`.
    /// - [`Error::InvalidArgument`] if `symbol` exceeds
    ///   [`MAX_SYMBOL_LEN`] or `max_active` is zero.
    pub fn register_kretprobe(
        &mut self,
        addr: u64,
        symbol: &[u8],
        handler: u32,
        max_active: usize,
    ) -> Result<u32> {
        if symbol.len() > MAX_SYMBOL_LEN {
            return Err(Error::InvalidArgument);
        }
        if max_active == 0 {
            return Err(Error::InvalidArgument);
        }
        let dup = self
            .kretprobes
            .iter()
            .any(|krp| krp.kp.active && krp.kp.addr == addr);
        if dup {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .kretprobes
            .iter_mut()
            .find(|krp| !krp.kp.active)
            .ok_or(Error::OutOfMemory)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        slot.kp = Kprobe::default();
        slot.kp.addr = addr;
        slot.kp.symbol[..symbol.len()].copy_from_slice(symbol);
        slot.kp.symbol_len = symbol.len();
        slot.kp.active = true;
        slot.kp.id = id;
        slot.handler_id = handler;
        slot.max_active = max_active.min(MAX_KRETPROBE_INSTANCES);
        slot.nmissed = 0;
        slot.instances = [KretprobeInstance::default(); MAX_KRETPROBE_INSTANCES];
        slot.instance_count = 0;
        self.kretprobe_count += 1;
        Ok(id)
    }

    /// Unregisters the kretprobe with the given `id`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no active kretprobe has this
    ///   `id`.
    pub fn unregister_kretprobe(&mut self, id: u32) -> Result<()> {
        let krp = self
            .kretprobes
            .iter_mut()
            .find(|krp| krp.kp.active && krp.kp.id == id)
            .ok_or(Error::NotFound)?;

        krp.kp.state = KprobeState::Gone;
        krp.kp.active = false;
        krp.instance_count = 0;
        self.kretprobe_count = self.kretprobe_count.saturating_sub(1);
        Ok(())
    }

    /// Records a kretprobe entry for the given `task_id`.
    ///
    /// Saves the original `return_addr` so it can be restored
    /// when the function returns.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no active kretprobe has this
    ///   `id`.
    /// - [`Error::OutOfMemory`] if the instance pool is full
    ///   (increments `nmissed`).
    pub fn on_kretprobe_entry(&mut self, id: u32, task_id: u64, return_addr: u64) -> Result<()> {
        let krp = self
            .kretprobes
            .iter_mut()
            .find(|krp| krp.kp.active && krp.kp.id == id)
            .ok_or(Error::NotFound)?;

        if krp.instance_count >= krp.max_active {
            krp.nmissed += 1;
            return Err(Error::OutOfMemory);
        }
        let inst = krp
            .instances
            .iter_mut()
            .find(|inst| !inst.occupied)
            .ok_or_else(|| {
                krp.nmissed += 1;
                Error::OutOfMemory
            })?;

        inst.task_id = task_id;
        inst.return_addr = return_addr;
        inst.entry_addr = krp.kp.addr;
        inst.occupied = true;
        krp.instance_count += 1;
        Ok(())
    }

    /// Called when a task returns from a kretprobed function.
    ///
    /// Finds and removes the matching instance for `task_id`
    /// and returns `(handler_id, entry_addr)` so the caller
    /// can invoke the return handler and restore the original
    /// return address.
    ///
    /// Returns `None` if no matching instance is found.
    pub fn on_kretprobe_return(&mut self, task_id: u64) -> Option<(u32, u64)> {
        for krp in &mut self.kretprobes {
            if !krp.kp.active {
                continue;
            }
            let found = krp
                .instances
                .iter_mut()
                .find(|i| i.occupied && i.task_id == task_id);
            if let Some(inst) = found {
                let entry_addr = inst.entry_addr;
                inst.occupied = false;
                inst.task_id = 0;
                inst.return_addr = 0;
                inst.entry_addr = 0;
                krp.instance_count = krp.instance_count.saturating_sub(1);
                return Some((krp.handler_id, entry_addr));
            }
        }
        None
    }

    /// Returns the total number of registered probes (kprobes
    /// plus kretprobes).
    pub fn len(&self) -> usize {
        self.kprobe_count + self.kretprobe_count
    }

    /// Returns `true` if no probes are registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns runtime statistics for the kprobe with the
    /// given `id`.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no active kprobe has this
    ///   `id`.
    pub fn stats(&self, id: u32) -> Result<KprobeStats> {
        let kp = self
            .kprobes
            .iter()
            .find(|kp| kp.active && kp.id == id)
            .ok_or(Error::NotFound)?;
        Ok(KprobeStats {
            hit_count: kp.hit_count,
            miss_count: kp.miss_count,
            state: kp.state,
        })
    }
}
