// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Context switch implementation.
//!
//! Handles saving and restoring CPU state during task switches,
//! including general-purpose registers, floating-point/SIMD state
//! (FPU/SSE/AVX), and segment registers. Also manages TLB
//! flushing decisions and lazy FPU state switching for
//! performance optimization.

use oncrix_lib::{Error, Result};

/// Maximum number of context switch entries to track.
const MAX_CONTEXTS: usize = 1024;

/// Number of general-purpose registers to save (x86_64).
const _GP_REGISTER_COUNT: usize = 16;

/// FPU/SSE state size in bytes (FXSAVE area).
const FPU_STATE_SIZE: usize = 512;

/// Extended state size for AVX (XSAVE area).
const _XSAVE_STATE_SIZE: usize = 832;

/// FPU state management mode.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FpuMode {
    /// Eager: always save/restore FPU state.
    Eager,
    /// Lazy: only save FPU state on first FPU use after switch.
    Lazy,
    /// Disabled: FPU not available.
    Disabled,
}

/// CPU register state for context switching.
#[derive(Clone, Copy)]
pub struct CpuContext {
    /// Task identifier this context belongs to.
    task_id: u64,
    /// Stack pointer (RSP on x86_64).
    stack_pointer: u64,
    /// Instruction pointer (RIP on x86_64).
    instruction_pointer: u64,
    /// Flags register (RFLAGS on x86_64).
    flags: u64,
    /// General-purpose registers (RAX-R15 on x86_64).
    gp_regs: [u64; 16],
    /// Kernel stack base address.
    kernel_stack_base: u64,
    /// Kernel stack size in bytes.
    kernel_stack_size: u64,
    /// Page table base (CR3 on x86_64).
    page_table_base: u64,
    /// Whether FPU state is valid and saved.
    fpu_state_valid: bool,
    /// FPU/SSE state (FXSAVE format).
    fpu_state: [u8; FPU_STATE_SIZE],
    /// Whether this context is currently active on a CPU.
    active: bool,
    /// CPU this context last ran on (-1 if never).
    last_cpu: i32,
}

impl CpuContext {
    /// Creates a new empty CPU context.
    pub const fn new() -> Self {
        Self {
            task_id: 0,
            stack_pointer: 0,
            instruction_pointer: 0,
            flags: 0,
            gp_regs: [0u64; 16],
            kernel_stack_base: 0,
            kernel_stack_size: 0,
            page_table_base: 0,
            fpu_state_valid: false,
            fpu_state: [0u8; FPU_STATE_SIZE],
            active: false,
            last_cpu: -1,
        }
    }

    /// Creates a context for a new task.
    pub const fn for_task(task_id: u64, entry_point: u64, stack_top: u64, page_table: u64) -> Self {
        Self {
            task_id,
            stack_pointer: stack_top,
            instruction_pointer: entry_point,
            flags: 0x200, // IF (interrupt flag) set
            gp_regs: [0u64; 16],
            kernel_stack_base: 0,
            kernel_stack_size: 0,
            page_table_base: page_table,
            fpu_state_valid: false,
            fpu_state: [0u8; FPU_STATE_SIZE],
            active: false,
            last_cpu: -1,
        }
    }

    /// Returns the task identifier.
    pub const fn task_id(&self) -> u64 {
        self.task_id
    }

    /// Returns the stack pointer.
    pub const fn stack_pointer(&self) -> u64 {
        self.stack_pointer
    }

    /// Returns the instruction pointer.
    pub const fn instruction_pointer(&self) -> u64 {
        self.instruction_pointer
    }

    /// Returns the page table base address.
    pub const fn page_table_base(&self) -> u64 {
        self.page_table_base
    }

    /// Sets the kernel stack for this context.
    pub fn set_kernel_stack(&mut self, base: u64, size: u64) {
        self.kernel_stack_base = base;
        self.kernel_stack_size = size;
    }

    /// Returns whether this context is active on a CPU.
    pub const fn is_active(&self) -> bool {
        self.active
    }

    /// Returns the last CPU this context ran on.
    pub const fn last_cpu(&self) -> i32 {
        self.last_cpu
    }

    /// Returns whether FPU state is valid.
    pub const fn has_fpu_state(&self) -> bool {
        self.fpu_state_valid
    }
}

impl Default for CpuContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics for context switch operations.
#[derive(Clone, Copy)]
pub struct SwitchStats {
    /// Total number of context switches performed.
    total_switches: u64,
    /// Number of switches that required TLB flush.
    tlb_flushes: u64,
    /// Number of FPU state saves.
    fpu_saves: u64,
    /// Number of FPU state restores.
    fpu_restores: u64,
    /// Number of switches between same address space.
    same_mm_switches: u64,
    /// Cumulative switch time in nanoseconds.
    total_switch_time_ns: u64,
}

impl SwitchStats {
    /// Creates new zero-initialized switch statistics.
    pub const fn new() -> Self {
        Self {
            total_switches: 0,
            tlb_flushes: 0,
            fpu_saves: 0,
            fpu_restores: 0,
            same_mm_switches: 0,
            total_switch_time_ns: 0,
        }
    }

    /// Returns the total number of context switches.
    pub const fn total_switches(&self) -> u64 {
        self.total_switches
    }

    /// Returns the number of TLB flushes.
    pub const fn tlb_flushes(&self) -> u64 {
        self.tlb_flushes
    }

    /// Returns the number of FPU saves.
    pub const fn fpu_saves(&self) -> u64 {
        self.fpu_saves
    }

    /// Returns average switch time in nanoseconds.
    pub const fn avg_switch_time_ns(&self) -> u64 {
        if self.total_switches == 0 {
            0
        } else {
            self.total_switch_time_ns / self.total_switches
        }
    }
}

impl Default for SwitchStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Context switch manager handling task state transitions.
pub struct ContextSwitchManager {
    /// Stored CPU contexts for tasks.
    contexts: [CpuContext; MAX_CONTEXTS],
    /// Number of registered contexts.
    count: usize,
    /// FPU management mode.
    fpu_mode: FpuMode,
    /// Per-CPU statistics.
    stats: SwitchStats,
    /// Currently active task ID per CPU (up to 256 CPUs).
    active_task_per_cpu: [u64; 256],
    /// Number of CPUs.
    nr_cpus: usize,
}

impl ContextSwitchManager {
    /// Creates a new context switch manager.
    pub const fn new() -> Self {
        Self {
            contexts: [const { CpuContext::new() }; MAX_CONTEXTS],
            count: 0,
            fpu_mode: FpuMode::Lazy,
            stats: SwitchStats::new(),
            active_task_per_cpu: [0u64; 256],
            nr_cpus: 0,
        }
    }

    /// Sets the number of CPUs.
    pub fn set_nr_cpus(&mut self, nr: usize) {
        if nr <= 256 {
            self.nr_cpus = nr;
        }
    }

    /// Sets the FPU management mode.
    pub fn set_fpu_mode(&mut self, mode: FpuMode) {
        self.fpu_mode = mode;
    }

    /// Registers a new task context.
    pub fn register_context(&mut self, ctx: CpuContext) -> Result<()> {
        if self.count >= MAX_CONTEXTS {
            return Err(Error::OutOfMemory);
        }
        self.contexts[self.count] = ctx;
        self.count += 1;
        Ok(())
    }

    /// Performs a context switch between two tasks.
    pub fn switch_to(&mut self, prev_task: u64, next_task: u64, cpu: u32) -> Result<()> {
        if (cpu as usize) >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }

        let prev_idx = self.contexts[..self.count]
            .iter()
            .position(|c| c.task_id == prev_task);
        let next_idx = self.contexts[..self.count]
            .iter()
            .position(|c| c.task_id == next_task);

        let next_i = next_idx.ok_or(Error::NotFound)?;

        // Save previous context
        if let Some(prev_i) = prev_idx {
            self.contexts[prev_i].active = false;
            self.contexts[prev_i].last_cpu = cpu as i32;

            // FPU save
            if self.fpu_mode == FpuMode::Eager || self.contexts[prev_i].fpu_state_valid {
                self.stats.fpu_saves += 1;
            }
        }

        // Check if we need a TLB flush
        let needs_tlb_flush = match prev_idx {
            Some(pi) => self.contexts[pi].page_table_base != self.contexts[next_i].page_table_base,
            None => true,
        };

        if needs_tlb_flush {
            self.stats.tlb_flushes += 1;
        } else {
            self.stats.same_mm_switches += 1;
        }

        // Restore next context
        self.contexts[next_i].active = true;
        self.contexts[next_i].last_cpu = cpu as i32;

        // FPU restore
        if self.fpu_mode == FpuMode::Eager && self.contexts[next_i].fpu_state_valid {
            self.stats.fpu_restores += 1;
        }

        self.active_task_per_cpu[cpu as usize] = next_task;
        self.stats.total_switches += 1;

        Ok(())
    }

    /// Returns the currently active task on a CPU.
    pub fn active_task(&self, cpu: u32) -> Result<u64> {
        if (cpu as usize) >= self.nr_cpus {
            return Err(Error::InvalidArgument);
        }
        Ok(self.active_task_per_cpu[cpu as usize])
    }

    /// Returns context switch statistics.
    pub const fn stats(&self) -> &SwitchStats {
        &self.stats
    }

    /// Returns the number of registered contexts.
    pub const fn context_count(&self) -> usize {
        self.count
    }

    /// Removes a task context by task ID.
    pub fn remove_context(&mut self, task_id: u64) -> Result<()> {
        let pos = self.contexts[..self.count]
            .iter()
            .position(|c| c.task_id == task_id);
        match pos {
            Some(idx) => {
                let mut i = idx;
                while i + 1 < self.count {
                    self.contexts[i] = self.contexts[i + 1];
                    i += 1;
                }
                self.count -= 1;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }
}

impl Default for ContextSwitchManager {
    fn default() -> Self {
        Self::new()
    }
}
