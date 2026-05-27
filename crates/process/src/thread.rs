// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Thread representation and state management.

use crate::context::{CpuContext, Cr3Frame};
use crate::fd_table::KernelFdTable;
use crate::kstack::KernelStack;
use crate::pid::{Pid, Tid};
use oncrix_lib::Result;
use oncrix_mm::address_space::UserAddressSpace;

/// Thread execution state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    /// Ready to be scheduled.
    Ready,
    /// Currently running on a CPU.
    Running,
    /// Blocked waiting for an event (IPC, timer, etc.).
    Blocked,
    /// Thread has exited and is awaiting cleanup.
    Exited,
}

/// POSIX scheduling policy (`SCHED_*`).
///
/// Values match the conventional Linux ABI so the syscall layer can
/// pass them through unchanged: `SCHED_OTHER = 0`, `SCHED_FIFO = 1`,
/// `SCHED_RR = 2`. ONCRIX currently records the policy per thread but
/// its credit/aging picker behaves identically across policies; the
/// stored value lets a future real-time picker honour `FIFO`/`RR`
/// without an ABI change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(i32)]
pub enum SchedPolicy {
    /// Standard time-sharing policy (the default).
    #[default]
    Other = 0,
    /// First-in-first-out real-time policy.
    Fifo = 1,
    /// Round-robin real-time policy.
    RoundRobin = 2,
}

impl SchedPolicy {
    /// Convert a raw `SCHED_*` integer to a [`SchedPolicy`].
    ///
    /// Returns `None` for unrecognised values so the caller can map it
    /// to `EINVAL`.
    pub const fn from_raw(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::Other),
            1 => Some(Self::Fifo),
            2 => Some(Self::RoundRobin),
            _ => None,
        }
    }

    /// Return the raw `SCHED_*` integer for this policy.
    pub const fn as_raw(self) -> i32 {
        self as i32
    }
}

/// Thread priority level (0 = highest, 255 = lowest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Priority(u8);

impl Priority {
    /// Highest priority (real-time / kernel threads).
    pub const HIGHEST: Self = Self(0);
    /// Normal user-space priority.
    pub const NORMAL: Self = Self(128);
    /// Lowest priority (idle).
    pub const IDLE: Self = Self(255);

    /// Create a priority from a raw value.
    pub const fn new(level: u8) -> Self {
        Self(level)
    }

    /// Return the raw priority value.
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// Convert a POSIX nice value (`[-20, 19]`) to a kernel [`Priority`].
    ///
    /// POSIX nice runs from `-20` (most favourable, highest priority) to
    /// `+19` (least favourable, lowest priority). The kernel priority axis
    /// is inverted: `0` is highest, `255` is lowest. We map the 40-step
    /// nice range linearly onto `[0, 255]`, keeping nice `0` near
    /// [`Priority::NORMAL`].
    ///
    /// Mapping: `level = (nice + 20) * 255 / 39`, with `nice` clamped to
    /// `[-20, 19]` first. So `-20 → 0` (HIGHEST), `+19 → 255` (IDLE), and
    /// `0 → 130` (just below NORMAL).
    pub const fn from_nice(nice: i32) -> Self {
        let clamped = if nice < -20 {
            -20
        } else if nice > 19 {
            19
        } else {
            nice
        };
        // (clamped + 20) is in [0, 39]; scale to [0, 255].
        let level = ((clamped + 20) * 255 / 39) as u8;
        Self(level)
    }

    /// Scheduling weight derived from this priority.
    ///
    /// Higher-priority threads (lower raw level) get a larger weight so
    /// the priority-aware picker grants them credit faster. The mapping
    /// is the linear inverse of the raw level: `weight = 256 - level`,
    /// giving `HIGHEST (0) → 256`, `NORMAL (128) → 128`, and
    /// `IDLE (255) → 1`. The minimum weight is `1`, never `0`, so even
    /// the lowest-priority thread keeps accruing credit and cannot
    /// starve (see the scheduler's aging loop).
    pub const fn weight(self) -> u32 {
        256 - self.0 as u32
    }

    /// Convert this kernel [`Priority`] back to a POSIX nice value.
    ///
    /// Inverse of [`from_nice`](Self::from_nice): `nice = level * 39 / 255
    /// - 20`, yielding a value in `[-20, 19]`. The round-trip is not exact
    /// for every raw level (the 256→40 quantisation is lossy), but it is
    /// stable for any nice the kernel itself produced via `from_nice`.
    pub const fn to_nice(self) -> i32 {
        (self.0 as i32) * 39 / 255 - 20
    }
}

/// A kernel thread.
///
/// Each thread belongs to exactly one process and maintains its own
/// execution context (register state, stack pointer, etc.). Phase
/// 10c adds:
///
/// * `cpu_context` — the saved register file consumed/produced by the
///   scheduler's context-switch routine.
/// * `kernel_stack` — a private 16 KiB kernel stack that is installed
///   into `TSS.RSP0` whenever this thread is picked to run, so that
///   ring 3 → 0 traps land on the thread's own stack (fork-safe).
///
/// Both fields are `Option` because the idle thread and the initial
/// bootstrap thread run on the static boot stack and don't need a
/// heap-allocated private one.
#[derive(Debug)]
pub struct Thread {
    /// Thread identifier.
    tid: Tid,
    /// Owning process.
    pid: Pid,
    /// Current execution state.
    state: ThreadState,
    /// Scheduling priority.
    priority: Priority,
    /// POSIX scheduling policy (`SCHED_*`). Stored per thread; the
    /// credit/aging picker is policy-agnostic today, so this only
    /// affects what `sched_getscheduler(2)` reports back.
    policy: SchedPolicy,
    /// Accumulated scheduling credit for the priority-aware picker.
    ///
    /// Ready threads gain credit equal to their [`Priority::weight`] on
    /// each pick pass; the thread with the most credit is chosen and has
    /// its credit reset. Because every weight is `>= 1`, low-priority
    /// threads keep accruing and are eventually selected — this is the
    /// anti-starvation (aging) mechanism. Saturating arithmetic bounds
    /// the value so a long-blocked low-priority thread cannot overflow.
    sched_credit: u32,
    /// CPU ticks charged to user-mode execution for this thread.
    ///
    /// Incremented once per PIT timer tick while this thread is the
    /// current (running) thread. ONCRIX does not yet distinguish the
    /// trap-from-ring-3 vs trap-from-ring-0 case at the timer, so *all*
    /// charged ticks land in this user bucket; `stime` stays `0` until a
    /// finer split is added. Consumed by `times(2)` / `getrusage(2)`.
    utime_ticks: u64,
    /// CPU ticks charged to kernel-mode execution for this thread.
    ///
    /// Reserved for a future user/system split; currently always `0`
    /// (see [`utime_ticks`](Self::utime_ticks)).
    stime_ticks: u64,
    /// Stack pointer (legacy field, still used by the kthread path).
    stack_pointer: u64,
    /// Thread-local storage base address (FS base on x86_64).
    tls_base: u64,
    /// Saved register context for scheduler-driven switches.
    cpu_context: CpuContext,
    /// Private 16 KiB kernel stack (None for static bootstrap threads).
    kernel_stack: Option<KernelStack>,
    /// Cached top-of-stack for `TSS.RSP0` installation (avoids re-deref
    /// on every switch). `0` means "use the global ring-0 stack".
    kernel_stack_top: u64,
    /// Per-process user-mode address space.
    ///
    /// Phase 13 gives every process its own [`UserAddressSpace`] so
    /// that `fork`/`execve` can diverge from the parent without
    /// clobbering shared static buffers (which previously triggered an
    /// `#UD` after `wait4` because the parent's text was overwritten by
    /// the child's `execve`).
    ///
    /// `None` for kernel threads that share the boot mapping.
    /// The scheduler glue patches `PD_0_1G[2]` on every context switch
    /// so each user thread sees its own private page table; on `execve`
    /// the kernel replaces this field with a freshly built address
    /// space and releases the old one.
    ///
    /// `UserAddressSpace` is `Send`-but-not-`Sync` (heap-allocated
    /// frames pointed at by raw indices); the single-CPU SYSCALL
    /// invariant covers all access patterns we currently need.
    pub user_address_space: Option<UserAddressSpace>,
    /// Saved user-mode `RIP` for an in-flight SYSCALL on this thread.
    ///
    /// The arch SYSCALL stub mirrors `RCX` (post-syscall user RIP) into
    /// a global atomic on entry, but that atomic is shared across all
    /// threads. When the calling thread blocks (e.g. `wait4` yielding)
    /// and another thread runs its own SYSCALL, the atomic is
    /// overwritten — so when the original caller resumes and SYSRETs,
    /// it would jump to the wrong RIP. The scheduler therefore
    /// snapshots the three SYSCALL registers into these per-thread
    /// fields on yield and restores them on resume.
    pub saved_user_rip: u64,
    /// Saved user-mode `RSP` mirror — see [`saved_user_rip`](Self::saved_user_rip).
    pub saved_user_rsp: u64,
    /// Saved user-mode `RFLAGS` mirror — see [`saved_user_rip`](Self::saved_user_rip).
    pub saved_user_rflags: u64,
    /// Saved interrupt-return frame for preemptive scheduling
    /// (Phase 20 prep).
    ///
    /// `None` until the thread has been preempted at least once.
    /// `Some([rip, cs, rflags, rsp, ss, scratch[0..6]])` carries the
    /// eleven `u64`s a future naked timer ISR will spill on preemption
    /// and reload before issuing `iretq` to resume the thread.
    ///
    /// Stored as a raw `[u64; 11]` (rather than the typed `IretFrame`)
    /// because the typed wrapper lives in `oncrix-kernel` and a process
    /// → kernel dependency would close the cycle `kernel → process →
    /// kernel`. The kernel-side helpers
    /// `oncrix_kernel::arch::x86_64::iret_frame::IretFrame::{from_raw,
    /// into_raw}` round-trip the buffer at zero cost. Slot layout
    /// matches `IretFrame::SLOTS`: `rip, cs, rflags, rsp, ss,
    /// saved[0..6]`.
    ///
    /// Phase 20 only adds the storage; the activation step (rewriting
    /// `timer_handler` to use it) ships in a later commit so the new
    /// preemption datapath can be QEMU-verified in isolation.
    pub saved_irq_frame_raw: Option<[u64; 11]>,
    /// Current working directory path bytes (no heap; POSIX §2.7).
    ///
    /// Initialised to `b"/"` (root). Inherited unchanged across `fork`
    /// (child gets a copy of parent's cwd). NOT reset on `execve` per
    /// POSIX.1-2024.  Updated by `chdir(2)`.
    pub cwd: [u8; 256],
    /// Byte length of the valid prefix in `cwd` (excludes the trailing
    /// null that some helpers write for C-string use).
    pub cwd_len: u8,
    /// Per-thread open file descriptor table.
    ///
    /// POSIX.1-2024: each thread (process) owns an independent copy of
    /// the fd table. `fork(2)` produces a deep copy with pipe refcounts
    /// bumped for each inherited pipe fd. `execve(2)` clears non-`O_CLOEXEC`
    /// fds (deferred; O_CLOEXEC support ships in a later batch).
    pub fd_table: KernelFdTable,
}

// SAFETY: `UserAddressSpace` itself is `Send` (raw `PhysAddr`s plus a
// fn-pointer). The whole [`Thread`] is moved between scheduler slots
// during a switch, so we make the wrapper `Send` explicitly.
unsafe impl Send for Thread {}

impl Thread {
    /// Create a new thread in the Ready state.
    ///
    /// The thread has no kernel stack and an empty CPU context; call
    /// [`attach_kernel_stack`](Self::attach_kernel_stack) and
    /// [`set_cpu_context`](Self::set_cpu_context) before scheduling.
    pub const fn new(tid: Tid, pid: Pid, priority: Priority) -> Self {
        let mut cwd = [0u8; 256];
        cwd[0] = b'/';
        Self {
            tid,
            pid,
            state: ThreadState::Ready,
            priority,
            policy: SchedPolicy::Other,
            sched_credit: 0,
            utime_ticks: 0,
            stime_ticks: 0,
            stack_pointer: 0,
            tls_base: 0,
            cpu_context: CpuContext::empty(),
            kernel_stack: None,
            kernel_stack_top: 0,
            user_address_space: None,
            saved_user_rip: 0,
            saved_user_rsp: 0,
            saved_user_rflags: 0,
            saved_irq_frame_raw: None,
            cwd,
            cwd_len: 1,
            fd_table: KernelFdTable::new(),
        }
    }

    /// Physical address of this thread's per-process user-mode page
    /// table (the PT installed at `PD_0_1G[2]` covering VMA
    /// `0x400000..0x600000`).
    ///
    /// Returns `None` for kernel threads or any thread without an
    /// installed [`UserAddressSpace`]. Used by the scheduler glue to
    /// patch `PD_0_1G[2]` on every context switch, mirroring the legacy
    /// `user_pt_phys` field this method replaces.
    pub fn user_pt_phys(&self) -> Option<u64> {
        self.user_address_space
            .as_ref()
            .map(|uas| uas.user_pt_phys().as_u64())
    }

    /// Physical address of this thread's per-process anonymous-mmap
    /// page table, if any (the PT installed at `PD_0_1G[3]` covering
    /// VMA `0x600000..0x800000`).
    ///
    /// Returns `None` when the thread has no [`UserAddressSpace`] or
    /// has not yet called `mmap`. Used by the scheduler glue so each
    /// process's mmap pages are correctly switched in alongside the
    /// text/stack PT at slot 2.
    pub fn user_mmap_pt_phys(&self) -> Option<u64> {
        self.user_address_space
            .as_ref()
            .and_then(|uas| uas.mmap_pt_phys())
            .map(|p| p.as_u64())
    }

    /// Return the thread ID.
    pub const fn tid(&self) -> Tid {
        self.tid
    }

    /// Return the owning process ID.
    pub const fn pid(&self) -> Pid {
        self.pid
    }

    /// Return the current thread state.
    pub const fn state(&self) -> ThreadState {
        self.state
    }

    /// Return the scheduling priority.
    pub const fn priority(&self) -> Priority {
        self.priority
    }

    /// Set the scheduling priority.
    pub fn set_priority(&mut self, priority: Priority) {
        self.priority = priority;
    }

    /// Return the scheduling policy (`SCHED_*`).
    pub const fn policy(&self) -> SchedPolicy {
        self.policy
    }

    /// Set the scheduling policy (`SCHED_*`).
    pub fn set_policy(&mut self, policy: SchedPolicy) {
        self.policy = policy;
    }

    /// Return the user-mode CPU ticks charged to this thread.
    pub const fn utime_ticks(&self) -> u64 {
        self.utime_ticks
    }

    /// Return the kernel-mode CPU ticks charged to this thread.
    ///
    /// Always `0` today (coarse accounting charges everything to
    /// [`utime_ticks`](Self::utime_ticks)).
    pub const fn stime_ticks(&self) -> u64 {
        self.stime_ticks
    }

    /// Charge one PIT tick of CPU time to this thread (user bucket).
    ///
    /// Called from the timer interrupt for the currently running thread.
    /// Uses saturating arithmetic so a long-lived thread cannot overflow
    /// the counter.
    pub fn charge_tick(&mut self) {
        self.utime_ticks = self.utime_ticks.saturating_add(1);
    }

    /// Return the accumulated scheduling credit (priority-aware picker).
    pub const fn sched_credit(&self) -> u32 {
        self.sched_credit
    }

    /// Add `amount` to the scheduling credit (saturating).
    ///
    /// Called by the scheduler's aging pass on every Ready thread that
    /// was *not* picked, so waiting threads gradually rise to the top.
    pub fn add_sched_credit(&mut self, amount: u32) {
        self.sched_credit = self.sched_credit.saturating_add(amount);
    }

    /// Reset the scheduling credit to zero.
    ///
    /// Called when a thread is picked to run, so it must re-earn its
    /// way to the front against the others' accumulated credit.
    pub fn reset_sched_credit(&mut self) {
        self.sched_credit = 0;
    }

    /// Set the thread state.
    pub fn set_state(&mut self, state: ThreadState) {
        self.state = state;
    }

    /// Set the saved stack pointer (legacy).
    pub fn set_stack_pointer(&mut self, sp: u64) {
        self.stack_pointer = sp;
    }

    /// Get the saved stack pointer (legacy).
    pub const fn stack_pointer(&self) -> u64 {
        self.stack_pointer
    }

    /// Set the TLS base address.
    pub fn set_tls_base(&mut self, addr: u64) {
        self.tls_base = addr;
    }

    /// Get the TLS base address.
    pub const fn tls_base(&self) -> u64 {
        self.tls_base
    }

    /// Return a reference to the saved CPU context.
    pub const fn cpu_context(&self) -> &CpuContext {
        &self.cpu_context
    }

    /// Return a mutable reference to the saved CPU context.
    pub fn cpu_context_mut(&mut self) -> &mut CpuContext {
        &mut self.cpu_context
    }

    /// Replace the saved CPU context wholesale.
    pub fn set_cpu_context(&mut self, ctx: CpuContext) {
        self.cpu_context = ctx;
    }

    /// Attach a freshly allocated 16 KiB kernel stack to this thread.
    ///
    /// This also caches the stack top for fast `TSS.RSP0` lookups on
    /// context switch. Replaces any previously attached stack.
    pub fn attach_kernel_stack(&mut self, stack: KernelStack) {
        self.kernel_stack_top = stack.top();
        self.kernel_stack = Some(stack);
    }

    /// Allocate and attach a kernel stack in one call.
    ///
    /// Returns `Err(OutOfMemory)` if the kernel heap is exhausted.
    pub fn ensure_kernel_stack(&mut self) -> Result<()> {
        if self.kernel_stack.is_none() {
            let stack = KernelStack::allocate()?;
            self.attach_kernel_stack(stack);
        }
        Ok(())
    }

    /// Return the top of this thread's kernel stack, or `0` if the
    /// thread runs on the global bootstrap stack.
    pub const fn kernel_stack_top(&self) -> u64 {
        self.kernel_stack_top
    }

    /// Return a mutable reference to the kernel stack, if any.
    ///
    /// Used by arch-specific clone code to pre-seed the child's
    /// `iretq` frame.
    pub fn kernel_stack_mut(&mut self) -> Option<&mut KernelStack> {
        self.kernel_stack.as_mut()
    }

    /// Set only the address-space root (`CR3` on x86_64).
    ///
    /// Invoked after the memory-management crate clones the parent's
    /// page tables and returns a `Cr3Frame` for the child.
    pub fn set_address_space(&mut self, cr3: Cr3Frame) {
        self.cpu_context.cr3 = cr3;
    }

    /// Return the thread's address-space root.
    pub const fn address_space(&self) -> Cr3Frame {
        self.cpu_context.cr3
    }

    /// Return the current working directory as a byte slice.
    pub fn cwd(&self) -> &[u8] {
        &self.cwd[..self.cwd_len as usize]
    }

    /// Set the current working directory from a byte slice (max 255 bytes).
    ///
    /// Silently truncates paths longer than 255 bytes.
    pub fn set_cwd(&mut self, path: &[u8]) {
        let len = path.len().min(255);
        self.cwd[..len].copy_from_slice(&path[..len]);
        self.cwd_len = len as u8;
    }
}
