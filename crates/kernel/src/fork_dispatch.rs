// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel-side implementations of `fork(2)`, `wait4(2)`, `execve(2)`, and `_exit(2)`.
//!
//! These syscalls require direct access to scheduler state, the process
//! table, and the saved SYSCALL register slots — all of which live inside
//! `oncrix_kernel`. They are therefore intercepted in
//! [`crate::arch::x86_64::syscall_entry::syscall_dispatch_wrapper`] rather
//! than delegated to the `oncrix_syscall` crate.
//!
//! # Phase 11 scope
//!
//! * `sys_fork` — cooperative single-CPU fork. Shares the boot PML4/PDPT/PD
//!   with the parent and only carries a distinct `user_pt_phys` pointer; the
//!   sched-glue patches `PD_0_1G[2]` on every context switch. No mm-subsystem
//!   frame allocator is wired yet — the child inherits the parent's physical
//!   PT rather than copying it. True CoW fork is a Phase 12 concern.
//!
//! * `sys_wait4` — blocking wait for a single direct child. Spins on
//!   `yield_now` until the child transitions to `Exited`. WNOHANG returns 0
//!   immediately. Writes the exit code (shifted left 8) to the user `*wstatus`
//!   pointer if non-null.
//!
//! * `sys_execve` — path-validated in-kernel exec. Only `"/bin/sh"` is
//!   recognized. The embedded shell ELF is fetched via `embedded_sh_elf()`,
//!   loaded into the static user load region via `load_sh_elf()`, and the
//!   SYSCALL epilogue is redirected to the new entry point.
//!
//! * `sys_exit` — marks the current process as `Exited` in the process table
//!   and transitions the current thread to the `Exited` scheduler state, then
//!   loops on `yield_now` so it is never rescheduled.
//!
//! # POSIX references
//!
//! POSIX.1-2024 `fork(3p)`, `wait(3p)`, `waitid(3p)`, `execve(3p)`, `_exit(3p)`.
//! See `.priv-storage/.TheOpenGroup/susv5-html/functions/`.

use oncrix_hal::arch::x86_64::uart::{COM1, Uart16550};
use oncrix_hal::serial::SerialPort;
use oncrix_process::pid::{Pid, alloc_pid};
use oncrix_process::process::Process;
use oncrix_process::table::{ExitStatus, ProcessEntry, ProcessTable};

use crate::arch::x86_64::clone::ForkSnapshot;
use crate::arch::x86_64::sched_glue::read_cr3;
use crate::arch::x86_64::syscall_entry::{
    saved_user_rflags, saved_user_rip, saved_user_rsp, set_saved_user_rflags, set_saved_user_rip,
    set_saved_user_rsp,
};

// ── POSIX WNOHANG option flag ────────────────────────────────────

/// `WNOHANG` — do not block if no child has changed state.
const WNOHANG: u64 = 1;

// ── RFLAGS constant ─────────────────────────────────────────────

/// Default user RFLAGS: reserved bit 1 + IF (interrupts enabled).
const DEFAULT_USER_RFLAGS: u64 = 0x202;

// ── Global process table ─────────────────────────────────────────

/// Global process table.
///
/// Managed exclusively by kernel-side fork/wait/exit paths. Accessed
/// with interrupts logically disabled (single-CPU SYSCALL context).
// SAFETY: Accessed only from the SYSCALL dispatch path where the
// single CPU is in ring 0. No concurrent mutation is possible on
// single-CPU builds.
static mut PROCESS_TABLE: ProcessTable = ProcessTable::new();

/// Insert a [`ProcessEntry`] into the global process table.
///
/// # Safety
///
/// Must be called only from the SYSCALL dispatch path (single-CPU,
/// interrupts effectively disabled).
pub unsafe fn register_process(entry: ProcessEntry) {
    // SAFETY: single-CPU SYSCALL context; no aliased access.
    unsafe {
        #[allow(static_mut_refs)]
        let _ = PROCESS_TABLE.insert(entry);
    }
}

/// Mark a process as exited with the given raw exit code.
///
/// # Safety
///
/// Same single-CPU SYSCALL context requirement.
pub unsafe fn exit_process(pid: Pid, code: i32) {
    // SAFETY: see module-level note.
    unsafe {
        #[allow(static_mut_refs)]
        if let Some(entry) = PROCESS_TABLE.get_mut(pid) {
            entry.process.exit();
            entry.exit_status = Some(ExitStatus::code(code));
        }
    }
}

// ── sys_fork ─────────────────────────────────────────────────────

/// Kernel handler for `SYS_FORK` (Linux number 57).
///
/// POSIX.1-2024 semantics:
/// - Parent: returns child PID (> 0) on success, -EAGAIN / -ENOMEM on failure.
/// - Child: returns 0 (delivered via `fork_trampoline` which zeroes RAX).
///
/// Phase 10c simplification: the child shares the parent's CR3 (PML4/PDPT/PD
/// are identical). The child carries its own `user_pt_phys` copied from the
/// parent's `Thread::user_pt_phys`. On every context switch `sched_glue`
/// patches `PD_0_1G[2]` — in Phase 10c both child and parent point at the
/// same physical PT page, so there is no actual address-space isolation.
/// True CoW requires mm-subsystem frame allocation and is deferred.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path with interrupts disabled.
pub unsafe fn sys_fork() -> i64 {
    let mut serial = Uart16550::new(COM1);
    let _ = serial.write_str("[fork] sys_fork called\n");

    // Snapshot parent's user register state from the SYSCALL entry stubs.
    let user_rip = saved_user_rip();
    let user_rsp = saved_user_rsp();
    let user_rflags = saved_user_rflags();

    // Acquire the parent thread's priority and user_pt_phys.
    // SAFETY: single-CPU SYSCALL context.
    let (parent_priority, parent_user_pt_phys, parent_pid) = match crate::current::current_thread()
    {
        Some(t) => (t.priority(), t.user_pt_phys, t.pid()),
        None => return -11, // EAGAIN — no current thread
    };

    // Allocate a child PID.
    let child_pid = alloc_pid();

    // Phase 10c: child shares the parent's PML4 CR3. The child's
    // user_pt_phys field is copied from the parent so the scheduler
    // can patch PD[2] appropriately when switching to the child.
    //
    // SAFETY: read_cr3 is a privileged but side-effect-free read.
    let child_cr3 = unsafe { read_cr3() };

    let snapshot = ForkSnapshot {
        user_rip,
        user_rsp,
        user_rflags,
        priority: parent_priority,
        child_cr3,
        child_pid,
    };

    // Build the child thread and register it with the scheduler.
    // SAFETY: single-CPU SYSCALL context, interrupts disabled.
    let child_tid = unsafe {
        match crate::current::fork_current(snapshot) {
            Ok(tid) => tid,
            Err(_) => return -12, // ENOMEM
        }
    };

    // Set the child's user_pt_phys to match the parent's so the
    // scheduler glue can patch PD_0_1G[2] on context switch.
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        let sched = &mut crate::arch::x86_64::init::SCHEDULER;
        if let Some(child_thread) = sched.get_mut(child_tid) {
            child_thread.user_pt_phys = parent_user_pt_phys;
        }
    }

    // Register child in the process table so wait4 can find it.
    let child_process = Process::new(child_pid);
    let child_entry = ProcessEntry::new(child_process, parent_pid);
    // SAFETY: single-CPU SYSCALL context.
    unsafe { register_process(child_entry) };

    let _ = serial.write_str("[fork] child created\n");

    // Return child PID to parent (child returns 0 via fork_trampoline).
    child_pid.as_u64() as i64
}

// ── sys_wait4 ────────────────────────────────────────────────────

/// Kernel handler for `SYS_WAIT4`.
///
/// POSIX.1-2024 `waitpid(3p)` semantics:
/// - `pid > 0` — wait for a specific child.
/// - `pid == -1` — wait for any child.
/// - `options & WNOHANG` — return 0 immediately if no child exited.
/// - On success: writes `(exit_code << 8)` to `*wstatus` if non-null,
///   removes child from process table, returns child PID.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn sys_wait4(pid_arg: u64, wstatus_ptr: u64, options: u64, _rusage: u64) -> i64 {
    let mut serial = Uart16550::new(COM1);

    // Determine the caller's PID (for child-of check).
    let caller_pid = match crate::current::current_thread() {
        Some(t) => t.pid(),
        None => return -10, // ECHILD — no current process
    };

    let target_pid: Option<Pid> = if pid_arg as i64 > 0 {
        Some(Pid::new(pid_arg))
    } else if pid_arg as i64 == -1 {
        None // any child
    } else {
        // Process groups etc. are not implemented; return EINVAL.
        return -22;
    };

    // Check that the caller actually has children.
    // SAFETY: single-CPU SYSCALL context.
    let has_children = unsafe {
        #[allow(static_mut_refs)]
        PROCESS_TABLE.children(caller_pid).next().is_some()
    };
    if !has_children {
        return -10; // ECHILD
    }

    loop {
        // Look for a zombie child matching the requested PID.
        let found = unsafe {
            #[allow(static_mut_refs)]
            find_zombie_child(&PROCESS_TABLE, caller_pid, target_pid)
        };

        if let Some((zombie_pid, exit_code)) = found {
            // Write wstatus to user space if pointer is non-null and valid.
            if wstatus_ptr != 0 && wstatus_ptr < 0xFFFF_8000_0000_0000 {
                // SAFETY: Phase 10c assumes cooperative userspace. The pointer
                // is non-null and below the kernel canonical half. Full
                // validation (page presence, alignment) is deferred.
                unsafe {
                    (wstatus_ptr as *mut i32).write_volatile(exit_code << 8);
                }
            }

            // Reap the zombie: remove from table.
            // SAFETY: single-CPU SYSCALL context.
            unsafe {
                #[allow(static_mut_refs)]
                PROCESS_TABLE.remove(zombie_pid);
            }

            let _ = serial.write_str("[wait4] reaped child\n");
            return zombie_pid.as_u64() as i64;
        }

        // WNOHANG: return 0 immediately if no zombie is available.
        if options & WNOHANG != 0 {
            return 0;
        }

        // Blocking path: yield the CPU and retry.
        // SAFETY: single-CPU, interrupts disabled context. yield_now
        // is documented to require interrupts-off.
        let switched = unsafe { crate::current::yield_now() };
        if !switched {
            // No other thread to run — spin briefly to avoid a busy loop
            // without actually sleeping (no timer infrastructure yet).
            // In practice this branch only occurs when the child hasn't
            // exited because nothing else can run it.
            return 0; // Treat as WNOHANG equivalent for now.
        }
    }
}

/// Find a zombie child of `parent` matching `target` (any if None).
///
/// Returns `(zombie_pid, raw_exit_code)` or `None`.
fn find_zombie_child(table: &ProcessTable, parent: Pid, target: Option<Pid>) -> Option<(Pid, i32)> {
    table.zombie_children(parent).find_map(|entry| {
        if let Some(tp) = target {
            if entry.pid() != tp {
                return None;
            }
        }
        let code = entry.exit_status.map(|s| s.raw()).unwrap_or(0);
        Some((entry.pid(), code))
    })
}

// ── sys_execve ───────────────────────────────────────────────────

/// Maximum pathname length accepted from user space.
const MAX_PATHNAME: usize = 256;

/// Kernel handler for `SYS_EXECVE`.
///
/// POSIX.1-2024 `execve(3p)` semantics:
/// - On success: does not return; the current process image is replaced.
///   The SYSCALL epilogue is redirected to the new program entry by
///   overwriting the saved user RIP / RSP / RFLAGS atomics.
/// - On failure: returns a negative errno; the caller continues normally.
///
/// # Phase 11 implementation
///
/// Only `"/bin/sh"` is recognized. The embedded ELF blob is fetched via
/// [`crate::arch::x86_64::init_embed::embedded_sh_elf`] and loaded into
/// the static user load region via
/// [`crate::arch::x86_64::init_embed::load_sh_elf`]. On success the
/// SYSCALL epilogue redirects to the new entry point.
///
/// # Phase 12 TODO
///
/// - True address-space isolation: allocate a fresh frame for the child
///   via the mm-subsystem rather than clobbering the shared static region.
/// - VFS path resolution for arbitrary binaries beyond `/bin/sh`.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path with interrupts effectively
/// disabled (single-CPU SYSCALL context).
pub unsafe fn sys_execve(pathname_ptr: u64, _argv: u64, _envp: u64) -> i64 {
    let mut serial = Uart16550::new(COM1);

    // Validate the pathname pointer.
    if pathname_ptr == 0 || pathname_ptr >= 0xFFFF_8000_0000_0000 {
        return -22; // EINVAL
    }

    // Copy the null-terminated pathname from user space.
    let path = match copy_user_string(pathname_ptr, MAX_PATHNAME) {
        Some(s) => s,
        None => return -22, // EINVAL — too long or non-ASCII
    };

    // Only "/bin/sh" is recognized in Phase 11.
    if path != b"/bin/sh" {
        return -2; // ENOENT
    }

    // Fetch the embedded shell ELF blob.
    let elf_bytes = match crate::arch::x86_64::init_embed::embedded_sh_elf() {
        Some(bytes) => bytes,
        None => {
            let _ =
                serial.write_str("[exec] /bin/sh ELF not embedded (build without embed-init?)\n");
            return -2; // ENOENT
        }
    };

    // Load the shell ELF segments into the static user load region,
    // overwriting the current process image (init).
    //
    // SAFETY: Single-CPU SYSCALL dispatch path. load_sh_elf requires
    // exclusive access to USER_LOAD_REGION and must not be called
    // concurrently — the interrupts-off SYSCALL context guarantees this.
    let entry = match unsafe { crate::arch::x86_64::init_embed::load_sh_elf(elf_bytes) } {
        Some(e) => e,
        None => {
            let _ = serial.write_str("[exec] /bin/sh ELF parse/load failed\n");
            return -8; // ENOEXEC
        }
    };

    // Redirect the SYSCALL epilogue to the new program entry.
    // USER_INIT_RSP is the top of the static 2 MiB user region — the same
    // stack address the init ELF started with, now reused for sh.
    set_saved_user_rip(entry);
    set_saved_user_rsp(crate::arch::x86_64::init_embed::user_init_rsp());
    set_saved_user_rflags(DEFAULT_USER_RFLAGS);

    // Flush the entire TLB before returning to user space. `load_sh_elf`
    // may have written new bytes at physical frames that the CPU had
    // cached as empty/zero-filled under the previous `init` mapping, and
    // without invalidating those cached translations the child's first
    // user-mode access to its .data / .rodata segment would #PF even
    // though the mapping is valid in the active page table.
    //
    // SAFETY: writing CR3 with its own current value is a privileged
    // but side-effect-free operation that invalidates all non-global
    // TLB entries. Runs in the single-CPU SYSCALL context with
    // interrupts disabled.
    unsafe {
        core::arch::asm!(
            "mov {tmp}, cr3",
            "mov cr3, {tmp}",
            tmp = out(reg) _,
            options(nostack, preserves_flags),
        );
    }

    // Return 0 — the SYSCALL epilogue will sysretq into sh's _start.
    0
}

// ── sys_exit ─────────────────────────────────────────────────────

/// Kernel handler for `SYS_EXIT` (Linux number 60) and
/// `SYS_EXIT_GROUP` (Linux number 231).
///
/// POSIX.1-2024 `_exit(3p)` semantics:
/// - Marks the current process as exited with `code`.
/// - Removes the current thread from the scheduler so it is never
///   rescheduled. Loops on `yield_now` as a safety backstop.
///
/// This function does not return to the SYSCALL epilogue in the normal
/// sense: the thread's state is set to `Exited` before we yield, so the
/// round-robin scanner will skip it on every future pass.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn sys_exit(code: u64) -> i64 {
    let mut serial = Uart16550::new(COM1);
    let exit_code = (code & 0xFF) as i32;

    let _ = serial.write_str("[exit] process exiting with code=");
    // Write decimal exit code to serial.
    write_exit_code(&mut serial, exit_code);
    let _ = serial.write_str("\n");

    // Mark the process as exited in the process table.
    // SAFETY: Single-CPU SYSCALL context.
    if let Some(pid) = crate::current::current_pid() {
        unsafe { exit_process(pid, exit_code) };
    }

    // Transition the current thread to Exited so the scheduler skips it.
    // SAFETY: Single-CPU SYSCALL context; no other code touches the scheduler.
    unsafe {
        #[allow(static_mut_refs)]
        let sched = &mut crate::arch::x86_64::init::SCHEDULER;
        if let Some(t) = sched.current_mut() {
            t.set_state(oncrix_process::thread::ThreadState::Exited);
        }
    }

    // Yield in a loop — the scheduler will skip Exited threads, so this
    // thread effectively never runs again. The loop satisfies the compiler
    // (callers have `-> i64` return, but we never actually reach the
    // return because yield_now eventually runs another thread, and when
    // (if) we are re-entered it is still Exited, so we loop forever).
    //
    // SAFETY: interrupts-off SYSCALL context; no scheduler borrow held.
    loop {
        unsafe {
            let _ = crate::current::yield_now();
        }
        // Spin to avoid a busy loop burning 100 % CPU when there are
        // no other threads. `pause` is the x86_64 spin-wait hint.
        // SAFETY: `pause` is a hint instruction with no side effects.
        unsafe { core::arch::asm!("pause", options(nomem, nostack)) };
    }
}

/// Write a decimal i32 to the serial console (no heap).
fn write_exit_code(serial: &mut Uart16550, mut n: i32) {
    if n < 0 {
        let _ = serial.write_byte(b'-');
        // Avoid overflow: i32::MIN.abs() panics in debug; use wrapping.
        n = n.wrapping_abs();
    }
    if n == 0 {
        let _ = serial.write_byte(b'0');
        return;
    }
    let mut buf = [0u8; 10];
    let mut i = 0usize;
    let mut v = n as u32;
    while v > 0 {
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        i += 1;
    }
    // Digits are stored in reverse order.
    while i > 0 {
        i -= 1;
        let _ = serial.write_byte(buf[i]);
    }
}

/// Copy a null-terminated ASCII string from user space.
///
/// Returns `None` if the string is longer than `max_len` bytes or
/// contains non-ASCII bytes. Returns the bytes (without the null) on
/// success.
///
/// # Safety (internal)
///
/// The caller must have validated that `ptr` is non-null and below
/// the kernel canonical boundary. Reading is done byte-by-byte with
/// `read_volatile` to respect MMIO-style access semantics and avoid
/// creating a slice over potentially unmapped pages.
fn copy_user_string(ptr: u64, max_len: usize) -> Option<&'static [u8]> {
    // SAFETY: static buffer for the copied string lives in BSS.
    static mut PATH_BUF: [u8; MAX_PATHNAME] = [0; MAX_PATHNAME];

    // SAFETY: single-CPU SYSCALL context; no aliased access to PATH_BUF.
    #[allow(static_mut_refs)]
    let buf = unsafe { &mut PATH_BUF };
    let base = ptr as *const u8;
    let mut i = 0usize;

    loop {
        if i >= max_len {
            return None; // Too long.
        }
        // SAFETY: ptr is user-space (caller checked); we read one byte
        // at a time with volatile to avoid compiler reordering.
        let byte = unsafe { base.add(i).read_volatile() };
        if byte == 0 {
            break;
        }
        if !byte.is_ascii() {
            return None; // Non-ASCII — reject for simplicity.
        }
        buf[i] = byte;
        i += 1;
    }

    // SAFETY: we just wrote `i` bytes from validated user pointer;
    // returning an &'static slice is safe because PATH_BUF is a
    // fixed static and we are the sole accessor.
    Some(unsafe { &PATH_BUF[..i] })
}
