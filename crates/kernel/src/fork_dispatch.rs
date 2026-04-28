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
//! # Phase 13 scope
//!
//! * `sys_fork` — single-CPU fork backed by per-process [`UserAddressSpace`].
//!   The child receives a freshly allocated PT + 2 MiB backing region copied
//!   eagerly from the parent. PML4/PDPT/PD are still shared; only
//!   `PD_0_1G[2]` differs per process and is patched at context-switch time.
//!
//! * `sys_wait4` — blocking wait for a single direct child. Spins on
//!   `yield_now` until the child transitions to `Exited`. WNOHANG returns 0
//!   immediately. Writes the exit code (shifted left 8) to the user `*wstatus`
//!   pointer if non-null.
//!
//! * `sys_execve` — path-validated in-kernel exec. Only `"/bin/sh"` is
//!   recognized. A new [`UserAddressSpace`] is allocated, the embedded shell
//!   ELF is loaded into it, the calling thread's previous address space is
//!   released, and the SYSCALL epilogue is redirected to the new entry point.
//!
//! * `sys_exit` — marks the current process as `Exited` in the process table
//!   and transitions the current thread to the `Exited` scheduler state, then
//!   loops on `yield_now` so it is never rescheduled.
//!
//! [`UserAddressSpace`]: oncrix_mm::address_space::UserAddressSpace
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

/// Return the parent PID of the calling process.
///
/// POSIX.1-2024 `getppid(3p)` — always succeeds; returns 0 if the
/// calling process is not found in the table (should not happen).
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU context).
pub unsafe fn sys_getppid() -> i64 {
    // SAFETY: single-CPU SYSCALL context; no concurrent table access.
    unsafe {
        #[allow(static_mut_refs)]
        crate::current::current_pid()
            .and_then(|pid| PROCESS_TABLE.get(pid))
            .map(|entry| entry.parent.as_u64() as i64)
            .unwrap_or(0) // POSIX: parent is PID 1 (init) if not found
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
/// Phase 13: the child receives a freshly allocated [`UserAddressSpace`]
/// whose 2 MiB backing region is `memcpy`'d from the parent's. PML4/PDPT/PD
/// remain shared (only `PD_0_1G[2]` differs per process); the scheduler
/// glue patches that slot on every context switch. The eager copy
/// simplifies POSIX semantics — neither parent nor child can corrupt
/// the other's text/data even after `execve`.
///
/// [`UserAddressSpace`]: oncrix_mm::address_space::UserAddressSpace
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

    // Acquire the parent thread's priority + PID.
    // SAFETY: single-CPU SYSCALL context.
    let (parent_priority, parent_pid) = match crate::current::current_thread() {
        Some(t) => (t.priority(), t.pid()),
        None => return -11, // EAGAIN — no current thread
    };

    // Phase 13: build the child's UserAddressSpace by eager-copying
    // the parent's. Single-CPU + interrupts-off serves as the "freeze
    // parent during copy" guarantee. The PML4 CR3 stays the same
    // because every process shares PML4/PDPT/PD; only PD[2] differs.
    //
    // SAFETY: single-CPU SYSCALL context. The frame allocator and the
    // parent's UAS are accessed exclusively here.
    let child_uas = unsafe {
        // Re-borrow the parent thread to reach its UAS (we dropped the
        // earlier borrow above).
        let parent_uas = match crate::current::current_thread() {
            Some(t) => match &t.user_address_space {
                Some(uas) => uas,
                None => {
                    let _ = serial.write_str("[fork] parent has no UserAddressSpace\n");
                    return -11; // EAGAIN
                }
            },
            None => return -11,
        };
        let alloc = crate::frame_alloc::frame_alloc();
        match parent_uas.clone_for_fork(alloc) {
            Ok(uas) => uas,
            Err(_) => {
                let _ = serial.write_str("[fork] clone_for_fork OOM\n");
                return -12; // ENOMEM
            }
        }
    };

    // Allocate a child PID.
    let child_pid = alloc_pid();

    // Child CR3 stays the parent's PML4 root — only PD[2] differs and
    // that is handled at context-switch time via the child's own
    // `user_pt_phys()`.
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
            Err(_) => {
                // Roll back the child UAS to avoid leaking frames.
                let alloc = crate::frame_alloc::frame_alloc();
                child_uas.release(alloc);
                return -12; // ENOMEM
            }
        }
    };

    // Install the freshly cloned UAS on the child thread.
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        #[allow(static_mut_refs)]
        let sched = &mut crate::arch::x86_64::init::SCHEDULER;
        if let Some(child_thread) = sched.get_mut(child_tid) {
            child_thread.user_address_space = Some(child_uas);
        } else {
            // Should not happen — fork_current just inserted child_tid.
            let alloc = crate::frame_alloc::frame_alloc();
            child_uas.release(alloc);
            return -12; // ENOMEM
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

            // Reap the zombie: remove from process table, and free
            // the child thread's per-process UserAddressSpace +
            // remove the thread from the scheduler so the 96 MiB
            // frame pool isn't leaked one fork's worth (2 MiB) at a
            // time.
            //
            // SAFETY: single-CPU SYSCALL context.
            unsafe {
                #[allow(static_mut_refs)]
                PROCESS_TABLE.remove(zombie_pid);
            }
            // SAFETY: same as above; SCHEDULER is exclusively owned
            // here.
            let zombie_tid = unsafe {
                #[allow(static_mut_refs)]
                let sched = &mut crate::arch::x86_64::init::SCHEDULER;
                // Find the (single) thread whose owning PID matches
                // the zombie PID. The Phase 13 process model is
                // single-threaded-per-process, so there is at most
                // one such thread.
                let mut tid_opt: Option<oncrix_process::pid::Tid> = None;
                for slot in sched.threads_iter_mut() {
                    if let Some(t) = slot
                        && t.pid() == zombie_pid
                    {
                        // Take and release the UAS frames before the
                        // Thread is dropped.
                        if let Some(uas) = t.user_address_space.take() {
                            let alloc = crate::frame_alloc::frame_alloc();
                            uas.release(alloc);
                        }
                        tid_opt = Some(t.tid());
                        break;
                    }
                }
                tid_opt
            };
            if let Some(tid) = zombie_tid {
                // SAFETY: same single-CPU context.
                unsafe {
                    #[allow(static_mut_refs)]
                    let _ = crate::arch::x86_64::init::SCHEDULER.remove(tid);
                }
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
/// # Phase 13 implementation
///
/// Only `"/bin/sh"` is recognized. A fresh [`UserAddressSpace`] is
/// allocated via [`crate::frame_alloc`], the embedded `/bin/sh` ELF is
/// loaded into it, the calling thread's previous address space is
/// `release`d (so its frames return to the global pool), and the new
/// UAS is installed both on the thread and at `PD_0_1G[2]`. The
/// SYSCALL epilogue is redirected to the new entry point.
///
/// [`UserAddressSpace`]: oncrix_mm::address_space::UserAddressSpace
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

    // Only "/bin/sh" is recognized in Phase 13.
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

    // Build a fresh UserAddressSpace and load /bin/sh into it. The new
    // UAS is independent of the calling thread's old one — that is the
    // whole point of Phase 13: parent (init) keeps its own frames so
    // when wait4 resumes it after the child exits, init's text is
    // still mapped at 0x400000.
    //
    // SAFETY: Single-CPU SYSCALL dispatch path. The frame allocator
    // and the running thread's UAS are accessed exclusively here. The
    // new UAS is not yet visible to ring 3 (PD[2] still points at the
    // calling process's old PT) when `map_elf_segments` runs, so the
    // backing region is not aliased.
    let entry = unsafe {
        let alloc = crate::frame_alloc::frame_alloc();
        let mut new_uas = match oncrix_mm::address_space::UserAddressSpace::new_empty(
            alloc,
            crate::frame_alloc::phys_to_virt,
        ) {
            Ok(u) => u,
            Err(_) => {
                let _ = serial.write_str("[exec] new_empty OOM\n");
                return -12; // ENOMEM
            }
        };
        match new_uas.map_elf_segments(elf_bytes) {
            Ok(e) => {
                let _ = serial.write_str("[exec] loaded /bin/sh at entry=0x");
                write_hex(&mut serial, e);
                let _ = serial.write_str("\n");

                // Take the calling thread's old UAS and replace it with
                // the new one. The old UAS is then released so its
                // frames return to the global pool.
                let old_uas = match crate::current::current_thread_mut() {
                    Some(t) => t.user_address_space.replace(new_uas),
                    None => {
                        // No current thread? Drop the new UAS to avoid
                        // leaking frames.
                        new_uas.release(alloc);
                        return -22; // EINVAL
                    }
                };

                // Install the new PT at PD_0_1G[2] (the calling thread
                // now owns the new UAS, so look it up to get the phys
                // address). Then release the old UAS.
                if let Some(thread) = crate::current::current_thread() {
                    if let Some(uas) = thread.user_address_space.as_ref() {
                        crate::arch::x86_64::init::install_user_pt(uas.user_pt_phys().as_u64());
                    }
                }

                // Free the old address space's frames.
                if let Some(old) = old_uas {
                    old.release(alloc);
                }

                e
            }
            Err(_) => {
                let _ = serial.write_str("[exec] /bin/sh ELF parse/load failed\n");
                new_uas.release(alloc);
                return -8; // ENOEXEC
            }
        }
    };

    // Redirect the SYSCALL epilogue to the new program entry. The new
    // UAS exposes a fresh 2 MiB user region; the top of that region is
    // the canonical initial RSP for ring 3.
    set_saved_user_rip(entry);
    set_saved_user_rsp(crate::arch::x86_64::init::USER_INIT_RSP);
    set_saved_user_rflags(DEFAULT_USER_RFLAGS);

    // Return 0 — the SYSCALL epilogue will sysretq into sh's _start.
    0
}

/// Write a 64-bit value as `0x`-prefixed hex to the serial console.
fn write_hex(serial: &mut Uart16550, value: u64) {
    let mut buf = [0u8; 16];
    let mut n = value;
    for byte in buf.iter_mut().rev() {
        let digit = (n & 0xF) as u8;
        *byte = if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        };
        n >>= 4;
    }
    let start = buf.iter().position(|&b| b != b'0').unwrap_or(15);
    for &b in &buf[start..] {
        let _ = serial.write_byte(b);
    }
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
