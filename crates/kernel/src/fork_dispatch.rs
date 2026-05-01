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
//!   argv/envp are read from user space and laid out on the System V AMD64
//!   initial stack at user VA 0x5FF000.
//!
//! * `sys_exit` — marks the current process as `Exited` in the process table,
//!   raises SIGCHLD on the parent, transitions the current thread to the
//!   `Exited` scheduler state, then loops on `yield_now` so it is never
//!   rescheduled.
//!
//! * `sys_kill` — deliver a signal to a target process by PID.
//!   POSIX.1-2024 `kill(3p)` semantics.
//!
//! [`UserAddressSpace`]: oncrix_mm::address_space::UserAddressSpace
//!
//! # POSIX references
//!
//! POSIX.1-2024 `fork(3p)`, `wait(3p)`, `waitid(3p)`, `execve(3p)`, `_exit(3p)`,
//! `kill(3p)`. See `.priv-storage/.TheOpenGroup/susv5-html/functions/`.

use oncrix_hal::arch::x86_64::uart::{COM1, Uart16550};
use oncrix_hal::serial::SerialPort;
use oncrix_process::pid::{Pid, alloc_pid};
use oncrix_process::process::Process;
use oncrix_process::signal::Signal;
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

/// Maximum number of argv/envp pointers accepted from user space.
const MAX_ARGV: usize = 64;

/// Maximum bytes copied per argv/envp string.
const MAX_ARG_STR: usize = 256;

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
/// UAS is installed both on the thread and at `PD_0_1G[2]`. argv and
/// envp are read from user space and written to the System V AMD64
/// initial stack at the top 4 KiB of the user region (user VA 0x5FF000).
/// The SYSCALL epilogue is redirected to the new entry point with
/// RSP = 0x5FF000.
///
/// [`UserAddressSpace`]: oncrix_mm::address_space::UserAddressSpace
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path with interrupts effectively
/// disabled (single-CPU SYSCALL context).
pub unsafe fn sys_execve(pathname_ptr: u64, argv_ptr: u64, envp_ptr: u64) -> i64 {
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

    // Resolve `path` against the embedded binary set. Phase 23
    // recognises `/bin/{sh,echo,cat,true,false}` plus the matching
    // bare names (a primitive `$PATH=/bin` shortcut).
    let elf_bytes = match crate::arch::x86_64::init_embed::embedded_lookup(path) {
        Some(bytes) => bytes,
        None => {
            let _ = serial.write_str("[exec] path not in embedded set: ");
            for &b in path {
                let _ = serial.write_byte(b);
            }
            let _ = serial.write_str("\n");
            return -2; // ENOENT
        }
    };

    // Snapshot argv/envp from the CALLING process's address space
    // BEFORE the UAS swap below.  After the swap PD_0_1G[2] points at
    // the new (mostly-zeroed) backing region, and any read through
    // `argv_ptr` / `envp_ptr` would return garbage — they are user
    // VAs (e.g. 0x5FFxxx into sh's stack) that resolve to the wrong
    // physical frame post-swap.
    //
    // SAFETY: single-CPU SYSCALL context; the calling process's UAS
    // is still installed at this point so `read_volatile` through the
    // user VAs returns the actual argv/envp the caller built.
    static mut ARGV_STRS: [[u8; MAX_ARG_STR]; MAX_ARGV] = [[0u8; MAX_ARG_STR]; MAX_ARGV];
    static mut ARGV_LENS: [usize; MAX_ARGV] = [0usize; MAX_ARGV];
    static mut ENVP_STRS: [[u8; MAX_ARG_STR]; MAX_ARGV] = [[0u8; MAX_ARG_STR]; MAX_ARGV];
    static mut ENVP_LENS: [usize; MAX_ARGV] = [0usize; MAX_ARGV];
    let (argc, nenv) = unsafe {
        #[allow(static_mut_refs)]
        let a = collect_user_argv(argv_ptr, &mut ARGV_STRS, &mut ARGV_LENS);
        #[allow(static_mut_refs)]
        let n = collect_user_argv(envp_ptr, &mut ENVP_STRS, &mut ENVP_LENS);
        (a, n)
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
                let _ = serial.write_str("[exec] loaded ");
                for &b in path {
                    let _ = serial.write_byte(b);
                }
                let _ = serial.write_str(" at entry=0x");
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
                let _ = serial.write_str("[exec] ELF parse/load failed for ");
                for &b in path {
                    let _ = serial.write_byte(b);
                }
                let _ = serial.write_str("\n");
                new_uas.release(alloc);
                return -8; // ENOEXEC
            }
        }
    };

    // Build the System V AMD64 initial stack in the top 4 KiB of the user
    // region (backing slice offset USER_REGION_SIZE-4096..USER_REGION_SIZE,
    // user VA 0x5FF000..0x600000).
    //
    // Layout at user RSP = 0x5FF000 (low → high address):
    //   [rsp+0]:              argc (u64)
    //   [rsp+8]:              argv[0] user VA
    //   ...
    //   [rsp+8*(argc)]:       argv[argc-1] user VA
    //   [rsp+8*(argc+1)]:     NULL (u64)
    //   [rsp+8*(argc+2)]:     envp[0] user VA
    //   ...
    //                         NULL (u64)
    //                         AT_NULL auxv entry: {0, 0}
    //   string area growing up: argv strings, then envp strings
    //
    // SAFETY: We access the new UAS through the kernel's phys_to_virt
    // mapping. Single-CPU SYSCALL context ensures exclusive access.
    unsafe {
        // argv/envp strings already collected from the OLD UAS above
        // (before the swap). The static buffers persist between the
        // pre-swap collection and this stack-build phase; SYSCALL
        // dispatch is single-CPU so no aliasing.

        if let Some(thread) = crate::current::current_thread_mut() {
            if let Some(uas) = thread.user_address_space.as_mut() {
                // SAFETY: exclusive access to the new UAS backing region.
                let backing = uas.backing_slice_mut();
                let region_size = backing.len(); // USER_REGION_SIZE = 2 MiB

                // Install the per-process `rt_sigreturn` trampoline at
                // user VA 0x5FE000 (one page below the initial stack)
                // BEFORE taking the long-lived `stack` borrow below —
                // both writes target the same `backing` slice and the
                // borrow checker rejects two `&mut` regions of it being
                // live at once.
                let tramp_off = crate::arch::x86_64::init_embed::SIGRETURN_TRAMPOLINE_OFFSET;
                let tramp = &crate::arch::x86_64::init_embed::SIGRETURN_TRAMPOLINE_BYTES;
                if tramp_off + tramp.len() <= region_size {
                    backing[tramp_off..tramp_off + tramp.len()].copy_from_slice(tramp);
                }

                let stack_off = region_size - 4096;
                let stack = &mut backing[stack_off..];

                // Zero the 4 KiB stack window.
                for b in stack.iter_mut() {
                    *b = 0;
                }

                // User VA corresponding to stack[0].
                let stack_user_va: u64 = 0x5FF000;

                // Pointer table entries: 1(argc) + argc + 1(NULL) + nenv + 1(NULL) + 2(AT_NULL).
                let ptr_entries = 1usize + argc + 1 + nenv + 1 + 2;
                // String area starts after the pointer table.
                let mut str_off = ptr_entries * 8;

                // Write argc.
                let argc_bytes = (argc as u64).to_ne_bytes();
                stack[0..8].copy_from_slice(&argc_bytes);

                // Write argv pointers and strings.
                for i in 0..argc {
                    #[allow(static_mut_refs)]
                    let len = ARGV_LENS[i];
                    if str_off + len + 1 > 4096 {
                        break; // overflow guard
                    }
                    #[allow(static_mut_refs)]
                    stack[str_off..str_off + len].copy_from_slice(&ARGV_STRS[i][..len]);
                    stack[str_off + len] = 0;
                    let user_va = stack_user_va + str_off as u64;
                    let va_bytes = user_va.to_ne_bytes();
                    let slot = (1 + i) * 8;
                    stack[slot..slot + 8].copy_from_slice(&va_bytes);
                    str_off += len + 1;
                }
                // argv NULL at slot (1 + argc)*8 — already zero.

                // Write envp pointers and strings.
                let envp_base = (1 + argc + 1) * 8;
                for j in 0..nenv {
                    #[allow(static_mut_refs)]
                    let len = ENVP_LENS[j];
                    if str_off + len + 1 > 4096 {
                        break;
                    }
                    #[allow(static_mut_refs)]
                    stack[str_off..str_off + len].copy_from_slice(&ENVP_STRS[j][..len]);
                    stack[str_off + len] = 0;
                    let user_va = stack_user_va + str_off as u64;
                    let va_bytes = user_va.to_ne_bytes();
                    let slot = envp_base + j * 8;
                    stack[slot..slot + 8].copy_from_slice(&va_bytes);
                    str_off += len + 1;
                }
                // envp NULL and AT_NULL auxv are already zero.
            }
        }
    }

    // Redirect the SYSCALL epilogue to the new program entry.
    // RSP = 0x5FF000: argc at [rsp], argv at [rsp+8], envp at [rsp+8*(argc+2)].
    // 16-byte aligned (0x5FF000 % 16 == 0).
    set_saved_user_rip(entry);
    set_saved_user_rsp(0x5FF000);
    set_saved_user_rflags(DEFAULT_USER_RFLAGS);

    // Return 0 — the SYSCALL epilogue will sysretq into sh's _start.
    0
}

/// Copy up to `MAX_ARGV` char* entries from a user-space argv/envp array.
///
/// `ptr_array` is the user VA of a NULL-terminated array of `char *`.
/// Each pointed-to string is copied (≤ `MAX_ARG_STR` bytes) into
/// `strs[i][..]` and its length (without null) into `lens[i]`.
/// Returns the number of entries collected.
///
/// # Safety
///
/// Called from single-CPU SYSCALL dispatch context. `ptr_array` must be
/// a user-space address (< 0xFFFF_8000_0000_0000) or 0 (treated as empty).
unsafe fn collect_user_argv(
    ptr_array: u64,
    strs: &mut [[u8; MAX_ARG_STR]; MAX_ARGV],
    lens: &mut [usize; MAX_ARGV],
) -> usize {
    if ptr_array == 0 || ptr_array >= 0xFFFF_8000_0000_0000 {
        return 0;
    }
    let mut count = 0usize;
    let base = ptr_array as *const u64;
    while count < MAX_ARGV {
        // SAFETY: reading one char* from the user-space array.
        let str_ptr = unsafe { base.add(count).read_volatile() };
        if str_ptr == 0 {
            break; // NULL terminator
        }
        if str_ptr >= 0xFFFF_8000_0000_0000 {
            break; // invalid pointer
        }
        let s = str_ptr as *const u8;
        let mut i = 0usize;
        while i < MAX_ARG_STR {
            // SAFETY: reading one byte from user space string.
            let byte = unsafe { s.add(i).read_volatile() };
            if byte == 0 {
                break;
            }
            strs[count][i] = byte;
            i += 1;
        }
        lens[count] = i;
        count += 1;
    }
    count
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

// ── sys_kill ─────────────────────────────────────────────────────

/// Kernel handler for `SYS_KILL` (Linux number 62).
///
/// POSIX.1-2024 `kill(3p)` semantics (subset):
/// - `pid > 0` — send signal to the specific process.
/// - `pid == 0` or `pid < 0` — process groups are not implemented;
///   returns -ESRCH (-3).
/// - `sig == 0` — existence check: returns 0 if the process exists,
///   -ESRCH otherwise. Does NOT raise a signal.
/// - `sig > 64` — returns -EINVAL (-22).
///
/// Signal state is recorded in the process table entry (not the thread).
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn sys_kill(pid_arg: u64, sig_arg: u64) -> i64 {
    // Validate signal number. Accept 0..=64; actual raise only for 1..=32.
    if sig_arg > 64 {
        return -22; // EINVAL
    }

    // Only positive PIDs supported; process groups deferred.
    let pid_signed = pid_arg as i64;
    if pid_signed <= 0 {
        return -3; // ESRCH
    }

    let target_pid = Pid::new(pid_arg);

    // SAFETY: single-CPU SYSCALL context; exclusive access to PROCESS_TABLE.
    unsafe {
        #[allow(static_mut_refs)]
        let entry = PROCESS_TABLE.get_mut(target_pid);
        match entry {
            None => -3, // ESRCH — no such process
            Some(e) => {
                if sig_arg == 0 {
                    // Existence check only.
                    0
                } else {
                    e.signals.pending.raise(Signal(sig_arg as u8));
                    0
                }
            }
        }
    }
}

// ── sys_exit ─────────────────────────────────────────────────────

/// Kernel handler for `SYS_EXIT` (Linux number 60) and
/// `SYS_EXIT_GROUP` (Linux number 231).
///
/// POSIX.1-2024 `_exit(3p)` semantics:
/// - Marks the current process as exited with `code`.
/// - Raises SIGCHLD on the parent process.
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

        // Raise SIGCHLD on the parent process so it can wake from wait4.
        // SAFETY: single-CPU SYSCALL context; exclusive access to PROCESS_TABLE.
        unsafe {
            #[allow(static_mut_refs)]
            if let Some(entry) = PROCESS_TABLE.get(pid) {
                let parent_pid = entry.parent;
                #[allow(static_mut_refs)]
                if let Some(parent_entry) = PROCESS_TABLE.get_mut(parent_pid) {
                    parent_entry.signals.pending.raise(Signal::SIGCHLD);
                }
            }
        }
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

// ── sys_chdir / sys_getcwd ────────────────────────────────────────

/// Kernel handler for `SYS_CHDIR` (Linux number 80).
///
/// POSIX.1-2024 `chdir(3p)` semantics:
/// - Resolves `path_ptr` (absolute or relative-to-cwd) against the VFS.
/// - Verifies the target is a directory.
/// - Updates the calling thread's `cwd` field.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU context).
pub unsafe fn sys_chdir(path_ptr: u64) -> i64 {
    if path_ptr == 0 || path_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }

    // Copy path from user space.
    static mut CHDIR_BUF: [u8; 256] = [0u8; 256];
    // SAFETY: single-CPU SYSCALL context; exclusive access to CHDIR_BUF.
    #[allow(static_mut_refs)]
    let path_bytes: &[u8] = unsafe {
        let buf = &mut CHDIR_BUF;
        let base = path_ptr as *const u8;
        let mut i = 0usize;
        loop {
            if i >= 255 {
                return -36; // ENAMETOOLONG
            }
            let byte = base.add(i).read_volatile();
            if byte == 0 {
                break;
            }
            buf[i] = byte;
            i += 1;
        }
        &buf[..i]
    };

    if path_bytes.is_empty() {
        return -2; // ENOENT
    }

    // Resolve to absolute path.
    static mut ABS_BUF: [u8; 256] = [0u8; 256];
    // SAFETY: single-CPU SYSCALL context.
    #[allow(static_mut_refs)]
    let abs_path: &[u8] = unsafe {
        if path_bytes[0] == b'/' {
            // Already absolute — copy as-is.
            let len = path_bytes.len().min(255);
            ABS_BUF[..len].copy_from_slice(&path_bytes[..len]);
            &ABS_BUF[..len]
        } else {
            // Relative — prepend cwd.
            let cwd = crate::current::current_thread()
                .map(|t| {
                    let s = t.cwd();
                    let l = s.len();
                    (s.as_ptr(), l)
                })
                .unwrap_or((b"/".as_ptr(), 1));
            let cwd_slice = core::slice::from_raw_parts(cwd.0, cwd.1);
            // Copy cwd.
            let copy_cwd = cwd_slice.len().min(255);
            ABS_BUF[..copy_cwd].copy_from_slice(&cwd_slice[..copy_cwd]);
            let mut out_len = copy_cwd;
            // Append '/' separator if cwd doesn't end with '/'.
            if out_len < 255 && (out_len == 0 || ABS_BUF[out_len - 1] != b'/') {
                ABS_BUF[out_len] = b'/';
                out_len += 1;
            }
            // Append path.
            let copy_path = path_bytes.len().min(255 - out_len);
            ABS_BUF[out_len..out_len + copy_path].copy_from_slice(&path_bytes[..copy_path]);
            out_len += copy_path;
            if out_len > 255 {
                return -36; // ENAMETOOLONG
            }
            &ABS_BUF[..out_len]
        }
    };

    // Verify target exists and is a directory.
    let check = crate::state::with_global(|s| {
        match s.vfs.lookup_path(abs_path) {
            Ok(inode) => {
                if inode.file_type == oncrix_vfs::inode::FileType::Directory {
                    Ok(())
                } else {
                    Err(-20i64) // ENOTDIR
                }
            }
            Err(oncrix_lib::Error::NotFound) => Err(-2i64), // ENOENT
            Err(_) => Err(-22i64),                          // EINVAL
        }
    });

    match check {
        Some(Ok(())) => {}
        Some(Err(e)) => return e,
        None => return -5, // EIO
    }

    // Normalise trailing slash away (keep exactly one '/' for root).
    let norm_len = {
        let mut l = abs_path.len();
        while l > 1 && abs_path[l - 1] == b'/' {
            l -= 1;
        }
        l
    };

    // Write into the current thread's cwd.
    // SAFETY: single-CPU SYSCALL context.
    unsafe {
        if let Some(t) = crate::current::current_thread_mut() {
            t.set_cwd(&abs_path[..norm_len]);
        }
    }

    0
}

/// Kernel handler for `SYS_GETCWD` (Linux number 79).
///
/// POSIX.1-2024 `getcwd(3p)` semantics:
/// - Copies the current working directory path (null-terminated) into
///   the user buffer `buf_ptr` of size `size`.
/// - Returns the number of bytes written (including the null) on success.
/// - Returns `-ERANGE` if the buffer is too small.
/// - Returns `-EFAULT` if the buffer pointer is invalid.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU context).
pub unsafe fn sys_getcwd(buf_ptr: u64, size: u64) -> i64 {
    if buf_ptr == 0 || buf_ptr >= 0xFFFF_8000_0000_0000 {
        return -14; // EFAULT
    }
    let size = size as usize;
    if size == 0 {
        return -22; // EINVAL
    }

    let (cwd_ptr, cwd_len) = crate::current::current_thread()
        .map(|t| {
            let s = t.cwd();
            (s.as_ptr(), s.len())
        })
        .unwrap_or((b"/".as_ptr(), 1));

    // Need cwd_len + 1 for null terminator.
    if cwd_len + 1 > size {
        return -34; // ERANGE
    }

    // Copy cwd + null terminator to user buffer.
    // SAFETY: buf_ptr validated above; cwd_len is within 255.
    unsafe {
        let dst = buf_ptr as *mut u8;
        core::ptr::copy_nonoverlapping(cwd_ptr, dst, cwd_len);
        dst.add(cwd_len).write(0);
    }

    (cwd_len + 1) as i64
}

// ── Crate-private accessor for the global process table ─────────

/// Crate-internal mutable accessor for the global process table.
///
/// Lets sibling kernel modules (e.g. [`crate::signal_dispatch`]) read
/// and mutate per-process state — pending signals, exit status — that
/// only the fork/wait/exit machinery has historically touched. Keeps
/// the static itself private so all uses funnel through one auditable
/// entry point.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path on the single CPU
/// with interrupts effectively disabled. No two callers may hold the
/// returned `&mut` simultaneously, and the borrow must be dropped
/// before any other code path that reaches the table (notably
/// [`sys_exit`], [`sys_kill`], [`sys_fork`], [`sys_wait4`]).
pub(crate) unsafe fn process_table_mut() -> &'static mut ProcessTable {
    // SAFETY: caller upholds the single-borrower invariant documented
    // above; PROCESS_TABLE has 'static lifetime.
    unsafe {
        #[allow(static_mut_refs)]
        &mut PROCESS_TABLE
    }
}
