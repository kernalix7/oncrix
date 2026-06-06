// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! User-space process execution.
//!
//! Provides the infrastructure to load an ELF binary and set up a
//! new process to execute it. This is the kernel-side implementation
//! of `execve`.

use crate::elf::{self, LoadSegment, pf};
use oncrix_lib::{Error, Result};
use oncrix_mm::addr::VirtAddr;
use oncrix_mm::address_space::{
    AddressSpace, Protection, RegionKind, USER_SPACE_END, USER_SPACE_START, VmRegion,
};
use oncrix_process::pid::{Pid, alloc_pid, alloc_tid};
use oncrix_process::signal::{Signal, SignalAction, SignalState};
use oncrix_process::thread::{Priority, Thread};

/// Default user stack size (64 KiB).
const USER_STACK_SIZE: u64 = 64 * 1024;

/// Default user stack top address (just below the canonical hole).
const USER_STACK_TOP: u64 = USER_SPACE_END - 0xFFF;

/// Maximum ELF binary size we can handle (16 MiB).
const MAX_ELF_SIZE: usize = 16 * 1024 * 1024;

/// Information needed to start a user-space process after exec.
#[derive(Debug, Clone, Copy)]
pub struct ExecInfo {
    /// Entry point virtual address.
    pub entry: u64,
    /// User stack pointer (top of stack, grows down).
    pub stack_top: u64,
    /// Process ID.
    pub pid: Pid,
    /// Whether the binary is position-independent.
    pub is_pie: bool,
    /// Number of memory regions set up.
    pub region_count: usize,
}

/// Prepare a user-space process from an ELF binary in memory.
///
/// This function:
/// 1. Validates the ELF header
/// 2. Extracts PT_LOAD segments
/// 3. Sets up the address space with appropriate regions
/// 4. Configures a user stack
///
/// The caller is responsible for actually mapping the pages and
/// jumping to user mode.
pub fn prepare_exec(elf_data: &[u8]) -> Result<(ExecInfo, AddressSpace)> {
    if elf_data.len() > MAX_ELF_SIZE {
        return Err(Error::InvalidArgument);
    }

    // Parse ELF header.
    let info = elf::parse_header(elf_data)?;

    // Reject an entry point outside the canonical user address range.
    if info.entry < USER_SPACE_START || info.entry > USER_SPACE_END {
        return Err(Error::InvalidArgument);
    }

    // Extract loadable segments.
    let (segments, seg_count) = elf::load_segments(elf_data)?;

    // Create a new address space (using a placeholder PML4 address;
    // in a real kernel, we'd allocate a page frame here).
    let mut address_space = AddressSpace::new(oncrix_mm::addr::PhysAddr::new(0));

    // Map each PT_LOAD segment as a VmRegion.
    let mut region_count = 0;
    for seg in &segments[..seg_count] {
        // Validate the segment before trusting any of its fields. These guard
        // the attacker path; valid binaries pass unchanged.
        if seg.file_size > seg.mem_size {
            return Err(Error::InvalidArgument);
        }
        let foff_end = seg
            .file_offset
            .checked_add(seg.file_size)
            .ok_or(Error::InvalidArgument)?;
        if foff_end > elf_data.len() as u64 {
            return Err(Error::InvalidArgument);
        }
        let aligned = page_align_up(seg.mem_size);
        let seg_end = seg
            .vaddr
            .checked_add(aligned)
            .ok_or(Error::InvalidArgument)?;
        if seg.vaddr < USER_SPACE_START || seg_end > USER_SPACE_END {
            return Err(Error::InvalidArgument);
        }

        let prot = segment_protection(seg);
        let kind = segment_kind(seg);

        let region = VmRegion {
            start: VirtAddr::new(seg.vaddr),
            size: aligned,
            prot,
            kind,
        };

        address_space.add_region(region)?;
        region_count += 1;
    }

    // Set up user stack region.
    let stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
    let stack_region = VmRegion {
        start: VirtAddr::new(stack_bottom),
        size: USER_STACK_SIZE,
        prot: Protection::RW,
        kind: RegionKind::Stack,
    };
    address_space.add_region(stack_region)?;
    region_count += 1;

    // Set the initial program break above the highest segment.
    let brk = compute_initial_brk(&segments[..seg_count]);
    address_space.set_brk(VirtAddr::new(brk));

    let pid = alloc_pid();

    let exec_info = ExecInfo {
        entry: info.entry,
        stack_top: USER_STACK_TOP,
        pid,
        is_pie: info.is_pie,
        region_count,
    };

    Ok((exec_info, address_space))
}

/// Create a `Thread` for the new process.
pub fn create_user_thread(pid: Pid, priority: Priority) -> Thread {
    let tid = alloc_tid();
    let thread = Thread::new(tid, pid, priority);
    // Thread::new already sets state to Ready.
    thread
}

/// Convert ELF segment flags to `Protection`.
fn segment_protection(seg: &LoadSegment) -> Protection {
    let mut prot = Protection(0);
    if seg.flags & pf::PF_R != 0 {
        prot = Protection(prot.0 | Protection::READ.0);
    }
    if seg.flags & pf::PF_W != 0 {
        prot = Protection(prot.0 | Protection::WRITE.0);
    }
    if seg.flags & pf::PF_X != 0 {
        prot = Protection(prot.0 | Protection::EXEC.0);
    }
    prot
}

/// Determine the region kind from segment flags.
fn segment_kind(seg: &LoadSegment) -> RegionKind {
    if seg.flags & pf::PF_X != 0 {
        RegionKind::Code
    } else {
        RegionKind::Data
    }
}

/// Compute the initial program break (heap start) from segments.
///
/// The break is placed at the first page boundary after the highest
/// loadable segment.
fn compute_initial_brk(segments: &[LoadSegment]) -> u64 {
    let mut highest = USER_SPACE_START;
    for seg in segments {
        let end = seg.vaddr.saturating_add(seg.mem_size);
        if end > highest {
            highest = end;
        }
    }
    page_align_up(highest)
}

/// Align a value up to the nearest page boundary.
///
/// Uses saturating arithmetic so a near-`u64::MAX` input saturates rather than
/// wrapping to a tiny value; callers reject the saturated result via their
/// segment-end bound checks.
fn page_align_up(val: u64) -> u64 {
    const PAGE_SIZE: u64 = 4096;
    val.saturating_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

// ── execve: process image replacement ──────────────────────────

/// Maximum number of arguments and environment variables.
const MAX_ARGC: usize = 128;

/// Maximum combined byte size of all argv + envp strings (including NUL
/// terminators) and their pointer arrays. The initial stack image must fit
/// inside the fixed [`USER_STACK_SIZE`] region with room left for the program
/// to run, so this is capped well below it. An attacker who supplies oversized
/// argument strings is rejected here rather than driving the computed stack
/// pointer below the mapped stack region (an out-of-bounds write).
const MAX_ARG_BYTES: u64 = USER_STACK_SIZE / 2;

/// Result of `do_execve` — contains everything needed to switch
/// to the new process image.
#[derive(Debug, Clone, Copy)]
pub struct ExecveResult {
    /// Entry point virtual address.
    pub entry: u64,
    /// Initial stack pointer (with argc/argv/envp laid out).
    pub stack_pointer: u64,
    /// Whether the binary is position-independent.
    pub is_pie: bool,
}

/// Perform the kernel-side `execve` operation.
///
/// Replaces the calling process's address space with a new ELF
/// binary. The process keeps its PID, parent, and open file
/// descriptors (except `O_CLOEXEC`).
///
/// # Arguments
///
/// - `pid`: PID of the calling process
/// - `elf_data`: the ELF binary contents (already read from VFS)
/// - `argv`: argument strings (kernel-side copies)
/// - `argc`: number of arguments
/// - `envp`: environment strings (kernel-side copies)
/// - `envc`: number of environment variables
///
/// # Returns
///
/// On success, returns `ExecveResult` with the new entry point
/// and stack pointer. The caller must update the thread's CPU
/// context to jump to user space at this address.
pub fn do_execve(
    pid: Pid,
    elf_data: &[u8],
    argv: &[&[u8]],
    envp: &[&[u8]],
) -> Result<(ExecveResult, AddressSpace)> {
    if elf_data.len() > MAX_ELF_SIZE {
        return Err(Error::InvalidArgument);
    }
    if argv.len() > MAX_ARGC || envp.len() > MAX_ARGC {
        return Err(Error::InvalidArgument);
    }

    // Bound the total argument/environment byte size *before* laying out the
    // stack. Without this an attacker can pass 128 multi-megabyte strings:
    // the per-array count check above passes, but the summed size drives the
    // computed stack pointer below the fixed 64 KiB stack region, turning the
    // subsequent argv/envp/string write into an out-of-bounds write.
    let mut arg_bytes: u64 = 0;
    for s in argv.iter().chain(envp.iter()) {
        arg_bytes = arg_bytes
            .checked_add(s.len() as u64)
            .and_then(|n| n.checked_add(1)) // NUL terminator
            .ok_or(Error::InvalidArgument)?;
    }
    if arg_bytes > MAX_ARG_BYTES {
        return Err(Error::InvalidArgument);
    }

    // Parse and validate the ELF binary.
    let elf_info = elf::parse_header(elf_data)?;

    // Reject an entry point outside the canonical user address range.
    if elf_info.entry < USER_SPACE_START || elf_info.entry > USER_SPACE_END {
        return Err(Error::InvalidArgument);
    }

    let (segments, seg_count) = elf::load_segments(elf_data)?;

    // Build a new address space (old one will be torn down by caller).
    let mut address_space = AddressSpace::new(oncrix_mm::addr::PhysAddr::new(0));

    // Map PT_LOAD segments.
    for seg in &segments[..seg_count] {
        // Validate the segment before trusting any of its fields. These guard
        // the attacker path; valid binaries pass unchanged.
        if seg.file_size > seg.mem_size {
            return Err(Error::InvalidArgument);
        }
        let foff_end = seg
            .file_offset
            .checked_add(seg.file_size)
            .ok_or(Error::InvalidArgument)?;
        if foff_end > elf_data.len() as u64 {
            return Err(Error::InvalidArgument);
        }
        let aligned = page_align_up(seg.mem_size);
        let seg_end = seg
            .vaddr
            .checked_add(aligned)
            .ok_or(Error::InvalidArgument)?;
        if seg.vaddr < USER_SPACE_START || seg_end > USER_SPACE_END {
            return Err(Error::InvalidArgument);
        }

        let prot = segment_protection(seg);
        let kind = segment_kind(seg);
        let region = VmRegion {
            start: VirtAddr::new(seg.vaddr),
            size: aligned,
            prot,
            kind,
        };
        address_space.add_region(region)?;
    }

    // Set up user stack.
    let stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
    let stack_region = VmRegion {
        start: VirtAddr::new(stack_bottom),
        size: USER_STACK_SIZE,
        prot: Protection::RW,
        kind: RegionKind::Stack,
    };
    address_space.add_region(stack_region)?;

    // Set initial program break.
    let brk = compute_initial_brk(&segments[..seg_count]);
    address_space.set_brk(VirtAddr::new(brk));

    // Compute the initial stack pointer with argc/argv/envp layout.
    // The stack grows down from USER_STACK_TOP. This is fallible: it fails
    // closed if the computed pointer would fall outside the mapped stack.
    let sp = compute_initial_stack(argv, envp)?;

    let result = ExecveResult {
        entry: elf_info.entry,
        stack_pointer: sp,
        is_pie: elf_info.is_pie,
    };

    // Suppress unused-variable warning — pid is used by the caller
    // to update the process table entry.
    let _ = pid;

    Ok((result, address_space))
}

/// Reset signal dispositions after execve (POSIX requirement).
///
/// - Signals set to `SIG_IGN` remain ignored.
/// - Signals set to a handler are reset to `SIG_DFL`.
/// - The signal mask is preserved (per POSIX).
/// - Pending signals are preserved.
pub fn reset_signals_on_exec(signals: &mut SignalState) {
    for sig_num in 1..=Signal::MAX {
        let sig = Signal(sig_num);
        let action = signals.get_action(sig);
        if let SignalAction::Handler(_) = action {
            // Reset caught signals to default. Ignore SIGKILL/SIGSTOP
            // errors since set_action rejects them (they're already
            // SIG_DFL anyway).
            let _ = signals.set_action(sig, SignalAction::Default);
        }
        // SIG_IGN stays as SIG_IGN per POSIX.
    }
}

/// Compute the initial stack pointer for execve.
///
/// The System V AMD64 ABI requires the stack to look like this
/// at process entry (`_start`):
///
/// ```text
/// (high address)
///     NULL            ← end of envp
///     envp[envc-1]
///     ...
///     envp[0]
///     NULL            ← end of argv
///     argv[argc-1]
///     ...
///     argv[0]
///     argc            ← RSP points here
/// (low address)
/// ```
///
/// This function computes the resulting SP value. The actual string
/// data and pointer arrays are written to the stack by the caller
/// after mapping the stack pages.
fn compute_initial_stack(argv: &[&[u8]], envp: &[&[u8]]) -> Result<u64> {
    let argc = argv.len();
    let envc = envp.len();

    // Calculate total string data size.
    let mut string_bytes: u64 = 0;
    for arg in argv {
        // Each string + null terminator.
        string_bytes = string_bytes.saturating_add(arg.len() as u64 + 1);
    }
    for env in envp {
        string_bytes = string_bytes.saturating_add(env.len() as u64 + 1);
    }

    // Pointer array: argc + argv pointers + NULL + envp pointers + NULL.
    let pointer_count = 1 + argc + 1 + envc + 1;
    let pointer_bytes = (pointer_count as u64).saturating_mul(8);

    let total = string_bytes.saturating_add(pointer_bytes);

    // Align down to 16-byte boundary (ABI requirement).
    let sp = USER_STACK_TOP.saturating_sub(total) & !0xF;

    // Fail closed: the computed stack pointer must land inside the mapped
    // stack region [stack_bottom, USER_STACK_TOP). A pointer below
    // stack_bottom means the argv/envp/string image does not fit and any
    // subsequent write would be out of bounds. `do_execve` already bounds
    // the total argument byte size, so valid callers never hit this; it is
    // defense in depth for any other caller of this helper.
    let stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
    if sp < stack_bottom {
        return Err(Error::InvalidArgument);
    }
    Ok(sp)
}
