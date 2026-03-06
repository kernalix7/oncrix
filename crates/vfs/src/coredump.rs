// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Core dump file generation.
//!
//! When a process terminates abnormally (signal delivery, assertion failure,
//! `abort(3)`), the kernel generates a core dump file.  This module produces
//! ELF-format core files (`ET_CORE`) compatible with GDB and other debuggers.
//!
//! A core file contains:
//! 1. An ELF header identifying it as `ET_CORE`.
//! 2. `PT_NOTE` segments carrying per-thread register state, signal info,
//!    and process metadata (`prstatus`, `prpsinfo`, `NT_FILE` maps).
//! 3. `PT_LOAD` segments covering the readable virtual-memory regions of
//!    the crashed process.
//!
//! # Linux reference
//! `fs/binfmt_elf.c` — `elf_core_dump()`, `fill_note()`, `fill_prstatus()`
//! `include/uapi/linux/elf.h` — ELF core note types
//!
//! # POSIX reference
//! POSIX.1-2024 `sigaction` — core dump signal behaviour

use oncrix_lib::{Error, Result};

// ── ELF core constants ────────────────────────────────────────────────────────

/// ELF magic number bytes.
pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
/// ELF class: 64-bit.
pub const ELFCLASS64: u8 = 2;
/// ELF data encoding: little-endian.
pub const ELFDATA2LSB: u8 = 1;
/// ELF version: current.
pub const EV_CURRENT: u8 = 1;
/// ELF OS/ABI: System V.
pub const ELFOSABI_NONE: u8 = 0;

/// ELF object type: core dump.
pub const ET_CORE: u16 = 4;
/// Machine type: x86-64.
pub const EM_X86_64: u16 = 62;

/// Program-header type: note segment.
pub const PT_NOTE: u32 = 4;
/// Program-header type: loadable segment.
pub const PT_LOAD: u32 = 1;

/// Segment flag: readable.
pub const PF_R: u32 = 4;
/// Segment flag: writable.
pub const PF_W: u32 = 2;
/// Segment flag: executable.
pub const PF_X: u32 = 1;

// ── ELF note types ────────────────────────────────────────────────────────────

/// Note type: `prstatus` (register state + signal info per thread).
pub const NT_PRSTATUS: u32 = 1;
/// Note type: `prpsinfo` (process name, arguments, state).
pub const NT_PRPSINFO: u32 = 3;
/// Note type: x86-64 floating-point state (`struct user_fpregs_struct`).
pub const NT_FPREGSET: u32 = 2;
/// Note type: file-backed memory mappings (`NT_FILE`).
pub const NT_FILE: u32 = 0x46494c45;
/// Note name for Linux-specific notes.
pub const NOTE_NAME_CORE: &[u8] = b"CORE\0";
/// Note name for Linux-specific notes.
pub const NOTE_NAME_LINUX: &[u8] = b"LINUX\0";

// ── Size constants ────────────────────────────────────────────────────────────

/// Number of general-purpose registers for x86-64 (`user_regs_struct`).
const GP_REG_COUNT: usize = 27;
/// Number of floating-point registers (128-bit XMM registers × 16 = 256 bytes, plus control).
const FP_REG_BYTES: usize = 512;
/// Maximum number of VMA regions we'll record.
const MAX_VMA_REGIONS: usize = 64;
/// Maximum number of threads.
const MAX_THREADS: usize = 32;
/// Maximum number of `PT_LOAD` program-header entries.
const MAX_LOAD_PHDRS: usize = MAX_VMA_REGIONS;
/// Maximum path length for a VMA file name.
const VMA_FILE_NAME_LEN: usize = 128;
/// Size of the process name in `prpsinfo`.
const PRPSINFO_FNAME_LEN: usize = 16;
/// Size of the process args in `prpsinfo`.
const PRPSINFO_ARGS_LEN: usize = 80;
/// Alignment of note entries (4 bytes per ELF spec).
const NOTE_ALIGN: usize = 4;

// ── Register state ────────────────────────────────────────────────────────────

/// x86-64 general-purpose register set (matches `struct user_regs_struct`).
#[derive(Debug, Clone, Copy, Default)]
pub struct GpRegs {
    /// Register values in kernel ABI order: r15, r14, r13, r12, rbp, rbx,
    /// r11, r10, r9, r8, rax, rcx, rdx, rsi, rdi, orig_rax, rip, cs,
    /// eflags, rsp, ss, fs_base, gs_base, ds, es, fs, gs.
    pub regs: [u64; GP_REG_COUNT],
}

impl GpRegs {
    /// Serialize to little-endian bytes.
    pub fn to_bytes(&self, out: &mut [u8]) -> usize {
        let total = GP_REG_COUNT * 8;
        if out.len() < total {
            return 0;
        }
        for (i, &r) in self.regs.iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&r.to_le_bytes());
        }
        total
    }
}

/// x86-64 floating-point / SSE register state.
#[derive(Debug, Clone)]
pub struct FpRegs {
    /// Raw register bytes (FXSAVE format).
    pub data: [u8; FP_REG_BYTES],
}

impl Default for FpRegs {
    fn default() -> Self {
        Self {
            data: [0u8; FP_REG_BYTES],
        }
    }
}

// ── Signal info ───────────────────────────────────────────────────────────────

/// Simplified signal information captured at crash time.
#[derive(Debug, Clone, Copy, Default)]
pub struct SigInfo {
    /// Signal number.
    pub signo: i32,
    /// Signal code (`si_code`).
    pub code: i32,
    /// Faulting address (for SIGSEGV, SIGBUS).
    pub fault_addr: u64,
}

// ── Per-thread state ──────────────────────────────────────────────────────────

/// Per-thread snapshot for inclusion in the core dump.
#[derive(Debug, Clone)]
pub struct ThreadInfo {
    /// Kernel thread ID.
    pub tid: u32,
    /// Process ID (tgid).
    pub pid: u32,
    /// General-purpose registers.
    pub gp_regs: GpRegs,
    /// Floating-point registers.
    pub fp_regs: FpRegs,
    /// Signal that caused the crash (main thread only; 0 for others).
    pub signal: SigInfo,
    /// Process priority.
    pub priority: i32,
    /// Thread nice value.
    pub nice: i32,
    /// Pending signal mask.
    pub sigpend: u64,
    /// Blocked signal mask.
    pub sighold: u64,
}

impl ThreadInfo {
    /// Create a minimal thread-info record.
    pub fn new(tid: u32, pid: u32) -> Self {
        Self {
            tid,
            pid,
            gp_regs: GpRegs::default(),
            fp_regs: FpRegs::default(),
            signal: SigInfo::default(),
            priority: 0,
            nice: 0,
            sigpend: 0,
            sighold: 0,
        }
    }
}

// ── VMA region descriptor ─────────────────────────────────────────────────────

/// A virtual-memory area (VMA) region to include in the core dump.
#[derive(Debug, Clone, Copy)]
pub struct VmaRegion {
    /// Region start virtual address.
    pub start: u64,
    /// Region end virtual address (exclusive).
    pub end: u64,
    /// Region protection flags (PF_R | PF_W | PF_X).
    pub prot: u32,
    /// Region flags (anonymous, file-backed, etc.).
    pub flags: u32,
    /// File offset for file-backed mappings.
    pub file_offset: u64,
    /// Device number for file-backed mappings.
    pub dev: u64,
    /// Inode number for file-backed mappings.
    pub ino: u64,
    /// File name for file-backed mappings.
    pub file_name: [u8; VMA_FILE_NAME_LEN],
    /// Length of the file name.
    pub file_name_len: usize,
    /// Whether this region should be dumped (false for huge special regions).
    pub dump: bool,
}

impl VmaRegion {
    /// Construct an anonymous VMA region.
    pub fn anonymous(start: u64, end: u64, prot: u32) -> Self {
        Self {
            start,
            end,
            prot,
            flags: 0,
            file_offset: 0,
            dev: 0,
            ino: 0,
            file_name: [0u8; VMA_FILE_NAME_LEN],
            file_name_len: 0,
            dump: true,
        }
    }

    /// Size in bytes.
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

// ── Process metadata ──────────────────────────────────────────────────────────

/// Process-level metadata for `prpsinfo`.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// Process group.
    pub pgrp: u32,
    /// Session ID.
    pub sid: u32,
    /// Real UID.
    pub uid: u32,
    /// Real GID.
    pub gid: u32,
    /// Process state character (R, S, D, Z, T, …).
    pub state: u8,
    /// Executable file name (at most `PRPSINFO_FNAME_LEN - 1` bytes).
    pub fname: [u8; PRPSINFO_FNAME_LEN],
    /// Length of `fname`.
    pub fname_len: usize,
    /// Process argument string.
    pub args: [u8; PRPSINFO_ARGS_LEN],
    /// Length of `args`.
    pub args_len: usize,
}

impl ProcessInfo {
    /// Create a minimal `ProcessInfo`.
    pub fn new(pid: u32, ppid: u32) -> Self {
        Self {
            pid,
            ppid,
            pgrp: 0,
            sid: 0,
            uid: 0,
            gid: 0,
            state: b'Z',
            fname: [0u8; PRPSINFO_FNAME_LEN],
            fname_len: 0,
            args: [0u8; PRPSINFO_ARGS_LEN],
            args_len: 0,
        }
    }

    /// Set the executable file name.
    pub fn set_fname(&mut self, name: &[u8]) {
        let len = name.len().min(PRPSINFO_FNAME_LEN - 1);
        self.fname[..len].copy_from_slice(&name[..len]);
        self.fname_len = len;
    }

    /// Set the argument string.
    pub fn set_args(&mut self, args: &[u8]) {
        let len = args.len().min(PRPSINFO_ARGS_LEN - 1);
        self.args[..len].copy_from_slice(&args[..len]);
        self.args_len = len;
    }
}

// ── Core dump builder ─────────────────────────────────────────────────────────

/// Core dump writer state.
///
/// Collects threads, VMA regions, and process metadata, then serialises
/// everything into an ELF core file.
pub struct CoreDumpBuilder {
    /// Per-thread snapshots.
    threads: [Option<ThreadInfo>; MAX_THREADS],
    thread_count: usize,
    /// VMA regions.
    vmas: [Option<VmaRegion>; MAX_VMA_REGIONS],
    vma_count: usize,
    /// Process metadata.
    proc_info: ProcessInfo,
}

impl CoreDumpBuilder {
    /// Create a new builder with default `ProcessInfo`.
    pub fn new(pid: u32, ppid: u32) -> Self {
        Self {
            threads: [const { None }; MAX_THREADS],
            thread_count: 0,
            vmas: [const { None }; MAX_VMA_REGIONS],
            vma_count: 0,
            proc_info: ProcessInfo::new(pid, ppid),
        }
    }

    /// Set process metadata.
    pub fn set_proc_info(&mut self, info: ProcessInfo) {
        self.proc_info = info;
    }

    /// Add a thread snapshot.  Returns `OutOfMemory` if the table is full.
    pub fn add_thread(&mut self, thread: ThreadInfo) -> Result<()> {
        if self.thread_count >= MAX_THREADS {
            return Err(Error::OutOfMemory);
        }
        self.threads[self.thread_count] = Some(thread);
        self.thread_count += 1;
        Ok(())
    }

    /// Add a VMA region.  Returns `OutOfMemory` if the table is full.
    pub fn add_vma(&mut self, vma: VmaRegion) -> Result<()> {
        if self.vma_count >= MAX_VMA_REGIONS {
            return Err(Error::OutOfMemory);
        }
        self.vmas[self.vma_count] = Some(vma);
        self.vma_count += 1;
        Ok(())
    }

    /// Compute the total size of the core file.
    ///
    /// Used to pre-allocate the output buffer or to write the file in chunks.
    pub fn compute_size(&self) -> u64 {
        // ELF header (64) + program headers + note segment + load segments
        let phdr_count = 1 + self.vma_count; // 1 PT_NOTE + N PT_LOAD
        let ehdr_size = 64u64;
        let phdrs_size = phdr_count as u64 * 56;
        let notes_size = self.compute_notes_size() as u64;
        let load_size: u64 = self
            .vmas
            .iter()
            .filter_map(|v| v.as_ref())
            .filter(|v| v.dump)
            .map(|v| v.size())
            .sum();
        ehdr_size + phdrs_size + notes_size + load_size
    }

    fn compute_notes_size(&self) -> usize {
        let mut size = 0usize;
        // prpsinfo note.
        size += self.note_size(NOTE_NAME_CORE.len(), 124);
        // prstatus + fpregset per thread.
        for _ in 0..self.thread_count {
            size += self.note_size(NOTE_NAME_CORE.len(), 148); // prstatus
            size += self.note_size(NOTE_NAME_CORE.len(), FP_REG_BYTES); // fpregset
        }
        // NT_FILE note.
        size += self.note_size(
            NOTE_NAME_CORE.len(),
            8 + self.vma_count * 24 + self.vma_fname_bytes(),
        );
        size
    }

    fn note_size(&self, name_len: usize, desc_len: usize) -> usize {
        // Note header (12) + name (aligned) + desc (aligned).
        12 + align_up(name_len, NOTE_ALIGN) + align_up(desc_len, NOTE_ALIGN)
    }

    fn vma_fname_bytes(&self) -> usize {
        self.vmas
            .iter()
            .filter_map(|v| v.as_ref())
            .map(|v| v.file_name_len + 1) // NUL terminated
            .sum()
    }

    /// Write the ELF core file into `out`.
    ///
    /// Returns the number of bytes written, or `OutOfMemory` if `out` is
    /// too small.
    pub fn write(&self, out: &mut [u8]) -> Result<usize> {
        let total = self.compute_size() as usize;
        if out.len() < total {
            return Err(Error::OutOfMemory);
        }

        let phdr_count = 1 + self.vma_count; // 1 PT_NOTE + N PT_LOAD
        let phdrs_offset: u64 = 64; // right after ELF header
        let phdrs_size = phdr_count as u64 * 56;
        let notes_offset: u64 = phdrs_offset + phdrs_size;
        let notes_size = self.compute_notes_size() as u64;
        let load_offset = notes_offset + notes_size;

        let mut pos = 0usize;

        // Write ELF header.
        pos += write_elf64_header(&mut out[pos..], phdr_count as u16, phdrs_offset);

        // Write PT_NOTE program header.
        pos += write_phdr(
            &mut out[pos..],
            PT_NOTE,
            0,
            notes_offset,
            notes_size,
            notes_size,
            PF_R,
            1,
        );

        // Write PT_LOAD program headers.
        let mut vma_file_offset = load_offset;
        for vma in self.vmas.iter().filter_map(|v| v.as_ref()) {
            let file_sz = if vma.dump { vma.size() } else { 0 };
            pos += write_phdr(
                &mut out[pos..],
                PT_LOAD,
                vma.prot,
                vma_file_offset,
                file_sz,
                vma.size(),
                vma.prot,
                0x1000,
            );
            vma_file_offset += file_sz;
        }

        // Write note segment.
        pos += self.write_notes(&mut out[pos..]);

        // Write PT_LOAD data (placeholder zeroes for actual pages).
        for vma in self.vmas.iter().filter_map(|v| v.as_ref()) {
            if vma.dump {
                let sz = vma.size() as usize;
                if pos + sz <= out.len() {
                    out[pos..pos + sz].fill(0);
                    pos += sz;
                }
            }
        }

        Ok(pos)
    }

    fn write_notes(&self, out: &mut [u8]) -> usize {
        let mut pos = 0usize;
        // prpsinfo.
        pos += write_note(
            &mut out[pos..],
            NT_PRPSINFO,
            NOTE_NAME_CORE,
            &self.build_prpsinfo(),
        );
        // prstatus + fpregset per thread.
        for thread in self.threads.iter().filter_map(|t| t.as_ref()) {
            pos += write_note(
                &mut out[pos..],
                NT_PRSTATUS,
                NOTE_NAME_CORE,
                &self.build_prstatus(thread),
            );
            pos += write_note(
                &mut out[pos..],
                NT_FPREGSET,
                NOTE_NAME_CORE,
                &thread.fp_regs.data,
            );
        }
        // NT_FILE.
        let nt_file = self.build_nt_file();
        pos += write_note(&mut out[pos..], NT_FILE, NOTE_NAME_CORE, &nt_file);
        pos
    }

    fn build_prpsinfo(&self) -> [u8; 124] {
        let mut buf = [0u8; 124];
        buf[0] = self.proc_info.state;
        // fname at offset 28, args at offset 44.
        let fname_len = self.proc_info.fname_len.min(15);
        buf[28..28 + fname_len].copy_from_slice(&self.proc_info.fname[..fname_len]);
        let args_len = self.proc_info.args_len.min(79);
        buf[44..44 + args_len].copy_from_slice(&self.proc_info.args[..args_len]);
        buf
    }

    fn build_prstatus(&self, thread: &ThreadInfo) -> [u8; 148] {
        let mut buf = [0u8; 148];
        // si_signo at offset 0.
        buf[0..4].copy_from_slice(&thread.signal.signo.to_le_bytes());
        // pid at offset 24.
        buf[24..28].copy_from_slice(&thread.pid.to_le_bytes());
        // tid at offset 28.
        buf[28..32].copy_from_slice(&thread.tid.to_le_bytes());
        // GP regs at offset 112.
        thread.gp_regs.to_bytes(&mut buf[112..]);
        buf
    }

    fn build_nt_file(&self) -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec::Vec::new();
        let count = self.vma_count as u64;
        let page_size: u64 = 0x1000;
        v.extend_from_slice(&count.to_le_bytes());
        v.extend_from_slice(&page_size.to_le_bytes());
        for vma in self.vmas.iter().filter_map(|v| v.as_ref()) {
            v.extend_from_slice(&vma.start.to_le_bytes());
            v.extend_from_slice(&vma.end.to_le_bytes());
            v.extend_from_slice(&vma.file_offset.to_le_bytes());
        }
        for vma in self.vmas.iter().filter_map(|v| v.as_ref()) {
            v.extend_from_slice(&vma.file_name[..vma.file_name_len]);
            v.push(0); // NUL terminator
        }
        v
    }
}

// ── ELF serialisation helpers ─────────────────────────────────────────────────

/// Write a 64-byte ELF64 header for an `ET_CORE` file.
fn write_elf64_header(out: &mut [u8], phdr_count: u16, phoff: u64) -> usize {
    if out.len() < 64 {
        return 0;
    }
    out[0..4].copy_from_slice(&ELF_MAGIC);
    out[4] = ELFCLASS64;
    out[5] = ELFDATA2LSB;
    out[6] = EV_CURRENT;
    out[7] = ELFOSABI_NONE;
    out[8..16].fill(0); // padding
    out[16..18].copy_from_slice(&ET_CORE.to_le_bytes());
    out[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
    out[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version = EV_CURRENT
    out[24..32].fill(0); // e_entry = 0 for core
    out[32..40].copy_from_slice(&phoff.to_le_bytes());
    out[40..48].fill(0); // e_shoff = 0
    out[48..52].fill(0); // e_flags = 0
    out[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    out[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    out[56..58].copy_from_slice(&phdr_count.to_le_bytes());
    out[58..60].copy_from_slice(&64u16.to_le_bytes()); // e_shentsize
    out[60..62].fill(0); // e_shnum = 0
    out[62..64].fill(0); // e_shstrndx = 0
    64
}

/// Write a 56-byte ELF64 program-header entry.
#[allow(clippy::too_many_arguments)]
fn write_phdr(
    out: &mut [u8],
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_prot: u32,
    p_align: u64,
) -> usize {
    if out.len() < 56 {
        return 0;
    }
    out[0..4].copy_from_slice(&p_type.to_le_bytes());
    out[4..8].copy_from_slice(&p_flags.to_le_bytes());
    out[8..16].copy_from_slice(&p_offset.to_le_bytes());
    out[16..24].fill(0); // p_vaddr = 0 for notes
    out[24..32].fill(0); // p_paddr = 0
    out[32..40].copy_from_slice(&p_filesz.to_le_bytes());
    out[40..48].copy_from_slice(&p_memsz.to_le_bytes());
    out[48..56].copy_from_slice(&p_align.to_le_bytes());
    // p_prot is encoded in p_flags; p_prot parameter used separately.
    let _ = p_prot;
    56
}

/// Write a single ELF note entry.
fn write_note(out: &mut [u8], note_type: u32, name: &[u8], desc: &[u8]) -> usize {
    let name_sz = name.len();
    let desc_sz = desc.len();
    let aligned_name = align_up(name_sz, NOTE_ALIGN);
    let aligned_desc = align_up(desc_sz, NOTE_ALIGN);
    let total = 12 + aligned_name + aligned_desc;
    if out.len() < total {
        return 0;
    }
    out[0..4].copy_from_slice(&(name_sz as u32).to_le_bytes());
    out[4..8].copy_from_slice(&(desc_sz as u32).to_le_bytes());
    out[8..12].copy_from_slice(&note_type.to_le_bytes());
    out[12..12 + name_sz].copy_from_slice(name);
    out[12 + name_sz..12 + aligned_name].fill(0);
    let desc_start = 12 + aligned_name;
    out[desc_start..desc_start + desc_sz].copy_from_slice(desc);
    out[desc_start + desc_sz..desc_start + aligned_desc].fill(0);
    total
}

/// Round `v` up to the next multiple of `align`.
const fn align_up(v: usize, align: usize) -> usize {
    (v + align - 1) & !(align - 1)
}

// ── `alloc` usage note ────────────────────────────────────────────────────────
// `build_nt_file` uses `alloc::vec::Vec` because the NT_FILE note has a
// variable-length layout that is awkward to express with fixed-size buffers.
// The crate already depends on `alloc` via other modules.
extern crate alloc;
