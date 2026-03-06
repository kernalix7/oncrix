// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Core dump generation for crashed processes.
//!
//! Produces ELF core files containing register state, memory mappings,
//! and auxiliary information for post-mortem debugging with tools like
//! GDB.
//!
//! # ELF Core File Layout
//!
//! ```text
//! +-------------------+
//! | ELF Header        |  (64 bytes)
//! +-------------------+
//! | PT_NOTE segment   |  (prstatus, prpsinfo, auxv)
//! +-------------------+
//! | PT_LOAD segments  |  (memory regions)
//! +-------------------+
//! ```
//!
//! Reference: ELF specification, Linux `core(5)` man page.

use oncrix_lib::{Error, Result};

use crate::pid::Pid;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// ELF magic bytes.
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// ELF class: 64-bit.
const ELFCLASS64: u8 = 2;

/// ELF data: little-endian.
const ELFDATA2LSB: u8 = 1;

/// ELF version: current.
const EV_CURRENT: u8 = 1;

/// ELF OS/ABI: System V.
const ELFOSABI_NONE: u8 = 0;

/// ELF type: core file.
const ET_CORE: u16 = 4;

/// ELF machine: x86_64.
const EM_X86_64: u16 = 62;

/// Program header type: loadable segment.
const PT_LOAD: u32 = 1;

/// Program header type: note segment.
const PT_NOTE: u32 = 4;

/// ELF header size for 64-bit.
const ELF64_EHDR_SIZE: usize = 64;

/// Program header entry size for 64-bit.
const ELF64_PHDR_SIZE: usize = 56;

/// Note type: prstatus (process status with registers).
const NT_PRSTATUS: u32 = 1;

/// Note type: prpsinfo (process information).
const NT_PRPSINFO: u32 = 3;

/// Note type: auxiliary vector.
const _NT_AUXV: u32 = 6;

/// Maximum memory regions in a core dump.
const MAX_CORE_REGIONS: usize = 32;

/// Maximum core dump size (16 MiB).
const MAX_CORE_SIZE: usize = 16 * 1024 * 1024;

/// Core file name (ONCRIX\0 padded to 8 bytes).
const _CORE_NAME: [u8; 8] = [b'O', b'N', b'C', b'R', b'I', b'X', 0, 0];

/// Name used in ELF notes ("CORE\0" padded to 8).
const NOTE_NAME: [u8; 8] = [b'C', b'O', b'R', b'E', 0, 0, 0, 0];

/// Length of "CORE\0" including null terminator.
const NOTE_NAME_LEN: usize = 5;

// ---------------------------------------------------------------------------
// Register State
// ---------------------------------------------------------------------------

/// x86_64 register state saved at crash time.
///
/// Layout matches the Linux `struct user_regs_struct` for
/// compatibility with GDB.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct CoreRegs {
    /// R15 register.
    pub r15: u64,
    /// R14 register.
    pub r14: u64,
    /// R13 register.
    pub r13: u64,
    /// R12 register.
    pub r12: u64,
    /// RBP (base pointer).
    pub rbp: u64,
    /// RBX register.
    pub rbx: u64,
    /// R11 register.
    pub r11: u64,
    /// R10 register.
    pub r10: u64,
    /// R9 register.
    pub r9: u64,
    /// R8 register.
    pub r8: u64,
    /// RAX register.
    pub rax: u64,
    /// RCX register.
    pub rcx: u64,
    /// RDX register.
    pub rdx: u64,
    /// RSI register.
    pub rsi: u64,
    /// RDI register.
    pub rdi: u64,
    /// Original RAX (syscall number).
    pub orig_rax: u64,
    /// RIP (instruction pointer).
    pub rip: u64,
    /// CS segment.
    pub cs: u64,
    /// RFLAGS.
    pub eflags: u64,
    /// RSP (stack pointer).
    pub rsp: u64,
    /// SS segment.
    pub ss: u64,
    /// FS base.
    pub fs_base: u64,
    /// GS base.
    pub gs_base: u64,
    /// DS segment.
    pub ds: u64,
    /// ES segment.
    pub es: u64,
    /// FS segment.
    pub fs: u64,
    /// GS segment.
    pub gs: u64,
}

// ---------------------------------------------------------------------------
// ELF Prstatus (NT_PRSTATUS)
// ---------------------------------------------------------------------------

/// Signal information embedded in prstatus.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct ElfSigInfo {
    /// Signal number.
    pub si_signo: i32,
    /// Extra code.
    pub si_code: i32,
    /// Errno value.
    pub si_errno: i32,
}

/// ELF prstatus note data.
///
/// Contains signal info, PID, and register state at crash time.
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct Prstatus {
    /// Signal information.
    pub sig_info: ElfSigInfo,
    /// Current signal number.
    pub cur_sig: u16,
    /// Padding.
    pub _pad0: u16,
    /// Padding.
    pub _pad1: u32,
    /// Pending signal mask.
    pub sig_pend: u64,
    /// Held (blocked) signal mask.
    pub sig_hold: u64,
    /// Process ID.
    pub pid: i32,
    /// Parent PID.
    pub ppid: i32,
    /// Process group ID.
    pub pgrp: i32,
    /// Session ID.
    pub sid: i32,
    /// User time (seconds).
    pub utime_sec: u64,
    /// User time (microseconds).
    pub utime_usec: u64,
    /// System time (seconds).
    pub stime_sec: u64,
    /// System time (microseconds).
    pub stime_usec: u64,
    /// Children user time (seconds).
    pub cutime_sec: u64,
    /// Children user time (microseconds).
    pub cutime_usec: u64,
    /// Children system time (seconds).
    pub cstime_sec: u64,
    /// Children system time (microseconds).
    pub cstime_usec: u64,
    /// General-purpose registers.
    pub regs: CoreRegs,
    /// FPU valid flag.
    pub fpvalid: i32,
    /// Padding to align.
    pub _pad2: i32,
}

// ---------------------------------------------------------------------------
// ELF Prpsinfo (NT_PRPSINFO)
// ---------------------------------------------------------------------------

/// ELF prpsinfo note data.
///
/// Contains process name and command line for identification.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct Prpsinfo {
    /// Process state character.
    pub state: u8,
    /// Process name (first character).
    pub sname: u8,
    /// Zombie flag.
    pub zomb: u8,
    /// Nice value.
    pub nice: u8,
    /// Flags.
    pub flag: u64,
    /// Real UID.
    pub uid: u32,
    /// Real GID.
    pub gid: u32,
    /// PID.
    pub pid: i32,
    /// Parent PID.
    pub ppid: i32,
    /// Process group ID.
    pub pgrp: i32,
    /// Session ID.
    pub sid: i32,
    /// Filename (16 bytes, null-terminated).
    pub fname: [u8; 16],
    /// Command line arguments (80 bytes, null-terminated).
    pub psargs: [u8; 80],
}

#[allow(clippy::derivable_impls)]
impl Default for Prpsinfo {
    fn default() -> Self {
        Self {
            state: 0,
            sname: 0,
            zomb: 0,
            nice: 0,
            flag: 0,
            uid: 0,
            gid: 0,
            pid: 0,
            ppid: 0,
            pgrp: 0,
            sid: 0,
            fname: [0; 16],
            psargs: [0; 80],
        }
    }
}

// ---------------------------------------------------------------------------
// Memory Region for Core Dump
// ---------------------------------------------------------------------------

/// A memory region to include in the core dump.
#[derive(Debug, Clone, Copy, Default)]
pub struct CoreRegion {
    /// Virtual address start.
    pub vaddr: u64,
    /// Region size in bytes.
    pub size: u64,
    /// ELF permission flags (PF_R=4, PF_W=2, PF_X=1).
    pub flags: u32,
    /// File offset where data will be placed.
    pub file_offset: u64,
}

// ---------------------------------------------------------------------------
// Core Dump Builder
// ---------------------------------------------------------------------------

/// Describes the crash context for core dump generation.
pub struct CrashInfo {
    /// PID of the crashed process.
    pub pid: Pid,
    /// Parent PID.
    pub ppid: Pid,
    /// Signal that caused the crash.
    pub signal: u8,
    /// Register state at crash.
    pub regs: CoreRegs,
    /// Process name (null-terminated).
    pub name: [u8; 16],
    /// Command line (null-terminated).
    pub cmdline: [u8; 80],
    /// UID.
    pub uid: u32,
    /// GID.
    pub gid: u32,
}

impl CrashInfo {
    /// Create a new crash info with the given PID and signal.
    pub fn new(pid: Pid, signal: u8) -> Self {
        Self {
            pid,
            ppid: Pid::new(0),
            signal,
            regs: CoreRegs::default(),
            name: [0; 16],
            cmdline: [0; 80],
            uid: 0,
            gid: 0,
        }
    }

    /// Set the process name.
    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(15);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name[len] = 0;
    }
}

/// Core dump builder.
///
/// Collects memory regions and crash information, then serializes
/// to an ELF core file format.
pub struct CoreDumpBuilder {
    /// Crash information.
    pub crash: CrashInfo,
    /// Memory regions to include.
    regions: [CoreRegion; MAX_CORE_REGIONS],
    /// Number of regions.
    region_count: usize,
}

impl CoreDumpBuilder {
    /// Create a new builder with the given crash info.
    pub fn new(crash: CrashInfo) -> Self {
        Self {
            crash,
            regions: [CoreRegion::default(); MAX_CORE_REGIONS],
            region_count: 0,
        }
    }

    /// Add a memory region to the core dump.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the maximum number of
    /// regions has been reached.
    pub fn add_region(&mut self, vaddr: u64, size: u64, flags: u32) -> Result<()> {
        if self.region_count >= MAX_CORE_REGIONS {
            return Err(Error::OutOfMemory);
        }
        self.regions[self.region_count] = CoreRegion {
            vaddr,
            size,
            flags,
            file_offset: 0, // computed during serialize
        };
        self.region_count += 1;
        Ok(())
    }

    /// Compute the total size of the core file.
    pub fn compute_size(&self) -> usize {
        let note_size = self.note_segment_size();
        // 1 PT_NOTE + N PT_LOAD segments
        let phdr_count = 1 + self.region_count;
        let header_size = ELF64_EHDR_SIZE + phdr_count * ELF64_PHDR_SIZE;
        let data_size: u64 = self.regions[..self.region_count]
            .iter()
            .map(|r| r.size)
            .sum();
        header_size + note_size + data_size as usize
    }

    /// Serialize the core dump into the provided buffer.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OutOfMemory`] if the buffer is too small or
    /// the core file exceeds [`MAX_CORE_SIZE`].
    pub fn serialize(&mut self, buf: &mut [u8]) -> Result<usize> {
        let total = self.compute_size();
        if total > buf.len() || total > MAX_CORE_SIZE {
            return Err(Error::OutOfMemory);
        }

        let phdr_count = 1 + self.region_count;
        let note_size = self.note_segment_size();
        let phdr_offset = ELF64_EHDR_SIZE;
        let note_offset = phdr_offset + phdr_count * ELF64_PHDR_SIZE;
        let mut data_offset = note_offset + note_size;

        // Compute file offsets for each region
        for region in &mut self.regions[..self.region_count] {
            region.file_offset = data_offset as u64;
            data_offset += region.size as usize;
        }

        let mut pos = 0;

        // === ELF Header ===
        pos += self.write_elf_header(buf, phdr_count as u16, phdr_offset as u64)?;

        // === Program Headers ===
        // PT_NOTE
        pos += write_phdr(
            &mut buf[pos..],
            PT_NOTE,
            note_offset as u64,
            0,
            note_size as u64,
            note_size as u64,
            4, // PF_R
            0,
        )?;

        // PT_LOAD for each region
        for region in &self.regions[..self.region_count] {
            pos += write_phdr(
                &mut buf[pos..],
                PT_LOAD,
                region.file_offset,
                region.vaddr,
                region.size,
                region.size,
                region.flags,
                0x1000,
            )?;
        }

        // === Note Segment ===
        pos += self.write_notes(&mut buf[pos..])?;

        // === Memory data (placeholder — real impl would copy from
        // the process address space) ===
        for region in &self.regions[..self.region_count] {
            let end = pos + region.size as usize;
            if end > buf.len() {
                return Err(Error::OutOfMemory);
            }
            // Zero-fill (real kernel would copy actual pages)
            buf[pos..end].fill(0);
            pos = end;
        }

        Ok(pos)
    }

    /// Write the ELF header. Returns bytes written (64).
    fn write_elf_header(&self, buf: &mut [u8], phnum: u16, phoff: u64) -> Result<usize> {
        if buf.len() < ELF64_EHDR_SIZE {
            return Err(Error::InvalidArgument);
        }
        // e_ident
        buf[0..4].copy_from_slice(&ELF_MAGIC);
        buf[4] = ELFCLASS64;
        buf[5] = ELFDATA2LSB;
        buf[6] = EV_CURRENT;
        buf[7] = ELFOSABI_NONE;
        buf[8..16].fill(0); // padding

        // e_type
        put_u16_le(&mut buf[16..], ET_CORE);
        // e_machine
        put_u16_le(&mut buf[18..], EM_X86_64);
        // e_version
        put_u32_le(&mut buf[20..], EV_CURRENT as u32);
        // e_entry
        put_u64_le(&mut buf[24..], 0);
        // e_phoff
        put_u64_le(&mut buf[32..], phoff);
        // e_shoff
        put_u64_le(&mut buf[40..], 0);
        // e_flags
        put_u32_le(&mut buf[48..], 0);
        // e_ehsize
        put_u16_le(&mut buf[52..], ELF64_EHDR_SIZE as u16);
        // e_phentsize
        put_u16_le(&mut buf[54..], ELF64_PHDR_SIZE as u16);
        // e_phnum
        put_u16_le(&mut buf[56..], phnum);
        // e_shentsize
        put_u16_le(&mut buf[58..], 0);
        // e_shnum
        put_u16_le(&mut buf[60..], 0);
        // e_shstrndx
        put_u16_le(&mut buf[62..], 0);

        Ok(ELF64_EHDR_SIZE)
    }

    /// Compute the total size of the note segment.
    fn note_segment_size(&self) -> usize {
        // Each note: namesz(4) + descsz(4) + type(4) + name(aligned) + desc(aligned)
        let prstatus_size = note_entry_size(NOTE_NAME_LEN, core::mem::size_of::<Prstatus>());
        let prpsinfo_size = note_entry_size(NOTE_NAME_LEN, core::mem::size_of::<Prpsinfo>());
        prstatus_size + prpsinfo_size
    }

    /// Write NT_PRSTATUS and NT_PRPSINFO notes. Returns bytes written.
    fn write_notes(&self, buf: &mut [u8]) -> Result<usize> {
        let mut pos = 0;

        // NT_PRSTATUS
        let prstatus = self.build_prstatus();
        let prstatus_bytes = unsafe {
            core::slice::from_raw_parts(
                &prstatus as *const Prstatus as *const u8,
                core::mem::size_of::<Prstatus>(),
            )
        };
        pos += write_note(
            &mut buf[pos..],
            &NOTE_NAME[..NOTE_NAME_LEN],
            NT_PRSTATUS,
            prstatus_bytes,
        )?;

        // NT_PRPSINFO
        let prpsinfo = self.build_prpsinfo();
        let prpsinfo_bytes = unsafe {
            core::slice::from_raw_parts(
                &prpsinfo as *const Prpsinfo as *const u8,
                core::mem::size_of::<Prpsinfo>(),
            )
        };
        pos += write_note(
            &mut buf[pos..],
            &NOTE_NAME[..NOTE_NAME_LEN],
            NT_PRPSINFO,
            prpsinfo_bytes,
        )?;

        Ok(pos)
    }

    /// Build the prstatus structure from crash info.
    fn build_prstatus(&self) -> Prstatus {
        Prstatus {
            sig_info: ElfSigInfo {
                si_signo: self.crash.signal as i32,
                si_code: 0,
                si_errno: 0,
            },
            cur_sig: self.crash.signal as u16,
            pid: self.crash.pid.as_u64() as i32,
            ppid: self.crash.ppid.as_u64() as i32,
            regs: self.crash.regs,
            ..Prstatus::default()
        }
    }

    /// Build the prpsinfo structure from crash info.
    fn build_prpsinfo(&self) -> Prpsinfo {
        Prpsinfo {
            pid: self.crash.pid.as_u64() as i32,
            ppid: self.crash.ppid.as_u64() as i32,
            uid: self.crash.uid,
            gid: self.crash.gid,
            fname: self.crash.name,
            psargs: self.crash.cmdline,
            ..Prpsinfo::default()
        }
    }

    /// Returns the number of memory regions.
    pub fn region_count(&self) -> usize {
        self.region_count
    }
}

// ---------------------------------------------------------------------------
// Core Dump Policy
// ---------------------------------------------------------------------------

/// Policy for core dump generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CoreDumpPolicy {
    /// Never generate core dumps.
    Disabled,
    /// Generate core dumps for all crashing signals.
    Enabled,
    /// Generate only for specific signals (SIGSEGV, SIGABRT, etc.).
    #[default]
    DefaultSignals,
}

/// Check if a signal should generate a core dump under the default
/// policy.
pub fn should_dump(signal: u8) -> bool {
    matches!(
        signal,
        3  // SIGQUIT
        | 4  // SIGILL
        | 6  // SIGABRT
        | 7  // SIGBUS
        | 8  // SIGFPE
        | 11 // SIGSEGV
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write a 64-bit program header entry. Returns bytes written.
#[allow(clippy::too_many_arguments)]
fn write_phdr(
    buf: &mut [u8],
    p_type: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_flags: u32,
    p_align: u64,
) -> Result<usize> {
    if buf.len() < ELF64_PHDR_SIZE {
        return Err(Error::InvalidArgument);
    }
    put_u32_le(&mut buf[0..], p_type);
    put_u32_le(&mut buf[4..], p_flags);
    put_u64_le(&mut buf[8..], p_offset);
    put_u64_le(&mut buf[16..], p_vaddr);
    put_u64_le(&mut buf[24..], 0); // p_paddr
    put_u64_le(&mut buf[32..], p_filesz);
    put_u64_le(&mut buf[40..], p_memsz);
    put_u64_le(&mut buf[48..], p_align);
    Ok(ELF64_PHDR_SIZE)
}

/// Compute the size of one ELF note entry with 4-byte alignment.
fn note_entry_size(namesz: usize, descsz: usize) -> usize {
    let name_aligned = (namesz + 3) & !3;
    let desc_aligned = (descsz + 3) & !3;
    12 + name_aligned + desc_aligned // 12 = namesz(4) + descsz(4) + type(4)
}

/// Write an ELF note entry. Returns bytes written.
fn write_note(buf: &mut [u8], name: &[u8], note_type: u32, desc: &[u8]) -> Result<usize> {
    let total = note_entry_size(name.len(), desc.len());
    if buf.len() < total {
        return Err(Error::InvalidArgument);
    }

    let name_aligned = (name.len() + 3) & !3;
    let desc_aligned = (desc.len() + 3) & !3;

    put_u32_le(&mut buf[0..], name.len() as u32);
    put_u32_le(&mut buf[4..], desc.len() as u32);
    put_u32_le(&mut buf[8..], note_type);

    // Name (padded)
    buf[12..12 + name.len()].copy_from_slice(name);
    buf[12 + name.len()..12 + name_aligned].fill(0);

    // Descriptor (padded)
    let desc_start = 12 + name_aligned;
    buf[desc_start..desc_start + desc.len()].copy_from_slice(desc);
    buf[desc_start + desc.len()..desc_start + desc_aligned].fill(0);

    Ok(total)
}

/// Write a little-endian u16.
fn put_u16_le(buf: &mut [u8], val: u16) {
    let bytes = val.to_le_bytes();
    buf[0] = bytes[0];
    buf[1] = bytes[1];
}

/// Write a little-endian u32.
fn put_u32_le(buf: &mut [u8], val: u32) {
    let bytes = val.to_le_bytes();
    buf[..4].copy_from_slice(&bytes);
}

/// Write a little-endian u64.
fn put_u64_le(buf: &mut [u8], val: u64) {
    let bytes = val.to_le_bytes();
    buf[..8].copy_from_slice(&bytes);
}
