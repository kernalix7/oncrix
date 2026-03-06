// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Core dump generation.
//!
//! Produces ELF core dump files from a crashed process containing
//! register state, memory segments, and ELF note sections
//! (NT_PRSTATUS, NT_PRPSINFO). Supports coredump_filter and
//! RLIMIT_CORE enforcement.
//!
//! Reference: Linux `fs/coredump.c`, `fs/binfmt_elf.c`.

use oncrix_lib::{Error, Result};

// ── ELF constants ───────────────────────────────────────────────

/// ELF magic bytes.
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// ELFCLASS64.
const ELFCLASS64: u8 = 2;

/// ELFDATA2LSB (little-endian).
const ELFDATA2LSB: u8 = 1;

/// EV_CURRENT.
const EV_CURRENT: u8 = 1;

/// ET_CORE — core file type.
const ET_CORE: u16 = 4;

/// EM_X86_64 — AMD x86-64 architecture.
const EM_X86_64: u16 = 62;

/// PT_NOTE program header type.
const PT_NOTE: u32 = 4;

/// PT_LOAD program header type.
const PT_LOAD: u32 = 1;

/// NT_PRSTATUS — process status note type.
const NT_PRSTATUS: u32 = 1;

/// NT_PRPSINFO — process info note type.
const NT_PRPSINFO: u32 = 3;

// ── Limits ──────────────────────────────────────────────────────

/// Maximum VMA segments in a core dump.
const MAX_SEGMENTS: usize = 128;

/// Maximum ELF notes.
const MAX_NOTES: usize = 8;

/// Maximum process name length.
const MAX_PROC_NAME: usize = 16;

/// Size of the ELF64 header (bytes).
const ELF64_EHDR_SIZE: usize = 64;

/// Size of one ELF64 program header (bytes).
const ELF64_PHDR_SIZE: usize = 56;

/// Unlimited core size sentinel.
const RLIM_INFINITY: u64 = u64::MAX;

const FILTER_ANON_PRIVATE: u32 = 1 << 0;
const FILTER_ANON_SHARED: u32 = 1 << 1;
const FILTER_FILE_PRIVATE: u32 = 1 << 2;
const FILTER_FILE_SHARED: u32 = 1 << 3;
const FILTER_ELF_HEADERS: u32 = 1 << 4;
const _FILTER_HUGETLB: u32 = 1 << 5;

/// Default filter (anon private + anon shared + ELF headers).
const DEFAULT_FILTER: u32 = FILTER_ANON_PRIVATE | FILTER_ANON_SHARED | FILTER_ELF_HEADERS;

/// Type of a VMA segment for coredump filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmaType {
    /// Anonymous private mapping.
    AnonPrivate,
    /// Anonymous shared mapping.
    AnonShared,
    /// File-backed private mapping.
    FilePrivate,
    /// File-backed shared mapping.
    FileShared,
    /// ELF header region.
    ElfHeader,
}

impl VmaType {
    /// Return the filter bit for this VMA type.
    const fn filter_bit(self) -> u32 {
        match self {
            Self::AnonPrivate => FILTER_ANON_PRIVATE,
            Self::AnonShared => FILTER_ANON_SHARED,
            Self::FilePrivate => FILTER_FILE_PRIVATE,
            Self::FileShared => FILTER_FILE_SHARED,
            Self::ElfHeader => FILTER_ELF_HEADERS,
        }
    }
}

/// A collected VMA segment for the core dump.
#[derive(Debug, Clone, Copy)]
pub struct VmaSegment {
    /// Virtual start address.
    pub vaddr: u64,
    /// Segment size in bytes.
    pub size: u64,
    /// Protection flags (rwx bitmask).
    pub prot: u32,
    /// VMA classification.
    pub vma_type: VmaType,
    /// File offset in the core file (filled during layout).
    pub file_offset: u64,
    /// Whether this segment is included after filtering.
    pub included: bool,
}

/// Saved register state for core dump (x86_64).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct RegisterState {
    /// General-purpose registers.
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    /// Instruction pointer.
    pub rip: u64,
    /// Flags register.
    pub rflags: u64,
}

/// Process metadata for the NT_PRPSINFO note.
#[derive(Debug, Clone, Copy)]
pub struct ProcessInfo {
    /// Process name (up to MAX_PROC_NAME bytes).
    pub name: [u8; MAX_PROC_NAME],
    /// Name length.
    pub name_len: u32,
    /// Process ID.
    pub pid: u64,
    /// Parent process ID.
    pub ppid: u64,
    /// Signal that caused the dump.
    pub dump_signal: u32,
    /// Exit code (if applicable).
    pub exit_code: u32,
    /// UID of the process owner.
    pub uid: u32,
    /// GID of the process owner.
    pub gid: u32,
}

/// An ELF note section entry.
#[derive(Debug, Clone, Copy)]
struct NoteSection {
    /// Note type (NT_PRSTATUS, NT_PRPSINFO, etc.).
    note_type: u32,
    /// Data size in bytes.
    data_size: u32,
    /// Whether this note is populated.
    populated: bool,
}

/// Core dump writer: collects state and produces ELF core layout.
pub struct CoredumpWriter {
    /// Collected VMA segments.
    segments: [VmaSegment; MAX_SEGMENTS],
    /// Number of collected segments.
    segment_count: usize,
    /// ELF notes.
    notes: [NoteSection; MAX_NOTES],
    /// Number of notes.
    note_count: usize,
    /// Saved register state.
    regs: RegisterState,
    /// Process metadata.
    proc_info: ProcessInfo,
    /// Active coredump filter bitmask.
    filter: u32,
    /// Whether register state has been captured.
    regs_captured: bool,
    /// Whether process info has been set.
    info_set: bool,
}

impl CoredumpWriter {
    /// Create a new coredump writer with default filter.
    pub const fn new() -> Self {
        let seg = VmaSegment {
            vaddr: 0,
            size: 0,
            prot: 0,
            vma_type: VmaType::AnonPrivate,
            file_offset: 0,
            included: true,
        };
        let note = NoteSection {
            note_type: 0,
            data_size: 0,
            populated: false,
        };
        let regs = RegisterState {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            rsp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rflags: 0,
        };
        let info = ProcessInfo {
            name: [0u8; MAX_PROC_NAME],
            name_len: 0,
            pid: 0,
            ppid: 0,
            dump_signal: 0,
            exit_code: 0,
            uid: 0,
            gid: 0,
        };
        Self {
            segments: [seg; MAX_SEGMENTS],
            segment_count: 0,
            notes: [note; MAX_NOTES],
            note_count: 0,
            regs,
            proc_info: info,
            filter: DEFAULT_FILTER,
            regs_captured: false,
            info_set: false,
        }
    }

    /// Set the process metadata for the core dump.
    pub fn set_process_info(&mut self, info: ProcessInfo) -> Result<()> {
        self.proc_info = info;
        self.info_set = true;
        Ok(())
    }

    /// Capture the register state at the time of the dump.
    pub fn capture_regs(&mut self, regs: RegisterState) -> Result<()> {
        self.regs = regs;
        self.regs_captured = true;
        Ok(())
    }

    /// Add a VMA segment to the core dump.
    pub fn collect_vma(
        &mut self,
        vaddr: u64,
        size: u64,
        prot: u32,
        vma_type: VmaType,
    ) -> Result<()> {
        if self.segment_count >= MAX_SEGMENTS {
            return Err(Error::OutOfMemory);
        }
        self.segments[self.segment_count] = VmaSegment {
            vaddr,
            size,
            prot,
            vma_type,
            file_offset: 0,
            included: true,
        };
        self.segment_count += 1;
        Ok(())
    }

    /// Apply the coredump_filter bitmask.
    ///
    /// Marks segments as excluded if their type does not match
    /// the filter bits.
    pub fn apply_filter(&mut self, mask: u32) {
        self.filter = mask;
        for seg in &mut self.segments[..self.segment_count] {
            seg.included = (mask & seg.vma_type.filter_bit()) != 0;
        }
    }

    /// Check whether the total dump size fits within the limit.
    ///
    /// Returns `Error::InvalidArgument` if the core would exceed
    /// the limit (mirrors RLIMIT_CORE enforcement).
    pub fn check_limit(&self, limit: u64) -> Result<u64> {
        if limit == 0 {
            return Err(Error::InvalidArgument);
        }
        let total = self.estimate_size();
        if limit != RLIM_INFINITY && total > limit {
            return Err(Error::InvalidArgument);
        }
        Ok(total)
    }

    /// Build the ELF64 file header for the core dump.
    ///
    /// Returns the 64-byte header as a fixed array.
    pub fn build_header(&self) -> Result<[u8; ELF64_EHDR_SIZE]> {
        if !self.info_set {
            return Err(Error::InvalidArgument);
        }
        let mut hdr = [0u8; ELF64_EHDR_SIZE];
        // e_ident
        hdr[0..4].copy_from_slice(&ELF_MAGIC);
        hdr[4] = ELFCLASS64;
        hdr[5] = ELFDATA2LSB;
        hdr[6] = EV_CURRENT;
        // e_type = ET_CORE
        hdr[16..18].copy_from_slice(&ET_CORE.to_le_bytes());
        // e_machine = EM_X86_64
        hdr[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        // e_version = EV_CURRENT
        hdr[20..24].copy_from_slice(&1u32.to_le_bytes());
        // e_ehsize
        let ehsize = ELF64_EHDR_SIZE as u16;
        hdr[52..54].copy_from_slice(&ehsize.to_le_bytes());
        // e_phentsize
        let phentsize = ELF64_PHDR_SIZE as u16;
        hdr[54..56].copy_from_slice(&phentsize.to_le_bytes());
        // e_phnum = notes + included segments
        let phnum = self.included_segment_count() as u16 + 1;
        hdr[56..58].copy_from_slice(&phnum.to_le_bytes());
        // e_phoff = immediately after header
        let phoff = ELF64_EHDR_SIZE as u64;
        hdr[32..40].copy_from_slice(&phoff.to_le_bytes());
        Ok(hdr)
    }

    /// Build the NT_PRSTATUS note descriptor.
    pub fn build_prstatus_note(&mut self) -> Result<NoteDescriptor> {
        if !self.regs_captured {
            return Err(Error::InvalidArgument);
        }
        if self.note_count >= MAX_NOTES {
            return Err(Error::OutOfMemory);
        }
        let data_size = core::mem::size_of::<RegisterState>() as u32 + 16; // signal + pid fields
        self.notes[self.note_count] = NoteSection {
            note_type: NT_PRSTATUS,
            data_size,
            populated: true,
        };
        self.note_count += 1;
        Ok(NoteDescriptor {
            note_type: NT_PRSTATUS,
            signal: self.proc_info.dump_signal,
            pid: self.proc_info.pid,
        })
    }

    /// Build the NT_PRPSINFO note descriptor.
    pub fn build_prpsinfo_note(&mut self) -> Result<NoteDescriptor> {
        if !self.info_set {
            return Err(Error::InvalidArgument);
        }
        if self.note_count >= MAX_NOTES {
            return Err(Error::OutOfMemory);
        }
        let data_size = MAX_PROC_NAME as u32 + 24; // name + uid/gid/pid
        self.notes[self.note_count] = NoteSection {
            note_type: NT_PRPSINFO,
            data_size,
            populated: true,
        };
        self.note_count += 1;
        Ok(NoteDescriptor {
            note_type: NT_PRPSINFO,
            signal: 0,
            pid: self.proc_info.pid,
        })
    }

    /// Return the number of collected segments.
    pub fn segment_count(&self) -> usize {
        self.segment_count
    }

    /// Return the number of included segments after filtering.
    pub fn included_segment_count(&self) -> usize {
        self.segments[..self.segment_count]
            .iter()
            .filter(|s| s.included)
            .count()
    }

    /// Return the current coredump filter mask.
    pub fn filter(&self) -> u32 {
        self.filter
    }

    // ── Internal helpers ────────────────────────────────────────

    /// Estimate the total core file size.
    fn estimate_size(&self) -> u64 {
        let header_size = ELF64_EHDR_SIZE as u64;
        let note_phdr = ELF64_PHDR_SIZE as u64;
        let load_phdrs = self.included_segment_count() as u64 * ELF64_PHDR_SIZE as u64;
        let note_data: u64 = self.notes[..self.note_count]
            .iter()
            .filter(|n| n.populated)
            .map(|n| n.data_size as u64 + 12) // name+desc hdr
            .sum();
        let segment_data: u64 = self.segments[..self.segment_count]
            .iter()
            .filter(|s| s.included)
            .map(|s| s.size)
            .sum();
        header_size + note_phdr + load_phdrs + note_data + segment_data
    }
}

/// Descriptor returned from note-building methods.
#[derive(Debug, Clone, Copy)]
pub struct NoteDescriptor {
    /// Note type (NT_PRSTATUS, NT_PRPSINFO).
    pub note_type: u32,
    /// Signal number (0 for non-status notes).
    pub signal: u32,
    /// Process ID.
    pub pid: u64,
}
