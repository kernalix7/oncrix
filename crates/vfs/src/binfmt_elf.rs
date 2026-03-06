// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ELF binary format handler — `binfmt_elf`.
//!
//! Parses ELF64 (and ELF32) executables and shared objects, validates their
//! structure, and prepares the information needed to load them into a process
//! address space.  The actual page-table manipulation is performed by the MM
//! subsystem; this module only reads and validates the binary.
//!
//! Supported ELF types:
//! - `ET_EXEC` — statically linked executables
//! - `ET_DYN`  — position-independent executables and shared libraries
//!
//! # Linux reference
//! `fs/binfmt_elf.c` — `load_elf_binary()`, `elf_map()`, ELF aux-vector setup
//! `include/uapi/linux/elf.h` — ELF type definitions
//!
//! # POSIX reference
//! POSIX.1-2024 `exec` family — program loading semantics
//! System V ABI supplement — ELF specification

use oncrix_lib::{Error, Result};

// ── ELF magic & identification ────────────────────────────────────────────────

/// ELF magic bytes at offset 0 of the file.
pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/// ELF class: 32-bit.
pub const ELFCLASS32: u8 = 1;
/// ELF class: 64-bit.
pub const ELFCLASS64: u8 = 2;

/// ELF data encoding: little-endian.
pub const ELFDATA2LSB: u8 = 1;
/// ELF data encoding: big-endian.
pub const ELFDATA2MSB: u8 = 2;

/// ELF version: current.
pub const EV_CURRENT: u8 = 1;

/// ELF OS/ABI: System V (generic).
pub const ELFOSABI_NONE: u8 = 0;
/// ELF OS/ABI: GNU/Linux.
pub const ELFOSABI_LINUX: u8 = 3;

// ── ELF object type ───────────────────────────────────────────────────────────

/// ELF object file type (`e_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ElfType {
    /// No file type.
    None = 0,
    /// Relocatable object file.
    Rel = 1,
    /// Executable file.
    Exec = 2,
    /// Shared object file / PIC executable.
    Dyn = 3,
    /// Core dump.
    Core = 4,
}

impl ElfType {
    fn from_raw(v: u16) -> Result<Self> {
        match v {
            0 => Ok(Self::None),
            1 => Ok(Self::Rel),
            2 => Ok(Self::Exec),
            3 => Ok(Self::Dyn),
            4 => Ok(Self::Core),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ── Machine type ──────────────────────────────────────────────────────────────

/// ELF machine architecture (`e_machine`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ElfMachine {
    /// x86 (IA-32).
    X86 = 3,
    /// ARM 32-bit.
    Arm = 40,
    /// x86-64.
    X86_64 = 62,
    /// AArch64.
    Aarch64 = 183,
    /// RISC-V.
    RiscV = 243,
}

impl ElfMachine {
    fn from_raw(v: u16) -> Result<Self> {
        match v {
            3 => Ok(Self::X86),
            40 => Ok(Self::Arm),
            62 => Ok(Self::X86_64),
            183 => Ok(Self::Aarch64),
            243 => Ok(Self::RiscV),
            _ => Err(Error::InvalidArgument),
        }
    }
}

// ── Program-header segment types ─────────────────────────────────────────────

/// ELF program-header segment type (`p_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PhdrType {
    /// Null (ignore).
    Null = 0,
    /// Loadable segment.
    Load = 1,
    /// Dynamic linking info.
    Dynamic = 2,
    /// Interpreter path.
    Interp = 3,
    /// Auxiliary information.
    Note = 4,
    /// Reserved.
    ShLib = 5,
    /// Program header table itself.
    Phdr = 6,
    /// Thread-local storage template.
    Tls = 7,
    /// GNU stack permissions hint.
    GnuStack = 0x6474_E551,
    /// GNU read-only-after-relocation region.
    GnuRelRo = 0x6474_E552,
}

impl PhdrType {
    fn from_raw(v: u32) -> Self {
        match v {
            0 => Self::Null,
            1 => Self::Load,
            2 => Self::Dynamic,
            3 => Self::Interp,
            4 => Self::Note,
            5 => Self::ShLib,
            6 => Self::Phdr,
            7 => Self::Tls,
            0x6474_E551 => Self::GnuStack,
            0x6474_E552 => Self::GnuRelRo,
            _ => Self::Null,
        }
    }
}

// ── Segment permission flags ──────────────────────────────────────────────────

/// ELF segment permission flags (`p_flags`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentFlags(pub u32);

impl SegmentFlags {
    /// Segment is executable.
    pub const EXEC: u32 = 0x1;
    /// Segment is writable.
    pub const WRITE: u32 = 0x2;
    /// Segment is readable.
    pub const READ: u32 = 0x4;

    /// Returns `true` if the execute bit is set.
    pub fn executable(self) -> bool {
        self.0 & Self::EXEC != 0
    }
    /// Returns `true` if the write bit is set.
    pub fn writable(self) -> bool {
        self.0 & Self::WRITE != 0
    }
    /// Returns `true` if the read bit is set.
    pub fn readable(self) -> bool {
        self.0 & Self::READ != 0
    }
}

// ── ELF64 header ─────────────────────────────────────────────────────────────

/// Size of the ELF identification block (`e_ident`).
const ELF_IDENT_LEN: usize = 16;
/// Offset of the ELF class byte within `e_ident`.
const EI_CLASS: usize = 4;
/// Offset of the data encoding byte within `e_ident`.
const EI_DATA: usize = 5;
/// Offset of the ELF version byte within `e_ident`.
const EI_VERSION: usize = 6;
/// Offset of the OS/ABI byte within `e_ident`.
const EI_OSABI: usize = 7;

/// ELF64 file header (little-endian layout, 64 bytes total).
#[derive(Debug, Clone, Copy)]
pub struct Elf64Header {
    /// Identification bytes.
    pub e_ident: [u8; ELF_IDENT_LEN],
    /// Object file type.
    pub e_type: u16,
    /// Required architecture.
    pub e_machine: u16,
    /// ELF format version.
    pub e_version: u32,
    /// Entry-point virtual address.
    pub e_entry: u64,
    /// Program-header table file offset.
    pub e_phoff: u64,
    /// Section-header table file offset.
    pub e_shoff: u64,
    /// Processor-specific flags.
    pub e_flags: u32,
    /// ELF header size (bytes).
    pub e_ehsize: u16,
    /// Program-header entry size.
    pub e_phentsize: u16,
    /// Number of program-header entries.
    pub e_phnum: u16,
    /// Section-header entry size.
    pub e_shentsize: u16,
    /// Number of section-header entries.
    pub e_shnum: u16,
    /// Section-name string-table index.
    pub e_shstrndx: u16,
}

/// Expected size of an ELF64 header in bytes.
pub const ELF64_EHDR_SIZE: usize = 64;
/// Expected size of an ELF64 program-header entry.
pub const ELF64_PHDR_SIZE: usize = 56;

impl Elf64Header {
    /// Parse an ELF64 header from raw bytes.
    ///
    /// Returns `InvalidArgument` if the buffer is too short or the magic
    /// bytes do not match.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < ELF64_EHDR_SIZE {
            return Err(Error::InvalidArgument);
        }
        if buf[0..4] != ELF_MAGIC {
            return Err(Error::InvalidArgument);
        }
        let read_u16 = |off: usize| -> u16 { u16::from_le_bytes([buf[off], buf[off + 1]]) };
        let read_u32 = |off: usize| -> u32 {
            u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
        };
        let read_u64 = |off: usize| -> u64 {
            u64::from_le_bytes([
                buf[off],
                buf[off + 1],
                buf[off + 2],
                buf[off + 3],
                buf[off + 4],
                buf[off + 5],
                buf[off + 6],
                buf[off + 7],
            ])
        };
        let mut e_ident = [0u8; ELF_IDENT_LEN];
        e_ident.copy_from_slice(&buf[..ELF_IDENT_LEN]);
        Ok(Self {
            e_ident,
            e_type: read_u16(16),
            e_machine: read_u16(18),
            e_version: read_u32(20),
            e_entry: read_u64(24),
            e_phoff: read_u64(32),
            e_shoff: read_u64(40),
            e_flags: read_u32(48),
            e_ehsize: read_u16(52),
            e_phentsize: read_u16(54),
            e_phnum: read_u16(56),
            e_shentsize: read_u16(58),
            e_shnum: read_u16(60),
            e_shstrndx: read_u16(62),
        })
    }

    /// Returns the ELF class byte.
    pub fn elf_class(&self) -> u8 {
        self.e_ident[EI_CLASS]
    }

    /// Returns `true` if this is a 64-bit ELF.
    pub fn is_64bit(&self) -> bool {
        self.e_ident[EI_CLASS] == ELFCLASS64
    }

    /// Returns `true` if this is little-endian.
    pub fn is_little_endian(&self) -> bool {
        self.e_ident[EI_DATA] == ELFDATA2LSB
    }
}

// ── ELF64 program header ──────────────────────────────────────────────────────

/// ELF64 program-header entry (56 bytes, little-endian).
#[derive(Debug, Clone, Copy)]
pub struct Elf64Phdr {
    /// Segment type.
    pub p_type: u32,
    /// Segment flags.
    pub p_flags: u32,
    /// Offset of segment in file image.
    pub p_offset: u64,
    /// Virtual address of segment in memory.
    pub p_vaddr: u64,
    /// Physical address (ignored for most ELF types).
    pub p_paddr: u64,
    /// Size of segment in file (may be 0 for BSS).
    pub p_filesz: u64,
    /// Size of segment in memory.
    pub p_memsz: u64,
    /// Segment alignment.
    pub p_align: u64,
}

impl Elf64Phdr {
    /// Parse a single program-header entry from a raw byte slice.
    pub fn parse(buf: &[u8]) -> Result<Self> {
        if buf.len() < ELF64_PHDR_SIZE {
            return Err(Error::InvalidArgument);
        }
        let read_u32 = |off: usize| -> u32 {
            u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
        };
        let read_u64 = |off: usize| -> u64 {
            u64::from_le_bytes([
                buf[off],
                buf[off + 1],
                buf[off + 2],
                buf[off + 3],
                buf[off + 4],
                buf[off + 5],
                buf[off + 6],
                buf[off + 7],
            ])
        };
        Ok(Self {
            p_type: read_u32(0),
            p_flags: read_u32(4),
            p_offset: read_u64(8),
            p_vaddr: read_u64(16),
            p_paddr: read_u64(24),
            p_filesz: read_u64(32),
            p_memsz: read_u64(40),
            p_align: read_u64(48),
        })
    }

    /// Returns the segment type.
    pub fn seg_type(&self) -> PhdrType {
        PhdrType::from_raw(self.p_type)
    }

    /// Returns the segment permission flags.
    pub fn flags(&self) -> SegmentFlags {
        SegmentFlags(self.p_flags)
    }
}

// ── Parsed ELF info ───────────────────────────────────────────────────────────

/// Maximum number of program-header entries we'll store.
const MAX_PHDRS: usize = 32;

/// Maximum interpreter path length.
const MAX_INTERP_LEN: usize = 256;

/// Fully parsed ELF binary descriptor.
///
/// Produced by `parse_elf()` and consumed by the exec path to set up
/// the process address space.
pub struct ElfInfo {
    /// Parsed ELF64 header.
    pub header: Elf64Header,
    /// Parsed ELF type.
    pub elf_type: ElfType,
    /// Machine architecture.
    pub machine: ElfMachine,
    /// Program-header entries (up to `MAX_PHDRS`).
    pub phdrs: [Option<Elf64Phdr>; MAX_PHDRS],
    /// Number of valid program-header entries.
    pub phdr_count: usize,
    /// Entry-point virtual address.
    pub entry_point: u64,
    /// Load bias: added to `p_vaddr` for ET_DYN binaries.
    pub load_bias: u64,
    /// Address of the `PT_INTERP` segment content (dynamic linker path).
    pub interp_path: [u8; MAX_INTERP_LEN],
    /// Length of `interp_path`.
    pub interp_len: usize,
    /// Whether this binary requires a dynamic linker.
    pub needs_interp: bool,
    /// `PT_GNU_STACK` flags (controls NX stack).
    pub gnu_stack_flags: SegmentFlags,
}

impl ElfInfo {
    /// Parse an ELF binary from a flat byte buffer.
    ///
    /// Validates the magic, class, encoding, version, and machine type,
    /// then reads all program-header entries.
    ///
    /// # Errors
    ///
    /// - `InvalidArgument` — bad magic, unsupported class/encoding/version,
    ///   or malformed program-header data.
    /// - `NotImplemented` — 32-bit ELF (not yet supported).
    pub fn parse(data: &[u8]) -> Result<Self> {
        let header = Elf64Header::parse(data)?;
        if !header.is_64bit() {
            return Err(Error::NotImplemented);
        }
        if !header.is_little_endian() {
            return Err(Error::NotImplemented);
        }
        if header.e_ident[EI_VERSION] != EV_CURRENT {
            return Err(Error::InvalidArgument);
        }
        let elf_type = ElfType::from_raw(header.e_type)?;
        if elf_type != ElfType::Exec && elf_type != ElfType::Dyn {
            return Err(Error::InvalidArgument);
        }
        let machine = ElfMachine::from_raw(header.e_machine)?;
        let ph_off = header.e_phoff as usize;
        let ph_num = header.e_phnum as usize;
        let ph_ent = header.e_phentsize as usize;
        if ph_num > MAX_PHDRS {
            return Err(Error::InvalidArgument);
        }
        if ph_ent < ELF64_PHDR_SIZE {
            return Err(Error::InvalidArgument);
        }
        let phdrs_end = ph_off.saturating_add(ph_num.saturating_mul(ph_ent));
        if data.len() < phdrs_end {
            return Err(Error::InvalidArgument);
        }
        let mut phdrs = [const { None }; MAX_PHDRS];
        let mut phdr_count = 0usize;
        let mut interp_path = [0u8; MAX_INTERP_LEN];
        let mut interp_len = 0usize;
        let mut needs_interp = false;
        let mut gnu_stack_flags = SegmentFlags(0x6); // RW by default
        for i in 0..ph_num {
            let start = ph_off + i * ph_ent;
            let ph = Elf64Phdr::parse(&data[start..start + ELF64_PHDR_SIZE])?;
            match ph.seg_type() {
                PhdrType::Interp => {
                    // Copy the interpreter path from the file data.
                    let off = ph.p_offset as usize;
                    let sz = ph.p_filesz as usize;
                    if off + sz <= data.len() && sz > 0 {
                        let copy_len = sz.min(MAX_INTERP_LEN - 1);
                        interp_path[..copy_len].copy_from_slice(&data[off..off + copy_len]);
                        interp_len = copy_len;
                        needs_interp = true;
                    }
                }
                PhdrType::GnuStack => {
                    gnu_stack_flags = ph.flags();
                }
                _ => {}
            }
            phdrs[i] = Some(ph);
            phdr_count += 1;
        }
        Ok(Self {
            header,
            elf_type,
            machine,
            phdrs,
            phdr_count,
            entry_point: header.e_entry,
            load_bias: 0,
            interp_path,
            interp_len,
            needs_interp,
            gnu_stack_flags,
        })
    }

    /// Returns the interpreter path as a byte slice (may include a trailing NUL).
    pub fn interp_path(&self) -> &[u8] {
        &self.interp_path[..self.interp_len]
    }

    /// Returns `true` if the GNU stack is executable.
    pub fn executable_stack(&self) -> bool {
        self.gnu_stack_flags.executable()
    }

    /// Returns `true` if this is a position-independent executable / shared lib.
    pub fn is_pic(&self) -> bool {
        self.elf_type == ElfType::Dyn
    }

    /// Returns an iterator over valid `PT_LOAD` segments.
    pub fn load_segments(&self) -> impl Iterator<Item = &Elf64Phdr> {
        self.phdrs
            .iter()
            .filter_map(|p| p.as_ref())
            .filter(|p| p.seg_type() == PhdrType::Load)
    }
}

// ── Auxiliary vector ─────────────────────────────────────────────────────────

/// Auxiliary vector entry types (AT_* constants).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u64)]
pub enum AuxType {
    /// End of vector.
    Null = 0,
    /// Ignore.
    Ignore = 1,
    /// File descriptor of program.
    ExecFd = 2,
    /// Program headers for program.
    Phdr = 3,
    /// Size of program header entry.
    Phent = 4,
    /// Number of program headers.
    Phnum = 5,
    /// System page size.
    Pagesz = 6,
    /// Base address of interpreter.
    Base = 7,
    /// Flags.
    Flags = 8,
    /// Entry point of program.
    Entry = 9,
    /// Program is not ELF.
    NotElf = 10,
    /// Real UID.
    Uid = 11,
    /// Effective UID.
    EUid = 12,
    /// Real GID.
    Gid = 13,
    /// Effective GID.
    EGid = 14,
    /// Platform string.
    Platform = 15,
    /// Hardware capabilities.
    HwCap = 16,
    /// Clock ticks per second.
    ClkTck = 17,
    /// Base address of vDSO.
    SysInfo = 32,
    /// Address of vDSO ELF header.
    SysInfoEhdr = 33,
}

/// A single auxiliary vector entry.
#[derive(Debug, Clone, Copy)]
pub struct AuxEntry {
    /// Entry type.
    pub a_type: u64,
    /// Entry value.
    pub a_val: u64,
}

/// Maximum number of auxiliary vector entries.
const MAX_AUX_ENTRIES: usize = 32;

/// Auxiliary vector for a new process.
pub struct AuxVec {
    entries: [AuxEntry; MAX_AUX_ENTRIES],
    count: usize,
}

impl AuxVec {
    /// Create an empty auxiliary vector.
    pub const fn new() -> Self {
        Self {
            entries: [const {
                AuxEntry {
                    a_type: 0,
                    a_val: 0,
                }
            }; MAX_AUX_ENTRIES],
            count: 0,
        }
    }

    /// Append an entry.  Returns `OutOfMemory` if the vector is full.
    pub fn push(&mut self, a_type: AuxType, a_val: u64) -> Result<()> {
        if self.count >= MAX_AUX_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        self.entries[self.count] = AuxEntry {
            a_type: a_type as u64,
            a_val,
        };
        self.count += 1;
        Ok(())
    }

    /// Returns all entries as a slice.
    pub fn as_slice(&self) -> &[AuxEntry] {
        &self.entries[..self.count]
    }

    /// Build a standard auxiliary vector for an ELF executable.
    ///
    /// `page_size` — system page size, `phdr_vaddr` — virtual address where
    /// the program headers have been mapped, `interp_base` — load address of
    /// the dynamic linker (0 if statically linked).
    pub fn build_for_elf(
        info: &ElfInfo,
        page_size: u64,
        phdr_vaddr: u64,
        interp_base: u64,
    ) -> Result<Self> {
        let mut av = Self::new();
        av.push(AuxType::Phdr, phdr_vaddr)?;
        av.push(AuxType::Phent, ELF64_PHDR_SIZE as u64)?;
        av.push(AuxType::Phnum, info.header.e_phnum as u64)?;
        av.push(AuxType::Pagesz, page_size)?;
        av.push(AuxType::Base, interp_base)?;
        av.push(AuxType::Flags, 0)?;
        av.push(AuxType::Entry, info.entry_point)?;
        av.push(AuxType::ClkTck, 100)?;
        av.push(AuxType::Null, 0)?;
        Ok(av)
    }
}

// ── binfmt registration ───────────────────────────────────────────────────────

/// Check if a byte buffer starts with an ELF magic header.
///
/// Called by the binary-format dispatcher before attempting a full parse.
pub fn is_elf(buf: &[u8]) -> bool {
    buf.len() >= 4 && buf[0..4] == ELF_MAGIC
}

/// Attempt to load an ELF binary from `data`.
///
/// This is the entry point called by the exec path.  On success, returns
/// a fully validated `ElfInfo` ready for address-space setup.
pub fn load_elf_binary(data: &[u8]) -> Result<ElfInfo> {
    if !is_elf(data) {
        return Err(Error::InvalidArgument);
    }
    ElfInfo::parse(data)
}
