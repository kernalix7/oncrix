// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Crash dump (kdump) data collection subsystem.
//!
//! Collects system state at the moment of a kernel crash and formats it
//! as an ELF core dump suitable for post-mortem analysis with GDB or
//! the `crash` utility.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                     CrashDumpCollector                            │
//! │                                                                  │
//! │  crash_reason ── Panic / Oops / NMI / Watchdog / …               │
//! │  cpu_states   ── [CpuRegisterState; MAX_CPUS]                    │
//! │  mem_regions  ── [MemoryRegion; MAX_REGIONS] (PT_LOAD)           │
//! │  vmcoreinfo   ── [VmcoreinfoEntry; …] key=value notes            │
//! │                                                                  │
//! │  ┌──────────┐                                                    │
//! │  │ ELF hdr  │ Elf64_Ehdr + Elf64_Phdr[] → on-disk layout        │
//! │  │ PT_NOTE  │ crash reason, CPU regs, vmcoreinfo                 │
//! │  │ PT_LOAD  │ physical memory segments                           │
//! │  └──────────┘                                                    │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage Flow
//!
//! 1. At boot, call `CrashDumpCollector::new()` and register memory
//!    regions via `add_memory_region()`.
//! 2. On crash, call `capture_cpu_state()` for each online CPU.
//! 3. Set the crash reason via `set_crash_reason()`.
//! 4. Build the ELF header with `build_elf_header()`.
//! 5. Iterate program headers with `build_program_headers()`.
//! 6. Build the vmcoreinfo note with `build_vmcoreinfo_note()`.
//!
//! # Reference
//!
//! Linux `kernel/crash_dump.c`, `kernel/crash_core.c`,
//! `include/linux/crash_dump.h`, `/proc/vmcore` format.

use oncrix_lib::{Error, Result};

// ── ELF Constants ───────────────────────────────────────────────────────────

/// ELF magic: 0x7f 'E' 'L' 'F'.
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// ELFCLASS64 — 64-bit objects.
const ELFCLASS64: u8 = 2;

/// ELFDATA2LSB — little-endian.
const ELFDATA2LSB: u8 = 1;

/// EV_CURRENT — current ELF version.
const EV_CURRENT: u8 = 1;

/// ELFOSABI_NONE — no OS-specific ABI.
const ELFOSABI_NONE: u8 = 0;

/// ET_CORE — core dump file type.
const ET_CORE: u16 = 4;

/// EM_X86_64 — AMD x86-64 architecture.
const EM_X86_64: u16 = 62;

/// PT_NULL — unused program header entry.
const _PT_NULL: u32 = 0;

/// PT_LOAD — loadable segment.
const PT_LOAD: u32 = 1;

/// PT_NOTE — note segment.
const PT_NOTE: u32 = 4;

/// PF_R — segment is readable.
const PF_R: u32 = 0x4;

/// PF_W — segment is writable.
const PF_W: u32 = 0x2;

/// PF_X — segment is executable.
const _PF_X: u32 = 0x1;

/// Size of an ELF64 header.
const ELF64_EHDR_SIZE: usize = 64;

/// Size of an ELF64 program header entry.
const ELF64_PHDR_SIZE: usize = 56;

/// Note name for CORE notes.
const NOTE_NAME_CORE: &[u8] = b"CORE\0\0\0\0";

/// Note name for vmcoreinfo.
const NOTE_NAME_VMCOREINFO: &[u8] = b"VMCOREINFO\0\0";

/// Note type for process status (prstatus).
const NT_PRSTATUS: u32 = 1;

/// Note type for vmcoreinfo.
const _NT_VMCOREINFO: u32 = 0x564d4300;

// ── System Limits ───────────────────────────────────────────────────────────

/// Maximum number of CPUs whose state can be captured.
const MAX_CPUS: usize = 64;

/// Maximum number of physical memory regions in the dump.
const MAX_REGIONS: usize = 128;

/// Maximum number of vmcoreinfo key=value entries.
const MAX_VMCOREINFO_ENTRIES: usize = 64;

/// Maximum length of a vmcoreinfo key.
const MAX_KEY_LEN: usize = 32;

/// Maximum length of a vmcoreinfo value.
const MAX_VALUE_LEN: usize = 64;

/// Maximum size of the vmcoreinfo note section in bytes.
const MAX_NOTE_SIZE: usize = 4096;

// ── Crash Reason ────────────────────────────────────────────────────────────

/// Reason the kernel crashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashReason {
    /// Explicit kernel panic (BUG, assertion, etc.).
    Panic,
    /// Kernel oops (recoverable fault that became fatal).
    Oops,
    /// Non-maskable interrupt (hardware error, watchdog).
    Nmi,
    /// Soft/hard lockup detected by the watchdog.
    Watchdog,
    /// Out-of-memory killer triggered.
    Oom,
    /// Double fault.
    DoubleFault,
    /// Machine check exception (MCE).
    MachineCheck,
    /// User-triggered crash (SysRq-c or similar).
    UserTriggered,
    /// Unknown or unclassified reason.
    Unknown,
}

impl CrashReason {
    /// Return a human-readable string for the crash reason.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Panic => "Kernel panic",
            Self::Oops => "Kernel oops",
            Self::Nmi => "Non-maskable interrupt",
            Self::Watchdog => "Watchdog timeout",
            Self::Oom => "Out of memory",
            Self::DoubleFault => "Double fault",
            Self::MachineCheck => "Machine check exception",
            Self::UserTriggered => "User-triggered crash dump",
            Self::Unknown => "Unknown",
        }
    }

    /// Return a short code for vmcoreinfo.
    pub fn code(self) -> u32 {
        match self {
            Self::Panic => 1,
            Self::Oops => 2,
            Self::Nmi => 3,
            Self::Watchdog => 4,
            Self::Oom => 5,
            Self::DoubleFault => 6,
            Self::MachineCheck => 7,
            Self::UserTriggered => 8,
            Self::Unknown => 0,
        }
    }
}

// ── CPU Register State ──────────────────────────────────────────────────────

/// Saved register state for one CPU at crash time.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CpuRegisterState {
    /// Whether this CPU slot is populated.
    pub valid: bool,
    /// CPU number (0-based).
    pub cpu_id: u32,
    /// General-purpose registers (rax, rbx, rcx, rdx, rsi, rdi, rbp,
    /// rsp, r8-r15).
    pub gp_regs: [u64; 16],
    /// Instruction pointer (RIP).
    pub rip: u64,
    /// Flags register (RFLAGS).
    pub rflags: u64,
    /// Code segment selector.
    pub cs: u64,
    /// Stack segment selector.
    pub ss: u64,
    /// CR0 control register.
    pub cr0: u64,
    /// CR2 control register (page-fault linear address).
    pub cr2: u64,
    /// CR3 control register (page directory base).
    pub cr3: u64,
    /// CR4 control register.
    pub cr4: u64,
    /// Timestamp counter at capture time.
    pub tsc: u64,
    /// Whether this CPU was the one that triggered the crash.
    pub is_crashing_cpu: bool,
}

impl CpuRegisterState {
    /// Create an empty (invalid) CPU register state.
    pub const fn new() -> Self {
        Self {
            valid: false,
            cpu_id: 0,
            gp_regs: [0u64; 16],
            rip: 0,
            rflags: 0,
            cs: 0,
            ss: 0,
            cr0: 0,
            cr2: 0,
            cr3: 0,
            cr4: 0,
            tsc: 0,
            is_crashing_cpu: false,
        }
    }

    /// Total size of the register note data for this CPU.
    pub fn note_data_size() -> usize {
        // gp_regs (16*8) + rip + rflags + cs + ss + cr0-4 + tsc
        16 * 8 + 8 * 8
    }

    /// Encode register state into a byte buffer for the ELF note.
    ///
    /// Returns the number of bytes written.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        let size = Self::note_data_size();
        if buf.len() < size {
            return Err(Error::InvalidArgument);
        }
        let mut pos = 0;
        for &reg in &self.gp_regs {
            buf[pos..pos + 8].copy_from_slice(&reg.to_le_bytes());
            pos += 8;
        }
        for &val in &[
            self.rip,
            self.rflags,
            self.cs,
            self.ss,
            self.cr0,
            self.cr2,
            self.cr3,
            self.cr4,
        ] {
            buf[pos..pos + 8].copy_from_slice(&val.to_le_bytes());
            pos += 8;
        }
        Ok(pos)
    }
}

// ── Memory Region ───────────────────────────────────────────────────────────

/// A physical memory region to include in the dump.
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    /// Whether this region slot is in use.
    pub active: bool,
    /// Physical start address.
    pub phys_addr: u64,
    /// Virtual start address (if mapped).
    pub virt_addr: u64,
    /// Size of the region in bytes.
    pub size: u64,
    /// Offset in the dump file where this region's data starts.
    pub file_offset: u64,
    /// Whether this region is readable.
    pub readable: bool,
    /// Whether this region is writable.
    pub writable: bool,
    /// Region type for diagnostics.
    pub region_type: MemoryRegionType,
}

/// Type classification for a memory region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryRegionType {
    /// Conventional RAM.
    Ram,
    /// Kernel text/code.
    KernelText,
    /// Kernel data/bss.
    KernelData,
    /// Kernel module space.
    Module,
    /// Reserved by firmware.
    Reserved,
    /// Device MMIO (usually excluded).
    DeviceMmio,
}

impl MemoryRegion {
    /// Create an empty (inactive) memory region slot.
    pub const fn new() -> Self {
        Self {
            active: false,
            phys_addr: 0,
            virt_addr: 0,
            size: 0,
            file_offset: 0,
            readable: false,
            writable: false,
            region_type: MemoryRegionType::Ram,
        }
    }

    /// Compute the ELF PT_LOAD flags for this region.
    pub fn elf_flags(&self) -> u32 {
        let mut flags = 0u32;
        if self.readable {
            flags |= PF_R;
        }
        if self.writable {
            flags |= PF_W;
        }
        flags
    }
}

// ── Vmcoreinfo ──────────────────────────────────────────────────────────────

/// A single vmcoreinfo key=value pair.
#[derive(Debug, Clone, Copy)]
pub struct VmcoreinfoEntry {
    /// Whether this entry is in use.
    pub active: bool,
    /// Key bytes (null-terminated within the buffer).
    pub key: [u8; MAX_KEY_LEN],
    /// Key length (excluding null terminator).
    pub key_len: usize,
    /// Value bytes (null-terminated within the buffer).
    pub value: [u8; MAX_VALUE_LEN],
    /// Value length (excluding null terminator).
    pub value_len: usize,
}

impl VmcoreinfoEntry {
    /// Create an empty vmcoreinfo entry.
    pub const fn new() -> Self {
        Self {
            active: false,
            key: [0u8; MAX_KEY_LEN],
            key_len: 0,
            value: [0u8; MAX_VALUE_LEN],
            value_len: 0,
        }
    }

    /// Set the key and value for this entry.
    pub fn set(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        if key.len() >= MAX_KEY_LEN || value.len() >= MAX_VALUE_LEN {
            return Err(Error::InvalidArgument);
        }
        self.key[..key.len()].copy_from_slice(key);
        self.key_len = key.len();
        self.value[..value.len()].copy_from_slice(value);
        self.value_len = value.len();
        self.active = true;
        Ok(())
    }

    /// Encode as "KEY=VALUE\n" into a buffer. Returns bytes written.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        if !self.active {
            return Ok(0);
        }
        let needed = self.key_len + 1 + self.value_len + 1;
        if buf.len() < needed {
            return Err(Error::InvalidArgument);
        }
        buf[..self.key_len].copy_from_slice(&self.key[..self.key_len]);
        buf[self.key_len] = b'=';
        let vstart = self.key_len + 1;
        buf[vstart..vstart + self.value_len].copy_from_slice(&self.value[..self.value_len]);
        buf[vstart + self.value_len] = b'\n';
        Ok(needed)
    }
}

// ── ELF Header Structures ───────────────────────────────────────────────────

/// ELF64 file header (repr(C) for binary layout).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Ehdr {
    /// Magic number and identification.
    pub e_ident: [u8; 16],
    /// Object file type (ET_CORE).
    pub e_type: u16,
    /// Architecture (EM_X86_64).
    pub e_machine: u16,
    /// ELF version.
    pub e_version: u32,
    /// Entry point (0 for core dumps).
    pub e_entry: u64,
    /// Program header table offset.
    pub e_phoff: u64,
    /// Section header table offset (0 for core dumps).
    pub e_shoff: u64,
    /// Processor-specific flags.
    pub e_flags: u32,
    /// ELF header size.
    pub e_ehsize: u16,
    /// Program header entry size.
    pub e_phentsize: u16,
    /// Number of program header entries.
    pub e_phnum: u16,
    /// Section header entry size.
    pub e_shentsize: u16,
    /// Number of section header entries.
    pub e_shnum: u16,
    /// Section name string table index.
    pub e_shstrndx: u16,
}

impl Elf64Ehdr {
    /// Create a new ELF64 core dump header.
    pub fn new_core(phnum: u16) -> Self {
        let mut ident = [0u8; 16];
        ident[0..4].copy_from_slice(&ELF_MAGIC);
        ident[4] = ELFCLASS64;
        ident[5] = ELFDATA2LSB;
        ident[6] = EV_CURRENT;
        ident[7] = ELFOSABI_NONE;
        Self {
            e_ident: ident,
            e_type: ET_CORE,
            e_machine: EM_X86_64,
            e_version: EV_CURRENT as u32,
            e_entry: 0,
            e_phoff: ELF64_EHDR_SIZE as u64,
            e_shoff: 0,
            e_flags: 0,
            e_ehsize: ELF64_EHDR_SIZE as u16,
            e_phentsize: ELF64_PHDR_SIZE as u16,
            e_phnum: phnum,
            e_shentsize: 0,
            e_shnum: 0,
            e_shstrndx: 0,
        }
    }

    /// Encode the header into a byte buffer. Returns bytes written.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < ELF64_EHDR_SIZE {
            return Err(Error::InvalidArgument);
        }
        buf[0..16].copy_from_slice(&self.e_ident);
        buf[16..18].copy_from_slice(&self.e_type.to_le_bytes());
        buf[18..20].copy_from_slice(&self.e_machine.to_le_bytes());
        buf[20..24].copy_from_slice(&self.e_version.to_le_bytes());
        buf[24..32].copy_from_slice(&self.e_entry.to_le_bytes());
        buf[32..40].copy_from_slice(&self.e_phoff.to_le_bytes());
        buf[40..48].copy_from_slice(&self.e_shoff.to_le_bytes());
        buf[48..52].copy_from_slice(&self.e_flags.to_le_bytes());
        buf[52..54].copy_from_slice(&self.e_ehsize.to_le_bytes());
        buf[54..56].copy_from_slice(&self.e_phentsize.to_le_bytes());
        buf[56..58].copy_from_slice(&self.e_phnum.to_le_bytes());
        buf[58..60].copy_from_slice(&self.e_shentsize.to_le_bytes());
        buf[60..62].copy_from_slice(&self.e_shnum.to_le_bytes());
        buf[62..64].copy_from_slice(&self.e_shstrndx.to_le_bytes());
        Ok(ELF64_EHDR_SIZE)
    }
}

/// ELF64 program header entry.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Phdr {
    /// Segment type (PT_LOAD, PT_NOTE, etc.).
    pub p_type: u32,
    /// Segment flags (PF_R, PF_W, PF_X).
    pub p_flags: u32,
    /// Offset in the file.
    pub p_offset: u64,
    /// Virtual address.
    pub p_vaddr: u64,
    /// Physical address.
    pub p_paddr: u64,
    /// Size in file.
    pub p_filesz: u64,
    /// Size in memory.
    pub p_memsz: u64,
    /// Alignment.
    pub p_align: u64,
}

impl Elf64Phdr {
    /// Create a new PT_LOAD program header.
    pub fn new_load(region: &MemoryRegion) -> Self {
        Self {
            p_type: PT_LOAD,
            p_flags: region.elf_flags(),
            p_offset: region.file_offset,
            p_vaddr: region.virt_addr,
            p_paddr: region.phys_addr,
            p_filesz: region.size,
            p_memsz: region.size,
            p_align: 4096,
        }
    }

    /// Create a new PT_NOTE program header.
    pub fn new_note(offset: u64, size: u64) -> Self {
        Self {
            p_type: PT_NOTE,
            p_flags: PF_R,
            p_offset: offset,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: size,
            p_memsz: size,
            p_align: 4,
        }
    }

    /// Encode the program header into a byte buffer.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < ELF64_PHDR_SIZE {
            return Err(Error::InvalidArgument);
        }
        buf[0..4].copy_from_slice(&self.p_type.to_le_bytes());
        buf[4..8].copy_from_slice(&self.p_flags.to_le_bytes());
        buf[8..16].copy_from_slice(&self.p_offset.to_le_bytes());
        buf[16..24].copy_from_slice(&self.p_vaddr.to_le_bytes());
        buf[24..32].copy_from_slice(&self.p_paddr.to_le_bytes());
        buf[32..40].copy_from_slice(&self.p_filesz.to_le_bytes());
        buf[40..48].copy_from_slice(&self.p_memsz.to_le_bytes());
        buf[48..56].copy_from_slice(&self.p_align.to_le_bytes());
        Ok(ELF64_PHDR_SIZE)
    }
}

// ── Crash Dump Collector ────────────────────────────────────────────────────

/// Statistics about the crash dump collection.
#[derive(Debug, Clone, Copy)]
pub struct CrashDumpStats {
    /// Number of CPUs whose state was captured.
    pub cpus_captured: u32,
    /// Number of memory regions registered.
    pub regions_registered: u32,
    /// Total bytes of memory in the dump.
    pub total_memory_bytes: u64,
    /// Number of vmcoreinfo entries.
    pub vmcoreinfo_entries: u32,
    /// Total file size of the dump (header + notes + data).
    pub estimated_file_size: u64,
}

/// Main crash dump collector.
///
/// Accumulates CPU register states, memory regions, and vmcoreinfo
/// entries, then builds an ELF core dump describing the system state.
pub struct CrashDumpCollector {
    /// Crash reason.
    crash_reason: CrashReason,
    /// Timestamp (TSC or similar) of the crash.
    crash_timestamp: u64,
    /// CPU register states (one per online CPU).
    cpu_states: [CpuRegisterState; MAX_CPUS],
    /// Number of CPUs captured.
    cpu_count: u32,
    /// ID of the CPU that triggered the crash.
    crashing_cpu: u32,
    /// Physical memory regions to dump.
    regions: [MemoryRegion; MAX_REGIONS],
    /// Number of active memory regions.
    region_count: usize,
    /// Vmcoreinfo entries.
    vmcoreinfo: [VmcoreinfoEntry; MAX_VMCOREINFO_ENTRIES],
    /// Number of active vmcoreinfo entries.
    vmcoreinfo_count: usize,
    /// Whether the collector has been finalized (headers built).
    finalized: bool,
}

impl CrashDumpCollector {
    /// Create a new crash dump collector.
    pub const fn new() -> Self {
        Self {
            crash_reason: CrashReason::Unknown,
            crash_timestamp: 0,
            cpu_states: [const { CpuRegisterState::new() }; MAX_CPUS],
            cpu_count: 0,
            crashing_cpu: 0,
            regions: [const { MemoryRegion::new() }; MAX_REGIONS],
            region_count: 0,
            vmcoreinfo: [const { VmcoreinfoEntry::new() }; MAX_VMCOREINFO_ENTRIES],
            vmcoreinfo_count: 0,
            finalized: false,
        }
    }

    /// Set the crash reason.
    pub fn set_crash_reason(&mut self, reason: CrashReason, timestamp: u64) {
        self.crash_reason = reason;
        self.crash_timestamp = timestamp;
    }

    /// Get the crash reason.
    pub fn crash_reason(&self) -> CrashReason {
        self.crash_reason
    }

    /// Get the crash timestamp.
    pub fn crash_timestamp(&self) -> u64 {
        self.crash_timestamp
    }

    /// Capture register state for a CPU.
    pub fn capture_cpu_state(
        &mut self,
        cpu_id: u32,
        state: &CpuRegisterState,
        is_crashing: bool,
    ) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.cpu_states[idx].valid {
            return Err(Error::AlreadyExists);
        }
        self.cpu_states[idx] = *state;
        self.cpu_states[idx].valid = true;
        self.cpu_states[idx].cpu_id = cpu_id;
        self.cpu_states[idx].is_crashing_cpu = is_crashing;
        self.cpu_count += 1;
        if is_crashing {
            self.crashing_cpu = cpu_id;
        }
        Ok(())
    }

    /// Get the register state for a CPU.
    pub fn get_cpu_state(&self, cpu_id: u32) -> Option<&CpuRegisterState> {
        let idx = cpu_id as usize;
        if idx < MAX_CPUS && self.cpu_states[idx].valid {
            Some(&self.cpu_states[idx])
        } else {
            None
        }
    }

    /// Get the number of CPUs captured.
    pub fn cpu_count(&self) -> u32 {
        self.cpu_count
    }

    /// Get the crashing CPU ID.
    pub fn crashing_cpu(&self) -> u32 {
        self.crashing_cpu
    }

    /// Add a physical memory region to the dump.
    pub fn add_memory_region(
        &mut self,
        phys_addr: u64,
        virt_addr: u64,
        size: u64,
        region_type: MemoryRegionType,
        readable: bool,
        writable: bool,
    ) -> Result<()> {
        if self.region_count >= MAX_REGIONS {
            return Err(Error::OutOfMemory);
        }
        let slot = self.region_count;
        self.regions[slot].active = true;
        self.regions[slot].phys_addr = phys_addr;
        self.regions[slot].virt_addr = virt_addr;
        self.regions[slot].size = size;
        self.regions[slot].readable = readable;
        self.regions[slot].writable = writable;
        self.regions[slot].region_type = region_type;
        self.region_count += 1;
        Ok(())
    }

    /// Get the number of memory regions.
    pub fn region_count(&self) -> usize {
        self.region_count
    }

    /// Get a memory region by index.
    pub fn get_region(&self, idx: usize) -> Option<&MemoryRegion> {
        if idx < self.region_count && self.regions[idx].active {
            Some(&self.regions[idx])
        } else {
            None
        }
    }

    /// Add a vmcoreinfo key=value entry.
    pub fn add_vmcoreinfo(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        if self.vmcoreinfo_count >= MAX_VMCOREINFO_ENTRIES {
            return Err(Error::OutOfMemory);
        }
        let slot = self.vmcoreinfo_count;
        self.vmcoreinfo[slot].set(key, value)?;
        self.vmcoreinfo_count += 1;
        Ok(())
    }

    /// Add standard vmcoreinfo entries (OSRELEASE, PAGESIZE, etc.).
    pub fn add_standard_vmcoreinfo(&mut self) -> Result<()> {
        self.add_vmcoreinfo(b"OSRELEASE", b"oncrix-0.1.0")?;
        self.add_vmcoreinfo(b"PAGESIZE", b"4096")?;
        self.add_vmcoreinfo(b"CRASHTIME_TICKS", b"0")?;

        let mut reason_buf = [0u8; 16];
        let code = self.crash_reason.code();
        let len = encode_u32_decimal(code, &mut reason_buf);
        self.add_vmcoreinfo(b"CRASH_REASON", &reason_buf[..len])?;

        let mut cpu_buf = [0u8; 16];
        let len = encode_u32_decimal(self.cpu_count, &mut cpu_buf);
        self.add_vmcoreinfo(b"CPUS", &cpu_buf[..len])?;
        Ok(())
    }

    /// Compute the total size of the PT_NOTE segment.
    pub fn compute_note_size(&self) -> u64 {
        // Each CPU prstatus note:
        // namesz(4) + descsz(4) + type(4) + name(aligned) + data(aligned)
        let name_aligned = align_up(NOTE_NAME_CORE.len(), 4);
        let data_size = CpuRegisterState::note_data_size();
        let data_aligned = align_up(data_size, 4);
        let per_cpu_note = 12 + name_aligned + data_aligned;
        let cpu_notes = per_cpu_note * self.cpu_count as usize;

        // Vmcoreinfo note
        let vmcore_data_size = self.compute_vmcoreinfo_data_size();
        let vmcore_name_aligned = align_up(NOTE_NAME_VMCOREINFO.len(), 4);
        let vmcore_data_aligned = align_up(vmcore_data_size, 4);
        let vmcore_note = if vmcore_data_size > 0 {
            12 + vmcore_name_aligned + vmcore_data_aligned
        } else {
            0
        };

        (cpu_notes + vmcore_note) as u64
    }

    /// Compute the total data size of vmcoreinfo entries.
    fn compute_vmcoreinfo_data_size(&self) -> usize {
        let mut total = 0;
        for i in 0..self.vmcoreinfo_count {
            if self.vmcoreinfo[i].active {
                // "KEY=VALUE\n"
                total += self.vmcoreinfo[i].key_len + 1 + self.vmcoreinfo[i].value_len + 1;
            }
        }
        total
    }

    /// Finalize the dump layout: compute file offsets for all regions.
    pub fn finalize(&mut self) -> Result<()> {
        // Program headers: 1 (PT_NOTE) + region_count (PT_LOAD)
        let phdr_count = 1 + self.region_count;
        let phdr_table_size = phdr_count * ELF64_PHDR_SIZE;
        let note_offset = (ELF64_EHDR_SIZE + phdr_table_size) as u64;
        let note_size = self.compute_note_size();
        let data_start = align_up_u64(note_offset + note_size, 4096);

        let mut current_offset = data_start;
        for i in 0..self.region_count {
            if self.regions[i].active {
                self.regions[i].file_offset = current_offset;
                current_offset += self.regions[i].size;
            }
        }
        self.finalized = true;
        Ok(())
    }

    /// Build the ELF header for the core dump.
    pub fn build_elf_header(&self) -> Result<Elf64Ehdr> {
        if !self.finalized {
            return Err(Error::InvalidArgument);
        }
        let phnum = (1 + self.region_count) as u16;
        Ok(Elf64Ehdr::new_core(phnum))
    }

    /// Build all program headers into a buffer.
    ///
    /// Returns the number of bytes written.
    pub fn build_program_headers(&self, buf: &mut [u8]) -> Result<usize> {
        if !self.finalized {
            return Err(Error::InvalidArgument);
        }
        let phdr_count = 1 + self.region_count;
        let needed = phdr_count * ELF64_PHDR_SIZE;
        if buf.len() < needed {
            return Err(Error::InvalidArgument);
        }

        let mut pos = 0;

        // PT_NOTE header
        let phdr_table_size = phdr_count * ELF64_PHDR_SIZE;
        let note_offset = (ELF64_EHDR_SIZE + phdr_table_size) as u64;
        let note_size = self.compute_note_size();
        let note_phdr = Elf64Phdr::new_note(note_offset, note_size);
        pos += note_phdr.encode(&mut buf[pos..])?;

        // PT_LOAD headers
        for i in 0..self.region_count {
            if self.regions[i].active {
                let load_phdr = Elf64Phdr::new_load(&self.regions[i]);
                pos += load_phdr.encode(&mut buf[pos..])?;
            }
        }
        Ok(pos)
    }

    /// Build a single CPU prstatus ELF note into a buffer.
    ///
    /// Returns bytes written.
    pub fn build_cpu_note(&self, cpu_id: u32, buf: &mut [u8]) -> Result<usize> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS || !self.cpu_states[idx].valid {
            return Err(Error::NotFound);
        }
        let name_len = NOTE_NAME_CORE.len() as u32;
        let data_size = CpuRegisterState::note_data_size() as u32;
        let name_aligned = align_up(name_len as usize, 4);
        let data_aligned = align_up(data_size as usize, 4);
        let total = 12 + name_aligned + data_aligned;
        if buf.len() < total {
            return Err(Error::InvalidArgument);
        }

        let mut pos = 0;
        // namesz
        buf[pos..pos + 4].copy_from_slice(&name_len.to_le_bytes());
        pos += 4;
        // descsz
        buf[pos..pos + 4].copy_from_slice(&data_size.to_le_bytes());
        pos += 4;
        // type
        buf[pos..pos + 4].copy_from_slice(&NT_PRSTATUS.to_le_bytes());
        pos += 4;
        // name (padded)
        buf[pos..pos + NOTE_NAME_CORE.len()].copy_from_slice(NOTE_NAME_CORE);
        pos += name_aligned;
        // data
        let written = self.cpu_states[idx].encode(&mut buf[pos..pos + data_aligned])?;
        pos += align_up(written, 4);
        Ok(pos)
    }

    /// Build the vmcoreinfo note into a buffer.
    ///
    /// Returns bytes written.
    pub fn build_vmcoreinfo_note(&self, buf: &mut [u8]) -> Result<usize> {
        if self.vmcoreinfo_count == 0 {
            return Ok(0);
        }
        // First, encode all vmcoreinfo data
        let mut data_buf = [0u8; MAX_NOTE_SIZE];
        let mut data_len = 0;
        for i in 0..self.vmcoreinfo_count {
            let written = self.vmcoreinfo[i].encode(&mut data_buf[data_len..])?;
            data_len += written;
        }

        let name_len = NOTE_NAME_VMCOREINFO.len() as u32;
        let name_aligned = align_up(name_len as usize, 4);
        let data_aligned = align_up(data_len, 4);
        let total = 12 + name_aligned + data_aligned;
        if buf.len() < total {
            return Err(Error::InvalidArgument);
        }

        let mut pos = 0;
        buf[pos..pos + 4].copy_from_slice(&name_len.to_le_bytes());
        pos += 4;
        buf[pos..pos + 4].copy_from_slice(&(data_len as u32).to_le_bytes());
        pos += 4;
        buf[pos..pos + 4].copy_from_slice(&_NT_VMCOREINFO.to_le_bytes());
        pos += 4;
        buf[pos..pos + NOTE_NAME_VMCOREINFO.len()].copy_from_slice(NOTE_NAME_VMCOREINFO);
        pos += name_aligned;
        buf[pos..pos + data_len].copy_from_slice(&data_buf[..data_len]);
        pos += data_aligned;
        Ok(pos)
    }

    /// Compute dump statistics.
    pub fn stats(&self) -> CrashDumpStats {
        let mut total_mem = 0u64;
        for i in 0..self.region_count {
            if self.regions[i].active {
                total_mem += self.regions[i].size;
            }
        }
        let phdr_count = 1 + self.region_count;
        let note_size = self.compute_note_size();
        let headers_size = (ELF64_EHDR_SIZE + phdr_count * ELF64_PHDR_SIZE) as u64;
        CrashDumpStats {
            cpus_captured: self.cpu_count,
            regions_registered: self.region_count as u32,
            total_memory_bytes: total_mem,
            vmcoreinfo_entries: self.vmcoreinfo_count as u32,
            estimated_file_size: headers_size + note_size + total_mem,
        }
    }

    /// Check whether the collector has been finalized.
    pub fn is_finalized(&self) -> bool {
        self.finalized
    }

    /// Reset the collector for reuse.
    pub fn reset(&mut self) {
        self.crash_reason = CrashReason::Unknown;
        self.crash_timestamp = 0;
        for state in &mut self.cpu_states {
            state.valid = false;
        }
        self.cpu_count = 0;
        self.crashing_cpu = 0;
        for region in &mut self.regions {
            region.active = false;
        }
        self.region_count = 0;
        for entry in &mut self.vmcoreinfo {
            entry.active = false;
        }
        self.vmcoreinfo_count = 0;
        self.finalized = false;
    }
}

// ── Helper Functions ────────────────────────────────────────────────────────

/// Align `val` up to the next multiple of `align`.
fn align_up(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}

/// Align a u64 value up to the next multiple of `align`.
fn align_up_u64(val: u64, align: u64) -> u64 {
    (val + align - 1) & !(align - 1)
}

/// Encode a u32 as decimal ASCII. Returns the number of bytes written.
fn encode_u32_decimal(val: u32, buf: &mut [u8]) -> usize {
    if val == 0 {
        if !buf.is_empty() {
            buf[0] = b'0';
        }
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut n = val;
    let mut pos = 0;
    while n > 0 {
        tmp[pos] = b'0' + (n % 10) as u8;
        n /= 10;
        pos += 1;
    }
    if buf.len() < pos {
        return 0;
    }
    for i in 0..pos {
        buf[i] = tmp[pos - 1 - i];
    }
    pos
}
