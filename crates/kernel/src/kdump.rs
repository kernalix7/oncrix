// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel crash dump (kdump) support.
//!
//! Provides infrastructure for capturing kernel memory state when a
//! panic occurs. The crash dump is stored as an ELF core file
//! (`vmcore`) that can be analyzed post-mortem with tools like
//! `crash` or `gdb`.
//!
//! # Architecture
//!
//! ```text
//!  Boot time:
//!    reserve_crash_kernel_region()
//!      └── CrashRegion marked in memory map
//!
//!  Panic path:
//!    panic_notifier fires
//!      └── KdumpManager::trigger_dump()
//!            ├── capture_registers()
//!            ├── build_vmcore_header() → ELF phdr per region
//!            └── write crash data to reserved region
//!
//!  Post-crash:
//!    second kernel (or kexec) reads vmcore from reserved region
//! ```
//!
//! # Memory Regions
//!
//! The crash dump captures one or more physical memory regions.
//! Each region becomes an ELF `PT_LOAD` program header in the
//! vmcore. The elfcorehdr (a small ELF header block) is built
//! at dump time and describes all captured regions.
//!
//! Reference: Linux `kernel/crash_core.c`, `fs/proc/vmcore.c`,
//! `include/linux/crash_core.h`.

use oncrix_lib::{Error, Result};

// -------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------

/// Maximum number of crash memory regions.
const MAX_CRASH_REGIONS: usize = 64;

/// Maximum number of ELF program headers in a vmcore.
const MAX_PHDR_ENTRIES: usize = 64;

/// Maximum number of CPU register snapshots (one per CPU).
const MAX_CPUS: usize = 64;

/// Maximum number of panic notifier callbacks registered with
/// the kdump subsystem.
const MAX_NOTIFIERS: usize = 16;

/// Maximum length of a notifier name in bytes.
const MAX_NOTIFIER_NAME_LEN: usize = 64;

/// ELF magic bytes: 0x7f 'E' 'L' 'F'.
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// ELF class for 64-bit objects (ELFCLASS64).
const ELFCLASS64: u8 = 2;

/// ELF data encoding: little-endian (ELFDATA2LSB).
const ELFDATA2LSB: u8 = 1;

/// ELF version: current (EV_CURRENT).
const EV_CURRENT: u8 = 1;

/// ELF OS/ABI: System V (ELFOSABI_NONE).
const ELFOSABI_NONE: u8 = 0;

/// ELF type: core file (ET_CORE).
const ET_CORE: u16 = 4;

/// ELF machine: AMD x86-64 (EM_X86_64).
const EM_X86_64: u16 = 62;

/// ELF program header type: loadable segment (PT_LOAD).
const PT_LOAD: u32 = 1;

/// ELF program header type: note segment (PT_NOTE).
const PT_NOTE: u32 = 4;

/// ELF program header flags: readable (PF_R).
const PF_R: u32 = 0x4;

/// Size of an ELF64 file header in bytes.
const ELF64_EHDR_SIZE: usize = 64;

/// Size of an ELF64 program header entry in bytes.
const ELF64_PHDR_SIZE: usize = 56;

// -------------------------------------------------------------------
// CrashRegionType
// -------------------------------------------------------------------

/// Classification of a physical memory region for crash dump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CrashRegionType {
    /// Conventional RAM — contains kernel/user data.
    #[default]
    Ram,
    /// Reserved memory that should not be included in the dump.
    Reserved,
    /// ACPI reclaimable memory.
    AcpiReclaimable,
    /// ACPI NVS (Non-Volatile Storage) memory.
    AcpiNvs,
    /// Memory-mapped I/O region.
    Mmio,
    /// Crash kernel reserved region (destination for dump data).
    CrashKernel,
    /// ELF core header region.
    ElfCoreHdr,
}

// -------------------------------------------------------------------
// CrashRegion
// -------------------------------------------------------------------

/// A physical memory region descriptor for the crash dump.
///
/// Each region maps a contiguous range of physical memory that
/// may be captured in the vmcore.
#[derive(Debug, Clone, Copy)]
pub struct CrashRegion {
    /// Physical base address of the region.
    pub base: u64,
    /// Size of the region in bytes.
    pub size: u64,
    /// Type/classification of this region.
    pub region_type: CrashRegionType,
    /// Whether this region should be included in the vmcore.
    pub include_in_dump: bool,
    /// Whether this slot is in use.
    pub in_use: bool,
}

impl CrashRegion {
    /// Creates an empty (unused) region slot.
    const fn empty() -> Self {
        Self {
            base: 0,
            size: 0,
            region_type: CrashRegionType::Ram,
            include_in_dump: false,
            in_use: false,
        }
    }

    /// Returns the end address (exclusive) of this region.
    pub fn end(&self) -> u64 {
        self.base.saturating_add(self.size)
    }

    /// Returns whether `addr` falls within this region.
    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }
}

// -------------------------------------------------------------------
// Elf64Ehdr
// -------------------------------------------------------------------

/// ELF64 file header for the vmcore.
///
/// This is a simplified representation — the actual on-disk
/// format is `repr(C)` and matches the ELF specification.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Ehdr {
    /// ELF identification bytes (magic + class + encoding).
    pub e_ident: [u8; 16],
    /// Object file type (ET_CORE for crash dumps).
    pub e_type: u16,
    /// Architecture (EM_X86_64).
    pub e_machine: u16,
    /// ELF version (EV_CURRENT).
    pub e_version: u32,
    /// Entry point virtual address (0 for core files).
    pub e_entry: u64,
    /// Program header table file offset.
    pub e_phoff: u64,
    /// Section header table file offset (0 for core files).
    pub e_shoff: u64,
    /// Processor-specific flags.
    pub e_flags: u32,
    /// ELF header size in bytes.
    pub e_ehsize: u16,
    /// Size of one program header entry.
    pub e_phentsize: u16,
    /// Number of program header entries.
    pub e_phnum: u16,
    /// Size of one section header entry (0 for core files).
    pub e_shentsize: u16,
    /// Number of section header entries (0 for core files).
    pub e_shnum: u16,
    /// Section name string table index (0 for core files).
    pub e_shstrndx: u16,
}

impl Default for Elf64Ehdr {
    fn default() -> Self {
        let mut ident = [0u8; 16];
        ident[0] = ELF_MAGIC[0];
        ident[1] = ELF_MAGIC[1];
        ident[2] = ELF_MAGIC[2];
        ident[3] = ELF_MAGIC[3];
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
            e_phnum: 0,
            e_shentsize: 0,
            e_shnum: 0,
            e_shstrndx: 0,
        }
    }
}

// -------------------------------------------------------------------
// Elf64Phdr
// -------------------------------------------------------------------

/// ELF64 program header for a vmcore segment.
///
/// Each loadable memory region in the crash dump is described
/// by one program header entry.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Elf64Phdr {
    /// Segment type (PT_LOAD for memory, PT_NOTE for metadata).
    pub p_type: u32,
    /// Segment flags (PF_R for readable).
    pub p_flags: u32,
    /// Offset of the segment data in the vmcore file.
    pub p_offset: u64,
    /// Virtual address of the segment.
    pub p_vaddr: u64,
    /// Physical address of the segment.
    pub p_paddr: u64,
    /// Size of the segment in the file.
    pub p_filesz: u64,
    /// Size of the segment in memory.
    pub p_memsz: u64,
    /// Segment alignment.
    pub p_align: u64,
}

// -------------------------------------------------------------------
// VmcoreHeader
// -------------------------------------------------------------------

/// Assembled vmcore header containing the ELF header and all
/// program headers.
///
/// This is the elfcorehdr that describes the layout of the
/// crash dump. It is written to the reserved elfcorehdr region
/// during a panic.
#[derive(Debug, Clone, Copy)]
pub struct VmcoreHeader {
    /// ELF file header.
    pub ehdr: Elf64Ehdr,
    /// Program header entries (one per memory region + one for
    /// the PT_NOTE segment).
    pub phdrs: [Elf64Phdr; MAX_PHDR_ENTRIES],
    /// Number of program headers actually populated.
    pub phdr_count: usize,
    /// Total size of the vmcore header in bytes (ehdr + phdrs).
    pub total_size: usize,
}

impl VmcoreHeader {
    /// Creates an empty vmcore header.
    const fn empty() -> Self {
        Self {
            ehdr: Elf64Ehdr {
                e_ident: [0; 16],
                e_type: ET_CORE,
                e_machine: EM_X86_64,
                e_version: 1,
                e_entry: 0,
                e_phoff: ELF64_EHDR_SIZE as u64,
                e_shoff: 0,
                e_flags: 0,
                e_ehsize: ELF64_EHDR_SIZE as u16,
                e_phentsize: ELF64_PHDR_SIZE as u16,
                e_phnum: 0,
                e_shentsize: 0,
                e_shnum: 0,
                e_shstrndx: 0,
            },
            phdrs: [Elf64Phdr {
                p_type: 0,
                p_flags: 0,
                p_offset: 0,
                p_vaddr: 0,
                p_paddr: 0,
                p_filesz: 0,
                p_memsz: 0,
                p_align: 0,
            }; MAX_PHDR_ENTRIES],
            phdr_count: 0,
            total_size: 0,
        }
    }
}

// -------------------------------------------------------------------
// CpuCrashState
// -------------------------------------------------------------------

/// Snapshot of CPU register state captured during a panic.
///
/// One instance is saved per CPU that was online when the panic
/// occurred.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuCrashState {
    /// General-purpose register RAX.
    pub rax: u64,
    /// General-purpose register RBX.
    pub rbx: u64,
    /// General-purpose register RCX.
    pub rcx: u64,
    /// General-purpose register RDX.
    pub rdx: u64,
    /// Source index register RSI.
    pub rsi: u64,
    /// Destination index register RDI.
    pub rdi: u64,
    /// Base pointer register RBP.
    pub rbp: u64,
    /// Stack pointer register RSP.
    pub rsp: u64,
    /// Extended register R8.
    pub r8: u64,
    /// Extended register R9.
    pub r9: u64,
    /// Extended register R10.
    pub r10: u64,
    /// Extended register R11.
    pub r11: u64,
    /// Extended register R12.
    pub r12: u64,
    /// Extended register R13.
    pub r13: u64,
    /// Extended register R14.
    pub r14: u64,
    /// Extended register R15.
    pub r15: u64,
    /// Instruction pointer at time of panic.
    pub rip: u64,
    /// Processor flags register.
    pub rflags: u64,
    /// Code segment selector.
    pub cs: u64,
    /// Stack segment selector.
    pub ss: u64,
    /// CR3 — page table base register.
    pub cr3: u64,
    /// CR2 — page fault linear address.
    pub cr2: u64,
    /// CPU identifier.
    pub cpu_id: u32,
    /// Whether this slot contains valid register data.
    pub valid: bool,
}

impl CpuCrashState {
    /// Creates an empty (invalid) CPU state.
    const fn empty() -> Self {
        Self {
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
            cs: 0,
            ss: 0,
            cr3: 0,
            cr2: 0,
            cpu_id: 0,
            valid: false,
        }
    }
}

// -------------------------------------------------------------------
// KdumpNotifier
// -------------------------------------------------------------------

/// A callback registered to be invoked during crash dump
/// capture.
///
/// Notifiers run in panic context — they must not allocate,
/// sleep, or take locks.
#[derive(Debug, Clone, Copy)]
pub struct KdumpNotifier {
    /// Human-readable name.
    name: [u8; MAX_NOTIFIER_NAME_LEN],
    /// Valid length of `name`.
    name_len: usize,
    /// Opaque callback identifier.
    pub callback_id: u64,
    /// Priority (lower = called first).
    pub priority: u8,
    /// Whether this notifier is enabled.
    pub enabled: bool,
    /// Whether this slot is occupied.
    in_use: bool,
}

impl KdumpNotifier {
    /// Creates an empty notifier slot.
    const fn empty() -> Self {
        Self {
            name: [0; MAX_NOTIFIER_NAME_LEN],
            name_len: 0,
            callback_id: 0,
            priority: 128,
            enabled: false,
            in_use: false,
        }
    }

    /// Returns the notifier name as a byte slice.
    pub fn name(&self) -> &[u8] {
        &self.name[..self.name_len]
    }
}

// -------------------------------------------------------------------
// KdumpConfig
// -------------------------------------------------------------------

/// Configuration for the kdump subsystem.
///
/// Holds the crash kernel reservation, elfcorehdr location,
/// and global enable/disable state.
#[derive(Debug, Clone, Copy)]
pub struct KdumpConfig {
    /// Physical address of the reserved crash kernel region.
    pub crash_kernel_base: u64,
    /// Size of the reserved crash kernel region in bytes.
    pub crash_kernel_size: u64,
    /// Physical address of the elfcorehdr region.
    pub elfcorehdr_base: u64,
    /// Size of the elfcorehdr region in bytes.
    pub elfcorehdr_size: u64,
    /// Whether kdump is globally enabled.
    pub enabled: bool,
    /// Whether a crash kernel image has been loaded.
    pub image_loaded: bool,
}

impl KdumpConfig {
    /// Creates a default (disabled) configuration.
    const fn empty() -> Self {
        Self {
            crash_kernel_base: 0,
            crash_kernel_size: 0,
            elfcorehdr_base: 0,
            elfcorehdr_size: 0,
            enabled: false,
            image_loaded: false,
        }
    }

    /// Returns whether kdump is ready to capture a dump.
    ///
    /// Requires: enabled, image loaded, and valid crash kernel
    /// reservation.
    pub fn is_ready(&self) -> bool {
        self.enabled && self.image_loaded && self.crash_kernel_size > 0
    }
}

// -------------------------------------------------------------------
// DumpState
// -------------------------------------------------------------------

/// Current state of a crash dump operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DumpState {
    /// No dump in progress.
    #[default]
    Idle,
    /// Dump capture is in progress.
    Capturing,
    /// Dump capture completed successfully.
    Complete,
    /// Dump capture failed.
    Failed,
}

// -------------------------------------------------------------------
// DumpStats
// -------------------------------------------------------------------

/// Statistics about a crash dump operation.
#[derive(Debug, Clone, Copy, Default)]
pub struct DumpStats {
    /// Number of memory regions captured.
    pub regions_captured: usize,
    /// Total bytes of memory captured.
    pub bytes_captured: u64,
    /// Number of CPUs whose state was captured.
    pub cpus_captured: usize,
    /// Number of notifiers that were invoked.
    pub notifiers_invoked: usize,
    /// Timestamp (TSC or similar) when dump started.
    pub start_tsc: u64,
    /// Timestamp when dump completed.
    pub end_tsc: u64,
}

// -------------------------------------------------------------------
// KdumpManager
// -------------------------------------------------------------------

/// Central manager for crash dump operations.
///
/// Manages the memory map of regions to capture, the crash
/// kernel reservation, CPU register snapshots, and the vmcore
/// header generation.
pub struct KdumpManager {
    /// Physical memory regions known to the system.
    regions: [CrashRegion; MAX_CRASH_REGIONS],
    /// Number of active regions.
    region_count: usize,
    /// Per-CPU register snapshots.
    cpu_states: [CpuCrashState; MAX_CPUS],
    /// Number of CPUs with valid register data.
    cpu_count: usize,
    /// Registered dump notifiers.
    notifiers: [KdumpNotifier; MAX_NOTIFIERS],
    /// Number of active notifiers.
    notifier_count: usize,
    /// Kdump configuration.
    config: KdumpConfig,
    /// Current dump state.
    state: DumpState,
    /// Statistics from the most recent dump operation.
    stats: DumpStats,
    /// Pre-built vmcore header (updated when regions change).
    vmcore_header: VmcoreHeader,
}

impl Default for KdumpManager {
    fn default() -> Self {
        Self::new()
    }
}

impl KdumpManager {
    /// Creates a new, unconfigured kdump manager.
    pub const fn new() -> Self {
        Self {
            regions: [CrashRegion::empty(); MAX_CRASH_REGIONS],
            region_count: 0,
            cpu_states: [CpuCrashState::empty(); MAX_CPUS],
            cpu_count: 0,
            notifiers: [KdumpNotifier::empty(); MAX_NOTIFIERS],
            notifier_count: 0,
            config: KdumpConfig::empty(),
            state: DumpState::Idle,
            stats: DumpStats {
                regions_captured: 0,
                bytes_captured: 0,
                cpus_captured: 0,
                notifiers_invoked: 0,
                start_tsc: 0,
                end_tsc: 0,
            },
            vmcore_header: VmcoreHeader::empty(),
        }
    }

    // ── Configuration ─────────────────────────────────────────────

    /// Configures the crash kernel reservation.
    ///
    /// The region at `[base, base+size)` is reserved for the
    /// crash kernel image and dump data. This must be called
    /// before enabling kdump.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `base` is zero or `size`
    ///   is zero.
    /// - [`Error::Busy`] if a dump is currently in progress.
    pub fn set_crash_kernel(&mut self, base: u64, size: u64) -> Result<()> {
        if base == 0 || size == 0 {
            return Err(Error::InvalidArgument);
        }
        if self.state == DumpState::Capturing {
            return Err(Error::Busy);
        }
        self.config.crash_kernel_base = base;
        self.config.crash_kernel_size = size;
        Ok(())
    }

    /// Configures the elfcorehdr reservation.
    ///
    /// The elfcorehdr region stores the ELF header that
    /// describes the vmcore layout. It is written at dump time.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `base` is zero or `size`
    ///   is zero.
    pub fn set_elfcorehdr(&mut self, base: u64, size: u64) -> Result<()> {
        if base == 0 || size == 0 {
            return Err(Error::InvalidArgument);
        }
        self.config.elfcorehdr_base = base;
        self.config.elfcorehdr_size = size;
        Ok(())
    }

    /// Marks a crash kernel image as loaded and enables kdump.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if no crash kernel region
    ///   has been reserved.
    pub fn load_crash_image(&mut self) -> Result<()> {
        if self.config.crash_kernel_size == 0 {
            return Err(Error::InvalidArgument);
        }
        self.config.image_loaded = true;
        self.config.enabled = true;
        Ok(())
    }

    /// Unloads the crash kernel image and disables kdump.
    pub fn unload_crash_image(&mut self) {
        self.config.image_loaded = false;
        self.config.enabled = false;
    }

    /// Returns a reference to the current kdump configuration.
    pub fn config(&self) -> &KdumpConfig {
        &self.config
    }

    /// Returns the current dump state.
    pub fn state(&self) -> DumpState {
        self.state
    }

    /// Returns statistics from the most recent dump.
    pub fn stats(&self) -> &DumpStats {
        &self.stats
    }

    // ── Memory Region Management ──────────────────────────────────

    /// Adds a physical memory region to the crash memory map.
    ///
    /// # Errors
    ///
    /// - [`Error::OutOfMemory`] if the region table is full.
    /// - [`Error::InvalidArgument`] if `size` is zero.
    /// - [`Error::AlreadyExists`] if a region with the same
    ///   base address already exists.
    pub fn add_region(
        &mut self,
        base: u64,
        size: u64,
        region_type: CrashRegionType,
        include_in_dump: bool,
    ) -> Result<usize> {
        if size == 0 {
            return Err(Error::InvalidArgument);
        }
        // Check for duplicate base address.
        let dup = self.regions[..self.region_count]
            .iter()
            .any(|r| r.in_use && r.base == base);
        if dup {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .regions
            .iter()
            .position(|r| !r.in_use)
            .ok_or(Error::OutOfMemory)?;

        self.regions[slot] = CrashRegion {
            base,
            size,
            region_type,
            include_in_dump,
            in_use: true,
        };
        self.region_count += 1;
        Ok(slot)
    }

    /// Removes a memory region by its base address.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no region exists at `base`.
    /// - [`Error::Busy`] if a dump is in progress.
    pub fn remove_region(&mut self, base: u64) -> Result<()> {
        if self.state == DumpState::Capturing {
            return Err(Error::Busy);
        }
        let idx = self
            .regions
            .iter()
            .position(|r| r.in_use && r.base == base)
            .ok_or(Error::NotFound)?;
        self.regions[idx] = CrashRegion::empty();
        self.region_count = self.region_count.saturating_sub(1);
        Ok(())
    }

    /// Returns the region at the given slot index.
    pub fn get_region(&self, index: usize) -> Option<&CrashRegion> {
        if index < MAX_CRASH_REGIONS && self.regions[index].in_use {
            Some(&self.regions[index])
        } else {
            None
        }
    }

    /// Returns the number of active memory regions.
    pub fn region_count(&self) -> usize {
        self.region_count
    }

    /// Finds the region containing a physical address.
    pub fn find_region(&self, addr: u64) -> Option<&CrashRegion> {
        self.regions.iter().find(|r| r.in_use && r.contains(addr))
    }

    /// Returns the total size of all dumpable regions in bytes.
    pub fn dumpable_size(&self) -> u64 {
        self.regions
            .iter()
            .filter(|r| r.in_use && r.include_in_dump)
            .fold(0u64, |acc, r| acc.saturating_add(r.size))
    }

    // ── CPU State Capture ─────────────────────────────────────────

    /// Captures register state for a CPU.
    ///
    /// Called from the panic path on each online CPU.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `cpu_id` exceeds
    ///   [`MAX_CPUS`].
    /// - [`Error::AlreadyExists`] if this CPU already has a
    ///   valid snapshot.
    pub fn capture_cpu_state(&mut self, cpu_id: u32, state: &CpuCrashState) -> Result<()> {
        let idx = cpu_id as usize;
        if idx >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.cpu_states[idx].valid {
            return Err(Error::AlreadyExists);
        }
        self.cpu_states[idx] = *state;
        self.cpu_states[idx].cpu_id = cpu_id;
        self.cpu_states[idx].valid = true;
        self.cpu_count += 1;
        Ok(())
    }

    /// Returns the register snapshot for a CPU, if captured.
    pub fn get_cpu_state(&self, cpu_id: u32) -> Option<&CpuCrashState> {
        let idx = cpu_id as usize;
        if idx < MAX_CPUS && self.cpu_states[idx].valid {
            Some(&self.cpu_states[idx])
        } else {
            None
        }
    }

    /// Returns the number of CPUs with captured state.
    pub fn cpu_count(&self) -> usize {
        self.cpu_count
    }

    /// Clears all CPU register snapshots.
    pub fn clear_cpu_states(&mut self) {
        self.cpu_states = [CpuCrashState::empty(); MAX_CPUS];
        self.cpu_count = 0;
    }

    // ── Notifier Management ───────────────────────────────────────

    /// Registers a dump notifier callback.
    ///
    /// Notifiers are invoked in priority order (lower value =
    /// called first) during crash dump capture.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if `name` is empty or too
    ///   long.
    /// - [`Error::OutOfMemory`] if the notifier table is full.
    /// - [`Error::AlreadyExists`] if a notifier with the same
    ///   `callback_id` already exists.
    pub fn register_notifier(&mut self, name: &[u8], callback_id: u64, priority: u8) -> Result<()> {
        if name.is_empty() || name.len() > MAX_NOTIFIER_NAME_LEN {
            return Err(Error::InvalidArgument);
        }
        // Check for duplicate.
        let dup = self
            .notifiers
            .iter()
            .any(|n| n.in_use && n.callback_id == callback_id);
        if dup {
            return Err(Error::AlreadyExists);
        }
        let slot = self
            .notifiers
            .iter_mut()
            .find(|n| !n.in_use)
            .ok_or(Error::OutOfMemory)?;

        slot.name = [0; MAX_NOTIFIER_NAME_LEN];
        let nlen = name.len().min(MAX_NOTIFIER_NAME_LEN);
        slot.name[..nlen].copy_from_slice(&name[..nlen]);
        slot.name_len = nlen;
        slot.callback_id = callback_id;
        slot.priority = priority;
        slot.enabled = true;
        slot.in_use = true;
        self.notifier_count += 1;
        Ok(())
    }

    /// Unregisters a dump notifier by callback ID.
    ///
    /// # Errors
    ///
    /// - [`Error::NotFound`] if no notifier with this ID exists.
    pub fn unregister_notifier(&mut self, callback_id: u64) -> Result<()> {
        let slot = self
            .notifiers
            .iter_mut()
            .find(|n| n.in_use && n.callback_id == callback_id)
            .ok_or(Error::NotFound)?;
        *slot = KdumpNotifier::empty();
        self.notifier_count = self.notifier_count.saturating_sub(1);
        Ok(())
    }

    /// Returns the number of registered notifiers.
    pub fn notifier_count(&self) -> usize {
        self.notifier_count
    }

    // ── Vmcore Header Generation ──────────────────────────────────

    /// Builds the vmcore ELF header from the current memory map.
    ///
    /// Creates one `PT_NOTE` program header for CPU state and
    /// one `PT_LOAD` program header for each dumpable memory
    /// region.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if no dumpable regions exist.
    /// - [`Error::OutOfMemory`] if the number of regions exceeds
    ///   the program header table capacity.
    pub fn build_vmcore_header(&mut self) -> Result<&VmcoreHeader> {
        let dumpable_count = self
            .regions
            .iter()
            .filter(|r| r.in_use && r.include_in_dump)
            .count();
        if dumpable_count == 0 {
            return Err(Error::InvalidArgument);
        }
        // +1 for the PT_NOTE segment.
        let total_phdrs = dumpable_count + 1;
        if total_phdrs > MAX_PHDR_ENTRIES {
            return Err(Error::OutOfMemory);
        }

        // Initialize ELF header.
        let mut ehdr = Elf64Ehdr::default();
        ehdr.e_phnum = total_phdrs as u16;

        // Calculate data offset: after ehdr + all phdrs.
        let header_size = ELF64_EHDR_SIZE + (total_phdrs * ELF64_PHDR_SIZE);
        let mut data_offset = header_size as u64;

        let mut phdrs = [Elf64Phdr::default(); MAX_PHDR_ENTRIES];
        let mut phdr_idx = 0;

        // PT_NOTE segment for CPU register state.
        let note_size = (self.cpu_count as u64) * (core::mem::size_of::<CpuCrashState>() as u64);
        phdrs[phdr_idx] = Elf64Phdr {
            p_type: PT_NOTE,
            p_flags: PF_R,
            p_offset: data_offset,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: note_size,
            p_memsz: note_size,
            p_align: 4,
        };
        data_offset = data_offset.saturating_add(note_size);
        phdr_idx += 1;

        // PT_LOAD segments for each dumpable region.
        for region in &self.regions {
            if !region.in_use || !region.include_in_dump {
                continue;
            }
            if phdr_idx >= MAX_PHDR_ENTRIES {
                break;
            }
            phdrs[phdr_idx] = Elf64Phdr {
                p_type: PT_LOAD,
                p_flags: PF_R,
                p_offset: data_offset,
                p_vaddr: region.base,
                p_paddr: region.base,
                p_filesz: region.size,
                p_memsz: region.size,
                p_align: 4096,
            };
            data_offset = data_offset.saturating_add(region.size);
            phdr_idx += 1;
        }

        self.vmcore_header = VmcoreHeader {
            ehdr,
            phdrs,
            phdr_count: phdr_idx,
            total_size: header_size,
        };

        Ok(&self.vmcore_header)
    }

    /// Returns the pre-built vmcore header, if available.
    pub fn vmcore_header(&self) -> Option<&VmcoreHeader> {
        if self.vmcore_header.phdr_count > 0 {
            Some(&self.vmcore_header)
        } else {
            None
        }
    }

    // ── Dump Trigger ──────────────────────────────────────────────

    /// Triggers a crash dump capture.
    ///
    /// This is the main entry point from the panic handler. It:
    /// 1. Transitions to `Capturing` state.
    /// 2. Invokes registered notifiers in priority order.
    /// 3. Builds the vmcore header.
    /// 4. Records statistics.
    ///
    /// The `invoke_callback` closure is called for each enabled
    /// notifier with its `callback_id`. It should return `true`
    /// if the callback succeeded.
    ///
    /// # Errors
    ///
    /// - [`Error::InvalidArgument`] if kdump is not ready.
    /// - [`Error::Busy`] if a dump is already in progress.
    pub fn trigger_dump<F>(&mut self, start_tsc: u64, mut invoke_callback: F) -> Result<&DumpStats>
    where
        F: FnMut(u64) -> bool,
    {
        if !self.config.is_ready() {
            return Err(Error::InvalidArgument);
        }
        if self.state == DumpState::Capturing {
            return Err(Error::Busy);
        }

        self.state = DumpState::Capturing;
        self.stats = DumpStats::default();
        self.stats.start_tsc = start_tsc;

        // Invoke notifiers in priority order.
        // We collect indices sorted by priority first to
        // avoid borrowing issues.
        let mut sorted_indices = [0usize; MAX_NOTIFIERS];
        let mut sorted_count = 0usize;
        for (i, n) in self.notifiers.iter().enumerate() {
            if n.in_use && n.enabled {
                sorted_indices[sorted_count] = i;
                sorted_count += 1;
            }
        }
        // Insertion sort by priority.
        for i in 1..sorted_count {
            let mut j = i;
            while j > 0 {
                let a = sorted_indices[j - 1];
                let b = sorted_indices[j];
                if self.notifiers[a].priority > self.notifiers[b].priority {
                    sorted_indices.swap(j - 1, j);
                }
                j -= 1;
            }
        }
        for i in 0..sorted_count {
            let cb_id = self.notifiers[sorted_indices[i]].callback_id;
            if invoke_callback(cb_id) {
                self.stats.notifiers_invoked += 1;
            }
        }

        // Build vmcore header.
        match self.build_vmcore_header() {
            Ok(_) => {
                self.stats.regions_captured = self
                    .regions
                    .iter()
                    .filter(|r| r.in_use && r.include_in_dump)
                    .count();
                self.stats.bytes_captured = self.dumpable_size();
                self.stats.cpus_captured = self.cpu_count;
                self.state = DumpState::Complete;
            }
            Err(_) => {
                self.state = DumpState::Failed;
            }
        }

        self.stats.end_tsc = start_tsc; // Caller updates later.
        Ok(&self.stats)
    }

    /// Resets the dump state back to idle.
    ///
    /// Called after the dump has been consumed (e.g., after
    /// reboot into the crash kernel).
    pub fn reset(&mut self) {
        self.state = DumpState::Idle;
        self.stats = DumpStats::default();
        self.clear_cpu_states();
        self.vmcore_header = VmcoreHeader::empty();
    }

    /// Returns `true` if kdump is configured and ready.
    pub fn is_ready(&self) -> bool {
        self.config.is_ready()
    }

    /// Returns `true` if the region table is empty.
    pub fn is_empty(&self) -> bool {
        self.region_count == 0
    }
}

impl core::fmt::Debug for KdumpManager {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KdumpManager")
            .field("region_count", &self.region_count)
            .field("cpu_count", &self.cpu_count)
            .field("notifier_count", &self.notifier_count)
            .field("state", &self.state)
            .field("config", &self.config)
            .finish()
    }
}
