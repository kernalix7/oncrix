// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! KVM-style hypervisor interface for ONCRIX.
//!
//! Provides a minimal hardware-assisted virtualization layer modeled
//! after Linux's KVM subsystem. Supports creation and management of
//! virtual machines with virtual CPUs and guest physical memory
//! mapping.
//!
//! # Architecture
//!
//! ```text
//!  KvmSystem (global manager, up to 8 VMs)
//!      │
//!      ├── Vm (virtual machine)
//!      │   ├── VmMemoryMap (up to 32 slots)
//!      │   │   └── VmMemorySlot (GPA → HPA mapping)
//!      │   └── Vcpu (up to 4 per VM)
//!      │       ├── VmRegisters (guest register state)
//!      │       └── VcpuState (Created/Running/Halted/Stopped)
//!      ...
//! ```
//!
//! Reference: Linux `arch/x86/kvm/`, `include/uapi/linux/kvm.h`.

use oncrix_lib::Error;

// -----------------------------------------------------------------------
// Constants: VMX control register bits
// -----------------------------------------------------------------------

/// CR0 bit: Protection Enable — required for VMX operation.
pub const CR0_PE: u64 = 1 << 0;

/// CR0 bit: Numeric Error — required for VMX operation.
pub const CR0_NE: u64 = 1 << 5;

/// CR0 bit: Paging — required for 64-bit VMX guests.
pub const CR0_PG: u64 = 1 << 31;

/// CR4 bit: VMX Enable — must be set to enter VMX operation.
pub const CR4_VMXE: u64 = 1 << 13;

/// CR4 bit: Physical Address Extension — required for 64-bit mode.
pub const CR4_PAE: u64 = 1 << 5;

/// CR4 bit: Page Size Extensions.
pub const CR4_PSE: u64 = 1 << 4;

/// CR4 bit: OS support for FXSAVE/FXRSTOR.
pub const CR4_OSFXSR: u64 = 1 << 9;

/// CR4 bit: OS support for XSAVE and processor extended states.
pub const CR4_OSXSAVE: u64 = 1 << 18;

/// Maximum number of VMs managed by [`KvmSystem`].
const MAX_VMS: usize = 8;

/// Maximum number of vCPUs per [`Vm`].
const MAX_VCPUS: usize = 4;

/// Maximum number of memory slots per [`VmMemoryMap`].
const MAX_MEMORY_SLOTS: usize = 32;

// -----------------------------------------------------------------------
// VmcsField
// -----------------------------------------------------------------------

/// Key VMCS (Virtual Machine Control Structure) field encodings.
///
/// Each variant carries the 32-bit encoding value used by the
/// `VMREAD` / `VMWRITE` instructions to address a specific field.
///
/// Reference: Intel SDM Vol. 3, Appendix B "Field Encoding in VMCS".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmcsField {
    /// Guest RIP (instruction pointer).
    GuestRip = 0x681E,
    /// Guest RSP (stack pointer).
    GuestRsp = 0x681C,
    /// Guest RFLAGS.
    GuestRflags = 0x6820,
    /// Guest CR0.
    GuestCr0 = 0x6800,
    /// Guest CR3 (page table base).
    GuestCr3 = 0x6802,
    /// Guest CR4.
    GuestCr4 = 0x6804,
    /// Guest CS selector.
    GuestCsSelector = 0x0802,
    /// Guest DS selector.
    GuestDsSelector = 0x0806,
    /// Guest ES selector.
    GuestEsSelector = 0x0800,
    /// Guest SS selector.
    GuestSsSelector = 0x0804,
    /// Guest FS selector.
    GuestFsSelector = 0x0808,
    /// Guest GS selector.
    GuestGsSelector = 0x080A,
    /// VM-exit reason field.
    VmExitReason = 0x4402,
    /// VM-exit qualification (additional exit details).
    ExitQualification = 0x6400,
    /// Guest physical address involved in the exit.
    GuestPhysicalAddress = 0x2400,
    /// VM-exit instruction length.
    VmExitInstructionLen = 0x440C,
    /// VM-exit instruction information.
    VmExitInstructionInfo = 0x440E,
}

impl VmcsField {
    /// Return the raw 32-bit encoding value for this VMCS field.
    pub const fn encoding(self) -> u32 {
        self as u32
    }
}

// -----------------------------------------------------------------------
// VmRegisters
// -----------------------------------------------------------------------

/// Guest virtual CPU register state.
///
/// Captures all general-purpose registers, the instruction pointer,
/// flags, control registers, and segment selectors needed to
/// fully describe the architectural state of a guest vCPU.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct VmRegisters {
    /// General-purpose register RAX.
    pub rax: u64,
    /// General-purpose register RBX.
    pub rbx: u64,
    /// General-purpose register RCX.
    pub rcx: u64,
    /// General-purpose register RDX.
    pub rdx: u64,
    /// General-purpose register RSI.
    pub rsi: u64,
    /// General-purpose register RDI.
    pub rdi: u64,
    /// Frame pointer register RBP.
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
    /// Instruction pointer.
    pub rip: u64,
    /// CPU flags register.
    pub rflags: u64,
    /// Control register 0 (protection/paging mode bits).
    pub cr0: u64,
    /// Control register 3 (page table base address).
    pub cr3: u64,
    /// Control register 4 (extension enable bits).
    pub cr4: u64,
    /// Code segment selector.
    pub cs: u16,
    /// Data segment selector.
    pub ds: u16,
    /// Extra segment selector.
    pub es: u16,
    /// Stack segment selector.
    pub ss: u16,
    /// FS segment selector.
    pub fs: u16,
    /// GS segment selector.
    pub gs: u16,
}

impl VmRegisters {
    /// Create a zeroed register set.
    pub const fn zero() -> Self {
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
            cr0: 0,
            cr3: 0,
            cr4: 0,
            cs: 0,
            ds: 0,
            es: 0,
            ss: 0,
            fs: 0,
            gs: 0,
        }
    }
}

impl Default for VmRegisters {
    fn default() -> Self {
        Self::zero()
    }
}

// -----------------------------------------------------------------------
// VmExitReason
// -----------------------------------------------------------------------

/// Reason for a VM exit (guest → host transition).
///
/// When the guest executes a sensitive instruction or triggers a
/// condition monitored by the VMM, control returns to the host
/// with one of these exit reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VmExitReason {
    /// Guest executed a HLT instruction.
    Halt,
    /// Guest performed a port I/O read (IN instruction).
    IoIn,
    /// Guest performed a port I/O write (OUT instruction).
    IoOut,
    /// Guest accessed a memory-mapped I/O region.
    Mmio,
    /// Guest executed a CPUID instruction.
    CpuId,
    /// Guest accessed a model-specific register (RDMSR/WRMSR).
    Msr,
    /// External interrupt delivered while guest was running.
    Interrupt,
    /// Guest initiated an orderly shutdown (triple fault, etc.).
    Shutdown,
    /// Exit reason not recognized or not yet handled.
    #[default]
    Unknown,
}

// -----------------------------------------------------------------------
// VmExitInfo
// -----------------------------------------------------------------------

/// Detailed information about a VM exit event.
///
/// Combines the high-level [`VmExitReason`] with the specific
/// parameters (port number, address, data value, access size) that
/// characterize the exit.
#[derive(Debug, Clone, Copy)]
pub struct VmExitInfo {
    /// High-level reason for the VM exit.
    pub reason: VmExitReason,
    /// I/O port number (for [`VmExitReason::IoIn`] /
    /// [`VmExitReason::IoOut`]).
    pub port: u16,
    /// Guest physical address (for [`VmExitReason::Mmio`]).
    pub address: u64,
    /// Data value read or written by the guest.
    pub data: u64,
    /// Access size in bytes (1, 2, 4, or 8).
    pub size: u8,
}

impl VmExitInfo {
    /// Create a new exit info with only a reason and zeroed
    /// details.
    pub const fn new(reason: VmExitReason) -> Self {
        Self {
            reason,
            port: 0,
            address: 0,
            data: 0,
            size: 0,
        }
    }
}

impl Default for VmExitInfo {
    fn default() -> Self {
        Self::new(VmExitReason::Unknown)
    }
}

// -----------------------------------------------------------------------
// VcpuState
// -----------------------------------------------------------------------

/// Lifecycle state of a virtual CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum VcpuState {
    /// The vCPU has been created but never started.
    #[default]
    Created,
    /// The vCPU is currently executing guest code.
    Running,
    /// The vCPU executed HLT and is waiting for an interrupt.
    Halted,
    /// The vCPU has been explicitly stopped.
    Stopped,
}

// -----------------------------------------------------------------------
// Vcpu
// -----------------------------------------------------------------------

/// A virtual CPU belonging to a [`Vm`].
///
/// Each `Vcpu` maintains its own register state, execution state,
/// and the most recent VM-exit information. The host drives guest
/// execution via [`Vcpu::run`] and handles exits in a loop.
pub struct Vcpu {
    /// Unique identifier of this vCPU within its parent VM.
    id: u32,
    /// Current lifecycle state.
    state: VcpuState,
    /// Architectural register state of the guest.
    regs: VmRegisters,
    /// Information about the most recent VM exit.
    last_exit: VmExitInfo,
}

impl Vcpu {
    /// Create a new vCPU with the given identifier.
    ///
    /// The vCPU starts in [`VcpuState::Created`] with zeroed
    /// registers.
    pub const fn new(id: u32) -> Self {
        Self {
            id,
            state: VcpuState::Created,
            regs: VmRegisters::zero(),
            last_exit: VmExitInfo::new(VmExitReason::Unknown),
        }
    }

    /// Return this vCPU's identifier.
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Return the current lifecycle state.
    pub const fn state(&self) -> VcpuState {
        self.state
    }

    /// Return a reference to the most recent VM-exit info.
    pub const fn last_exit(&self) -> &VmExitInfo {
        &self.last_exit
    }

    /// Enter the guest and execute until a VM exit occurs.
    ///
    /// On success, returns the exit information describing why the
    /// guest stopped. The caller is responsible for handling the
    /// exit (emulating I/O, injecting interrupts, etc.) before
    /// calling `run` again.
    ///
    /// Returns `Err(Error::InvalidArgument)` if the vCPU is in
    /// [`VcpuState::Stopped`].
    pub fn run(&mut self) -> Result<&VmExitInfo, Error> {
        if self.state == VcpuState::Stopped {
            return Err(Error::InvalidArgument);
        }
        self.state = VcpuState::Running;
        // Stub: In a real implementation this would execute
        // VMLAUNCH/VMRESUME. For now, simulate an immediate halt
        // exit so the interface is exercisable.
        self.last_exit = VmExitInfo::new(VmExitReason::Halt);
        self.state = VcpuState::Halted;
        Ok(&self.last_exit)
    }

    /// Execute a single guest instruction and return.
    ///
    /// This is the single-step equivalent of [`Vcpu::run`],
    /// useful for debugging guest code.
    ///
    /// Returns `Err(Error::InvalidArgument)` if the vCPU is in
    /// [`VcpuState::Stopped`].
    pub fn step(&mut self) -> Result<&VmExitInfo, Error> {
        if self.state == VcpuState::Stopped {
            return Err(Error::InvalidArgument);
        }
        self.state = VcpuState::Running;
        // Stub: single-step via Monitor Trap Flag (MTF).
        self.last_exit = VmExitInfo::new(VmExitReason::Halt);
        self.state = VcpuState::Halted;
        Ok(&self.last_exit)
    }

    /// Replace the guest register state.
    pub fn set_regs(&mut self, regs: &VmRegisters) {
        self.regs = *regs;
    }

    /// Return a copy of the current guest register state.
    pub fn get_regs(&self) -> VmRegisters {
        self.regs
    }

    /// Explicitly stop this vCPU. Once stopped it cannot be
    /// resumed.
    pub fn stop(&mut self) {
        self.state = VcpuState::Stopped;
    }
}

// -----------------------------------------------------------------------
// VmMemorySlot
// -----------------------------------------------------------------------

/// A mapping from a guest physical address range to a host
/// physical address range.
///
/// The VMM uses memory slots to define the guest's physical memory
/// layout. Each slot maps a contiguous region of guest physical
/// addresses (GPA) to a contiguous region of host physical
/// addresses (HPA).
#[derive(Debug, Clone, Copy)]
pub struct VmMemorySlot {
    /// Slot identifier.
    pub slot: u32,
    /// Starting guest physical address.
    pub guest_phys_addr: u64,
    /// Starting host physical address.
    pub host_phys_addr: u64,
    /// Size of the region in bytes.
    pub memory_size: u64,
}

impl VmMemorySlot {
    /// Create a new memory slot mapping.
    pub const fn new(
        slot: u32,
        guest_phys_addr: u64,
        host_phys_addr: u64,
        memory_size: u64,
    ) -> Self {
        Self {
            slot,
            guest_phys_addr,
            host_phys_addr,
            memory_size,
        }
    }

    /// Check whether the given GPA falls within this slot.
    pub const fn contains_gpa(&self, gpa: u64) -> bool {
        gpa >= self.guest_phys_addr && gpa < self.guest_phys_addr.wrapping_add(self.memory_size)
    }

    /// Translate a GPA to an HPA using this slot's mapping.
    ///
    /// Returns `None` if the GPA is outside this slot.
    pub const fn translate(&self, gpa: u64) -> Option<u64> {
        if self.contains_gpa(gpa) {
            let offset = gpa.wrapping_sub(self.guest_phys_addr);
            Some(self.host_phys_addr.wrapping_add(offset))
        } else {
            None
        }
    }
}

// -----------------------------------------------------------------------
// VmMemoryMap
// -----------------------------------------------------------------------

/// Guest physical memory map consisting of up to
/// [`MAX_MEMORY_SLOTS`] slots.
///
/// Manages the collection of [`VmMemorySlot`] entries that define
/// the guest's view of physical memory and provides GPA-to-HPA
/// translation.
pub struct VmMemoryMap {
    /// Memory slot storage (`None` = unused).
    slots: [Option<VmMemorySlot>; MAX_MEMORY_SLOTS],
}

impl Default for VmMemoryMap {
    fn default() -> Self {
        Self::new()
    }
}

impl VmMemoryMap {
    /// Create an empty memory map.
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_MEMORY_SLOTS],
        }
    }

    /// Add or replace a memory slot.
    ///
    /// If a slot with the same `slot` ID already exists it is
    /// replaced. Otherwise the first free entry is used.
    ///
    /// Returns `Err(Error::OutOfMemory)` if the table is full and
    /// the slot ID is new.
    pub fn add(&mut self, slot: VmMemorySlot) -> Result<(), Error> {
        // Replace existing slot with same ID.
        let mut i = 0;
        while i < MAX_MEMORY_SLOTS {
            if let Some(ref existing) = self.slots[i] {
                if existing.slot == slot.slot {
                    self.slots[i] = Some(slot);
                    return Ok(());
                }
            }
            i = i.saturating_add(1);
        }

        // Find a free entry.
        let mut j = 0;
        while j < MAX_MEMORY_SLOTS {
            if self.slots[j].is_none() {
                self.slots[j] = Some(slot);
                return Ok(());
            }
            j = j.saturating_add(1);
        }

        Err(Error::OutOfMemory)
    }

    /// Remove a memory slot by its slot ID.
    ///
    /// Returns `Err(Error::NotFound)` if no slot with the given
    /// ID exists.
    pub fn remove(&mut self, slot_id: u32) -> Result<(), Error> {
        let mut i = 0;
        while i < MAX_MEMORY_SLOTS {
            if let Some(ref s) = self.slots[i] {
                if s.slot == slot_id {
                    self.slots[i] = None;
                    return Ok(());
                }
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Translate a guest physical address to a host physical
    /// address.
    ///
    /// Searches all active slots and returns the HPA for the
    /// first matching slot. Returns `Err(Error::NotFound)` if
    /// the GPA is not covered by any slot.
    pub fn translate(&self, gpa: u64) -> Result<u64, Error> {
        let mut i = 0;
        while i < MAX_MEMORY_SLOTS {
            if let Some(ref s) = self.slots[i] {
                if let Some(hpa) = s.translate(gpa) {
                    return Ok(hpa);
                }
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Return the number of active (non-empty) slots.
    pub fn slot_count(&self) -> usize {
        let mut n = 0usize;
        let mut i = 0;
        while i < MAX_MEMORY_SLOTS {
            if self.slots[i].is_some() {
                n = n.saturating_add(1);
            }
            i = i.saturating_add(1);
        }
        n
    }
}

// -----------------------------------------------------------------------
// Vm
// -----------------------------------------------------------------------

/// A virtual machine consisting of vCPUs and a guest physical
/// memory map.
///
/// Each `Vm` supports up to [`MAX_VCPUS`] virtual processors and
/// a [`VmMemoryMap`] describing the guest's physical address
/// space.
pub struct Vm {
    /// Unique identifier of this VM within the [`KvmSystem`].
    id: u32,
    /// Virtual CPUs (`None` = slot unused).
    vcpus: [Option<Vcpu>; MAX_VCPUS],
    /// Guest physical memory map.
    memory: VmMemoryMap,
}

impl Vm {
    /// Create a new virtual machine with the given identifier.
    pub const fn new(id: u32) -> Self {
        Self {
            id,
            vcpus: [None, None, None, None],
            memory: VmMemoryMap::new(),
        }
    }

    /// Return this VM's identifier.
    pub const fn id(&self) -> u32 {
        self.id
    }

    /// Return a reference to the guest memory map.
    pub const fn memory(&self) -> &VmMemoryMap {
        &self.memory
    }

    /// Return a mutable reference to the guest memory map.
    pub fn memory_mut(&mut self) -> &mut VmMemoryMap {
        &mut self.memory
    }

    /// Create a new vCPU and return its index.
    ///
    /// Returns `Err(Error::OutOfMemory)` if all vCPU slots are
    /// occupied.
    pub fn create_vcpu(&mut self) -> Result<u32, Error> {
        let mut i = 0u32;
        while (i as usize) < MAX_VCPUS {
            if self.vcpus[i as usize].is_none() {
                self.vcpus[i as usize] = Some(Vcpu::new(i));
                return Ok(i);
            }
            i = i.saturating_add(1);
        }
        Err(Error::OutOfMemory)
    }

    /// Destroy (remove) a vCPU by index.
    ///
    /// Returns `Err(Error::NotFound)` if no vCPU exists at the
    /// given index.
    pub fn destroy_vcpu(&mut self, index: u32) -> Result<(), Error> {
        let idx = index as usize;
        if idx >= MAX_VCPUS {
            return Err(Error::InvalidArgument);
        }
        if self.vcpus[idx].is_none() {
            return Err(Error::NotFound);
        }
        self.vcpus[idx] = None;
        Ok(())
    }

    /// Get a reference to a vCPU by index.
    pub fn vcpu(&self, index: u32) -> Option<&Vcpu> {
        let idx = index as usize;
        if idx < MAX_VCPUS {
            self.vcpus[idx].as_ref()
        } else {
            None
        }
    }

    /// Get a mutable reference to a vCPU by index.
    pub fn vcpu_mut(&mut self, index: u32) -> Option<&mut Vcpu> {
        let idx = index as usize;
        if idx < MAX_VCPUS {
            self.vcpus[idx].as_mut()
        } else {
            None
        }
    }

    /// Return the number of active vCPUs.
    pub fn vcpu_count(&self) -> usize {
        let mut n = 0usize;
        let mut i = 0;
        while i < MAX_VCPUS {
            if self.vcpus[i].is_some() {
                n = n.saturating_add(1);
            }
            i = i.saturating_add(1);
        }
        n
    }
}

// -----------------------------------------------------------------------
// KvmSystem
// -----------------------------------------------------------------------

/// Global KVM system manager.
///
/// Manages up to [`MAX_VMS`] virtual machines. This is the
/// top-level entry point for the hypervisor subsystem.
pub struct KvmSystem {
    /// VM slots (`None` = unused).
    vms: [Option<Vm>; MAX_VMS],
    /// Monotonically increasing counter for VM IDs.
    next_vm_id: u32,
}

impl Default for KvmSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl KvmSystem {
    /// Create a new KVM system with no active VMs.
    pub const fn new() -> Self {
        Self {
            vms: [None, None, None, None, None, None, None, None],
            next_vm_id: 0,
        }
    }

    /// Create a new virtual machine and return its ID.
    ///
    /// Returns `Err(Error::OutOfMemory)` if all VM slots are
    /// occupied.
    pub fn create_vm(&mut self) -> Result<u32, Error> {
        let mut i = 0;
        while i < MAX_VMS {
            if self.vms[i].is_none() {
                let id = self.next_vm_id;
                self.next_vm_id = self.next_vm_id.saturating_add(1);
                self.vms[i] = Some(Vm::new(id));
                return Ok(id);
            }
            i = i.saturating_add(1);
        }
        Err(Error::OutOfMemory)
    }

    /// Destroy a virtual machine by its ID.
    ///
    /// Returns `Err(Error::NotFound)` if no VM with the given ID
    /// exists.
    pub fn destroy_vm(&mut self, vm_id: u32) -> Result<(), Error> {
        let mut i = 0;
        while i < MAX_VMS {
            if let Some(ref vm) = self.vms[i] {
                if vm.id() == vm_id {
                    self.vms[i] = None;
                    return Ok(());
                }
            }
            i = i.saturating_add(1);
        }
        Err(Error::NotFound)
    }

    /// Get a reference to a VM by its ID.
    pub fn vm(&self, vm_id: u32) -> Option<&Vm> {
        let mut i = 0;
        while i < MAX_VMS {
            if let Some(ref vm) = self.vms[i] {
                if vm.id() == vm_id {
                    return Some(vm);
                }
            }
            i = i.saturating_add(1);
        }
        None
    }

    /// Get a mutable reference to a VM by its ID.
    pub fn vm_mut(&mut self, vm_id: u32) -> Option<&mut Vm> {
        let idx = self
            .vms
            .iter()
            .position(|slot| slot.as_ref().is_some_and(|vm| vm.id() == vm_id))?;
        self.vms[idx].as_mut()
    }

    /// Return the number of active VMs.
    pub fn vm_count(&self) -> usize {
        let mut n = 0usize;
        let mut i = 0;
        while i < MAX_VMS {
            if self.vms[i].is_some() {
                n = n.saturating_add(1);
            }
            i = i.saturating_add(1);
        }
        n
    }
}
