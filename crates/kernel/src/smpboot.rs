// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! SMP bootstrap and CPU online/offline management.
//!
//! Handles the multi-processor boot sequence for Application Processors
//! (APs) and manages CPU lifecycle transitions (online, offline, parked).
//! On x86_64, the BSP (Bootstrap Processor) sends INIT-SIPI-SIPI
//! sequences to each AP via the local APIC, directing them to a
//! real-mode trampoline that transitions through protected mode into
//! long mode, then enters the kernel's per-CPU init path.
//!
//! # Boot Sequence
//!
//! ```text
//! BSP                          AP
//! ───                          ──
//! prepare_trampoline()
//! boot_secondary(cpu_id)
//!   ├─ send INIT IPI ────────► reset
//!   ├─ delay 10ms
//!   ├─ send SIPI ────────────► trampoline (real mode)
//!   │                          ├─ protected mode
//!   │                          ├─ long mode
//!   │                          └─ ap_entry()
//!   └─ wait_for_ap(cpu_id)      ├─ init GDT/IDT
//!        ◄── handshake ─────────┤  init per-CPU data
//!                                └─ mark Online
//! ```
//!
//! # CPU State Machine
//!
//! ```text
//! Offline ──boot_secondary()──► Booting ──ap_entry()──► Online
//!    ▲                                                     │
//!    └──────── park_cpu() ◄── Parked ◄── cpu_offline() ───┘
//! ```
//!
//! # Reference
//!
//! Linux `arch/x86/kernel/smpboot.c`, `kernel/smpboot.c`.

use oncrix_lib::{Error, Result};

// ======================================================================
// Constants
// ======================================================================

/// Maximum number of logical CPUs supported.
const MAX_CPUS: usize = 256;

/// Maximum number of NUMA nodes.
const MAX_NUMA_NODES: usize = 16;

/// Size of the boot trampoline in bytes (one 4K page).
const TRAMPOLINE_SIZE: usize = 4096;

/// Timeout for AP handshake in timer ticks (~10ms each).
const AP_HANDSHAKE_TIMEOUT: u64 = 1000;

/// Timeout for CPU offline drain in timer ticks.
const OFFLINE_DRAIN_TIMEOUT: u64 = 500;

/// Maximum number of per-CPU init callbacks.
const MAX_INIT_CALLBACKS: usize = 32;

/// Maximum name length for init callbacks.
const MAX_NAME_LEN: usize = 64;

/// Trampoline default physical base address (below 1MB for real mode).
const _TRAMPOLINE_DEFAULT_BASE: u64 = 0x8000;

// ======================================================================
// CpuState — per-CPU lifecycle state
// ======================================================================

/// Runtime state of a logical CPU in the SMP boot framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum CpuState {
    /// CPU has not been initialised or is fully powered down.
    #[default]
    Offline = 0,
    /// BSP has sent INIT-SIPI and is waiting for the AP to respond.
    Booting = 1,
    /// AP has entered the kernel and is executing per-CPU init.
    Initializing = 2,
    /// CPU is fully online and available for scheduling.
    Online = 3,
    /// CPU is being taken offline (draining work, migrating tasks).
    GoingOffline = 4,
    /// CPU is parked — halted but can be quickly brought back online.
    Parked = 5,
}

// ======================================================================
// BootTrampoline — real-mode trampoline buffer
// ======================================================================

/// Real-mode trampoline code and data for AP startup.
///
/// On x86_64 the SIPI vector points to a physical page below 1 MB
/// containing 16-bit real-mode code that transitions the AP through
/// protected mode into long mode and jumps to `ap_entry`.
#[derive(Debug, Clone, Copy)]
pub struct BootTrampoline {
    /// Physical base address of the trampoline page.
    pub phys_base: u64,
    /// Trampoline code/data (one page).
    pub code: [u8; TRAMPOLINE_SIZE],
    /// Virtual address of the AP entry point (`ap_entry` in kernel).
    pub entry_point: u64,
    /// Physical address of the kernel's page table root (CR3 value).
    pub page_table_root: u64,
    /// GDT pointer to load in the trampoline.
    pub gdt_base: u64,
    /// GDT limit.
    pub gdt_limit: u16,
    /// Whether the trampoline has been prepared.
    pub prepared: bool,
}

impl BootTrampoline {
    /// Create an empty trampoline descriptor.
    pub const fn new() -> Self {
        Self {
            phys_base: 0,
            code: [0u8; TRAMPOLINE_SIZE],
            entry_point: 0,
            page_table_root: 0,
            gdt_base: 0,
            gdt_limit: 0,
            prepared: false,
        }
    }

    /// Prepare the trampoline code for the given entry point.
    ///
    /// Copies architecture-specific real-mode stub into the trampoline
    /// page and patches in the entry point, CR3, and GDT pointer.
    pub fn prepare(
        &mut self,
        phys_base: u64,
        entry_point: u64,
        page_table_root: u64,
        gdt_base: u64,
        gdt_limit: u16,
    ) -> Result<()> {
        if phys_base >= 0x10_0000 {
            return Err(Error::InvalidArgument);
        }
        self.phys_base = phys_base;
        self.entry_point = entry_point;
        self.page_table_root = page_table_root;
        self.gdt_base = gdt_base;
        self.gdt_limit = gdt_limit;

        // In a real implementation the trampoline code bytes would be
        // assembled here. We zero-fill as a placeholder.
        self.code.fill(0);

        // Patch entry point address at offset 0x10 (8 bytes, LE).
        let ep_bytes = entry_point.to_le_bytes();
        self.code[0x10..0x18].copy_from_slice(&ep_bytes);

        // Patch CR3 at offset 0x18.
        let cr3_bytes = page_table_root.to_le_bytes();
        self.code[0x18..0x20].copy_from_slice(&cr3_bytes);

        self.prepared = true;
        Ok(())
    }

    /// Returns whether the trampoline has been prepared.
    pub fn is_prepared(&self) -> bool {
        self.prepared
    }
}

// ======================================================================
// CpuMask — bitmask over CPU IDs
// ======================================================================

/// Bitmask representing a set of CPU IDs.
///
/// Supports up to [`MAX_CPUS`] CPUs using a fixed-size array of `u64`
/// words.
#[derive(Debug, Clone, Copy)]
pub struct CpuMask {
    /// Bitmask words (each bit = one CPU ID).
    bits: [u64; Self::WORDS],
}

impl CpuMask {
    /// Number of 64-bit words needed for [`MAX_CPUS`] bits.
    const WORDS: usize = (MAX_CPUS + 63) / 64;

    /// Empty mask (no CPUs set).
    pub const fn empty() -> Self {
        Self {
            bits: [0u64; Self::WORDS],
        }
    }

    /// Set the bit for `cpu_id`.
    pub fn set(&mut self, cpu_id: usize) -> Result<()> {
        if cpu_id >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let word = cpu_id / 64;
        let bit = cpu_id % 64;
        self.bits[word] |= 1u64 << bit;
        Ok(())
    }

    /// Clear the bit for `cpu_id`.
    pub fn clear(&mut self, cpu_id: usize) -> Result<()> {
        if cpu_id >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        let word = cpu_id / 64;
        let bit = cpu_id % 64;
        self.bits[word] &= !(1u64 << bit);
        Ok(())
    }

    /// Test whether `cpu_id` is set.
    pub fn is_set(&self, cpu_id: usize) -> bool {
        if cpu_id >= MAX_CPUS {
            return false;
        }
        let word = cpu_id / 64;
        let bit = cpu_id % 64;
        (self.bits[word] & (1u64 << bit)) != 0
    }

    /// Count the number of set bits.
    pub fn count(&self) -> usize {
        self.bits.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Return the index of the first set bit, or `None`.
    pub fn first_set(&self) -> Option<usize> {
        for (i, word) in self.bits.iter().enumerate() {
            if *word != 0 {
                return Some(i * 64 + word.trailing_zeros() as usize);
            }
        }
        None
    }

    /// Return the index of the next set bit after `from`, or `None`.
    pub fn next_set(&self, from: usize) -> Option<usize> {
        let start = from + 1;
        if start >= MAX_CPUS {
            return None;
        }
        let word_idx = start / 64;
        let bit_idx = start % 64;

        // Check remainder of the first word.
        let masked = self.bits[word_idx] & !((1u64 << bit_idx) - 1);
        if masked != 0 {
            return Some(word_idx * 64 + masked.trailing_zeros() as usize);
        }

        // Scan subsequent words.
        for (i, word) in self.bits.iter().enumerate().skip(word_idx + 1) {
            if *word != 0 {
                return Some(i * 64 + word.trailing_zeros() as usize);
            }
        }
        None
    }

    /// Perform bitwise OR with another mask.
    pub fn union(&mut self, other: &CpuMask) {
        for (a, b) in self.bits.iter_mut().zip(other.bits.iter()) {
            *a |= *b;
        }
    }

    /// Perform bitwise AND with another mask.
    pub fn intersect(&mut self, other: &CpuMask) {
        for (a, b) in self.bits.iter_mut().zip(other.bits.iter()) {
            *a &= *b;
        }
    }

    /// Clear all bits.
    pub fn clear_all(&mut self) {
        self.bits.fill(0);
    }

    /// Check whether the mask is empty.
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|w| *w == 0)
    }
}

// ======================================================================
// PerCpuInit — per-CPU init callback descriptor
// ======================================================================

/// A callback descriptor for per-CPU initialisation.
///
/// Subsystems register these so that when a new CPU comes online,
/// their per-CPU state is initialised.
#[derive(Debug, Clone, Copy)]
pub struct PerCpuInit {
    /// Human-readable callback name.
    pub name: [u8; MAX_NAME_LEN],
    /// Name length in bytes.
    pub name_len: usize,
    /// Callback identifier (used to dispatch to the actual function).
    pub func_id: u64,
    /// Priority (lower = earlier execution).
    pub priority: u32,
    /// Whether this entry is active.
    pub active: bool,
}

impl PerCpuInit {
    /// Create an empty (inactive) descriptor.
    const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            func_id: 0,
            priority: 0,
            active: false,
        }
    }
}

// ======================================================================
// CpuDescriptor — per-CPU metadata
// ======================================================================

/// Metadata describing a single logical CPU.
#[derive(Debug, Clone, Copy)]
pub struct CpuDescriptor {
    /// Logical CPU ID.
    pub cpu_id: u32,
    /// APIC ID (x86) or MPIDR (ARM).
    pub apic_id: u32,
    /// NUMA node this CPU belongs to.
    pub numa_node: u32,
    /// Current lifecycle state.
    pub state: CpuState,
    /// Monotonic tick count when this CPU last transitioned to Online.
    pub online_timestamp: u64,
    /// Monotonic tick count when this CPU last went offline.
    pub offline_timestamp: u64,
    /// Number of times this CPU has been brought online.
    pub boot_count: u64,
    /// Whether this CPU is the BSP.
    pub is_bsp: bool,
    /// Whether this CPU supports SMT (hyper-threading).
    pub smt_capable: bool,
    /// Sibling CPU ID for SMT pairs (u32::MAX if none).
    pub smt_sibling: u32,
}

impl CpuDescriptor {
    /// Create an uninitialised CPU descriptor.
    const fn empty() -> Self {
        Self {
            cpu_id: 0,
            apic_id: 0,
            numa_node: 0,
            state: CpuState::Offline,
            online_timestamp: 0,
            offline_timestamp: 0,
            boot_count: 0,
            is_bsp: false,
            smt_capable: false,
            smt_sibling: u32::MAX,
        }
    }
}

// ======================================================================
// SmpBootStats — aggregate SMP boot statistics
// ======================================================================

/// Statistics gathered during the SMP boot process.
#[derive(Debug, Clone, Copy)]
pub struct SmpBootStats {
    /// Total APs successfully booted.
    pub total_booted: u32,
    /// Total APs that failed to respond.
    pub total_failed: u32,
    /// Total CPUs currently online (including BSP).
    pub cpus_online: u32,
    /// Total CPUs currently parked.
    pub cpus_parked: u32,
    /// Fastest AP boot time in ticks.
    pub min_boot_ticks: u64,
    /// Slowest AP boot time in ticks.
    pub max_boot_ticks: u64,
    /// Sum of all AP boot times in ticks (for average computation).
    pub total_boot_ticks: u64,
    /// Number of online/offline transitions.
    pub transition_count: u64,
}

impl SmpBootStats {
    /// Create zeroed statistics.
    const fn new() -> Self {
        Self {
            total_booted: 0,
            total_failed: 0,
            cpus_online: 0,
            cpus_parked: 0,
            min_boot_ticks: u64::MAX,
            max_boot_ticks: 0,
            total_boot_ticks: 0,
            transition_count: 0,
        }
    }

    /// Record a successful AP boot with the given duration.
    fn record_boot(&mut self, ticks: u64) {
        self.total_booted += 1;
        self.cpus_online += 1;
        self.total_boot_ticks += ticks;
        if ticks < self.min_boot_ticks {
            self.min_boot_ticks = ticks;
        }
        if ticks > self.max_boot_ticks {
            self.max_boot_ticks = ticks;
        }
        self.transition_count += 1;
    }

    /// Record a failed AP boot attempt.
    fn record_failure(&mut self) {
        self.total_failed += 1;
    }
}

// ======================================================================
// SmpBootState — top-level SMP bootstrap manager
// ======================================================================

/// Top-level SMP bootstrap state.
///
/// Manages the full boot sequence for all APs, tracks per-CPU state,
/// and coordinates online/offline transitions.
pub struct SmpBootState {
    /// Per-CPU descriptors (index = logical CPU ID).
    cpus: [CpuDescriptor; MAX_CPUS],
    /// Number of CPUs discovered by firmware/ACPI.
    num_possible: u32,
    /// Boot trampoline descriptor.
    trampoline: BootTrampoline,
    /// Mask of CPUs that are currently online.
    online_mask: CpuMask,
    /// Mask of CPUs that are possible (present in ACPI/DT).
    possible_mask: CpuMask,
    /// Mask of CPUs that are currently parked.
    parked_mask: CpuMask,
    /// Per-CPU init callbacks.
    init_callbacks: [PerCpuInit; MAX_INIT_CALLBACKS],
    /// Number of registered init callbacks.
    num_init_callbacks: usize,
    /// Aggregate boot statistics.
    stats: SmpBootStats,
    /// Current monotonic tick (updated by caller).
    current_tick: u64,
    /// NUMA node assignment table (cpu_id -> node_id).
    numa_map: [u32; MAX_CPUS],
}

impl SmpBootState {
    /// Create a new SMP boot state with all CPUs offline.
    pub const fn new() -> Self {
        Self {
            cpus: [const { CpuDescriptor::empty() }; MAX_CPUS],
            num_possible: 0,
            trampoline: BootTrampoline::new(),
            online_mask: CpuMask::empty(),
            possible_mask: CpuMask::empty(),
            parked_mask: CpuMask::empty(),
            init_callbacks: [const { PerCpuInit::empty() }; MAX_INIT_CALLBACKS],
            num_init_callbacks: 0,
            stats: SmpBootStats::new(),
            current_tick: 0,
            numa_map: [0u32; MAX_CPUS],
        }
    }

    /// Register a CPU discovered by ACPI/MADT or device tree.
    ///
    /// Must be called before [`boot_secondary`](Self::boot_secondary).
    pub fn register_cpu(
        &mut self,
        cpu_id: u32,
        apic_id: u32,
        numa_node: u32,
        is_bsp: bool,
    ) -> Result<()> {
        let id = cpu_id as usize;
        if id >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if numa_node as usize >= MAX_NUMA_NODES {
            return Err(Error::InvalidArgument);
        }
        if self.cpus[id].state != CpuState::Offline && self.cpus[id].apic_id != 0 {
            return Err(Error::AlreadyExists);
        }

        self.cpus[id].cpu_id = cpu_id;
        self.cpus[id].apic_id = apic_id;
        self.cpus[id].numa_node = numa_node;
        self.cpus[id].is_bsp = is_bsp;
        self.numa_map[id] = numa_node;
        self.possible_mask.set(id)?;
        self.num_possible += 1;

        if is_bsp {
            self.cpus[id].state = CpuState::Online;
            self.cpus[id].boot_count = 1;
            self.online_mask.set(id)?;
            self.stats.cpus_online = 1;
        }

        Ok(())
    }

    /// Prepare the real-mode trampoline for AP startup.
    pub fn prepare_trampoline(
        &mut self,
        phys_base: u64,
        entry_point: u64,
        page_table_root: u64,
        gdt_base: u64,
        gdt_limit: u16,
    ) -> Result<()> {
        self.trampoline
            .prepare(phys_base, entry_point, page_table_root, gdt_base, gdt_limit)
    }

    /// Boot a secondary (AP) CPU.
    ///
    /// Sends INIT-SIPI-SIPI via the local APIC and waits for the AP
    /// to signal that it has entered `ap_entry`. Returns an error if
    /// the trampoline is not prepared, the CPU ID is invalid, or the
    /// AP does not respond within the timeout.
    pub fn boot_secondary(&mut self, cpu_id: u32) -> Result<()> {
        let id = cpu_id as usize;
        if id >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if !self.trampoline.is_prepared() {
            return Err(Error::NotImplemented);
        }
        if !self.possible_mask.is_set(id) {
            return Err(Error::NotFound);
        }
        if self.cpus[id].state != CpuState::Offline && self.cpus[id].state != CpuState::Parked {
            return Err(Error::Busy);
        }
        if self.cpus[id].is_bsp {
            return Err(Error::InvalidArgument);
        }

        // Transition to Booting.
        self.cpus[id].state = CpuState::Booting;

        // In a real implementation, this would:
        // 1. Write the AP's startup data into the trampoline page.
        // 2. Send INIT IPI to the target APIC ID.
        // 3. Delay ~10ms.
        // 4. Send SIPI with vector = trampoline page number.
        // 5. Wait for AP to set its state to Initializing.

        // Simulate the AP responding successfully.
        self.cpus[id].state = CpuState::Initializing;
        Ok(())
    }

    /// Wait for an AP to complete its initialisation and come online.
    ///
    /// Returns `Ok(ticks)` with the boot duration on success, or
    /// `WouldBlock` if the AP has not yet responded within the
    /// timeout.
    pub fn wait_for_ap(&mut self, cpu_id: u32) -> Result<u64> {
        let id = cpu_id as usize;
        if id >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        match self.cpus[id].state {
            CpuState::Online => {
                // Already online — return cached boot duration.
                let duration = self.current_tick - self.cpus[id].online_timestamp;
                Ok(duration)
            }
            CpuState::Initializing => {
                // Simulate successful completion.
                self.complete_ap_online(id)?;
                Ok(0)
            }
            CpuState::Booting => {
                // Still waiting for AP handshake.
                Err(Error::WouldBlock)
            }
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Mark an AP as fully online after it has completed init.
    ///
    /// Called internally after the AP signals readiness, and also
    /// serves as the entry point for the AP's own init code.
    fn complete_ap_online(&mut self, id: usize) -> Result<()> {
        if id >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }

        self.cpus[id].state = CpuState::Online;
        self.cpus[id].online_timestamp = self.current_tick;
        self.cpus[id].boot_count += 1;
        self.online_mask.set(id)?;
        self.parked_mask.clear(id)?;

        // Run per-CPU init callbacks.
        self.run_init_callbacks(id as u32)?;

        let boot_ticks = 0; // placeholder — real impl measures from SIPI
        self.stats.record_boot(boot_ticks);

        Ok(())
    }

    /// Bring a CPU online (convenience wrapper).
    pub fn cpu_online(&mut self, cpu_id: u32) -> Result<()> {
        let id = cpu_id as usize;
        if id >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        match self.cpus[id].state {
            CpuState::Online => Ok(()), // already online
            CpuState::Parked => {
                // Resume from parked state (no SIPI needed).
                self.cpus[id].state = CpuState::Initializing;
                self.complete_ap_online(id)
            }
            CpuState::Offline => self
                .boot_secondary(cpu_id)
                .and_then(|()| self.wait_for_ap(cpu_id).map(|_| ())),
            _ => Err(Error::Busy),
        }
    }

    /// Take a CPU offline.
    ///
    /// Migrates any tasks off the CPU, runs teardown callbacks, and
    /// transitions the CPU to [`CpuState::Offline`].
    pub fn cpu_offline(&mut self, cpu_id: u32) -> Result<()> {
        let id = cpu_id as usize;
        if id >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.cpus[id].is_bsp {
            return Err(Error::PermissionDenied);
        }
        if self.cpus[id].state != CpuState::Online {
            return Err(Error::InvalidArgument);
        }

        // Transition to GoingOffline.
        self.cpus[id].state = CpuState::GoingOffline;

        // In a real implementation:
        // 1. Stop scheduling on this CPU (set need_offline flag).
        // 2. Migrate all runnable tasks to other CPUs.
        // 3. Drain timers, workqueues, RCU callbacks.
        // 4. Run teardown callbacks in reverse priority.
        // 5. Send CPU-offline IPI.

        self.cpus[id].state = CpuState::Offline;
        self.cpus[id].offline_timestamp = self.current_tick;
        self.online_mask.clear(id)?;
        self.parked_mask.clear(id)?;

        if self.stats.cpus_online > 0 {
            self.stats.cpus_online -= 1;
        }
        self.stats.transition_count += 1;

        Ok(())
    }

    /// Park a CPU (halt but keep hot for fast re-online).
    ///
    /// The CPU enters a low-power halt loop but its per-CPU state is
    /// preserved so it can be brought back online quickly without a
    /// full INIT-SIPI sequence.
    pub fn park_cpu(&mut self, cpu_id: u32) -> Result<()> {
        let id = cpu_id as usize;
        if id >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        if self.cpus[id].is_bsp {
            return Err(Error::PermissionDenied);
        }
        if self.cpus[id].state != CpuState::Online {
            return Err(Error::InvalidArgument);
        }

        self.cpus[id].state = CpuState::Parked;
        self.online_mask.clear(id)?;
        self.parked_mask.set(id)?;

        if self.stats.cpus_online > 0 {
            self.stats.cpus_online -= 1;
        }
        self.stats.cpus_parked += 1;
        self.stats.transition_count += 1;

        Ok(())
    }

    /// Register a per-CPU init callback.
    ///
    /// The callback is invoked on each CPU when it transitions to
    /// [`CpuState::Online`].
    pub fn register_init_callback(
        &mut self,
        name: &[u8],
        func_id: u64,
        priority: u32,
    ) -> Result<()> {
        if self.num_init_callbacks >= MAX_INIT_CALLBACKS {
            return Err(Error::OutOfMemory);
        }
        let len = name.len().min(MAX_NAME_LEN);
        let slot = &mut self.init_callbacks[self.num_init_callbacks];
        slot.name[..len].copy_from_slice(&name[..len]);
        slot.name_len = len;
        slot.func_id = func_id;
        slot.priority = priority;
        slot.active = true;
        self.num_init_callbacks += 1;
        Ok(())
    }

    /// Run all registered per-CPU init callbacks for the given CPU.
    fn run_init_callbacks(&self, _cpu_id: u32) -> Result<()> {
        // In a real implementation, callbacks would be sorted by
        // priority and dispatched through a function-pointer table.
        // Here we just validate that the callback list is consistent.
        for i in 0..self.num_init_callbacks {
            if !self.init_callbacks[i].active {
                return Err(Error::InvalidArgument);
            }
        }
        Ok(())
    }

    /// Set the SMT sibling relationship between two CPUs.
    pub fn set_smt_sibling(&mut self, cpu_a: u32, cpu_b: u32) -> Result<()> {
        let a = cpu_a as usize;
        let b = cpu_b as usize;
        if a >= MAX_CPUS || b >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        self.cpus[a].smt_capable = true;
        self.cpus[a].smt_sibling = cpu_b;
        self.cpus[b].smt_capable = true;
        self.cpus[b].smt_sibling = cpu_a;
        Ok(())
    }

    /// Update the current monotonic tick counter.
    pub fn set_current_tick(&mut self, tick: u64) {
        self.current_tick = tick;
    }

    /// Get the state of a specific CPU.
    pub fn get_cpu_state(&self, cpu_id: u32) -> Result<CpuState> {
        let id = cpu_id as usize;
        if id >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.cpus[id].state)
    }

    /// Get the CPU descriptor for a specific CPU.
    pub fn get_cpu_descriptor(&self, cpu_id: u32) -> Result<&CpuDescriptor> {
        let id = cpu_id as usize;
        if id >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(&self.cpus[id])
    }

    /// Get a reference to the online CPU mask.
    pub fn online_mask(&self) -> &CpuMask {
        &self.online_mask
    }

    /// Get a reference to the possible CPU mask.
    pub fn possible_mask(&self) -> &CpuMask {
        &self.possible_mask
    }

    /// Get the number of CPUs currently online.
    pub fn num_online(&self) -> u32 {
        self.stats.cpus_online
    }

    /// Get the number of CPUs currently parked.
    pub fn num_parked(&self) -> u32 {
        self.stats.cpus_parked
    }

    /// Get the total number of possible CPUs.
    pub fn num_possible(&self) -> u32 {
        self.num_possible
    }

    /// Get a reference to the boot statistics.
    pub fn stats(&self) -> &SmpBootStats {
        &self.stats
    }

    /// Boot all registered APs that are currently offline.
    ///
    /// Returns the number of APs successfully brought online.
    pub fn boot_all_aps(&mut self) -> Result<u32> {
        let mut booted = 0u32;

        // Collect CPU IDs to boot.
        let mut to_boot = [0u32; MAX_CPUS];
        let mut count = 0usize;
        for i in 0..MAX_CPUS {
            if self.possible_mask.is_set(i)
                && self.cpus[i].state == CpuState::Offline
                && !self.cpus[i].is_bsp
            {
                to_boot[count] = i as u32;
                count += 1;
            }
        }

        for idx in 0..count {
            let cpu_id = to_boot[idx];
            match self.cpu_online(cpu_id) {
                Ok(()) => booted += 1,
                Err(_) => self.stats.record_failure(),
            }
        }

        Ok(booted)
    }

    /// Check if the AP handshake timeout has been exceeded.
    pub fn check_ap_timeout(&self, cpu_id: u32) -> bool {
        let id = cpu_id as usize;
        if id >= MAX_CPUS {
            return true;
        }
        if self.cpus[id].state != CpuState::Booting {
            return false;
        }
        // In a real implementation, we'd compare against the tick
        // when the SIPI was sent.
        self.current_tick > AP_HANDSHAKE_TIMEOUT
    }

    /// Check if the offline drain timeout has been exceeded.
    pub fn check_offline_timeout(&self, cpu_id: u32) -> bool {
        let id = cpu_id as usize;
        if id >= MAX_CPUS {
            return true;
        }
        if self.cpus[id].state != CpuState::GoingOffline {
            return false;
        }
        self.current_tick
            .saturating_sub(self.cpus[id].offline_timestamp)
            > OFFLINE_DRAIN_TIMEOUT
    }

    /// Get the NUMA node for a CPU.
    pub fn get_numa_node(&self, cpu_id: u32) -> Result<u32> {
        let id = cpu_id as usize;
        if id >= MAX_CPUS {
            return Err(Error::InvalidArgument);
        }
        Ok(self.numa_map[id])
    }
}
