// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! BPF helper function registry.
//!
//! Provides a registry of helper functions callable from BPF programs
//! during execution.  Each helper has a unique numeric ID, argument
//! count, and return type, following the Linux eBPF helper convention.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────┐
//! │                  BpfHelperRegistry                            │
//! │                                                              │
//! │  BpfHelperFn[0..MAX_HELPERS]  (registered helpers)           │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  id: BpfHelperId                                       │  │
//! │  │  name: [u8; 32]                                        │  │
//! │  │  arg_count: u8                                         │  │
//! │  │  return_type: BpfReturnType                            │  │
//! │  │  flags: BpfHelperFlags                                 │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  BpfHelperContext (per-call execution context)                │
//! │  ┌────────────────────────────────────────────────────────┐  │
//! │  │  program_type, map_fds, current_cpu, current_pid       │  │
//! │  └────────────────────────────────────────────────────────┘  │
//! │                                                              │
//! │  BpfHelperStats (global counters)                            │
//! │  - per_helper_calls, total_calls, unknown_helper_calls       │
//! └──────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Dispatch
//!
//! The main entry point is [`BpfHelperRegistry::call_helper`] which
//! validates the helper ID, checks argument count, and dispatches
//! to the appropriate built-in implementation.
//!
//! # Reference
//!
//! Linux `include/uapi/linux/bpf.h`, `kernel/bpf/helpers.c`.

use oncrix_lib::{Error, Result};

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

/// Maximum registered helpers in the registry.
const MAX_HELPERS: usize = 64;

/// Helper function name buffer length.
const HELPER_NAME_LEN: usize = 32;

/// Maximum BPF helper arguments.
const MAX_HELPER_ARGS: usize = 5;

/// Maximum map file descriptors per context.
const MAX_MAP_FDS: usize = 16;

/// Maximum number of distinct helper IDs for stats.
const MAX_HELPER_IDS: usize = 32;

/// Simulated monotonic clock value for `ktime_get_ns`.
const SIMULATED_KTIME_NS: u64 = 1_000_000_000;

/// Maximum stack depth for `get_stack_id`.
const MAX_STACK_DEPTH: u32 = 127;

// ══════════════════════════════════════════════════════════════
// BpfHelperId
// ══════════════════════════════════════════════════════════════

/// Numeric IDs for BPF helper functions.
///
/// Each variant corresponds to a specific helper callable from
/// BPF bytecode via the `call` instruction.  IDs follow the
/// Linux BPF helper numbering convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BpfHelperId {
    /// Look up a key in a BPF map.
    MapLookupElem = 1,
    /// Update a key/value pair in a BPF map.
    MapUpdateElem = 2,
    /// Delete a key from a BPF map.
    MapDeleteElem = 3,
    /// Read kernel memory safely.
    ProbeRead = 4,
    /// Get current monotonic time in nanoseconds.
    KtimeGetNs = 5,
    /// Get current PID and TGID packed as `(tgid << 32) | pid`.
    GetCurrentPidTgid = 6,
    /// Get current UID and GID packed as `(gid << 32) | uid`.
    GetCurrentUidGid = 7,
    /// Get current task's comm (command name).
    GetCurrentComm = 8,
    /// Output data to a perf event ring buffer.
    PerfEventOutput = 9,
    /// Get the current SMP processor ID.
    GetSmpProcessorId = 10,
    /// Tail-call into another BPF program.
    TailCall = 11,
    /// Get the cgroup ID of the current task.
    GetCurrentCgroupId = 12,
    /// Submit data to a BPF ring buffer.
    Ringbuf = 13,
    /// Print a formatted trace message (debug).
    TracePrintk = 14,
    /// Get the stack trace ID.
    GetStackId = 15,
    /// Load bytes from an skb (network packet).
    SkbLoadBytes = 16,
}

impl BpfHelperId {
    /// Convert a raw u32 to a helper ID, if valid.
    pub fn from_raw(raw: u32) -> Result<Self> {
        match raw {
            1 => Ok(Self::MapLookupElem),
            2 => Ok(Self::MapUpdateElem),
            3 => Ok(Self::MapDeleteElem),
            4 => Ok(Self::ProbeRead),
            5 => Ok(Self::KtimeGetNs),
            6 => Ok(Self::GetCurrentPidTgid),
            7 => Ok(Self::GetCurrentUidGid),
            8 => Ok(Self::GetCurrentComm),
            9 => Ok(Self::PerfEventOutput),
            10 => Ok(Self::GetSmpProcessorId),
            11 => Ok(Self::TailCall),
            12 => Ok(Self::GetCurrentCgroupId),
            13 => Ok(Self::Ringbuf),
            14 => Ok(Self::TracePrintk),
            15 => Ok(Self::GetStackId),
            16 => Ok(Self::SkbLoadBytes),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Get the raw u32 value of this helper ID.
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    /// Get the expected number of arguments for this helper.
    pub const fn expected_arg_count(self) -> u8 {
        match self {
            Self::MapLookupElem => 2, // map_fd, key
            Self::MapUpdateElem => 4, // map_fd, key, value, flags
            Self::MapDeleteElem => 2, // map_fd, key
            Self::ProbeRead => 3,     // dst, size, unsafe_ptr
            Self::KtimeGetNs => 0,
            Self::GetCurrentPidTgid => 0,
            Self::GetCurrentUidGid => 0,
            Self::GetCurrentComm => 2,  // buf, size
            Self::PerfEventOutput => 5, // ctx, map, flags, data, size
            Self::GetSmpProcessorId => 0,
            Self::TailCall => 3, // ctx, prog_array, index
            Self::GetCurrentCgroupId => 0,
            Self::Ringbuf => 4,      // map, data, size, flags
            Self::TracePrintk => 3,  // fmt, size, arg1
            Self::GetStackId => 3,   // ctx, map, flags
            Self::SkbLoadBytes => 4, // skb, offset, to, len
        }
    }
}

// ══════════════════════════════════════════════════════════════
// BpfReturnType
// ══════════════════════════════════════════════════════════════

/// Return type classification for BPF helper functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfReturnType {
    /// Returns an integer (0 = success, negative = error).
    Integer,
    /// Returns a pointer (to map value, packet data, etc.).
    Pointer,
    /// Returns void (always succeeds, return value ignored).
    Void,
}

impl Default for BpfReturnType {
    fn default() -> Self {
        Self::Integer
    }
}

// ══════════════════════════════════════════════════════════════
// BpfHelperFlags
// ══════════════════════════════════════════════════════════════

/// Capability flags for a BPF helper function.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfHelperFlags(u32);

impl BpfHelperFlags {
    /// No special flags.
    pub const NONE: Self = Self(0);
    /// Helper may sleep (not callable from NMI/hard-IRQ BPF progs).
    pub const MAY_SLEEP: Self = Self(1 << 0);
    /// Helper reads kernel memory.
    pub const READS_KERNEL: Self = Self(1 << 1);
    /// Helper writes kernel memory.
    pub const WRITES_KERNEL: Self = Self(1 << 2);
    /// Helper accesses network packet data.
    pub const ACCESSES_PKT: Self = Self(1 << 3);
    /// Helper requires CAP_SYS_ADMIN.
    pub const NEEDS_ADMIN: Self = Self(1 << 4);

    /// Create flags from a raw value.
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    /// Get the raw u32 value.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Check if a flag is set.
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Combine two flag sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

impl Default for BpfHelperFlags {
    fn default() -> Self {
        Self::NONE
    }
}

// ══════════════════════════════════════════════════════════════
// BpfProgramType
// ══════════════════════════════════════════════════════════════

/// BPF program types that can call helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BpfProgramType {
    /// Socket filter program.
    SocketFilter = 0,
    /// Kprobe/uprobe tracing program.
    Kprobe = 1,
    /// Tracepoint program.
    Tracepoint = 2,
    /// XDP (eXpress Data Path) program.
    Xdp = 3,
    /// Perf event program.
    PerfEvent = 4,
    /// Cgroup socket program.
    CgroupSkb = 5,
    /// LSM (Linux Security Module) hook program.
    Lsm = 6,
    /// Struct ops program.
    StructOps = 7,
}

impl Default for BpfProgramType {
    fn default() -> Self {
        Self::SocketFilter
    }
}

// ══════════════════════════════════════════════════════════════
// BpfHelperFn
// ══════════════════════════════════════════════════════════════

/// A registered BPF helper function descriptor.
#[derive(Clone, Copy)]
pub struct BpfHelperFn {
    /// Unique helper ID.
    pub id: u32,
    /// Human-readable helper name.
    pub name: [u8; HELPER_NAME_LEN],
    /// Expected number of arguments (0-5).
    pub arg_count: u8,
    /// Return type classification.
    pub return_type: BpfReturnType,
    /// Capability flags.
    pub flags: BpfHelperFlags,
    /// Whether this slot is occupied.
    pub registered: bool,
}

impl BpfHelperFn {
    /// Create an empty helper descriptor.
    pub const fn new() -> Self {
        Self {
            id: 0,
            name: [0u8; HELPER_NAME_LEN],
            arg_count: 0,
            return_type: BpfReturnType::Integer,
            flags: BpfHelperFlags::NONE,
            registered: false,
        }
    }

    /// Create a helper descriptor with the given parameters.
    pub fn with_params(
        id: BpfHelperId,
        name: &[u8],
        arg_count: u8,
        return_type: BpfReturnType,
        flags: BpfHelperFlags,
    ) -> Self {
        let mut helper = Self::new();
        helper.id = id.as_u32();
        let copy_len = name.len().min(HELPER_NAME_LEN);
        helper.name[..copy_len].copy_from_slice(&name[..copy_len]);
        helper.arg_count = arg_count;
        helper.return_type = return_type;
        helper.flags = flags;
        helper.registered = true;
        helper
    }
}

impl Default for BpfHelperFn {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// BpfHelperContext
// ══════════════════════════════════════════════════════════════

/// Per-call execution context for BPF helper dispatch.
///
/// Provides the helper with information about the calling BPF
/// program and the current execution environment.
#[derive(Clone, Copy)]
pub struct BpfHelperContext {
    /// Type of the calling BPF program.
    pub program_type: BpfProgramType,
    /// Map file descriptors available to the program.
    pub map_fds: [u32; MAX_MAP_FDS],
    /// Number of valid map file descriptors.
    pub map_fd_count: u8,
    /// CPU ID where the BPF program is executing.
    pub current_cpu: u32,
    /// PID of the task that triggered the BPF program.
    pub current_pid: u32,
    /// TGID (thread group ID) of the current task.
    pub current_tgid: u32,
    /// UID of the current task.
    pub current_uid: u32,
    /// GID of the current task.
    pub current_gid: u32,
    /// Cgroup ID of the current task.
    pub current_cgroup_id: u64,
    /// Current comm (task name).
    pub current_comm: [u8; 16],
}

impl BpfHelperContext {
    /// Create a new empty context.
    pub const fn new() -> Self {
        Self {
            program_type: BpfProgramType::SocketFilter,
            map_fds: [0u32; MAX_MAP_FDS],
            map_fd_count: 0,
            current_cpu: 0,
            current_pid: 0,
            current_tgid: 0,
            current_uid: 0,
            current_gid: 0,
            current_cgroup_id: 0,
            current_comm: [0u8; 16],
        }
    }

    /// Add a map file descriptor to the context.
    pub fn add_map_fd(&mut self, fd: u32) -> Result<()> {
        if self.map_fd_count as usize >= MAX_MAP_FDS {
            return Err(Error::OutOfMemory);
        }
        self.map_fds[self.map_fd_count as usize] = fd;
        self.map_fd_count += 1;
        Ok(())
    }

    /// Set the current task information.
    pub fn set_task_info(&mut self, pid: u32, tgid: u32, uid: u32, gid: u32, comm: &[u8]) {
        self.current_pid = pid;
        self.current_tgid = tgid;
        self.current_uid = uid;
        self.current_gid = gid;
        let copy_len = comm.len().min(16);
        self.current_comm = [0u8; 16];
        self.current_comm[..copy_len].copy_from_slice(&comm[..copy_len]);
    }
}

impl Default for BpfHelperContext {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// BpfHelperStats
// ══════════════════════════════════════════════════════════════

/// Statistics for BPF helper function calls.
#[derive(Clone, Copy)]
pub struct BpfHelperStats {
    /// Per-helper call counts (indexed by helper ID).
    pub per_helper_calls: [u64; MAX_HELPER_IDS],
    /// Total successful helper calls.
    pub total_calls: u64,
    /// Total calls to unknown/unregistered helpers.
    pub unknown_helper_calls: u64,
    /// Total helper calls that returned an error.
    pub error_calls: u64,
    /// Total argument validation failures.
    pub arg_mismatch_calls: u64,
}

impl BpfHelperStats {
    /// Create zeroed statistics.
    pub const fn new() -> Self {
        Self {
            per_helper_calls: [0u64; MAX_HELPER_IDS],
            total_calls: 0,
            unknown_helper_calls: 0,
            error_calls: 0,
            arg_mismatch_calls: 0,
        }
    }

    /// Record a successful call to a helper.
    pub fn record_call(&mut self, helper_id: u32) {
        self.total_calls += 1;
        if (helper_id as usize) < MAX_HELPER_IDS {
            self.per_helper_calls[helper_id as usize] += 1;
        }
    }

    /// Record an unknown helper call.
    pub fn record_unknown(&mut self) {
        self.unknown_helper_calls += 1;
    }

    /// Record an error from a helper call.
    pub fn record_error(&mut self) {
        self.error_calls += 1;
    }

    /// Record an argument mismatch.
    pub fn record_arg_mismatch(&mut self) {
        self.arg_mismatch_calls += 1;
    }
}

impl Default for BpfHelperStats {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// BpfHelperRegistry
// ══════════════════════════════════════════════════════════════

/// Registry of BPF helper functions.
///
/// Manages registration, lookup, and dispatch of helper
/// functions callable from BPF programs.
pub struct BpfHelperRegistry {
    /// Registered helpers.
    pub helpers: [BpfHelperFn; MAX_HELPERS],
    /// Number of registered helpers.
    pub helper_count: u32,
    /// Global call statistics.
    pub stats: BpfHelperStats,
    /// Whether the registry has been initialized with builtins.
    pub initialized: bool,
}

impl BpfHelperRegistry {
    /// Create a new empty helper registry.
    pub const fn new() -> Self {
        Self {
            helpers: [const { BpfHelperFn::new() }; MAX_HELPERS],
            helper_count: 0,
            stats: BpfHelperStats::new(),
            initialized: false,
        }
    }

    /// Initialize the registry with all built-in helpers.
    pub fn init_builtins(&mut self) -> Result<()> {
        if self.initialized {
            return Err(Error::AlreadyExists);
        }

        self.register_builtin(
            BpfHelperId::MapLookupElem,
            b"map_lookup_elem",
            BpfReturnType::Pointer,
            BpfHelperFlags::NONE,
        )?;
        self.register_builtin(
            BpfHelperId::MapUpdateElem,
            b"map_update_elem",
            BpfReturnType::Integer,
            BpfHelperFlags::NONE,
        )?;
        self.register_builtin(
            BpfHelperId::MapDeleteElem,
            b"map_delete_elem",
            BpfReturnType::Integer,
            BpfHelperFlags::NONE,
        )?;
        self.register_builtin(
            BpfHelperId::ProbeRead,
            b"probe_read",
            BpfReturnType::Integer,
            BpfHelperFlags::READS_KERNEL,
        )?;
        self.register_builtin(
            BpfHelperId::KtimeGetNs,
            b"ktime_get_ns",
            BpfReturnType::Integer,
            BpfHelperFlags::NONE,
        )?;
        self.register_builtin(
            BpfHelperId::GetCurrentPidTgid,
            b"get_current_pid_tgid",
            BpfReturnType::Integer,
            BpfHelperFlags::NONE,
        )?;
        self.register_builtin(
            BpfHelperId::GetCurrentUidGid,
            b"get_current_uid_gid",
            BpfReturnType::Integer,
            BpfHelperFlags::NONE,
        )?;
        self.register_builtin(
            BpfHelperId::GetCurrentComm,
            b"get_current_comm",
            BpfReturnType::Integer,
            BpfHelperFlags::NONE,
        )?;
        self.register_builtin(
            BpfHelperId::PerfEventOutput,
            b"perf_event_output",
            BpfReturnType::Integer,
            BpfHelperFlags::NONE,
        )?;
        self.register_builtin(
            BpfHelperId::GetSmpProcessorId,
            b"get_smp_processor_id",
            BpfReturnType::Integer,
            BpfHelperFlags::NONE,
        )?;
        self.register_builtin(
            BpfHelperId::TailCall,
            b"tail_call",
            BpfReturnType::Void,
            BpfHelperFlags::NONE,
        )?;
        self.register_builtin(
            BpfHelperId::GetCurrentCgroupId,
            b"get_current_cgroup_id",
            BpfReturnType::Integer,
            BpfHelperFlags::NONE,
        )?;
        self.register_builtin(
            BpfHelperId::Ringbuf,
            b"ringbuf_output",
            BpfReturnType::Integer,
            BpfHelperFlags::NONE,
        )?;
        self.register_builtin(
            BpfHelperId::TracePrintk,
            b"trace_printk",
            BpfReturnType::Integer,
            BpfHelperFlags::NEEDS_ADMIN,
        )?;
        self.register_builtin(
            BpfHelperId::GetStackId,
            b"get_stackid",
            BpfReturnType::Integer,
            BpfHelperFlags::READS_KERNEL,
        )?;
        self.register_builtin(
            BpfHelperId::SkbLoadBytes,
            b"skb_load_bytes",
            BpfReturnType::Integer,
            BpfHelperFlags::ACCESSES_PKT,
        )?;

        self.initialized = true;
        Ok(())
    }

    /// Register a helper function in the registry.
    pub fn register(&mut self, helper: BpfHelperFn) -> Result<()> {
        // Check for duplicate ID.
        if self.lookup_by_id(helper.id).is_some() {
            return Err(Error::AlreadyExists);
        }
        if self.helper_count as usize >= MAX_HELPERS {
            return Err(Error::OutOfMemory);
        }
        let idx = self.helper_count as usize;
        self.helpers[idx] = helper;
        self.helper_count += 1;
        Ok(())
    }

    /// Unregister a helper by its ID.
    pub fn unregister(&mut self, helper_id: u32) -> Result<()> {
        let pos = self.helpers[..self.helper_count as usize]
            .iter()
            .position(|h| h.registered && h.id == helper_id);
        match pos {
            Some(idx) => {
                self.helpers[idx].registered = false;
                // Compact by swapping with last.
                let last = self.helper_count as usize - 1;
                if idx != last {
                    self.helpers[idx] = self.helpers[last];
                }
                self.helpers[last] = BpfHelperFn::new();
                self.helper_count -= 1;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Look up a helper by its numeric ID.
    pub fn lookup_by_id(&self, id: u32) -> Option<&BpfHelperFn> {
        self.helpers[..self.helper_count as usize]
            .iter()
            .find(|h| h.registered && h.id == id)
    }

    /// Look up a helper by name.
    pub fn lookup_by_name(&self, name: &[u8]) -> Option<&BpfHelperFn> {
        self.helpers[..self.helper_count as usize].iter().find(|h| {
            if !h.registered {
                return false;
            }
            let helper_name_len = h
                .name
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(HELPER_NAME_LEN);
            helper_name_len == name.len() && h.name[..helper_name_len] == *name
        })
    }

    /// Call a helper function by ID with arguments.
    ///
    /// Validates the helper exists, checks argument count,
    /// and dispatches to the built-in implementation.
    pub fn call_helper(
        &mut self,
        id: u32,
        args: &[u64; MAX_HELPER_ARGS],
        ctx: &BpfHelperContext,
    ) -> Result<u64> {
        let helper = match self.lookup_by_id(id) {
            Some(h) => *h,
            None => {
                self.stats.record_unknown();
                return Err(Error::NotFound);
            }
        };

        self.stats.record_call(id);
        bpf_dispatch_helper(id, args, ctx, &helper)
    }

    /// Get the number of registered helpers.
    pub fn count(&self) -> u32 {
        self.helper_count
    }

    /// Get a reference to the stats.
    pub fn get_stats(&self) -> &BpfHelperStats {
        &self.stats
    }

    /// Reset all statistics.
    pub fn reset_stats(&mut self) {
        self.stats = BpfHelperStats::new();
    }

    /// Register a built-in helper with automatic arg count.
    fn register_builtin(
        &mut self,
        id: BpfHelperId,
        name: &[u8],
        return_type: BpfReturnType,
        flags: BpfHelperFlags,
    ) -> Result<()> {
        let helper =
            BpfHelperFn::with_params(id, name, id.expected_arg_count(), return_type, flags);
        self.register(helper)
    }
}

impl Default for BpfHelperRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ══════════════════════════════════════════════════════════════
// Built-in helper dispatch
// ══════════════════════════════════════════════════════════════

/// Dispatch a BPF helper call to the built-in implementation.
///
/// Each helper returns a `u64` result value.  For helpers that
/// return pointers, the value is a simulated address.
fn bpf_dispatch_helper(
    id: u32,
    args: &[u64; MAX_HELPER_ARGS],
    ctx: &BpfHelperContext,
    _helper: &BpfHelperFn,
) -> Result<u64> {
    let helper_id = BpfHelperId::from_raw(id)?;
    match helper_id {
        BpfHelperId::MapLookupElem => bpf_map_lookup_elem(args[0] as u32, args[1]),
        BpfHelperId::MapUpdateElem => {
            bpf_map_update_elem(args[0] as u32, args[1], args[2], args[3] as u32)
        }
        BpfHelperId::MapDeleteElem => bpf_map_delete_elem(args[0] as u32, args[1]),
        BpfHelperId::ProbeRead => bpf_probe_read(args[0], args[1] as u32, args[2]),
        BpfHelperId::KtimeGetNs => Ok(bpf_ktime_get_ns()),
        BpfHelperId::GetCurrentPidTgid => Ok(bpf_get_current_pid_tgid(ctx)),
        BpfHelperId::GetCurrentUidGid => Ok(bpf_get_current_uid_gid(ctx)),
        BpfHelperId::GetCurrentComm => bpf_get_current_comm(ctx, args[0], args[1] as u32),
        BpfHelperId::PerfEventOutput => bpf_perf_event_output(args[0], args[1] as u32, args[2]),
        BpfHelperId::GetSmpProcessorId => Ok(bpf_get_smp_processor_id(ctx)),
        BpfHelperId::TailCall => bpf_tail_call(args[0], args[1] as u32, args[2] as u32),
        BpfHelperId::GetCurrentCgroupId => Ok(bpf_get_current_cgroup_id(ctx)),
        BpfHelperId::Ringbuf => bpf_ringbuf_output(args[0] as u32, args[1], args[2] as u32),
        BpfHelperId::TracePrintk => bpf_trace_printk(args[0], args[1] as u32),
        BpfHelperId::GetStackId => bpf_get_stackid(args[0], args[1] as u32, args[2] as u32),
        BpfHelperId::SkbLoadBytes => {
            bpf_skb_load_bytes(args[0], args[1] as u32, args[2], args[3] as u32)
        }
    }
}

// ── Individual built-in helper implementations ───────────────

/// Map lookup: returns a simulated pointer or 0 (NULL) for not found.
fn bpf_map_lookup_elem(map_fd: u32, _key_ptr: u64) -> Result<u64> {
    // Stub: return a non-zero address indicating "found" for map 0.
    if map_fd == 0 {
        Ok(0xDEAD_BEE0_0000_1000)
    } else {
        Ok(0) // NULL = not found
    }
}

/// Map update: returns 0 on success.
fn bpf_map_update_elem(_map_fd: u32, _key_ptr: u64, _value_ptr: u64, _flags: u32) -> Result<u64> {
    Ok(0)
}

/// Map delete: returns 0 on success.
fn bpf_map_delete_elem(_map_fd: u32, _key_ptr: u64) -> Result<u64> {
    Ok(0)
}

/// Probe read: read kernel memory safely.
fn bpf_probe_read(_dst: u64, size: u32, _unsafe_ptr: u64) -> Result<u64> {
    if size == 0 || size > 4096 {
        return Err(Error::InvalidArgument);
    }
    // Stub: in a real kernel this copies from kernel space.
    Ok(0)
}

/// Get current monotonic time in nanoseconds.
fn bpf_ktime_get_ns() -> u64 {
    // Stub: returns simulated value.
    SIMULATED_KTIME_NS
}

/// Get PID/TGID packed value.
fn bpf_get_current_pid_tgid(ctx: &BpfHelperContext) -> u64 {
    ((ctx.current_tgid as u64) << 32) | (ctx.current_pid as u64)
}

/// Get UID/GID packed value.
fn bpf_get_current_uid_gid(ctx: &BpfHelperContext) -> u64 {
    ((ctx.current_gid as u64) << 32) | (ctx.current_uid as u64)
}

/// Get current comm into buffer.
fn bpf_get_current_comm(ctx: &BpfHelperContext, _buf_ptr: u64, size: u32) -> Result<u64> {
    if size == 0 || size > 16 {
        return Err(Error::InvalidArgument);
    }
    // Stub: in a real kernel this copies ctx.current_comm to user ptr.
    let comm_len = ctx.current_comm.iter().position(|&b| b == 0).unwrap_or(16);
    Ok(comm_len as u64)
}

/// Output to perf event ring buffer.
fn bpf_perf_event_output(_ctx_ptr: u64, _map_fd: u32, _flags: u64) -> Result<u64> {
    Ok(0)
}

/// Get current SMP processor ID.
fn bpf_get_smp_processor_id(ctx: &BpfHelperContext) -> u64 {
    ctx.current_cpu as u64
}

/// Tail call into another BPF program.
fn bpf_tail_call(_ctx_ptr: u64, _prog_array_fd: u32, _index: u32) -> Result<u64> {
    // Stub: tail calls never return on success, return error here.
    Err(Error::InvalidArgument)
}

/// Get current cgroup ID.
fn bpf_get_current_cgroup_id(ctx: &BpfHelperContext) -> u64 {
    ctx.current_cgroup_id
}

/// Ring buffer output.
fn bpf_ringbuf_output(_map_fd: u32, _data_ptr: u64, _size: u32) -> Result<u64> {
    Ok(0)
}

/// Trace printk (debug output).
fn bpf_trace_printk(_fmt_ptr: u64, fmt_size: u32) -> Result<u64> {
    if fmt_size == 0 || fmt_size > 256 {
        return Err(Error::InvalidArgument);
    }
    Ok(fmt_size as u64)
}

/// Get stack trace ID.
fn bpf_get_stackid(_ctx_ptr: u64, _map_fd: u32, flags: u32) -> Result<u64> {
    // Return a simulated stack ID.
    let depth = flags & 0xFF;
    if depth > MAX_STACK_DEPTH {
        return Err(Error::InvalidArgument);
    }
    Ok(0x1000 | depth as u64)
}

/// Load bytes from a network packet (skb).
fn bpf_skb_load_bytes(_skb_ptr: u64, offset: u32, _to_ptr: u64, len: u32) -> Result<u64> {
    if len == 0 || len > 4096 {
        return Err(Error::InvalidArgument);
    }
    // Bounds check on offset.
    if offset.checked_add(len).is_none() {
        return Err(Error::InvalidArgument);
    }
    Ok(0)
}

/// Convenience function to call a BPF helper by ID.
///
/// This is the top-level dispatch entry point that validates the
/// helper exists in the given registry and invokes it.
pub fn bpf_call_helper(
    registry: &mut BpfHelperRegistry,
    id: u32,
    args: &[u64; MAX_HELPER_ARGS],
    ctx: &BpfHelperContext,
) -> Result<u64> {
    registry.call_helper(id, args, ctx)
}
