// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `bpf(2)` — BPF system call interface.
//!
//! This module implements the `bpf` system call which provides user-space
//! access to the in-kernel BPF virtual machine subsystem. It supports
//! map creation and manipulation, program loading and attachment, and
//! object pinning to the BPF filesystem.
//!
//! # Syscall signature
//!
//! ```text
//! int bpf(int cmd, union bpf_attr *attr, unsigned int size);
//! ```
//!
//! # Commands
//!
//! | Command | Description |
//! |---------|-------------|
//! | `BPF_MAP_CREATE` | Create a new BPF map |
//! | `BPF_MAP_LOOKUP_ELEM` | Look up a value by key |
//! | `BPF_MAP_UPDATE_ELEM` | Insert or update a key-value pair |
//! | `BPF_MAP_DELETE_ELEM` | Delete a key from the map |
//! | `BPF_PROG_LOAD` | Load a BPF program |
//! | `BPF_PROG_ATTACH` | Attach a program to a target |
//! | `BPF_PROG_DETACH` | Detach a program from a target |
//! | `BPF_OBJ_PIN` | Pin an object to BPF filesystem |
//! | `BPF_OBJ_GET` | Retrieve a pinned object |
//! | `BPF_PROG_TEST_RUN` | Test-run a BPF program |
//! | `BPF_BTF_LOAD` | Load BTF (BPF Type Format) data |
//!
//! # References
//!
//! - Linux: `kernel/bpf/syscall.c`, `include/uapi/linux/bpf.h`
//! - `bpf(2)` man page

extern crate alloc;

use alloc::vec::Vec;
use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants — BPF commands
// ---------------------------------------------------------------------------

/// Create a new BPF map.
pub const BPF_MAP_CREATE: u32 = 0;
/// Look up a map element by key.
pub const BPF_MAP_LOOKUP_ELEM: u32 = 1;
/// Update or insert a map element.
pub const BPF_MAP_UPDATE_ELEM: u32 = 2;
/// Delete a map element by key.
pub const BPF_MAP_DELETE_ELEM: u32 = 3;
/// Iterate to the next map key.
pub const BPF_MAP_GET_NEXT_KEY: u32 = 4;
/// Load a BPF program.
pub const BPF_PROG_LOAD: u32 = 5;
/// Attach a BPF program to a target.
pub const BPF_OBJ_PIN: u32 = 6;
/// Retrieve a pinned BPF object.
pub const BPF_OBJ_GET: u32 = 7;
/// Attach a BPF program.
pub const BPF_PROG_ATTACH: u32 = 8;
/// Detach a BPF program.
pub const BPF_PROG_DETACH: u32 = 9;
/// Test-run a BPF program with provided data.
pub const BPF_PROG_TEST_RUN: u32 = 10;
/// Load BTF (BPF Type Format) metadata.
pub const BPF_BTF_LOAD: u32 = 18;

// ---------------------------------------------------------------------------
// Constants — BPF map types
// ---------------------------------------------------------------------------

/// Hash table map.
pub const BPF_MAP_TYPE_HASH: u32 = 1;
/// Array map (integer keys 0..max_entries-1).
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
/// Program array (for tail calls).
pub const BPF_MAP_TYPE_PROG_ARRAY: u32 = 3;
/// Per-CPU hash table.
pub const BPF_MAP_TYPE_PERCPU_HASH: u32 = 4;
/// Per-CPU array.
pub const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 5;
/// LRU hash table.
pub const BPF_MAP_TYPE_LRU_HASH: u32 = 9;
/// Ring buffer.
pub const BPF_MAP_TYPE_RINGBUF: u32 = 27;

/// Maximum valid built-in map type.
const BPF_MAP_TYPE_MAX: u32 = 33;

// ---------------------------------------------------------------------------
// Constants — BPF program types
// ---------------------------------------------------------------------------

/// Socket filter program.
pub const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;
/// Traffic classifier (tc) program.
pub const BPF_PROG_TYPE_SCHED_CLS: u32 = 3;
/// Traffic action (tc) program.
pub const BPF_PROG_TYPE_SCHED_ACT: u32 = 4;
/// Tracepoint program.
pub const BPF_PROG_TYPE_TRACEPOINT: u32 = 5;
/// XDP (eXpress Data Path) program.
pub const BPF_PROG_TYPE_XDP: u32 = 6;
/// cgroup/skb program.
pub const BPF_PROG_TYPE_CGROUP_SKB: u32 = 8;
/// kprobe program.
pub const BPF_PROG_TYPE_KPROBE: u32 = 2;

/// Maximum valid built-in program type.
const BPF_PROG_TYPE_MAX: u32 = 32;

// ---------------------------------------------------------------------------
// Constants — BPF map update flags
// ---------------------------------------------------------------------------

/// Create new element or update existing (default).
pub const BPF_ANY: u64 = 0;
/// Create new element only if key does not exist.
pub const BPF_NOEXIST: u64 = 1;
/// Update existing element only.
pub const BPF_EXIST: u64 = 2;
/// Spin lock-friendly update.
pub const BPF_F_LOCK: u64 = 4;

// ---------------------------------------------------------------------------
// Constants — BPF attach types
// ---------------------------------------------------------------------------

/// Attach to cgroup ingress path.
pub const BPF_CGROUP_INET_INGRESS: u32 = 0;
/// Attach to cgroup egress path.
pub const BPF_CGROUP_INET_EGRESS: u32 = 1;
/// Attach to cgroup/sock_create.
pub const BPF_CGROUP_INET_SOCK_CREATE: u32 = 2;
/// Attach to XDP hook.
pub const BPF_XDP: u32 = 37;

// ---------------------------------------------------------------------------
// Constants — capability checks
// ---------------------------------------------------------------------------

/// Required capability for BPF operations.
pub const CAP_SYS_ADMIN: u32 = 21;
/// Required capability for BPF networking.
pub const CAP_NET_ADMIN: u32 = 12;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Maximum number of BPF maps.
const MAX_MAPS: usize = 64;
/// Maximum number of BPF programs.
const MAX_PROGS: usize = 64;
/// Maximum BPF program instructions.
const MAX_INSN_COUNT: usize = 4096;
/// Maximum map key size in bytes.
const MAX_KEY_SIZE: u32 = 512;
/// Maximum map value size in bytes.
const MAX_VALUE_SIZE: u32 = 65536;
/// Maximum number of entries in a map.
const MAX_MAP_ENTRIES: u32 = 1 << 20;
/// Maximum path length for pinned objects.
const MAX_PIN_PATH_LEN: usize = 256;
/// Maximum number of pinned objects.
const MAX_PINNED_OBJECTS: usize = 128;
/// Maximum BTF data size.
const MAX_BTF_SIZE: usize = 65536;

// ---------------------------------------------------------------------------
// BpfMapAttr — map creation attributes
// ---------------------------------------------------------------------------

/// Attributes for `BPF_MAP_CREATE`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BpfMapAttr {
    /// Map type (BPF_MAP_TYPE_*).
    pub map_type: u32,
    /// Key size in bytes.
    pub key_size: u32,
    /// Value size in bytes.
    pub value_size: u32,
    /// Maximum number of entries.
    pub max_entries: u32,
    /// Map creation flags.
    pub map_flags: u32,
}

impl BpfMapAttr {
    /// Validate map creation attributes.
    pub fn validate(&self) -> Result<()> {
        if self.map_type == 0 || self.map_type >= BPF_MAP_TYPE_MAX {
            return Err(Error::InvalidArgument);
        }
        if self.key_size == 0 || self.key_size > MAX_KEY_SIZE {
            return Err(Error::InvalidArgument);
        }
        if self.value_size == 0 || self.value_size > MAX_VALUE_SIZE {
            return Err(Error::InvalidArgument);
        }
        if self.max_entries == 0 || self.max_entries > MAX_MAP_ENTRIES {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BpfProgAttr — program load attributes
// ---------------------------------------------------------------------------

/// Attributes for `BPF_PROG_LOAD`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BpfProgAttr {
    /// Program type (BPF_PROG_TYPE_*).
    pub prog_type: u32,
    /// Number of instructions.
    pub insn_cnt: u32,
    /// License string hash (GPL-compatible = 1, proprietary = 0).
    pub license_gpl: u32,
    /// Log level (0 = no log, 1 = verbose).
    pub log_level: u32,
    /// Expected attach type.
    pub expected_attach_type: u32,
}

impl BpfProgAttr {
    /// Validate program load attributes.
    pub fn validate(&self) -> Result<()> {
        if self.prog_type == 0 || self.prog_type >= BPF_PROG_TYPE_MAX {
            return Err(Error::InvalidArgument);
        }
        if self.insn_cnt == 0 || self.insn_cnt as usize > MAX_INSN_COUNT {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BpfMap — in-kernel BPF map
// ---------------------------------------------------------------------------

/// A BPF map instance.
///
/// Stores key-value pairs in a flat array. Keys and values are
/// stored as byte slices of fixed sizes.
pub struct BpfMap {
    /// Map file descriptor (unique ID).
    pub fd: i32,
    /// Map type.
    pub map_type: u32,
    /// Key size in bytes.
    pub key_size: u32,
    /// Value size in bytes.
    pub value_size: u32,
    /// Maximum number of entries.
    pub max_entries: u32,
    /// Map flags.
    pub flags: u32,
    /// Number of active entries.
    entry_count: u32,
    /// Flat storage: each entry is `key_size + value_size` bytes,
    /// prefixed by a 1-byte occupied flag.
    storage: Vec<u8>,
    /// Entry stride (1 + key_size + value_size).
    stride: usize,
}

impl BpfMap {
    /// Create a new BPF map from validated attributes.
    pub fn new(fd: i32, attr: &BpfMapAttr) -> Self {
        let stride = 1 + attr.key_size as usize + attr.value_size as usize;
        let total = stride * attr.max_entries as usize;
        let mut storage = Vec::new();
        storage.resize(total, 0u8);
        Self {
            fd,
            map_type: attr.map_type,
            key_size: attr.key_size,
            value_size: attr.value_size,
            max_entries: attr.max_entries,
            flags: attr.map_flags,
            entry_count: 0,
            storage,
            stride,
        }
    }

    /// Look up a value by key. Returns a slice into the value bytes.
    pub fn lookup(&self, key: &[u8]) -> Result<&[u8]> {
        if key.len() != self.key_size as usize {
            return Err(Error::InvalidArgument);
        }
        for i in 0..self.max_entries as usize {
            let base = i * self.stride;
            if self.storage[base] == 0 {
                continue;
            }
            let k_start = base + 1;
            let k_end = k_start + self.key_size as usize;
            if &self.storage[k_start..k_end] == key {
                let v_start = k_end;
                let v_end = v_start + self.value_size as usize;
                return Ok(&self.storage[v_start..v_end]);
            }
        }
        Err(Error::NotFound)
    }

    /// Update or insert a key-value pair.
    pub fn update(&mut self, key: &[u8], value: &[u8], update_flags: u64) -> Result<()> {
        if key.len() != self.key_size as usize {
            return Err(Error::InvalidArgument);
        }
        if value.len() != self.value_size as usize {
            return Err(Error::InvalidArgument);
        }

        // Search for existing entry.
        let ks = self.key_size as usize;
        let vs = self.value_size as usize;
        for i in 0..self.max_entries as usize {
            let base = i * self.stride;
            if self.storage[base] == 0 {
                continue;
            }
            let k_start = base + 1;
            let k_end = k_start + ks;
            if self.storage[k_start..k_end] == *key {
                if update_flags == BPF_NOEXIST {
                    return Err(Error::AlreadyExists);
                }
                let v_start = k_end;
                self.storage[v_start..v_start + vs].copy_from_slice(value);
                return Ok(());
            }
        }

        // Key not found — insert new.
        if update_flags == BPF_EXIST {
            return Err(Error::NotFound);
        }
        if self.entry_count >= self.max_entries {
            return Err(Error::OutOfMemory);
        }

        // Find empty slot.
        for i in 0..self.max_entries as usize {
            let base = i * self.stride;
            if self.storage[base] == 0 {
                self.storage[base] = 1; // occupied
                let k_start = base + 1;
                self.storage[k_start..k_start + ks].copy_from_slice(key);
                let v_start = k_start + ks;
                self.storage[v_start..v_start + vs].copy_from_slice(value);
                self.entry_count += 1;
                return Ok(());
            }
        }

        Err(Error::OutOfMemory)
    }

    /// Delete an element by key.
    pub fn delete(&mut self, key: &[u8]) -> Result<()> {
        if key.len() != self.key_size as usize {
            return Err(Error::InvalidArgument);
        }
        let ks = self.key_size as usize;
        for i in 0..self.max_entries as usize {
            let base = i * self.stride;
            if self.storage[base] == 0 {
                continue;
            }
            let k_start = base + 1;
            let k_end = k_start + ks;
            if self.storage[k_start..k_end] == *key {
                // Zero out the slot.
                let end = base + self.stride;
                for byte in &mut self.storage[base..end] {
                    *byte = 0;
                }
                self.entry_count = self.entry_count.saturating_sub(1);
                return Ok(());
            }
        }
        Err(Error::NotFound)
    }

    /// Return the number of entries in the map.
    pub const fn entry_count(&self) -> u32 {
        self.entry_count
    }
}

// ---------------------------------------------------------------------------
// BpfProg — loaded BPF program
// ---------------------------------------------------------------------------

/// A loaded BPF program.
#[derive(Debug, Clone, Copy)]
pub struct BpfProg {
    /// Program file descriptor (unique ID).
    pub fd: i32,
    /// Program type.
    pub prog_type: u32,
    /// Number of instructions.
    pub insn_cnt: u32,
    /// Whether the program is GPL-licensed.
    pub gpl_compatible: bool,
    /// Attach type for this program.
    pub attach_type: u32,
    /// Whether the program is currently attached.
    pub attached: bool,
    /// Target fd the program is attached to (if any).
    pub attach_target_fd: i32,
}

impl BpfProg {
    /// Create a new program from validated attributes.
    pub fn new(fd: i32, attr: &BpfProgAttr) -> Self {
        Self {
            fd,
            prog_type: attr.prog_type,
            insn_cnt: attr.insn_cnt,
            gpl_compatible: attr.license_gpl != 0,
            attach_type: attr.expected_attach_type,
            attached: false,
            attach_target_fd: -1,
        }
    }
}

// ---------------------------------------------------------------------------
// BpfPinnedObject — object pinned to BPF filesystem
// ---------------------------------------------------------------------------

/// Type of pinned BPF object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfObjType {
    /// A pinned map.
    Map,
    /// A pinned program.
    Prog,
}

/// A BPF object pinned to the BPF filesystem.
#[derive(Debug, Clone, Copy)]
pub struct BpfPinnedObject {
    /// Object type.
    pub obj_type: BpfObjType,
    /// File descriptor of the pinned object.
    pub fd: i32,
    /// Path hash (simplified — real impl uses the full path).
    pub path_hash: u64,
}

// ---------------------------------------------------------------------------
// BpfTestRunResult — result of BPF_PROG_TEST_RUN
// ---------------------------------------------------------------------------

/// Result of running a BPF program in test mode.
#[derive(Debug, Clone, Copy)]
pub struct BpfTestRunResult {
    /// Return value of the BPF program.
    pub retval: u32,
    /// Duration of the test run in nanoseconds.
    pub duration_ns: u32,
    /// Output data size.
    pub data_size_out: u32,
}

// ---------------------------------------------------------------------------
// BpfContext — per-process BPF context
// ---------------------------------------------------------------------------

/// Per-process BPF subsystem context.
///
/// Manages maps, programs, and pinned objects.
pub struct BpfContext {
    /// Allocated maps (indexed by slot).
    maps: [Option<BpfMap>; MAX_MAPS],
    /// Loaded programs.
    progs: [Option<BpfProg>; MAX_PROGS],
    /// Pinned objects.
    pinned: [Option<BpfPinnedObject>; MAX_PINNED_OBJECTS],
    /// Number of maps.
    map_count: usize,
    /// Number of programs.
    prog_count: usize,
    /// Number of pinned objects.
    pinned_count: usize,
    /// Next fd to allocate.
    next_fd: i32,
    /// Caller capabilities (bitmap).
    capabilities: u64,
}

impl BpfContext {
    /// Create a new BPF context with no capabilities.
    pub fn new() -> Self {
        Self {
            maps: [const { None }; MAX_MAPS],
            progs: [const { None }; MAX_PROGS],
            pinned: [const { None }; MAX_PINNED_OBJECTS],
            map_count: 0,
            prog_count: 0,
            pinned_count: 0,
            next_fd: 200,
            capabilities: 0,
        }
    }

    /// Create a context with specified capabilities.
    pub fn with_capabilities(caps: u64) -> Self {
        let mut ctx = Self::new();
        ctx.capabilities = caps;
        ctx
    }

    /// Check if the caller has a specific capability.
    fn has_cap(&self, cap: u32) -> bool {
        self.capabilities & (1u64 << cap) != 0
    }

    /// Check that the caller has CAP_SYS_ADMIN or CAP_NET_ADMIN.
    fn check_bpf_permission(&self) -> Result<()> {
        if !self.has_cap(CAP_SYS_ADMIN) && !self.has_cap(CAP_NET_ADMIN) {
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }

    /// Allocate a new fd.
    fn alloc_fd(&mut self) -> i32 {
        let fd = self.next_fd;
        self.next_fd += 1;
        fd
    }

    /// Find a free map slot.
    fn find_free_map_slot(&self) -> Result<usize> {
        for (i, slot) in self.maps.iter().enumerate() {
            if slot.is_none() {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a map by fd.
    fn find_map_by_fd(&self, fd: i32) -> Result<usize> {
        for (i, slot) in self.maps.iter().enumerate() {
            if let Some(m) = slot {
                if m.fd == fd {
                    return Ok(i);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Find a free program slot.
    fn find_free_prog_slot(&self) -> Result<usize> {
        for (i, slot) in self.progs.iter().enumerate() {
            if slot.is_none() {
                return Ok(i);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Find a program by fd.
    fn find_prog_by_fd(&self, fd: i32) -> Result<usize> {
        for (i, slot) in self.progs.iter().enumerate() {
            if let Some(p) = slot {
                if p.fd == fd {
                    return Ok(i);
                }
            }
        }
        Err(Error::NotFound)
    }

    // -----------------------------------------------------------------------
    // Map operations
    // -----------------------------------------------------------------------

    /// Create a new BPF map.
    pub fn map_create(&mut self, attr: &BpfMapAttr) -> Result<i32> {
        self.check_bpf_permission()?;
        attr.validate()?;
        let slot = self.find_free_map_slot()?;
        let fd = self.alloc_fd();
        self.maps[slot] = Some(BpfMap::new(fd, attr));
        self.map_count += 1;
        Ok(fd)
    }

    /// Look up an element in a BPF map.
    pub fn map_lookup_elem(&self, map_fd: i32, key: &[u8]) -> Result<&[u8]> {
        let slot = self.find_map_by_fd(map_fd)?;
        match &self.maps[slot] {
            Some(m) => m.lookup(key),
            None => Err(Error::NotFound),
        }
    }

    /// Update an element in a BPF map.
    pub fn map_update_elem(
        &mut self,
        map_fd: i32,
        key: &[u8],
        value: &[u8],
        flags: u64,
    ) -> Result<()> {
        let slot = self.find_map_by_fd(map_fd)?;
        match &mut self.maps[slot] {
            Some(m) => m.update(key, value, flags),
            None => Err(Error::NotFound),
        }
    }

    /// Delete an element from a BPF map.
    pub fn map_delete_elem(&mut self, map_fd: i32, key: &[u8]) -> Result<()> {
        let slot = self.find_map_by_fd(map_fd)?;
        match &mut self.maps[slot] {
            Some(m) => m.delete(key),
            None => Err(Error::NotFound),
        }
    }

    // -----------------------------------------------------------------------
    // Program operations
    // -----------------------------------------------------------------------

    /// Load a BPF program.
    pub fn prog_load(&mut self, attr: &BpfProgAttr) -> Result<i32> {
        self.check_bpf_permission()?;
        attr.validate()?;
        let slot = self.find_free_prog_slot()?;
        let fd = self.alloc_fd();
        self.progs[slot] = Some(BpfProg::new(fd, attr));
        self.prog_count += 1;
        Ok(fd)
    }

    /// Attach a BPF program to a target.
    pub fn prog_attach(&mut self, prog_fd: i32, target_fd: i32, attach_type: u32) -> Result<()> {
        self.check_bpf_permission()?;
        let slot = self.find_prog_by_fd(prog_fd)?;
        match &mut self.progs[slot] {
            Some(p) => {
                if p.attached {
                    return Err(Error::Busy);
                }
                p.attached = true;
                p.attach_type = attach_type;
                p.attach_target_fd = target_fd;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Detach a BPF program from its target.
    pub fn prog_detach(&mut self, prog_fd: i32) -> Result<()> {
        let slot = self.find_prog_by_fd(prog_fd)?;
        match &mut self.progs[slot] {
            Some(p) => {
                if !p.attached {
                    return Err(Error::InvalidArgument);
                }
                p.attached = false;
                p.attach_target_fd = -1;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// Test-run a BPF program with synthetic input.
    pub fn prog_test_run(&self, prog_fd: i32) -> Result<BpfTestRunResult> {
        let slot = self.find_prog_by_fd(prog_fd)?;
        match &self.progs[slot] {
            Some(_) => {
                // In a real kernel the BPF interpreter would execute here.
                // Return a synthetic result for structural correctness.
                Ok(BpfTestRunResult {
                    retval: 0,
                    duration_ns: 0,
                    data_size_out: 0,
                })
            }
            None => Err(Error::NotFound),
        }
    }

    // -----------------------------------------------------------------------
    // Object pinning
    // -----------------------------------------------------------------------

    /// Pin a BPF object (map or program) to the BPF filesystem.
    pub fn obj_pin(&mut self, fd: i32, path_hash: u64) -> Result<()> {
        self.check_bpf_permission()?;

        // Check that fd is a known map or program.
        let obj_type = if self.find_map_by_fd(fd).is_ok() {
            BpfObjType::Map
        } else if self.find_prog_by_fd(fd).is_ok() {
            BpfObjType::Prog
        } else {
            return Err(Error::NotFound);
        };

        // Check for duplicate pin path.
        for slot in &self.pinned {
            if let Some(p) = slot {
                if p.path_hash == path_hash {
                    return Err(Error::AlreadyExists);
                }
            }
        }

        // Find free slot.
        for slot in &mut self.pinned {
            if slot.is_none() {
                *slot = Some(BpfPinnedObject {
                    obj_type,
                    fd,
                    path_hash,
                });
                self.pinned_count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Retrieve a pinned BPF object by path hash.
    pub fn obj_get(&self, path_hash: u64) -> Result<i32> {
        for slot in &self.pinned {
            if let Some(p) = slot {
                if p.path_hash == path_hash {
                    return Ok(p.fd);
                }
            }
        }
        Err(Error::NotFound)
    }

    /// Return the number of loaded maps.
    pub const fn map_count(&self) -> usize {
        self.map_count
    }

    /// Return the number of loaded programs.
    pub const fn prog_count(&self) -> usize {
        self.prog_count
    }
}

impl Default for BpfContext {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Syscall dispatch
// ---------------------------------------------------------------------------

/// Dispatch the `bpf(2)` syscall by command.
///
/// # Arguments
///
/// - `ctx` — Per-process BPF context.
/// - `cmd` — BPF command (BPF_MAP_CREATE, etc.).
///
/// # Returns
///
/// Command-specific result encoded as `i64`:
/// - For map/prog creation: the new file descriptor.
/// - For lookups/updates/deletes: 0 on success.
///
/// # Errors
///
/// - `InvalidArgument` — Unknown command.
/// - `PermissionDenied` — Caller lacks required capabilities.
/// - `OutOfMemory` — No free slots for maps or programs.
/// - `NotFound` — Referenced fd does not exist.
pub fn sys_bpf_dispatch(ctx: &mut BpfContext, cmd: u32) -> Result<i64> {
    match cmd {
        BPF_MAP_CREATE | BPF_MAP_LOOKUP_ELEM | BPF_MAP_UPDATE_ELEM | BPF_MAP_DELETE_ELEM
        | BPF_MAP_GET_NEXT_KEY | BPF_PROG_LOAD | BPF_OBJ_PIN | BPF_OBJ_GET | BPF_PROG_ATTACH
        | BPF_PROG_DETACH | BPF_PROG_TEST_RUN | BPF_BTF_LOAD => {
            // In a real kernel, the attr union would be decoded here
            // based on the command. We return NotImplemented for
            // commands that require user-space attr data we don't have
            // in this dispatch stub.
            let _ = ctx;
            Err(Error::NotImplemented)
        }
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn admin_ctx() -> BpfContext {
        BpfContext::with_capabilities(1u64 << CAP_SYS_ADMIN)
    }

    fn hash_map_attr() -> BpfMapAttr {
        BpfMapAttr {
            map_type: BPF_MAP_TYPE_HASH,
            key_size: 4,
            value_size: 8,
            max_entries: 16,
            map_flags: 0,
        }
    }

    fn socket_filter_attr() -> BpfProgAttr {
        BpfProgAttr {
            prog_type: BPF_PROG_TYPE_SOCKET_FILTER,
            insn_cnt: 10,
            license_gpl: 1,
            log_level: 0,
            expected_attach_type: 0,
        }
    }

    #[test]
    fn test_map_create() {
        let mut ctx = admin_ctx();
        let fd = ctx.map_create(&hash_map_attr());
        assert!(fd.is_ok());
        assert_eq!(ctx.map_count(), 1);
    }

    #[test]
    fn test_map_create_permission_denied() {
        let mut ctx = BpfContext::new();
        assert_eq!(
            ctx.map_create(&hash_map_attr()).unwrap_err(),
            Error::PermissionDenied,
        );
    }

    #[test]
    fn test_map_create_bad_attr() {
        let mut ctx = admin_ctx();
        let mut attr = hash_map_attr();
        attr.key_size = 0;
        assert_eq!(ctx.map_create(&attr).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn test_map_lookup_update_delete() {
        let mut ctx = admin_ctx();
        let fd = ctx.map_create(&hash_map_attr()).unwrap();

        let key = [1u8, 0, 0, 0];
        let value = [42u8, 0, 0, 0, 0, 0, 0, 0];

        // Insert.
        assert!(ctx.map_update_elem(fd, &key, &value, BPF_ANY).is_ok());

        // Lookup.
        let got = ctx.map_lookup_elem(fd, &key).unwrap();
        assert_eq!(got, &value);

        // Delete.
        assert!(ctx.map_delete_elem(fd, &key).is_ok());
        assert_eq!(ctx.map_lookup_elem(fd, &key).unwrap_err(), Error::NotFound,);
    }

    #[test]
    fn test_map_update_noexist() {
        let mut ctx = admin_ctx();
        let fd = ctx.map_create(&hash_map_attr()).unwrap();
        let key = [1u8, 0, 0, 0];
        let value = [0u8; 8];

        assert!(ctx.map_update_elem(fd, &key, &value, BPF_NOEXIST).is_ok());
        assert_eq!(
            ctx.map_update_elem(fd, &key, &value, BPF_NOEXIST)
                .unwrap_err(),
            Error::AlreadyExists,
        );
    }

    #[test]
    fn test_map_update_exist() {
        let mut ctx = admin_ctx();
        let fd = ctx.map_create(&hash_map_attr()).unwrap();
        let key = [1u8, 0, 0, 0];
        let value = [0u8; 8];

        // BPF_EXIST on non-existent key fails.
        assert_eq!(
            ctx.map_update_elem(fd, &key, &value, BPF_EXIST)
                .unwrap_err(),
            Error::NotFound,
        );
    }

    #[test]
    fn test_prog_load() {
        let mut ctx = admin_ctx();
        let fd = ctx.prog_load(&socket_filter_attr());
        assert!(fd.is_ok());
        assert_eq!(ctx.prog_count(), 1);
    }

    #[test]
    fn test_prog_load_bad_type() {
        let mut ctx = admin_ctx();
        let mut attr = socket_filter_attr();
        attr.prog_type = 0;
        assert_eq!(ctx.prog_load(&attr).unwrap_err(), Error::InvalidArgument);
    }

    #[test]
    fn test_prog_attach_detach() {
        let mut ctx = admin_ctx();
        let prog_fd = ctx.prog_load(&socket_filter_attr()).unwrap();

        assert!(
            ctx.prog_attach(prog_fd, 10, BPF_CGROUP_INET_INGRESS)
                .is_ok()
        );
        // Attach again should fail (already attached).
        assert_eq!(
            ctx.prog_attach(prog_fd, 10, BPF_CGROUP_INET_INGRESS)
                .unwrap_err(),
            Error::Busy,
        );
        assert!(ctx.prog_detach(prog_fd).is_ok());
    }

    #[test]
    fn test_prog_test_run() {
        let mut ctx = admin_ctx();
        let fd = ctx.prog_load(&socket_filter_attr()).unwrap();
        let result = ctx.prog_test_run(fd);
        assert!(result.is_ok());
    }

    #[test]
    fn test_obj_pin_get() {
        let mut ctx = admin_ctx();
        let map_fd = ctx.map_create(&hash_map_attr()).unwrap();
        let path_hash: u64 = 0xDEAD_BEEF;

        assert!(ctx.obj_pin(map_fd, path_hash).is_ok());
        let got_fd = ctx.obj_get(path_hash).unwrap();
        assert_eq!(got_fd, map_fd);
    }

    #[test]
    fn test_obj_pin_duplicate() {
        let mut ctx = admin_ctx();
        let fd = ctx.map_create(&hash_map_attr()).unwrap();
        let hash: u64 = 123;
        assert!(ctx.obj_pin(fd, hash).is_ok());
        assert_eq!(ctx.obj_pin(fd, hash).unwrap_err(), Error::AlreadyExists);
    }

    #[test]
    fn test_dispatch_unknown_cmd() {
        let mut ctx = admin_ctx();
        assert_eq!(
            sys_bpf_dispatch(&mut ctx, 999).unwrap_err(),
            Error::InvalidArgument,
        );
    }

    #[test]
    fn test_dispatch_known_cmd() {
        let mut ctx = admin_ctx();
        // Known commands return NotImplemented (need attr data).
        assert_eq!(
            sys_bpf_dispatch(&mut ctx, BPF_MAP_CREATE).unwrap_err(),
            Error::NotImplemented,
        );
    }

    #[test]
    fn test_map_delete_nonexistent() {
        let mut ctx = admin_ctx();
        let fd = ctx.map_create(&hash_map_attr()).unwrap();
        let key = [99u8, 0, 0, 0];
        assert_eq!(ctx.map_delete_elem(fd, &key).unwrap_err(), Error::NotFound);
    }

    #[test]
    fn test_map_bad_key_size() {
        let mut ctx = admin_ctx();
        let fd = ctx.map_create(&hash_map_attr()).unwrap();
        let bad_key = [1u8, 2]; // 2 bytes, expected 4
        assert_eq!(
            ctx.map_lookup_elem(fd, &bad_key).unwrap_err(),
            Error::InvalidArgument,
        );
    }
}
