// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `bpf(2)` syscall handler — thin dispatch layer.
//!
//! This module provides the top-level `bpf(2)` syscall entry point that
//! validates the `union bpf_attr` size and dispatches each command to the
//! appropriate handler in the BPF subsystem.
//!
//! The detailed command implementations live in [`crate::bpf_calls`].
//! This file mirrors the Linux split between `kernel/bpf/syscall.c`
//! (per-command handlers) and the arch-level syscall stub.
//!
//! # Syscall signature
//!
//! ```text
//! int bpf(int cmd, union bpf_attr *attr, unsigned int size);
//! ```
//!
//! # Security model
//!
//! - `CAP_BPF` (or `CAP_SYS_ADMIN` on older kernels) is required for all
//!   operations that load programs or create maps that are accessible to
//!   unprivileged users.
//! - Unprivileged BPF (`/proc/sys/kernel/unprivileged_bpf_disabled`) may
//!   additionally restrict which operations are available.
//!
//! # References
//!
//! - Linux: `kernel/bpf/syscall.c`
//! - `include/uapi/linux/bpf.h`
//! - `bpf(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// BPF command constants (must match `include/uapi/linux/bpf.h`)
// ---------------------------------------------------------------------------

/// Create a new BPF map.
pub const BPF_MAP_CREATE: u32 = 0;
/// Lookup a map element by key.
pub const BPF_MAP_LOOKUP_ELEM: u32 = 1;
/// Insert or update a map element.
pub const BPF_MAP_UPDATE_ELEM: u32 = 2;
/// Delete a map element.
pub const BPF_MAP_DELETE_ELEM: u32 = 3;
/// Get the next key in a map (used for iteration).
pub const BPF_MAP_GET_NEXT_KEY: u32 = 4;
/// Load a verified BPF program.
pub const BPF_PROG_LOAD: u32 = 5;
/// Pin a BPF object to the BPF virtual filesystem.
pub const BPF_OBJ_PIN: u32 = 6;
/// Retrieve a pinned BPF object by path.
pub const BPF_OBJ_GET: u32 = 7;
/// Attach a BPF program to a hook.
pub const BPF_PROG_ATTACH: u32 = 8;
/// Detach a BPF program from a hook.
pub const BPF_PROG_DETACH: u32 = 9;
/// Test-run a BPF program.
pub const BPF_PROG_TEST_RUN: u32 = 10;
/// Get the next program ID.
pub const BPF_PROG_GET_NEXT_ID: u32 = 11;
/// Get the next map ID.
pub const BPF_MAP_GET_NEXT_ID: u32 = 12;
/// Get an fd to a program by ID.
pub const BPF_PROG_GET_FD_BY_ID: u32 = 13;
/// Get an fd to a map by ID.
pub const BPF_MAP_GET_FD_BY_ID: u32 = 14;
/// Get information about a program or map.
pub const BPF_OBJ_GET_INFO_BY_FD: u32 = 15;
/// Query programs attached to a hook.
pub const BPF_PROG_QUERY: u32 = 16;
/// Attach a raw tracepoint.
pub const BPF_RAW_TRACEPOINT_OPEN: u32 = 17;
/// Load BTF (BPF Type Format) data.
pub const BPF_BTF_LOAD: u32 = 18;
/// Get an fd to a BTF object by ID.
pub const BPF_BTF_GET_FD_BY_ID: u32 = 19;
/// Get task file-descriptor info.
pub const BPF_TASK_FD_QUERY: u32 = 20;
/// Lookup and delete a map element atomically.
pub const BPF_MAP_LOOKUP_AND_DELETE_ELEM: u32 = 21;
/// Freeze a BPF map (make it read-only).
pub const BPF_MAP_FREEZE: u32 = 22;
/// Get the next BTF ID.
pub const BPF_BTF_GET_NEXT_ID: u32 = 23;
/// Batch lookup.
pub const BPF_MAP_LOOKUP_BATCH: u32 = 24;
/// Batch lookup and delete.
pub const BPF_MAP_LOOKUP_AND_DELETE_BATCH: u32 = 25;
/// Batch update.
pub const BPF_MAP_UPDATE_BATCH: u32 = 26;
/// Batch delete.
pub const BPF_MAP_DELETE_BATCH: u32 = 27;
/// Create a BPF link.
pub const BPF_LINK_CREATE: u32 = 28;
/// Update a BPF link.
pub const BPF_LINK_UPDATE: u32 = 29;
/// Get an fd to a link by ID.
pub const BPF_LINK_GET_FD_BY_ID: u32 = 30;
/// Get the next link ID.
pub const BPF_LINK_GET_NEXT_ID: u32 = 31;
/// Enable/disable program stats collection.
pub const BPF_ENABLE_STATS: u32 = 32;
/// Iterate map/program/link/btf objects.
pub const BPF_ITER_CREATE: u32 = 33;
/// Pin a BPF link.
pub const BPF_LINK_PIN: u32 = 34;
/// Detach a BPF program from its link target.
pub const BPF_PROG_BIND_MAP: u32 = 35;
/// Retrieve an fd for a token.
pub const BPF_TOKEN_CREATE: u32 = 36;

/// Maximum valid command value.
const BPF_CMD_MAX: u32 = BPF_TOKEN_CREATE;

/// Maximum accepted `bpf_attr` size (bytes).
///
/// The kernel accepts `size` up to the size of `union bpf_attr`; any extra
/// bytes must be zero-padded by user-space.  We cap validation here.
pub const BPF_ATTR_MAX_SIZE: u32 = 256;

// ---------------------------------------------------------------------------
// BPF map type constants
// ---------------------------------------------------------------------------

/// Hash map.
pub const BPF_MAP_TYPE_HASH: u32 = 1;
/// Array map.
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
/// Program array (tail-call table).
pub const BPF_MAP_TYPE_PROG_ARRAY: u32 = 3;
/// Perf event array.
pub const BPF_MAP_TYPE_PERF_EVENT_ARRAY: u32 = 4;
/// Per-CPU hash map.
pub const BPF_MAP_TYPE_PERCPU_HASH: u32 = 5;
/// Per-CPU array.
pub const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;
/// Stack-trace map.
pub const BPF_MAP_TYPE_STACK_TRACE: u32 = 7;
/// cgroup array.
pub const BPF_MAP_TYPE_CGROUP_ARRAY: u32 = 8;
/// Least-recently-used hash map.
pub const BPF_MAP_TYPE_LRU_HASH: u32 = 9;
/// Per-CPU LRU hash map.
pub const BPF_MAP_TYPE_LRU_PERCPU_HASH: u32 = 10;
/// Longest-prefix-match trie map.
pub const BPF_MAP_TYPE_LPM_TRIE: u32 = 11;
/// Array of maps.
pub const BPF_MAP_TYPE_ARRAY_OF_MAPS: u32 = 12;
/// Hash of maps.
pub const BPF_MAP_TYPE_HASH_OF_MAPS: u32 = 13;
/// Device map.
pub const BPF_MAP_TYPE_DEVMAP: u32 = 14;
/// Socket map.
pub const BPF_MAP_TYPE_SOCKMAP: u32 = 15;
/// CPU map.
pub const BPF_MAP_TYPE_CPUMAP: u32 = 16;
/// XSK (AF_XDP) socket map.
pub const BPF_MAP_TYPE_XSKMAP: u32 = 17;
/// Socket hash map.
pub const BPF_MAP_TYPE_SOCKHASH: u32 = 18;
/// cgroup storage map.
pub const BPF_MAP_TYPE_CGROUP_STORAGE: u32 = 19;
/// Reuseport socket array.
pub const BPF_MAP_TYPE_REUSEPORT_SOCKARRAY: u32 = 20;
/// Per-CPU cgroup storage.
pub const BPF_MAP_TYPE_PERCPU_CGROUP_STORAGE: u32 = 21;
/// Queue map.
pub const BPF_MAP_TYPE_QUEUE: u32 = 22;
/// Stack map.
pub const BPF_MAP_TYPE_STACK: u32 = 23;
/// SK storage map.
pub const BPF_MAP_TYPE_SK_STORAGE: u32 = 24;
/// Devmap hash.
pub const BPF_MAP_TYPE_DEVMAP_HASH: u32 = 25;
/// Struct-ops map.
pub const BPF_MAP_TYPE_STRUCT_OPS: u32 = 26;
/// Ring buffer map.
pub const BPF_MAP_TYPE_RINGBUF: u32 = 27;
/// Inode storage map.
pub const BPF_MAP_TYPE_INODE_STORAGE: u32 = 28;
/// Task storage map.
pub const BPF_MAP_TYPE_TASK_STORAGE: u32 = 29;
/// Bloom filter map.
pub const BPF_MAP_TYPE_BLOOM_FILTER: u32 = 30;
/// User ring buffer map.
pub const BPF_MAP_TYPE_USER_RINGBUF: u32 = 31;
/// cgrp storage map.
pub const BPF_MAP_TYPE_CGRP_STORAGE: u32 = 32;
/// Arena map.
pub const BPF_MAP_TYPE_ARENA: u32 = 33;

// ---------------------------------------------------------------------------
// bpf_attr — flat interpretation for validation
// ---------------------------------------------------------------------------

/// Common prefix of `union bpf_attr` used for initial validation.
///
/// The full union is 256 bytes in the Linux UAPI; this struct captures only
/// the first 12 bytes that are shared by all commands.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct BpfAttrCommon {
    /// Map type or program type depending on command.
    pub type_: u32,
    /// Key size in bytes (map commands).
    pub key_size: u32,
    /// Value size in bytes (map commands) / insn_cnt (prog commands).
    pub value_size_or_insn_cnt: u32,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `bpf(2)` syscall.
///
/// `attr_ptr` points to a user-space `union bpf_attr` of `size` bytes.
/// `size` must not exceed [`BPF_ATTR_MAX_SIZE`]; any bytes beyond the
/// portion understood for `cmd` must be zero-padded by user-space.
///
/// Returns a non-negative integer on success (semantics are command-specific)
/// or a negative errno on failure.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown command, `attr_ptr` is null,
///   `size` is 0 or exceeds the maximum, or the attr contains invalid fields.
/// - [`Error::PermissionDenied`] — caller lacks `CAP_BPF` or `CAP_SYS_ADMIN`.
/// - [`Error::NotFound`] — referenced map/program/link does not exist.
/// - [`Error::OutOfMemory`] — resource allocation failed.
/// - [`Error::NotImplemented`] — command is valid but not yet implemented.
pub fn sys_bpf(cmd: u32, attr_ptr: u64, size: u32) -> Result<i64> {
    if attr_ptr == 0 {
        return Err(Error::InvalidArgument);
    }
    if size == 0 || size > BPF_ATTR_MAX_SIZE {
        return Err(Error::InvalidArgument);
    }
    if cmd > BPF_CMD_MAX {
        return Err(Error::InvalidArgument);
    }

    match cmd {
        BPF_MAP_CREATE => do_map_create(attr_ptr, size),
        BPF_MAP_LOOKUP_ELEM => do_map_lookup(attr_ptr, size),
        BPF_MAP_UPDATE_ELEM => do_map_update(attr_ptr, size),
        BPF_MAP_DELETE_ELEM => do_map_delete(attr_ptr, size),
        BPF_MAP_GET_NEXT_KEY => do_map_get_next_key(attr_ptr, size),
        BPF_PROG_LOAD => do_prog_load(attr_ptr, size),
        BPF_OBJ_PIN => do_obj_pin(attr_ptr, size),
        BPF_OBJ_GET => do_obj_get(attr_ptr, size),
        BPF_PROG_ATTACH => do_prog_attach(attr_ptr, size),
        BPF_PROG_DETACH => do_prog_detach(attr_ptr, size),
        BPF_BTF_LOAD => do_btf_load(attr_ptr, size),
        BPF_MAP_FREEZE => do_map_freeze(attr_ptr, size),
        BPF_LINK_CREATE => do_link_create(attr_ptr, size),
        BPF_LINK_UPDATE => do_link_update(attr_ptr, size),
        _ => Err(Error::NotImplemented),
    }
}

// ---------------------------------------------------------------------------
// Per-command stubs
// ---------------------------------------------------------------------------

fn do_map_create(_attr: u64, _size: u32) -> Result<i64> {
    // TODO: allocate a kernel BPF map, install fd, return fd.
    Err(Error::NotImplemented)
}

fn do_map_lookup(_attr: u64, _size: u32) -> Result<i64> {
    // TODO: look up key in map, copy value to user-space.
    Err(Error::NotImplemented)
}

fn do_map_update(_attr: u64, _size: u32) -> Result<i64> {
    // TODO: insert or update key-value pair in map.
    Err(Error::NotImplemented)
}

fn do_map_delete(_attr: u64, _size: u32) -> Result<i64> {
    // TODO: delete key from map.
    Err(Error::NotImplemented)
}

fn do_map_get_next_key(_attr: u64, _size: u32) -> Result<i64> {
    // TODO: return the next key after the given one (for iteration).
    Err(Error::NotImplemented)
}

fn do_prog_load(_attr: u64, _size: u32) -> Result<i64> {
    // TODO: verify and JIT-compile BPF program, install fd.
    Err(Error::NotImplemented)
}

fn do_obj_pin(_attr: u64, _size: u32) -> Result<i64> {
    // TODO: pin map/prog to a BPF-fs path.
    Err(Error::NotImplemented)
}

fn do_obj_get(_attr: u64, _size: u32) -> Result<i64> {
    // TODO: open a pinned BPF-fs object, return fd.
    Err(Error::NotImplemented)
}

fn do_prog_attach(_attr: u64, _size: u32) -> Result<i64> {
    // TODO: attach prog to cgroup/network hook.
    Err(Error::NotImplemented)
}

fn do_prog_detach(_attr: u64, _size: u32) -> Result<i64> {
    // TODO: detach prog from cgroup/network hook.
    Err(Error::NotImplemented)
}

fn do_btf_load(_attr: u64, _size: u32) -> Result<i64> {
    // TODO: parse and validate BTF data, create BTF object.
    Err(Error::NotImplemented)
}

fn do_map_freeze(_attr: u64, _size: u32) -> Result<i64> {
    // TODO: mark map as read-only.
    Err(Error::NotImplemented)
}

fn do_link_create(_attr: u64, _size: u32) -> Result<i64> {
    // TODO: create a BPF link, return fd.
    Err(Error::NotImplemented)
}

fn do_link_update(_attr: u64, _size: u32) -> Result<i64> {
    // TODO: replace the program in a BPF link.
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_bpf(cmd: u32, attr_ptr: u64, size: u32) -> Result<i64> {
    sys_bpf(cmd, attr_ptr, size)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bpf_null_attr_rejected() {
        assert_eq!(
            sys_bpf(BPF_MAP_CREATE, 0, 8).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn bpf_zero_size_rejected() {
        assert_eq!(
            sys_bpf(BPF_MAP_CREATE, 0x1000, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn bpf_oversized_attr_rejected() {
        assert_eq!(
            sys_bpf(BPF_MAP_CREATE, 0x1000, BPF_ATTR_MAX_SIZE + 1).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn bpf_unknown_cmd_rejected() {
        assert_eq!(
            sys_bpf(BPF_CMD_MAX + 1, 0x1000, 8).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn bpf_not_implemented_returns_error() {
        // Valid cmd but stub not implemented — expect NotImplemented.
        assert_eq!(
            sys_bpf(BPF_MAP_CREATE, 0x1000, 8).unwrap_err(),
            Error::NotImplemented
        );
    }
}
