// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Extended `prctl(2)` operation handlers — memory-tagging, speculation
//! control, SVE/SME vector length, tagged addresses, and syscall user dispatch.
//!
//! This module complements the core `prctl.rs` module with newer Linux prctl
//! options added from kernel 5.0 onwards.  Each operation is self-contained and
//! operates on a [`PrctlExtState`] per-process structure.
//!
//! # Covered operations
//!
//! | Option                       | Constant | Purpose                         |
//! |------------------------------|----------|---------------------------------|
//! | `PR_SET_TAGGED_ADDR_CTRL`    | 55       | AArch64 tagged address control  |
//! | `PR_GET_TAGGED_ADDR_CTRL`    | 56       | Read tagged address flags       |
//! | `PR_SET_IO_FLUSHER`          | 57       | Mark process as I/O flusher     |
//! | `PR_GET_IO_FLUSHER`          | 58       | Query I/O flusher status        |
//! | `PR_SET_SPECULATION_CTRL`    | 53       | Speculation mitigation control  |
//! | `PR_GET_SPECULATION_CTRL`    | 52       | Query speculation mitigations   |
//! | `PR_SET_SYSCALL_USER_DISPATCH` | 59     | Syscall user dispatch mode      |
//! | `PR_SVE_SET_VL`              | 50       | Set SVE vector length           |
//! | `PR_SVE_GET_VL`              | 51       | Get SVE vector length           |
//! | `PR_SET_VMA`                 | 0x53564d41 | Set VMA name annotation      |
//! | `PR_RISCV_SET_ICACHE_FLUSH_CTX` | 71    | RISC-V icache flush context     |
//! | `PR_SET_MDWE`                | 65       | Memory-deny write-execute       |
//! | `PR_GET_MDWE`                | 66       | Query MDWE state                |
//!
//! # References
//!
//! - Linux: `include/uapi/linux/prctl.h`, `kernel/sys.c`
//! - AArch64 MTE: `Documentation/arm64/memory-tagging-extension.rst`
//! - Speculation: `Documentation/userspace-api/spec_ctrl.rst`

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Option constants (newer Linux prctl options)
// ---------------------------------------------------------------------------

/// Get speculation misfeature status.
pub const PR_GET_SPECULATION_CTRL: i32 = 52;
/// Set speculation misfeature control.
pub const PR_SET_SPECULATION_CTRL: i32 = 53;
/// Set SVE vector length.
pub const PR_SVE_SET_VL: i32 = 50;
/// Get SVE vector length.
pub const PR_SVE_GET_VL: i32 = 51;
/// Set AArch64 tagged address control flags.
pub const PR_SET_TAGGED_ADDR_CTRL: i32 = 55;
/// Get AArch64 tagged address control flags.
pub const PR_GET_TAGGED_ADDR_CTRL: i32 = 56;
/// Mark this process as an I/O flusher.
pub const PR_SET_IO_FLUSHER: i32 = 57;
/// Query I/O flusher status.
pub const PR_GET_IO_FLUSHER: i32 = 58;
/// Set syscall user dispatch mode.
pub const PR_SET_SYSCALL_USER_DISPATCH: i32 = 59;
/// Set memory-deny-write-execute policy.
pub const PR_SET_MDWE: i32 = 65;
/// Get memory-deny-write-execute policy.
pub const PR_GET_MDWE: i32 = 66;
/// Annotate a VMA with a name.
pub const PR_SET_VMA: i32 = 0x5356_4d41_u32 as i32;
/// RISC-V icache flush context control.
pub const PR_RISCV_SET_ICACHE_FLUSH_CTX: i32 = 71;

// ---------------------------------------------------------------------------
// Speculation control — PR_SPEC_*
// ---------------------------------------------------------------------------

/// Speculation feature: indirect branch speculation (Spectre v2).
pub const PR_SPEC_INDIRECT_BRANCH: u64 = 1 << 1;
/// Speculation feature: store bypass (Spectre v4 / SSB).
pub const PR_SPEC_STORE_BYPASS: u64 = 1 << 0;
/// Speculation feature: L1D flush on context switch.
pub const PR_SPEC_L1D_FLUSH: u64 = 1 << 2;

/// Speculation control value: feature enabled (vulnerable).
pub const PR_SPEC_ENABLE: u64 = 1 << 1;
/// Speculation control value: feature disabled (mitigated).
pub const PR_SPEC_DISABLE: u64 = 1 << 2;
/// Speculation control value: force-disable (irrevocable).
pub const PR_SPEC_FORCE_DISABLE: u64 = 1 << 3;
/// Speculation control value: disable only in priv exec (not user).
pub const PR_SPEC_DISABLE_NOEXEC: u64 = 1 << 4;

/// Per-feature speculation mitigation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpecState {
    /// Speculation allowed (vulnerable; default).
    #[default]
    Enabled,
    /// Speculation disabled for this thread.
    Disabled,
    /// Speculation disabled irrevocably.
    ForceDisabled,
}

// ---------------------------------------------------------------------------
// SVE (Scalable Vector Extension) vector length
// ---------------------------------------------------------------------------

/// Minimum SVE vector length in bytes (128 bits).
pub const SVE_VL_MIN: u16 = 16;
/// Maximum SVE vector length in bytes (2048 bits).
pub const SVE_VL_MAX: u16 = 256;

/// Flag: inherit SVE vector length across execve.
pub const PR_SVE_VL_INHERIT: u32 = 1 << 17;
/// Flag: set SVE vector length only for the next execve.
pub const PR_SVE_VL_ONEXEC: u32 = 1 << 18;

/// Validate that `vl` is a power-of-two multiple of 16 within SVE bounds.
pub fn sve_vl_valid(vl: u16) -> bool {
    vl >= SVE_VL_MIN && vl <= SVE_VL_MAX && vl % 16 == 0
}

// ---------------------------------------------------------------------------
// Tagged address control flags (AArch64)
// ---------------------------------------------------------------------------

/// Enable tagged address ABI (TBI — Top Byte Ignore).
pub const PR_TAGGED_ADDR_ENABLE: u64 = 1 << 0;
/// Enable Memory Tagging Extension (MTE) async mode.
pub const PR_MTE_TCF_ASYNC: u64 = 1 << 1;
/// Enable MTE synchronous mode.
pub const PR_MTE_TCF_SYNC: u64 = 1 << 2;
/// Tag include mask (bits 3–6 encode excluded tag 0–3).
pub const PR_MTE_TAG_MASK: u64 = 0xF << 3;
/// All known tagged address control flag bits.
const TAGGED_ADDR_CTRL_KNOWN: u64 =
    PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_ASYNC | PR_MTE_TCF_SYNC | PR_MTE_TAG_MASK;

// ---------------------------------------------------------------------------
// Syscall user dispatch (SUD)
// ---------------------------------------------------------------------------

/// Enable syscall user dispatch mode.
pub const PR_SYS_DISPATCH_ON: i32 = 1;
/// Disable syscall user dispatch mode.
pub const PR_SYS_DISPATCH_OFF: i32 = 0;

/// Selector value: forward syscall to the kernel.
pub const SYSCALL_DISPATCH_FILTER_ALLOW: u8 = 0;
/// Selector value: dispatch to user handler (raise SIGSYS).
pub const SYSCALL_DISPATCH_FILTER_BLOCK: u8 = 1;

/// Syscall user dispatch configuration.
#[derive(Debug, Clone, Copy)]
pub struct SudConfig {
    /// Dispatch is active.
    pub enabled: bool,
    /// Start of the "privileged" code range (syscalls from here bypass SUD).
    pub offset: u64,
    /// Length of the privileged range.
    pub len: u64,
    /// User-space address of the per-thread dispatch selector byte.
    pub selector_addr: u64,
}

impl SudConfig {
    /// Construct a disabled SUD configuration.
    pub const fn disabled() -> Self {
        Self {
            enabled: false,
            offset: 0,
            len: 0,
            selector_addr: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// MDWE — Memory Deny Write Execute
// ---------------------------------------------------------------------------

/// MDWE flag: refuse mprotect(PROT_EXEC) on writable mappings.
pub const PR_MDWE_REFUSE_EXEC_GAIN: u64 = 1 << 0;
/// MDWE flag: enable MDWE for child processes as well.
pub const PR_MDWE_NO_INHERIT: u64 = 1 << 1;
/// All known MDWE flag bits.
const MDWE_FLAGS_KNOWN: u64 = PR_MDWE_REFUSE_EXEC_GAIN | PR_MDWE_NO_INHERIT;

// ---------------------------------------------------------------------------
// PrctlExtState — per-process extended prctl state
// ---------------------------------------------------------------------------

/// Extended per-process prctl state for newer Linux options.
///
/// Stored alongside the core [`super::prctl::PrctlState`] but covers
/// operations that were added in more recent kernel versions.
#[derive(Debug, Clone)]
pub struct PrctlExtState {
    /// Speculation state for indirect branches.
    pub spec_indirect_branch: SpecState,
    /// Speculation state for store bypass.
    pub spec_store_bypass: SpecState,
    /// Speculation state for L1D flush.
    pub spec_l1d_flush: SpecState,
    /// Current SVE vector length (bytes).  0 = not set / hardware default.
    pub sve_vl: u16,
    /// SVE vector length flags (inherit / on-exec; high 16 bits of the packed vl word).
    pub sve_flags: u32,
    /// AArch64 tagged address control flags.
    pub tagged_addr_ctrl: u64,
    /// Whether this process is marked as an I/O flusher.
    pub io_flusher: bool,
    /// Syscall user dispatch configuration.
    pub sud: SudConfig,
    /// Memory-deny-write-execute flags.
    pub mdwe: u64,
}

impl PrctlExtState {
    /// Create a new state with safe defaults.
    pub const fn new() -> Self {
        Self {
            spec_indirect_branch: SpecState::Enabled,
            spec_store_bypass: SpecState::Enabled,
            spec_l1d_flush: SpecState::Enabled,
            sve_vl: 0,
            sve_flags: 0,
            tagged_addr_ctrl: 0,
            io_flusher: false,
            sud: SudConfig::disabled(),
            mdwe: 0,
        }
    }
}

impl Default for PrctlExtState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Speculation control handlers
// ---------------------------------------------------------------------------

/// Handler for `prctl(PR_GET_SPECULATION_CTRL, feature, ...)`.
///
/// Returns a bitmask describing the current speculation mitigation state for
/// the requested `feature`.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Unrecognised `feature` constant.
/// * [`Error::NotImplemented`]  — Feature exists but is not supported on this
///   platform.
pub fn do_get_speculation_ctrl(state: &PrctlExtState, feature: u64) -> Result<u64> {
    let spec_state = match feature {
        PR_SPEC_STORE_BYPASS => &state.spec_store_bypass,
        PR_SPEC_INDIRECT_BRANCH => &state.spec_indirect_branch,
        PR_SPEC_L1D_FLUSH => &state.spec_l1d_flush,
        _ => return Err(Error::InvalidArgument),
    };
    let bits = match spec_state {
        SpecState::Enabled => PR_SPEC_ENABLE,
        SpecState::Disabled => PR_SPEC_DISABLE,
        SpecState::ForceDisabled => PR_SPEC_FORCE_DISABLE | PR_SPEC_DISABLE,
    };
    Ok(bits)
}

/// Handler for `prctl(PR_SET_SPECULATION_CTRL, feature, value, ...)`.
///
/// Updates the speculation mitigation state for `feature`.
///
/// `FORCE_DISABLE` is irrevocable — once set, any attempt to re-enable is
/// rejected.
///
/// # Errors
///
/// * [`Error::InvalidArgument`]  — Unrecognised `feature` or `value`.
/// * [`Error::PermissionDenied`] — Attempt to re-enable after force-disable.
pub fn do_set_speculation_ctrl(state: &mut PrctlExtState, feature: u64, value: u64) -> Result<()> {
    let slot = match feature {
        PR_SPEC_STORE_BYPASS => &mut state.spec_store_bypass,
        PR_SPEC_INDIRECT_BRANCH => &mut state.spec_indirect_branch,
        PR_SPEC_L1D_FLUSH => &mut state.spec_l1d_flush,
        _ => return Err(Error::InvalidArgument),
    };

    // Once force-disabled, the state is irrevocable.
    if *slot == SpecState::ForceDisabled && value != PR_SPEC_FORCE_DISABLE {
        return Err(Error::PermissionDenied);
    }

    *slot = match value {
        PR_SPEC_ENABLE => SpecState::Enabled,
        PR_SPEC_DISABLE => SpecState::Disabled,
        PR_SPEC_FORCE_DISABLE => SpecState::ForceDisabled,
        _ => return Err(Error::InvalidArgument),
    };
    Ok(())
}

// ---------------------------------------------------------------------------
// SVE vector length handlers
// ---------------------------------------------------------------------------

/// Handler for `prctl(PR_SVE_GET_VL)`.
///
/// Returns the current SVE vector length packed with the inherit/on-exec flags.
///
/// If no SVE vector length has been set, returns a synthetic default of 16
/// (the minimum, 128 bits).
pub fn do_sve_get_vl(state: &PrctlExtState) -> u32 {
    let vl = if state.sve_vl == 0 {
        SVE_VL_MIN
    } else {
        state.sve_vl
    };
    (vl as u32) | (state.sve_flags << 16)
}

/// Handler for `prctl(PR_SVE_SET_VL, vl_and_flags)`.
///
/// Sets the SVE vector length for the calling thread.  The `vl_flags` argument
/// encodes both the desired vector length (low bits) and control flags (high).
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Vector length is out of range or not a
///   multiple of 16 bytes.
/// * [`Error::NotImplemented`]  — SVE not available on this platform.
pub fn do_sve_set_vl(state: &mut PrctlExtState, vl_flags: u32) -> Result<u32> {
    let vl = (vl_flags & 0xFFFF) as u16;
    let flags = (vl_flags >> 16) & 0xFFFF;

    if !sve_vl_valid(vl) {
        return Err(Error::InvalidArgument);
    }
    // Only known flag bits are accepted.
    let known_flags = PR_SVE_VL_INHERIT | PR_SVE_VL_ONEXEC;
    if flags & !known_flags != 0 {
        return Err(Error::InvalidArgument);
    }

    state.sve_vl = vl;
    state.sve_flags = flags;
    Ok(do_sve_get_vl(state))
}

// ---------------------------------------------------------------------------
// Tagged address control (AArch64)
// ---------------------------------------------------------------------------

/// Handler for `prctl(PR_GET_TAGGED_ADDR_CTRL)`.
///
/// Returns the current tagged address control flags for the calling process.
pub fn do_get_tagged_addr_ctrl(state: &PrctlExtState) -> Result<u64> {
    Ok(state.tagged_addr_ctrl)
}

/// Handler for `prctl(PR_SET_TAGGED_ADDR_CTRL, flags)`.
///
/// Sets the AArch64 tagged address control flags.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Unknown flag bits present in `flags`.
pub fn do_set_tagged_addr_ctrl(state: &mut PrctlExtState, flags: u64) -> Result<()> {
    if flags & !TAGGED_ADDR_CTRL_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }
    state.tagged_addr_ctrl = flags;
    Ok(())
}

// ---------------------------------------------------------------------------
// I/O flusher
// ---------------------------------------------------------------------------

/// Handler for `prctl(PR_SET_IO_FLUSHER, value)`.
///
/// Setting `value = 1` marks this process as an I/O flusher, which allows it
/// to allocate memory for writeback without recursing into reclaim.  Setting
/// `value = 0` clears the flag.
///
/// # Errors
///
/// * [`Error::PermissionDenied`] — Setting requires `CAP_SYS_RESOURCE`
///   (here: `caller_uid == 0`).
/// * [`Error::InvalidArgument`]  — `value` is not 0 or 1.
pub fn do_set_io_flusher(state: &mut PrctlExtState, value: u64, caller_uid: u32) -> Result<()> {
    if caller_uid != 0 {
        return Err(Error::PermissionDenied);
    }
    match value {
        0 => {
            state.io_flusher = false;
            Ok(())
        }
        1 => {
            state.io_flusher = true;
            Ok(())
        }
        _ => Err(Error::InvalidArgument),
    }
}

/// Handler for `prctl(PR_GET_IO_FLUSHER)`.
///
/// Returns `1` if the process is an I/O flusher, `0` otherwise.
///
/// # Errors
///
/// * [`Error::PermissionDenied`] — Query requires `CAP_SYS_RESOURCE`.
pub fn do_get_io_flusher(state: &PrctlExtState, caller_uid: u32) -> Result<u64> {
    if caller_uid != 0 {
        return Err(Error::PermissionDenied);
    }
    Ok(if state.io_flusher { 1 } else { 0 })
}

// ---------------------------------------------------------------------------
// Syscall user dispatch
// ---------------------------------------------------------------------------

/// Handler for `prctl(PR_SET_SYSCALL_USER_DISPATCH, mode, offset, len, selector)`.
///
/// Configures syscall user dispatch for the calling process.  When enabled,
/// syscalls made from addresses outside `[offset, offset+len)` are redirected
/// to the process with `SIGSYS` unless the per-thread selector byte is set to
/// `SYSCALL_DISPATCH_FILTER_ALLOW`.
///
/// # Arguments
///
/// * `mode`          — `PR_SYS_DISPATCH_ON` (1) or `PR_SYS_DISPATCH_OFF` (0).
/// * `offset`        — Start of the privileged (non-intercepted) code region.
/// * `len`           — Length of the privileged region.
/// * `selector_addr` — User-space address of the filter selector byte.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — `mode` is neither 0 nor 1, or `offset + len`
///   overflows.
pub fn do_set_syscall_user_dispatch(
    state: &mut PrctlExtState,
    mode: i32,
    offset: u64,
    len: u64,
    selector_addr: u64,
) -> Result<()> {
    match mode {
        PR_SYS_DISPATCH_OFF => {
            state.sud = SudConfig::disabled();
            Ok(())
        }
        PR_SYS_DISPATCH_ON => {
            // Validate range does not overflow.
            offset.checked_add(len).ok_or(Error::InvalidArgument)?;
            state.sud = SudConfig {
                enabled: true,
                offset,
                len,
                selector_addr,
            };
            Ok(())
        }
        _ => Err(Error::InvalidArgument),
    }
}

// ---------------------------------------------------------------------------
// MDWE — Memory Deny Write Execute
// ---------------------------------------------------------------------------

/// Handler for `prctl(PR_SET_MDWE, flags)`.
///
/// Enables memory-deny-write-execute policy.  Once enabled, `MDWE` is
/// irrevocable for the lifetime of the process.
///
/// # Errors
///
/// * [`Error::InvalidArgument`] — Unknown flag bits.
/// * [`Error::PermissionDenied`] — Attempt to clear flags (MDWE is one-way).
pub fn do_set_mdwe(state: &mut PrctlExtState, flags: u64) -> Result<()> {
    if flags & !MDWE_FLAGS_KNOWN != 0 {
        return Err(Error::InvalidArgument);
    }
    // One-way: cannot clear already-set flags.
    if state.mdwe & !flags != 0 {
        return Err(Error::PermissionDenied);
    }
    state.mdwe |= flags;
    Ok(())
}

/// Handler for `prctl(PR_GET_MDWE)`.
///
/// Returns the current MDWE flags.
pub fn do_get_mdwe(state: &PrctlExtState) -> u64 {
    state.mdwe
}

// ---------------------------------------------------------------------------
// Extended prctl table — per-process registry
// ---------------------------------------------------------------------------

/// Maximum number of processes in the extended prctl table.
pub const PRCTL_EXT_TABLE_SIZE: usize = 256;

/// A process entry in the extended prctl table.
pub struct PrctlExtEntry {
    /// PID of the owning process.
    pub pid: u32,
    /// UID of the owning process.
    pub uid: u32,
    /// Extended prctl state.
    pub state: PrctlExtState,
}

impl PrctlExtEntry {
    /// Create a new entry with default extended state.
    pub fn new(pid: u32, uid: u32) -> Self {
        Self {
            pid,
            uid,
            state: PrctlExtState::new(),
        }
    }
}

/// Global registry of per-process extended prctl state.
pub struct PrctlExtTable {
    entries: [Option<PrctlExtEntry>; PRCTL_EXT_TABLE_SIZE],
    count: usize,
}

impl PrctlExtTable {
    /// Create an empty table.
    pub const fn new() -> Self {
        Self {
            entries: [const { None }; PRCTL_EXT_TABLE_SIZE],
            count: 0,
        }
    }

    /// Register a process.
    ///
    /// # Errors
    ///
    /// [`Error::OutOfMemory`] if the table is full.
    pub fn register(&mut self, entry: PrctlExtEntry) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                self.count += 1;
                return Ok(());
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Remove a process entry on exit.
    pub fn unregister(&mut self, pid: u32) {
        for slot in self.entries.iter_mut() {
            if slot.as_ref().map(|e| e.pid == pid).unwrap_or(false) {
                *slot = None;
                self.count -= 1;
                return;
            }
        }
    }

    /// Get a mutable reference to the state for `pid`.
    pub fn get_mut(&mut self, pid: u32) -> Option<&mut PrctlExtEntry> {
        self.entries
            .iter_mut()
            .find_map(|s| s.as_mut().filter(|e| e.pid == pid))
    }

    /// Get an immutable reference to the state for `pid`.
    pub fn get(&self, pid: u32) -> Option<&PrctlExtEntry> {
        self.entries
            .iter()
            .find_map(|s| s.as_ref().filter(|e| e.pid == pid))
    }

    /// Return the number of registered processes.
    pub const fn count(&self) -> usize {
        self.count
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Speculation control ---

    #[test]
    fn spec_get_default_enabled() {
        let state = PrctlExtState::new();
        let bits = do_get_speculation_ctrl(&state, PR_SPEC_STORE_BYPASS).unwrap();
        assert_eq!(bits, PR_SPEC_ENABLE);
    }

    #[test]
    fn spec_set_disable() {
        let mut state = PrctlExtState::new();
        do_set_speculation_ctrl(&mut state, PR_SPEC_STORE_BYPASS, PR_SPEC_DISABLE).unwrap();
        let bits = do_get_speculation_ctrl(&state, PR_SPEC_STORE_BYPASS).unwrap();
        assert_eq!(bits, PR_SPEC_DISABLE);
    }

    #[test]
    fn spec_force_disable_irrevocable() {
        let mut state = PrctlExtState::new();
        do_set_speculation_ctrl(&mut state, PR_SPEC_STORE_BYPASS, PR_SPEC_FORCE_DISABLE).unwrap();
        assert_eq!(
            do_set_speculation_ctrl(&mut state, PR_SPEC_STORE_BYPASS, PR_SPEC_ENABLE),
            Err(Error::PermissionDenied)
        );
    }

    #[test]
    fn spec_invalid_feature() {
        let state = PrctlExtState::new();
        assert_eq!(
            do_get_speculation_ctrl(&state, 0xFF),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn spec_invalid_value() {
        let mut state = PrctlExtState::new();
        assert_eq!(
            do_set_speculation_ctrl(&mut state, PR_SPEC_STORE_BYPASS, 0xFF),
            Err(Error::InvalidArgument)
        );
    }

    // --- SVE vector length ---

    #[test]
    fn sve_get_default_returns_min() {
        let state = PrctlExtState::new();
        let vl_raw = do_sve_get_vl(&state);
        assert_eq!(vl_raw & 0xFFFF, SVE_VL_MIN as u32);
    }

    #[test]
    fn sve_set_valid_vl() {
        let mut state = PrctlExtState::new();
        do_sve_set_vl(&mut state, 32).unwrap(); // 32 bytes = 256 bits
        assert_eq!(state.sve_vl, 32);
    }

    #[test]
    fn sve_set_invalid_vl_rejected() {
        let mut state = PrctlExtState::new();
        assert_eq!(do_sve_set_vl(&mut state, 15), Err(Error::InvalidArgument)); // not multiple of 16
        assert_eq!(do_sve_set_vl(&mut state, 512), Err(Error::InvalidArgument)); // > max
    }

    #[test]
    fn sve_vl_roundtrip() {
        let mut state = PrctlExtState::new();
        let raw = do_sve_set_vl(&mut state, 64).unwrap();
        assert_eq!(raw & 0xFFFF, 64);
    }

    // --- Tagged address control ---

    #[test]
    fn tagged_addr_get_default_zero() {
        let state = PrctlExtState::new();
        assert_eq!(do_get_tagged_addr_ctrl(&state).unwrap(), 0);
    }

    #[test]
    fn tagged_addr_set_enable() {
        let mut state = PrctlExtState::new();
        do_set_tagged_addr_ctrl(&mut state, PR_TAGGED_ADDR_ENABLE).unwrap();
        assert_eq!(
            do_get_tagged_addr_ctrl(&state).unwrap(),
            PR_TAGGED_ADDR_ENABLE
        );
    }

    #[test]
    fn tagged_addr_unknown_flags_rejected() {
        let mut state = PrctlExtState::new();
        assert_eq!(
            do_set_tagged_addr_ctrl(&mut state, 0xDEAD_0000),
            Err(Error::InvalidArgument)
        );
    }

    // --- I/O flusher ---

    #[test]
    fn io_flusher_requires_root() {
        let mut state = PrctlExtState::new();
        assert_eq!(
            do_set_io_flusher(&mut state, 1, 500),
            Err(Error::PermissionDenied)
        );
        assert_eq!(do_get_io_flusher(&state, 500), Err(Error::PermissionDenied));
    }

    #[test]
    fn io_flusher_set_and_get() {
        let mut state = PrctlExtState::new();
        do_set_io_flusher(&mut state, 1, 0).unwrap();
        assert_eq!(do_get_io_flusher(&state, 0).unwrap(), 1);
        do_set_io_flusher(&mut state, 0, 0).unwrap();
        assert_eq!(do_get_io_flusher(&state, 0).unwrap(), 0);
    }

    #[test]
    fn io_flusher_invalid_value() {
        let mut state = PrctlExtState::new();
        assert_eq!(
            do_set_io_flusher(&mut state, 2, 0),
            Err(Error::InvalidArgument)
        );
    }

    // --- Syscall user dispatch ---

    #[test]
    fn sud_enable() {
        let mut state = PrctlExtState::new();
        do_set_syscall_user_dispatch(&mut state, PR_SYS_DISPATCH_ON, 0x1000, 0x2000, 0x500)
            .unwrap();
        assert!(state.sud.enabled);
        assert_eq!(state.sud.offset, 0x1000);
        assert_eq!(state.sud.len, 0x2000);
    }

    #[test]
    fn sud_disable() {
        let mut state = PrctlExtState::new();
        do_set_syscall_user_dispatch(&mut state, PR_SYS_DISPATCH_ON, 0, 100, 0).unwrap();
        do_set_syscall_user_dispatch(&mut state, PR_SYS_DISPATCH_OFF, 0, 0, 0).unwrap();
        assert!(!state.sud.enabled);
    }

    #[test]
    fn sud_overflow_rejected() {
        let mut state = PrctlExtState::new();
        assert_eq!(
            do_set_syscall_user_dispatch(&mut state, PR_SYS_DISPATCH_ON, u64::MAX, 1, 0),
            Err(Error::InvalidArgument)
        );
    }

    #[test]
    fn sud_invalid_mode() {
        let mut state = PrctlExtState::new();
        assert_eq!(
            do_set_syscall_user_dispatch(&mut state, 99, 0, 0, 0),
            Err(Error::InvalidArgument)
        );
    }

    // --- MDWE ---

    #[test]
    fn mdwe_set_and_get() {
        let mut state = PrctlExtState::new();
        do_set_mdwe(&mut state, PR_MDWE_REFUSE_EXEC_GAIN).unwrap();
        assert_eq!(do_get_mdwe(&state), PR_MDWE_REFUSE_EXEC_GAIN);
    }

    #[test]
    fn mdwe_one_way_cannot_clear() {
        let mut state = PrctlExtState::new();
        do_set_mdwe(&mut state, PR_MDWE_REFUSE_EXEC_GAIN).unwrap();
        // Try to clear by setting flags that don't include the already-set bit
        assert_eq!(do_set_mdwe(&mut state, 0), Err(Error::PermissionDenied));
    }

    #[test]
    fn mdwe_unknown_flags_rejected() {
        let mut state = PrctlExtState::new();
        assert_eq!(do_set_mdwe(&mut state, 0xFF00), Err(Error::InvalidArgument));
    }

    // --- PrctlExtTable ---

    #[test]
    fn ext_table_register_and_lookup() {
        let mut t = PrctlExtTable::new();
        t.register(PrctlExtEntry::new(100, 500)).unwrap();
        assert!(t.get(100).is_some());
        assert_eq!(t.count(), 1);
    }

    #[test]
    fn ext_table_unregister() {
        let mut t = PrctlExtTable::new();
        t.register(PrctlExtEntry::new(100, 500)).unwrap();
        t.unregister(100);
        assert!(t.get(100).is_none());
        assert_eq!(t.count(), 0);
    }

    #[test]
    fn ext_table_modify_state() {
        let mut t = PrctlExtTable::new();
        t.register(PrctlExtEntry::new(100, 0)).unwrap();
        {
            let entry = t.get_mut(100).unwrap();
            do_set_mdwe(&mut entry.state, PR_MDWE_REFUSE_EXEC_GAIN).unwrap();
        }
        let entry = t.get(100).unwrap();
        assert_eq!(do_get_mdwe(&entry.state), PR_MDWE_REFUSE_EXEC_GAIN);
    }
}
