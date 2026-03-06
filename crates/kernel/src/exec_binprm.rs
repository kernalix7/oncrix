// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Binary program execution (linux_binprm equivalent).
//!
//! Implements the exec flow: allocate binprm, detect format
//! (ELF / script), check setuid/setgid security, flush old
//! address space, and complete or fail the exec.
//!
//! Reference: Linux `fs/exec.c`, `include/linux/binfmts.h`.

use oncrix_lib::{Error, Result};

// ── Constants ────────────────────────────────────────────────────

/// Maximum concurrent exec operations.
const MAX_BINPRMS: usize = 64;

/// Maximum filename length (bytes).
const MAX_FILENAME_LEN: usize = 256;

/// ELF magic: 0x7f 'E' 'L' 'F'.
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// Script shebang: '#' '!'.
const SCRIPT_MAGIC: [u8; 2] = [b'#', b'!'];

/// Maximum argument + environment byte size.
const MAX_ARG_BYTES: u64 = 2 * 1024 * 1024;

/// Maximum number of arguments.
const MAX_ARGC: u32 = 4096;

/// Maximum number of environment variables.
const MAX_ENVC: u32 = 4096;

/// Size of the binary header read for format detection.
const BINPRM_HEADER_SIZE: usize = 256;

/// Detected binary format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryFormat {
    /// 64-bit ELF executable.
    Elf64,
    /// Interpreted script (shebang #!).
    Script,
    /// Format could not be determined.
    Unknown,
}

/// Lifecycle state for a binprm slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BinprmState {
    /// Slot is free.
    Free,
    /// Allocated, fields being populated.
    Init,
    /// Security and validity checks passed.
    Checked,
    /// Binary loaded into new address space.
    Loaded,
    /// Exec failed, awaiting cleanup.
    Failed,
}

/// Binary program descriptor for exec.
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct LinuxBinprm {
    /// Path to the executable.
    pub filename: [u8; MAX_FILENAME_LEN],
    /// Length of the filename (excluding padding).
    pub filename_len: u32,
    /// Number of argv entries.
    pub argc: u32,
    /// Number of envp entries.
    pub envc: u32,
    /// Total bytes of argument + environment strings.
    pub total_arg_size: u64,
    /// Detected binary format.
    pub format: BinaryFormat,
    /// First bytes of the binary (for magic detection).
    pub header: [u8; BINPRM_HEADER_SIZE],
    /// Bytes valid in `header`.
    pub header_len: u32,
    /// Effective UID after exec (may differ due to setuid).
    pub cred_uid: u32,
    /// Effective GID after exec (may differ due to setgid).
    pub cred_gid: u32,
    /// Original file owner UID.
    pub file_uid: u32,
    /// Original file owner GID.
    pub file_gid: u32,
    /// File permission mode bits.
    pub file_mode: u32,
    /// Whether AT_SECURE should be set in the auxiliary vector.
    pub secureexec: bool,
    /// Task ID that initiated this exec.
    pub task_id: u64,
}

/// A slot in the binprm table.
#[derive(Debug, Clone, Copy)]
struct BinprmSlot {
    /// The binprm data.
    binprm: LinuxBinprm,
    /// Lifecycle state.
    state: BinprmState,
    /// Generation counter.
    generation: u64,
}

/// Statistics for exec operations.
#[derive(Debug, Clone, Copy)]
pub struct BinprmStats {
    /// Total exec operations attempted.
    pub total_execs: u64,
    /// Successful exec completions.
    pub total_success: u64,
    /// Failed exec operations.
    pub total_failures: u64,
    /// Currently active binprm slots.
    pub active_count: u32,
}

/// Manages active exec operations.
pub struct BinprmTable {
    /// Binprm slot pool.
    slots: [BinprmSlot; MAX_BINPRMS],
    /// Next generation counter.
    next_generation: u64,
    /// Statistics.
    stats: BinprmStats,
}

impl BinprmTable {
    /// Create a new binprm table.
    pub const fn new() -> Self {
        let binprm = LinuxBinprm {
            filename: [0u8; MAX_FILENAME_LEN],
            filename_len: 0,
            argc: 0,
            envc: 0,
            total_arg_size: 0,
            format: BinaryFormat::Unknown,
            header: [0u8; BINPRM_HEADER_SIZE],
            header_len: 0,
            cred_uid: 0,
            cred_gid: 0,
            file_uid: 0,
            file_gid: 0,
            file_mode: 0,
            secureexec: false,
            task_id: 0,
        };
        let slot = BinprmSlot {
            binprm,
            state: BinprmState::Free,
            generation: 0,
        };
        Self {
            slots: [slot; MAX_BINPRMS],
            next_generation: 1,
            stats: BinprmStats {
                total_execs: 0,
                total_success: 0,
                total_failures: 0,
                active_count: 0,
            },
        }
    }

    /// Allocate a binprm slot for a new exec operation.
    pub fn alloc_binprm(&mut self, task_id: u64, filename: &[u8]) -> Result<u64> {
        if filename.is_empty() || filename.len() > MAX_FILENAME_LEN {
            return Err(Error::InvalidArgument);
        }
        let pos = self
            .slots
            .iter()
            .position(|s| s.state == BinprmState::Free)
            .ok_or(Error::OutOfMemory)?;
        let cur_gen = self.next_generation;
        self.next_generation += 1;
        let slot = &mut self.slots[pos];
        slot.binprm.filename[..filename.len()].copy_from_slice(filename);
        slot.binprm.filename_len = filename.len() as u32;
        slot.binprm.task_id = task_id;
        slot.binprm.argc = 0;
        slot.binprm.envc = 0;
        slot.binprm.total_arg_size = 0;
        slot.binprm.format = BinaryFormat::Unknown;
        slot.binprm.header_len = 0;
        slot.binprm.secureexec = false;
        slot.state = BinprmState::Init;
        slot.generation = cur_gen;
        self.stats.total_execs += 1;
        self.stats.active_count += 1;
        Ok(pos as u64)
    }

    /// Record argument and environment counts.
    pub fn set_args(&mut self, id: u64, argc: u32, envc: u32, total_arg_size: u64) -> Result<()> {
        let slot = self.get_slot_mut(id, BinprmState::Init)?;
        if argc > MAX_ARGC || envc > MAX_ENVC {
            return Err(Error::InvalidArgument);
        }
        if total_arg_size > MAX_ARG_BYTES {
            return Err(Error::InvalidArgument);
        }
        slot.binprm.argc = argc;
        slot.binprm.envc = envc;
        slot.binprm.total_arg_size = total_arg_size;
        Ok(())
    }

    /// Detect binary format from the first bytes of the file.
    pub fn detect_format(&mut self, id: u64, header: &[u8]) -> Result<BinaryFormat> {
        let slot = self.get_slot_mut(id, BinprmState::Init)?;
        let copy_len = header.len().min(BINPRM_HEADER_SIZE);
        slot.binprm.header[..copy_len].copy_from_slice(&header[..copy_len]);
        slot.binprm.header_len = copy_len as u32;
        let fmt = if copy_len >= 4 && slot.binprm.header[..4] == ELF_MAGIC {
            BinaryFormat::Elf64
        } else if copy_len >= 2 && slot.binprm.header[..2] == SCRIPT_MAGIC {
            BinaryFormat::Script
        } else {
            BinaryFormat::Unknown
        };
        slot.binprm.format = fmt;
        Ok(fmt)
    }

    /// Evaluate setuid/setgid security implications.
    ///
    /// Sets `secureexec` (AT_SECURE) when effective IDs change
    /// due to setuid/setgid bits on the binary.
    pub fn check_security(
        &mut self,
        id: u64,
        caller_uid: u32,
        caller_gid: u32,
        file_uid: u32,
        file_gid: u32,
        file_mode: u32,
    ) -> Result<()> {
        let slot = self.get_slot_mut(id, BinprmState::Init)?;
        slot.binprm.file_uid = file_uid;
        slot.binprm.file_gid = file_gid;
        slot.binprm.file_mode = file_mode;
        slot.binprm.cred_uid = caller_uid;
        slot.binprm.cred_gid = caller_gid;
        // setuid bit (04000).
        if file_mode & 0o4000 != 0 {
            slot.binprm.cred_uid = file_uid;
            slot.binprm.secureexec = true;
        }
        // setgid bit (02000).
        if file_mode & 0o2000 != 0 {
            slot.binprm.cred_gid = file_gid;
            slot.binprm.secureexec = true;
        }
        // AT_SECURE also when ruid != euid or rgid != egid.
        if caller_uid != slot.binprm.cred_uid || caller_gid != slot.binprm.cred_gid {
            slot.binprm.secureexec = true;
        }
        Ok(())
    }

    /// Validate all binprm fields and move to Checked state.
    pub fn prepare_binprm(&mut self, id: u64) -> Result<()> {
        let slot = self.get_slot_mut(id, BinprmState::Init)?;
        if slot.binprm.format == BinaryFormat::Unknown {
            return Err(Error::InvalidArgument);
        }
        if slot.binprm.filename_len == 0 {
            return Err(Error::InvalidArgument);
        }
        slot.state = BinprmState::Checked;
        Ok(())
    }

    /// Mark the old address space for teardown.
    ///
    /// In a real kernel this would unmap all VMAs, reset signal
    /// handlers, close O_CLOEXEC descriptors, etc.
    pub fn flush_old_exec(&mut self, id: u64) -> Result<()> {
        let slot = self.get_slot_mut(id, BinprmState::Checked)?;
        slot.state = BinprmState::Loaded;
        Ok(())
    }

    /// Complete a successful exec and free the binprm slot.
    pub fn complete_exec(&mut self, id: u64) -> Result<LinuxBinprm> {
        let slot = self.get_slot_mut(id, BinprmState::Loaded)?;
        let result = slot.binprm;
        slot.state = BinprmState::Free;
        self.stats.total_success += 1;
        self.stats.active_count = self.stats.active_count.saturating_sub(1);
        Ok(result)
    }

    /// Mark an exec as failed and free the binprm slot.
    pub fn fail_exec(&mut self, id: u64) -> Result<()> {
        let idx = id as usize;
        if idx >= MAX_BINPRMS {
            return Err(Error::InvalidArgument);
        }
        if self.slots[idx].state == BinprmState::Free {
            return Err(Error::NotFound);
        }
        self.slots[idx].state = BinprmState::Free;
        self.stats.total_failures += 1;
        self.stats.active_count = self.stats.active_count.saturating_sub(1);
        Ok(())
    }

    /// Get a read-only view of a binprm.
    pub fn get_binprm(&self, id: u64) -> Result<&LinuxBinprm> {
        let idx = id as usize;
        if idx >= MAX_BINPRMS {
            return Err(Error::InvalidArgument);
        }
        if self.slots[idx].state == BinprmState::Free {
            return Err(Error::NotFound);
        }
        Ok(&self.slots[idx].binprm)
    }

    /// Return statistics.
    pub fn stats(&self) -> &BinprmStats {
        &self.stats
    }

    // ── Internal helpers ────────────────────────────────────────

    /// Get a mutable slot reference, checking state.
    fn get_slot_mut(&mut self, id: u64, expected_state: BinprmState) -> Result<&mut BinprmSlot> {
        let idx = id as usize;
        if idx >= MAX_BINPRMS {
            return Err(Error::InvalidArgument);
        }
        if self.slots[idx].state != expected_state {
            return Err(Error::InvalidArgument);
        }
        Ok(&mut self.slots[idx])
    }
}
