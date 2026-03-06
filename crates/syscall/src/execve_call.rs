// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `execve` syscall handler.
//!
//! Implements `execve(2)` per POSIX.1-2024.
//! `execve` replaces the current process image with a new program.
//! It opens the file, validates the ELF magic bytes, maps the program
//! segments into memory, builds the initial stack (argv/envp/auxv),
//! and transfers control to the entry point.
//!
//! # References
//!
//! - POSIX.1-2024: `exec()`
//! - Linux man pages: `execve(2)`
//! - System V ABI: initial process stack layout

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// ELF magic number (first 4 bytes of any ELF file).
pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/// ELF class: 64-bit.
pub const ELFCLASS64: u8 = 2;

/// ELF data: little-endian.
pub const ELFDATA2LSB: u8 = 1;

/// ELF type: executable.
pub const ET_EXEC: u16 = 2;

/// ELF type: shared object (position-independent executable).
pub const ET_DYN: u16 = 3;

/// ELF machine: x86-64.
pub const EM_X86_64: u16 = 62;

/// Maximum combined length of all argv strings (2 MiB + 4096).
const MAX_ARG_STRLEN: usize = 2 * 1024 * 1024 + 4096;

/// Maximum number of arguments (argv + envp combined).
const MAX_ARG_STRINGS: usize = 0x7FFF_FFFF;

/// Minimum ELF header size (64 bytes for ELF64).
const ELF64_EHDR_SIZE: usize = 64;

// ---------------------------------------------------------------------------
// ElfIdent — first 16 bytes of an ELF header
// ---------------------------------------------------------------------------

/// The ELF identification array (first 16 bytes of the ELF header).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfIdent {
    /// Magic number `[0x7F, 'E', 'L', 'F']`.
    pub magic: [u8; 4],
    /// ELF class (32-bit or 64-bit).
    pub class: u8,
    /// Data encoding (little-endian or big-endian).
    pub data: u8,
    /// ELF version (must be 1).
    pub version: u8,
    /// OS/ABI identification.
    pub os_abi: u8,
    /// ABI version.
    pub abi_version: u8,
    /// Padding bytes.
    pub pad: [u8; 7],
}

impl ElfIdent {
    /// Validate the ELF identification bytes.
    pub fn validate(&self) -> Result<()> {
        if self.magic != ELF_MAGIC {
            return Err(Error::InvalidArgument);
        }
        if self.class != ELFCLASS64 {
            return Err(Error::InvalidArgument);
        }
        if self.data != ELFDATA2LSB {
            return Err(Error::InvalidArgument);
        }
        if self.version != 1 {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ExecveArgs — bundled arguments
// ---------------------------------------------------------------------------

/// Arguments for the `execve` syscall.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExecveArgs {
    /// User-space pointer to the null-terminated pathname.
    pub filename_ptr: u64,
    /// User-space pointer to the argv array (null-terminated array of pointers).
    pub argv_ptr: u64,
    /// User-space pointer to the envp array (null-terminated array of pointers).
    pub envp_ptr: u64,
}

impl ExecveArgs {
    /// Validate the `execve` argument pointers.
    ///
    /// Returns `Err(InvalidArgument)` if any pointer is null.
    pub fn validate(&self) -> Result<()> {
        if self.filename_ptr == 0 {
            return Err(Error::InvalidArgument);
        }
        // argv and envp may be null (treated as empty arrays).
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// LoadedElf — outcome of ELF parsing
// ---------------------------------------------------------------------------

/// Information extracted from a successfully parsed ELF binary.
#[derive(Debug, Clone, Copy, Default)]
pub struct LoadedElf {
    /// Virtual address of the program entry point.
    pub entry: u64,
    /// Load bias (difference between virtual and file addresses).
    pub load_bias: u64,
    /// Address of the program header table in memory.
    pub phdr_addr: u64,
    /// Number of program headers.
    pub phdr_count: u16,
    /// Address of the interpreter (dynamic linker), if any.
    pub interp_base: Option<u64>,
}

// ---------------------------------------------------------------------------
// InitStack — initial process stack layout
// ---------------------------------------------------------------------------

/// Describes the initial stack layout for a newly executed program.
///
/// The stack is built from high to low memory:
/// `[argc | argv ptrs | NULL | envp ptrs | NULL | auxv pairs | 0,0 | strings]`
#[derive(Debug, Clone, Copy, Default)]
pub struct InitStack {
    /// Stack pointer to hand to the entry point.
    pub sp: u64,
    /// Number of argument strings.
    pub argc: u64,
    /// Total bytes consumed by the stack.
    pub stack_bytes: usize,
}

// ---------------------------------------------------------------------------
// ExecContext — encapsulates execution setup
// ---------------------------------------------------------------------------

/// Context accumulated during `execve` processing.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExecContext {
    /// Loaded ELF information.
    pub elf: LoadedElf,
    /// Initial stack layout.
    pub stack: InitStack,
    /// Number of argv strings.
    pub argc: usize,
    /// Number of envp strings.
    pub envc: usize,
}

// ---------------------------------------------------------------------------
// ELF validation helpers
// ---------------------------------------------------------------------------

/// Validate the first bytes of a file as a 64-bit ELF executable.
pub fn validate_elf_header(bytes: &[u8]) -> Result<()> {
    if bytes.len() < ELF64_EHDR_SIZE {
        return Err(Error::InvalidArgument);
    }
    // Check magic.
    if &bytes[0..4] != ELF_MAGIC {
        return Err(Error::InvalidArgument);
    }
    // Check class (64-bit).
    if bytes[4] != ELFCLASS64 {
        return Err(Error::InvalidArgument);
    }
    // Check encoding (little-endian).
    if bytes[5] != ELFDATA2LSB {
        return Err(Error::InvalidArgument);
    }
    // Check version.
    if bytes[6] != 1 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Extract the ELF type from a validated header byte slice.
pub fn elf_type(bytes: &[u8]) -> u16 {
    // e_type is at offset 16 in the ELF64 header (2-byte little-endian field).
    u16::from_le_bytes([bytes[16], bytes[17]])
}

/// Return `true` if the ELF type is ET_EXEC or ET_DYN.
pub fn is_executable_type(bytes: &[u8]) -> bool {
    let t = elf_type(bytes);
    t == ET_EXEC || t == ET_DYN
}

// ---------------------------------------------------------------------------
// Argument list helpers
// ---------------------------------------------------------------------------

/// Count the number of strings in a null-terminated user-space string array.
///
/// `ptrs` is a slice of user-space pointers; a null pointer marks the end.
/// Returns `Err(InvalidArgument)` if more than `MAX_ARG_STRINGS` entries exist.
pub fn count_strings(ptrs: &[u64]) -> Result<usize> {
    let mut count = 0usize;
    for &ptr in ptrs {
        if ptr == 0 {
            break;
        }
        count = count.checked_add(1).ok_or(Error::InvalidArgument)?;
        if count > MAX_ARG_STRINGS {
            return Err(Error::InvalidArgument);
        }
    }
    Ok(count)
}

/// Validate total argument/environment length against `MAX_ARG_STRLEN`.
pub fn validate_arg_length(total_bytes: usize) -> Result<()> {
    if total_bytes > MAX_ARG_STRLEN {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Public syscall handler
// ---------------------------------------------------------------------------

/// `execve` — execute a program.
///
/// Replaces the current process image with the program at `filename`.
/// `argv` and `envp` are passed to the new program as its argument and
/// environment vectors.
///
/// Processing steps:
/// 1. Validate argument pointers.
/// 2. Open and read the file header.
/// 3. Check ELF magic and type.
/// 4. Load PT_LOAD segments into memory (stub).
/// 5. Build the initial stack with argc/argv/envp/auxv.
/// 6. Set the instruction pointer to the entry point (stub).
///
/// On success, this call does not return to the caller — the new program
/// begins executing. The stub returns an `ExecContext` for testing.
///
/// # Errors
///
/// | `Error`             | Condition                                   |
/// |---------------------|---------------------------------------------|
/// | `InvalidArgument`   | Null filename pointer or arg count overflow |
/// | `NotFound`          | File does not exist                         |
/// | `InvalidArgument`  | Not a valid ELF64 executable                |
/// | `PermissionDenied`  | File is not executable                      |
///
/// Reference: POSIX.1-2024 §exec.
pub fn do_execve(args: &ExecveArgs, header_bytes: Option<&[u8]>) -> Result<ExecContext> {
    args.validate()?;

    if let Some(bytes) = header_bytes {
        validate_elf_header(bytes)?;
        if !is_executable_type(bytes) {
            return Err(Error::InvalidArgument);
        }
    }

    // Stub: real implementation loads ELF segments, sets up the mm_struct,
    // builds the initial stack, and schedules the new image for execution.
    let ctx = ExecContext {
        elf: LoadedElf {
            entry: 0x0040_0000,
            load_bias: 0,
            phdr_addr: 0x0040_0040,
            phdr_count: 1,
            interp_base: None,
        },
        stack: InitStack {
            sp: 0x0000_7FFF_FFFF_F000,
            argc: 0,
            stack_bytes: 4096,
        },
        argc: 0,
        envc: 0,
    };

    Ok(ctx)
}

/// Validate `execve` arguments without executing.
pub fn validate_execve_args(args: &ExecveArgs) -> Result<()> {
    args.validate()
}
