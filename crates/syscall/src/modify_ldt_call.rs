// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! `modify_ldt(2)` syscall handler — read or write the LDT (x86-64).
//!
//! `modify_ldt` reads or modifies the Local Descriptor Table (LDT) of a
//! process.  It is an x86 / x86-64 specific system call.
//!
//! # Syscall signature
//!
//! ```text
//! int modify_ldt(int func, void *ptr, unsigned long bytecount);
//! ```
//!
//! # `func` values
//!
//! | Value | Description |
//! |-------|-------------|
//! | 0     | Read LDT entries into `ptr` |
//! | 1     | Write an LDT entry from `ptr` |
//! | 2     | Read default LDT |
//! | 0x11  | Write an LDT entry (new format) |
//!
//! # References
//!
//! - Linux: `arch/x86/kernel/ldt.c`
//! - `modify_ldt(2)` man page

use oncrix_lib::{Error, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Read the current LDT.
pub const LDT_READ: i32 = 0;
/// Write an LDT entry (old format).
pub const LDT_WRITE: i32 = 1;
/// Read the default LDT.
pub const LDT_READ_DEFAULT: i32 = 2;
/// Write an LDT entry (new format — validates base/limit).
pub const LDT_WRITE_NEW: i32 = 0x11;

/// Size of a single LDT entry descriptor in bytes.
pub const LDT_ENTRY_SIZE: usize = 8;

/// Maximum number of LDT entries per process.
pub const LDT_ENTRIES: usize = 8192;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// A single LDT descriptor (8 bytes, x86 segment format).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[repr(C)]
pub struct LdtEntry {
    /// Low 32 bits of the descriptor.
    pub low: u32,
    /// High 32 bits of the descriptor.
    pub high: u32,
}

impl LdtEntry {
    /// Create a new entry.
    pub const fn new(low: u32, high: u32) -> Self {
        Self { low, high }
    }

    /// Return whether this is a null (unused) descriptor.
    pub fn is_null(&self) -> bool {
        self.low == 0 && self.high == 0
    }
}

/// Parameters for a `modify_ldt` request.
#[derive(Debug, Clone, Copy)]
pub struct ModifyLdtRequest {
    /// Operation selector.
    pub func: i32,
    /// User-space pointer to descriptor buffer.
    pub ptr: u64,
    /// Byte count of the buffer.
    pub bytecount: u64,
}

impl ModifyLdtRequest {
    /// Create a new request.
    pub const fn new(func: i32, ptr: u64, bytecount: u64) -> Self {
        Self {
            func,
            ptr,
            bytecount,
        }
    }

    /// Validate the request.
    pub fn validate(&self) -> Result<()> {
        match self.func {
            LDT_READ | LDT_READ_DEFAULT => {
                if self.ptr == 0 {
                    return Err(Error::InvalidArgument);
                }
            }
            LDT_WRITE | LDT_WRITE_NEW => {
                if self.ptr == 0 {
                    return Err(Error::InvalidArgument);
                }
                if (self.bytecount as usize) < LDT_ENTRY_SIZE {
                    return Err(Error::InvalidArgument);
                }
            }
            _ => return Err(Error::InvalidArgument),
        }
        Ok(())
    }
}

impl Default for ModifyLdtRequest {
    fn default() -> Self {
        Self::new(LDT_READ, 0, 0)
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// Handle the `modify_ldt(2)` syscall.
///
/// # Errors
///
/// - [`Error::InvalidArgument`] — unknown `func`, null pointer, or short buffer.
/// - [`Error::NotImplemented`] — x86 LDT subsystem not yet wired.
pub fn sys_modify_ldt(func: i32, ptr: u64, bytecount: u64) -> Result<i64> {
    let req = ModifyLdtRequest::new(func, ptr, bytecount);
    req.validate()?;
    match func {
        LDT_READ | LDT_READ_DEFAULT => do_read_ldt(ptr, bytecount),
        LDT_WRITE | LDT_WRITE_NEW => do_write_ldt(ptr, bytecount, func == LDT_WRITE_NEW),
        _ => Err(Error::InvalidArgument),
    }
}

fn do_read_ldt(ptr: u64, bytecount: u64) -> Result<i64> {
    let _ = (ptr, bytecount);
    // TODO: Copy current LDT entries into user-space buffer.
    Err(Error::NotImplemented)
}

fn do_write_ldt(ptr: u64, bytecount: u64, new_format: bool) -> Result<i64> {
    let _ = (ptr, bytecount, new_format);
    // TODO: Read LDT entry from user space, validate it, and install into
    // the process's GDT/LDT.
    Err(Error::NotImplemented)
}

/// Entry point called from the syscall dispatcher.
pub fn do_modify_ldt_syscall(func: i32, ptr: u64, bytecount: u64) -> Result<i64> {
    sys_modify_ldt(func, ptr, bytecount)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_func_rejected() {
        assert_eq!(
            sys_modify_ldt(99, 1, 8).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn read_null_ptr_rejected() {
        assert_eq!(
            sys_modify_ldt(LDT_READ, 0, 0).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn write_null_ptr_rejected() {
        assert_eq!(
            sys_modify_ldt(LDT_WRITE, 0, 8).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn write_short_buffer_rejected() {
        assert_eq!(
            sys_modify_ldt(LDT_WRITE, 1, 4).unwrap_err(),
            Error::InvalidArgument
        );
    }

    #[test]
    fn read_valid_passes_validation() {
        let req = ModifyLdtRequest::new(LDT_READ, 0x1000, 64);
        assert!(req.validate().is_ok());
    }

    #[test]
    fn ldt_entry_null_check() {
        let entry = LdtEntry::default();
        assert!(entry.is_null());
    }

    #[test]
    fn ldt_entry_non_null() {
        let entry = LdtEntry::new(1, 0);
        assert!(!entry.is_null());
    }
}
