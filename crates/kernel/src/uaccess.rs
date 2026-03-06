// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! User-space pointer validation and safe data transfer.
//!
//! Before the kernel dereferences any pointer provided by user space,
//! it must verify that the pointer falls within the user-space address
//! range and is properly aligned. These functions provide safe
//! abstractions for `copy_from_user` and `copy_to_user` semantics.

use oncrix_lib::{Error, Result};
use oncrix_mm::address_space::{USER_SPACE_END, USER_SPACE_START};

/// Validate that a user-space pointer range is within bounds.
///
/// Returns `Ok(())` if the entire range `[ptr, ptr + len)` lies
/// within the user-space address range. Returns `InvalidArgument`
/// if any part falls outside or wraps around.
pub fn validate_user_range(ptr: u64, len: u64) -> Result<()> {
    if len == 0 {
        return Ok(());
    }

    // Check that the pointer is within user space.
    if ptr < USER_SPACE_START {
        return Err(Error::InvalidArgument);
    }

    // Check for wrap-around.
    let end = ptr.checked_add(len).ok_or(Error::InvalidArgument)?;

    // Check that the end is within user space.
    if end > USER_SPACE_END + 1 {
        return Err(Error::InvalidArgument);
    }

    Ok(())
}

/// Validate a user-space string pointer (null-terminated).
///
/// Walks the string up to `max_len` bytes looking for a null
/// terminator. Returns the string length (not including the null
/// byte) on success.
///
/// # Safety
///
/// The caller must ensure that the memory at `ptr` is actually
/// mapped and accessible. This function only validates the address
/// range, not the page table mappings.
pub unsafe fn validate_user_string(ptr: u64, max_len: usize) -> Result<usize> {
    validate_user_range(ptr, max_len as u64)?;

    // SAFETY: Caller guarantees the memory is mapped.
    unsafe {
        let base = ptr as *const u8;
        for i in 0..max_len {
            if *base.add(i) == 0 {
                return Ok(i);
            }
        }
    }

    // No null terminator found within max_len.
    Err(Error::InvalidArgument)
}

/// Copy data from user space to kernel space.
///
/// Validates the source range, then copies `len` bytes from the
/// user-space address `src` to the kernel buffer `dst`.
///
/// # Safety
///
/// - `src` must point to mapped, readable user-space memory.
/// - `dst` must point to a valid kernel buffer of at least `len` bytes.
pub unsafe fn copy_from_user(dst: &mut [u8], src: u64, len: usize) -> Result<usize> {
    if len == 0 {
        return Ok(0);
    }

    if dst.len() < len {
        return Err(Error::InvalidArgument);
    }

    validate_user_range(src, len as u64)?;

    // SAFETY: Range is validated. Caller guarantees pages are mapped.
    unsafe {
        let src_ptr = src as *const u8;
        core::ptr::copy_nonoverlapping(src_ptr, dst.as_mut_ptr(), len);
    }

    Ok(len)
}

/// Copy data from kernel space to user space.
///
/// Validates the destination range, then copies `len` bytes from
/// the kernel buffer `src` to the user-space address `dst`.
///
/// # Safety
///
/// - `dst` must point to mapped, writable user-space memory.
/// - `src` must be a valid kernel buffer of at least `len` bytes.
pub unsafe fn copy_to_user(dst: u64, src: &[u8], len: usize) -> Result<usize> {
    if len == 0 {
        return Ok(0);
    }

    if src.len() < len {
        return Err(Error::InvalidArgument);
    }

    validate_user_range(dst, len as u64)?;

    // SAFETY: Range is validated. Caller guarantees pages are mapped.
    unsafe {
        let dst_ptr = dst as *mut u8;
        core::ptr::copy_nonoverlapping(src.as_ptr(), dst_ptr, len);
    }

    Ok(len)
}

/// Read a single u64 value from user space.
///
/// # Safety
///
/// The user-space address must be mapped and properly aligned.
pub unsafe fn get_user_u64(addr: u64) -> Result<u64> {
    validate_user_range(addr, 8)?;

    if addr % 8 != 0 {
        return Err(Error::InvalidArgument);
    }

    // SAFETY: Range and alignment validated.
    unsafe { Ok(*(addr as *const u64)) }
}

/// Write a single u64 value to user space.
///
/// # Safety
///
/// The user-space address must be mapped, writable, and properly aligned.
pub unsafe fn put_user_u64(addr: u64, value: u64) -> Result<()> {
    validate_user_range(addr, 8)?;

    if addr % 8 != 0 {
        return Err(Error::InvalidArgument);
    }

    // SAFETY: Range and alignment validated.
    unsafe {
        *(addr as *mut u64) = value;
    }

    Ok(())
}
