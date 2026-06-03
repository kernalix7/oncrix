// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! System-identity syscalls: `uname(2)`, `sethostname(2)`, `setdomainname(2)`.
//!
//! Maintains two mutable globals — `HOSTNAME` and `DOMAINNAME` — that are
//! written by `sethostname`/`setdomainname` and read back through the
//! `nodename`/`domainname` fields of the `struct utsname` returned by `uname`.
//!
//! # struct utsname layout (POSIX.1-2024 / Linux x86_64 ABI)
//!
//! Six fields of 65 bytes each, in order:
//!
//! | Offset | Field        | Fixed value / source       |
//! |--------|--------------|----------------------------|
//! |    0   | `sysname`    | `"ONCRIX"`                 |
//! |   65   | `nodename`   | `HOSTNAME` global          |
//! |  130   | `release`    | `"0.1.0"`                  |
//! |  195   | `version`    | `"ONCRIX 0.1.0"`           |
//! |  260   | `machine`    | `"x86_64"`                 |
//! |  325   | `domainname` | `DOMAINNAME` global        |
//!
//! Total: 390 bytes.
//!
//! # Single-CPU safety
//!
//! ONCRIX currently runs on a single CPU with interrupts masked during
//! SYSCALL dispatch. The static muts are therefore accessed exclusively
//! from the SYSCALL path; there is no concurrent reader or writer.
//!
//! POSIX.1-2024 references:
//! - `uname(3p)` — `functions/uname.html`
//! - `sethostname(2)` / `setdomainname(2)` — Linux man-pages extensions

// ── Global identity state ─────────────────────────────────────────────────

/// System hostname, NUL-padded to 65 bytes.
///
/// # Safety
///
/// Must only be accessed from the single-CPU SYSCALL dispatch path
/// with interrupts masked. No concurrent access is possible under the
/// current single-processor model.
static mut HOSTNAME: [u8; 65] = {
    let mut buf = [0u8; 65];
    // b"oncrix" = [111, 110, 99, 114, 105, 120]
    buf[0] = b'o';
    buf[1] = b'n';
    buf[2] = b'c';
    buf[3] = b'r';
    buf[4] = b'i';
    buf[5] = b'x';
    buf
};

/// System domain name, NUL-padded to 65 bytes.
///
/// # Safety
///
/// Same single-CPU SYSCALL-context constraint as [`HOSTNAME`].
static mut DOMAINNAME: [u8; 65] = {
    let mut buf = [0u8; 65];
    // b"(none)" = [40, 110, 111, 110, 101, 41]
    buf[0] = b'(';
    buf[1] = b'n';
    buf[2] = b'o';
    buf[3] = b'n';
    buf[4] = b'e';
    buf[5] = b')';
    buf
};

// ── utsname field constants ───────────────────────────────────────────────

/// Byte length of each `utsname` field (including NUL terminator slot).
const FIELD_LEN: usize = 65;

/// Total size of `struct utsname` (6 × 65 bytes).
pub const UTSNAME_SIZE: usize = 6 * FIELD_LEN; // 390

// Static field literals (written into the output buffer at fixed offsets).
const SYSNAME: &[u8] = b"ONCRIX";
const RELEASE: &[u8] = b"0.1.0";
const VERSION: &[u8] = b"ONCRIX 0.1.0";
const MACHINE: &[u8] = b"x86_64";

// ── Helper ────────────────────────────────────────────────────────────────

/// Write `src` into `dst[offset..offset+FIELD_LEN]`, NUL-padding the rest.
///
/// Truncates silently at `FIELD_LEN - 1` bytes so the field is always
/// NUL-terminated. `dst` must be at least `offset + FIELD_LEN` bytes.
fn write_field(dst: &mut [u8], offset: usize, src: &[u8]) {
    let copy = src.len().min(FIELD_LEN - 1);
    let mut i = 0;
    while i < copy {
        dst[offset + i] = src[i];
        i += 1;
    }
    // Zero-pad remainder of slot (including NUL terminator).
    while i < FIELD_LEN {
        dst[offset + i] = 0;
        i += 1;
    }
}

// ── sys_uname ─────────────────────────────────────────────────────────────

/// Kernel handler for `SYS_UNAME` (number 63).
///
/// Fills the 390-byte `struct utsname` at the user-space address `buf_ptr`
/// with six NUL-padded 65-byte fields: `sysname`, `nodename`, `release`,
/// `version`, `machine`, `domainname`.
///
/// # Errors (returned as negative errno)
///
/// - `-14` `EFAULT` — the 390-byte struct at `buf_ptr` is not a writable
///   user-space region.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.  All static
/// muts accessed here are exclusively owned for the duration of this call
/// (single CPU, interrupts masked by SYSCALL entry).
pub unsafe fn sys_uname(buf_ptr: u64) -> i64 {
    // Span-check the exact 390-byte struct the kernel is about to write.
    if crate::uaccess::verify_user_access(buf_ptr, UTSNAME_SIZE as u64, true).is_err() {
        return -14; // EFAULT
    }

    // Stack-allocate the 390-byte output struct.
    let mut buf = [0u8; UTSNAME_SIZE];

    write_field(&mut buf, 0, SYSNAME);

    // SAFETY: single-CPU SYSCALL context; HOSTNAME not concurrently mutated.
    #[allow(static_mut_refs)]
    let hostname_len = {
        let h = unsafe { &HOSTNAME };
        let mut n = 0;
        while n < FIELD_LEN && h[n] != 0 {
            n += 1;
        }
        n
    };
    #[allow(static_mut_refs)]
    // SAFETY: single-CPU SYSCALL context.
    write_field(&mut buf, FIELD_LEN, unsafe { &HOSTNAME[..hostname_len] });

    write_field(&mut buf, 2 * FIELD_LEN, RELEASE);
    write_field(&mut buf, 3 * FIELD_LEN, VERSION);
    write_field(&mut buf, 4 * FIELD_LEN, MACHINE);

    // SAFETY: single-CPU SYSCALL context; DOMAINNAME not concurrently mutated.
    #[allow(static_mut_refs)]
    let domainname_len = {
        let d = unsafe { &DOMAINNAME };
        let mut n = 0;
        while n < FIELD_LEN && d[n] != 0 {
            n += 1;
        }
        n
    };
    #[allow(static_mut_refs)]
    // SAFETY: single-CPU SYSCALL context.
    write_field(&mut buf, 5 * FIELD_LEN, unsafe {
        &DOMAINNAME[..domainname_len]
    });

    // Write the struct to user space, byte-by-byte (volatile, validated ptr).
    let dst = buf_ptr as *mut u8;
    let mut i = 0;
    while i < UTSNAME_SIZE {
        // SAFETY: buf_ptr validated above; single-byte volatile stores are safe
        // as long as the user mapping is present (kernel guarantees ring-3 RSP
        // access during SYSCALL is to user-mapped pages).
        unsafe { dst.add(i).write_volatile(buf[i]) };
        i += 1;
    }

    0
}

// ── sys_sethostname ───────────────────────────────────────────────────────

/// Kernel handler for `SYS_SETHOSTNAME` (number 170).
///
/// Copies at most 64 bytes from the user-space buffer `name_ptr` (of length
/// `len`) into the global `HOSTNAME`, then NUL-terminates the stored copy.
///
/// # Errors (returned as negative errno)
///
/// - `-22` `EINVAL` — `len` exceeds 64.
/// - `-14` `EFAULT` — the `len`-byte span at `name_ptr` is not a readable
///   user-space region.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.
pub unsafe fn sys_sethostname(name_ptr: u64, len: u64) -> i64 {
    if len > 64 {
        return -22; // EINVAL
    }
    // Span-check the exact `len` bytes the kernel is about to read.
    if crate::uaccess::verify_user_access(name_ptr, len, false).is_err() {
        return -14; // EFAULT
    }

    let copy = len as usize;
    // SAFETY: single-CPU SYSCALL context; HOSTNAME exclusively owned here.
    #[allow(static_mut_refs)]
    let hostname = unsafe { &mut HOSTNAME };

    // Volatile byte-by-byte copy from user space.
    let src = name_ptr as *const u8;
    let mut i = 0;
    while i < copy {
        // SAFETY: name_ptr validated; i < copy <= 64 < 65 (HOSTNAME length).
        hostname[i] = unsafe { src.add(i).read_volatile() };
        i += 1;
    }
    // NUL-terminate and zero-pad remainder.
    while i < 65 {
        hostname[i] = 0;
        i += 1;
    }

    0
}

// ── sys_setdomainname ─────────────────────────────────────────────────────

/// Kernel handler for `SYS_SETDOMAINNAME` (number 171).
///
/// Copies at most 64 bytes from the user-space buffer `name_ptr` (of length
/// `len`) into the global `DOMAINNAME`, then NUL-terminates the stored copy.
///
/// # Errors (returned as negative errno)
///
/// - `-22` `EINVAL` — `len` exceeds 64.
/// - `-14` `EFAULT` — the `len`-byte span at `name_ptr` is not a readable
///   user-space region.
///
/// # Safety
///
/// Must be called from the single-CPU SYSCALL dispatch path.
pub unsafe fn sys_setdomainname(name_ptr: u64, len: u64) -> i64 {
    if len > 64 {
        return -22; // EINVAL
    }
    // Span-check the exact `len` bytes the kernel is about to read.
    if crate::uaccess::verify_user_access(name_ptr, len, false).is_err() {
        return -14; // EFAULT
    }

    let copy = len as usize;
    // SAFETY: single-CPU SYSCALL context; DOMAINNAME exclusively owned here.
    #[allow(static_mut_refs)]
    let domainname = unsafe { &mut DOMAINNAME };

    let src = name_ptr as *const u8;
    let mut i = 0;
    while i < copy {
        // SAFETY: name_ptr validated; i < copy <= 64 < 65 (DOMAINNAME length).
        domainname[i] = unsafe { src.add(i).read_volatile() };
        i += 1;
    }
    while i < 65 {
        domainname[i] = 0;
        i += 1;
    }

    0
}
