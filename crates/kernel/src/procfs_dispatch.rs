// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Synthesizer for dynamic `/proc` file content.
//!
//! Lives in the kernel crate (not `oncrix_vfs`) because it needs to
//! read `PIT_TIMER` directly — the VFS crate sits below the kernel in
//! the dependency graph and cannot call back into it.
//!
//! Called from `fd_table::dispatch_read` whenever a `FileBackend::ProcFile`
//! handle is encountered.

use oncrix_hal::timer::Timer;
use oncrix_vfs::procfs::ProcKind;

/// PIT tick frequency in hertz (matches `time_syscalls.rs`).
const TIMER_HZ: u64 = 100;

/// Read the current PIT tick count.
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path (single-CPU,
/// interrupts effectively disabled by FMASK).
unsafe fn pit_ticks() -> u64 {
    // SAFETY: same invariant as time_syscalls::current_ticks — single-CPU
    // SYSCALL context, no concurrent mutation of PIT_TIMER.
    unsafe {
        let pit_ptr = &raw const crate::arch::init::PIT_TIMER;
        (*pit_ptr).current_ticks()
    }
}

/// Synthesize the content of a `/proc` file into `buf`.
///
/// Returns the number of bytes written (may be less than the full
/// content if `buf` is smaller than the output).
///
/// # Safety
///
/// Must be called from the SYSCALL dispatch path.
pub unsafe fn proc_synthesize(kind: ProcKind, buf: &mut [u8]) -> usize {
    let mut tmp = [0u8; 256];

    let content: &[u8] = match kind {
        ProcKind::Uptime => {
            // SAFETY: SYSCALL dispatch context — same as pit_ticks contract.
            let ticks = unsafe { pit_ticks() };
            let secs = ticks / TIMER_HZ;
            let centi = (ticks % TIMER_HZ) as u32;
            let n = fmt_uptime(secs, centi, &mut tmp);
            &tmp[..n]
        }
        ProcKind::Version => b"ONCRIX 0.1.0 x86_64\n",
        ProcKind::Meminfo => {
            b"MemTotal:       131072 kB\nMemFree:         65536 kB\nMemAvailable:    65536 kB\n"
        }
    };

    let len = content.len().min(buf.len());
    buf[..len].copy_from_slice(&content[..len]);
    len
}

/// Format uptime as `"<secs>.<centi> 0.00\n"` into `buf`.
///
/// Returns bytes written.  Uses only stack-allocated scratch space.
fn fmt_uptime(secs: u64, centi: u32, buf: &mut [u8]) -> usize {
    let mut pos = 0usize;
    pos += write_u64(secs, &mut buf[pos..]);
    if pos < buf.len() {
        buf[pos] = b'.';
        pos += 1;
    }
    // Two-digit centiseconds with leading zero.
    if pos < buf.len() {
        buf[pos] = b'0' + (centi / 10) as u8;
        pos += 1;
    }
    if pos < buf.len() {
        buf[pos] = b'0' + (centi % 10) as u8;
        pos += 1;
    }
    // Idle time — always "0.00" for now (no SMP idle accounting).
    let suffix = b" 0.00\n";
    let copy = suffix.len().min(buf.len() - pos);
    buf[pos..pos + copy].copy_from_slice(&suffix[..copy]);
    pos + copy
}

/// Write `val` as ASCII decimal into `buf`. Returns bytes written.
fn write_u64(val: u64, buf: &mut [u8]) -> usize {
    if buf.is_empty() {
        return 0;
    }
    if val == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut digits = [0u8; 20];
    let mut n = val;
    let mut i = 20usize;
    while n > 0 {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    let len = (20 - i).min(buf.len());
    buf[..len].copy_from_slice(&digits[i..i + len]);
    len
}
