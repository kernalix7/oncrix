// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/taskset` — set or retrieve a process's CPU affinity.
//!
//! `taskset(1)` is a util-linux utility (not POSIX) that binds a process
//! to a subset of CPUs via a hexadecimal CPU mask. ONCRIX supports:
//!
//! ```text
//! taskset <mask> <command> [args...]   # set own affinity, then exec
//! taskset -p                           # print own current affinity mask
//! ```
//!
//! ONCRIX is single-CPU, so the only valid mask bit is CPU 0; a mask
//! without bit 0 is rejected by the kernel with `EINVAL`. The `-p` form
//! here queries the calling process (cross-pid affinity is not modelled).
//!
//! Exit status:
//!   * 0 — `-p` query succeeded (command form never returns on success).
//!   * 1 — usage error, affinity syscall failure, or exec failure.
//!
//! Reference: util-linux `taskset(1)`; Linux `sched_setaffinity(2)`.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

/// Size of the `cpu_set_t` we exchange with the kernel (8 bytes = one
/// 64-bit word, enough for the single modelled CPU). Must be a non-zero
/// multiple of 8.
const CPU_SET_BYTES: usize = 8;

// ---------------------------------------------------------------------------
// Entry point — naked, captures argc / argv / envp from the SysV AMD64 stack.
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        // rdi = argc
        "mov rdi, [rsp]",
        // rsi = &argv[0]
        "lea rsi, [rsp + 8]",
        // rdx = &envp[0] = rsi + 8*(argc+1) = rsi + 8*argc + 8
        "lea rdx, [rsi + rdi*8 + 8]",
        "call {main}",
        "ud2",
        main = sym taskset_main,
    );
}

// ---------------------------------------------------------------------------
// taskset logic
// ---------------------------------------------------------------------------

extern "C" fn taskset_main(argc: usize, argv: *const *const u8, envp: *const *const u8) -> ! {
    if argc < 2 {
        write_all(2, b"usage: taskset mask command [args] | taskset -p\n");
        libc::exit(1)
    }

    // SAFETY: argc >= 2 keeps argv[1] in range; kernel argv is
    // NULL-terminated so in-range slots are readable.
    let arg1 = unsafe { argv.add(1).read() };
    if arg1.is_null() {
        write_all(2, b"taskset: missing operand\n");
        libc::exit(1)
    }

    // `-p` / `--pid`: query and print the calling process's mask.
    if is_pid_flag(arg1) {
        print_self_affinity();
    }

    // Otherwise argv[1] is a hex CPU mask; argv[2..] is the command.
    let mask = match parse_hex_u64(arg1) {
        Some(m) => m,
        None => {
            write_all(2, b"taskset: invalid mask\n");
            libc::exit(1)
        }
    };
    if argc < 3 {
        write_all(2, b"taskset: missing command\n");
        libc::exit(1)
    }
    // SAFETY: argc >= 3 keeps argv[2] in range.
    let path = unsafe { argv.add(2).read() };
    if path.is_null() {
        write_all(2, b"taskset: missing command\n");
        libc::exit(1)
    }

    // Apply affinity to ourselves; the exec'd command inherits it.
    let mut set = [0u8; CPU_SET_BYTES];
    write_mask(&mut set, mask);
    // SAFETY: set is a valid CPU_SET_BYTES buffer for the call.
    let rc = unsafe { libc::sched_setaffinity(0, CPU_SET_BYTES, set.as_ptr()) };
    if rc < 0 {
        write_all(2, b"taskset: failed to set affinity\n");
        libc::exit(1)
    }

    // SAFETY: path is a kernel-supplied C string; new_argv = &argv[2] is
    // a still-NULL-terminated tail; envp inherited.
    let new_argv = unsafe { argv.add(2) };
    // SAFETY: all three are kernel-supplied NUL-/NULL-terminated arrays.
    let _ = unsafe { libc::execve(path, new_argv, envp) };

    write_all(2, b"taskset: cannot exec command\n");
    libc::exit(1)
}

/// Query the calling process's CPU mask and print it as hex, then exit.
fn print_self_affinity() -> ! {
    let mut set = [0u8; CPU_SET_BYTES];
    // SAFETY: set is a valid CPU_SET_BYTES buffer for the call.
    let rc = unsafe { libc::sched_getaffinity(0, CPU_SET_BYTES, set.as_mut_ptr()) };
    if rc < 0 {
        write_all(2, b"taskset: failed to get affinity\n");
        libc::exit(1)
    }
    let mask = read_mask(&set);
    let mut out = [0u8; 32];
    let n = format_hex(mask, &mut out);
    write_all(1, b"mask: 0x");
    write_all(1, &out[..n]);
    write_all(1, b"\n");
    libc::exit(0)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns `true` if the C string at `ptr` is `-p` or `--pid`.
fn is_pid_flag(ptr: *const u8) -> bool {
    c_eq(ptr, b"-p\0") || c_eq(ptr, b"--pid\0")
}

/// Compare a NUL-terminated C string against a NUL-terminated pattern.
fn c_eq(ptr: *const u8, pat: &[u8]) -> bool {
    for (i, &want) in pat.iter().enumerate() {
        // SAFETY: we stop at the pattern's NUL and the C string is
        // NUL-terminated, so we never read past either terminator.
        let got = unsafe { ptr.add(i).read() };
        if got != want {
            return false;
        }
        if want == 0 {
            return true;
        }
    }
    true
}

/// Parse a hexadecimal `u64` from a NUL-terminated C string, accepting an
/// optional `0x`/`0X` prefix. Returns `None` on empty input, overflow, or
/// any non-hex byte.
fn parse_hex_u64(ptr: *const u8) -> Option<u64> {
    let mut i = 0usize;
    // SAFETY: NUL-terminated C string.
    let b0 = unsafe { ptr.read() };
    if b0 == b'0' {
        // SAFETY: b0 non-NUL ⇒ index 1 valid.
        let b1 = unsafe { ptr.add(1).read() };
        if b1 == b'x' || b1 == b'X' {
            i = 2;
        }
    }
    let mut acc: u64 = 0;
    let mut saw = false;
    loop {
        // SAFETY: advance only past non-NUL bytes.
        let b = unsafe { ptr.add(i).read() };
        if b == 0 {
            break;
        }
        let d = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return None,
        };
        acc = acc.checked_mul(16)?.checked_add(d as u64)?;
        saw = true;
        i += 1;
    }
    if saw { Some(acc) } else { None }
}

/// Store the low bytes of `mask` little-endian into `set`.
fn write_mask(set: &mut [u8; CPU_SET_BYTES], mask: u64) {
    for (i, slot) in set.iter_mut().enumerate() {
        *slot = ((mask >> (i * 8)) & 0xFF) as u8;
    }
}

/// Read a little-endian `u64` mask out of `set`.
fn read_mask(set: &[u8; CPU_SET_BYTES]) -> u64 {
    let mut mask = 0u64;
    for (i, &b) in set.iter().enumerate() {
        mask |= (b as u64) << (i * 8);
    }
    mask
}

/// Format `value` as lowercase hex (no `0x`) into `out`, returning the
/// number of bytes written. `0` formats as `"0"`.
fn format_hex(value: u64, out: &mut [u8]) -> usize {
    if value == 0 {
        out[0] = b'0';
        return 1;
    }
    // Build digits most-significant-first by scanning nibbles.
    let mut started = false;
    let mut n = 0usize;
    for shift in (0..16).rev() {
        let nibble = ((value >> (shift * 4)) & 0xF) as u8;
        if nibble != 0 {
            started = true;
        }
        if started {
            out[n] = if nibble < 10 {
                b'0' + nibble
            } else {
                b'a' + (nibble - 10)
            };
            n += 1;
        }
    }
    n
}

/// Write all bytes in `buf` to `fd`, retrying on short writes.
fn write_all(fd: i32, buf: &[u8]) {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: buf slice is valid for buf.len() bytes.
        let n = unsafe { libc::write(fd, buf[pos..].as_ptr(), buf.len() - pos) };
        if n <= 0 {
            break;
        }
        pos += n as usize;
    }
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libc::exit(1)
}
