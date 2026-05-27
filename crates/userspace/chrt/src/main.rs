// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/chrt` — manipulate the scheduling policy of a process.
//!
//! `chrt(1)` is a util-linux utility (not POSIX) that sets or queries a
//! process's scheduling policy and priority. ONCRIX supports the two
//! canonical forms:
//!
//! ```text
//! chrt [-o|-f|-r] [priority] <command> [args...]   # run command under policy
//! chrt -p                                          # query own policy
//! ```
//!
//! Policy selection flags (default `SCHED_OTHER` if none given):
//!   * `-o` / `--other` → `SCHED_OTHER` (0)
//!   * `-f` / `--fifo`  → `SCHED_FIFO`  (1)
//!   * `-r` / `--rr`    → `SCHED_RR`    (2)
//!   * `-p` / `--pid`   → print the calling process's current policy and exit.
//!
//! When running a command, `chrt` applies the chosen policy (and, if a
//! numeric priority operand is present, that real-time priority) to
//! itself via `sched_setscheduler`, then `execve`s the command so the
//! new program inherits the policy.
//!
//! Exit status:
//!   * 0 — `-p` query succeeded (command form never returns on success).
//!   * 1 — usage error, `sched_setscheduler` failure, or exec failure.
//!
//! Reference: util-linux `chrt(1)`;
//! `.priv-storage/.TheOpenGroup/susv5-html/functions/sched_setscheduler.html`.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

/// `SCHED_OTHER` — standard time-sharing policy.
const SCHED_OTHER: i32 = 0;
/// `SCHED_FIFO` — first-in-first-out real-time policy.
const SCHED_FIFO: i32 = 1;
/// `SCHED_RR` — round-robin real-time policy.
const SCHED_RR: i32 = 2;

/// `struct sched_param` — only the leading `sched_priority` matters here.
#[repr(C)]
struct SchedParam {
    sched_priority: i32,
}

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
        main = sym chrt_main,
    );
}

// ---------------------------------------------------------------------------
// chrt logic
// ---------------------------------------------------------------------------

extern "C" fn chrt_main(argc: usize, argv: *const *const u8, envp: *const *const u8) -> ! {
    if argc < 2 {
        write_all(2, b"usage: chrt [-o|-f|-r] [prio] command [args]\n");
        libc::exit(1)
    }

    // Walk leading option words. Track chosen policy and whether `-p`.
    let mut idx = 1usize;
    let mut policy = SCHED_OTHER;
    loop {
        if idx >= argc {
            break;
        }
        // SAFETY: idx < argc keeps argv[idx] in range; the kernel argv
        // array is NULL-terminated so in-range slots are readable.
        let arg = unsafe { argv.add(idx).read() };
        if arg.is_null() {
            break;
        }
        match classify_flag(arg) {
            Flag::Query => {
                query_self_policy();
            }
            Flag::Policy(p) => {
                policy = p;
                idx += 1;
            }
            Flag::NotAFlag => break,
        }
    }

    // Optional numeric priority operand (real-time priority).
    let mut sched_priority = 0i32;
    if idx < argc {
        // SAFETY: idx < argc, see above.
        let arg = unsafe { argv.add(idx).read() };
        if !arg.is_null()
            && let Some(n) = parse_u31(arg)
        {
            sched_priority = n;
            idx += 1;
        }
    }

    // Remaining argv[idx..] is the command. Require at least one word.
    if idx >= argc {
        write_all(2, b"chrt: missing command\n");
        libc::exit(1)
    }
    // SAFETY: idx < argc.
    let path = unsafe { argv.add(idx).read() };
    if path.is_null() {
        write_all(2, b"chrt: missing command\n");
        libc::exit(1)
    }

    // Apply the policy to ourselves before exec; the command inherits it.
    let param = SchedParam { sched_priority };
    // SAFETY: sched_setscheduler is a syscall wrapper; &param is a valid
    // readable pointer to a single i32-sized struct for the call.
    let rc =
        unsafe { libc::sched_setscheduler(0, policy, &param as *const SchedParam as *const u8) };
    if rc < 0 {
        write_all(2, b"chrt: failed to set scheduling policy\n");
        libc::exit(1)
    }

    // SAFETY: path is a kernel-supplied C string; new_argv = &argv[idx]
    // is a still-NULL-terminated tail; envp inherited.
    let new_argv = unsafe { argv.add(idx) };
    // SAFETY: all three are kernel-supplied NUL-/NULL-terminated arrays.
    let _ = unsafe { libc::execve(path, new_argv, envp) };

    write_all(2, b"chrt: cannot exec command\n");
    libc::exit(1)
}

/// Query and print the calling process's current scheduling policy.
///
/// Never returns: prints the policy name and exits `0`, or an error and
/// exits `1`.
fn query_self_policy() -> ! {
    // SAFETY: sched_getscheduler is a plain syscall wrapper.
    let pol = unsafe { libc::sched_getscheduler(0) };
    // libc::sched_getscheduler returns i64 (policy >=0, or negative errno);
    // narrow to i32 to match the SCHED_* constants. Errnos fall through to `_`.
    let name: &[u8] = match pol as i32 {
        SCHED_OTHER => b"current scheduling policy: SCHED_OTHER\n",
        SCHED_FIFO => b"current scheduling policy: SCHED_FIFO\n",
        SCHED_RR => b"current scheduling policy: SCHED_RR\n",
        _ => {
            write_all(2, b"chrt: cannot get scheduling policy\n");
            libc::exit(1)
        }
    };
    write_all(1, name);
    libc::exit(0)
}

// ---------------------------------------------------------------------------
// Argument parsing helpers
// ---------------------------------------------------------------------------

/// Classification of a leading `chrt` argument word.
enum Flag {
    /// `-p`/`--pid`: query mode.
    Query,
    /// A policy-selection flag carrying its `SCHED_*` value.
    Policy(i32),
    /// Not a recognised flag — start of the command / priority.
    NotAFlag,
}

/// Classify a leading argument as a policy flag, query flag, or neither.
fn classify_flag(ptr: *const u8) -> Flag {
    // SAFETY: ptr is a NUL-terminated C string from the kernel argv.
    let b0 = unsafe { ptr.read() };
    if b0 != b'-' {
        return Flag::NotAFlag;
    }
    // SAFETY: b0 non-NUL, so index 1 is within the string.
    let b1 = unsafe { ptr.add(1).read() };
    // Short single-letter flags: -o / -f / -r / -p with NUL after.
    // SAFETY: b1 non-NUL ⇒ index 2 valid; if b1 == 0 we never read it.
    let b2 = if b1 == 0 {
        0
    } else {
        unsafe { ptr.add(2).read() }
    };
    if b2 == 0 {
        return match b1 {
            b'o' => Flag::Policy(SCHED_OTHER),
            b'f' => Flag::Policy(SCHED_FIFO),
            b'r' => Flag::Policy(SCHED_RR),
            b'p' => Flag::Query,
            _ => Flag::NotAFlag,
        };
    }
    // Long forms: --other/--fifo/--rr/--pid.
    if c_eq(ptr, b"--other\0") {
        Flag::Policy(SCHED_OTHER)
    } else if c_eq(ptr, b"--fifo\0") {
        Flag::Policy(SCHED_FIFO)
    } else if c_eq(ptr, b"--rr\0") {
        Flag::Policy(SCHED_RR)
    } else if c_eq(ptr, b"--pid\0") {
        Flag::Query
    } else {
        Flag::NotAFlag
    }
}

/// Compare a NUL-terminated C string at `ptr` against a NUL-terminated
/// pattern `pat` (including the terminators).
fn c_eq(ptr: *const u8, pat: &[u8]) -> bool {
    for (i, &want) in pat.iter().enumerate() {
        // SAFETY: we stop at the pattern's NUL, and the C string is
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

/// Parse a non-negative decimal integer (`[0, i32::MAX]`) from a
/// NUL-terminated C string. Returns `None` on empty input, a sign, or
/// any non-digit byte.
fn parse_u31(ptr: *const u8) -> Option<i32> {
    let mut i = 0usize;
    let mut acc: i32 = 0;
    let mut saw_digit = false;
    loop {
        // SAFETY: we advance only while the previous byte was non-NUL.
        let b = unsafe { ptr.add(i).read() };
        if b == 0 {
            break;
        }
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((b - b'0') as i32)?;
        saw_digit = true;
        i += 1;
    }
    if saw_digit { Some(acc) } else { None }
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
