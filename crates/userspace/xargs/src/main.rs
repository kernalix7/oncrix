// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/xargs` — build and run command lines from standard input.
//!
//! Supported usage:
//!
//! ```text
//! xargs [CMD [ARG...]]            # one invocation with all stdin tokens appended
//! xargs -n MAX [CMD [ARG...]]     # batches of MAX tokens per invocation
//! xargs -I REPL [CMD [ARG...]]    # per-token; replace exact-match REPL slot with token
//! xargs -0 ...                    # tokens are NUL-separated instead of whitespace
//! ```
//!
//! `CMD` defaults to `/bin/echo` when no command is supplied. The kernel's
//! `embedded_lookup` accepts both `/bin/<name>` and bare-name forms, so the
//! command is passed to `execve` unchanged.
//!
//! Heap-free: uses a fixed 8 KiB stdin buffer, up to 64 tokens per batch, and
//! an 80-slot argv array (static prefix + tokens + NULL terminator).
//!
//! Exit codes: 0 on full success, 1 on any failure (parse, fork, exec, or any
//! child exiting non-zero). This collapses the POSIX 0/123/124/125/126/127
//! ladder for ONCRIX simplicity.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/xargs.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

/// Maximum command line bytes read from stdin.
const STDIN_BUF: usize = 8192;
/// Maximum tokens collected before forcing a flush.
const TOKEN_MAX: usize = 64;
/// Maximum bytes per individual token (including NUL terminator).
const TOKEN_LEN: usize = 128;
/// Maximum static-prefix argv slots supplied on xargs's own command line.
const PREFIX_MAX: usize = 16;
/// Maximum bytes per static-prefix argv slot (including NUL terminator).
const PREFIX_LEN: usize = 128;
/// argv array length for the spawned child: prefix + tokens + NULL terminator.
const ARGV_MAX: usize = 80;

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym xargs_main,
    );
}

extern "C" fn xargs_main(argc: usize, argv: *const *const u8) -> ! {
    // -------- parse flags --------
    let mut idx = 1usize;
    let mut null_delim = false;
    let mut max_per_batch: usize = 0; // 0 = unlimited (one invocation)
    let mut replace: Option<&'static [u8]> = None;

    while idx < argc {
        // SAFETY: idx < argc and argv was provided by the kernel.
        let arg = unsafe { cstr_at(argv, idx) };
        if arg == b"-0" {
            null_delim = true;
            idx += 1;
            continue;
        }
        if arg == b"-n" {
            idx += 1;
            if idx >= argc {
                fail(b"xargs: -n needs MAX\n");
            }
            // SAFETY: idx < argc.
            let v = unsafe { cstr_at(argv, idx) };
            match parse_usize(v) {
                Some(n) if n > 0 => max_per_batch = n,
                _ => fail(b"xargs: invalid -n value\n"),
            }
            idx += 1;
            continue;
        }
        if arg == b"-I" {
            idx += 1;
            if idx >= argc {
                fail(b"xargs: -I needs REPL\n");
            }
            // SAFETY: idx < argc.
            replace = Some(unsafe { cstr_at(argv, idx) });
            // -I implies one execution per token.
            max_per_batch = 1;
            idx += 1;
            continue;
        }
        // First non-flag argument starts the static command prefix.
        break;
    }

    // -------- copy static argv prefix --------
    // `prefix_storage[i]` holds a NUL-terminated copy of argv[idx + i]; the
    // trailing zero byte is the NUL since the array is zero-initialised.
    let mut prefix_storage = [[0u8; PREFIX_LEN]; PREFIX_MAX];
    let mut prefix_len = [0usize; PREFIX_MAX];
    let mut prefix_count = 0usize;

    while idx < argc && prefix_count < PREFIX_MAX {
        // SAFETY: idx < argc.
        let s = unsafe { cstr_at(argv, idx) };
        if s.len() >= PREFIX_LEN {
            fail(b"xargs: argument too long\n");
        }
        prefix_storage[prefix_count][..s.len()].copy_from_slice(s);
        prefix_len[prefix_count] = s.len();
        prefix_count += 1;
        idx += 1;
    }
    if idx < argc {
        fail(b"xargs: too many static arguments\n");
    }
    // No command supplied → default to /bin/echo.
    if prefix_count == 0 {
        let dflt = b"/bin/echo";
        prefix_storage[0][..dflt.len()].copy_from_slice(dflt);
        prefix_len[0] = dflt.len();
        prefix_count = 1;
    }

    // -------- read all of stdin into a fixed buffer --------
    let mut stdin_buf = [0u8; STDIN_BUF];
    let mut stdin_len = 0usize;
    loop {
        if stdin_len >= stdin_buf.len() {
            fail(b"xargs: input buffer overflow\n");
        }
        // SAFETY: stdin_buf has STDIN_BUF - stdin_len writable bytes at offset stdin_len.
        let n = unsafe {
            libc::read(
                0,
                stdin_buf.as_mut_ptr().add(stdin_len),
                stdin_buf.len() - stdin_len,
            )
        };
        if n <= 0 {
            break;
        }
        stdin_len += n as usize;
    }

    // -------- token store (NUL-terminated copies) --------
    let mut token_storage = [[0u8; TOKEN_LEN]; TOKEN_MAX];
    let mut token_len = [0usize; TOKEN_MAX];
    let mut token_count = 0usize;

    let mut any_failure = false;
    let mut any_invocation = false;

    let batch_size = if max_per_batch == 0 {
        TOKEN_MAX
    } else {
        max_per_batch.min(TOKEN_MAX)
    };

    // Tokenizer state.
    let mut i = 0usize;
    while i < stdin_len {
        // Find next token start.
        if !null_delim {
            while i < stdin_len && is_ws(stdin_buf[i]) {
                i += 1;
            }
        } else {
            while i < stdin_len && stdin_buf[i] == 0 {
                i += 1;
            }
        }
        if i >= stdin_len {
            break;
        }
        let start = i;
        if !null_delim {
            while i < stdin_len && !is_ws(stdin_buf[i]) {
                i += 1;
            }
        } else {
            while i < stdin_len && stdin_buf[i] != 0 {
                i += 1;
            }
        }
        let tok = &stdin_buf[start..i];
        if tok.len() >= TOKEN_LEN {
            fail(b"xargs: token too long\n");
        }
        token_storage[token_count][..tok.len()].copy_from_slice(tok);
        token_len[token_count] = tok.len();
        token_count += 1;

        if token_count >= batch_size {
            any_invocation = true;
            if !run_batch(
                &prefix_storage,
                &prefix_len,
                prefix_count,
                &token_storage,
                &token_len,
                token_count,
                replace,
            ) {
                any_failure = true;
            }
            token_count = 0;
        }
    }

    if token_count > 0 {
        any_invocation = true;
        if !run_batch(
            &prefix_storage,
            &prefix_len,
            prefix_count,
            &token_storage,
            &token_len,
            token_count,
            replace,
        ) {
            any_failure = true;
        }
    }

    // POSIX: when no items are read, xargs runs the command once with no
    // appended args (unless an extension like GNU `-r` says otherwise).
    if !any_invocation
        && !run_batch(
            &prefix_storage,
            &prefix_len,
            prefix_count,
            &token_storage,
            &token_len,
            0,
            replace,
        )
    {
        any_failure = true;
    }

    if any_failure {
        libc::exit(1);
    }
    libc::exit(0)
}

/// Build argv from the static prefix + this batch of tokens, fork+execve,
/// and wait for the child. Returns `true` if the child exited 0.
fn run_batch(
    prefix_storage: &[[u8; PREFIX_LEN]; PREFIX_MAX],
    prefix_len: &[usize; PREFIX_MAX],
    prefix_count: usize,
    token_storage: &[[u8; TOKEN_LEN]; TOKEN_MAX],
    token_len: &[usize; TOKEN_MAX],
    token_count: usize,
    replace: Option<&[u8]>,
) -> bool {
    // For `-I REPL`, expand REPL inside any prefix slot that exactly matches
    // it. Each substituted slot needs its own backing storage; reuse a stack
    // scratch array sized to prefix_count.
    let mut subst_storage = [[0u8; TOKEN_LEN]; PREFIX_MAX];
    let mut subst_len = [0usize; PREFIX_MAX];

    let mut argv: [*const u8; ARGV_MAX] = [core::ptr::null(); ARGV_MAX];
    let mut slot = 0usize;

    // Static prefix (with optional REPL substitution).
    let token = if token_count > 0 {
        Some(&token_storage[0][..token_len[0]])
    } else {
        None
    };
    for i in 0..prefix_count {
        if slot >= ARGV_MAX - 1 {
            return write_err(b"xargs: argv overflow\n");
        }
        let p = &prefix_storage[i][..prefix_len[i]];
        let needs_subst = match (replace, token) {
            (Some(r), Some(_)) => p == r,
            _ => false,
        };
        if needs_subst {
            // SAFETY of branch: replace+token were both Some, so unwrap is fine.
            let t = token.unwrap_or(&[]);
            if t.len() >= TOKEN_LEN {
                return write_err(b"xargs: substitution too long\n");
            }
            subst_storage[i][..t.len()].copy_from_slice(t);
            subst_len[i] = t.len();
            argv[slot] = subst_storage[i].as_ptr();
        } else {
            argv[slot] = prefix_storage[i].as_ptr();
        }
        slot += 1;
    }

    // Append tokens. With `-I REPL` the token is consumed by substitution
    // (POSIX: only one token per invocation, replaced inline) so don't append.
    if replace.is_none() {
        for cell in token_storage.iter().take(token_count) {
            if slot >= ARGV_MAX - 1 {
                return write_err(b"xargs: argv overflow\n");
            }
            argv[slot] = cell.as_ptr();
            slot += 1;
        }
    }
    // argv[slot] stays NULL — POSIX-required terminator.

    let envp: [*const u8; 1] = [core::ptr::null()];
    let path = prefix_storage[0].as_ptr();

    let pid = libc::fork();
    if pid < 0 {
        return write_err(b"xargs: fork failed\n");
    }
    if pid == 0 {
        // SAFETY: prefix_storage[0] is NUL-terminated (zero-padded array);
        // argv ends in NULL; envp is a single NULL.
        unsafe { libc::execve(path, argv.as_ptr(), envp.as_ptr()) };
        // execve only returns on failure.
        let _ = write_all(2, b"xargs: exec failed\n");
        libc::exit(127);
    }

    let mut status: i32 = 0;
    // SAFETY: pid is a valid child PID; status is a stack i32 owned for this call.
    let w = unsafe { libc::waitpid(pid, &mut status as *mut i32, 0) };
    if w < 0 {
        return write_err(b"xargs: waitpid failed\n");
    }
    // POSIX wait status: low 7 bits = signal, byte 1 = exit code when normal.
    let exit_code = (status >> 8) & 0xff;
    let signaled = (status & 0x7f) != 0;
    !signaled && exit_code == 0
}

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

fn parse_usize(s: &[u8]) -> Option<usize> {
    if s.is_empty() {
        return None;
    }
    let mut acc: usize = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((b - b'0') as usize)?;
    }
    Some(acc)
}

fn write_err(msg: &[u8]) -> bool {
    let _ = write_all(2, msg);
    false
}

fn fail(msg: &[u8]) -> ! {
    let _ = write_all(2, msg);
    libc::exit(1)
}

fn write_all(fd: i32, buf: &[u8]) -> bool {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: buf slice is valid for buf.len() bytes.
        let n = unsafe { libc::write(fd, buf[pos..].as_ptr(), buf.len() - pos) };
        if n <= 0 {
            return false;
        }
        pos += n as usize;
    }
    true
}

/// SAFETY: caller guarantees `idx < argc` and `argv` is a valid argv pointer
/// supplied by the kernel; each entry is a NUL-terminated C string.
unsafe fn cstr_at(argv: *const *const u8, idx: usize) -> &'static [u8] {
    unsafe {
        let p = *argv.add(idx);
        if p.is_null() {
            return &[];
        }
        let mut len = 0usize;
        while *p.add(len) != 0 {
            len += 1;
            if len > 4096 {
                break;
            }
        }
        core::slice::from_raw_parts(p, len)
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    let _ = write_all(2, b"xargs: panic\n");
    libc::exit(1)
}
