// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/tr` — translate or delete characters.
//!
//! Usage:
//!   tr SET1 SET2     # translate each byte in SET1 to the corresponding byte in SET2
//!   tr -d SET1       # delete each byte in SET1
//!   tr -s SET1       # squeeze repeated occurrences of bytes in SET1
//!   tr -d -s SET1 SET2  # delete + squeeze (POSIX combination)
//!
//! Set syntax (subset):
//!   * Literal bytes
//!   * Backslash escapes: \\ \\n \\t \\r \\0
//!   * Ranges: a-z, A-Z, 0-9
//!   * POSIX character classes: [:upper:], [:lower:], [:digit:], [:alpha:], [:space:]
//!
//! When SET2 is shorter than SET1 (translation mode), SET2 is padded
//! by repeating its last byte. POSIX behaviour.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/tr.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym tr_main,
    );
}

extern "C" fn tr_main(argc: usize, argv: *const *const u8) -> ! {
    let mut delete = false;
    let mut squeeze = false;
    let mut idx = 1usize;

    // Parse `-d`, `-s` flags (any combination, can be in either order).
    while idx < argc {
        // SAFETY: idx < argc.
        let arg = unsafe { cstr_at(argv, idx) };
        if arg == b"-d" {
            delete = true;
            idx += 1;
            continue;
        }
        if arg == b"-s" {
            squeeze = true;
            idx += 1;
            continue;
        }
        if arg == b"-ds" || arg == b"-sd" {
            delete = true;
            squeeze = true;
            idx += 1;
            continue;
        }
        if arg == b"--" {
            idx += 1;
            break;
        }
        if !arg.is_empty() && arg[0] == b'-' {
            write_err(b"tr: unknown option\n");
            libc::exit(1);
        }
        break;
    }

    // Expand SET1.
    let mut set1 = [0u8; 256];
    let mut set1_len = 0usize;
    if idx >= argc {
        write_err(b"tr: missing operand\n");
        libc::exit(1);
    }
    // SAFETY: idx < argc.
    let s1_bytes = unsafe { cstr_at(argv, idx) };
    if !expand_set(s1_bytes, &mut set1, &mut set1_len) {
        write_err(b"tr: invalid SET1\n");
        libc::exit(1);
    }
    idx += 1;

    // Optional SET2 (only used in translation mode, not -d alone).
    let mut set2 = [0u8; 256];
    let mut set2_len = 0usize;
    let translating = !delete;
    if translating {
        if idx >= argc {
            write_err(b"tr: missing SET2\n");
            libc::exit(1);
        }
        // SAFETY: idx < argc.
        let s2_bytes = unsafe { cstr_at(argv, idx) };
        if !expand_set(s2_bytes, &mut set2, &mut set2_len) {
            write_err(b"tr: invalid SET2\n");
            libc::exit(1);
        }
    }

    // Build a 256-entry translation table.
    // For translate mode: table[i] = i by default, table[set1[k]] = set2[k]
    // (or set2's last byte when SET2 is shorter than SET1).
    // For delete mode: a separate "in_set1" bitmap indicates bytes to drop.
    let mut table = [0u8; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        *slot = i as u8;
    }
    let mut in_set1 = [false; 256];
    for &b in &set1[..set1_len] {
        in_set1[b as usize] = true;
    }
    if translating && set2_len > 0 {
        let pad = set2[set2_len - 1];
        for (k, &src) in set1[..set1_len].iter().enumerate() {
            let dst = if k < set2_len { set2[k] } else { pad };
            table[src as usize] = dst;
        }
    }

    // Stream stdin → stdout, applying delete/translate/squeeze.
    let mut inbuf = [0u8; 4096];
    let mut outbuf = [0u8; 4096];
    let mut prev_out: i32 = -1;
    loop {
        // SAFETY: inbuf is owned and writable.
        let n = unsafe { libc::read(0, inbuf.as_mut_ptr(), inbuf.len()) };
        if n <= 0 {
            break;
        }
        let mut out_len = 0usize;
        for &b in &inbuf[..n as usize] {
            if delete && in_set1[b as usize] {
                continue;
            }
            let translated = if translating { table[b as usize] } else { b };
            // Squeeze: only emit if the resulting byte differs from the
            // previous emitted byte AND the resulting byte was in SET1.
            // POSIX defines `-s` as squeezing characters listed in the
            // (last) set; with translation, that's SET2 — but our
            // simpler model squeezes any byte that came from SET1.
            if squeeze {
                let in_squeeze_set = if translating {
                    // POSIX: `-s` operates on SET2 in translate mode.
                    let mut found = false;
                    for &s in &set2[..set2_len] {
                        if s == translated {
                            found = true;
                            break;
                        }
                    }
                    found
                } else {
                    in_set1[translated as usize]
                };
                if in_squeeze_set && (translated as i32) == prev_out {
                    continue;
                }
            }
            outbuf[out_len] = translated;
            out_len += 1;
            prev_out = translated as i32;
            if out_len == outbuf.len() {
                if !write_all(1, &outbuf[..out_len]) {
                    libc::exit(1);
                }
                out_len = 0;
            }
        }
        if out_len > 0 && !write_all(1, &outbuf[..out_len]) {
            libc::exit(1);
        }
    }

    libc::exit(0)
}

/// Expand a tr SET specifier into a flat byte sequence.
///
/// Returns `false` on a malformed escape, an unterminated range, or
/// when the expansion overflows `out`. Caller-supplied buffer holds
/// the expanded bytes; `out_len` is updated to the count.
fn expand_set(spec: &[u8], out: &mut [u8], out_len: &mut usize) -> bool {
    let mut i = 0usize;
    let mut len = 0usize;
    while i < spec.len() {
        let b = spec[i];
        // POSIX class: `[:name:]`
        if b == b'['
            && i + 1 < spec.len()
            && spec[i + 1] == b':'
            && let Some(end) = find_class_end(&spec[i + 2..])
        {
            let class = &spec[i + 2..i + 2 + end];
            i += 2 + end + 2; // skip past `:]`
            if !append_class(class, out, &mut len) {
                return false;
            }
            continue;
        }
        // Escape: `\X`
        if b == b'\\' && i + 1 < spec.len() {
            let escaped = match spec[i + 1] {
                b'\\' => b'\\',
                b'n' => b'\n',
                b't' => b'\t',
                b'r' => b'\r',
                b'0' => 0,
                c => c,
            };
            if len >= out.len() {
                return false;
            }
            out[len] = escaped;
            len += 1;
            i += 2;
            continue;
        }
        // Range: `A-Z`
        if i + 2 < spec.len() && spec[i + 1] == b'-' && spec[i + 2] != b']' {
            let start = b;
            let end = spec[i + 2];
            if start > end {
                return false;
            }
            for c in start..=end {
                if len >= out.len() {
                    return false;
                }
                out[len] = c;
                len += 1;
            }
            i += 3;
            continue;
        }
        // Plain byte.
        if len >= out.len() {
            return false;
        }
        out[len] = b;
        len += 1;
        i += 1;
    }
    *out_len = len;
    true
}

fn find_class_end(rest: &[u8]) -> Option<usize> {
    // Look for `:]` and return the index of the `:` (i.e. end of name).
    for i in 0..rest.len().saturating_sub(1) {
        if rest[i] == b':' && rest[i + 1] == b']' {
            return Some(i);
        }
    }
    None
}

fn append_class(class: &[u8], out: &mut [u8], len: &mut usize) -> bool {
    let push = |c: u8, out: &mut [u8], len: &mut usize| -> bool {
        if *len >= out.len() {
            return false;
        }
        out[*len] = c;
        *len += 1;
        true
    };
    match class {
        b"upper" => {
            for c in b'A'..=b'Z' {
                if !push(c, out, len) {
                    return false;
                }
            }
        }
        b"lower" => {
            for c in b'a'..=b'z' {
                if !push(c, out, len) {
                    return false;
                }
            }
        }
        b"digit" => {
            for c in b'0'..=b'9' {
                if !push(c, out, len) {
                    return false;
                }
            }
        }
        b"alpha" => {
            for c in b'A'..=b'Z' {
                if !push(c, out, len) {
                    return false;
                }
            }
            for c in b'a'..=b'z' {
                if !push(c, out, len) {
                    return false;
                }
            }
        }
        b"space" => {
            for &c in b" \t\n\r" {
                if !push(c, out, len) {
                    return false;
                }
            }
        }
        b"alnum" => {
            for c in b'0'..=b'9' {
                if !push(c, out, len) {
                    return false;
                }
            }
            for c in b'A'..=b'Z' {
                if !push(c, out, len) {
                    return false;
                }
            }
            for c in b'a'..=b'z' {
                if !push(c, out, len) {
                    return false;
                }
            }
        }
        _ => return false,
    }
    true
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

fn write_err(msg: &[u8]) {
    let _ = write_all(2, msg);
}

/// SAFETY: caller guarantees `idx < argc` and `argv` is a valid argv pointer.
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
    write_err(b"tr: panic\n");
    libc::exit(1)
}
