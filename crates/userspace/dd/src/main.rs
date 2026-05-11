// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/dd` — POSIX.1-2024 `dd` utility (subset).
//!
//! Convert and copy a file with block-based I/O. Operands are
//! `KEY=VALUE` pairs (no leading `-`).
//!
//! Supported operands:
//!   * `if=FILE` — input file (default stdin).
//!   * `of=FILE` — output file (default stdout).
//!   * `bs=N` — both ibs and obs (default 512). Accepts `K`/`M`
//!     suffix (×1024 / ×1048576).
//!   * `ibs=N` — input block size (default `bs` or 512).
//!   * `obs=N` — output block size (default `bs` or 512).
//!   * `count=N` — copy at most N input blocks.
//!   * `skip=N` — skip N ibs-sized blocks of input before copying.
//!   * `seek=N` — seek N obs-sized blocks into output before writing.
//!     ONCRIX has no `lseek` syscall yet, so this prints a stderr
//!     warning and is otherwise ignored.
//!   * `conv=FLAGS` — comma-separated conversion flags:
//!     `ucase`, `lcase`, `noerror`, `notrunc`, `sync`.
//!   * `status=LEVEL` — `none` / `noxfer` / `progress`. Default is the full
//!     `records in/records out/bytes copied` summary.
//!
//! Block sizes are capped at 65536 bytes; over-large values emit a stderr
//! warning and clamp to the cap.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/dd.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// `_start` is naked so the Rust prologue cannot move RSP before we read
/// the argc/argv slot the kernel placed at the initial stack top.
#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym dd_main,
    );
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Maximum allowed block size. dd traditionally caps high to avoid
/// runaway allocations; we use a stack buffer of this size for both
/// the input and output paths.
const BLOCK_CAP: usize = 65536;

/// Default `bs` when no value is given.
const DEFAULT_BS: usize = 512;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// `conv=` flag bitset.
#[derive(Clone, Copy, Default)]
struct ConvFlags {
    ucase: bool,
    lcase: bool,
    noerror: bool,
    notrunc: bool,
    sync: bool,
}

/// `status=` summary verbosity.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StatusLevel {
    /// Full summary: records in, records out, bytes copied.
    Default,
    /// Suppress everything.
    None,
    /// Suppress bytes-copied transfer-rate line; keep records lines.
    Noxfer,
    /// Same as Default for now (no periodic line — ONCRIX has no SIGUSR1).
    Progress,
}

/// Parsed dd configuration.
struct Config {
    if_path: Option<*const u8>,
    of_path: Option<*const u8>,
    ibs: usize,
    obs: usize,
    count: Option<u64>,
    skip: u64,
    seek: u64,
    conv: ConvFlags,
    status: StatusLevel,
}

impl Config {
    /// Default configuration: stdin → stdout, 512-byte blocks, no
    /// conv flags, full summary.
    const fn new() -> Self {
        Self {
            if_path: None,
            of_path: None,
            ibs: DEFAULT_BS,
            obs: DEFAULT_BS,
            count: None,
            skip: 0,
            seek: 0,
            conv: ConvFlags {
                ucase: false,
                lcase: false,
                noerror: false,
                notrunc: false,
                sync: false,
            },
            status: StatusLevel::Default,
        }
    }
}

/// Counters tracked across the copy loop. `full` blocks read or wrote
/// exactly `ibs`/`obs` bytes; `partial` blocks were short (typically the
/// final read or a short read from a pipe).
#[derive(Default)]
struct Counts {
    in_full: u64,
    in_partial: u64,
    out_full: u64,
    out_partial: u64,
    bytes_copied: u64,
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

extern "C" fn dd_main(argc: usize, argv: *const *const u8) -> ! {
    let mut cfg = Config::new();
    let mut explicit_bs = false;
    let mut explicit_ibs = false;
    let mut explicit_obs = false;

    let mut i: usize = 1;
    while i < argc {
        // SAFETY: i < argc; argv was supplied by execve with `argc` entries.
        let raw = unsafe { argv.add(i).read() };
        if raw.is_null() {
            break;
        }
        // SAFETY: argv strings are null-terminated.
        let arg = unsafe { cstr_bytes(raw) };

        if !parse_operand(
            arg,
            raw,
            &mut cfg,
            &mut explicit_bs,
            &mut explicit_ibs,
            &mut explicit_obs,
        ) {
            write_all(2, b"dd: invalid operand\n");
            libc::exit(1);
        }
        i += 1;
    }

    // bs= sets ibs and obs unless overridden by a later ibs=/obs=.
    let _ = (explicit_bs, explicit_ibs, explicit_obs);

    // Clamp block sizes.
    if cfg.ibs == 0 || cfg.obs == 0 {
        write_all(2, b"dd: block size must be > 0\n");
        libc::exit(1);
    }
    if cfg.ibs > BLOCK_CAP {
        write_all(2, b"dd: ibs too large, clamping to 65536\n");
        cfg.ibs = BLOCK_CAP;
    }
    if cfg.obs > BLOCK_CAP {
        write_all(2, b"dd: obs too large, clamping to 65536\n");
        cfg.obs = BLOCK_CAP;
    }

    if cfg.conv.ucase && cfg.conv.lcase {
        write_all(2, b"dd: conv=ucase and conv=lcase are mutually exclusive\n");
        libc::exit(1);
    }

    // Resolve input fd.
    let in_fd: i32 = match cfg.if_path {
        None => 0,
        Some(p) => {
            // SAFETY: p comes from argv, which is null-terminated.
            let r = unsafe { libc::open(p, libc::O_RDONLY, 0) };
            if r < 0 {
                write_all(2, b"dd: cannot open input\n");
                libc::exit(1);
            }
            r as i32
        }
    };

    // Resolve output fd. O_TRUNC unless conv=notrunc.
    let out_fd: i32 = match cfg.of_path {
        None => 1,
        Some(p) => {
            let mut flags = libc::O_WRONLY | libc::O_CREAT;
            if !cfg.conv.notrunc {
                flags |= libc::O_TRUNC;
            }
            // SAFETY: p is null-terminated argv pointer.
            let r = unsafe { libc::open(p, flags, 0o644) };
            if r < 0 {
                if in_fd != 0 {
                    let _ = libc::close(in_fd);
                }
                write_all(2, b"dd: cannot open output\n");
                libc::exit(1);
            }
            r as i32
        }
    };

    // skip=N: discard N ibs-sized blocks from input (no lseek dependency).
    if cfg.skip > 0 && !skip_input(in_fd, cfg.ibs, cfg.skip) {
        write_all(2, b"dd: short read on skip\n");
        // POSIX dd warns but proceeds; we do likewise.
    }

    // seek=N: ONCRIX libc does not currently expose lseek. Warn and proceed.
    if cfg.seek > 0 {
        write_all(2, b"dd: seek= not supported (no lseek); ignoring\n");
    }

    let mut counts = Counts::default();
    let exit_code = copy_loop(in_fd, out_fd, &cfg, &mut counts);

    if in_fd > 0 {
        let _ = libc::close(in_fd);
    }
    if out_fd > 1 {
        let _ = libc::close(out_fd);
    }

    if cfg.status != StatusLevel::None {
        emit_summary(&counts, cfg.status);
    }

    libc::exit(exit_code)
}

// ---------------------------------------------------------------------------
// Operand parsing
// ---------------------------------------------------------------------------

/// Parse one `KEY=VALUE` operand and update `cfg`.
/// Returns `false` on a malformed or unknown operand.
fn parse_operand(
    arg: &[u8],
    raw: *const u8,
    cfg: &mut Config,
    explicit_bs: &mut bool,
    explicit_ibs: &mut bool,
    explicit_obs: &mut bool,
) -> bool {
    let eq = match find_byte(arg, b'=') {
        Some(p) => p,
        None => return false,
    };
    let key = &arg[..eq];
    let val = &arg[eq + 1..];
    // SAFETY: `raw + eq + 1` lies inside the same null-terminated string;
    // either points at a value byte or at the terminator if val is empty.
    let val_cstr = unsafe { raw.add(eq + 1) };

    match key {
        b"if" => {
            if val.is_empty() {
                return false;
            }
            cfg.if_path = Some(val_cstr);
        }
        b"of" => {
            if val.is_empty() {
                return false;
            }
            cfg.of_path = Some(val_cstr);
        }
        b"bs" => {
            let n = match parse_size(val) {
                Some(v) => v,
                None => return false,
            };
            cfg.ibs = n;
            cfg.obs = n;
            *explicit_bs = true;
        }
        b"ibs" => {
            let n = match parse_size(val) {
                Some(v) => v,
                None => return false,
            };
            cfg.ibs = n;
            *explicit_ibs = true;
        }
        b"obs" => {
            let n = match parse_size(val) {
                Some(v) => v,
                None => return false,
            };
            cfg.obs = n;
            *explicit_obs = true;
        }
        b"count" => {
            cfg.count = Some(match parse_u64(val) {
                Some(v) => v,
                None => return false,
            });
        }
        b"skip" => {
            cfg.skip = match parse_u64(val) {
                Some(v) => v,
                None => return false,
            };
        }
        b"seek" => {
            cfg.seek = match parse_u64(val) {
                Some(v) => v,
                None => return false,
            };
        }
        b"conv" => {
            if !parse_conv(val, &mut cfg.conv) {
                return false;
            }
        }
        b"status" => {
            cfg.status = match val {
                b"none" => StatusLevel::None,
                b"noxfer" => StatusLevel::Noxfer,
                b"progress" => StatusLevel::Progress,
                _ => return false,
            };
        }
        _ => return false,
    }
    true
}

/// Parse a comma-separated `conv=` value into `out`.
fn parse_conv(val: &[u8], out: &mut ConvFlags) -> bool {
    let mut start = 0usize;
    let mut idx = 0usize;
    while idx <= val.len() {
        let at_end = idx == val.len();
        if at_end || val[idx] == b',' {
            let tok = &val[start..idx];
            if !tok.is_empty() && !apply_conv_token(tok, out) {
                return false;
            }
            start = idx + 1;
        }
        idx += 1;
    }
    true
}

fn apply_conv_token(tok: &[u8], out: &mut ConvFlags) -> bool {
    match tok {
        b"ucase" => out.ucase = true,
        b"lcase" => out.lcase = true,
        b"noerror" => out.noerror = true,
        b"notrunc" => out.notrunc = true,
        b"sync" => out.sync = true,
        _ => return false,
    }
    true
}

/// Parse `bs=`/`ibs=`/`obs=` value: digits with optional `K`/`M` suffix.
fn parse_size(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    let last = *bytes.last()?;
    let (digits, mult): (&[u8], u64) = match last {
        b'K' | b'k' => (&bytes[..bytes.len() - 1], 1024),
        b'M' | b'm' => (&bytes[..bytes.len() - 1], 1024 * 1024),
        _ => (bytes, 1),
    };
    let v = parse_u64(digits)?;
    let scaled = v.checked_mul(mult)?;
    if scaled > usize::MAX as u64 {
        return None;
    }
    Some(scaled as usize)
}

fn parse_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut acc: u64 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(acc)
}

// ---------------------------------------------------------------------------
// Copy loop
// ---------------------------------------------------------------------------

/// Discard `nblocks` × `ibs` bytes from `fd`. Returns `true` if all bytes
/// were read; `false` on early EOF (POSIX dd reports but does not abort).
fn skip_input(fd: i32, ibs: usize, nblocks: u64) -> bool {
    let mut buf = [0u8; BLOCK_CAP];
    let chunk = ibs.min(BLOCK_CAP);
    let mut remaining: u64 = nblocks.saturating_mul(ibs as u64);
    while remaining > 0 {
        let want = remaining.min(chunk as u64) as usize;
        // SAFETY: buf is owned writable storage of BLOCK_CAP bytes.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr(), want) };
        if n <= 0 {
            return false;
        }
        remaining -= n as u64;
    }
    true
}

/// Drive the read/convert/write loop. Returns the process exit code.
fn copy_loop(in_fd: i32, out_fd: i32, cfg: &Config, counts: &mut Counts) -> i32 {
    let mut in_buf = [0u8; BLOCK_CAP];
    // `out_buf` accumulates converted bytes until we have a full `obs`
    // block to flush. Worst case it holds (obs - 1) leftover bytes plus
    // a fresh ibs block, both <= BLOCK_CAP.
    let mut out_buf = [0u8; BLOCK_CAP * 2];
    let mut out_len: usize = 0;
    let mut exit_code: i32 = 0;

    let mut blocks_read: u64 = 0;
    loop {
        if let Some(limit) = cfg.count {
            if blocks_read >= limit {
                break;
            }
        }

        // SAFETY: in_buf is owned writable storage of BLOCK_CAP bytes.
        let n = unsafe { libc::read(in_fd, in_buf.as_mut_ptr(), cfg.ibs) };
        if n == 0 {
            break;
        }
        if n < 0 {
            write_all(2, b"dd: read error\n");
            if cfg.conv.noerror {
                // POSIX: with noerror, dd continues with the next block.
                // We have no lseek, so the safest thing is to treat the
                // read as if it returned 0 bytes for this iteration and
                // continue.
                blocks_read += 1;
                continue;
            }
            exit_code = 1;
            break;
        }

        let got = n as usize;
        if got == cfg.ibs {
            counts.in_full += 1;
        } else {
            counts.in_partial += 1;
        }

        // Optionally NUL-pad short reads to a full ibs (conv=sync).
        let block_end = if cfg.conv.sync && got < cfg.ibs {
            for slot in &mut in_buf[got..cfg.ibs] {
                *slot = 0;
            }
            cfg.ibs
        } else {
            got
        };

        // Apply case conversion in place.
        if cfg.conv.ucase {
            for b in &mut in_buf[..block_end] {
                if b.is_ascii_lowercase() {
                    *b -= 32;
                }
            }
        } else if cfg.conv.lcase {
            for b in &mut in_buf[..block_end] {
                if b.is_ascii_uppercase() {
                    *b += 32;
                }
            }
        }

        // Append converted bytes to out_buf, flushing full obs-sized
        // chunks to the output as they accumulate.
        if out_len + block_end > out_buf.len() {
            // Should not happen given BLOCK_CAP * 2 sizing and the
            // BLOCK_CAP clamp on ibs/obs, but guard anyway.
            write_all(2, b"dd: internal buffer overflow\n");
            exit_code = 1;
            break;
        }
        out_buf[out_len..out_len + block_end].copy_from_slice(&in_buf[..block_end]);
        out_len += block_end;

        while out_len >= cfg.obs {
            if !write_all_checked(out_fd, &out_buf[..cfg.obs]) {
                write_all(2, b"dd: write error\n");
                exit_code = 1;
                return exit_code;
            }
            counts.out_full += 1;
            counts.bytes_copied += cfg.obs as u64;
            out_buf.copy_within(cfg.obs..out_len, 0);
            out_len -= cfg.obs;
        }

        blocks_read += 1;
    }

    // Flush any trailing partial block.
    if out_len > 0 {
        if !write_all_checked(out_fd, &out_buf[..out_len]) {
            write_all(2, b"dd: write error\n");
            exit_code = 1;
        } else {
            counts.out_partial += 1;
            counts.bytes_copied += out_len as u64;
        }
    }

    exit_code
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

/// Emit the standard dd end-of-run summary to stderr.
///
/// Format:
///   `IN_FULL+IN_PARTIAL records in\n`
///   `OUT_FULL+OUT_PARTIAL records out\n`
///   `BYTES bytes copied\n`   (omitted for `status=noxfer`)
fn emit_summary(c: &Counts, level: StatusLevel) {
    let mut buf = [0u8; 96];

    let mut n = fmt_u64(&mut buf, c.in_full);
    buf[n] = b'+';
    n += 1;
    n += fmt_u64_at(&mut buf, n, c.in_partial);
    let tail = b" records in\n";
    if n + tail.len() <= buf.len() {
        buf[n..n + tail.len()].copy_from_slice(tail);
        n += tail.len();
    }
    write_all(2, &buf[..n]);

    let mut n = fmt_u64(&mut buf, c.out_full);
    buf[n] = b'+';
    n += 1;
    n += fmt_u64_at(&mut buf, n, c.out_partial);
    let tail = b" records out\n";
    if n + tail.len() <= buf.len() {
        buf[n..n + tail.len()].copy_from_slice(tail);
        n += tail.len();
    }
    write_all(2, &buf[..n]);

    if level != StatusLevel::Noxfer {
        let mut n = fmt_u64(&mut buf, c.bytes_copied);
        let tail = b" bytes copied\n";
        if n + tail.len() <= buf.len() {
            buf[n..n + tail.len()].copy_from_slice(tail);
            n += tail.len();
        }
        write_all(2, &buf[..n]);
    }
}

/// Write decimal representation of `v` to `buf[0..]`, returning the
/// number of bytes written.
fn fmt_u64(buf: &mut [u8], v: u64) -> usize {
    fmt_u64_at(buf, 0, v)
}

/// Write decimal representation of `v` to `buf[start..]`, returning the
/// number of bytes written.
fn fmt_u64_at(buf: &mut [u8], start: usize, v: u64) -> usize {
    if v == 0 {
        if start < buf.len() {
            buf[start] = b'0';
            return 1;
        }
        return 0;
    }
    let mut tmp = [0u8; 20];
    let mut n = v;
    let mut i = 0usize;
    while n > 0 {
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    let mut written = 0usize;
    while i > 0 {
        i -= 1;
        if start + written >= buf.len() {
            break;
        }
        buf[start + written] = tmp[i];
        written += 1;
    }
    written
}

// ---------------------------------------------------------------------------
// I/O helpers
// ---------------------------------------------------------------------------

/// Write the entire slice or stop on error. Used for diagnostics where
/// we don't distinguish partial writes.
fn write_all(fd: i32, buf: &[u8]) {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: buf slice is valid for buf.len() bytes.
        let n = unsafe { libc::write(fd, buf[pos..].as_ptr(), buf.len() - pos) };
        if n <= 0 {
            return;
        }
        pos += n as usize;
    }
}

/// Write the entire slice; return `false` if any write returned `<= 0`.
fn write_all_checked(fd: i32, buf: &[u8]) -> bool {
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

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------

/// Build a byte slice view of a null-terminated argv string.
///
/// # Safety
///
/// `p` must point to a null-terminated byte sequence.
unsafe fn cstr_bytes(p: *const u8) -> &'static [u8] {
    let mut len = 0usize;
    // SAFETY: caller guarantees `p` is null-terminated. The 8 KiB cap is a
    // belt-and-braces guard against a corrupted argv.
    while unsafe { p.add(len).read() } != 0 {
        len += 1;
        if len > 8192 {
            break;
        }
    }
    // SAFETY: `p` is valid for `len` bytes by construction.
    unsafe { core::slice::from_raw_parts(p, len) }
}

fn find_byte(haystack: &[u8], needle: u8) -> Option<usize> {
    for (i, &b) in haystack.iter().enumerate() {
        if b == needle {
            return Some(i);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(2, b"dd: panic\n");
    libc::exit(1)
}
