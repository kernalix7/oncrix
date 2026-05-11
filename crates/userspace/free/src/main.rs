// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/free` — display amount of free and used memory.
//!
//! Reads `/proc/meminfo` and prints a procps-style three-column table:
//!
//! ```text
//!               total        used        free      shared  buff/cache   available
//! Mem:        TOTAL       USED        FREE              0           0   AVAIL
//! Swap:           0           0           0
//! ```
//!
//! Unit flags (mutually exclusive — last one wins):
//! - `-b` — bytes
//! - `-k` — kibibytes (default)
//! - `-m` — mebibytes
//! - `-g` — gibibytes
//! - `-h` / `--human` — auto-scale each cell (KiB → MiB → GiB, 1 decimal)
//!
//! Other:
//! - `-s SEC` — repeat every `SEC` seconds; the table is reprinted with a
//!   blank line separator. `SEC` must be a positive integer; fractional
//!   seconds are not supported.
//! - `--help` — print usage and exit 0.
//!
//! Parsing notes:
//! - `/proc/meminfo` lines look like `MemTotal: 131072 kB`. The third
//!   token (`kB`) is ignored — values are always interpreted as KiB,
//!   matching Linux's procfs convention.
//! - ONCRIX's procfs currently emits only `MemTotal` and `MemFree`
//!   (see `crates/vfs/src/procfs.rs`, `ProcGenerator::MemInfo`). Any
//!   missing field defaults to `0`, and `used` falls back to
//!   `total - free` when `Buffers`/`Cached`/`Shmem` are absent.
//!
//! `free` is not POSIX-standardised; this implementation follows procps
//! semantics so existing scripts behave predictably.

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
        main = sym free_main,
    );
}

extern "C" fn free_main(argc: usize, argv: *const *const u8) -> ! {
    let mut unit = Unit::Kib;
    let mut human = false;
    let mut interval: u64 = 0;

    let mut i: usize = 1;
    while i < argc {
        // SAFETY: kernel passes a NUL-terminated argv array of length `argc`.
        let arg = unsafe { c_str(*argv.add(i)) };
        match arg {
            b"-b" => unit = Unit::B,
            b"-k" => unit = Unit::Kib,
            b"-m" => unit = Unit::Mib,
            b"-g" => unit = Unit::Gib,
            b"-h" | b"--human" => human = true,
            b"-s" => {
                i += 1;
                if i >= argc {
                    write_err(b"free: -s requires a positive integer argument\n");
                    libc::exit(2);
                }
                // SAFETY: same NUL-terminated argv guarantee.
                let sarg = unsafe { c_str(*argv.add(i)) };
                match parse_pos_u64(sarg) {
                    Some(v) if v > 0 => interval = v,
                    _ => {
                        write_err(b"free: -s requires a positive integer argument\n");
                        libc::exit(2);
                    }
                }
            }
            b"--help" => {
                write_err(b"usage: free [-b|-k|-m|-g] [-h] [-s SEC]\n");
                libc::exit(0);
            }
            _ => {
                write_err(b"free: unknown option\n");
                libc::exit(2);
            }
        }
        i += 1;
    }

    let mode = if human { DisplayMode::Human } else { DisplayMode::Fixed(unit) };

    loop {
        let mi = read_meminfo();
        emit_report(&mi, mode);

        if interval == 0 {
            break;
        }
        // Blank line separator between repeated reports (procps style).
        write_out(b"\n");
        sleep_seconds(interval);
    }

    libc::exit(0)
}

// ----- /proc/meminfo -------------------------------------------------------

/// Parsed subset of `/proc/meminfo`. All values are in **kibibytes**.
#[derive(Clone, Copy, Default)]
struct MemInfo {
    total: u64,
    free: u64,
    available: u64,
    buffers: u64,
    cached: u64,
    sreclaimable: u64,
    shmem: u64,
    swap_total: u64,
    swap_free: u64,
    /// True if any field beyond `total`/`free` was seen — used to decide
    /// whether `used = total - free - buff/cache - shared` is meaningful.
    rich: bool,
}

/// Open `/proc/meminfo`, read up to 4 KiB, parse known keys.
///
/// On any failure all fields default to `0`; `free` should still print a
/// usable (zero-filled) table rather than abort.
fn read_meminfo() -> MemInfo {
    const PATH: &[u8] = b"/proc/meminfo\0";
    let mut mi = MemInfo::default();

    // SAFETY: PATH is a NUL-terminated byte string.
    let fd = unsafe { libc::open(PATH.as_ptr(), libc::O_RDONLY, 0) };
    if fd < 0 {
        return mi;
    }
    let fd = fd as i32;

    let mut buf = [0u8; 4096];
    // SAFETY: `buf` is valid for `buf.len()` writes.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr(), buf.len()) };
    libc::close(fd);
    if n <= 0 {
        return mi;
    }

    for line in buf[..n as usize].split(|&b| b == b'\n') {
        parse_line(line, &mut mi);
    }
    mi
}

/// Parse one `/proc/meminfo` line of the form `Key: <num> [unit]`.
///
/// Unknown keys are silently ignored. The optional unit suffix (`kB`)
/// is discarded — Linux always emits kibibytes for these fields.
fn parse_line(line: &[u8], mi: &mut MemInfo) {
    let colon = match line.iter().position(|&b| b == b':') {
        Some(p) => p,
        None => return,
    };
    let key = &line[..colon];
    let rest = &line[colon + 1..];

    // Find the first numeric token after the colon.
    let mut j = 0;
    while j < rest.len() && (rest[j] == b' ' || rest[j] == b'\t') {
        j += 1;
    }
    let start = j;
    while j < rest.len() && rest[j].is_ascii_digit() {
        j += 1;
    }
    if start == j {
        return;
    }
    let mut val: u64 = 0;
    for &b in &rest[start..j] {
        val = val.saturating_mul(10).saturating_add((b - b'0') as u64);
    }

    match key {
        b"MemTotal" => mi.total = val,
        b"MemFree" => mi.free = val,
        b"MemAvailable" => {
            mi.available = val;
            mi.rich = true;
        }
        b"Buffers" => {
            mi.buffers = val;
            mi.rich = true;
        }
        b"Cached" => {
            mi.cached = val;
            mi.rich = true;
        }
        b"SReclaimable" => {
            mi.sreclaimable = val;
            mi.rich = true;
        }
        b"Shmem" => {
            mi.shmem = val;
            mi.rich = true;
        }
        b"SwapTotal" => {
            mi.swap_total = val;
            mi.rich = true;
        }
        b"SwapFree" => {
            mi.swap_free = val;
            mi.rich = true;
        }
        _ => {}
    }
}

// ----- report --------------------------------------------------------------

/// How each numeric cell is rendered.
#[derive(Clone, Copy)]
enum DisplayMode {
    /// All cells in a single fixed unit.
    Fixed(Unit),
    /// Auto-scaled per cell with one decimal place.
    Human,
}

#[derive(Clone, Copy)]
enum Unit {
    /// Bytes — multiply KiB by 1024.
    B,
    /// Kibibytes — values as stored.
    Kib,
    /// Mebibytes — divide KiB by 1024.
    Mib,
    /// Gibibytes — divide KiB by 1024 * 1024.
    Gib,
}

const COL_WIDTH: usize = 12;

fn emit_report(mi: &MemInfo, mode: DisplayMode) {
    // procps derives buff/cache as Buffers + Cached + SReclaimable.
    let buff_cache = mi.buffers.saturating_add(mi.cached).saturating_add(mi.sreclaimable);
    let shared = mi.shmem;

    // `used = total - free - buff/cache - shared` when the rich fields are
    // present; otherwise fall back to `total - free`. Saturating subtract
    // keeps the math harmless when /proc/meminfo is inconsistent.
    let used = if mi.rich && (buff_cache > 0 || shared > 0 || mi.available > 0) {
        mi.total
            .saturating_sub(mi.free)
            .saturating_sub(buff_cache)
            .saturating_sub(shared)
    } else {
        mi.total.saturating_sub(mi.free)
    };
    let available = if mi.available > 0 { mi.available } else { mi.free };

    let swap_used = mi.swap_total.saturating_sub(mi.swap_free);

    let mut out = OutBuf::new();

    // Header — left-pad so it lines up with the data rows.
    out.push_slice(b"              total        used        free      shared  buff/cache   available\n");

    out.push_slice(b"Mem:   ");
    push_cell(&mut out, mi.total, mode);
    push_cell(&mut out, used, mode);
    push_cell(&mut out, mi.free, mode);
    push_cell(&mut out, shared, mode);
    push_cell(&mut out, buff_cache, mode);
    push_cell(&mut out, available, mode);
    out.push(b'\n');

    out.push_slice(b"Swap:  ");
    push_cell(&mut out, mi.swap_total, mode);
    push_cell(&mut out, swap_used, mode);
    push_cell(&mut out, mi.swap_free, mode);
    out.push(b'\n');

    out.flush(1);
}

/// Render one numeric cell right-aligned in [`COL_WIDTH`] characters.
fn push_cell(out: &mut OutBuf, kib: u64, mode: DisplayMode) {
    let mut tmp = [0u8; 32];
    let n = format_cell(kib, mode, &mut tmp);
    let pad = COL_WIDTH.saturating_sub(n);
    for _ in 0..pad {
        out.push(b' ');
    }
    out.push_slice(&tmp[..n]);
}

/// Format `kib` according to `mode` into `out`, returning the byte length.
fn format_cell(kib: u64, mode: DisplayMode, out: &mut [u8]) -> usize {
    match mode {
        DisplayMode::Fixed(Unit::B) => write_u64(kib.saturating_mul(1024), out),
        DisplayMode::Fixed(Unit::Kib) => write_u64(kib, out),
        DisplayMode::Fixed(Unit::Mib) => write_u64(kib / 1024, out),
        DisplayMode::Fixed(Unit::Gib) => write_u64(kib / (1024 * 1024), out),
        DisplayMode::Human => write_human(kib, out),
    }
}

/// Auto-scale a KiB value to the largest unit that keeps the integer
/// part under 1024, formatting as `N.D<unit>` with a single decimal.
///
/// Output suffixes match procps: `B`, `K`, `M`, `G`, `T`. The value `0`
/// renders as `0B` to mirror procps' `-h` output exactly.
fn write_human(kib: u64, out: &mut [u8]) -> usize {
    if kib == 0 {
        return write_bytes(b"0B", out);
    }
    // Work in bytes so the `B` unit prints whole bytes for sub-KiB values.
    let mut value = kib.saturating_mul(1024);
    let units: &[u8] = b"BKMGT";
    let mut idx = 0;
    while value >= 1024 * 1024 && idx + 1 < units.len() {
        value /= 1024;
        idx += 1;
    }
    // `value` is now < 1024 * 1024 in the current unit's "milli" form.
    // Convert to `whole.tenth` against 1024.
    let whole = value / 1024;
    let frac_tenths = ((value % 1024) * 10) / 1024;
    let next_unit = idx + 1;

    // If `whole >= 1000`, bump to the next unit so we stay under 4 chars.
    if whole >= 1000 && next_unit < units.len() {
        let v2 = value;
        let whole2 = v2 / (1024 * 1024);
        let frac2 = ((v2 / 1024 % 1024) * 10) / 1024;
        let mut pos = 0;
        pos += write_u64(whole2, &mut out[pos..]);
        out[pos] = b'.';
        pos += 1;
        pos += write_u64(frac2, &mut out[pos..]);
        out[pos] = units[next_unit];
        pos + 1
    } else {
        let mut pos = 0;
        pos += write_u64(whole, &mut out[pos..]);
        out[pos] = b'.';
        pos += 1;
        pos += write_u64(frac_tenths, &mut out[pos..]);
        out[pos] = units[idx];
        pos + 1
    }
}

fn write_u64(mut v: u64, out: &mut [u8]) -> usize {
    if v == 0 {
        if out.is_empty() {
            return 0;
        }
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut n = 0;
    while v > 0 && n < tmp.len() {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    let len = n.min(out.len());
    for i in 0..len {
        out[i] = tmp[n - 1 - i];
    }
    len
}

fn write_bytes(src: &[u8], dst: &mut [u8]) -> usize {
    let n = src.len().min(dst.len());
    dst[..n].copy_from_slice(&src[..n]);
    n
}

// ----- parsing helpers -----------------------------------------------------

/// Parse a non-empty ASCII-decimal byte slice into `u64`. Returns `None`
/// on empty input, non-digit characters, or overflow.
fn parse_pos_u64(s: &[u8]) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut acc: u64 = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(acc)
}

// ----- sleep ---------------------------------------------------------------

/// Block for `secs` seconds via `nanosleep(2)`. Best-effort: an error
/// return from the kernel is ignored — `free -s` should keep polling.
fn sleep_seconds(secs: u64) {
    let req = libc::Timespec {
        tv_sec: secs as i64,
        tv_nsec: 0,
    };
    // SAFETY: `req` is a valid local Timespec; `rem` is null which is allowed.
    unsafe {
        let _ = libc::nanosleep(&req, core::ptr::null_mut());
    }
}

// ----- output buffer -------------------------------------------------------

const BUF_CAP: usize = 256;

struct OutBuf {
    buf: [u8; BUF_CAP],
    len: usize,
}

impl OutBuf {
    fn new() -> Self {
        Self {
            buf: [0; BUF_CAP],
            len: 0,
        }
    }

    fn push(&mut self, b: u8) {
        if self.len == BUF_CAP {
            self.flush(1);
        }
        self.buf[self.len] = b;
        self.len += 1;
    }

    fn push_slice(&mut self, s: &[u8]) {
        for &b in s {
            self.push(b);
        }
    }

    fn flush(&mut self, fd: i32) {
        let mut pos = 0;
        while pos < self.len {
            // SAFETY: `buf[pos..len]` is initialised and within bounds.
            let n = unsafe { libc::write(fd, self.buf[pos..].as_ptr(), self.len - pos) };
            if n <= 0 {
                break;
            }
            pos += n as usize;
        }
        self.len = 0;
    }
}

// ----- helpers -------------------------------------------------------------

/// Read a NUL-terminated C string into a slice; returns an empty slice if
/// `p` is null.
///
/// # Safety
///
/// `p` must be either null or point to a NUL-terminated byte sequence
/// valid for reads up to and including the terminator.
unsafe fn c_str<'a>(p: *const u8) -> &'a [u8] {
    if p.is_null() {
        return &[];
    }
    let mut len = 0;
    // SAFETY: caller upholds that `p` is NUL-terminated.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` bytes from `p` are valid (we just walked them).
    unsafe { core::slice::from_raw_parts(p, len) }
}

fn write_err(msg: &[u8]) {
    write_all(2, msg);
}

fn write_out(msg: &[u8]) {
    write_all(1, msg);
}

fn write_all(fd: i32, msg: &[u8]) {
    let mut pos = 0;
    while pos < msg.len() {
        // SAFETY: `msg` is a valid byte slice for its length.
        let n = unsafe { libc::write(fd, msg[pos..].as_ptr(), msg.len() - pos) };
        if n <= 0 {
            break;
        }
        pos += n as usize;
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { libc::write(2, b"free: panic\n".as_ptr(), 12) };
    libc::exit(1)
}
