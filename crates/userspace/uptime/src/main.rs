// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/uptime` — print how long the system has been running.
//!
//! Default form (no arguments):
//!   `HH:MM:SS up DURATION, 1 user, load average: 0.00, 0.00, 0.00\n`
//!
//! - `HH:MM:SS` is the current wall-clock time (UTC) from `libc::time`.
//! - `DURATION` is pretty-printed from `/proc/uptime`:
//!     - `X day(s), HH:MM` when uptime ≥ 1 day,
//!     - `HH:MM`           when uptime ≥ 1 hour,
//!     - `M min`           otherwise.
//! - `1 user` is hard-coded — ONCRIX has a single sh session.
//! - The three load-average values are zero. ONCRIX does not yet expose
//!   `/proc/loadavg`; the field is kept for layout compatibility with
//!   procps so consumers that scrape the line keep parsing.
//!
//! Flags:
//! - `-p` — pretty form: `up X days, Y hours, Z minutes\n` (empty units
//!   are skipped; `up 0 minutes\n` when uptime is below one minute).
//! - `-s` — print the wall-clock time at boot as `YYYY-MM-DD HH:MM:SS\n`.
//!
//! `uptime` is not POSIX-standardised — this implementation follows
//! procps semantics. The kernel hook at `/proc/uptime` (see
//! `crates/vfs/src/procfs.rs`, `ProcKind::Uptime`) is currently a stub
//! emitting `"0\n"`, so the parser tolerates a missing fractional part
//! and a single integer token.
//!
//! Date math (used for `-s` and the wall-clock prefix) is the public-domain
//! `civil_from_days` algorithm by Howard Hinnant, reused inline from
//! `/bin/date` so this binary stays self-contained.

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
        main = sym uptime_main,
    );
}

extern "C" fn uptime_main(argc: usize, argv: *const *const u8) -> ! {
    // Parse a single optional flag. Multiple flags or unknown options
    // are rejected to keep behaviour predictable.
    let mut mode = Mode::Default;
    let mut i: usize = 1;
    while i < argc {
        // SAFETY: kernel passes a NUL-terminated argv array of length `argc`.
        let arg = unsafe { c_str(*argv.add(i)) };
        if arg == b"-p" || arg == b"--pretty" {
            mode = Mode::Pretty;
        } else if arg == b"-s" || arg == b"--since" {
            mode = Mode::Since;
        } else if arg == b"--help" {
            write_err(b"usage: uptime [-p|-s]\n");
            libc::exit(0);
        } else {
            write_err(b"uptime: unknown option\n");
            libc::exit(2);
        }
        i += 1;
    }

    let now = current_epoch_seconds();
    let up_secs = read_proc_uptime();

    let mut out = OutBuf::new();
    match mode {
        Mode::Default => emit_default(&mut out, now, up_secs),
        Mode::Pretty => emit_pretty(&mut out, up_secs),
        Mode::Since => emit_since(&mut out, now, up_secs),
    }
    out.flush(1);
    libc::exit(0)
}

/// Selected output form.
#[derive(Clone, Copy)]
enum Mode {
    /// Procps-style single-line summary.
    Default,
    /// `-p` — only the human-readable duration.
    Pretty,
    /// `-s` — wall-clock timestamp at boot.
    Since,
}

// ----- /proc/uptime --------------------------------------------------------

/// Read `/proc/uptime` and return the integer seconds-since-boot.
///
/// On any failure (open/read error, empty file, malformed token) returns
/// `0` rather than aborting — `uptime` should still print a usable line.
fn read_proc_uptime() -> u64 {
    const PATH: &[u8] = b"/proc/uptime\0";
    // SAFETY: PATH is a NUL-terminated byte string.
    let fd = unsafe { libc::open(PATH.as_ptr(), libc::O_RDONLY, 0) };
    if fd < 0 {
        return 0;
    }
    let fd = fd as i32;

    let mut buf = [0u8; 64];
    // SAFETY: `buf` is valid for `buf.len()` writes.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr(), buf.len()) };
    libc::close(fd);
    if n <= 0 {
        return 0;
    }
    parse_uptime_secs(&buf[..n as usize])
}

/// Extract the integer prefix of the first whitespace-separated token in
/// a `/proc/uptime`-style buffer. The fractional `.NN` suffix and the
/// optional second token (idle time) are ignored.
fn parse_uptime_secs(s: &[u8]) -> u64 {
    let mut acc: u64 = 0;
    let mut seen = false;
    for &b in s {
        if b.is_ascii_digit() {
            acc = acc.saturating_mul(10).saturating_add((b - b'0') as u64);
            seen = true;
        } else {
            // Any non-digit (`.`, ` `, `\n`, …) terminates the integer part.
            if seen {
                return acc;
            }
            // Skip leading whitespace defensively; abort on garbage.
            if b == b' ' || b == b'\t' || b == b'\n' {
                continue;
            }
            return 0;
        }
    }
    acc
}

// ----- output --------------------------------------------------------------

fn emit_default(out: &mut OutBuf, now: i64, up: u64) {
    let tm = break_down(now);
    out.push_pad2(tm.hour, b'0');
    out.push(b':');
    out.push_pad2(tm.minute, b'0');
    out.push(b':');
    out.push_pad2(tm.second, b'0');
    out.push_slice(b" up ");
    push_duration_short(out, up);
    out.push_slice(b",  1 user,  load average: 0.00, 0.00, 0.00\n");
}

fn emit_pretty(out: &mut OutBuf, up: u64) {
    out.push_slice(b"up ");
    let days = up / 86_400;
    let hours = (up % 86_400) / 3_600;
    let minutes = (up % 3_600) / 60;
    let mut wrote = false;
    if days > 0 {
        out.push_u64(days);
        out.push_slice(if days == 1 { b" day" } else { b" days" });
        wrote = true;
    }
    if hours > 0 {
        if wrote {
            out.push_slice(b", ");
        }
        out.push_u64(hours);
        out.push_slice(if hours == 1 { b" hour" } else { b" hours" });
        wrote = true;
    }
    if minutes > 0 {
        if wrote {
            out.push_slice(b", ");
        }
        out.push_u64(minutes);
        out.push_slice(if minutes == 1 { b" minute" } else { b" minutes" });
        wrote = true;
    }
    if !wrote {
        // procps falls back to a literal "0 minutes" when uptime < 60s.
        out.push_slice(b"0 minutes");
    }
    out.push(b'\n');
}

fn emit_since(out: &mut OutBuf, now: i64, up: u64) {
    // Saturating subtract keeps boot time non-negative if the kernel
    // clock rolls back relative to /proc/uptime (shouldn't happen, but
    // a stub procfs returning 0 makes "since" == "now").
    let boot = now.saturating_sub(up as i64);
    let tm = break_down(boot);
    out.push_year4(tm.year);
    out.push(b'-');
    out.push_pad2(tm.month, b'0');
    out.push(b'-');
    out.push_pad2(tm.day, b'0');
    out.push(b' ');
    out.push_pad2(tm.hour, b'0');
    out.push(b':');
    out.push_pad2(tm.minute, b'0');
    out.push(b':');
    out.push_pad2(tm.second, b'0');
    out.push(b'\n');
}

/// Default-form duration field.
///
/// - `>= 1 day`  → `X day(s), HH:MM`
/// - `>= 1 hour` → `HH:MM`
/// - otherwise   → `M min`
fn push_duration_short(out: &mut OutBuf, up: u64) {
    let days = up / 86_400;
    let hours = (up % 86_400) / 3_600;
    let minutes = (up % 3_600) / 60;

    if days > 0 {
        out.push_u64(days);
        out.push_slice(if days == 1 { b" day, " } else { b" days, " });
        out.push_pad2(hours as u32, b'0');
        out.push(b':');
        out.push_pad2(minutes as u32, b'0');
    } else if hours > 0 {
        out.push_pad2(hours as u32, b'0');
        out.push(b':');
        out.push_pad2(minutes as u32, b'0');
    } else {
        out.push_u64(minutes);
        out.push_slice(b" min");
    }
}

// ----- date math (civil_from_days, mirrored from /bin/date) ---------------

struct Tm {
    year: i32,
    month: u32,  // 1..=12
    day: u32,    // 1..=31
    hour: u32,   // 0..=23
    minute: u32, // 0..=59
    second: u32, // 0..=59
}

fn current_epoch_seconds() -> i64 {
    // SAFETY: passing null tloc — the libc wrapper ignores it.
    unsafe { libc::time(core::ptr::null_mut()) }
}

/// Break down Unix epoch seconds into a UTC `Tm` using Howard Hinnant's
/// public-domain `civil_from_days` algorithm. See `/bin/date` for the
/// derivation; this is a trimmed copy that omits weekday/day-of-year.
fn break_down(epoch: i64) -> Tm {
    let secs_per_day: i64 = 86_400;
    let mut days = epoch.div_euclid(secs_per_day);
    let tod = epoch.rem_euclid(secs_per_day);

    let hour = (tod / 3600) as u32;
    let minute = ((tod % 3600) / 60) as u32;
    let second = (tod % 60) as u32;

    days += 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let doe = (days - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = (y + i64::from(m <= 2)) as i32;

    Tm {
        year,
        month: m,
        day: d,
        hour,
        minute,
        second,
    }
}

// ----- output buffer -------------------------------------------------------

const BUF_CAP: usize = 128;

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

    /// Push a value 0..=99 padded to two characters with `pad`.
    fn push_pad2(&mut self, v: u32, pad: u8) {
        let v = v % 100;
        let tens = (v / 10) as u8;
        let ones = (v % 10) as u8;
        let first = if tens == 0 { pad } else { b'0' + tens };
        self.push(first);
        self.push(b'0' + ones);
    }

    /// Push a 4-digit year (years outside [0, 9999] are rendered with
    /// the variable-width signed formatter).
    fn push_year4(&mut self, year: i32) {
        if (0..=9999).contains(&year) {
            let y = year as u32;
            self.push(b'0' + ((y / 1000) as u8));
            self.push(b'0' + (((y / 100) % 10) as u8));
            self.push(b'0' + (((y / 10) % 10) as u8));
            self.push(b'0' + ((y % 10) as u8));
        } else {
            self.push_i64(i64::from(year));
        }
    }

    fn push_u64(&mut self, mut v: u64) {
        if v == 0 {
            self.push(b'0');
            return;
        }
        let mut tmp = [0u8; 20];
        let mut n = 0;
        while v > 0 {
            tmp[n] = b'0' + (v % 10) as u8;
            v /= 10;
            n += 1;
        }
        while n > 0 {
            n -= 1;
            self.push(tmp[n]);
        }
    }

    fn push_i64(&mut self, v: i64) {
        if v < 0 {
            self.push(b'-');
            // i64::MIN handled via i128 widening.
            let u = (v as i128).unsigned_abs() as u64;
            self.push_u64(u);
        } else {
            self.push_u64(v as u64);
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
    let mut pos = 0;
    while pos < msg.len() {
        // SAFETY: `msg` is a valid byte slice for its length.
        let n = unsafe { libc::write(2, msg[pos..].as_ptr(), msg.len() - pos) };
        if n <= 0 {
            break;
        }
        pos += n as usize;
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { libc::write(2, b"uptime: panic\n".as_ptr(), 14) };
    libc::exit(1)
}
