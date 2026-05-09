// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/date` — print the current date and time.
//!
//! With no arguments, prints the default POSIX-style format:
//!   `Day Mon DD HH:MM:SS YYYY`
//! e.g. `Wed Apr 14 12:34:56 2026`.
//!
//! With a `+FORMAT` argument, expands format directives:
//! - `%Y` 4-digit year, `%y` 2-digit year, `%m` zero-padded month
//! - `%d` zero-padded day-of-month, `%j` zero-padded day-of-year
//! - `%H` hour (00-23), `%M` minute, `%S` second
//! - `%T` -> `%H:%M:%S`, `%D` -> `%m/%d/%y`
//! - `%a` short weekday, `%A` full weekday
//! - `%b` short month, `%B` full month
//! - `%s` Unix epoch seconds, `%n` newline, `%t` tab, `%%` literal `%`
//!
//! UTC only — userspace cannot reach kernel timezone routines, and ONCRIX
//! has no timezone database yet. The broken-down time is computed inline
//! using Howard Hinnant's `civil_from_days` integer date algorithm.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/date.html`

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
        main = sym date_main,
    );
}

extern "C" fn date_main(argc: usize, argv: *const *const u8) -> ! {
    let now = current_epoch_seconds();
    let tm = break_down(now);

    let mut out = OutBuf::new();

    if argc >= 2 {
        // SAFETY: argv[1] is a NUL-terminated C string supplied by the kernel.
        let arg = unsafe { c_str(*argv.add(1)) };
        if !arg.is_empty() && arg[0] == b'+' {
            format_custom(&mut out, &arg[1..], &tm, now);
        } else if arg == b"-u" || arg == b"--utc" {
            // Already UTC; ignore.
            format_default(&mut out, &tm);
        } else {
            write_err(b"date: unsupported operand (use `+FORMAT`)\n");
            libc::exit(1);
        }
    } else {
        format_default(&mut out, &tm);
    }

    // Append newline if not already present.
    if !out.ends_with_newline() {
        out.push(b'\n');
    }
    out.flush(1);
    libc::exit(0)
}

/// Broken-down UTC time.
struct Tm {
    year: i32,
    month: u32,    // 1..=12
    day: u32,      // 1..=31
    hour: u32,     // 0..=23
    minute: u32,   // 0..=59
    second: u32,   // 0..=59
    weekday: u32,  // 0=Sun..6=Sat
    day_of_year: u32, // 1..=366
}

fn current_epoch_seconds() -> i64 {
    // SAFETY: passing null tloc — the libc wrapper ignores it.
    unsafe { libc::time(core::ptr::null_mut()) }
}

/// Break down Unix epoch seconds into a UTC `Tm`.
///
/// Uses Howard Hinnant's public-domain `civil_from_days` integer date
/// algorithm to derive (year, month, day) from days since 1970-01-01.
fn break_down(epoch: i64) -> Tm {
    // Floored division/modulo so negative epoch values (pre-1970) still
    // give a non-negative time-of-day.
    let secs_per_day: i64 = 86_400;
    let mut days = epoch.div_euclid(secs_per_day);
    let tod = epoch.rem_euclid(secs_per_day);

    let hour = (tod / 3600) as u32;
    let minute = ((tod % 3600) / 60) as u32;
    let second = (tod % 60) as u32;

    // Weekday: 1970-01-01 was a Thursday (=4 with Sun=0).
    let weekday = ((days.rem_euclid(7) + 4) % 7) as u32;

    // civil_from_days — shift epoch from 1970-01-01 to 0000-03-01 internal era.
    days += 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let doe = (days - era * 146_097) as u32; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = (y + i64::from(m <= 2)) as i32;

    // Day-of-year (1..=366) for the Gregorian calendar year.
    let day_of_year = day_of_year(year, m, d);

    Tm {
        year,
        month: m,
        day: d,
        hour,
        minute,
        second,
        weekday,
        day_of_year,
    }
}

/// Day-of-year (1..=366) for a Gregorian (year, month, day).
fn day_of_year(year: i32, month: u32, day: u32) -> u32 {
    const CUM: [u32; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let mut doy = CUM[(month - 1) as usize] + day;
    if month > 2 && is_leap(year) {
        doy += 1;
    }
    doy
}

fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

const SHORT_WD: [&[u8]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
const FULL_WD: [&[u8]; 7] = [
    b"Sunday",
    b"Monday",
    b"Tuesday",
    b"Wednesday",
    b"Thursday",
    b"Friday",
    b"Saturday",
];
const SHORT_MO: [&[u8]; 12] = [
    b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec",
];
const FULL_MO: [&[u8]; 12] = [
    b"January",
    b"February",
    b"March",
    b"April",
    b"May",
    b"June",
    b"July",
    b"August",
    b"September",
    b"October",
    b"November",
    b"December",
];

fn format_default(out: &mut OutBuf, tm: &Tm) {
    // `Wed Apr 14 12:34:56 2026`
    out.push_slice(SHORT_WD[tm.weekday as usize]);
    out.push(b' ');
    out.push_slice(SHORT_MO[(tm.month - 1) as usize]);
    out.push(b' ');
    out.push_pad2(tm.day, b' ');
    out.push(b' ');
    out.push_pad2(tm.hour, b'0');
    out.push(b':');
    out.push_pad2(tm.minute, b'0');
    out.push(b':');
    out.push_pad2(tm.second, b'0');
    out.push(b' ');
    out.push_year4(tm.year);
}

fn format_custom(out: &mut OutBuf, fmt: &[u8], tm: &Tm, epoch: i64) {
    let mut i = 0;
    while i < fmt.len() {
        let c = fmt[i];
        if c != b'%' {
            out.push(c);
            i += 1;
            continue;
        }
        i += 1;
        if i >= fmt.len() {
            // Trailing `%` — emit literally.
            out.push(b'%');
            break;
        }
        match fmt[i] {
            b'Y' => out.push_year4(tm.year),
            b'y' => {
                let y2 = tm.year.rem_euclid(100) as u32;
                out.push_pad2(y2, b'0');
            }
            b'm' => out.push_pad2(tm.month, b'0'),
            b'd' => out.push_pad2(tm.day, b'0'),
            b'H' => out.push_pad2(tm.hour, b'0'),
            b'M' => out.push_pad2(tm.minute, b'0'),
            b'S' => out.push_pad2(tm.second, b'0'),
            b'T' => {
                out.push_pad2(tm.hour, b'0');
                out.push(b':');
                out.push_pad2(tm.minute, b'0');
                out.push(b':');
                out.push_pad2(tm.second, b'0');
            }
            b'D' => {
                out.push_pad2(tm.month, b'0');
                out.push(b'/');
                out.push_pad2(tm.day, b'0');
                out.push(b'/');
                let y2 = tm.year.rem_euclid(100) as u32;
                out.push_pad2(y2, b'0');
            }
            b'j' => out.push_pad3(tm.day_of_year),
            b'a' => out.push_slice(SHORT_WD[tm.weekday as usize]),
            b'A' => out.push_slice(FULL_WD[tm.weekday as usize]),
            b'b' => out.push_slice(SHORT_MO[(tm.month - 1) as usize]),
            b'B' => out.push_slice(FULL_MO[(tm.month - 1) as usize]),
            b's' => out.push_i64(epoch),
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            b'%' => out.push(b'%'),
            other => {
                // Unknown directive — emit `%X` literally so users see what
                // they typed instead of silently dropping it.
                out.push(b'%');
                out.push(other);
            }
        }
        i += 1;
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

    /// Push a value 0..=99 padded to two characters with `pad`.
    fn push_pad2(&mut self, v: u32, pad: u8) {
        let v = v % 100;
        let tens = (v / 10) as u8;
        let ones = (v % 10) as u8;
        let first = if tens == 0 { pad } else { b'0' + tens };
        self.push(first);
        self.push(b'0' + ones);
    }

    /// Push a value 0..=999 zero-padded to three characters.
    fn push_pad3(&mut self, v: u32) {
        let v = v % 1000;
        self.push(b'0' + ((v / 100) as u8));
        self.push(b'0' + (((v / 10) % 10) as u8));
        self.push(b'0' + ((v % 10) as u8));
    }

    /// Push a 4-digit year. Years outside [0, 9999] fall back to a signed
    /// decimal representation (rare on a kernel without an RTC, but it
    /// keeps the formatter total).
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

    fn push_i64(&mut self, v: i64) {
        let mut tmp = [0u8; 20];
        let mut n;
        let neg = v < 0;
        // i64::MIN handled via unsigned magnitude.
        let mut u = if neg {
            (v as i128).unsigned_abs() as u64
        } else {
            v as u64
        };
        if u == 0 {
            self.push(b'0');
            return;
        }
        n = 0;
        while u > 0 {
            tmp[n] = b'0' + (u % 10) as u8;
            u /= 10;
            n += 1;
        }
        if neg {
            self.push(b'-');
        }
        while n > 0 {
            n -= 1;
            self.push(tmp[n]);
        }
    }

    fn ends_with_newline(&self) -> bool {
        self.len > 0 && self.buf[self.len - 1] == b'\n'
    }

    fn flush(&mut self, fd: i32) {
        let mut pos = 0;
        while pos < self.len {
            // SAFETY: buf[pos..len] is initialised and within bounds.
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
        // SAFETY: msg is a valid byte slice for its length.
        let n = unsafe { libc::write(2, msg[pos..].as_ptr(), msg.len() - pos) };
        if n <= 0 {
            break;
        }
        pos += n as usize;
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { libc::write(2, b"date: panic\n".as_ptr(), 12) };
    libc::exit(1)
}
