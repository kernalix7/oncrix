// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/cal` — print a calendar for a month or year.
//!
//! Usage:
//! - `cal`              current month
//! - `cal MONTH YEAR`   specific month (1..=12) of YEAR (1..=9999)
//! - `cal YEAR`         all twelve months of YEAR, three across
//! - `-m`               Monday is the first day of the week (default Sunday)
//! - `-3`               previous, current, and next month side by side
//!
//! Output uses the conventional util-linux layout: a centred header above
//! the seven-day grid, day numbers right-aligned in two-character fields
//! separated by a single space. Trailing all-empty week rows are omitted.
//!
//! `cal` is not POSIX-standard but is ubiquitous (BSD origin); this
//! implementation follows util-linux semantics for the supported flags.
//! Date math reuses the `civil_from_days` algorithm from `/bin/date`.

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
        main = sym cal_main,
    );
}

extern "C" fn cal_main(argc: usize, argv: *const *const u8) -> ! {
    let mut monday_first = false;
    let mut three_month = false;
    let mut positional: [u32; 2] = [0; 2];
    let mut positional_count: usize = 0;

    // Parse arguments. Skip argv[0]; everything else is a flag or a number.
    let mut i: usize = 1;
    while i < argc {
        // SAFETY: kernel passes a NUL-terminated argv array of length `argc`.
        let arg = unsafe { c_str(*argv.add(i)) };
        if arg == b"-m" {
            monday_first = true;
        } else if arg == b"-3" {
            three_month = true;
        } else if arg == b"--help" {
            usage();
            libc::exit(0);
        } else if !arg.is_empty() && arg[0] == b'-' && arg.len() > 1 {
            write_err(b"cal: unknown option\n");
            libc::exit(2);
        } else {
            if positional_count >= 2 {
                write_err(b"cal: too many arguments\n");
                libc::exit(2);
            }
            match parse_u32(arg) {
                Some(v) => {
                    positional[positional_count] = v;
                    positional_count += 1;
                }
                None => {
                    write_err(b"cal: invalid number\n");
                    libc::exit(2);
                }
            }
        }
        i += 1;
    }

    let mut out = OutBuf::new();

    match positional_count {
        0 => {
            // Current month.
            let tm = current_tm();
            if three_month {
                print_three(&mut out, tm.year, tm.month, monday_first);
            } else {
                print_month(&mut out, tm.year, tm.month, monday_first);
            }
        }
        1 => {
            // `cal YEAR` — full year, three months across.
            let year = positional[0];
            if !(1..=9999).contains(&year) {
                write_err(b"cal: year out of range (1..=9999)\n");
                libc::exit(1);
            }
            print_year(&mut out, year as i32, monday_first);
        }
        2 => {
            // `cal MONTH YEAR`.
            let month = positional[0];
            let year = positional[1];
            if !(1..=12).contains(&month) {
                write_err(b"cal: month out of range (1..=12)\n");
                libc::exit(1);
            }
            if !(1..=9999).contains(&year) {
                write_err(b"cal: year out of range (1..=9999)\n");
                libc::exit(1);
            }
            if three_month {
                print_three(&mut out, year as i32, month, monday_first);
            } else {
                print_month(&mut out, year as i32, month, monday_first);
            }
        }
        _ => unreachable!(),
    }

    out.flush(1);
    libc::exit(0)
}

// ----- date math -----------------------------------------------------------

/// Broken-down UTC time produced from the kernel's epoch clock.
struct Tm {
    year: i32,
    month: u32, // 1..=12
}

fn current_tm() -> Tm {
    // SAFETY: passing null tloc — the libc wrapper ignores it.
    let now = unsafe { libc::time(core::ptr::null_mut()) };
    let secs_per_day: i64 = 86_400;
    let mut days = now.div_euclid(secs_per_day);

    // civil_from_days — see /bin/date for the derivation.
    days += 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let doe = (days - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = (y + i64::from(m <= 2)) as i32;

    Tm { year, month: m }
}

fn is_leap(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

/// Number of days in `month` (1..=12) of `year`.
fn days_in_month(year: i32, month: u32) -> u32 {
    const DIM: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut d = DIM[(month - 1) as usize];
    if month == 2 && is_leap(year) {
        d = 29;
    }
    d
}

/// Weekday (0 = Sunday .. 6 = Saturday) of (year, month, 1).
///
/// Computed via Howard Hinnant's `days_from_civil` (the inverse of the
/// `civil_from_days` algorithm in `/bin/date`) and the known anchor that
/// 1970-01-01 was a Thursday (=4 with Sun=0).
fn weekday_of_first(year: i32, month: u32) -> u32 {
    let y = i64::from(year) - i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32; // [0, 399]
    let m = month;
    let mp = if m > 2 { m - 3 } else { m + 9 }; // [0, 11]
    let doy = (153 * mp + 2) / 5; // day-of-year for day 1
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days = era * 146_097 + doe as i64 - 719_468;
    ((days.rem_euclid(7) + 4) % 7) as u32
}

// ----- rendering -----------------------------------------------------------

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

const SU_HEADER: &[u8] = b"Su Mo Tu We Th Fr Sa";
const MO_HEADER: &[u8] = b"Mo Tu We Th Fr Sa Su";

/// Width of the seven-day grid (matches header length).
const GRID_W: usize = 20;

/// Number of rendered week rows per month (always 6 — trailing empty
/// rows are stripped during emit).
const WEEK_ROWS: usize = 6;

/// One month rendered as a `(header, weekday-row, six week rows)` block.
/// All strings are exactly `GRID_W` bytes wide so multi-month layouts
/// can join them with a fixed separator.
struct MonthBlock {
    title: [u8; GRID_W],
    wd: [u8; GRID_W],
    rows: [[u8; GRID_W]; WEEK_ROWS],
    used_rows: usize,
}

fn render_month(year: i32, month: u32, monday_first: bool) -> MonthBlock {
    let mut block = MonthBlock {
        title: [b' '; GRID_W],
        wd: [b' '; GRID_W],
        rows: [[b' '; GRID_W]; WEEK_ROWS],
        used_rows: 0,
    };

    // Title — "Month YYYY", centred over GRID_W.
    let name = FULL_MO[(month - 1) as usize];
    let mut title_buf = [0u8; GRID_W];
    let mut tlen = 0;
    for &b in name {
        title_buf[tlen] = b;
        tlen += 1;
    }
    title_buf[tlen] = b' ';
    tlen += 1;
    tlen += write_u32(&mut title_buf[tlen..], year as u32);
    let pad = (GRID_W.saturating_sub(tlen)) / 2;
    block.title[pad..pad + tlen].copy_from_slice(&title_buf[..tlen]);

    // Weekday row.
    let header = if monday_first { MO_HEADER } else { SU_HEADER };
    block.wd[..header.len()].copy_from_slice(header);

    // Day grid. Column 0 starts at offset 0 ("Xx Xx ..."), so day `n` in
    // column `c` lives at offset `c * 3`, occupying two bytes.
    let first_wd_sun = weekday_of_first(year, month); // 0=Sun..6=Sat
    let first_col = if monday_first {
        // Mon=0..Sun=6
        (first_wd_sun + 6) % 7
    } else {
        first_wd_sun
    };

    let dim = days_in_month(year, month);
    let mut row: usize = 0;
    let mut col: usize = first_col as usize;
    let mut last_row: usize = 0;

    let mut day: u32 = 1;
    while day <= dim {
        let off = col * 3;
        // Right-aligned 2-char field.
        if day < 10 {
            block.rows[row][off] = b' ';
            block.rows[row][off + 1] = b'0' + day as u8;
        } else {
            block.rows[row][off] = b'0' + (day / 10) as u8;
            block.rows[row][off + 1] = b'0' + (day % 10) as u8;
        }
        last_row = row;
        col += 1;
        if col == 7 {
            col = 0;
            row += 1;
            if row == WEEK_ROWS {
                break;
            }
        }
        day += 1;
    }
    block.used_rows = last_row + 1;
    block
}

fn print_month(out: &mut OutBuf, year: i32, month: u32, monday_first: bool) {
    let block = render_month(year, month, monday_first);
    emit_block_line(out, &block.title);
    emit_block_line(out, &block.wd);
    for r in 0..block.used_rows {
        emit_block_line(out, &block.rows[r]);
    }
}

fn print_three(out: &mut OutBuf, year: i32, month: u32, monday_first: bool) {
    let (py, pm) = prev_month(year, month);
    let (ny, nm) = next_month(year, month);
    let blocks = [
        render_month(py, pm, monday_first),
        render_month(year, month, monday_first),
        render_month(ny, nm, monday_first),
    ];
    emit_blocks_row(out, &blocks);
}

fn print_year(out: &mut OutBuf, year: i32, monday_first: bool) {
    // Year header centred over the full 3-month width
    // (3 * GRID_W + 2 separators of two spaces each = 64).
    let total_w = GRID_W * 3 + 2 * 2;
    let mut buf = [0u8; 8];
    let n = write_u32(&mut buf, year as u32);
    let pad = (total_w.saturating_sub(n)) / 2;
    for _ in 0..pad {
        out.push(b' ');
    }
    for &b in &buf[..n] {
        out.push(b);
    }
    out.push(b'\n');

    // Four rows of three months each.
    for q in 0..4 {
        let m1 = (q * 3 + 1) as u32;
        let blocks = [
            render_month(year, m1, monday_first),
            render_month(year, m1 + 1, monday_first),
            render_month(year, m1 + 2, monday_first),
        ];
        if q > 0 {
            out.push(b'\n');
        }
        emit_blocks_row(out, &blocks);
    }
}

fn prev_month(year: i32, month: u32) -> (i32, u32) {
    if month == 1 {
        (year - 1, 12)
    } else {
        (year, month - 1)
    }
}

fn next_month(year: i32, month: u32) -> (i32, u32) {
    if month == 12 {
        (year + 1, 1)
    } else {
        (year, month + 1)
    }
}

/// Emit a single fixed-width grid line, trimmed of trailing spaces.
fn emit_block_line(out: &mut OutBuf, line: &[u8; GRID_W]) {
    let mut end = line.len();
    while end > 0 && line[end - 1] == b' ' {
        end -= 1;
    }
    for &b in &line[..end] {
        out.push(b);
    }
    out.push(b'\n');
}

/// Emit three side-by-side month blocks separated by two spaces.
fn emit_blocks_row(out: &mut OutBuf, blocks: &[MonthBlock; 3]) {
    // Title row.
    for (i, b) in blocks.iter().enumerate() {
        if i > 0 {
            out.push(b' ');
            out.push(b' ');
        }
        for &c in &b.title {
            out.push(c);
        }
    }
    out.push(b'\n');

    // Weekday row.
    for (i, b) in blocks.iter().enumerate() {
        if i > 0 {
            out.push(b' ');
            out.push(b' ');
        }
        for &c in &b.wd {
            out.push(c);
        }
    }
    out.push(b'\n');

    // Six week rows; every column emits the full grid width even when its
    // own month ran out of days, so column alignment never drifts. After
    // all three columns finish, we strip trailing spaces from the joined
    // line for a clean right edge.
    let max_rows = blocks.iter().map(|b| b.used_rows).max().unwrap_or(0);
    let blank: [u8; GRID_W] = [b' '; GRID_W];
    for r in 0..max_rows {
        // Build the row in a small stack buffer so trailing spaces can
        // be trimmed before the newline.
        const ROW_W: usize = GRID_W * 3 + 2 * 2;
        let mut line = [b' '; ROW_W];
        let mut pos = 0;
        for (i, b) in blocks.iter().enumerate() {
            if i > 0 {
                pos += 2; // two-space separator
            }
            let src = if r < b.used_rows { &b.rows[r] } else { &blank };
            line[pos..pos + GRID_W].copy_from_slice(src);
            pos += GRID_W;
        }
        let mut end = pos;
        while end > 0 && line[end - 1] == b' ' {
            end -= 1;
        }
        for &c in &line[..end] {
            out.push(c);
        }
        out.push(b'\n');
    }
}

// ----- output buffer -------------------------------------------------------

const BUF_CAP: usize = 1024;

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

/// Parse a positive decimal `u32` from bytes; returns `None` on empty
/// input, non-digit characters, or numeric overflow.
fn parse_u32(s: &[u8]) -> Option<u32> {
    if s.is_empty() {
        return None;
    }
    let mut acc: u32 = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((b - b'0') as u32)?;
    }
    Some(acc)
}

/// Write a `u32` decimal into `buf` starting at index 0; returns the
/// number of bytes written. Caller guarantees `buf` has room (max 10).
fn write_u32(buf: &mut [u8], mut v: u32) -> usize {
    if v == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 10];
    let mut n = 0;
    while v > 0 {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    for k in 0..n {
        buf[k] = tmp[n - 1 - k];
    }
    n
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

fn usage() {
    write_err(b"usage: cal [-m] [-3] [[MONTH] YEAR]\n");
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe { libc::write(2, b"cal: panic\n".as_ptr(), 11) };
    libc::exit(1)
}
