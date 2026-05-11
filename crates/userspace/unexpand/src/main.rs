// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/unexpand` — convert leading spaces (and optionally all
//! internal whitespace runs) into TAB characters at tab-stop boundaries.
//!
//! Usage:
//!   unexpand [-a] [-t TABLIST] [FILE...]
//!
//! Reads each FILE in sequence (stdin if none, or for `-`) and writes
//! its contents to stdout, replacing runs of spaces with the minimum
//! number of TABs and trailing spaces that reproduce the same column
//! advance. By default only the run at the start of each line is a
//! candidate for conversion; `-a` enables conversion for every space
//! run in the line.
//!
//! Flags (POSIX subset):
//!
//! * `-a` — convert all space runs, not just the leading run.
//! * `-t LIST` — comma- or blank-separated list of tab stop columns.
//!   If a single number N is given, tab stops repeat every N columns
//!   (default 8). Implies `-a`.
//!
//! Tab-stop semantics: stops are 1-based column positions. With the
//! default of 8, stops are columns 9, 17, 25, ... so a run of spaces
//! that crosses column 8 becomes one TAB, and so on. An explicit list
//! is consumed left-to-right; once exhausted, any remaining trailing
//! spaces are emitted verbatim (no further tabbing).
//!
//! TAB bytes already present in the input pass through unchanged and
//! advance the column to the next stop. BACKSPACE decrements the
//! column (saturating at 0). Any other non-space, non-newline byte
//! advances the column by 1 and is emitted as-is.
//!
//! Up to 16 file arguments and up to 64 explicit tab stops are
//! supported. Reading uses a 4 KiB chunk; pending space runs are
//! buffered only as a count, not as bytes.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/unexpand.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

const READ_CHUNK: usize = 4096;
const MAX_FILES: usize = 16;
const MAX_STOPS: usize = 64;
const DEFAULT_TAB: usize = 8;

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym unexpand_main,
    );
}

extern "C" fn unexpand_main(argc: usize, argv: *const *const u8) -> ! {
    let mut all = false;
    let mut tab_width = DEFAULT_TAB;
    let mut stops: [usize; MAX_STOPS] = [0; MAX_STOPS];
    let mut nstops = 0usize;
    let mut files: [&[u8]; MAX_FILES] = [&[]; MAX_FILES];
    let mut nfiles = 0usize;

    let mut idx = 1usize;
    while idx < argc {
        // SAFETY: idx < argc.
        let arg = unsafe { cstr_at(argv, idx) };
        if arg == b"--" {
            idx += 1;
            while idx < argc && nfiles < MAX_FILES {
                // SAFETY: idx < argc.
                files[nfiles] = unsafe { cstr_at(argv, idx) };
                nfiles += 1;
                idx += 1;
            }
            break;
        } else if arg == b"-" {
            if nfiles < MAX_FILES {
                files[nfiles] = arg;
                nfiles += 1;
            }
            idx += 1;
        } else if arg == b"-a" {
            all = true;
            idx += 1;
        } else if arg == b"-t" {
            idx += 1;
            if idx >= argc {
                fail(b"unexpand: -t needs TABLIST\n");
            }
            // SAFETY: idx < argc.
            let s = unsafe { cstr_at(argv, idx) };
            parse_tablist(s, &mut tab_width, &mut stops, &mut nstops);
            all = true;
            idx += 1;
        } else if !arg.is_empty() && arg[0] == b'-' && arg.len() > 1 {
            // Combined short flags: -a, -t<list>, -at<list>.
            let rest = &arg[1..];
            let mut i = 0;
            while i < rest.len() {
                match rest[i] {
                    b'a' => {
                        all = true;
                        i += 1;
                    }
                    b't' => {
                        let after = &rest[i + 1..];
                        if !after.is_empty() {
                            parse_tablist(after, &mut tab_width, &mut stops, &mut nstops);
                            i = rest.len();
                        } else {
                            idx += 1;
                            if idx >= argc {
                                fail(b"unexpand: -t needs TABLIST\n");
                            }
                            // SAFETY: idx < argc.
                            let s = unsafe { cstr_at(argv, idx) };
                            parse_tablist(s, &mut tab_width, &mut stops, &mut nstops);
                            i = rest.len();
                        }
                        all = true;
                    }
                    _ => fail(b"unexpand: unknown option\n"),
                }
            }
            idx += 1;
        } else {
            if nfiles < MAX_FILES {
                files[nfiles] = arg;
                nfiles += 1;
            }
            idx += 1;
        }
    }

    let mut state = UnexpandState::new(all, tab_width, &stops[..nstops]);

    if nfiles == 0 {
        process_fd(0, &mut state);
    } else {
        for f in &files[..nfiles] {
            if *f == b"-" {
                process_fd(0, &mut state);
            } else {
                let mut path = [0u8; 512];
                if f.len() >= path.len() {
                    fail(b"unexpand: path too long\n");
                }
                path[..f.len()].copy_from_slice(f);
                // SAFETY: path is NUL-terminated (zero-initialized tail).
                let r = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY, 0) };
                if r < 0 {
                    fail(b"unexpand: cannot open file\n");
                }
                let fd = r as i32;
                process_fd(fd, &mut state);
                let _ = libc::close(fd);
            }
        }
    }

    state.flush();
    libc::exit(0)
}

/// Per-stream conversion state. Tracks the current column, whether we
/// are still in the leading-whitespace zone of the current line, and
/// the size of the pending run of spaces awaiting flush.
struct UnexpandState<'a> {
    all: bool,
    tab_width: usize,
    stops: &'a [usize],
    col: usize,
    pending_spaces: usize,
    /// Starting column of the current pending space run (0-based).
    run_start_col: usize,
    /// True until the current line has produced any non-space, non-tab byte.
    leading: bool,
}

impl<'a> UnexpandState<'a> {
    fn new(all: bool, tab_width: usize, stops: &'a [usize]) -> Self {
        Self {
            all,
            tab_width,
            stops,
            col: 0,
            pending_spaces: 0,
            run_start_col: 0,
            leading: true,
        }
    }

    /// Return the next tab stop column strictly greater than `col`,
    /// or `None` if no further stop is reachable (explicit list used up).
    fn next_stop(&self, col: usize) -> Option<usize> {
        if self.stops.is_empty() {
            if self.tab_width == 0 {
                return None;
            }
            // Repeating stops every `tab_width` starting at `tab_width`.
            // For column `col`, next stop is the smallest multiple of
            // tab_width that is > col.
            Some((col / self.tab_width + 1) * self.tab_width)
        } else {
            for &s in self.stops {
                if s > col {
                    return Some(s);
                }
            }
            None
        }
    }

    /// Decide whether the currently pending space run should be
    /// collapsed into TABs. Default mode: only the leading run; with
    /// `-a`: every run.
    fn run_collapsible(&self) -> bool {
        self.all || self.leading
    }

    /// Flush the pending space run. If collapsible, replace it with the
    /// minimum number of TABs (each advancing to the next tab stop that
    /// fits inside the run) followed by any leftover spaces. Otherwise
    /// emit the spaces verbatim.
    fn flush_run(&mut self) {
        if self.pending_spaces == 0 {
            return;
        }
        let start = self.run_start_col;
        let end = start + self.pending_spaces;
        if self.run_collapsible() {
            let mut cur = start;
            // Emit TABs while the next stop is strictly inside (start, end].
            // We also require that the run actually covers at least 2
            // columns from `cur` to the stop to make tabbing worthwhile
            // when stops are dense — a single space at column 7 with a
            // stop at 8 should still collapse (1 space → 1 TAB is the
            // POSIX expectation: any space run that lands on a stop
            // becomes a TAB).
            while let Some(stop) = self.next_stop(cur) {
                if stop > end {
                    break;
                }
                let _ = write_all(1, b"\t");
                cur = stop;
            }
            // Emit remaining spaces verbatim.
            let mut rem = end - cur;
            while rem > 0 {
                let _ = write_all(1, b" ");
                rem -= 1;
            }
        } else {
            // Emit spaces as-is.
            let mut rem = self.pending_spaces;
            while rem > 0 {
                let chunk = if rem >= 16 { 16 } else { rem };
                let buf = b"                ";
                let _ = write_all(1, &buf[..chunk]);
                rem -= chunk;
            }
        }
        self.pending_spaces = 0;
    }

    /// Feed one input byte.
    fn feed(&mut self, byte: u8) {
        match byte {
            b' ' => {
                if self.pending_spaces == 0 {
                    self.run_start_col = self.col;
                }
                self.pending_spaces += 1;
                self.col += 1;
            }
            b'\t' => {
                // A TAB inside a leading run extends the run if all
                // preceding bytes were spaces or tabs and the result
                // still lands on a tab stop boundary. Easier and
                // POSIX-conformant: flush the pending spaces (so any
                // collapse happens), then emit the TAB itself,
                // advancing the column to the next stop.
                self.flush_run();
                let _ = write_all(1, b"\t");
                self.col = match self.next_stop(self.col) {
                    Some(s) => s,
                    // No further stop — pretend the column advances by 1.
                    None => self.col + 1,
                };
            }
            b'\n' => {
                // Trailing-space runs at end-of-line are still subject
                // to the same collapse rules as any other run.
                self.flush_run();
                let _ = write_all(1, b"\n");
                self.col = 0;
                self.leading = true;
            }
            0x08 => {
                self.flush_run();
                let _ = write_all(1, b"\x08");
                self.col = self.col.saturating_sub(1);
                // Backspacing through leading whitespace doesn't change
                // the leading-zone flag — once content has appeared, we
                // stay out of leading mode for the rest of the line.
            }
            _ => {
                self.flush_run();
                // SAFETY: emit a single byte from a local slice.
                let _ = write_all(1, core::slice::from_ref(&byte));
                self.col += 1;
                self.leading = false;
            }
        }
    }

    /// End-of-stream flush. Drains any pending run without emitting a
    /// trailing newline (unexpand preserves the absence of a final
    /// newline, like the POSIX reference).
    fn flush(&mut self) {
        self.flush_run();
    }
}

fn process_fd(fd: i32, state: &mut UnexpandState<'_>) {
    let mut readbuf = [0u8; READ_CHUNK];
    loop {
        // SAFETY: readbuf is owned and writable for its full length.
        let n = unsafe { libc::read(fd, readbuf.as_mut_ptr(), readbuf.len()) };
        if n <= 0 {
            break;
        }
        for &b in &readbuf[..n as usize] {
            state.feed(b);
        }
    }
}

/// Parse a `-t` argument into either a single repeating tab width
/// (stored in `tab_width`, with `nstops` set to 0) or an explicit list
/// of stops (stored in `stops[..nstops]`). Separator: comma or blank.
fn parse_tablist(
    s: &[u8],
    tab_width: &mut usize,
    stops: &mut [usize; MAX_STOPS],
    nstops: &mut usize,
) {
    let mut count = 0usize;
    let mut i = 0usize;
    while i < s.len() {
        // Skip separators.
        while i < s.len() && (s[i] == b',' || s[i] == b' ') {
            i += 1;
        }
        if i >= s.len() {
            break;
        }
        let start = i;
        while i < s.len() && s[i] != b',' && s[i] != b' ' {
            i += 1;
        }
        let tok = &s[start..i];
        let v = match parse_usize(tok) {
            Some(v) if v > 0 => v,
            _ => fail(b"unexpand: invalid tab list\n"),
        };
        if count >= MAX_STOPS {
            fail(b"unexpand: too many tab stops\n");
        }
        stops[count] = v;
        count += 1;
    }
    if count == 0 {
        fail(b"unexpand: empty tab list\n");
    }
    if count == 1 {
        // Single value → repeating tab width.
        *tab_width = stops[0];
        *nstops = 0;
        return;
    }
    // Verify the list is strictly increasing.
    for k in 1..count {
        if stops[k] <= stops[k - 1] {
            fail(b"unexpand: tab list must be increasing\n");
        }
    }
    *nstops = count;
}

fn parse_usize(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    let mut acc: usize = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((b - b'0') as usize)?;
    }
    Some(acc)
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
    let _ = write_all(2, b"unexpand: panic\n");
    libc::exit(1)
}
