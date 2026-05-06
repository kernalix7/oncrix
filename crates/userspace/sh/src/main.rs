// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX minimal POSIX shell skeleton.
//!
//! Supports built-in commands: `exit`, `cd`, `export`.
//! External commands are located via PATH lookup and executed with `execve`.
//!
//! This is a skeleton implementation. A production shell would require
//! a full POSIX grammar parser, job control, and signal handling.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicI32, Ordering};

use oncrix_ulibc as libc;

/// Exit status of the most recently waited-for child, exposed to the
/// user via the `$?` special parameter (POSIX.1-2024 §2.5.2).
///
/// sh is single-threaded so a relaxed atomic is sufficient — the
/// atomic wrapper is purely a `static mut`-avoidance convenience.
static LAST_STATUS: AtomicI32 = AtomicI32::new(0);

/// Decode a `waitpid` raw status word into the conventional exit
/// code (0..=255) for `$?` reporting.
///
/// POSIX `wait(3p)` returns `(exit_code << 8)` for normally
/// terminated children and `signum` (no high-byte shift) for
/// signal-killed ones. The kernel currently only emits the former,
/// so we just take the high byte and downcast.
fn status_to_exit_code(raw: i32) -> i32 {
    ((raw as u32 >> 8) & 0xff) as i32
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Prompt string written to stdout before each command.
const PROMPT: &[u8] = b"$ ";
/// Maximum command line length.
const CMD_MAX: usize = 512;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    sh_main()
}

// ---------------------------------------------------------------------------
// Shell main loop
// ---------------------------------------------------------------------------

fn sh_main() -> ! {
    // Display the message of the day on startup — exercises the
    // embedded `/bin/cat` binary end-to-end via fork+execve. Best-
    // effort: failures are silent so a missing/empty motd does not
    // prevent the prompt from coming up.
    print_motd();

    let mut buf = [0u8; CMD_MAX];

    loop {
        // Print prompt.
        write_all(1, PROMPT);

        // Read a line from stdin.
        let n = read_line(&mut buf);
        if n == 0 {
            // EOF (Ctrl-D): exit cleanly.
            libc::exit(0);
        }

        let line = &buf[..n];
        // Trim trailing newline.
        let line = if line.last() == Some(&b'\n') {
            &line[..line.len() - 1]
        } else {
            line
        };

        if line.is_empty() {
            continue;
        }

        // Split on `;` (top-level only — no quoting awareness yet) and
        // run each segment in order.  Variable substitution is performed
        // per-segment so that `$?` reflects the exit status of the
        // immediately preceding command on the same line.
        run_semicolon_list(line);
    }
}

/// Operator that joins two adjacent commands in a list.
///
/// POSIX.1-2024 §2.9.3 defines an "AND-OR list" using `&&` (only run
/// the next command if the previous one returned 0) and `||` (only
/// run the next command if the previous one returned non-zero). `;`
/// is unconditional sequencing.
#[derive(Debug, Clone, Copy)]
enum ListOp {
    /// `;` — always run the next segment.
    Semi,
    /// `&&` — run only when previous exit status == 0.
    And,
    /// `||` — run only when previous exit status != 0.
    Or,
}

/// Split `line` on `;`, `&&`, and `||` (in left-to-right scan order)
/// and execute each segment honouring AND-OR short-circuit semantics.
///
/// `LAST_STATUS` is updated by each child's waitpid so that `$?` and
/// the `&&` / `||` decision both see the same value.
fn run_semicolon_list(line: &[u8]) {
    // Operator we used to JOIN this segment to the previous one — the
    // first segment is unconditional.
    let mut op = ListOp::Semi;
    let mut start = 0usize;

    loop {
        // Find the next `;`, `&&`, or `||` at top-level.
        let (end, next_op) = find_next_list_op(&line[start..]);

        let abs_end = end.map(|e| start + e);
        let segment = match abs_end {
            Some(e) => &line[start..e],
            None => &line[start..],
        };

        // Decide whether to RUN this segment based on the join op +
        // the prior LAST_STATUS.
        let should_run = match op {
            ListOp::Semi => true,
            ListOp::And => LAST_STATUS.load(Ordering::Relaxed) == 0,
            ListOp::Or => LAST_STATUS.load(Ordering::Relaxed) != 0,
        };

        let segment = trim(segment);
        if should_run && !segment.is_empty() {
            // Substitute variables in this segment before dispatching.
            let mut sub_buf = [0u8; CMD_MAX];
            let segment = substitute_vars(segment, &mut sub_buf);

            // Check for a pipeline: exactly one `|` splits into two segments.
            if let Some(pipe_pos) = find_pipe(segment) {
                run_pipeline(&segment[..pipe_pos], &segment[pipe_pos + 1..]);
            } else {
                dispatch_command(segment);
            }
        }

        match abs_end {
            Some(e) => {
                let advance = match next_op {
                    ListOp::Semi => 1,
                    ListOp::And | ListOp::Or => 2,
                };
                start = e + advance;
                op = next_op;
            }
            None => break,
        }
    }
}

/// Scan `line` from index 0 and return the position + kind of the
/// first top-level list operator, or `(None, _)` if no operator
/// appears in the segment.
///
/// "Top-level" here is unsophisticated — it does not honour quoting
/// or escapes (sh has no quoting yet); a future POSIX-compliance
/// batch will need a real tokeniser. The returned tuple's second
/// element is meaningless when the first is `None`; callers must
/// not consult it in that case.
fn find_next_list_op(line: &[u8]) -> (Option<usize>, ListOp) {
    let mut i = 0usize;
    while i < line.len() {
        if i + 1 < line.len() && line[i] == b'&' && line[i + 1] == b'&' {
            return (Some(i), ListOp::And);
        }
        if i + 1 < line.len() && line[i] == b'|' && line[i + 1] == b'|' {
            return (Some(i), ListOp::Or);
        }
        if line[i] == b';' {
            return (Some(i), ListOp::Semi);
        }
        i += 1;
    }
    (None, ListOp::Semi)
}

/// Replace `$?`, `$NAME`, and `${NAME}` in `src`, writing into `dst`.
///
/// - `$?` → decimal exit status of last child (POSIX §2.5.2).
/// - `$NAME` / `${NAME}` → value from the process environment via
///   `getenv`; expands to empty string when the variable is unset.
/// - NAME must match `[A-Za-z_][A-Za-z0-9_]*`.
///
/// Over-long output is silently truncated — POSIX leaves over-long
/// lines implementation-defined.
fn substitute_vars<'a>(src: &[u8], dst: &'a mut [u8]) -> &'a [u8] {
    let mut i = 0usize;
    let mut o = 0usize;

    while i < src.len() && o < dst.len() {
        if src[i] != b'$' {
            dst[o] = src[i];
            o += 1;
            i += 1;
            continue;
        }

        // src[i] == b'$'
        let after_dollar = i + 1;
        if after_dollar >= src.len() {
            // Lone `$` at end of input — pass through literally.
            dst[o] = src[i];
            o += 1;
            i += 1;
            continue;
        }

        let next = src[after_dollar];

        if next == b'?' {
            // $? — last exit status.
            let status = LAST_STATUS.load(Ordering::Relaxed);
            let mut digits = [0u8; 12];
            let dlen = i32_to_dec(status, &mut digits);
            let copy = dlen.min(dst.len() - o);
            dst[o..o + copy].copy_from_slice(&digits[..copy]);
            o += copy;
            i += 2;
            continue;
        }

        // Determine whether this is `${NAME}` or `$NAME`.
        let (name, advance) = if next == b'{' {
            // `${NAME}` form — scan for closing `}`.
            let name_start = after_dollar + 1;
            let mut end = name_start;
            while end < src.len() && src[end] != b'}' {
                end += 1;
            }
            let name = &src[name_start..end];
            let advance = if end < src.len() {
                // consume up to and including the `}`
                end + 1
            } else {
                end
            };
            (name, advance)
        } else if is_name_start(next) {
            // `$NAME` form — scan identifier characters.
            let name_start = after_dollar;
            let mut end = name_start;
            while end < src.len() && is_name_char(src[end]) {
                end += 1;
            }
            (&src[name_start..end], end)
        } else {
            // Not a recognised expansion — pass `$` through literally.
            dst[o] = b'$';
            o += 1;
            i += 1;
            continue;
        };

        // Look up `name` in the environment.
        if !name.is_empty() {
            o += getenv_into(name, &mut dst[o..]);
        }
        i = advance;
    }
    &dst[..o]
}

/// Return true if `b` is a valid first character of a POSIX NAME (`[A-Za-z_]`).
#[inline]
fn is_name_start(b: u8) -> bool {
    b.is_ascii_alphabetic() || b == b'_'
}

/// Return true if `b` is a valid continuation character of a POSIX NAME.
#[inline]
fn is_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Write the value of environment variable `name` into `out`, returning
/// the number of bytes written.  Returns 0 for unset variables.
///
/// The kernel currently passes an empty envp, so all variables are unset.
/// This function is the extension point for a future environ scan.
fn getenv_into(_name: &[u8], _out: &mut [u8]) -> usize {
    0
}

/// Format a (possibly negative) `i32` into the start of `buf` as
/// decimal ASCII; returns the number of bytes written.
fn i32_to_dec(value: i32, buf: &mut [u8; 12]) -> usize {
    if value == 0 {
        buf[0] = b'0';
        return 1;
    }
    let (mut n, neg) = if value < 0 {
        ((value as i64).unsigned_abs(), true)
    } else {
        (value as u64, false)
    };
    let mut tmp = [0u8; 12];
    let mut i = 12usize;
    while n > 0 {
        i -= 1;
        tmp[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    let len = 12 - i;
    let mut out = 0;
    if neg {
        buf[0] = b'-';
        out = 1;
    }
    buf[out..out + len].copy_from_slice(&tmp[i..]);
    out + len
}

// ---------------------------------------------------------------------------
// Pipeline execution
// ---------------------------------------------------------------------------

/// Find the position of the first unquoted `|` byte, returning `None` if there
/// is more than one `|` or none at all.  (Single-pipe only for now.)
fn find_pipe(line: &[u8]) -> Option<usize> {
    let mut first: Option<usize> = None;
    for (i, &b) in line.iter().enumerate() {
        if b == b'|' {
            if first.is_some() {
                // More than one pipe — not handled in this iteration.
                return None;
            }
            first = Some(i);
        }
    }
    first
}

/// Execute `left | right` via fork/pipe/dup2.
fn run_pipeline(left: &[u8], right: &[u8]) {
    let left = trim(left);
    let right = trim(right);

    let mut fds = [0i32; 2];
    // SAFETY: fds is a valid two-element i32 array.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), 0) };
    if rc < 0 {
        write_all(2, b"sh: pipe2 failed\n");
        return;
    }
    let read_fd = fds[0];
    let write_fd = fds[1];

    // Fork the writer (left side of pipe).
    let writer = libc::fork();
    if writer == 0 {
        // Child: redirect stdout → write end of pipe.
        // SAFETY: write_fd and STDOUT_FILENO (1) are valid non-negative fds.
        unsafe { libc::dup2(write_fd, 1) };
        libc::close(read_fd);
        libc::close(write_fd);
        dispatch_command(left);
        libc::exit(0);
    } else if writer < 0 {
        write_all(2, b"sh: fork failed\n");
        libc::close(read_fd);
        libc::close(write_fd);
        return;
    }

    // Fork the reader (right side of pipe).
    let reader = libc::fork();
    if reader == 0 {
        // Child: redirect stdin → read end of pipe.
        // SAFETY: read_fd and STDIN_FILENO (0) are valid non-negative fds.
        unsafe { libc::dup2(read_fd, 0) };
        libc::close(write_fd);
        libc::close(read_fd);
        dispatch_command(right);
        libc::exit(0);
    } else if reader < 0 {
        write_all(2, b"sh: fork failed\n");
    }

    // Parent: close both ends and wait for both children.
    libc::close(read_fd);
    libc::close(write_fd);
    // SAFETY: writer/reader are valid child PIDs returned by fork(); status ptr is valid.
    unsafe { libc::waitpid(writer, core::ptr::null_mut(), 0) };
    if reader > 0 {
        unsafe { libc::waitpid(reader, core::ptr::null_mut(), 0) };
    }
}

// ---------------------------------------------------------------------------
// Command dispatcher (builtins only)
// ---------------------------------------------------------------------------

/// Dispatch a single command line to the appropriate built-in handler.
///
/// If the command is not a known built-in, writes "sh: not found\n" to stderr
/// and exits with code 127 when called from a child process context.
fn dispatch_command(line: &[u8]) {
    let line = trim(line);
    if line.is_empty() {
        return;
    }

    // Strip any I/O redirection operators from the line before tokenizing.
    let mut cmd_buf = [0u8; CMD_MAX];
    let (stripped, redirs) = parse_redirections(line, &mut cmd_buf);
    let stripped = trim(stripped);
    if stripped.is_empty() {
        return;
    }

    let (cmd, rest) = split_first_token(stripped);

    match cmd {
        b"exit" => {
            let code = parse_i32(rest).unwrap_or(0);
            libc::exit(code);
        }
        b"cd" => {
            let dir = if rest.is_empty() { b"/" as &[u8] } else { rest };
            let mut path_buf = [0u8; 257];
            let len = dir.len().min(256);
            path_buf[..len].copy_from_slice(&dir[..len]);
            // SAFETY: path_buf is zero-initialized, so it is null-terminated.
            let ret = unsafe { libc::chdir(path_buf.as_ptr()) };
            if ret < 0 {
                write_all(2, b"cd: no such file or directory\n");
            }
        }
        b"export" => {
            // export is a built-in — stub: putenv not yet wired.
            let _ = rest;
        }
        b"pwd" => {
            let mut buf = [0u8; 258];
            // SAFETY: buf is valid for 258 writable bytes.
            let n = unsafe { libc::getcwd(buf.as_mut_ptr(), 256) };
            if n > 0 {
                let len = n as usize - 1;
                buf[len] = b'\n';
                write_all(1, &buf[..len + 1]);
            } else {
                write_all(1, b"/\n");
            }
        }
        b"pid" => {
            let pid = libc::getpid();
            let mut tmp = [0u8; 20];
            let s = fmt_i64(&mut tmp, pid);
            write_all(1, s);
            write_all(1, b"\n");
        }
        b"mkdir" => {
            if rest.is_empty() {
                write_all(2, b"mkdir: missing operand\n");
            } else {
                let mut path_buf = [0u8; 257];
                let len = rest.len().min(256);
                path_buf[..len].copy_from_slice(&rest[..len]);
                // SAFETY: path_buf is zero-initialized, so it is null-terminated.
                let ret = unsafe { libc::mkdir(path_buf.as_ptr(), 0o755) };
                if ret < 0 {
                    write_all(2, b"mkdir: error\n");
                }
            }
        }
        b"touch" => {
            if rest.is_empty() {
                write_all(2, b"touch: missing operand\n");
            } else {
                let mut path_buf = [0u8; 257];
                let len = rest.len().min(256);
                path_buf[..len].copy_from_slice(&rest[..len]);
                // O_CREAT|O_WRONLY
                // SAFETY: path_buf is zero-initialized, so it is null-terminated.
                let fd =
                    unsafe { libc::open(path_buf.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o644) };
                if fd >= 0 {
                    libc::close(fd as i32);
                }
            }
        }
        b"rm" => {
            if rest.is_empty() {
                write_all(2, b"rm: missing operand\n");
            } else {
                let mut path_buf = [0u8; 257];
                let len = rest.len().min(256);
                path_buf[..len].copy_from_slice(&rest[..len]);
                // SAFETY: path_buf is zero-initialized, so it is null-terminated.
                let ret = unsafe { libc::unlink(path_buf.as_ptr()) };
                if ret < 0 {
                    write_all(2, b"rm: error\n");
                }
            }
        }
        b"help" => {
            write_all(1, b"builtins: exit cd export pwd pid mkdir touch rm help\n");
            write_all(
                1,
                b"externals: echo cat ls true false wc head tail env uname (in /bin)\n",
            );
        }
        _ => {
            run_external(cmd, rest, &redirs);
        }
    }
}

// ---------------------------------------------------------------------------
// I/O redirection parsing
// ---------------------------------------------------------------------------

/// Maximum path length for a redirection target filename (including NUL).
const REDIR_PATH_LEN: usize = 128;

/// Parsed I/O redirections extracted from a command line.
///
/// Each direction stores the NUL-terminated filename and whether the
/// field is active (`has_*`).  Only the rightmost operator wins per
/// direction, matching POSIX sh behaviour.
struct Redirections {
    /// Stdout target (active when `has_out` is true).
    out_path: [u8; REDIR_PATH_LEN],
    has_out: bool,
    /// Append stdout target (active when `has_append` is true; `has_out` is
    /// also set so the open flags differ only in O_TRUNC vs O_APPEND).
    append: bool,
    /// Stdin source (active when `has_in` is true).
    in_path: [u8; REDIR_PATH_LEN],
    has_in: bool,
}

impl Redirections {
    const fn none() -> Self {
        Self {
            out_path: [0u8; REDIR_PATH_LEN],
            has_out: false,
            append: false,
            in_path: [0u8; REDIR_PATH_LEN],
            has_in: false,
        }
    }
}

/// Scan `line` for unquoted `>>`, `>`, and `<` redirection operators.
///
/// Returns the `Redirections` struct plus a heap-free "stripped" command
/// line written into `cmd_buf` (up to `cmd_buf.len()` bytes; NUL-
/// terminated).  The returned slice is the printable portion of `cmd_buf`
/// without the trailing NUL.
///
/// Operator precedence: rightmost operator wins per direction (POSIX 2.7).
/// Whitespace around the operator is allowed (`cmd >file` == `cmd > file`).
fn parse_redirections<'b>(line: &[u8], cmd_buf: &'b mut [u8; CMD_MAX]) -> (&'b [u8], Redirections) {
    let mut redirs = Redirections::none();
    let mut out_len = 0usize;
    let mut i = 0usize;

    while i < line.len() {
        // Detect `>>` before `>` so we don't consume the first `>` alone.
        if i + 1 < line.len() && line[i] == b'>' && line[i + 1] == b'>' {
            i += 2;
            // Skip whitespace between operator and filename.
            while i < line.len() && (line[i] == b' ' || line[i] == b'\t') {
                i += 1;
            }
            // Collect filename token.
            let start = i;
            while i < line.len() && line[i] != b' ' && line[i] != b'\t' {
                i += 1;
            }
            let name = &line[start..i];
            let copy_len = name.len().min(REDIR_PATH_LEN - 1);
            redirs.out_path = [0u8; REDIR_PATH_LEN];
            redirs.out_path[..copy_len].copy_from_slice(&name[..copy_len]);
            redirs.has_out = true;
            redirs.append = true;
            continue;
        }
        if line[i] == b'>' {
            i += 1;
            while i < line.len() && (line[i] == b' ' || line[i] == b'\t') {
                i += 1;
            }
            let start = i;
            while i < line.len() && line[i] != b' ' && line[i] != b'\t' {
                i += 1;
            }
            let name = &line[start..i];
            let copy_len = name.len().min(REDIR_PATH_LEN - 1);
            redirs.out_path = [0u8; REDIR_PATH_LEN];
            redirs.out_path[..copy_len].copy_from_slice(&name[..copy_len]);
            redirs.has_out = true;
            redirs.append = false;
            continue;
        }
        if line[i] == b'<' {
            i += 1;
            while i < line.len() && (line[i] == b' ' || line[i] == b'\t') {
                i += 1;
            }
            let start = i;
            while i < line.len() && line[i] != b' ' && line[i] != b'\t' {
                i += 1;
            }
            let name = &line[start..i];
            let copy_len = name.len().min(REDIR_PATH_LEN - 1);
            redirs.in_path = [0u8; REDIR_PATH_LEN];
            redirs.in_path[..copy_len].copy_from_slice(&name[..copy_len]);
            redirs.has_in = true;
            continue;
        }
        // Ordinary character — copy to cmd_buf.
        if out_len < CMD_MAX - 1 {
            cmd_buf[out_len] = line[i];
            out_len += 1;
        }
        i += 1;
    }
    cmd_buf[out_len] = 0;
    // Trim trailing whitespace from cmd portion.
    while out_len > 0 && (cmd_buf[out_len - 1] == b' ' || cmd_buf[out_len - 1] == b'\t') {
        cmd_buf[out_len - 1] = 0;
        out_len -= 1;
    }
    (&cmd_buf[..out_len], redirs)
}

/// Open a redirection target file and dup2 it onto `target_fd`.
///
/// Returns false if any operation fails (the caller should exit the child).
///
/// # Safety
///
/// Must be called only in the child process after fork, before execve.
unsafe fn apply_redirection(path: &[u8], open_flags: i32, open_mode: u32, target_fd: i32) -> bool {
    // path is already NUL-terminated in the fixed-size array; pass its ptr.
    // SAFETY: caller guarantees path is a NUL-terminated slice from Redirections.
    let fd = unsafe { libc::open(path.as_ptr(), open_flags, open_mode) };
    if fd < 0 {
        write_all(2, b"sh: redirection: cannot open file\n");
        return false;
    }
    // SAFETY: fd >= 0 and target_fd (0 or 1) are valid fds.
    unsafe { libc::dup2(fd as i32, target_fd) };
    libc::close(fd as i32);
    true
}

// ---------------------------------------------------------------------------
// External command execution
// ---------------------------------------------------------------------------

/// Display `/etc/motd` by fork+execve("/bin/cat", "/etc/motd").
///
/// Best-effort: any failure (fork, execve, file missing) is silent.
/// On success the child writes motd contents to fd 1 and exits; the
/// parent waits for it before returning so the next `$ ` prompt does
/// not interleave with motd output.
fn print_motd() {
    let pid = libc::fork();
    if pid == 0 {
        // Child: execve("/bin/cat", ["cat", "/etc/motd"], []).
        let path = c"/bin/cat".as_ptr().cast::<u8>();
        let arg0 = c"cat".as_ptr().cast::<u8>();
        let arg1 = c"/etc/motd".as_ptr().cast::<u8>();
        let argv: [*const u8; 3] = [arg0, arg1, core::ptr::null()];
        let envp: [*const u8; 1] = [core::ptr::null()];
        // SAFETY: Both pointer arrays are NUL-terminated; path and
        // argv strings are static C string literals.
        unsafe { libc::execve(path, argv.as_ptr(), envp.as_ptr()) };
        // execve only returns on failure — bail silently.
        libc::exit(0);
    } else if pid > 0 {
        // SAFETY: pid is a valid child PID; status pointer is null
        // (status is discarded — best-effort path).
        unsafe { libc::waitpid(pid, core::ptr::null_mut(), 0) };
    }
    // pid < 0 → fork failed; do nothing.
}

/// Maximum number of argv slots passed to an external command,
/// excluding the trailing NULL terminator.
const ARGV_MAX: usize = 8;
/// Maximum length of a single argv string (including NUL terminator).
const ARG_BUF_LEN: usize = 64;

/// Fork and exec an external command resolved against the kernel's
/// embedded binary set (`/bin/{sh,echo,cat,true,false}` plus their
/// bare-name aliases).
///
/// `cmd` is the command name (becomes both the execve path and
/// `argv[0]`). `rest` is the remaining whitespace-separated argument
/// string from the prompt; it is tokenised into `argv[1..]` slots up
/// to [`ARGV_MAX`] and at most [`ARG_BUF_LEN`] - 1 bytes per slot.
/// `redirs` carries any I/O redirections parsed from the original line;
/// they are applied in the child before `execve`.
fn run_external(cmd: &[u8], rest: &[u8], redirs: &Redirections) {
    if cmd.len() >= ARG_BUF_LEN {
        write_all(2, b"sh: command too long\n");
        return;
    }

    // Stack-allocated NUL-terminated storage for argv strings.
    // Each row is one argv slot; the trailing zero byte serves as the
    // NUL terminator since the array is zero-initialised.
    let mut arg_storage = [[0u8; ARG_BUF_LEN]; ARGV_MAX];
    let mut argv: [*const u8; ARGV_MAX + 1] = [core::ptr::null(); ARGV_MAX + 1];

    // argv[0] = cmd.
    arg_storage[0][..cmd.len()].copy_from_slice(cmd);
    argv[0] = arg_storage[0].as_ptr();

    // argv[1..] = whitespace-separated tokens of `rest`.
    let mut slot = 1usize;
    let mut i = 0usize;
    while i < rest.len() && slot < ARGV_MAX {
        // Skip leading whitespace.
        while i < rest.len() && (rest[i] == b' ' || rest[i] == b'\t') {
            i += 1;
        }
        if i == rest.len() {
            break;
        }
        let start = i;
        while i < rest.len() && rest[i] != b' ' && rest[i] != b'\t' {
            i += 1;
        }
        let tok = &rest[start..i];
        let copy_len = tok.len().min(ARG_BUF_LEN - 1);
        arg_storage[slot][..copy_len].copy_from_slice(&tok[..copy_len]);
        argv[slot] = arg_storage[slot].as_ptr();
        slot += 1;
    }
    // argv[slot] remains NULL — POSIX-required terminator.

    let envp: [*const u8; 1] = [core::ptr::null()];

    let child = libc::fork();
    if child == 0 {
        // Child: apply redirections before execve.
        if redirs.has_out {
            let flags = if redirs.append {
                libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND
            } else {
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC
            };
            // SAFETY: out_path is NUL-terminated (zero-initialized array).
            if !unsafe { apply_redirection(&redirs.out_path, flags, 0o644, 1) } {
                libc::exit(1);
            }
        }
        if redirs.has_in {
            // SAFETY: in_path is NUL-terminated (zero-initialized array).
            if !unsafe { apply_redirection(&redirs.in_path, libc::O_RDONLY, 0, 0) } {
                libc::exit(1);
            }
        }
        // execve into the requested binary. argv[0] is `cmd` which is also
        // the path — `embedded_lookup` accepts both `/bin/<name>` and bare
        // `<name>` forms.
        // SAFETY: arg_storage[0] is NUL-terminated (zero-padded);
        // argv and envp arrays are NULL-terminated.
        unsafe { libc::execve(arg_storage[0].as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        // execve only returns on failure.
        write_all(2, b"sh: exec failed\n");
        libc::exit(127);
    } else if child > 0 {
        // Parent: wait for the child and remember its exit status
        // for `$?`.
        let mut status: i32 = 0;
        // SAFETY: status is a valid stack i32 owned for the duration
        // of this call.
        unsafe { libc::waitpid(child, &mut status as *mut i32, 0) };
        LAST_STATUS.store(status_to_exit_code(status), Ordering::Relaxed);
    } else {
        write_all(2, b"sh: fork failed\n");
    }
}

// ---------------------------------------------------------------------------
// I/O helpers
// ---------------------------------------------------------------------------

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

/// Read bytes from stdin until `\n` or EOF.
///
/// Returns the number of bytes read (including the newline if present).
fn read_line(buf: &mut [u8]) -> usize {
    let mut pos = 0;
    while pos < buf.len() {
        // SAFETY: buf slice is valid for buf.len() writable bytes.
        let n = unsafe { libc::read(0, buf[pos..].as_mut_ptr(), 1) };
        if n <= 0 {
            break;
        }
        pos += 1;
        if buf[pos - 1] == b'\n' {
            break;
        }
    }
    pos
}

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------

/// Format a signed 64-bit integer into `buf` as ASCII decimal.
///
/// Returns the populated slice within `buf`.  `buf` must be at least 20 bytes.
fn fmt_i64(buf: &mut [u8; 20], mut n: i64) -> &[u8] {
    let mut pos = buf.len();
    let negative = n < 0;
    if n == i64::MIN {
        // i64::MIN cannot be negated in i64; return literal string.
        return b"-9223372036854775808";
    }
    if negative {
        n = -n;
    }
    loop {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    if negative {
        pos -= 1;
        buf[pos] = b'-';
    }
    &buf[pos..]
}

/// Trim leading and trailing ASCII whitespace from `s`.
fn trim(s: &[u8]) -> &[u8] {
    let start = s
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|&b| b != b' ' && b != b'\t')
        .map(|p| p + 1)
        .unwrap_or(0);
    if end <= start { &[] } else { &s[start..end] }
}

/// Split `s` at the first whitespace, returning (token, remainder).
fn split_first_token(s: &[u8]) -> (&[u8], &[u8]) {
    let tok_end = s
        .iter()
        .position(|&b| b == b' ' || b == b'\t')
        .unwrap_or(s.len());
    let rest_start = s[tok_end..]
        .iter()
        .position(|&b| b != b' ' && b != b'\t')
        .map(|p| tok_end + p)
        .unwrap_or(s.len());
    (&s[..tok_end], &s[rest_start..])
}

/// Parse the first ASCII decimal integer from `s`.
fn parse_i32(s: &[u8]) -> Option<i32> {
    let digits: &[u8] = s
        .iter()
        .position(|&b| !b.is_ascii_digit())
        .map(|e| &s[..e])
        .unwrap_or(s);
    if digits.is_empty() {
        return None;
    }
    let mut n: i32 = 0;
    for &d in digits {
        n = n.wrapping_mul(10).wrapping_add((d - b'0') as i32);
    }
    Some(n)
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(2, b"sh: panic\n");
    libc::exit(1)
}
