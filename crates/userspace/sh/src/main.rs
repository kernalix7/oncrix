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

use oncrix_ulibc as libc;

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

        // Check for a pipeline: exactly one `|` splits the line into two segments.
        if let Some(pipe_pos) = find_pipe(line) {
            run_pipeline(&line[..pipe_pos], &line[pipe_pos + 1..]);
        } else {
            dispatch_command(line);
        }
    }
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

    let (cmd, rest) = split_first_token(line);

    match cmd {
        b"exit" => {
            let code = parse_i32(rest).unwrap_or(0);
            libc::exit(code);
        }
        b"cd" => {
            // cd is a built-in — stub: chdir syscall not yet wired.
            let _ = rest;
        }
        b"export" => {
            // export is a built-in — stub: putenv not yet wired.
            let _ = rest;
        }
        b"pwd" => {
            write_all(1, b"/\n");
        }
        b"pid" => {
            let pid = libc::getpid();
            let mut tmp = [0u8; 20];
            let s = fmt_i64(&mut tmp, pid);
            write_all(1, s);
            write_all(1, b"\n");
        }
        b"ls" => {
            let target = if rest.is_empty() { b"/" as &[u8] } else { rest };
            do_ls(target);
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
                // O_CREAT|O_WRONLY = 0x41
                // SAFETY: path_buf is zero-initialized, so it is null-terminated.
                let fd = unsafe { libc::open(path_buf.as_ptr(), 0x41, 0o644) };
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
            write_all(
                1,
                b"builtins: exit cd export pwd pid ls mkdir touch rm help\n",
            );
            write_all(1, b"externals: echo cat true false (and more in /bin)\n");
        }
        _ => {
            run_external(cmd, rest);
        }
    }
}

// ---------------------------------------------------------------------------
// External command execution
// ---------------------------------------------------------------------------

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
fn run_external(cmd: &[u8], rest: &[u8]) {
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
        // Child: execve into the requested binary. argv[0] is `cmd`
        // which is also the path — `embedded_lookup` accepts both
        // `/bin/<name>` and bare `<name>` forms.
        // SAFETY: arg_storage[0] is NUL-terminated (zero-padded);
        // argv and envp arrays are NULL-terminated.
        unsafe { libc::execve(arg_storage[0].as_ptr(), argv.as_ptr(), envp.as_ptr()) };
        // execve only returns on failure.
        write_all(2, b"sh: exec failed\n");
        libc::exit(127);
    } else if child > 0 {
        // Parent: wait for the child.
        let mut status: i32 = 0;
        // SAFETY: status is a valid stack i32 owned for the duration
        // of this call.
        unsafe { libc::waitpid(child, &mut status as *mut i32, 0) };
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
// ls helper
// ---------------------------------------------------------------------------

/// Implements the `ls` builtin.
///
/// Opens `target` as a directory, reads directory entries with getdents64,
/// parses each linux_dirent64 record, and writes the name followed by `\n`.
fn do_ls(target: &[u8]) {
    let mut path_buf = [0u8; 257];
    let len = target.len().min(256);
    path_buf[..len].copy_from_slice(&target[..len]);

    // Open the directory (O_RDONLY = 0).
    // SAFETY: path_buf is zero-initialized, so it is null-terminated.
    let fd = unsafe { libc::open(path_buf.as_ptr(), 0, 0) };
    if fd < 0 {
        write_all(2, b"ls: not found\n");
        return;
    }

    let mut buf = [0u8; 4096];
    loop {
        // SAFETY: buf is a valid 4096-byte writable buffer.
        let n = unsafe { libc::getdents64(fd as i32, buf.as_mut_ptr(), buf.len()) };
        if n <= 0 {
            break;
        }
        // Walk the linux_dirent64 records in the returned buffer.
        // linux_dirent64 layout (as defined in getdents(2)):
        //   ino:    u64   (offset 0)
        //   off:    u64   (offset 8)
        //   reclen: u16   (offset 16)
        //   type:   u8    (offset 18)
        //   name:   [u8]  (offset 19, null-terminated)
        let mut pos = 0usize;
        while pos < n as usize {
            if pos + 19 > n as usize {
                break;
            }
            let reclen = u16::from_ne_bytes([buf[pos + 16], buf[pos + 17]]) as usize;
            if reclen == 0 || pos + reclen > n as usize {
                break;
            }
            // Extract null-terminated name starting at offset 19.
            let name_start = pos + 19;
            let name_end = buf[name_start..pos + reclen]
                .iter()
                .position(|&b| b == 0)
                .map(|i| name_start + i)
                .unwrap_or(pos + reclen);
            let name = &buf[name_start..name_end];
            write_all(1, name);
            write_all(1, b"\n");
            pos += reclen;
        }
    }

    libc::close(fd as i32);
}

// ---------------------------------------------------------------------------
// Panic handler
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(2, b"sh: panic\n");
    libc::exit(1)
}
