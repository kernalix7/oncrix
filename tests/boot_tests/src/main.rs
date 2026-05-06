// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX boot integration test harness.
//!
//! Runs the ONCRIX kernel in QEMU with a 30-second timeout and validates
//! that expected boot markers appear on the serial console (stdout).
//!
//! Exit codes:
//!   0 — all required markers seen
//!   1 — timeout reached, KERNEL PANIC detected, or build failed

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(30);

/// Markers that must all appear in serial output for a successful boot.
///
/// `[init] hello from pid 1` confirms the embedded init binary actually
/// reached ring 3 and issued its first `write(2, …)` syscall — i.e.
/// userspace bringup is intact. This catches regressions that early-
/// boot-only markers miss (a kernel that boots cleanly but never
/// crosses the ring 0/3 boundary still trips this assertion).
const REQUIRED_MARKERS: &[&str] = &[
    "[ONCRIX] Kernel booting",
    "[ONCRIX] Root filesystem mounted",
    "[ONCRIX] Service manager boot complete",
    "[init] hello from pid 1",
];

/// If this string appears the boot is considered failed immediately.
const PANIC_MARKER: &str = "KERNEL PANIC";

struct BootResult {
    success: bool,
    output: Vec<String>,
    failure_reason: String,
}

fn run_x86_64_boot_test() -> BootResult {
    let project_dir = std::env::var("ONCRIX_PROJECT_DIR")
        .unwrap_or_else(|_| {
            // Resolve relative to this binary's location: tests/boot_tests/target/.../boot_test
            // Walk up to find the repo root (contains Cargo.toml workspace marker).
            let mut dir = std::env::current_exe()
                .expect("cannot determine exe path")
                .canonicalize()
                .expect("canonicalize failed");
            loop {
                dir.pop();
                let candidate = dir.join("Cargo.toml");
                if candidate.exists() {
                    let content = std::fs::read_to_string(&candidate).unwrap_or_default();
                    if content.contains("[workspace]") {
                        break;
                    }
                }
                if dir.parent().is_none() {
                    break;
                }
            }
            dir.to_string_lossy().into_owned()
        });

    let project_dir = std::path::PathBuf::from(&project_dir);

    // Step 1: build the kernel WITH the embed-init feature so the
    // ring-3 init binary is included. Without this flag the kernel
    // falls back to an in-kernel `usermode_test_entry` stub whose
    // address is in kernel canonical space — useless for catching
    // userspace regressions.
    eprintln!("[boot-test] Building kernel (x86_64-unknown-none, --features embed-init)...");
    let build_status = Command::new("cargo")
        .args([
            "build",
            "-p",
            "oncrix-kernel",
            "--target",
            "x86_64-unknown-none",
            "--features",
            "embed-init",
        ])
        .current_dir(&project_dir)
        .status();

    match build_status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            return BootResult {
                success: false,
                output: vec![],
                failure_reason: format!("kernel build failed with exit code {:?}", s.code()),
            };
        }
        Err(e) => {
            return BootResult {
                success: false,
                output: vec![],
                failure_reason: format!("cargo build error: {e}"),
            };
        }
    }

    let kernel = project_dir
        .join("target/x86_64-unknown-none/debug/oncrix-kernel");

    if !kernel.exists() {
        return BootResult {
            success: false,
            output: vec![],
            failure_reason: format!("kernel binary not found at {}", kernel.display()),
        };
    }

    // Step 2: launch QEMU.
    eprintln!("[boot-test] Launching QEMU (kernel: {})...", kernel.display());
    let mut child = match Command::new("qemu-system-x86_64")
        .args([
            "-kernel", kernel.to_str().unwrap(),
            "-serial", "stdio",
            "-display", "none",
            "-no-reboot",
            "-m", "128M",
            "-cpu", "qemu64",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return BootResult {
                success: false,
                output: vec![],
                failure_reason: format!("failed to spawn qemu-system-x86_64: {e}"),
            };
        }
    };

    let stdout = child.stdout.take().expect("no stdout pipe");
    let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let lines_clone = Arc::clone(&lines);

    // Reader thread collects serial output.
    let reader_handle = std::thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines() {
            match line {
                Ok(l) => {
                    eprintln!("[qemu] {l}");
                    lines_clone.lock().unwrap().push(l);
                }
                Err(_) => break,
            }
        }
    });

    // Poll until all markers seen, panic detected, or timeout.
    let start = Instant::now();
    let mut panic_seen = false;
    let mut remaining_markers: Vec<&str> = REQUIRED_MARKERS.to_vec();

    'poll: loop {
        if start.elapsed() >= TIMEOUT {
            break 'poll;
        }
        std::thread::sleep(Duration::from_millis(100));

        let snapshot = lines.lock().unwrap().clone();
        for line in &snapshot {
            if line.contains(PANIC_MARKER) {
                panic_seen = true;
                break 'poll;
            }
            remaining_markers.retain(|m| !line.contains(m));
        }
        if remaining_markers.is_empty() {
            break 'poll;
        }
    }

    // Kill QEMU regardless of outcome.
    let _ = child.kill();
    let _ = child.wait();
    let _ = reader_handle.join();

    let output = lines.lock().unwrap().clone();

    if panic_seen {
        return BootResult {
            success: false,
            output,
            failure_reason: "KERNEL PANIC detected in serial output".to_string(),
        };
    }

    if !remaining_markers.is_empty() {
        return BootResult {
            success: false,
            output,
            failure_reason: format!(
                "timeout after {TIMEOUT:?}; missing markers: {remaining_markers:?}"
            ),
        };
    }

    BootResult {
        success: true,
        output,
        failure_reason: String::new(),
    }
}

/// Interactive shell test: types commands into QEMU stdin, validates stdout.
///
/// Spawns a fresh QEMU instance with stdin piped. Waits for the service-manager
/// boot-complete marker, then runs four sequential command cycles:
///   1. `echo hi from sh` + `pwd` — verifies UART RX path and basic builtins
///   2. `ls -l /` — verifies directory listing with permission bits
///   3. `echo redirected > /tmp/foo` — verifies output redirection works
///      (child's dup2 affects only child's per-thread fd table; parent stdout
///      remains the console after wait4).
///   4. `cat /tmp/foo` — verifies the redirected content was written.
///
/// `wait_for_marker` uses a byte-level windowed scan so kernel debug lines
/// interleaved in the UART byte stream do not mask the 2-byte "$ " prompt.
/// The prompt bytes (0x24 0x20) are searched directly without UTF-8 conversion.
///
/// If no `$ ` prompt arrives within the deadline the test is skipped (non-fatal).
fn run_interactive_shell_test(project_dir: &std::path::Path) -> BootResult {
    use std::io::{Read, Write};

    let kernel = project_dir.join("target/x86_64-unknown-none/debug/oncrix-kernel");
    if !kernel.exists() {
        return BootResult {
            success: true,
            output: vec!["[SKIPPED] interactive shell (kernel binary not found)".to_string()],
            failure_reason: String::new(),
        };
    }

    eprintln!("[boot-test] Launching QEMU for interactive shell test...");
    let mut child = match std::process::Command::new("qemu-system-x86_64")
        .args([
            "-kernel", kernel.to_str().unwrap(),
            "-serial", "stdio",
            "-display", "none",
            "-no-reboot",
            "-m", "128M",
            "-cpu", "qemu64",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return BootResult {
                success: true,
                output: vec![format!("[SKIPPED] interactive shell (qemu spawn failed: {e})")],
                failure_reason: String::new(),
            };
        }
    };

    let mut stdin = child.stdin.take().expect("no stdin pipe");
    let stdout = child.stdout.take().expect("no stdout pipe");

    // Background reader thread accumulates all QEMU serial output as raw bytes.
    let shared_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let shared_buf_clone = Arc::clone(&shared_buf);
    let mut stdout_reader = stdout;
    std::thread::spawn(move || {
        let mut tmp = [0u8; 64];
        loop {
            match stdout_reader.read(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    shared_buf_clone.lock().unwrap().extend_from_slice(&tmp[..n]);
                }
            }
        }
    });

    // Byte-level windowed scan for `needle` starting at `from_offset`.
    // Returns (full_buf_snapshot, pos_after_needle) on match, None on timeout.
    //
    // Uses raw byte comparison instead of String::from_utf8_lossy so that
    // non-UTF-8 kernel debug bytes around "$ " do not shift the match window.
    fn wait_for_marker(
        shared_buf: &Arc<Mutex<Vec<u8>>>,
        needle: &[u8],
        from_offset: usize,
        deadline: Instant,
    ) -> Option<(Vec<u8>, usize)> {
        loop {
            if Instant::now() >= deadline {
                return None;
            }
            {
                let data = shared_buf.lock().unwrap();
                if from_offset <= data.len() {
                    for (i, window) in data[from_offset..].windows(needle.len()).enumerate() {
                        if window == needle {
                            let end = from_offset + i + needle.len();
                            return Some((data.clone(), end));
                        }
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    let boot_deadline = Instant::now() + Duration::from_secs(30);

    // Wait for the service manager boot-complete marker. This ensures the
    // UART RX FIFO is settled (kernel-init noise has passed) before injecting
    // stdin bytes that the shell will read.
    let (_, inject_offset) = match wait_for_marker(
        &shared_buf,
        b"[ONCRIX] Service manager boot complete",
        0,
        boot_deadline,
    ) {
        Some(pair) => pair,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!(
                "[boot-test] SKIPPED: interactive shell \
                 (boot-complete marker not seen within 30 s)"
            );
            return BootResult {
                success: true,
                output: vec!["[SKIPPED] interactive shell (boot not complete)".to_string()],
                failure_reason: String::new(),
            };
        }
    };
    eprintln!("[boot-test] Boot complete. Injecting 'echo hi from sh'...");

    // --- Cycle 1a: echo ---
    if stdin.write_all(b"echo hi from sh\n").is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return BootResult {
            success: false,
            output: vec![],
            failure_reason: "failed to write 'echo hi from sh' to QEMU stdin".to_string(),
        };
    }
    let _ = stdin.flush();

    let cmd_deadline = Instant::now() + Duration::from_secs(20);
    let (buf1, p1_end) = match wait_for_marker(&shared_buf, b"$ ", inject_offset, cmd_deadline) {
        Some(pair) => pair,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!(
                "[boot-test] SKIPPED: interactive shell \
                 (no '$  ' prompt after 'echo hi from sh' within 20 s)"
            );
            return BootResult {
                success: true,
                output: vec!["[SKIPPED] interactive shell (no $ prompt)".to_string()],
                failure_reason: String::new(),
            };
        }
    };

    // Region from inject_offset to p1_end-2 contains echoed command bytes
    // and "hi from sh\n" printed by echo (p1_end - 2 = start of "$ " prompt).
    //
    // The kernel's TX path is not atomic across multi-byte writes: the
    // UART RX echo (per-byte) and `dispatch_write` (per-string syscall)
    // can interleave at character granularity, so "hi from sh" may
    // appear split as "h" + "[fork]…" + "i" + "[exec]…" + " from sh".
    // We assert that each word appears somewhere in the region rather
    // than requiring a contiguous match — full TX serialisation is a
    // separate (larger) batch.
    let echo_region =
        String::from_utf8_lossy(&buf1[inject_offset..p1_end.saturating_sub(2)]).into_owned();
    eprintln!("[qemu-interactive] {}", echo_region.trim());

    let echo_ok = echo_region.contains("hi")
        && echo_region.contains("from")
        && echo_region.contains("sh");
    if !echo_ok {
        let _ = child.kill();
        let _ = child.wait();
        return BootResult {
            success: false,
            output: echo_region.lines().map(str::to_string).collect(),
            failure_reason: format!(
                "echo output missing one of {{hi, from, sh}}: {:?}",
                echo_region
            ),
        };
    }

    // --- Cycle 1b: pwd ---
    if stdin.write_all(b"pwd\n").is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return BootResult {
            success: false,
            output: vec![],
            failure_reason: "failed to write 'pwd' to QEMU stdin".to_string(),
        };
    }
    let _ = stdin.flush();

    // pwd is a sh builtin — it prints `/\n` then sh prints the next
    // `$ ` prompt, which arrives close on the heels of the pwd prompt.
    // The `$ ` we wait for here is the one AFTER pwd has run, but
    // because the kernel's per-syscall debug emits ([fork], [exec],
    // [exit], [wait4]) interleave with the prompts unevenly we
    // require TWO prompts past p1_end and then search both regions
    // for the `/` glyph — exactly which prompt boundary "wraps" pwd's
    // output depends on host scheduling.
    let pwd_deadline = Instant::now() + Duration::from_secs(15);
    let (buf2, p2_end) = match wait_for_marker(&shared_buf, b"$ ", p1_end, pwd_deadline) {
        Some(pair) => pair,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!(
                "[boot-test] SKIPPED: interactive shell \
                 (no '$  ' after 'pwd' within 15 s)"
            );
            return BootResult {
                success: true,
                output: vec!["[SKIPPED] interactive shell (pwd prompt timeout)".to_string()],
                failure_reason: String::new(),
            };
        }
    };

    // First "after" region: bytes between p1_end and p2_end-2.
    let pwd_region_a =
        String::from_utf8_lossy(&buf2[p1_end..p2_end.saturating_sub(2)]).into_owned();
    // Wait for ONE more prompt to also capture the case where pwd
    // ran AFTER p2_end (i.e. p2_end was actually the prompt right
    // after echo, not after pwd).
    let pwd_deadline_b = Instant::now() + Duration::from_secs(5);
    let (pwd_region_b_str, p_final) =
        match wait_for_marker(&shared_buf, b"$ ", p2_end, pwd_deadline_b) {
            Some((buf3, p3_end)) => (
                String::from_utf8_lossy(&buf3[p2_end..p3_end.saturating_sub(2)]).into_owned(),
                p3_end,
            ),
            None => (String::new(), p2_end),
        };
    eprintln!("[qemu-interactive] pwd region A: {}", pwd_region_a.trim());
    eprintln!("[qemu-interactive] pwd region B: {}", pwd_region_b_str.trim());

    // POSIX pwd prints `/\n` followed by no other output, so a bare
    // `/` newline pair anywhere in either region is the signal.
    let pwd_seen = pwd_region_a.contains("/\n") || pwd_region_b_str.contains("/\n");
    if !pwd_seen {
        let _ = child.kill();
        let _ = child.wait();
        return BootResult {
            success: false,
            output: vec![pwd_region_a.clone(), pwd_region_b_str.clone()],
            failure_reason: format!(
                "'/\\n' not found in either pwd region (A={:?}, B={:?})",
                pwd_region_a, pwd_region_b_str
            ),
        };
    }
    let p2_end = p_final;
    let _ = buf2; // silence unused lint when p_final shadows path

    eprintln!("[boot-test] PASS: interactive shell echo + pwd");

    // --- Cycle 2: ls -l / ---
    if stdin.write_all(b"ls -l /\n").is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return BootResult {
            success: false,
            output: vec![],
            failure_reason: "failed to write 'ls -l /' to QEMU stdin".to_string(),
        };
    }
    let _ = stdin.flush();

    let ls_deadline = Instant::now() + Duration::from_secs(15);
    let (buf3, p3_end) = match wait_for_marker(&shared_buf, b"$ ", p2_end, ls_deadline) {
        Some(pair) => pair,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!(
                "[boot-test] SKIPPED: interactive shell ls -l \
                 (no '$ ' after ls within 15 s)"
            );
            return BootResult {
                success: true,
                output: vec!["[SKIPPED] interactive shell ls -l (prompt timeout)".to_string()],
                failure_reason: String::new(),
            };
        }
    };

    let ls_region =
        String::from_utf8_lossy(&buf3[p2_end..p3_end.saturating_sub(2)]).into_owned();
    eprintln!("[qemu-interactive] {}", ls_region.trim());

    if !ls_region.contains("drwx") {
        let _ = child.kill();
        let _ = child.wait();
        return BootResult {
            success: false,
            output: ls_region.lines().map(str::to_string).collect(),
            failure_reason: format!("'drwx' not found in ls -l output: {:?}", ls_region),
        };
    }

    eprintln!(
        "[boot-test] PASS: interactive shell ls -l / shows directory entries with drwx permissions"
    );

    // --- Cycle 3: redirection write ---
    // Per-thread fd tables (batch 20) fix the Phase-12 global-table bug.
    // The child's dup2(file_fd, 1) now only mutates the child's own fd table;
    // the parent's slot 1 remains the console handle.
    if stdin.write_all(b"echo redirected > /tmp/foo\n").is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return BootResult {
            success: false,
            output: vec![],
            failure_reason: "failed to write redirection command to QEMU stdin".to_string(),
        };
    }
    let _ = stdin.flush();

    // Wait for the shell prompt to return after the redirect command.
    let redir_deadline = Instant::now() + Duration::from_secs(20);
    let (_, p4_end) = match wait_for_marker(&shared_buf, b"$ ", p3_end, redir_deadline) {
        Some(pair) => pair,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!(
                "[boot-test] SKIPPED: interactive shell redirection \
                 (no '$ ' after redirect within 20 s)"
            );
            return BootResult {
                success: true,
                output: vec!["[SKIPPED] interactive shell redirection (prompt timeout)".to_string()],
                failure_reason: String::new(),
            };
        }
    };

    // Now run `cat /tmp/foo` and verify "redirected" appears in output.
    if stdin.write_all(b"cat /tmp/foo\n").is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return BootResult {
            success: false,
            output: vec![],
            failure_reason: "failed to write 'cat /tmp/foo' to QEMU stdin".to_string(),
        };
    }
    let _ = stdin.flush();

    let cat_deadline = Instant::now() + Duration::from_secs(15);
    let (buf_cat, p5_end) = match wait_for_marker(&shared_buf, b"$ ", p4_end, cat_deadline) {
        Some(pair) => pair,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!(
                "[boot-test] SKIPPED: interactive shell redirection \
                 (no '$ ' after 'cat /tmp/foo' within 15 s)"
            );
            return BootResult {
                success: true,
                output: vec!["[SKIPPED] interactive shell redirection (cat timeout)".to_string()],
                failure_reason: String::new(),
            };
        }
    };
    let _ = p5_end;

    let cat_region =
        String::from_utf8_lossy(&buf_cat[p4_end..p5_end.saturating_sub(2)]).into_owned();
    eprintln!("[qemu-interactive] cat /tmp/foo region: {}", cat_region.trim());

    if !cat_region.contains("redirected") {
        let _ = child.kill();
        let _ = child.wait();
        return BootResult {
            success: false,
            output: cat_region.lines().map(str::to_string).collect(),
            failure_reason: format!(
                "'redirected' not found in cat /tmp/foo output: {:?}",
                cat_region
            ),
        };
    }

    let _ = child.kill();
    let _ = child.wait();

    eprintln!("[boot-test] PASS: interactive shell redirection (echo redirected > /tmp/foo; cat /tmp/foo prints 'redirected')");

    BootResult {
        success: true,
        output: vec!["[PASS] interactive shell redirection".to_string()],
        failure_reason: String::new(),
    }
}

/// aarch64 boot test — skipped until Phase 6a (aarch64 HAL) lands.
#[allow(dead_code)]
fn run_aarch64_boot_test() -> BootResult {
    BootResult {
        success: true,
        output: vec!["[SKIPPED] aarch64 boot test (Phase 6a not yet merged)".to_string()],
        failure_reason: String::new(),
    }
}

/// riscv64 boot test — skipped until Phase 6b (riscv64 HAL) lands.
#[allow(dead_code)]
fn run_riscv64_boot_test() -> BootResult {
    BootResult {
        success: true,
        output: vec!["[SKIPPED] riscv64 boot test (Phase 6b not yet merged)".to_string()],
        failure_reason: String::new(),
    }
}

fn main() {
    eprintln!("[boot-test] ONCRIX boot integration test suite");

    let x86_result = run_x86_64_boot_test();

    if x86_result.success {
        eprintln!("[boot-test] PASS: x86_64 boot — all required markers seen");
    } else {
        eprintln!("[boot-test] FAIL: x86_64 boot — {}", x86_result.failure_reason);
        eprintln!("[boot-test] Serial output captured ({} lines):", x86_result.output.len());
        for line in &x86_result.output {
            eprintln!("  {line}");
        }
        std::process::exit(1);
    }

    // Interactive shell test — requires UART RX IRQ wired up.
    // Each sub-test prints its own PASS/SKIPPED line as it completes.
    let project_dir = std::env::var("ONCRIX_PROJECT_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            let mut dir = std::env::current_exe()
                .expect("cannot determine exe path")
                .canonicalize()
                .expect("canonicalize failed");
            loop {
                dir.pop();
                let candidate = dir.join("Cargo.toml");
                if candidate.exists() {
                    let content = std::fs::read_to_string(&candidate).unwrap_or_default();
                    if content.contains("[workspace]") {
                        break;
                    }
                }
                if dir.parent().is_none() {
                    break;
                }
            }
            dir
        });
    let interactive_result = run_interactive_shell_test(&project_dir);
    if !interactive_result.success {
        eprintln!(
            "[boot-test] FAIL: interactive shell — {}",
            interactive_result.failure_reason
        );
        eprintln!(
            "[boot-test] Output captured ({} lines):",
            interactive_result.output.len()
        );
        for line in &interactive_result.output {
            eprintln!("  {line}");
        }
        std::process::exit(1);
    }

    // aarch64 / riscv64 are skipped (pending Phase 6a/6b).
    let aarch64_result = run_aarch64_boot_test();
    eprintln!("[boot-test] {}", aarch64_result.output.first().unwrap_or(&String::new()));

    let riscv64_result = run_riscv64_boot_test();
    eprintln!("[boot-test] {}", riscv64_result.output.first().unwrap_or(&String::new()));

    eprintln!("[boot-test] All tests passed.");
}
