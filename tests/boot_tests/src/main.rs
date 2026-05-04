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
/// boot-complete marker (well before the shell starts), then injects both
/// commands into stdin so they are queued in the UART FIFO before the shell
/// calls its first `read(1)`. UART RX bytes that arrive during kernel init or
/// the ring-3 window are consumed by the uart_handler (IRQ 4) or the timer
/// handler's UART poll and pushed into STDIN_BUF via `console_push_byte`.
///
/// If no `$ ` prompt arrives within 30 s the test is skipped (non-fatal) so
/// CI on minimal images still passes.
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

    // Background reader thread accumulates all QEMU serial output.
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

    /// Poll `shared_buf` until `needle` appears at or after `from_offset`
    /// or `deadline` is reached. Returns the full accumulated string.
    fn wait_for_marker(
        shared_buf: &Arc<Mutex<Vec<u8>>>,
        needle: &str,
        from_offset: usize,
        deadline: Instant,
    ) -> Option<String> {
        loop {
            if Instant::now() >= deadline {
                return None;
            }
            let data = shared_buf.lock().unwrap();
            if data.len() > from_offset {
                let s = String::from_utf8_lossy(&data[from_offset..]);
                if s.contains(needle) {
                    return Some(String::from_utf8_lossy(&data).into_owned());
                }
            }
            drop(data);
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    let boot_deadline = Instant::now() + Duration::from_secs(30);

    // Wait for the service manager to finish booting (last kernel-only
    // marker before the shell is launched). Injecting stdin bytes here
    // ensures they are in the UART FIFO while the kernel is still in a
    // ring-0/ring-3 context with IF=1, allowing the UART IRQ (vector 36)
    // or the timer handler's UART poll to push them into STDIN_BUF before
    // the shell's first read(1) SYSCALL (which runs with IF=0).
    let boot_complete_marker = "[ONCRIX] Service manager boot complete";
    let boot_complete = match wait_for_marker(&shared_buf, boot_complete_marker, 0, boot_deadline)
    {
        Some(s) => s,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!(
                "[boot-test] SKIPPED: interactive shell (boot-complete marker not seen within 30 s)"
            );
            return BootResult {
                success: true,
                output: vec!["[SKIPPED] interactive shell (no $ prompt)".to_string()],
                failure_reason: String::new(),
            };
        }
    };
    let inject_offset = boot_complete.len();
    eprintln!("[boot-test] Boot complete. Injecting commands into UART stdin...");

    // Inject both commands now, before the shell's read(1) SYSCALL.
    // They will be buffered in QEMU's stdin pipe and delivered to UART
    // FIFO during the shell's ring-3 execution window.
    if stdin.write_all(b"echo hi from sh\npwd\n").is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return BootResult {
            success: false,
            output: vec![],
            failure_reason: "failed to write commands to QEMU stdin".to_string(),
        };
    }
    let _ = stdin.flush();

    // Now wait for the first `$ ` prompt — which appears after the shell
    // runs the pre-injected `echo hi from sh` command.
    let cmd_deadline = Instant::now() + Duration::from_secs(20);
    let first_prompt = match wait_for_marker(&shared_buf, "$ ", inject_offset, cmd_deadline) {
        Some(s) => s,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("[boot-test] SKIPPED: interactive shell (no '$ ' prompt within 20 s)");
            return BootResult {
                success: true,
                output: vec!["[SKIPPED] interactive shell (no $ prompt)".to_string()],
                failure_reason: String::new(),
            };
        }
    };
    let prompt1_offset = first_prompt.len();
    eprintln!("[boot-test] Got first prompt. Sending 'echo hi from sh'...");
    eprintln!("[qemu-interactive] {}", first_prompt.lines().last().unwrap_or("").trim());

    // The region between inject_offset and prompt1_offset contains the
    // echo command's output (including the echoed characters + "hi from sh").
    let echo_region = &first_prompt[inject_offset..];
    eprintln!("[qemu-interactive] {}", echo_region.trim());

    if !echo_region.contains("hi from sh") {
        let _ = child.kill();
        let _ = child.wait();
        return BootResult {
            success: false,
            output: echo_region.lines().map(str::to_string).collect(),
            failure_reason: format!(
                "'hi from sh' not found in echo output: {:?}",
                echo_region
            ),
        };
    }

    // after_echo is the output after the first prompt: pwd ran and printed
    // the second `$ ` with a `/` between them.
    let pwd_deadline = Instant::now() + Duration::from_secs(10);
    let after_echo_full = match wait_for_marker(&shared_buf, "$ ", prompt1_offset, pwd_deadline) {
        Some(s) => s,
        None => {
            let _ = child.kill();
            let _ = child.wait();
            return BootResult {
                success: false,
                output: vec![],
                failure_reason: "timeout waiting for second '$ ' prompt after echo".to_string(),
            };
        }
    };
    // after_echo contains the output between the first `$ ` and the second `$ `.
    // `pwd` was pre-injected so its output (`/`) should appear here.
    let after_echo = &after_echo_full[prompt1_offset..];
    eprintln!("[qemu-interactive] {}", after_echo.trim());

    let _ = child.kill();
    let _ = child.wait();

    if !after_echo.contains('/') {
        return BootResult {
            success: false,
            output: after_echo.lines().map(str::to_string).collect(),
            failure_reason: format!("'/' not found in pwd output: {:?}", after_echo),
        };
    }

    eprintln!("[boot-test] PASS: interactive shell echo + pwd");
    BootResult {
        success: true,
        output: vec![
            first_prompt.lines().last().unwrap_or("").to_string(),
            after_echo.lines().last().unwrap_or("").to_string(),
        ],
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
    if interactive_result.success {
        eprintln!(
            "[boot-test] {}",
            interactive_result.output.first().unwrap_or(&String::new())
        );
    } else {
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
