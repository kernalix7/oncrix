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

    // aarch64 / riscv64 are skipped (pending Phase 6a/6b).
    let aarch64_result = run_aarch64_boot_test();
    eprintln!("[boot-test] {}", aarch64_result.output.first().unwrap_or(&String::new()));

    let riscv64_result = run_riscv64_boot_test();
    eprintln!("[boot-test] {}", riscv64_result.output.first().unwrap_or(&String::new()));

    eprintln!("[boot-test] All tests passed.");
}
