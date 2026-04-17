// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel build script.
//!
//! Builds the `oncrix-init` userspace binary and writes its path to
//! `ONCRIX_INIT_BIN` so the kernel can embed it with `include_bytes!`.
//!
//! The init binary is built for `x86_64-unknown-none` with the user-space
//! linker script (`crates/userspace/user.ld`), producing an ELF at 0x400000.

use std::{env, path::PathBuf, process::Command};

fn main() {
    // Only build and embed the init binary when the `embed-init` feature is
    // enabled. Without the feature the kernel falls back to the inline
    // `usermode_test_entry` stub, and skipping the nested cargo invocation
    // lets cross-arch builds (aarch64/riscv64) succeed without needing an
    // x86_64 userspace toolchain.
    if env::var_os("CARGO_FEATURE_EMBED_INIT").is_none() {
        return;
    }

    // Locate workspace root (two levels above crates/kernel/).
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_root = manifest_dir
        .parent() // crates/
        .and_then(|p| p.parent()) // workspace root
        .expect("cannot determine workspace root");

    // Build the init binary in release mode so it's smaller.
    let status = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args([
            "build",
            "--release",
            "-p",
            "oncrix-init",
            "--target",
            "x86_64-unknown-none",
        ])
        .current_dir(workspace_root)
        .status()
        .expect("failed to invoke cargo to build oncrix-init");

    if !status.success() {
        panic!("oncrix-init build failed (exit code: {:?})", status.code());
    }

    // The binary lands in <workspace>/target/x86_64-unknown-none/release/init
    let init_bin = workspace_root
        .join("target")
        .join("x86_64-unknown-none")
        .join("release")
        .join("init");

    println!("cargo:rustc-env=ONCRIX_INIT_BIN={}", init_bin.display());
    println!("cargo:rerun-if-changed={}", init_bin.display());
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root
            .join("crates")
            .join("userspace")
            .join("init")
            .join("src")
            .join("main.rs")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        workspace_root
            .join("crates")
            .join("userspace")
            .join("user.ld")
            .display()
    );
}
