// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Kernel build script.
//!
//! Builds the `oncrix-init` userspace binary (from the nested
//! `crates/userspace/` workspace) and writes its path to
//! `ONCRIX_INIT_BIN` so the kernel can embed it with `include_bytes!`.
//!
//! Userspace lives in a separate workspace so it does not inherit the
//! kernel's workspace-wide rustflags (`-Tcrates/kernel/linker.ld` and
//! `-Ccode-model=kernel`). The cargo subprocess is invoked from inside
//! `crates/userspace/` with `CARGO_TARGET_X86_64_UNKNOWN_NONE_RUSTFLAGS`
//! overridden so hierarchical config merging cannot leak those kernel
//! flags through.

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

    let userspace_dir = workspace_root.join("crates").join("userspace");

    // Invoke cargo inside the userspace workspace.
    // - `current_dir` lets cargo discover the nested [workspace] manifest.
    // - `RUSTFLAGS` is the only rustflags source that is mutually exclusive
    //   with `target.<triple>.rustflags` in config files: setting it causes
    //   Cargo to ignore the hierarchical config rustflags entirely, so the
    //   root `.cargo/config.toml` kernel linker script and `code-model=kernel`
    //   never reach the userspace compiler invocation.
    // - `CARGO_ENCODED_RUSTFLAGS` is scrubbed because when the parent cargo
    //   is already running a build it sets this variable, and it has higher
    //   precedence than `RUSTFLAGS`.
    let status = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args([
            "build",
            "--release",
            "-p",
            "oncrix-init",
            "--target",
            "x86_64-unknown-none",
        ])
        .current_dir(&userspace_dir)
        .env("RUSTFLAGS", "-C relocation-model=static")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .status()
        .expect("failed to invoke cargo to build oncrix-init");

    if !status.success() {
        panic!("oncrix-init build failed (exit code: {:?})", status.code());
    }

    // Binary lands in crates/userspace/target/x86_64-unknown-none/release/init.
    let init_bin = userspace_dir
        .join("target")
        .join("x86_64-unknown-none")
        .join("release")
        .join("init");

    println!("cargo:rustc-env=ONCRIX_INIT_BIN={}", init_bin.display());
    println!("cargo:rerun-if-changed={}", init_bin.display());
    println!(
        "cargo:rerun-if-changed={}",
        userspace_dir
            .join("init")
            .join("src")
            .join("main.rs")
            .display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        userspace_dir.join("user.ld").display()
    );
}
