// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Build script for `oncrix-init`.
//!
//! Applies the user-space linker script so the binary is linked at 0x400000
//! instead of the kernel's higher-half address, overriding the workspace-wide
//! `-Tcrates/kernel/linker.ld` from `.cargo/config.toml`.

fn main() {
    // Override the kernel linker script with the user-space one.
    println!(
        "cargo:rustc-link-arg=-T{}",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../user.ld")
    );
    // Re-run only if the linker script changes.
    println!(
        "cargo:rerun-if-changed={}",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../user.ld")
    );
}
