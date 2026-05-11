// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Build script for `oncrix-install`.

fn main() {
    println!(
        "cargo:rustc-link-arg=-T{}",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../user.ld")
    );
    println!(
        "cargo:rerun-if-changed={}",
        concat!(env!("CARGO_MANIFEST_DIR"), "/../user.ld")
    );
}
