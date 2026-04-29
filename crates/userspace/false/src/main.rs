// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/false` — POSIX.1-2024 `false` utility.
//!
//! Exits with exit status 1. Ignores all arguments.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/false.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    libc::exit(1)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libc::exit(1)
}
