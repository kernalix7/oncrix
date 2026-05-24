// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `/bin/sync` — POSIX `sync(1)` utility.
//!
//! Flushes filesystem buffers via the `sync(2)` syscall (`SYS_SYNC`,
//! number 162). ONCRIX's root filesystem is an in-memory ramfs, so the
//! call always succeeds immediately with nothing to write back.
//!
//! POSIX reference: `.priv-storage/.TheOpenGroup/susv5-html/utilities/sync.html`

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let _ = libc::sync();
    libc::exit(0)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    libc::exit(1)
}
