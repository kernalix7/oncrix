// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! ONCRIX `mmap(2)` end-to-end smoke test (anonymous PROT_READ|PROT_WRITE).
//!
//! Verifies that:
//!   1. `mmap(NULL, 8192, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)`
//!      returns a pointer inside the per-process anonymous mmap window
//!      (`[0x600000, 0x800000)`).
//!   2. The returned pages are writable by user code.
//!   3. Reads observe the values just written (no aliasing/zeroing bug).
//!
//! Reports `[mmaptest] PASS` to fd 1 on success, or `[mmaptest] FAIL …`
//! to fd 2 on the first failed check. Exits 0 / 1 to match.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use oncrix_ulibc as libc;

// ---------------------------------------------------------------------------
// Entry point — naked so `[rsp]` reads argc, not a Rust local.
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
#[unsafe(naked)]
pub extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, [rsp]",
        "lea rsi, [rsp + 8]",
        "call {main}",
        "ud2",
        main = sym mmaptest_main,
    );
}

// ---------------------------------------------------------------------------
// Test logic
// ---------------------------------------------------------------------------

const MMAP_BASE: u64 = 0x0060_0000;
const MMAP_END: u64 = 0x0080_0000;
const MAP_LEN: usize = 8192;
const PATTERN_A: u32 = 0x1234_5678;
const PATTERN_B: u32 = 0xDEAD_BEEF;

extern "C" fn mmaptest_main(_argc: usize, _argv: *const *const u8) -> ! {
    write_all(1, b"[mmaptest] start\n");

    let prot = (libc::PROT_READ | libc::PROT_WRITE) as i32;
    let flags = (libc::MAP_ANONYMOUS | libc::MAP_PRIVATE) as i32;
    // SAFETY: anonymous + private + fd=-1 + off=0 + addr=NULL is the
    // form the kernel accepts in this phase.
    let p = unsafe { libc::mmap(core::ptr::null_mut(), MAP_LEN, prot, flags, -1, 0) };
    if p == libc::MAP_FAILED || p.is_null() {
        write_all(2, b"[mmaptest] FAIL mmap returned MAP_FAILED\n");
        libc::exit(1);
    }

    let addr = p as u64;
    if !(MMAP_BASE..MMAP_END).contains(&addr) {
        write_all(2, b"[mmaptest] FAIL pointer outside mmap window\n");
        libc::exit(1);
    }

    // Write two markers, one near the start and one a kilobyte in.
    // SAFETY: `p` points at the freshly mapped, RW pages; we touch
    // bytes 0..4 and 1024..1028 which are well inside MAP_LEN (8192).
    unsafe {
        let p32 = p.cast::<u32>();
        p32.write_volatile(PATTERN_A);
        p32.add(256).write_volatile(PATTERN_B);
    }

    // Read them back to confirm the mapping is real.
    // SAFETY: same region as the writes above.
    let (a, b) = unsafe {
        let p32 = p.cast::<u32>();
        (p32.read_volatile(), p32.add(256).read_volatile())
    };
    if a != PATTERN_A || b != PATTERN_B {
        write_all(2, b"[mmaptest] FAIL readback mismatch\n");
        libc::exit(1);
    }

    write_all(1, b"[mmaptest] PASS\n");
    libc::exit(0);
}

// ---------------------------------------------------------------------------
// I/O helpers
// ---------------------------------------------------------------------------

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

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(2, b"[mmaptest] panic\n");
    libc::exit(1);
}
