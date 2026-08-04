// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! AArch64 transition from EL1 (kernel) to EL0 (user space).
//!
//! The smoke payload has a dedicated RX page at [`EL0_ENTRY_VA`]. Its 16 KiB
//! stack occupies dedicated RW/NX pages ending at [`EL0_STACK_TOP_VA`], with
//! an unmapped guard page between code and stack. [`jump_to_el0`] seeds the
//! exception-return state, clears every general-purpose and SIMD register plus
//! the FP control/status registers, and uses `eret` to enter the payload at
//! EL0t. This one-way confidentiality scrub does not provide SIMD/FP trap or
//! context-switch preservation; that remains separate follow-up work.
//!
//! [`el0_test_entry`] verifies a stack canary, issues `svc #7`, and then issues
//! `svc #8` only after the exception vector has restored its frame and returned
//! to EL0. The two traps therefore prove both directions of the EL0/EL1 round
//! trip without involving a syscall dispatcher.

use oncrix_hal::arch::aarch64::pl011::{PL011_BASE, Pl011};
use oncrix_hal::serial::SerialPort;

/// `SPSR_EL1` value for an exception return to EL0t with DAIF masked.
///
/// - `M[4:0] = 0b00000` -> return to EL0 using `SP_EL0` (EL0t).
/// - `DAIF` (bits `[9:6]`) all set -> Debug, SError, IRQ, and FIQ masked.
///
/// Masking is deliberate for the smoke test so the two SVCs are the only
/// exceptions the round-trip depends on. `PSTATE.I` at EL0 does *not* mask a
/// physical IRQ that targets EL1 (a higher EL), so the caller additionally
/// disarms the generic timer before descending. A real userspace launch would
/// instead clear `I` (bit 7) so the preemptive scheduler keeps ticking.
const SPSR_EL0T_MASKED: u64 = 0x3C0;

/// Exception Class (`ESR_EL1.EC`, bits `[31:26]`) for an `SVC` instruction
/// executed in AArch64 state.
const EC_SVC_AARCH64: u64 = 0x15;

/// SVC immediate emitted when the EL0 stack canary comparison fails.
const SVC_STACK_FAILURE: u16 = 0x0BAD;

/// Size of the static EL0 (user) stack for the smoke test (16 KiB).
const EL0_STACK_SIZE: usize = 16 * 1024;

/// Virtual address of the dedicated RX page containing [`el0_test_entry`].
pub const EL0_ENTRY_VA: u64 = 0xC000_0000;

/// Initial EL0 stack pointer above the dedicated 16 KiB RW/NX stack mapping.
///
/// The stack occupies `0xC000_2000..0xC000_6000`; `0xC000_1000` is an
/// unmapped guard page separating it from the payload's RX page.
pub const EL0_STACK_TOP_VA: u64 = 0xC000_6000;

/// Backing storage for the EL0 smoke-test user stack.
///
/// The linker maps this page-aligned input section into the dedicated RW/NX
/// EL0 stack range. It is mutable because EL0 writes the canary through that
/// mapping; Rust code deliberately takes no reference to the mutable static.
#[repr(C, align(4096))]
struct El0Stack {
    _bytes: [u8; EL0_STACK_SIZE],
}

#[used]
#[unsafe(link_section = ".bss.user")]
static mut EL0_STACK: El0Stack = El0Stack {
    _bytes: [0; EL0_STACK_SIZE],
};

/// Debug helper: write a `u64` as `0x`-prefixed hex to the PL011 console.
fn write_hex(serial: &mut Pl011, value: u64) {
    let _ = serial.write_str("0x");
    let mut buf = [0u8; 16];
    let mut n = value;
    for byte in buf.iter_mut().rev() {
        let digit = (n & 0xF) as u8;
        *byte = if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        };
        n >>= 4;
    }
    let mut start = 0;
    while start < buf.len() - 1 && buf[start] == b'0' {
        start += 1;
    }
    for &byte in &buf[start..] {
        let _ = serial.write_byte(byte);
    }
}

/// Debug helper: write a `u16` as decimal to the PL011 console.
fn write_dec(serial: &mut Pl011, value: u16) {
    if value == 0 {
        let _ = serial.write_byte(b'0');
        return;
    }
    // `u16::MAX` is 65535 -> at most 5 decimal digits.
    let mut buf = [0u8; 5];
    let mut n = value;
    let mut i = buf.len();
    while n > 0 {
        i -= 1;
        buf[i] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    for &byte in &buf[i..] {
        let _ = serial.write_byte(byte);
    }
}

/// Descend to EL0 (user space).
///
/// Seeds the exception-return system registers, clears `x0..x30`, `q0..q31`,
/// `FPCR`, and `FPSR`, then executes `eret`. DAIF remains masked for this
/// deterministic smoke-test scope. After `eret`, the CPU executes `entry` at
/// EL0t using `user_sp`; later exceptions enter EL1 through the installed
/// `VBAR_EL1` vector. This is a one-way confidentiality scrub for the smoke
/// transition; SIMD/FP trap and context-switch save/restore remain follow-up.
///
/// # Safety
///
/// - `entry` must name a valid EL0-accessible executable mapping.
/// - `user_sp` must be 16-byte aligned and backed below by writable EL0 memory.
/// - The EL1 lower-EL synchronous vector must save and restore `x0..x30`,
///   `ELR_EL1`, and `SPSR_EL1` around [`aarch64_handle_sync_lower`].
/// - The caller must ensure no asynchronous source is required while DAIF is
///   masked; the smoke path disarms its timer before calling this function.
pub unsafe fn jump_to_el0(entry: u64, user_sp: u64) -> ! {
    let mut serial = Pl011::new(PL011_BASE);
    let _ = serial.write_str("[ONCRIX/aarch64] Transitioning to EL0...\n");
    let _ = serial.write_str("[debug] entry=");
    write_hex(&mut serial, entry);
    let _ = serial.write_str(" sp=");
    write_hex(&mut serial, user_sp);
    let _ = serial.write_str("\n");

    // SAFETY: The caller guarantees EL1 execution and valid EL0 mappings. All
    // operand-dependent system-register writes complete before the GPR, SIMD,
    // FPCR, and FPSR scrub. The ISB commits the return state before ERET
    // consumes it. ERET selects EL0t with DAIF masked and cannot fall through.
    unsafe {
        core::arch::asm!(
            "msr daifset, #0xf",
            "msr sp_el0, {sp}",
            "msr elr_el1, {entry}",
            "msr spsr_el1, {spsr}",
            "isb",
            "movi v0.2d, #0",
            "movi v1.2d, #0",
            "movi v2.2d, #0",
            "movi v3.2d, #0",
            "movi v4.2d, #0",
            "movi v5.2d, #0",
            "movi v6.2d, #0",
            "movi v7.2d, #0",
            "movi v8.2d, #0",
            "movi v9.2d, #0",
            "movi v10.2d, #0",
            "movi v11.2d, #0",
            "movi v12.2d, #0",
            "movi v13.2d, #0",
            "movi v14.2d, #0",
            "movi v15.2d, #0",
            "movi v16.2d, #0",
            "movi v17.2d, #0",
            "movi v18.2d, #0",
            "movi v19.2d, #0",
            "movi v20.2d, #0",
            "movi v21.2d, #0",
            "movi v22.2d, #0",
            "movi v23.2d, #0",
            "movi v24.2d, #0",
            "movi v25.2d, #0",
            "movi v26.2d, #0",
            "movi v27.2d, #0",
            "movi v28.2d, #0",
            "movi v29.2d, #0",
            "movi v30.2d, #0",
            "movi v31.2d, #0",
            "msr fpcr, xzr",
            "msr fpsr, xzr",
            "mov x0, xzr",
            "mov x1, xzr",
            "mov x2, xzr",
            "mov x3, xzr",
            "mov x4, xzr",
            "mov x5, xzr",
            "mov x6, xzr",
            "mov x7, xzr",
            "mov x8, xzr",
            "mov x9, xzr",
            "mov x10, xzr",
            "mov x11, xzr",
            "mov x12, xzr",
            "mov x13, xzr",
            "mov x14, xzr",
            "mov x15, xzr",
            "mov x16, xzr",
            "mov x17, xzr",
            "mov x18, xzr",
            "mov x19, xzr",
            "mov x20, xzr",
            "mov x21, xzr",
            "mov x22, xzr",
            "mov x23, xzr",
            "mov x24, xzr",
            "mov x25, xzr",
            "mov x26, xzr",
            "mov x27, xzr",
            "mov x28, xzr",
            "mov x29, xzr",
            "mov x30, xzr",
            "eret",
            sp = in(reg) user_sp,
            entry = in(reg) entry,
            spsr = in(reg) SPSR_EL0T_MASKED,
            options(noreturn),
        );
    }
}

/// Synchronous-exception handler for a *lower* Exception Level (EL0).
///
/// The lower-EL synchronous vector calls this function with a saved trap
/// frame. SVC #7 reports the validated stack canary and SVC #8 reports that
/// execution returned to EL0 after SVC #7. Those two expected traps return to
/// the vector so its `eret` can resume EL0. A canary failure, an unexpected
/// SVC, or any other lower-EL synchronous exception reports diagnostics and
/// fail-stops at EL1 rather than repeating a faulting EL0 instruction.
#[unsafe(no_mangle)]
pub extern "C" fn aarch64_handle_sync_lower() {
    let esr: u64;
    // SAFETY: `mrs` from `ESR_EL1` reads the Exception Syndrome Register,
    // which is always accessible at EL1 and has no side effects. It still
    // holds this exception's syndrome because no further exception has been
    // taken since entry (the CPU masks DAIF on exception entry).
    unsafe {
        core::arch::asm!("mrs {}, esr_el1", out(reg) esr, options(nomem, nostack));
    }

    let ec = (esr >> 26) & 0x3F;
    let mut serial = Pl011::new(PL011_BASE);

    if ec != EC_SVC_AARCH64 {
        let far: u64;
        // SAFETY: FAR_EL1 is a side-effect-free EL1 system-register read. Its
        // value is useful for address-related faults and harmless otherwise.
        unsafe {
            core::arch::asm!("mrs {}, far_el1", out(reg) far, options(nomem, nostack));
        }
        let _ = serial.write_str("[ONCRIX/aarch64] lower-EL exception: EC=");
        write_hex(&mut serial, ec);
        let _ = serial.write_str(" ESR=");
        write_hex(&mut serial, esr);
        let _ = serial.write_str(" FAR_EL1=");
        write_hex(&mut serial, far);
        let _ = serial.write_str("\n");
        fail_stop();
    }

    // ESR_EL1.ISS[15:0] contains the immediate from the trapped SVC.
    let imm = (esr & 0xFFFF) as u16;
    match imm {
        7 => {
            let _ = serial.write_str("[ONCRIX/aarch64] EL0 stack canary verified\n");
        }
        8 => {
            let _ = serial.write_str("[ONCRIX/aarch64] EL0 round trip verified\n");
        }
        SVC_STACK_FAILURE => {
            let _ = serial.write_str("[ONCRIX/aarch64] EL0 stack canary FAILED\n");
            fail_stop();
        }
        _ => {
            let _ = serial.write_str("[ONCRIX/aarch64] unexpected EL0 SVC #");
            write_dec(&mut serial, imm);
            let _ = serial.write_str("\n");
            fail_stop();
        }
    }
}

/// Parks the processor at EL1 after an unrecoverable EL0 smoke-test failure.
fn fail_stop() -> ! {
    // SAFETY: A local branch-to-self intentionally prevents return to a
    // faulting or failed EL0 context and does not access memory or the stack.
    unsafe {
        core::arch::asm!("b .", options(noreturn, nostack));
    }
}

/// Self-contained entry point for the dedicated EL0 RX payload page.
///
/// The naked body has no compiler-generated prologue, calls, external branch,
/// or literal pool. It writes and reloads a 64-bit canary through `SP_EL0`,
/// restores SP, and traps with SVC #7 on success. Reaching SVC #8 proves that
/// the first exception frame was restored and `eret` resumed the next EL0
/// instruction. A mismatch uses a distinct SVC and both terminal paths park
/// with a local branch-to-self.
#[unsafe(no_mangle)]
#[unsafe(naked)]
#[unsafe(link_section = ".text.user")]
pub extern "C" fn el0_test_entry() -> ! {
    core::arch::naked_asm!(
        "sub sp, sp, #16",
        "movz x9, #0x454c",
        "movk x9, #0x4958, lsl #16",
        "movk x9, #0x4352, lsl #32",
        "movk x9, #0x4f4e, lsl #48",
        "str x9, [sp]",
        "ldr x10, [sp]",
        "add sp, sp, #16",
        "cmp x9, x10",
        "b.ne 1f",
        "svc #7",
        "svc #8",
        "b .",
        "1:",
        "svc #0xbad",
        "b .",
    );
}
