// Copyright 2026 ONCRIX Contributors
// SPDX-License-Identifier: Apache-2.0

//! Embedded `init` and `/bin/sh` ELF blobs.
//!
//! Phase 13 stripped this module of its page-table-patching logic. The
//! singleton `USER_PT` / `USER_LOAD_REGION` plus
//! `install_user_mapping` / `load_init_elf` / `load_sh_elf` paths are
//! all gone — they were the source of the post-`wait4` `#UD` because
//! the parent's text was overwritten by the child's `execve`. Per-
//! process address spaces now live in
//! [`oncrix_mm::address_space::UserAddressSpace`], allocated through
//! [`crate::frame_alloc`], and installed at `PD_0_1G[2]` via
//! [`crate::arch::x86_64::init::install_user_pt`].
//!
//! What remains here is the build-time embedding of the userspace ELF
//! binaries. `kernel/build.rs` exports `ONCRIX_INIT_BIN`,
//! `ONCRIX_SH_BIN`, and `ONCRIX_{ECHO,CAT,TRUE,FALSE,WC,HEAD,TAIL,PWD,ENV,UNAME,YES,CLEAR,WHOAMI,KILL,BASENAME,DIRNAME,SEQ,TEST,TEE,TR,CUT,UNIQ,GREP,PRINTF}_BIN`;
//! this module includes the bytes and exposes [`embedded_init_elf`] /
//! [`embedded_sh_elf`] for the boot path and [`embedded_lookup`] for
//! `sys_execve` to resolve `/bin/<name>` paths against.

// ---------------------------------------------------------------------------
// Embedded binaries
// ---------------------------------------------------------------------------

/// The embedded `init` ELF binary.
///
/// Present only when the `embed-init` feature is enabled and
/// `ONCRIX_INIT_BIN` was set by `build.rs`.
#[cfg(feature = "embed-init")]
static EMBEDDED_INIT: &[u8] = include_bytes!(env!("ONCRIX_INIT_BIN"));

/// The embedded `/bin/sh` ELF binary.
///
/// Built alongside `init` by `build.rs` when `embed-init` is active.
/// Returned by [`embedded_sh_elf`] so that `sys_execve("/bin/sh", …)`
/// can replace the calling process image with it.
#[cfg(feature = "embed-init")]
static EMBEDDED_SH: &[u8] = include_bytes!(env!("ONCRIX_SH_BIN"));

/// The embedded `/bin/echo` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_ECHO: &[u8] = include_bytes!(env!("ONCRIX_ECHO_BIN"));

/// The embedded `/bin/cat` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_CAT: &[u8] = include_bytes!(env!("ONCRIX_CAT_BIN"));

/// The embedded `/bin/true` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_TRUE: &[u8] = include_bytes!(env!("ONCRIX_TRUE_BIN"));

/// The embedded `/bin/false` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_FALSE: &[u8] = include_bytes!(env!("ONCRIX_FALSE_BIN"));

/// The embedded `/bin/wc` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_WC: &[u8] = include_bytes!(env!("ONCRIX_WC_BIN"));

/// The embedded `/bin/head` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_HEAD: &[u8] = include_bytes!(env!("ONCRIX_HEAD_BIN"));

/// The embedded `/bin/tail` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_TAIL: &[u8] = include_bytes!(env!("ONCRIX_TAIL_BIN"));

/// The embedded `/bin/pwd` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_PWD: &[u8] = include_bytes!(env!("ONCRIX_PWD_BIN"));

/// The embedded `/bin/env` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_ENV: &[u8] = include_bytes!(env!("ONCRIX_ENV_BIN"));

/// The embedded `/bin/uname` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_UNAME: &[u8] = include_bytes!(env!("ONCRIX_UNAME_BIN"));

/// The embedded `/bin/ls` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_LS: &[u8] = include_bytes!(env!("ONCRIX_LS_BIN"));

/// The embedded `/bin/sigtest` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_SIGTEST: &[u8] = include_bytes!(env!("ONCRIX_SIGTEST_BIN"));

/// The embedded `/bin/mmaptest` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_MMAPTEST: &[u8] = include_bytes!(env!("ONCRIX_MMAPTEST_BIN"));

/// The embedded `/bin/sleep` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_SLEEP: &[u8] = include_bytes!(env!("ONCRIX_SLEEP_BIN"));

/// The embedded `/bin/yes` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_YES: &[u8] = include_bytes!(env!("ONCRIX_YES_BIN"));

/// The embedded `/bin/clear` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_CLEAR: &[u8] = include_bytes!(env!("ONCRIX_CLEAR_BIN"));

/// The embedded `/bin/whoami` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_WHOAMI: &[u8] = include_bytes!(env!("ONCRIX_WHOAMI_BIN"));

/// The embedded `/bin/kill` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_KILL: &[u8] = include_bytes!(env!("ONCRIX_KILL_BIN"));

/// The embedded `/bin/basename` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_BASENAME: &[u8] = include_bytes!(env!("ONCRIX_BASENAME_BIN"));

/// The embedded `/bin/dirname` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_DIRNAME: &[u8] = include_bytes!(env!("ONCRIX_DIRNAME_BIN"));

/// The embedded `/bin/seq` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_SEQ: &[u8] = include_bytes!(env!("ONCRIX_SEQ_BIN"));

/// The embedded `/bin/test` ELF binary (also resolvable as `[`).
#[cfg(feature = "embed-init")]
static EMBEDDED_TEST: &[u8] = include_bytes!(env!("ONCRIX_TEST_BIN"));

/// The embedded `/bin/tee` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_TEE: &[u8] = include_bytes!(env!("ONCRIX_TEE_BIN"));

/// The embedded `/bin/tr` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_TR: &[u8] = include_bytes!(env!("ONCRIX_TR_BIN"));

/// The embedded `/bin/cut` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_CUT: &[u8] = include_bytes!(env!("ONCRIX_CUT_BIN"));

/// The embedded `/bin/uniq` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_UNIQ: &[u8] = include_bytes!(env!("ONCRIX_UNIQ_BIN"));

/// The embedded `/bin/grep` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_GREP: &[u8] = include_bytes!(env!("ONCRIX_GREP_BIN"));

/// The embedded `/bin/printf` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_PRINTF: &[u8] = include_bytes!(env!("ONCRIX_PRINTF_BIN"));

// ---------------------------------------------------------------------------
// Signal-return trampoline
// ---------------------------------------------------------------------------

/// User VA at which the per-process `rt_sigreturn` trampoline is mapped.
///
/// One page below the System V initial-stack page (0x5FF000), still
/// inside the per-process 2 MiB region (0x400000..0x600000), so it is
/// always present in the running process's address space and shares the
/// same physical backing as the rest of the user mapping.
pub const SIGRETURN_TRAMPOLINE_VA: u64 = 0x0000_0000_005F_E000;

/// Offset of [`SIGRETURN_TRAMPOLINE_VA`] inside the 2 MiB user backing
/// region (which starts at user VA 0x400000).
pub const SIGRETURN_TRAMPOLINE_OFFSET: usize = 0x1FE000;

/// Bytes of the in-process `rt_sigreturn` trampoline.
///
/// Disassembly:
/// ```text
/// 48 89 e7           mov    %rsp, %rdi         ; frame VA = current RSP
/// b8 0f 00 00 00     mov    $0xf, %eax         ; SYS_RT_SIGRETURN = 15
/// 0f 05              syscall
/// f4                 hlt                       ; defensive
/// ```
///
/// On entry the user stack's top contains the kernel-pushed
/// `UserSignalFrame` (the handler popped its pretcode return address
/// via `ret`, so RSP now points at the start of the frame). Passing
/// RSP into RDI as the syscall argument lets the kernel both validate
/// the frame's magic word and restore the saved register state.
pub const SIGRETURN_TRAMPOLINE_BYTES: [u8; 11] = [
    0x48, 0x89, 0xe7, // mov rsp, rdi
    0xb8, 0x0f, 0x00, 0x00, 0x00, // mov $0xf, %eax
    0x0f, 0x05, // syscall
    0xf4, // hlt
];

// ---------------------------------------------------------------------------
// Public accessors
// ---------------------------------------------------------------------------

/// Return the embedded `init` ELF bytes.
///
/// Returns `Some(&[u8])` when the `embed-init` feature is enabled and
/// `ONCRIX_INIT_BIN` was set by `build.rs`. Returns `None` otherwise.
#[cfg(feature = "embed-init")]
pub fn embedded_init_elf() -> Option<&'static [u8]> {
    Some(EMBEDDED_INIT)
}

/// Placeholder when `embed-init` is disabled — always `None`.
#[cfg(not(feature = "embed-init"))]
pub fn embedded_init_elf() -> Option<&'static [u8]> {
    None
}

/// Return the embedded `/bin/sh` ELF bytes.
///
/// Returns `Some(&[u8])` when the `embed-init` feature is enabled and
/// `ONCRIX_SH_BIN` was set by `build.rs`. Returns `None` otherwise.
#[cfg(feature = "embed-init")]
pub fn embedded_sh_elf() -> Option<&'static [u8]> {
    Some(EMBEDDED_SH)
}

/// Placeholder when `embed-init` is disabled — always `None`.
#[cfg(not(feature = "embed-init"))]
pub fn embedded_sh_elf() -> Option<&'static [u8]> {
    None
}

/// Resolve a POSIX-style path (or bare command name) to an embedded
/// ELF blob.
///
/// Recognised paths: `/bin/sh`, `/bin/echo`, `/bin/cat`, `/bin/true`,
/// `/bin/false`, `/bin/wc`, `/bin/head`, `/bin/tail`, `/bin/pwd`,
/// `/bin/env`, `/bin/uname`, `/bin/yes`, `/bin/clear`, `/bin/whoami`,
/// `/bin/kill`, `/bin/basename`, `/bin/dirname`, `/bin/seq`,
/// `/bin/test` (also `/bin/[`), `/bin/tee`, `/bin/tr`, `/bin/cut`,
/// `/bin/uniq`, `/bin/grep`, `/bin/printf`.
/// Bare names without a leading `/` match the
/// same set — a primitive `$PATH=/bin` shortcut so `sh`'s execve from a
/// builtin's `argv[0] = "echo"` resolves without prefixing.
///
/// Returns `None` for any unknown path, or whenever the `embed-init`
/// feature is disabled.
#[cfg(feature = "embed-init")]
pub fn embedded_lookup(path: &[u8]) -> Option<&'static [u8]> {
    match path {
        b"/bin/sh" | b"sh" => Some(EMBEDDED_SH),
        b"/bin/echo" | b"echo" => Some(EMBEDDED_ECHO),
        b"/bin/cat" | b"cat" => Some(EMBEDDED_CAT),
        b"/bin/true" | b"true" => Some(EMBEDDED_TRUE),
        b"/bin/false" | b"false" => Some(EMBEDDED_FALSE),
        b"/bin/wc" | b"wc" => Some(EMBEDDED_WC),
        b"/bin/head" | b"head" => Some(EMBEDDED_HEAD),
        b"/bin/tail" | b"tail" => Some(EMBEDDED_TAIL),
        b"/bin/pwd" | b"pwd" => Some(EMBEDDED_PWD),
        b"/bin/env" | b"env" => Some(EMBEDDED_ENV),
        b"/bin/uname" | b"uname" => Some(EMBEDDED_UNAME),
        b"/bin/ls" | b"ls" => Some(EMBEDDED_LS),
        b"/bin/sigtest" | b"sigtest" => Some(EMBEDDED_SIGTEST),
        b"/bin/mmaptest" | b"mmaptest" => Some(EMBEDDED_MMAPTEST),
        b"/bin/sleep" | b"sleep" => Some(EMBEDDED_SLEEP),
        b"/bin/yes" | b"yes" => Some(EMBEDDED_YES),
        b"/bin/clear" | b"clear" => Some(EMBEDDED_CLEAR),
        b"/bin/whoami" | b"whoami" => Some(EMBEDDED_WHOAMI),
        b"/bin/kill" | b"kill" => Some(EMBEDDED_KILL),
        b"/bin/basename" | b"basename" => Some(EMBEDDED_BASENAME),
        b"/bin/dirname" | b"dirname" => Some(EMBEDDED_DIRNAME),
        b"/bin/seq" | b"seq" => Some(EMBEDDED_SEQ),
        b"/bin/test" | b"test" | b"/bin/[" | b"[" => Some(EMBEDDED_TEST),
        b"/bin/tee" | b"tee" => Some(EMBEDDED_TEE),
        b"/bin/tr" | b"tr" => Some(EMBEDDED_TR),
        b"/bin/cut" | b"cut" => Some(EMBEDDED_CUT),
        b"/bin/uniq" | b"uniq" => Some(EMBEDDED_UNIQ),
        b"/bin/grep" | b"grep" => Some(EMBEDDED_GREP),
        b"/bin/printf" | b"printf" => Some(EMBEDDED_PRINTF),
        _ => None,
    }
}

/// Placeholder when `embed-init` is disabled — always `None`.
#[cfg(not(feature = "embed-init"))]
pub fn embedded_lookup(_path: &[u8]) -> Option<&'static [u8]> {
    None
}
