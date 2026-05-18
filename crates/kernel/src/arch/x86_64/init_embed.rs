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
//! `ONCRIX_SH_BIN`, and `ONCRIX_{ECHO,CAT,TRUE,FALSE,WC,HEAD,TAIL,PWD,ENV,UNAME,YES,CLEAR,WHOAMI,KILL,BASENAME,DIRNAME,SEQ,TEST,TEE,TR,CUT,UNIQ,GREP,PRINTF,SORT,OD,EXPR,TOUCH,CP,RM,MKDIR,CMP,DATE,COMM,PASTE,NL,REV,TAC,XARGS,CKSUM,FOLD,REALPATH,CAL,STAT,WHICH,SUM,UPTIME,FACTOR,EXPAND,UNEXPAND,SPLIT,BASE64,MD5SUM,SHA256SUM,SHA1SUM,SHA512SUM,BASE32,SHA224SUM,SHA384SUM,ID,DD,HOSTNAME,TTY,STRINGS,FILE,FREE,INSTALL,TIMEOUT,LOGNAME}_BIN`;
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

/// The embedded `/bin/sort` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_SORT: &[u8] = include_bytes!(env!("ONCRIX_SORT_BIN"));

/// The embedded `/bin/od` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_OD: &[u8] = include_bytes!(env!("ONCRIX_OD_BIN"));

/// The embedded `/bin/expr` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_EXPR: &[u8] = include_bytes!(env!("ONCRIX_EXPR_BIN"));

/// The embedded `/bin/touch` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_TOUCH: &[u8] = include_bytes!(env!("ONCRIX_TOUCH_BIN"));

/// The embedded `/bin/cp` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_CP: &[u8] = include_bytes!(env!("ONCRIX_CP_BIN"));

/// The embedded `/bin/rm` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_RM: &[u8] = include_bytes!(env!("ONCRIX_RM_BIN"));

/// The embedded `/bin/mkdir` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_MKDIR: &[u8] = include_bytes!(env!("ONCRIX_MKDIR_BIN"));

/// The embedded `/bin/cmp` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_CMP: &[u8] = include_bytes!(env!("ONCRIX_CMP_BIN"));

/// The embedded `/bin/date` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_DATE: &[u8] = include_bytes!(env!("ONCRIX_DATE_BIN"));

/// The embedded `/bin/comm` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_COMM: &[u8] = include_bytes!(env!("ONCRIX_COMM_BIN"));

/// The embedded `/bin/paste` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_PASTE: &[u8] = include_bytes!(env!("ONCRIX_PASTE_BIN"));

/// The embedded `/bin/nl` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_NL: &[u8] = include_bytes!(env!("ONCRIX_NL_BIN"));

/// The embedded `/bin/rev` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_REV: &[u8] = include_bytes!(env!("ONCRIX_REV_BIN"));

/// The embedded `/bin/tac` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_TAC: &[u8] = include_bytes!(env!("ONCRIX_TAC_BIN"));

/// The embedded `/bin/xargs` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_XARGS: &[u8] = include_bytes!(env!("ONCRIX_XARGS_BIN"));

/// The embedded `/bin/cksum` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_CKSUM: &[u8] = include_bytes!(env!("ONCRIX_CKSUM_BIN"));

/// The embedded `/bin/fold` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_FOLD: &[u8] = include_bytes!(env!("ONCRIX_FOLD_BIN"));

/// The embedded `/bin/realpath` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_REALPATH: &[u8] = include_bytes!(env!("ONCRIX_REALPATH_BIN"));

/// The embedded `/bin/cal` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_CAL: &[u8] = include_bytes!(env!("ONCRIX_CAL_BIN"));

/// The embedded `/bin/stat` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_STAT: &[u8] = include_bytes!(env!("ONCRIX_STAT_BIN"));

/// The embedded `/bin/which` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_WHICH: &[u8] = include_bytes!(env!("ONCRIX_WHICH_BIN"));

/// The embedded `/bin/sum` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_SUM: &[u8] = include_bytes!(env!("ONCRIX_SUM_BIN"));

/// The embedded `/bin/uptime` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_UPTIME: &[u8] = include_bytes!(env!("ONCRIX_UPTIME_BIN"));

/// The embedded `/bin/factor` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_FACTOR: &[u8] = include_bytes!(env!("ONCRIX_FACTOR_BIN"));

/// The embedded `/bin/expand` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_EXPAND: &[u8] = include_bytes!(env!("ONCRIX_EXPAND_BIN"));

/// The embedded `/bin/unexpand` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_UNEXPAND: &[u8] = include_bytes!(env!("ONCRIX_UNEXPAND_BIN"));

/// The embedded `/bin/split` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_SPLIT: &[u8] = include_bytes!(env!("ONCRIX_SPLIT_BIN"));

/// The embedded `/bin/base64` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_BASE64: &[u8] = include_bytes!(env!("ONCRIX_BASE64_BIN"));

/// The embedded `/bin/md5sum` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_MD5SUM: &[u8] = include_bytes!(env!("ONCRIX_MD5SUM_BIN"));

/// The embedded `/bin/sha256sum` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_SHA256SUM: &[u8] = include_bytes!(env!("ONCRIX_SHA256SUM_BIN"));

/// The embedded `/bin/sha1sum` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_SHA1SUM: &[u8] = include_bytes!(env!("ONCRIX_SHA1SUM_BIN"));

/// The embedded `/bin/sha512sum` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_SHA512SUM: &[u8] = include_bytes!(env!("ONCRIX_SHA512SUM_BIN"));

/// The embedded `/bin/base32` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_BASE32: &[u8] = include_bytes!(env!("ONCRIX_BASE32_BIN"));

/// The embedded `/bin/sha224sum` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_SHA224SUM: &[u8] = include_bytes!(env!("ONCRIX_SHA224SUM_BIN"));

/// The embedded `/bin/sha384sum` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_SHA384SUM: &[u8] = include_bytes!(env!("ONCRIX_SHA384SUM_BIN"));

/// The embedded `/bin/id` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_ID: &[u8] = include_bytes!(env!("ONCRIX_ID_BIN"));

/// The embedded `/bin/dd` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_DD: &[u8] = include_bytes!(env!("ONCRIX_DD_BIN"));

/// The embedded `/bin/hostname` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_HOSTNAME: &[u8] = include_bytes!(env!("ONCRIX_HOSTNAME_BIN"));

/// The embedded `/bin/tty` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_TTY: &[u8] = include_bytes!(env!("ONCRIX_TTY_BIN"));

/// The embedded `/bin/strings` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_STRINGS: &[u8] = include_bytes!(env!("ONCRIX_STRINGS_BIN"));

/// The embedded `/bin/file` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_FILE: &[u8] = include_bytes!(env!("ONCRIX_FILE_BIN"));

/// The embedded `/bin/free` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_FREE: &[u8] = include_bytes!(env!("ONCRIX_FREE_BIN"));

/// The embedded `/bin/install` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_INSTALL: &[u8] = include_bytes!(env!("ONCRIX_INSTALL_BIN"));

/// The embedded `/bin/timeout` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_TIMEOUT: &[u8] = include_bytes!(env!("ONCRIX_TIMEOUT_BIN"));

/// The embedded `/bin/logname` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_LOGNAME: &[u8] = include_bytes!(env!("ONCRIX_LOGNAME_BIN"));

/// The embedded `/bin/groups` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_GROUPS: &[u8] = include_bytes!(env!("ONCRIX_GROUPS_BIN"));

/// The embedded `/bin/users` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_USERS: &[u8] = include_bytes!(env!("ONCRIX_USERS_BIN"));

/// The embedded `/bin/getent` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_GETENT: &[u8] = include_bytes!(env!("ONCRIX_GETENT_BIN"));

/// The embedded `/bin/nproc` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_NPROC: &[u8] = include_bytes!(env!("ONCRIX_NPROC_BIN"));

/// The embedded `/bin/arch` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_ARCH: &[u8] = include_bytes!(env!("ONCRIX_ARCH_BIN"));

/// The embedded `/bin/pathchk` ELF binary.
#[cfg(feature = "embed-init")]
static EMBEDDED_PATHCHK: &[u8] = include_bytes!(env!("ONCRIX_PATHCHK_BIN"));

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
/// `/bin/uniq`, `/bin/grep`, `/bin/printf`, `/bin/sort`, `/bin/od`,
/// `/bin/expr`, `/bin/touch`, `/bin/cp`, `/bin/rm`, `/bin/mkdir`,
/// `/bin/cmp`, `/bin/date`, `/bin/comm`, `/bin/paste`, `/bin/nl`,
/// `/bin/rev`, `/bin/tac`, `/bin/xargs`, `/bin/cksum`, `/bin/fold`,
/// `/bin/realpath`, `/bin/cal`, `/bin/stat`, `/bin/which`, `/bin/sum`,
/// `/bin/uptime`, `/bin/factor`, `/bin/expand`, `/bin/unexpand`,
/// `/bin/split`, `/bin/base64`, `/bin/md5sum`, `/bin/sha256sum`,
/// `/bin/sha1sum`, `/bin/sha512sum`, `/bin/base32`, `/bin/sha224sum`,
/// `/bin/sha384sum`, `/bin/id`, `/bin/dd`, `/bin/hostname`, `/bin/tty`,
/// `/bin/strings`, `/bin/file`, `/bin/free`, `/bin/install`,
/// `/bin/timeout`, `/bin/logname`.
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
        b"/bin/sort" | b"sort" => Some(EMBEDDED_SORT),
        b"/bin/od" | b"od" => Some(EMBEDDED_OD),
        b"/bin/expr" | b"expr" => Some(EMBEDDED_EXPR),
        b"/bin/touch" | b"touch" => Some(EMBEDDED_TOUCH),
        b"/bin/cp" | b"cp" => Some(EMBEDDED_CP),
        b"/bin/rm" | b"rm" => Some(EMBEDDED_RM),
        b"/bin/mkdir" | b"mkdir" => Some(EMBEDDED_MKDIR),
        b"/bin/cmp" | b"cmp" => Some(EMBEDDED_CMP),
        b"/bin/date" | b"date" => Some(EMBEDDED_DATE),
        b"/bin/comm" | b"comm" => Some(EMBEDDED_COMM),
        b"/bin/paste" | b"paste" => Some(EMBEDDED_PASTE),
        b"/bin/nl" | b"nl" => Some(EMBEDDED_NL),
        b"/bin/rev" | b"rev" => Some(EMBEDDED_REV),
        b"/bin/tac" | b"tac" => Some(EMBEDDED_TAC),
        b"/bin/xargs" | b"xargs" => Some(EMBEDDED_XARGS),
        b"/bin/cksum" | b"cksum" => Some(EMBEDDED_CKSUM),
        b"/bin/fold" | b"fold" => Some(EMBEDDED_FOLD),
        b"/bin/realpath" | b"realpath" => Some(EMBEDDED_REALPATH),
        b"/bin/cal" | b"cal" => Some(EMBEDDED_CAL),
        b"/bin/stat" | b"stat" => Some(EMBEDDED_STAT),
        b"/bin/which" | b"which" => Some(EMBEDDED_WHICH),
        b"/bin/sum" | b"sum" => Some(EMBEDDED_SUM),
        b"/bin/uptime" | b"uptime" => Some(EMBEDDED_UPTIME),
        b"/bin/factor" | b"factor" => Some(EMBEDDED_FACTOR),
        b"/bin/expand" | b"expand" => Some(EMBEDDED_EXPAND),
        b"/bin/unexpand" | b"unexpand" => Some(EMBEDDED_UNEXPAND),
        b"/bin/split" | b"split" => Some(EMBEDDED_SPLIT),
        b"/bin/base64" | b"base64" => Some(EMBEDDED_BASE64),
        b"/bin/md5sum" | b"md5sum" => Some(EMBEDDED_MD5SUM),
        b"/bin/sha256sum" | b"sha256sum" => Some(EMBEDDED_SHA256SUM),
        b"/bin/sha1sum" | b"sha1sum" => Some(EMBEDDED_SHA1SUM),
        b"/bin/sha512sum" | b"sha512sum" => Some(EMBEDDED_SHA512SUM),
        b"/bin/base32" | b"base32" => Some(EMBEDDED_BASE32),
        b"/bin/sha224sum" | b"sha224sum" => Some(EMBEDDED_SHA224SUM),
        b"/bin/sha384sum" | b"sha384sum" => Some(EMBEDDED_SHA384SUM),
        b"/bin/id" | b"id" => Some(EMBEDDED_ID),
        b"/bin/dd" | b"dd" => Some(EMBEDDED_DD),
        b"/bin/hostname" | b"hostname" => Some(EMBEDDED_HOSTNAME),
        b"/bin/tty" | b"tty" => Some(EMBEDDED_TTY),
        b"/bin/strings" | b"strings" => Some(EMBEDDED_STRINGS),
        b"/bin/file" | b"file" => Some(EMBEDDED_FILE),
        b"/bin/free" | b"free" => Some(EMBEDDED_FREE),
        b"/bin/install" | b"install" => Some(EMBEDDED_INSTALL),
        b"/bin/timeout" | b"timeout" => Some(EMBEDDED_TIMEOUT),
        b"/bin/logname" | b"logname" => Some(EMBEDDED_LOGNAME),
        b"/bin/groups" | b"groups" => Some(EMBEDDED_GROUPS),
        b"/bin/users" | b"users" => Some(EMBEDDED_USERS),
        b"/bin/getent" | b"getent" => Some(EMBEDDED_GETENT),
        b"/bin/nproc" | b"nproc" => Some(EMBEDDED_NPROC),
        b"/bin/arch" | b"arch" => Some(EMBEDDED_ARCH),
        b"/bin/pathchk" | b"pathchk" => Some(EMBEDDED_PATHCHK),
        _ => None,
    }
}

/// Placeholder when `embed-init` is disabled — always `None`.
#[cfg(not(feature = "embed-init"))]
pub fn embedded_lookup(_path: &[u8]) -> Option<&'static [u8]> {
    None
}
