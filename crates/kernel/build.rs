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
    let cargo_bin = env::var("CARGO").unwrap_or_else(|_| "cargo".into());

    // Build oncrix-init.
    let status = Command::new(&cargo_bin)
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

    // Build all userspace binaries the kernel embeds and exec()s.
    //
    // Phase 23 expanded the embedded set from `init` + `/bin/sh` to a
    // small POSIX coreutils slice (`echo`, `cat`, `true`, `false`, `wc`,
    // `head`, `tail`, `pwd`, `env`, `uname`).
    // Each invocation produces an ELF in `target/x86_64-unknown-none/release/`
    // that the kernel embeds via `include_bytes!` in `init_embed.rs`.
    let userspace_bins: &[(&str, &str)] = &[
        ("oncrix-sh", "sh"),
        ("oncrix-echo", "echo"),
        ("oncrix-cat", "cat"),
        ("oncrix-true", "true"),
        ("oncrix-false", "false"),
        ("oncrix-wc", "wc"),
        ("oncrix-head", "head"),
        ("oncrix-tail", "tail"),
        ("oncrix-pwd", "pwd"),
        ("oncrix-env", "env"),
        ("oncrix-uname", "uname"),
        ("oncrix-ls", "ls"),
        ("oncrix-sigtest", "sigtest"),
        ("oncrix-mmaptest", "mmaptest"),
        ("oncrix-sleep", "sleep"),
        ("oncrix-yes", "yes"),
        ("oncrix-clear", "clear"),
        ("oncrix-whoami", "whoami"),
        ("oncrix-kill", "kill"),
        ("oncrix-basename", "basename"),
        ("oncrix-dirname", "dirname"),
        ("oncrix-seq", "seq"),
        ("oncrix-test", "test"),
        ("oncrix-tee", "tee"),
        ("oncrix-tr", "tr"),
        ("oncrix-cut", "cut"),
        ("oncrix-uniq", "uniq"),
        ("oncrix-grep", "grep"),
        ("oncrix-printf", "printf"),
        ("oncrix-sort", "sort"),
        ("oncrix-od", "od"),
        ("oncrix-expr", "expr"),
        ("oncrix-touch", "touch"),
        ("oncrix-cp", "cp"),
        ("oncrix-rm", "rm"),
        ("oncrix-mkdir", "mkdir"),
        ("oncrix-cmp", "cmp"),
        ("oncrix-date", "date"),
        ("oncrix-comm", "comm"),
        ("oncrix-paste", "paste"),
        ("oncrix-nl", "nl"),
        ("oncrix-rev", "rev"),
        ("oncrix-tac", "tac"),
        ("oncrix-xargs", "xargs"),
        ("oncrix-cksum", "cksum"),
        ("oncrix-fold", "fold"),
        ("oncrix-realpath", "realpath"),
        ("oncrix-cal", "cal"),
        ("oncrix-stat", "stat"),
        ("oncrix-which", "which"),
        ("oncrix-sum", "sum"),
        ("oncrix-uptime", "uptime"),
        ("oncrix-factor", "factor"),
        ("oncrix-expand", "expand"),
        ("oncrix-unexpand", "unexpand"),
        ("oncrix-split", "split"),
        ("oncrix-base64", "base64"),
        ("oncrix-md5sum", "md5sum"),
        ("oncrix-sha256sum", "sha256sum"),
        ("oncrix-sha1sum", "sha1sum"),
        ("oncrix-sha512sum", "sha512sum"),
        ("oncrix-base32", "base32"),
        ("oncrix-sha224sum", "sha224sum"),
        ("oncrix-sha384sum", "sha384sum"),
        ("oncrix-id", "id"),
        ("oncrix-dd", "dd"),
        ("oncrix-hostname", "hostname"),
        ("oncrix-tty", "tty"),
        ("oncrix-strings", "strings"),
        ("oncrix-file", "file"),
        ("oncrix-free", "free"),
        ("oncrix-install", "install"),
        ("oncrix-timeout", "timeout"),
        ("oncrix-logname", "logname"),
        ("oncrix-groups", "groups"),
        ("oncrix-users", "users"),
        ("oncrix-getent", "getent"),
        ("oncrix-nproc", "nproc"),
        ("oncrix-arch", "arch"),
        ("oncrix-pathchk", "pathchk"),
        ("oncrix-printenv", "printenv"),
        ("oncrix-nohup", "nohup"),
        ("oncrix-mesg", "mesg"),
        ("oncrix-mountpoint", "mountpoint"),
        ("oncrix-lsmod", "lsmod"),
        ("oncrix-nice", "nice"),
        ("oncrix-df", "df"),
        ("oncrix-lscpu", "lscpu"),
        ("oncrix-hostid", "hostid"),
        ("oncrix-who", "who"),
        ("oncrix-last", "last"),
        ("oncrix-lsipc", "lsipc"),
        ("oncrix-ipcs", "ipcs"),
        ("oncrix-locale", "locale"),
        ("oncrix-pidof", "pidof"),
        ("oncrix-ldd", "ldd"),
        ("oncrix-ldconfig", "ldconfig"),
        ("oncrix-vmstat", "vmstat"),
        ("oncrix-passwd", "passwd"),
        ("oncrix-chsh", "chsh"),
        ("oncrix-ulimit", "ulimit"),
        ("oncrix-mount", "mount"),
        ("oncrix-lspci", "lspci"),
        ("oncrix-lsusb", "lsusb"),
        ("oncrix-blkid", "blkid"),
        ("oncrix-lsblk", "lsblk"),
        ("oncrix-swapon", "swapon"),
        ("oncrix-hostnamectl", "hostnamectl"),
        ("oncrix-timedatectl", "timedatectl"),
        ("oncrix-localectl", "localectl"),
        ("oncrix-useradd", "useradd"),
        ("oncrix-userdel", "userdel"),
        ("oncrix-usermod", "usermod"),
        ("oncrix-groupadd", "groupadd"),
        ("oncrix-groupdel", "groupdel"),
        ("oncrix-groupmod", "groupmod"),
        ("oncrix-tput", "tput"),
        ("oncrix-reset", "reset"),
        ("oncrix-tabs", "tabs"),
        ("oncrix-whereis", "whereis"),
        ("oncrix-apropos", "apropos"),
        ("oncrix-whatis", "whatis"),
        ("oncrix-lsattr", "lsattr"),
        ("oncrix-chattr", "chattr"),
        ("oncrix-getfacl", "getfacl"),
        ("oncrix-chmod", "chmod"),
        ("oncrix-chown", "chown"),
        ("oncrix-chgrp", "chgrp"),
        ("oncrix-ln", "ln"),
        ("oncrix-mv", "mv"),
        ("oncrix-mkfifo", "mkfifo"),
        ("oncrix-ifconfig", "ifconfig"),
        ("oncrix-route", "route"),
        ("oncrix-netstat", "netstat"),
        ("oncrix-arp", "arp"),
        ("oncrix-ss", "ss"),
        ("oncrix-ip", "ip"),
        ("oncrix-su", "su"),
        ("oncrix-login", "login"),
        ("oncrix-sudo", "sudo"),
        ("oncrix-write", "write"),
        ("oncrix-wall", "wall"),
        ("oncrix-talk", "talk"),
        ("oncrix-crontab", "crontab"),
        ("oncrix-at", "at"),
        ("oncrix-batch", "batch"),
        ("oncrix-pgrep", "pgrep"),
        ("oncrix-pkill", "pkill"),
        ("oncrix-killall", "killall"),
        ("oncrix-ps", "ps"),
        ("oncrix-top", "top"),
        ("oncrix-pmap", "pmap"),
        ("oncrix-iostat", "iostat"),
        ("oncrix-mpstat", "mpstat"),
        ("oncrix-pidstat", "pidstat"),
        ("oncrix-finger", "finger"),
        ("oncrix-newgrp", "newgrp"),
        ("oncrix-chrt", "chrt"),
        ("oncrix-taskset", "taskset"),
        ("oncrix-ionice", "ionice"),
        ("oncrix-watch", "watch"),
        ("oncrix-setfacl", "setfacl"),
        ("oncrix-chacl", "chacl"),
        ("oncrix-iconv", "iconv"),
        ("oncrix-shutdown", "shutdown"),
        ("oncrix-reboot", "reboot"),
        ("oncrix-halt", "halt"),
        ("oncrix-sync", "sync"),
        ("oncrix-readlink", "readlink"),
    ];
    for (pkg, bin_name) in userspace_bins {
        let status = Command::new(&cargo_bin)
            .args([
                "build",
                "--release",
                "-p",
                pkg,
                "--target",
                "x86_64-unknown-none",
            ])
            .current_dir(&userspace_dir)
            .env("RUSTFLAGS", "-C relocation-model=static")
            .env_remove("CARGO_ENCODED_RUSTFLAGS")
            .status()
            .unwrap_or_else(|e| panic!("failed to invoke cargo to build {pkg}: {e}"));

        if !status.success() {
            panic!("{pkg} build failed (exit code: {:?})", status.code());
        }

        let bin_path = userspace_dir
            .join("target")
            .join("x86_64-unknown-none")
            .join("release")
            .join(bin_name);
        let env_key = format!("ONCRIX_{}_BIN", bin_name.to_uppercase());
        println!("cargo:rustc-env={}={}", env_key, bin_path.display());
        println!("cargo:rerun-if-changed={}", bin_path.display());
        println!(
            "cargo:rerun-if-changed={}",
            userspace_dir
                .join(bin_name)
                .join("src")
                .join("main.rs")
                .display()
        );
    }

    let target_dir = userspace_dir
        .join("target")
        .join("x86_64-unknown-none")
        .join("release");

    let init_bin = target_dir.join("init");
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
