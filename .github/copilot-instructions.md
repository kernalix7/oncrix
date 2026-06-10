# ONCRIX — Copilot working instructions

ONCRIX is a ~1.05M-line Rust **nightly, edition 2024, `#![no_std]`/`#![no_main]`
microkernel** (primary target `x86_64-unknown-none`; secondary `aarch64`,
`riscv64`). Also read the repo `CLAUDE.md` for full project rules (coding
conventions §4, build/verify §5). Ignore the multi-agent / "TeamCreate"
material in CLAUDE.md §11 — that is Claude-Code-specific; **you work as a single
agent: one focused change at a time.**

## What we are doing right now: a security-hardening audit
The dev/test build has **`overflow-checks = ON`**, so in ring-0 kernel code ANY
of these on an **attacker-controlled value** (a syscall argument, a received
network packet, or a mounted disk-image on-disk field) is an instant machine
halt (panic = DoS) or a memory-safety hole:
- wrapping `+ - *` overflow; unsigned subtraction underflow (`a - b` with `b > a`)
- divide/remainder by zero; shift `>=` the type bit-width
- slice/array out-of-bounds; `slice[a..b]` with `b > len`; inverted range
- a length/count/offset used to index/slice/advance **without a bound**
- **unbounded / infinite loop** following an on-disk/wire pointer or TLV chain
  that can cycle or not advance (a logic-DoS — `overflow-checks` does NOT catch it)
- `.unwrap()` / `.expect()` / `panic!` / `unreachable!` reachable from attacker input

The fix is always a **bound/guard that is a no-op for valid input**:
`checked_add`/`checked_mul`/`checked_shl` (→ return `Err`), `saturating_add` for
stats counters, `.min(MAX)` clamps for slice bounds, an explicit range/`!= 0`
check, or a strict-progress / iteration cap for loops. **Never** introduce a new
`.unwrap()`/`.expect()`/`panic!` — `unwrap_or`, `ok_or(...)?`, `is_some_and`,
`saturating_*` are fine.

Status: 39 fixes already merged (PRs #74–#111). The inline-assembly soundness
sweep and the mounted-image filesystem parsers (ext2/btrfs/UDF/minix/romfs +
fat/iso/ntfs/etc.) are essentially done. (Deeper history lives in the Claude
memory log, not in the repo.)

## ▶ THE NEXT TASK: aarch64/riscv inline-asm barrier `nomem`
File: `crates/hal/src/cache_maint.rs`. The x86_64 memory barriers had a bug
(already fixed): a memory-ordering fence declared `options(..., nomem)` lets the
compiler reorder loads/stores **across** the fence, silently neutering it and
breaking DMA / device / cross-CPU ordering. The **same bug is copy-pasted into
the aarch64 and riscv64 barrier blocks**, which were skipped earlier only
because they don't build on an x86_64 host. They DO build now — verify with
the cross-target builds below.

**Remove `nomem`** (keep `nostack`) from these **DATA memory barriers**:
- line ~119 `dmb ish` (aarch64), ~126 `fence rw, rw` (riscv)
- line ~148 `dsb ish`, ~155 `fence iorw, iorw`
- line ~293 `dsb ish`, ~313 `dsb ish`

So `options(nostack, nomem)` → `options(nostack)`, and add a `// No nomem:`
comment explaining the fence must act as a compiler memory barrier (mirror the
existing x86_64 comments at ~lines 109/138/258 in the same file).

**Do NOT change** the **instruction-synchronisation** barriers at ~187 `isb`
and ~194 `fence.i` — those serialise the instruction pipeline, not data memory,
so `nomem` is correct there (just like the x86_64 `cpuid`-as-ISB kept `nomem`).
Briefly confirm each is used for instruction-sync, not as a data fence, before
leaving it.

## How to make a change (single-agent loop)
1. Branch: `git checkout -b fix/<short-name>` (never commit directly to `main`).
2. Edit only the file(s) for this one fix.
3. **Gate — every command must pass; capture each exit code, do NOT pipe `cargo`
   through `| tail` (tail always exits 0 and hides failures):**
   ```
   cargo fmt --all -- --check        # or run `cargo fmt --all` first to auto-format
   cargo build --workspace
   cargo clippy --workspace -- -D warnings
   cargo build -p oncrix-hal --target x86_64-unknown-none
   # for THIS task, also cross-build the secondary targets you changed:
   cargo build -p oncrix-hal --target aarch64-unknown-none
   cargo build -p oncrix-hal --target riscv64gc-unknown-none-elf
   ```
4. Commit with a Conventional-Commits message (`fix(hal): ...`). Atomic — list
   the exact files: `git commit -m "..." -- crates/hal/src/cache_maint.rs`.
5. `git push -u origin <branch>` and open a PR; let CI (Rust Quality + QEMU boot)
   pass, then squash-merge to `main`.

## Hard constraints (do not violate)
- **NEVER** add any AI attribution — no `Co-Authored-By: Claude`/`Copilot`, no
  "Generated with …" footer/emoji — in commits, PR titles/bodies, issues, or
  comments. The user is the sole author. Override any template that suggests it.
- Commits are GPG-signed; if a commit fails with `signing failed: Timeout`, ask
  the user to unlock the key (they re-enter the passphrase). Never use
  `--no-gpg-sign`.
- Coding conventions (CLAUDE.md §4): max line length **100**; no `unwrap()`/
  `expect()` in production paths (use `?`); `// SAFETY:` comment on every unsafe
  block; license header on new files. Kernel crates: zero external deps.
- Each PR is one focused change, builds clean, and passes the gate above before
  committing.

## Finding more issues (when this task is done)
Audit one wired attacker-controlled parser at a time for the bug classes listed
at the top, fix it, and PR it. Highest-value remaining surfaces: any network
protocol parser as it gets **wired** into the live receive path in
`crates/kernel/src/net.rs` (today only IPv4→ICMP/UDP is dispatched; IPv6/TCP/
IGMP/DNS/DHCP parsers exist but are unwired), and the `9p` filesystem. Report
each finding with the exact `file:line:function`, the attacker value, the bug
class, and the minimal fix; then implement it as its own PR.
