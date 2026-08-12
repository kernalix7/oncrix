# ONCRIX — Copilot working instructions

ONCRIX is a ~1.16M-line Rust **nightly, edition 2024, `#![no_std]`/`#![no_main]`
microkernel**. All three targets boot in QEMU and are covered by CI:
`x86_64-unknown-none` (primary — reaches ring 3 and runs a shell),
`aarch64-unknown-none` and `riscv64gc-unknown-none-elf` (preemptive kernel-thread
scheduling; aarch64 also does an EL0 round trip). Also read the repo `CLAUDE.md`
for full project rules (coding conventions §4, build/verify §5) and the per-crate
`AGENTS.md` for the crate you are touching. Ignore the multi-agent / "TeamCreate"
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

Status: the hardening sweep through PR #137 is done — the inline-assembly
soundness pass and the mounted-image filesystem parsers (ext2/btrfs/UDF/minix/
romfs + fat/iso/ntfs/etc.) are covered. PRs #138–#151 shifted to cross-architecture
bring-up (aarch64/riscv64 boot, MMU, preemption, FP/SIMD state, CI boot coverage).
Verify current state with `git log`, not with `WORK_STATUS.md` or `CHANGELOG.md` —
both are months stale.

## ▶ THE NEXT TASK: audit and wire one network protocol parser
The live receive path is `NetStack::process_packet` at `crates/kernel/src/net.rs:663`.
Its ethertype match (`net.rs:666`) handles **only** ARP and `ETHER_TYPE_IPV4`;
everything else returns `NotImplemented`. Inside `handle_ipv4` (`net.rs:801`) the
protocol match handles only `PROTO_ICMP` and `PROTO_UDP` (`net.rs:833-834`).
Parsers for ipv6, tcp, igmp, dns, dhcp, sctp and gre exist as sibling modules in
`crates/kernel/src/` but have **zero callers from `net.rs`** — dead surface today.

Wiring one makes it reachable from **remote, pre-authentication packet input**, so
the parser must be audited against the bug classes above *before* it is dispatched.
Do them one protocol per PR, in this order:

1. **Audit** the parser for every bug class listed above. Report each finding as
   `file:line:function` + the attacker-controlled value + the bug class + the
   minimal fix.
2. **Fix** the findings (bound/guard that is a no-op for valid input).
3. **Wire** it into the ethertype match (`net.rs:666`) or the IP protocol match
   (`net.rs:833`), mirroring how `handle_udp_packet` (`net.rs:860`) delegates to
   `crate::udp::parse_udp_datagram` and re-checks bounds at the call site.

Start with **IPv6**: `ETHER_TYPE_IPV6` is already defined at `net.rs:42` and never
matched, and the path mirrors the existing IPv4 one most closely. `9p`
(`crates/vfs/src/plan9fs.rs`) is the other high-value unaudited surface.

Note the existing defensive style at `net.rs:817-820`: bounds already validated by
the parser are **re-checked at the call site**. Keep that — it is deliberate.

## How to make a change (single-agent loop)
1. Branch: `git checkout -b fix/<short-name>` (never commit directly to `main`).
2. Edit only the file(s) for this one fix.
3. **Gate — every command must pass; capture each exit code, do NOT pipe `cargo`
   through `| tail` (tail always exits 0 and hides failures):**
   ```
   rustup update nightly             # CI installs the LATEST nightly every run
   cargo fmt --all -- --check        # or run `cargo fmt --all` first to auto-format
   cargo build --workspace
   cargo clippy --workspace -- -D warnings
   # cross-build when touching crates/hal/ or crates/kernel/src/arch/ — these are
   # NOT built by --workspace and break silently otherwise:
   cargo build -p oncrix-kernel --bin oncrix-kernel --target aarch64-unknown-none
   cargo build -p oncrix-kernel --bin oncrix-kernel --target riscv64gc-unknown-none-elf
   bash scripts/run-tests.sh         # 962 host unit tests across 9 crates
   bash scripts/run-qemu-test.sh     # boots all three arches
   ```
   `rustup update nightly` is not optional. `rust-toolchain.toml` pins the floating
   `nightly` channel and CI resolves it fresh, so a stale local toolchain passes
   clippy locally and fails CI on lints that did not exist when you last updated.

   `cargo test --workspace` **does not work** — the default target is bare metal and
   libtest needs std. `scripts/run-tests.sh` builds each crate for the host triple
   instead, sets the large `RUST_MIN_STACK` the inline-table idiom requires, and skips
   ~20 tests that genuinely fail today. Each skip entry names its root cause; deleting
   one is the definition of done for that fix. `oncrix-syscall` is not in the runner
   yet — 118 test-compile errors, in the crate holding 373 of the 494 test files.
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

## Finding more issues (when the task above is done)
Repeat the audit-then-wire loop for the next protocol, one per PR. After the
network parsers, the remaining unaudited high-risk surfaces are, in rough order of
value: `9p` (`crates/vfs/src/plan9fs.rs`), deeper `crates/mm/` (compaction, swap,
numa, balloon, zswap), the remaining `crates/drivers/` classes (gpu, input,
sensors), and HAL interrupt routing (APIC/IOAPIC).

Two standing cleanups, both low risk:
- `python3 scripts/check_safety.py` reports ~42 unsafe blocks without a `// SAFETY:`
  comment, all in `crates/userspace/`. The checker is not wired into CI.
- PR #25 (logo vector) has been open and mergeable for months; it needs a decision,
  not code.
