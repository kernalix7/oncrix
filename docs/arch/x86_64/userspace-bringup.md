# Userspace Bringup (Phases 10b – 12)

This document describes the architecture that takes ONCRIX from
"kernel boots to ring 0 and prints a banner" to "embedded
`/bin/sh` runs at ring 3, calls real syscalls, and is reaped by
`init` after exit". Three commits land it in stages:

| Phase | Commit | Goal |
|-------|--------|------|
| 10b | `bae1eb6` | Embedded `init` ELF launches at ring 3 with a stable SYSCALL path. |
| 10c | `9e3dad9` | `fork(2)` / `wait4(2)` / `execve(2)` plumbing — per-process context, scheduler glue, ELF loader for exec. |
| 11  | `cb7a9a8` | `init` actually spawns `/bin/sh` (embedded) via `fork+execve+wait4` end to end. |
| 12  | `1655a74` | `sys_open/read/write/close/lseek` route through a real per-process fd table over VFS. |

The entry-point is `kernel_main()` in `crates/kernel/src/main.rs`.
The discussion below assumes the early-boot phases (1–9) have
finished; everything afterwards belongs to userspace bringup.

## 1. Userspace VMA at `0x400000..0x600000`

A userspace process needs three things the early kernel did not
provide:

1. A **user-accessible** virtual memory range (`U` bit set on
   every page-table level walked by ring 3).
2. A **2 MiB-aligned region** to hold the program's PT_LOAD
   segments and an initial user stack.
3. A **stable physical backing** that does not collide with the
   kernel image, the heap, or the boot page tables.

The boot tables built in `boot.S` map `PML4[0] → PDPT_low[0] →
PD_0_1G` as 512 huge pages without `U`. Phase 10b patches:

```
PML4[0]               |= U
PDPT_low[0]           |= U
PD_0_1G[2]             = USER_PT | P|W|U      (was a 2 MiB huge page)
USER_PT[0..512]        = region_phys + i*4K | P|W|U
```

`USER_LOAD_REGION` is a `static mut [u8; 2 MiB]` in BSS — it
gets a physical address chosen by the linker (the kernel ELF's
BSS section) rather than being pinned at `0x400000`. `USER_PT`
is a single 4 KiB `static mut [u64; 512]` that re-maps user VA
`0x400000 .. 0x600000` onto those BSS-allocated frames. This
**decouples user VA from kernel physical layout** — neither the
heap nor the kernel text needs to leave the bottom 2 MiB free.

After installation, ring 3 access at user VA `0x402000` walks
`CR3 → PML4[0] → PDPT_low[0] → PD[2] = USER_PT → USER_PT[2] →
region_phys + 0x2000`, i.e. byte `0x2000` of `USER_LOAD_REGION`.

The same higher-half kernel alias still works:
`0xFFFFFFFF809AC000` (kernel VA of `USER_LOAD_REGION`) walks
through `PDPT_high[510] → PD[4] (huge)` and is *not* affected
by the `PD[2]` replacement — so the kernel can keep writing
into the region via its native pointer while ring 3 sees it
through `USER_PT`.

```
ring 3:  0x400000 ─┐
                   ├── PD_0_1G[2] = USER_PT ── USER_PT[i] ── phys frame i of USER_LOAD_REGION
ring 0:  alias  ─┘     (kernel) PD_0_1G[4..] = huge ─────── same phys frames
```

## 2. ELF Embedding (Phases 10a / 10b / 11)

`crates/kernel/build.rs` runs a separate Cargo invocation against
the nested `crates/userspace/` workspace with `RUSTFLAGS` /
`CARGO_ENCODED_RUSTFLAGS` overrides so the kernel's linker
script and code-model don't leak in. The resulting binaries
(`init` and `sh`) are emitted as env vars `ONCRIX_INIT_BIN` /
`ONCRIX_SH_BIN`, picked up by `init_embed.rs` via
`include_bytes!`:

```
const EMBEDDED_INIT: &[u8] = include_bytes!(env!("ONCRIX_INIT_BIN"));
const EMBEDDED_SH:   &[u8] = include_bytes!(env!("ONCRIX_SH_BIN"));
```

`load_init_elf()` and `load_sh_elf()` parse the ELF, copy each
PT_LOAD segment into `USER_LOAD_REGION` at `vaddr - 0x400000`,
zero the `.bss` tail, and return the entry point. The `sh`
loader additionally `write_bytes`-zeros the entire region first
to scrub stale `init` data.

A small ELF parser lives in `crates/kernel/src/elf.rs`
(`parse_header`, `load_segments`); the same module is used by
both `init` boot-load and `execve`.

## 3. Ring 3 Transition

After installing `USER_PT` and copying `init`, `main.rs` calls
`jump_to_usermode(entry, USER_INIT_RSP)`:

```rust
asm!(
    "push {ss};  push {rsp};  push {rflags};
     push {cs};  push {rip};
     xor rax..r15, ...;        // scrub kernel data leak
     iretq",
    ...
);
```

This is the **only** place the kernel transitions to ring 3
without going through a syscall return — every later
ring 3 entry uses SYSCALL and every later ring 0 → 3 return
uses SYSRET (or IRETQ fallback for non-canonical RCX).

`TSS.RSP0` is installed beforehand (`init_tss_rsp0()`) so any
ring 3 → 0 trap (page fault, timer IRQ) lands on a valid
ring-0 stack instead of triple-faulting on the user RSP.

## 4. SYSCALL/SYSRET Fast Path

`syscall_entry.rs` configures four MSRs and provides a naked
entry stub:

| MSR | Bits | Value |
|-----|------|-------|
| `IA32_EFER` | bit 0 (`SCE`) | enable SYSCALL |
| `IA32_STAR` | `[63:48]` / `[47:32]` | user CS base `0x10` / kernel CS `0x08` |
| `IA32_LSTAR` | full | `syscall_entry as u64` |
| `IA32_FMASK` | RFLAGS bits | clear `IF | DF | AC | NT | TF` on entry |

On `SYSCALL` from ring 3 the CPU loads kernel CS/SS from STAR
but **does not touch RSP**. The naked stub:

1. `swapgs` — switch to per-CPU GS (placeholder for now).
2. Save the user RSP into a static atomic.
3. Switch to the **current thread's private** kernel stack via
   `CURRENT_KSTACK_TOP` (mirrored from `TSS.RSP0` by
   `switch_tss_rsp0`). Falls back to a 32 KiB static
   `SYSCALL_KERNEL_STACK` only before the first thread is
   installed.
4. Save user `RIP` (RCX) and `RFLAGS` (R11) into atomics so
   `fork`/`execve` can read them without walking a frame.
5. Push a `SyscallArgs` struct and `call syscall_dispatch_wrapper`.
6. On return, pop, restore, sanitize R11, and either `sysretq`
   (canonical RCX) or build an `iretq` frame (non-canonical RCX).

The per-thread kstack switch in step 3 is **load-bearing**: the
older shared-stack design caused parent state to be clobbered
when a sleeping parent and a running child both rode the
SYSCALL fast path on the same buffer.

## 5. fork(2)

`fork()` is split between three layers:

| Layer | Crate | What it does |
|-------|-------|--------------|
| Snapshot | `oncrix_kernel::fork_dispatch::sys_fork` | Reads saved user RIP/RSP/RFLAGS atomics, allocates a child PID, builds a `ForkSnapshot`. |
| Construction | `arch_clone_thread` (clone.rs) | Allocates a 16 KiB child kstack, seeds an `iretq` frame + 6 callee-saved register slots + `fork_trampoline` return address, fills a `CpuContext`. |
| Registration | `current::fork_current` + `register_process` | Adds the new `Thread` to the scheduler and inserts a `ProcessEntry` so `wait4` can find it. |

### Child kstack seeding

When the scheduler picks the child, `switch_context` does
`mov rsp, [child_ctx + 48]; pop r15..rbx; ret`. The child stack
must therefore satisfy that exact sequence:

```
top - 0x08   SS     = USER_DATA | 3 = 0x1B   ── iretq frame
top - 0x10   RSP    = user_rsp
top - 0x18   RFLAGS = sanitized (IF=1, reserved=1, no IOPL)
top - 0x20   CS     = USER_CODE | 3 = 0x23
top - 0x28   RIP    = parent's saved user RIP (post-syscall)
top - 0x30   ret    = fork_trampoline                 ← `ret` lands here
top - 0x38   rbx    = 0                               ─┐
top - 0x40   rbp    = 0                                │
top - 0x48   r12    = 0                                │ consumed by the
top - 0x50   r13    = 0                                │ 6 `pop` insns
top - 0x58   r14    = 0                                │
top - 0x60   r15    = 0   ← CpuContext.rsp points here ┘
```

`fork_trampoline` is a naked function that zeroes all GP
registers (so kernel data doesn't leak to ring 3) and issues
`iretq` against the 5-word frame above. The child therefore
resumes at the **same** user RIP as the parent (i.e. the
instruction after the `SYSCALL`), with `RAX = 0` per
POSIX `fork(3p)`.

## 6. wait4(2)

`sys_wait4` (also in `fork_dispatch.rs`) is cooperatively
blocking: if there is no zombie child it calls
`current::yield_now`, which delegates to
`sched_yield_once(&mut SCHEDULER)` and in turn to
`switch_context`. When the child later transitions its
`ProcessEntry` to `Exited` (via `sys_exit`) the parent's next
loop iteration finds it, writes `(exit_code << 8)` to
`*wstatus` if non-null, removes the entry, and returns the
child PID.

`WNOHANG` is the only option flag wired today; everything else
returns `EINVAL`.

## 7. execve(2)

`sys_execve` recognizes a single hard-coded path,
`/bin/sh`, and ignores `argv`/`envp` for now. The work:

1. Validate the user pointer, copy ≤ 256 bytes into `PATH_BUF`,
   compare to `b"/bin/sh"`.
2. Fetch `embedded_sh_elf()`; bail with `ENOENT` if the
   `embed-init` feature is off.
3. Call `load_sh_elf()` — zeroes `USER_LOAD_REGION`, copies
   `sh`'s PT_LOAD segments, returns the ELF entry.
4. Overwrite the saved-user atomics: `set_saved_user_rip(entry)`,
   `set_saved_user_rsp(USER_INIT_RSP)`,
   `set_saved_user_rflags(0x202)`.
5. Self-reload `CR3` to drop stale TLB translations from the
   previous program's mapping.
6. Return `0`. The SYSCALL epilogue's `sysretq` then jumps to
   the new RIP — implementing the POSIX "execve does not
   return on success" contract by **redirecting the return**,
   not by avoiding it.

The shared `USER_LOAD_REGION` means **the parent's user image
is destroyed** by a child's execve. That's a Phase 13 concern;
see § 11.

## 8. _exit / sys_exit

`sys_exit(code)` (number 60 / 231):

1. Print `[exit] process exiting with code=N`.
2. Mark the `ProcessEntry` `Exited` with the low 8 bits of
   `code` (matches `WEXITSTATUS`).
3. Set the current `Thread` state to `ThreadState::Exited` so
   the scheduler skips it forever.
4. Loop on `yield_now` + `pause`. The thread never resumes;
   each yield finds another runnable thread and switches away.

POSIX `_exit(3p)` requires no stdio flushing — that is why the
serial print happens *before* the state mutation, not buffered
behind a flush call.

## 9. Cooperative-Only Scheduling (Phase 11)

The PIT timer IRQ used to call `SCHEDULER.schedule()` on every
tick, which silently rewrote `current` from under any
in-flight `prepare_switch` / `switch_context` pair. The result
was a corrupted "prev" pointer and an immediate #UD when the
saved-but-stale parent tried to `ret` to its previous frame.

Phase 11 disables that path: `timer_handler` in `interrupts.rs`
now only ticks `PIT_TIMER` and EOIs the PIC. Reschedules happen
exclusively via cooperative `yield_now`. Preemption returns once
saved IRQ frames are tracked per-thread.

## 10. fd Table & VFS-routed I/O (Phase 12)

Before Phase 12, `sys_write` for fd 0/1/2 was a hard-coded
serial bypass. After it:

```
ring 3 write(fd, buf, count)
   │
   ▼
SYSCALL → syscall_dispatch_wrapper
   │
   ▼
match SYS_WRITE:
   fd_table::dispatch_write(fd, buf, count)
     │
     ▼
   FileHandle.backend ─┬─ Console     → COM1 (Uart16550)
                       └─ RamfsFile   → ramfs.write_inode(ino, off, &buf)
```

`crates/kernel/src/fd_table.rs` holds:

| Type | Purpose |
|------|---------|
| `FileBackend::{Console, RamfsFile{ino}}` | Where the bytes go. |
| `HandleFlags` | `RDONLY` / `WRONLY` / `RDWR` / `APPEND`. |
| `FileHandle { backend, offset, flags }` | One open file description. |
| `KernelFdTable<32>` | Lowest-available fd allocator. |
| `CURRENT_FD_TABLE` | Single global table (Phase 12 simplification — one process at a time). |

`install_stdio()` is invoked from `main.rs` immediately after
`init`'s thread is finalised; it pre-populates fd 0/1/2 with
console handles. From that point the legacy `kernel_serial_write`
path is unreachable in normal boot — it survives only as a
defensive fallback for the `fd in 0..=2 && EBADF` case.

`crates/vfs/src/kernel_api.rs` exposes `KernelVfs` with
`lookup`, `inode_size`, `read_inode`, `write_inode` — the
single API surface that `dispatch_read` / `dispatch_write` /
`sys_open` use. Path resolution walks the mount table from
`/`; `O_CREAT` falls through to `ramfs::create`.

## 11. Known Limitations & Phase 13 Roadmap

The end-to-end test today produces:

```
[init] hello from pid 1 (ring 3)
[fork] sys_fork called
[fork] child created
[exec] loaded /bin/sh at entry=0x400570
$ [exit] process exiting with code=0
[wait4] reaped child

!!! EXCEPTION: Invalid Opcode (#UD) !!!  ← Phase 13 fix
  RIP: 0x4003f4   CS: 0x23
```

The post-`wait4` #UD is **not a regression**. After the child
execve overwrote `USER_LOAD_REGION` with `sh`, `init`'s text
at `0x400000..0x600000` is gone. When `wait4` returns to user
mode, the parent CPU fetches what was init's `init_main+...`
but is now somewhere inside `sh`, hits a non-instruction byte,
and faults.

The mm-subsystem already drafted the cure in Phase 10c —
`crates/mm/src/address_space/user.rs::UserAddressSpace` with
`new_empty`, `map_elf_segments`, `clone_for_fork`,
`user_pt_phys`, `release`. Phase 13 will:

1. Attach a `UserAddressSpace` to each `Thread` (currently
   only `user_pt_phys: Option<u64>` lives there).
2. Make `arch_clone_thread` call `clone_for_fork` so the
   child gets its own `USER_PT` / load region (eager copy
   for now; CoW deferred).
3. Make `sys_execve` allocate a fresh `UserAddressSpace`
   for the calling thread and `release` the old one — leaving
   the parent's mapping untouched.
4. Re-enable preemptive scheduling once saved IRQ frames are
   per-thread.

Other Phase 12 simplifications worth noting:

- `CURRENT_FD_TABLE` is global. SMP / multiple concurrent
  user processes need a per-thread (or per-Process) table.
- No permission checks (`EACCES`, `EROFS`) on open / write.
- `argv` / `envp` are accepted but ignored by `execve`.
- `sh`'s `read(0, …)` returns 0 immediately (console reads
  are unimplemented — it sees EOF and exits).

## 12. Files & Where to Read More

| Subject | File |
|---------|------|
| Boot to ring 3 | `crates/kernel/src/main.rs` (around `Phase 10` block), `crates/kernel/src/arch/x86_64/usermode.rs` |
| Page-table install | `crates/kernel/src/arch/x86_64/init_embed.rs::install_user_mapping` |
| ELF embed + parse | `crates/kernel/build.rs`, `crates/kernel/src/elf.rs`, `init_embed.rs::{load_init_elf, load_sh_elf}` |
| SYSCALL fast path | `crates/kernel/src/arch/x86_64/syscall_entry.rs` |
| fork / wait4 / execve / _exit | `crates/kernel/src/fork_dispatch.rs` |
| Child build | `crates/kernel/src/arch/x86_64/clone.rs` |
| Per-thread CpuContext / kstack | `crates/process/src/{context.rs, kstack.rs}` |
| Scheduler glue | `crates/kernel/src/arch/x86_64/sched_glue.rs`, `crates/process/src/scheduler.rs` |
| fd table dispatch | `crates/kernel/src/fd_table.rs` |
| VFS kernel API | `crates/vfs/src/kernel_api.rs` |
| Userspace shell | `crates/userspace/sh/src/main.rs` |
| POSIX specs (local) | `.priv-storage/.TheOpenGroup/susv5-html/functions/{fork,wait,execve,_exit,read,write,open,close,lseek}.html` |
