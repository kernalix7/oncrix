# Process and Thread Model

## Overview

ONCRIX uses a 1:1 threading model — each user thread maps to one
kernel thread. Processes are the unit of isolation; threads are
the unit of scheduling.

## Process

```rust
pub struct Process {
    pid: Pid,
    state: ProcessState,
    threads: [Option<Tid>; 64],
    thread_count: usize,
}
```

### Process States

| State | Description |
|-------|-------------|
| `Active` | Has at least one runnable thread |
| `Exited` | All threads done, awaiting parent's `wait` |

### Process Table

The global `ProcessTable` maps PID → `ProcessEntry`:

```rust
pub struct ProcessEntry {
    pub process: Process,
    pub parent: Pid,
    pub signals: SignalState,
    pub exit_status: Option<ExitStatus>,
}
```

- Capacity: 256 processes
- O(1) lookup by PID (hash-indexed with linear probe fallback)
- Supports `children()` and `zombie_children()` iterators for `wait4`

## Thread

```rust
pub struct Thread {
    tid: Tid,
    pid: Pid,
    state: ThreadState,
    priority: Priority,
    stack_pointer: u64,
}
```

### Thread States

```
Ready ──────▶ Running ──────▶ Blocked
  ▲              │                │
  │              ▼                │
  └────────── Exited              │
  ▲                               │
  └───────────────────────────────┘
```

### Priority

`Priority(u8)` where 0 is highest, 255 is lowest:

| Level | Value | Use |
|-------|-------|-----|
| `HIGHEST` | 0 | Kernel threads, real-time |
| `NORMAL` | 128 | Default user processes |
| `IDLE` | 255 | Idle thread |

## Process Lifecycle

### Creation (`fork`)

```
Parent process
    │
    ├─ alloc_pid() → child PID
    ├─ alloc_tid() → child TID
    ├─ Create child Process + Thread
    ├─ Copy address space (CoW)
    ├─ Copy signal state
    ├─ Insert into ProcessTable
    └─ Add child thread to scheduler
```

### Program Replacement (`execve`)

```
Current process
    │
    ├─ Parse ELF binary
    ├─ Create new AddressSpace
    ├─ Tear down old address space
    ├─ Map ELF segments
    ├─ Set up user stack (argc/argv/envp)
    ├─ Reset signal handlers (SIG_IGN kept)
    ├─ Close O_CLOEXEC fds
    └─ Jump to new entry point
```

### Termination (`exit`)

```
Process calls exit(status)
    │
    ├─ Mark process as Exited
    ├─ Set exit_status
    ├─ Release address space
    ├─ Close all file descriptors
    ├─ Re-parent children to init (PID 1)
    ├─ Send SIGCHLD to parent
    └─ Become zombie until parent calls wait4
```

## Signals

POSIX-compatible signal handling:

| Signal | Number | Default Action |
|--------|--------|---------------|
| SIGHUP | 1 | Terminate |
| SIGINT | 2 | Terminate (Ctrl+C) |
| SIGQUIT | 3 | Terminate + core dump |
| SIGKILL | 9 | Terminate (uncatchable) |
| SIGSEGV | 11 | Terminate + core dump |
| SIGTERM | 15 | Terminate |
| SIGCHLD | 17 | Ignore |
| SIGSTOP | 19 | Stop (uncatchable) |

### Signal State

Per-process:
- `actions[32]` — Handler for each signal
- `mask` — Blocked signal bitset
- `pending` — Pending signal bitset

### Delivery

```
send(sig) → pending.raise(sig)
    │
    ▼
scheduler picks thread
    │
    ▼
dequeue() → find lowest pending, unblocked signal
    │
    ▼
Action:
  SIG_DFL → terminate/ignore/stop
  SIG_IGN → discard
  Handler → set up signal trampoline
```

## Files

| File | Description |
|------|-------------|
| `process/src/pid.rs` | PID/TID newtypes, atomic allocation |
| `process/src/process.rs` | Process struct |
| `process/src/thread.rs` | Thread struct, states, priority |
| `process/src/table.rs` | Global process table |
| `process/src/signal.rs` | Signal handling |
| `process/src/fork.rs` | Fork implementation, CoW tracker |
| `process/src/scheduler.rs` | Round-robin scheduler |
| `kernel/src/exec.rs` | ELF loading, execve |
| `kernel/src/sched.rs` | Preemptive scheduling |
