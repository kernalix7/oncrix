# Scheduler

ONCRIX uses a priority-based preemptive scheduler.

## Contents

- [Design](#design)
- [Round-Robin Scheduler](#round-robin-scheduler)
- [Preemption](#preemption)
- [Time Slices](#time-slices)

---

## Design

### Scheduling Model

```
Thread States:
  Ready ──▶ Running ──▶ Blocked
    ▲          │           │
    │          ▼           │
    └───── Exited          │
    ▲                      │
    └──────────────────────┘
```

### Components

| Component | Location | Description |
|-----------|----------|-------------|
| `RoundRobinScheduler` | `process/src/scheduler.rs` | Core scheduling algorithm |
| `PreemptionState` | `kernel/src/sched.rs` | Preemption control |
| Timer ISR | `kernel/src/arch/x86_64/` | Triggers reschedule |

## Round-Robin Scheduler

The current scheduler is a simple round-robin with 256 thread slots:

- **Algorithm**: Scan for next `Ready` thread after current
- **Complexity**: O(N) worst case per decision
- **Max threads**: 256

### Operations

| Operation | Description |
|-----------|-------------|
| `add(thread)` | Register a ready thread |
| `remove(tid)` | Unregister a thread |
| `schedule()` | Pick next runnable thread |
| `block_current()` | Block the running thread |
| `unblock(tid)` | Wake a blocked thread |

## Preemption

Preemption uses a nesting counter to allow critical sections:

```rust
pub struct PreemptionState {
    preempt_count: u32,  // > 0 means preemption disabled
    need_reschedule: bool,
}
```

- `disable()` — Increment counter (nesting allowed)
- `enable()` — Decrement counter; if 0 and `need_reschedule`, reschedule
- Timer ISR sets `need_reschedule = true`

## Time Slices

Time slices are priority-dependent:

| Priority | Time Slice | Use Case |
|----------|-----------|----------|
| 0 (highest) | 1 ms | Real-time / kernel threads |
| 64 | 5 ms | High-priority user tasks |
| 128 (normal) | 10 ms | Default user processes |
| 192 | 15 ms | Background tasks |
| 255 (idle) | 20 ms | Idle thread |

Formula: `time_slice_ms = 1 + (priority / 14)`

## Future Work

- Multi-level feedback queue (MLFQ)
- Per-CPU run queues for SMP
- Real-time scheduling class (SCHED_FIFO, SCHED_RR)
- CPU affinity (`sched_setaffinity`)
- Load balancing across CPUs
