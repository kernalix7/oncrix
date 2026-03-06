# Copy-on-Write (CoW)

## Overview

After `fork()`, the parent and child processes share physical pages
mapped read-only. When either process writes to a shared page, a
**page fault** occurs. The CoW handler:

1. Allocates a new physical frame
2. Copies the old page to the new frame
3. Remaps the faulting process's PTE to the new frame with write permission
4. Decrements the CoW reference count for the old frame

This avoids copying the entire address space at fork time, making
`fork()` nearly instantaneous regardless of process size.

## Implementation

### PTE Marking

We use **bit 9** of the page table entry (one of the three OS-available
bits in x86_64 PTEs) as the CoW marker:

```
Bit   Meaning
───   ───────
 0    Present
 1    Writable        ← cleared for CoW pages
 2    User
...
 9    COW_BIT         ← set to distinguish from truly read-only pages
...
63    No-Execute
```

A CoW page is: `PRESENT | USER | COW_BIT` (no `WRITABLE`).

### Fault Detection

```rust
fn is_cow_fault(error_code: u64) -> bool {
    // Protection violation on a write
    error_code & PROTECTION != 0 && error_code & WRITE != 0
}
```

The handler then checks if the faulting PTE has `COW_BIT` set. If not,
it's a genuine segfault.

### Reference Counting

The `CowTracker` (in `oncrix-process::fork`) tracks how many processes
share each physical frame:

| State | Meaning |
|-------|---------|
| `Exclusive` | Single owner, frame is writable |
| `Shared(n)` | `n` processes share this frame read-only |

When `unshare()` brings the count to 1, the remaining owner can be
upgraded back to `Exclusive` (writable, no COW_BIT).

### Region-Level CoW

`mark_region_cow()` walks a 4-level page table and marks all present,
writable PTEs in a given virtual address range as CoW. This is called
by `fork()` for both parent and child address spaces.

## Flow Diagram

```
fork()
  │
  ├─ Allocate child PML4
  ├─ Copy parent page tables (shallow)
  ├─ mark_region_cow(parent_pml4, ...)  ← parent loses write
  ├─ mark_region_cow(child_pml4, ...)   ← child has CoW pages
  └─ Flush TLB for both processes
       │
       ▼
Child writes to shared page
  │
  ├─ #PF (protection violation, write)
  ├─ is_cow_fault() → true
  ├─ PTE has COW_BIT → true
  ├─ Allocate new frame
  ├─ Copy 4 KiB from old frame to new frame
  ├─ Update PTE: new frame, +WRITABLE, -COW_BIT
  ├─ cow_tracker.unshare(old_frame)
  ├─ Flush TLB entry
  └─ Return to user space (retry the write)
```

## Files

| File | Description |
|------|-------------|
| `mm/src/cow.rs` | CoW fault handler, PTE marking |
| `process/src/fork.rs` | `CowTracker`, `CowState` |
| `kernel/src/arch/x86_64/exceptions.rs` | Page fault entry point |
