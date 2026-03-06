# Kernel Heap Allocator

## Overview

The kernel heap uses a linked-list free-list allocator with
split and coalesce support. It is registered as the global
allocator via `#[global_allocator]`.

## Design

```
256 KiB Static Buffer
┌──────────────────────────────────────┐
│  [Used]  [Free]  [Used]  [Free]     │
│          ┌─────┐         ┌─────┐    │
│          │next─┼────────▶│next─┼──▶∅│
│          │size │         │size │    │
│          └─────┘         └─────┘    │
└──────────────────────────────────────┘
```

Each free block contains:
- `size: usize` — Block size
- `next: *mut FreeBlock` — Pointer to next free block

### Allocation

1. Walk the free list for a block ≥ requested size + alignment
2. Split if block is large enough to leave a valid remainder
3. Return the aligned address
4. Update `allocated` counter

### Deallocation

1. Reconstruct the block at the freed address
2. Add it back to the head of the free list
3. Decrement `allocated` counter

### Coalescing

Adjacent free blocks are merged during allocation scan to
reduce fragmentation.

## Thread Safety

```rust
// SAFETY: During early boot, only the BSP runs, so no
// concurrent access occurs. Before SMP initialization,
// this must be wrapped in a spinlock.
unsafe impl Sync for LinkedListAllocator {}
```

## Statistics

| Metric | Description |
|--------|-------------|
| `heap_size` | Total heap capacity |
| `allocated` | Currently allocated bytes |
| `free()` | Available = capacity - allocated |

## Limitations

- Fixed 256 KiB heap (static buffer, no growth)
- O(N) allocation (linear scan)
- No per-CPU caches
- No slab allocator for fixed-size objects

## Future Work

- Slab allocator for common kernel objects
- Growable heap via page mapping
- Per-CPU allocation pools for SMP
