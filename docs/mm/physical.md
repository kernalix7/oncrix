# Physical Memory Management

## Frame Allocator Trait

All physical memory allocators implement:

```rust
pub trait FrameAllocator {
    fn allocate_frame(&mut self) -> Option<Frame>;
    fn deallocate_frame(&mut self, frame: Frame);
    fn free_frames(&self) -> usize;
}
```

A `Frame` is a 4 KiB-aligned region of physical memory, identified
by its frame number (`physical_address >> 12`).

## Bitmap Allocator

The current implementation uses a bitmap where each bit represents
one 4 KiB frame:

- **Capacity**: 32768 frames = 128 MiB
- **Bitmap size**: 4096 bytes (1 page)
- **Allocation**: O(n) scan for first free bit
- **Deallocation**: O(1) bit clear

### Operations

| Function | Description |
|----------|-------------|
| `mark_range_free(start, count)` | Mark frames as available |
| `mark_range_used(start, count)` | Mark frames as allocated |
| `allocate_frame()` | Find and allocate first free frame |
| `deallocate_frame(frame)` | Return a frame to the free pool |

### Boot Integration

During boot, the kernel reads the Multiboot2 memory map and calls
`mark_range_free()` for each usable region, then `mark_range_used()`
for the kernel's own physical pages.

## Future Work

- Buddy allocator for O(log n) allocation
- Per-CPU free lists for SMP scalability
- NUMA-aware allocation
