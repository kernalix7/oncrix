# Memory Management

The ONCRIX memory management subsystem (`oncrix-mm` crate) handles all
aspects of physical and virtual memory.

## Contents

- [Overview](#overview)
- [Physical Memory](physical.md) — Frame allocator, bitmap allocator
- [Virtual Memory](virtual.md) — 4-level page tables, TLB management
- [Address Space](address-space.md) — Per-process virtual memory layout
- [Heap Allocator](heap.md) — Kernel heap (linked-list free-list)
- [Copy-on-Write](cow.md) — CoW page fault handling after fork

---

## Overview

### Address Types

ONCRIX uses newtypes to prevent mixing physical and virtual addresses:

```rust
pub struct PhysAddr(u64);  // Physical address (hardware)
pub struct VirtAddr(u64);  // Virtual address (CPU sees this)
pub struct Frame { number: u64 }  // Physical page frame (4 KiB)
pub struct Page { number: u64 }   // Virtual page (4 KiB)
```

### Memory Layout (x86_64)

```
Virtual Address Space (48-bit canonical)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
0x0000_0000_0000_0000  ─  Reserved
0x0000_0000_0040_0000  ─  USER_SPACE_START
         ...           ─  User code, data, heap
         ...           ─  User stack (grows down)
0x0000_7FFF_FFFF_FFFF  ─  USER_SPACE_END
━━━━━━━━━━━━━━━━━━━━━━━  (canonical hole)
0xFFFF_8000_0000_0000  ─  KERNEL_SPACE_START
         ...           ─  Kernel code, data
         ...           ─  Kernel heap (256 KiB)
0xFFFF_FFFF_8000_0000  ─  Higher-half kernel
0xFFFF_FFFF_FFFF_FFFF  ─  End
```

### Crate Structure

```
oncrix-mm/src/
├── addr.rs          — PhysAddr, VirtAddr newtypes
├── frame.rs         — Frame, Page, FrameAllocator trait
├── bitmap.rs        — BitmapAllocator (32768 frames = 128 MiB)
├── page_table.rs    — PageTable, PageTableEntry, map/unmap
├── address_space.rs — AddressSpace, VmRegion, Protection
├── heap.rs          — LinkedListAllocator (#[global_allocator])
└── cow.rs           — Copy-on-Write page fault handler
```

### Key Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `PAGE_SIZE` | 4096 | x86_64 page size |
| `MAX_REGIONS` | 64 | Max VM regions per process |
| `USER_SPACE_START` | `0x0040_0000` | First user-mappable address |
| `USER_SPACE_END` | `0x7FFF_FFFF_FFFF` | Last user-space address |
| `KERNEL_SPACE_START` | `0xFFFF_8000_0000_0000` | Kernel virtual base |
