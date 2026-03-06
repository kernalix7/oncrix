# Per-Process Address Space

## Overview

Each process in ONCRIX has its own `AddressSpace` containing:

- A root page table (PML4) physical address
- A list of virtual memory regions (`VmRegion`)
- A program break pointer (for `brk`/`sbrk`)

## VmRegion

A contiguous range of virtual memory with uniform protection:

```rust
pub struct VmRegion {
    pub start: VirtAddr,  // Page-aligned start
    pub size: u64,        // Page-aligned size
    pub prot: Protection, // R/W/X flags
    pub kind: RegionKind, // Code/Data/Heap/Stack/Mmap
}
```

### Protection Flags

| Flag | Value | Description |
|------|-------|-------------|
| `READ` | `0x1` | Page is readable |
| `WRITE` | `0x2` | Page is writable |
| `EXEC` | `0x4` | Page is executable |
| `RW` | `0x3` | Read + Write |
| `RX` | `0x5` | Read + Execute |

### Region Kinds

| Kind | Description |
|------|-------------|
| `Code` | `.text` segment (RX) |
| `Data` | `.data`, `.bss` segments (RW) |
| `Heap` | Grows upward via `brk` |
| `Stack` | Grows downward, 64 KiB default |
| `Mmap` | Memory-mapped regions |

## Typical Process Layout

```
0x0000_0000_0040_0000  ┬─ ELF .text (RX)
                       │  ELF .rodata (R)
                       │  ELF .data (RW)
                       │  ELF .bss (RW)
                       ├─ Program break (heap starts here)
                       │  ... heap grows up ...
                       │
                       │  ... free space ...
                       │
                       │  ... stack grows down ...
0x0000_7FFF_FFFF_0000  ├─ User stack top (64 KiB)
0x0000_7FFF_FFFF_FFFF  └─ USER_SPACE_END
```

## Operations

| Operation | Description |
|-----------|-------------|
| `add_region()` | Insert a new VmRegion (overlap-checked) |
| `remove_region()` | Remove by start address |
| `find_region()` | Find the region containing an address |
| `set_brk()` | Update the program break |
| `create_user_space()` | Allocate PML4 + copy kernel mappings |

## ELF Loading

When `execve` loads an ELF binary, each `PT_LOAD` segment becomes
a `VmRegion`:

```
PT_LOAD (PF_R|PF_X) → VmRegion { prot: RX, kind: Code }
PT_LOAD (PF_R|PF_W) → VmRegion { prot: RW, kind: Data }
```

The stack region is added separately, and the program break is set
to the first page boundary above the highest segment.
