# Virtual Memory (Page Tables)

## 4-Level Page Table (x86_64)

```
Virtual Address (48-bit):
┌─────────┬─────────┬─────────┬─────────┬────────────┐
│ PML4    │ PDPT    │ PD      │ PT      │ Offset     │
│ [47:39] │ [38:30] │ [29:21] │ [20:12] │ [11:0]     │
│ 9 bits  │ 9 bits  │ 9 bits  │ 9 bits  │ 12 bits    │
└─────────┴─────────┴─────────┴─────────┴────────────┘
    │          │         │         │          │
    ▼          ▼         ▼         ▼          ▼
  PML4 ──▶ PDPT ──▶ PD ──▶ PT ──▶ Physical + Offset
```

Each table has 512 entries (512 × 8 bytes = 4 KiB).

## Page Table Entry

```
63                                        12 11      0
┌──┬────────────────────────────────────────┬────────┐
│NX│        Physical Frame Address          │ Flags  │
└──┴────────────────────────────────────────┴────────┘
```

### Flags

| Bit | Name | Description |
|-----|------|-------------|
| 0 | `PRESENT` | Entry is valid |
| 1 | `WRITABLE` | Page is writable |
| 2 | `USER` | Accessible from Ring 3 |
| 3 | `WRITE_THROUGH` | Write-through caching |
| 4 | `NO_CACHE` | Disable caching |
| 5 | `ACCESSED` | CPU sets on access |
| 6 | `DIRTY` | CPU sets on write |
| 7 | `HUGE_PAGE` | 2 MiB / 1 GiB page |
| 8 | `GLOBAL` | Not flushed on CR3 switch |
| 9 | `COW_BIT` | Copy-on-Write (OS-defined) |
| 63 | `NO_EXECUTE` | NX bit |

## Operations

### `map_page(pml4, virt, phys, flags, allocator)`

Maps a virtual page to a physical frame. Walks 4 levels,
allocating intermediate tables as needed.

### `unmap_page(pml4, virt)`

Removes a mapping. Returns the old physical frame.
Caller must flush the TLB afterward.

### TLB Management

```rust
// Flush a single page
unsafe fn flush_tlb_page(addr: u64);

// Flush entire TLB (reload CR3)
unsafe fn flush_tlb_all();
```

## Safety Invariants

Page table manipulation uses `unsafe` because:
1. Raw pointer casts from physical addresses
2. `&'static mut PageTable` references are exclusive-by-convention
3. TLB consistency must be maintained manually

The caller must ensure page table walks are serialized (single CPU
during boot, or lock-protected during SMP).
