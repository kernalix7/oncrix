# ELF Binary Loading

## Overview

ONCRIX loads user-space programs from ELF64 binaries. The loader
supports `ET_EXEC` (static executables) and `ET_DYN` (PIE)
for x86_64.

## ELF Parsing Pipeline

```
ELF file bytes
    │
    ▼
parse_header()
    │  Validates: magic, class (64-bit), endianness (LE),
    │  machine (x86_64), type (EXEC or DYN)
    ▼
load_segments()
    │  Extracts PT_LOAD segments (up to 16)
    │  Returns: vaddr, file_offset, file_size, mem_size, flags, align
    ▼
prepare_exec() / do_execve()
    │  Creates AddressSpace with VmRegions for each segment
    │  Sets up user stack (64 KiB)
    │  Computes initial program break
    ▼
create_user_thread()
    │  Allocates TID, creates Thread at entry point
    ▼
jump_to_usermode (iretq)
```

## Segment Mapping

| ELF Flags | Protection | RegionKind |
|-----------|-----------|------------|
| `PF_R \| PF_X` | `RX` | `Code` |
| `PF_R \| PF_W` | `RW` | `Data` |
| `PF_R` | `READ` | `Data` |

## Stack Layout (System V AMD64 ABI)

At process entry (`_start`), the stack contains:

```
(high address)
    NULL              ← end of envp
    envp[envc-1]
    ...
    envp[0]
    NULL              ← end of argv
    argv[argc-1]
    ...
    argv[0]
    argc              ← RSP points here
(low address)
```

The stack pointer is 16-byte aligned per ABI.

## execve Signal Behavior

Per POSIX, `execve` resets signal dispositions:
- Signals set to `SIG_IGN` → remain `SIG_IGN`
- Signals set to a handler → reset to `SIG_DFL`
- Signal mask is preserved
- Pending signals are preserved

## Safety

- All struct reads from ELF data use `read_unaligned` to prevent
  alignment UB (the input slice may not be 8-byte aligned)
- Program header bounds are checked with `checked_mul`/`checked_add`
  to prevent integer overflow
- Maximum ELF size is 16 MiB
