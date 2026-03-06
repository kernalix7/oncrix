# x86_64 Architecture Support

ONCRIX's primary target platform. This section documents the
x86_64-specific implementation details.

## Contents

- [Boot Sequence](#boot-sequence)
- [GDT and TSS](#gdt-and-tss)
- [IDT and Exceptions](#idt-and-exceptions)
- [Paging](#paging)
- [SYSCALL/SYSRET](#syscallsysret)
- [Interrupt Controllers](#interrupt-controllers)
- [Timers](#timers)
- [Context Switching](#context-switching)

---

## Boot Sequence

```
GRUB / Multiboot2
    │
    ▼
_start()                    (kernel/src/main.rs)
    │
    ├─ Phase 1: Serial console (COM1, 115200 8N1)
    ├─ Phase 2: GDT (5 segments + TSS)
    ├─ Phase 3: IDT (5 exception handlers)
    ├─ Phase 4: Kernel heap (256 KiB linked-list)
    ├─ Phase 5: PIC remap (IRQ 0-15 → vectors 32-47)
    ├─ Phase 6: PIT timer (100 Hz periodic)
    ├─ Phase 7: Enable interrupts (sti)
    └─ halt_loop()
```

## GDT and TSS

| Entry | Selector | Description |
|-------|----------|-------------|
| 0 | `0x00` | Null descriptor |
| 1 | `0x08` | Kernel code (64-bit, DPL=0) |
| 2 | `0x10` | Kernel data (DPL=0) |
| 3 | `0x18` | User code (64-bit, DPL=3) |
| 4 | `0x20` | User data (DPL=3) |
| 5-6 | `0x28` | TSS (16-byte descriptor) |

The TSS provides:
- `RSP0`: Kernel stack for Ring 3 → Ring 0 transitions
- `IST1`: Dedicated stack for double fault handler

## IDT and Exceptions

| Vector | Exception | Handler | Error Code |
|--------|-----------|---------|------------|
| 0 | #DE Divide Error | Yes | No |
| 6 | #UD Invalid Opcode | Yes | No |
| 8 | #DF Double Fault | Yes (IST1) | Yes |
| 13 | #GP General Protection | Yes | Yes |
| 14 | #PF Page Fault | Yes (reads CR2) | Yes |
| 32 | IRQ0 Timer | Yes | No |
| 33 | IRQ1 Keyboard | Yes | No |
| 39 | IRQ7 Spurious | Yes | No |

## Paging

4-level page tables (PML4 → PDPT → PD → PT):

- 48-bit virtual addresses (256 TiB)
- 4 KiB page size (standard)
- Higher-half kernel at `0xFFFF_FFFF_8000_0000`
- NX bit supported (bit 63)
- CoW uses bit 9 (OS-available)

## SYSCALL/SYSRET

MSR setup for fast system call entry:

| MSR | Value | Purpose |
|-----|-------|---------|
| `EFER` | `+SCE` | Enable SYSCALL/SYSRET |
| `STAR` | `0x0013_0008_0000_0000` | Segment selectors |
| `LSTAR` | `syscall_entry` | Kernel entry point |
| `FMASK` | `0x200` | Clear IF on SYSCALL |

Entry sequence:
1. `swapgs` — Switch to kernel GS base (per-CPU data)
2. Save `RCX` (user RIP) and `R11` (user RFLAGS)
3. Switch to kernel stack (via per-CPU data)
4. Save all registers
5. Call `syscall_dispatch`
6. Restore registers
7. `swapgs` — Restore user GS base
8. `sysretq` — Return to user space

## Interrupt Controllers

### Legacy 8259 PIC

- Master PIC: IRQ 0-7 → vectors 32-39
- Slave PIC: IRQ 8-15 → vectors 40-47
- Remapped from default 0-15 to avoid exception conflicts

### Local APIC Timer

- MMIO at `0xFEE0_0000` (default)
- Calibrated against PIT for accurate timing
- Supports one-shot and periodic modes

## Context Switching

Callee-saved registers saved/restored in assembly:

```asm
; Save current context
push rbx
push rbp
push r12
push r13
push r14
push r15
mov [rdi], rsp    ; Save RSP to old thread

; Load new context
mov rsp, [rsi]    ; Load RSP from new thread
pop r15
pop r14
pop r13
pop r12
pop rbp
pop rbx
ret               ; Return to new thread's RIP
```
