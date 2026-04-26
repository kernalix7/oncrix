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
- [Userspace Bringup (Phases 10b – 12)](userspace-bringup.md) — ring 3 transition, `USER_PT`, `fork`/`wait4`/`execve`, fd table over VFS

---

## Boot Sequence

ONCRIX boots via the **Xen PVH ELF Note** (type 18) — QEMU's
`-kernel` loader scans the note to find a 32-bit physical entry
for uncompressed ELF64 images. Multiboot1 is intentionally
omitted because QEMU's Multiboot1 loader rejects ELFCLASS64;
GRUB2 / Multiboot2 is used for ISO images.

```
QEMU -kernel (PVH)  /  GRUB2 (Multiboot2)
    │
    ▼
_start32  (boot.S, 32-bit stub at 1 MiB physical)
    │
    ├─ Zero 16 KiB boot page tables
    ├─ Build PML4[0]→PDPT_low→PD_0_1G    (identity 0..1 GiB)
    ├─ Build PML4[511]→PDPT_high          (higher-half -2 GiB)
    ├─ CR4.PAE | EFER.LME | CR0.PG        (enable long mode)
    └─ ljmp to _start64_trampoline
    │
    ▼
_start64  (higher-half at 0xFFFFFFFF80000000)
    │
    ├─ Switch to bootstrap stack (8 MiB)
    └─ call kernel_main
    │
    ▼
kernel_main  (main.rs)
    │
    ├─ Phase 1:  Serial console           (COM1, 115200 8N1)
    ├─ Phase 2:  GDT                      (5 segments + TSS)
    ├─ Phase 3:  IDT                      (5 exception handlers)
    ├─ Phase 4:  Kernel heap              (16 MiB linked-list)
    ├─ Phase 5:  Scheduler                (idle thread ready)
    ├─ Phase 6:  SYSCALL/SYSRET           (MSR setup)
    ├─ Phase 7:  PIC + PIT timer          (~100 Hz, enables IF)
    ├─ Phase 8:  Root filesystem          (ramfs on /, creates /dev /proc /tmp /sbin)
    ├─ Phase 9:  IPC channels             (kernel↔console, kernel↔devmgr, kernel↔netd)
    ├─ Phase 10: Service manager          (PID 0 + PID 1 registration, init boot)
    └─ halt_loop()
```

### Memory Layout

| Region | Virtual | Physical |
|--------|---------|----------|
| Boot stub (PVH note, 32-bit code, GDT) | `0xFFFFFFFF80100000+` | `0x00100000+` |
| `.text` / `.rodata` | higher-half | `0x0010X000+` |
| `.data` / `.bss` (incl. 16 MiB heap, 8 MiB bootstrap stack) | higher-half | after kernel image |

VMA is always higher-half. LMA is set via linker `AT()` so the
ELF image loads at low physical memory but symbols resolve to
their higher-half addresses.

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
