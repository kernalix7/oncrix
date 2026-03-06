# Glossary

## ONCRIX-Specific Terms

| Term | Definition |
|------|-----------|
| **ONCRIX** | ONCRIX Is Not a Copy, Real Independent uniX |
| **TCB** | Trusted Computing Base — the minimal code running in Ring 0 |
| **Capability** | An unforgeable token granting access to a resource |
| **Endpoint** | A named IPC communication point |
| **Channel** | A bidirectional message ring buffer between two processes |

## Memory Management

| Term | Definition |
|------|-----------|
| **PhysAddr** | A physical memory address (hardware bus address) |
| **VirtAddr** | A virtual memory address (as seen by the CPU) |
| **Frame** | A 4 KiB page frame in physical memory |
| **Page** | A 4 KiB page in virtual memory |
| **PML4** | Page Map Level 4 — root of the 4-level page table (x86_64) |
| **PDPT** | Page Directory Pointer Table (level 3) |
| **PD** | Page Directory (level 2) |
| **PT** | Page Table (level 1, contains leaf entries) |
| **PTE** | Page Table Entry — maps a virtual page to a physical frame |
| **CoW** | Copy-on-Write — lazy page duplication after fork |
| **TLB** | Translation Lookaside Buffer — page table cache in the CPU |

## Process Management

| Term | Definition |
|------|-----------|
| **PID** | Process Identifier (`Pid(u64)`) |
| **TID** | Thread Identifier (`Tid(u64)`) |
| **BSP** | Bootstrap Processor — the first CPU to boot |
| **AP** | Application Processor — additional CPUs in SMP |
| **Zombie** | A process that has exited but whose parent hasn't called wait |

## Hardware (x86_64)

| Term | Definition |
|------|-----------|
| **GDT** | Global Descriptor Table — segment descriptors |
| **IDT** | Interrupt Descriptor Table — interrupt/exception handlers |
| **TSS** | Task State Segment — kernel stack pointers for interrupts |
| **IST** | Interrupt Stack Table — dedicated stacks for critical exceptions |
| **APIC** | Advanced Programmable Interrupt Controller |
| **PIC** | Programmable Interrupt Controller (legacy 8259) |
| **PIT** | Programmable Interval Timer (legacy 8254) |
| **MSR** | Model-Specific Register |
| **CR2** | Control Register 2 — page fault linear address |
| **CR3** | Control Register 3 — PML4 physical address |
| **EFER** | Extended Feature Enable Register |
| **LSTAR** | Long SYSCALL Target Address Register |
| **FMASK** | SYSCALL Flag Mask Register |

## POSIX

| Term | Definition |
|------|-----------|
| **fd** | File descriptor — integer handle to an open file |
| **brk** | Program break — end of the heap segment |
| **SIGKILL** | Signal 9 — uncatchable termination |
| **SIGSTOP** | Signal 19 — uncatchable stop |
| **errno** | Error number — negative return from syscalls |
