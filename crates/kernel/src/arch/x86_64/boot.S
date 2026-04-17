/* Copyright 2026 ONCRIX Contributors                                        */
/* SPDX-License-Identifier: Apache-2.0                                       */

/*
 * x86_64 boot entry.
 *
 * Provides Multiboot1 header + PVH ELF Note so QEMU -kernel can load the
 * kernel image directly, and a 32-bit entry stub that transitions to
 * long mode before calling into the Rust kernel_main.
 *
 * Memory layout (physical):
 *     0x00100000  MB1 header, PVH note, 32-bit stub, GDT
 *     then        .text, .rodata, .data, .bss (higher-half virtual)
 *
 * Virtual: higher-half KERNEL_VIRT_BASE = 0xFFFFFFFF80000000 (-2 GiB).
 *
 * Page tables built by the stub:
 *     PML4[0]    -> PDPT_low   (identity map 0..1 GiB, 2MiB pages)
 *     PML4[511]  -> PDPT_high  (maps 0xFFFFFFFF80000000..+2GiB to 0..2GiB)
 *     PDPT_low[0]    -> PD_0_1G   (1 GiB identity)
 *     PDPT_high[510] -> PD_0_1G   (higher-half -> low physical)
 *     PDPT_high[511] -> PD_0_1G   (covers -2G..0, reuses same PD)
 */

/* --- Xen PVH ELF Note ----------------------------------------------------- */
/* QEMU -kernel uses this to locate a 32-bit entry for uncompressed 64-bit  */
/* ELFs. Multiboot1 is intentionally omitted because QEMU's Multiboot1      */
/* loader rejects ELFCLASS64 images; GRUB2 (Multiboot2) is used for ISO.    */

.section .note.Xen, "a"
.align 4
    .long   4                        /* namesz                             */
    .long   4                        /* descsz                             */
    .long   18                       /* type = XEN_ELFNOTE_PHYS32_ENTRY    */
    .asciz  "Xen"                    /* name (padded to 4 bytes)           */
    .long   (_start32 - 0xFFFFFFFF80000000) /* 32-bit phys entry point     */

/* --- 32-bit stub: virtual == physical for this section -------------------- */

.section .boot.text, "ax"
.code32
.global _start32
_start32:
    cli

    /* Set up a small bootstrap stack (physical). */
    movl    $(_bootstrap_stack_top - 0xFFFFFFFF80000000), %esp

    /* Save Multiboot magic + info pointer (EAX, EBX) onto the stack for   */
    /* later pickup when we reach 64-bit mode.                             */
    pushl   $0
    pushl   %eax
    pushl   $0
    pushl   %ebx

    /* Zero the page-table region (16 KiB). */
    movl    $(__boot_page_tables - 0xFFFFFFFF80000000), %edi
    movl    %edi, %ecx
    xorl    %eax, %eax
    movl    $4096, %ecx              /* 16384 / 4                          */
    rep stosl

    /* Build PML4. */
    movl    $(__boot_page_tables - 0xFFFFFFFF80000000), %edi
    movl    $(__boot_pdpt_low  - 0xFFFFFFFF80000000), %eax
    orl     $0x03, %eax              /* present | writable                 */
    movl    %eax, (%edi)             /* PML4[0] -> PDPT_low                */
    movl    $(__boot_pdpt_high - 0xFFFFFFFF80000000), %eax
    orl     $0x03, %eax
    movl    %eax, 0xFF8(%edi)        /* PML4[511] -> PDPT_high             */

    /* PDPT_low[0] -> PD_0_1G  (identity 0..1G) */
    movl    $(__boot_pdpt_low - 0xFFFFFFFF80000000), %edi
    movl    $(__boot_pd_0_1g  - 0xFFFFFFFF80000000), %eax
    orl     $0x03, %eax
    movl    %eax, (%edi)

    /* PDPT_high[510] -> PD_0_1G  (virt 0xFFFFFFFF80000000..+1G to phys 0..1G) */
    /* PDPT_high[511] -> PD_0_1G  (virt 0xFFFFFFFFC0000000..+1G)                */
    movl    $(__boot_pdpt_high - 0xFFFFFFFF80000000), %edi
    movl    $(__boot_pd_0_1g   - 0xFFFFFFFF80000000), %eax
    orl     $0x03, %eax
    movl    %eax, 0xFF0(%edi)        /* entry 510                          */
    movl    %eax, 0xFF8(%edi)        /* entry 511                          */

    /* PD_0_1G: 512 x 2 MiB huge pages covering 0..1 GiB identity.          */
    movl    $(__boot_pd_0_1g - 0xFFFFFFFF80000000), %edi
    movl    $0x00000083, %eax        /* present | writable | 2M PS         */
    movl    $512, %ecx
1:
    movl    %eax, (%edi)
    movl    $0, 4(%edi)              /* high 32 bits of PTE                */
    addl    $0x200000, %eax          /* next 2 MiB                         */
    addl    $8, %edi
    loop    1b

    /* Enable PAE (CR4.PAE bit 5). */
    movl    %cr4, %eax
    orl     $(1 << 5), %eax
    movl    %eax, %cr4

    /* Load CR3 with PML4. */
    movl    $(__boot_page_tables - 0xFFFFFFFF80000000), %eax
    movl    %eax, %cr3

    /* Enable long mode (EFER.LME bit 8). */
    movl    $0xC0000080, %ecx        /* IA32_EFER MSR                      */
    rdmsr
    orl     $(1 << 8), %eax
    wrmsr

    /* Enable paging (CR0.PG) + write-protect (CR0.WP) + protected mode.   */
    movl    %cr0, %eax
    orl     $0x80010001, %eax        /* PG | WP | PE                       */
    movl    %eax, %cr0

    /* Load 64-bit GDT and far-jump into 64-bit code.                      */
    lgdt    (__boot_gdt64_ptr - 0xFFFFFFFF80000000)
    ljmp    $0x08, $(_start64_trampoline - 0xFFFFFFFF80000000)

/* --- 64-bit trampoline: still running at low physical ------------------- */

.code64
_start64_trampoline:
    /* Reload data segments with the 64-bit data selector. */
    movw    $0x10, %ax
    movw    %ax, %ds
    movw    %ax, %es
    movw    %ax, %fs
    movw    %ax, %gs
    movw    %ax, %ss

    /* Jump to the higher-half address of the 64-bit Rust entry. */
    movabs  $_start64, %rax
    jmp     *%rax

/* --- 64-bit entry: now running at higher-half virtual address ----------- */

.section .text, "ax"
.code64
.global _start64
_start64:
    /* Switch to the higher-half bootstrap stack. */
    movabs  $_bootstrap_stack_top, %rsp

    /* kernel_main takes no arguments; multiboot info was discarded for    */
    /* the minimal boot path. Subsystems that need it can read it later    */
    /* via dedicated interfaces once MM is up.                             */
    call    kernel_main

    /* kernel_main returns !, but guard against accidental return.         */
1:  cli
    hlt
    jmp     1b

/* --- 64-bit temporary GDT ----------------------------------------------- */

.section .boot.data, "a"
.align 16
__boot_gdt64:
    .quad   0x0000000000000000       /* null                               */
    .quad   0x00AF9A000000FFFF       /* 0x08: 64-bit code (L=1, DPL=0)     */
    .quad   0x00CF92000000FFFF       /* 0x10: data (writable)              */
__boot_gdt64_end:

.align 8
__boot_gdt64_ptr:
    .word   __boot_gdt64_end - __boot_gdt64 - 1
    .long   __boot_gdt64 - 0xFFFFFFFF80000000
    .long   0

/* --- Boot page tables (16 KiB, zeroed by stub) -------------------------- */

.section .boot.bss, "aw", @nobits
.align 4096
.global __boot_page_tables
__boot_page_tables:
    .skip   4096                     /* PML4                               */
__boot_pdpt_low:
    .skip   4096
__boot_pdpt_high:
    .skip   4096
__boot_pd_0_1g:
    .skip   4096

/* --- Bootstrap stack (8 MiB) -------------------------------------------- */
/* Sized to accommodate kernel_main's debug-build stack frame; inline      */
/* `KernelState::new()` + `Box::new()` chain consumes several MiB before   */
/* the value is moved to the heap. Release builds use far less.            */

.align 16
_bootstrap_stack:
    .skip   0x800000
_bootstrap_stack_top:
