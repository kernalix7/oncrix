/* Copyright 2026 ONCRIX Contributors */
/* SPDX-License-Identifier: Apache-2.0 */

/* AArch64 kernel linker script.
 *
 * QEMU -kernel loads the ELF at its physical addresses; we use a flat
 * 1:1 (identity) mapping so VMA == LMA.  The boot stub enables the MMU
 * with TTBR0_EL1 pointing at identity-mapped page tables, so physical
 * and virtual addresses are equal during early boot.
 *
 * QEMU virt machine loads ELF at 0x40080000 by default.
 */

ENTRY(_start)

SECTIONS
{
    . = 0x40080000;

    .text.boot : {
        KEEP(*(.text.boot))
    }

    .text ALIGN(4096) : {
        __text_start = .;
        *(.text .text.*)
        __text_end = .;
    }

    .rodata ALIGN(4096) : {
        __rodata_start = .;
        *(.rodata .rodata.*)
        __rodata_end = .;
    }

    .data ALIGN(4096) : {
        __data_start = .;
        *(.data .data.*)
        *(.got .got.*)
        __data_end = .;
    }

    .bss ALIGN(4096) (NOLOAD) : {
        __bss_start = .;
        *(.bss .bss.*)
        *(.bss.stack)
        *(COMMON)
        __bss_end = .;
    }

    __kernel_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.note.GNU-stack)
        *(.note.gnu.build-id)
        *(.note.ABI-tag)
        *(.eh_frame*)
        *(.ARM.exidx*)
    }
}
