/* Copyright 2026 ONCRIX Contributors */
/* SPDX-License-Identifier: Apache-2.0 */

/* RISC-V 64-bit kernel linker script.
 *
 * OpenSBI loads the next-stage payload at 0x80200000 on QEMU virt.
 * We use a flat 1:1 physical mapping (satp=0 during early boot).
 */

ENTRY(_start)

SECTIONS
{
    . = 0x80200000;

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
        *(.riscv.attributes)
    }
}
