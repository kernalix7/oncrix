/* Copyright 2026 ONCRIX Contributors */
/* SPDX-License-Identifier: Apache-2.0 */

/* User-space ELF linker script.
 *
 * Produces a flat, position-dependent ELF binary loaded at 0x400000
 * (the traditional Linux user-space base address).  The kernel maps
 * the binary into a fresh address space before executing _start.
 */

ENTRY(_start)

USER_BASE = 0x400000;

SECTIONS
{
    . = USER_BASE;

    .text ALIGN(4096) :
    {
        __text_start = .;
        *(.text.startup)   /* entry point first */
        *(.text .text.*)
        __text_end = .;
    }

    .rodata ALIGN(4096) :
    {
        __rodata_start = .;
        *(.rodata .rodata.*)
        __rodata_end = .;
    }

    .data ALIGN(4096) :
    {
        __data_start = .;
        *(.data .data.*)
        *(.got .got.*)
        *(.got.plt .got.plt.*)
        __data_end = .;
    }

    .bss ALIGN(4096) (NOLOAD) :
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    __user_end = .;

    /DISCARD/ :
    {
        *(.comment)
        *(.note.GNU-stack)
        *(.note.gnu.build-id)
        *(.note.ABI-tag)
        *(.eh_frame*)
    }
}
