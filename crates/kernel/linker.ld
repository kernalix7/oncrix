/* Copyright 2026 ONCRIX Contributors */
/* SPDX-License-Identifier: Apache-2.0 */

/* x86_64 kernel linker script */
/* Kernel is loaded at the conventional higher-half address */

ENTRY(_start)

KERNEL_PHYS_BASE = 0x100000;        /* 1 MiB physical load address */
KERNEL_VIRT_BASE = 0xFFFFFFFF80000000; /* -2 GiB (higher-half) */
KERNEL_OFFSET    = KERNEL_VIRT_BASE - KERNEL_PHYS_BASE;

SECTIONS
{
    . = KERNEL_VIRT_BASE;

    /* Multiboot2 header must be in the first 32 KiB */
    .multiboot2 ALIGN(8) : AT(ADDR(.multiboot2) - KERNEL_OFFSET)
    {
        KEEP(*(.multiboot2))
    }

    /* Code section */
    .text ALIGN(4K) : AT(ADDR(.text) - KERNEL_OFFSET)
    {
        __text_start = .;
        *(.text .text.*)
        __text_end = .;
    }

    /* Read-only data */
    .rodata ALIGN(4K) : AT(ADDR(.rodata) - KERNEL_OFFSET)
    {
        __rodata_start = .;
        *(.rodata .rodata.*)
        __rodata_end = .;
    }

    /* Initialized read-write data */
    .data ALIGN(4K) : AT(ADDR(.data) - KERNEL_OFFSET)
    {
        __data_start = .;
        *(.data .data.*)
        __data_end = .;
    }

    /* Uninitialized data (zeroed by bootloader/startup) */
    .bss ALIGN(4K) : AT(ADDR(.bss) - KERNEL_OFFSET)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    __kernel_end = .;

    /* Discard unwanted sections */
    /DISCARD/ :
    {
        *(.comment)
        *(.note.*)
        *(.eh_frame*)
    }
}
