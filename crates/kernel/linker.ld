/* Copyright 2026 ONCRIX Contributors */
/* SPDX-License-Identifier: Apache-2.0 */

/* x86_64 kernel linker script.
 *
 * All symbols live in the higher-half virtual range so the x86_64 "kernel"
 * code model (±2 GiB RIP-relative addressing) works. The boot stub and
 * its headers, however, execute before paging is enabled, so they are
 * physically loaded at 1 MiB via AT(). Addresses inside the stub use
 * `label - KERNEL_OFFSET` to compute the physical location.
 */

ENTRY(_start32)

KERNEL_PHYS_BASE = 0x100000;             /* 1 MiB physical load address    */
KERNEL_VIRT_BASE = 0xFFFFFFFF80000000;   /* -2 GiB (higher-half)           */
KERNEL_OFFSET    = KERNEL_VIRT_BASE - KERNEL_PHYS_BASE;

SECTIONS
{
    /* Start VMA at KERNEL_VIRT_BASE + KERNEL_PHYS_BASE so VMA - LMA is
     * always exactly KERNEL_VIRT_BASE. Assembly in boot.S can then use
     * `label - KERNEL_VIRT_BASE` to obtain the physical load address.
     */
    . = KERNEL_VIRT_BASE + KERNEL_PHYS_BASE;
    __boot_start = .;

    /* Multiboot1 header must be in the first 8 KiB (aligned to 4). */
    /* Multiboot2 header must be in the first 32 KiB (aligned to 8). */
    .multiboot2 ALIGN(8) : AT(ADDR(.multiboot2) - KERNEL_VIRT_BASE)
    {
        KEEP(*(.multiboot2))
    }

    /* PVH ELF Note — scanned from a PT_NOTE segment at boot. */
    .note.Xen ALIGN(4) : AT(ADDR(.note.Xen) - KERNEL_VIRT_BASE)
    {
        KEEP(*(.note.Xen))
    }

    /* 32-bit bootstrap code, executed before paging. */
    .boot.text ALIGN(16) : AT(ADDR(.boot.text) - KERNEL_VIRT_BASE)
    {
        KEEP(*(.boot.text))
    }

    .boot.data ALIGN(16) : AT(ADDR(.boot.data) - KERNEL_VIRT_BASE)
    {
        KEEP(*(.boot.data))
    }

    .boot.bss ALIGN(4096) (NOLOAD) : AT(ADDR(.boot.bss) - KERNEL_VIRT_BASE)
    {
        KEEP(*(.boot.bss))
    }

    __boot_end = .;

    /* --- Higher-half kernel proper ---------------------------------------- */

    .text ALIGN(4K) : AT(ADDR(.text) - KERNEL_VIRT_BASE)
    {
        __text_start = .;
        *(.text .text.*)
        __text_end = .;
    }

    .rodata ALIGN(4K) : AT(ADDR(.rodata) - KERNEL_VIRT_BASE)
    {
        __rodata_start = .;
        *(.rodata .rodata.*)
        __rodata_end = .;
    }

    .data ALIGN(4K) : AT(ADDR(.data) - KERNEL_VIRT_BASE)
    {
        __data_start = .;
        *(.data .data.*)
        *(.got .got.*)
        *(.got.plt .got.plt.*)
        __data_end = .;
    }

    .bss ALIGN(4K) : AT(ADDR(.bss) - KERNEL_VIRT_BASE)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    __kernel_end = .;

    /DISCARD/ :
    {
        *(.comment)
        *(.note.GNU-stack)
        *(.note.gnu.build-id)
        *(.note.ABI-tag)
        *(.eh_frame*)
    }
}
