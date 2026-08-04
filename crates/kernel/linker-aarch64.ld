/* Copyright 2026 ONCRIX Contributors */
/* SPDX-License-Identifier: Apache-2.0 */

/* AArch64 kernel linker script.
 *
 * QEMU -kernel loads the ELF at its physical addresses. The boot stub uses
 * identity mappings for the kernel and MMIO while installing dedicated user
 * mappings in the same TTBR0_EL1 hierarchy before enabling the MMU.
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

    .text.user ALIGN(4096) : {
        __user_text_start = .;
        KEEP(*(.text.user))
        __user_text_end = .;
        . = __user_text_start + 4096;
    }

    ASSERT((__user_text_start & 0xFFF) == 0,
           ".text.user must start on a 4 KiB boundary")
    ASSERT((__user_text_end - __user_text_start) <= 4096,
           ".text.user payload exceeds one page")
    ASSERT(SIZEOF(.text.user) == 4096, ".text.user must occupy exactly one page")

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

    .bss.user ALIGN(4096) (NOLOAD) : {
        __bss_start = .;
        __user_stack_start = .;
        KEEP(*(.bss.user))
        __user_stack_end = .;
    }

    ASSERT((__user_stack_start & 0xFFF) == 0,
           ".bss.user must start on a 4 KiB boundary")
    ASSERT((__user_stack_end - __user_stack_start) == 16384,
           ".bss.user must contain exactly 16 KiB")

    .bss ALIGN(4096) (NOLOAD) : {
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
