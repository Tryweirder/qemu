.code32
.text

#include "elfboot.h"

/*
 * Entry point for PVH guests.
 *
 * Xen ABI specifies the following register state when we come here:
 *
 * - `ebx`: contains the physical memory address where the loader has placed
 *          the boot start info structure.
 * - `cr0`: bit 0 (PE) must be set. All the other writeable bits are cleared.
 * - `cr4`: all bits are cleared.
 * - `cs `: must be a 32-bit read/execute code segment with a base of ‘0’
 *          and a limit of ‘0xFFFFFFFF’. The selector value is unspecified.
 * - `ds`, `es`: must be a 32-bit read/write data segment with a base of
 *               ‘0’ and a limit of ‘0xFFFFFFFF’.
 *               The selector values are all unspecified.
 * - `tr`: must be a 32-bit TSS (active) with a base of '0' and a limit
 *         of '0x67'.
 * - `eflags`: bit 17 (VM) must be cleared. Bit 9 (IF) must be cleared.
 *             Bit 8 (TF) must be cleared. Other bits are all unspecified.
 *
 * All other processor registers and flag bits are unspecified. The OS is in
 * charge of setting up it's own stack, GDT and IDT.
 */
.global pvh_entry
pvh_entry:
    # Output test banner string to serial0 and loop forever
    mov     $0x3F8, %dx
    mov     $banner, %esi
1:  movb    (%esi), %al
    or      %al, %al
    jz      2f
    outb    %al, %dx
    inc     %esi
    jmp     1b
2:  jmp     2b

banner: .asciz PVH_ELFBOOT_TEST_BANNER_STR

# Generate elf note section for xen PVH entry
.pushsection .note.Xen, "", @note;
.balign     4;
.long       name_end - name;
.long       desc_end - desc;
.long       XEN_ELFNOTE_PHYS32_ENTRY
name:       .asciz "Xen"
name_end:   .balign 4
desc:       .long pvh_entry
desc_end:   .balign 4
.popsection

# Pad .text to page size
.space 0x1000 - (. - pvh_entry)
