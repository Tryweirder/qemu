OUTPUT_FORMAT("elf32-i386")
PHDRS {
    text PT_LOAD FLAGS(5);
    note PT_NOTE FLAGS(0);
}
SECTIONS {
    . = 0x1000000;
    .text : { *(.text) } :text
    .note : { *(.note.*) } :note
}
