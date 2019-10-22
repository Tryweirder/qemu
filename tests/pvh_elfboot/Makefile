-include $(BUILD_DIR)/config-host.mak
-include $(SRC_PATH)/rules.mak

$(call set-vpath, $(SRC_PATH)/tests/pvh_elfboot)

all: x86_entry.elf

# order matters: linker script must be first
x86_entry.elf: i386.lds x86_entry.o
	$(LD) -melf_i386 -T $+ -o $@

x86_entry.o: x86_entry.S elfboot.h
	$(CPP) -D __ASSEMBLER__ -I. $< -o- | $(AS) --32 -march=i386 -o $@ --

clean:
	rm -f *.o *.elf

.PHONY: clean all
