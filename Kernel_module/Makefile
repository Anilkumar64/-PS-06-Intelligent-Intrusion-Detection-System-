# SPDX-License-Identifier: GPL-2.0
#
# Makefile for ids_kmod
#
# Build:   make
# Clean:   make clean
# Install: sudo make install
#

# Kernel build directory
KDIR ?= /lib/modules/$(shell uname -r)/build

# Module source
obj-m := ids_kmod.o

# Compiler flags
ccflags-y := -Wall -Wextra -Wno-unused-parameter

# Default target
all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

install: all
	sudo cp ids_kmod.ko /lib/modules/$(shell uname -r)/extra/
	sudo depmod -a
	@echo "Installed. Load with: sudo modprobe ids_kmod"

load: all
	sudo insmod ids_kmod.ko
	@echo "Loaded. Check: dmesg | tail -5"

unload:
	sudo rmmod ids_kmod || true
	@echo "Unloaded."

reload: unload load

stats:
	@cat /proc/ids_kmod 2>/dev/null || echo "Module not loaded or /proc entry missing"

.PHONY: all clean install load unload reload stats