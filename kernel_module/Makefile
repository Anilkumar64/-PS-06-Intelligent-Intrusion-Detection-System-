obj-m += ids_kmod.o

KDIR ?= /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

load:
	sudo insmod ids_kmod.ko

unload:
	sudo rmmod ids_kmod

reload: unload load

status:
	lsmod | grep ids_kmod || echo "Module not loaded"
	dmesg | tail -5

.PHONY: all clean load unload reload status