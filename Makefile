obj-m += kvm-hook.o
SRCDIR = $(PWD)
kvm-hook-objs := main.o kernel-hook/hook.o
MCFLAGS += -std=gnu11
ccflags-y += ${MCFLAGS}
CC += ${MCFLAGS}
KDIR := /lib/modules/$(shell uname -r)/build
KOUTPUT := $(PWD)/build
KOUTPUT_MAKEFILE := $(KOUTPUT)/Makefile

all: $(KOUTPUT_MAKEFILE)
	make -C $(KDIR) M=$(KOUTPUT) src=$(SRCDIR) modules

$(KOUTPUT):
	mkdir -p "$@"
	mkdir -p "$@"/kernel-hook

$(KOUTPUT_MAKEFILE): $(KOUTPUT)
	touch "$@"

clean:
	make -C $(KDIR) M=$(KOUTPUT) src=$(SRCDIR) clean
	$(shell rm $(KOUTPUT_MAKEFILE))
	rmdir $(KOUTPUT)/kernel-hook
	rmdir $(KOUTPUT)
