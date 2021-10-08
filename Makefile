CONFIG_MAKE = ../../configs/config.make
ifeq ($(wildcard $(CONFIG_MAKE)),$(CONFIG_MAKE))
include $(CONFIG_MAKE)
endif

AR = $(CROSS)ar
LD = $(CROSS)ld
RANLIB = $(CROSS)ranlib
DIR= $(shell pwd)
DSC_DIR=$(shell pwd)

obj-m:=  capwap.o
capwap-objs = capwap_core.o

ifeq ($(CAPWAP_CORE),y)
obj-m:=  capwap_core.o
capwap-objs = capwap_core.o
endif

ifeq ($(CAPWAP_NETLINK),y)
obj-m:=  capwap_netlink.o
capwap-objs = capwap_netlink.o
# capwap-objs += capwap_netlink.o capwap_eth.o
endif

ifeq ($(CAPWAP_ETH),y)
obj-m:=  capwap_eth.o
capwap-objs = capwap_eth.o
endif

##############################################

all: clean build

clean:
	$(RM) *.o *.ko *mod.c *~  .*.o.cmd .*.ko.cmd

capwap_core:
	$(MAKE) -C $(KERNEL_FULL_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS) M=$(DIR) modules

capwap_netlink:
	$(MAKE) -C $(KERNEL_FULL_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS) M=$(DIR) modules

capwap_eth:
	$(MAKE) -C $(KERNEL_FULL_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS) M=$(DIR) modules
	
build:
	$(MAKE) -C $(KERNEL_FULL_DIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS) M=$(DIR) modules
	
install:
	mkdir -p $(PREFIX)/lib;\
	cp capwap_core.ko $(PREFIX)/lib;\
	cp capwap_netlink.ko $(PREFIX)/lib;\
	cp capwap_eth.ko $(PREFIX)/lib
