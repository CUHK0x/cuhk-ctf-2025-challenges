ARCH=arm64
CROSS_COMPILE=aarch64-linux-gnu-
KERNEL_ROOT=../linux/
obj-m += babi.o

all:
	#make CC=$(CC) CROSS_COMPILE=$(CROSS_COMPILE) ARCH=$(ARCH) -C $(KERNEL_ROOT) M=$(PWD) modules
	make CROSS_COMPILE=$(CROSS_COMPILE) ARCH=$(ARCH) -C $(KERNEL_ROOT) M=$(PWD) modules

clean:
	make CROSS_COMPILE=$(CROSS_COMPILE) ARCH=$(ARCH) -C $(KERNEL_ROOT) M=$(PWD) clean