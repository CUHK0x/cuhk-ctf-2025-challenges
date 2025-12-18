#!/bin/bash
cat /home/ctf/logo
timeout 120 qemu-system-aarch64 \
	--snapshot \
	-machine virt \
	-initrd /home/ctf/rootfs.cpio \
	-kernel /home/ctf/Image \
	-append "console=ttyAMA0 init=/init panic=1000 oops=panic panic_on_warn=1 kaslr" \
	-monitor /dev/null \
	-nographic \
	-m 1G -smp cores=1 \
	-cpu cortex-a76