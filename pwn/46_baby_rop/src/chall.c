#include <stdio.h>
#include <unistd.h>

void duh()
{
	printf(".");
	usleep(1000*800);
	printf(".");
	usleep(1000*800);
	printf(".");
	usleep(1000*800);
	puts("");
}

void init()
{
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
}

int main()
{
	init();

	puts("Hello fellow hackers!");
	duh();
	puts("This is kylebot again!");
	duh();
	puts("I'm going to give you a gift! Enjoy!");
	duh();

	printf(">> ");

	char c[0x10];
	read(0, c, 0x400);
}