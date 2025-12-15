from pwn import *
from hashlib import sha256

HOST = '127.0.0.1'

def make_unique() -> bytes:
    return f'// {random.randbytes(8).hex()}\n'.encode()

def submit(code: bytes, unique: bool = True) -> bytes:
    conn = remote(HOST, 8000)
    conn.sendlineafter(
        b'Enter your C source file: (Type "EOF" in one line to end the file)',
        code + (make_unique() if unique else b'') + b'EOF'
    )
    return conn.recvall()

# Blank program: WA
BLANK = b'''
#include <stdio.h>
#include <stdlib.h>

int main() {
    return 0;
}
'''
assert b'Wrong Answer' in submit(BLANK)

# Regular program with glibc IO functions:
# segfaults at scanf (possibly due to not properly initialized glibc) and WA
NORMAL_IO = b'''
#include <stdio.h>
#include <stdlib.h>

int main() {
    int n;
    scanf("%d", &n);
    printf("%d", n);
    char s[256];
    scanf("%255s", s);
    puts(s);
    puts("Hi!");
    return 0;
}
'''
code = NORMAL_IO + make_unique()
out = submit(code, False)
assert b'Segmentation fault' in out
assert b'Wrong Answer' in out

# Resubmit: Submission rejected
assert b'Submission rejected' in submit(code, False)

# Program with glibc IO that outputs the correct answer: AC
FLAG = b'cuhk25ctf{4773N710n_70_d3741L_15_4Ll_y0u_N33D}'
CORRECT = f'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <time.h>
#include <stdbool.h>

int read_int() {{
    char buf[64];
    if (fgets(buf, sizeof(buf), stdin) == NULL)
        return 0;
    return atoi(buf);
}}

int main() {{
    int n = read_int();
    for (int i = 0; i < n; i++) {{
        char s[256];
        fgets(s, sizeof(s), stdin);
        if (strcmp(s, "{sha256(FLAG).hexdigest()}\\\\n") == 0) {{
            puts("YES");
        }} else puts("NO");
    }}
    fflush(stdout);
    return 0;
}}
'''
assert b'Accepted' in submit(CORRECT.encode())

# Bad Program: Compilation Error
MALFORMED = b'''
FLAG=cuhk25ctf{hehehaha}
'''
assert b'Compilation Error' in submit(MALFORMED)

# Opening file: Security violation
OPEN_FILE = b'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <math.h>
#include <time.h>
#include <stdbool.h>

int main() {
    FILE *f = fopen("/etc/passwd", "r");
    char buf[512];
    fgets(buf, sizeof(buf), f);
    fclose(f);
    return 0;
}
'''
assert b'Security Violation' in submit(OPEN_FILE)

LOOP = b'''
int main() {
    while (1) {}
}
'''
assert b'Time Limit Exceeded' in submit(LOOP)

# Solution: Gets flag
# Just run the script because I am lazy
# Okay this test sometimes fails, just run the solve script directly if happens
output = subprocess.run(['python3', 'solve.py'], cwd=str(Path(__file__).parent / Path('../writeup/')), stdout=PIPE).stdout
assert re.search(b'cuhk25ctf{.*}', output) is not None

print('Tests completed without errors.')