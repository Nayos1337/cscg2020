from pwn import *

p = process("./ropnop")

start = int(p.readline().split()[3],16)

input() # delay the script to start gdb

p.sendline(cyclic(50))

p.interactive()
