# eVMoji
For this challenge we are given a binary and a file called `code.bin`.
If we run the binary we get:
```
Usage: ./eVMoji <code.bin>
[1]    8707 segmentation fault (core dumped)  ./eVMoji
```
That's weird, but as this is not a pwn challenge, we don't need to investigate that, but this segfault is probably caused by a forgotten `exit` call after check for the number of arguments. But back to the topic.
This is a Reversing so we need to get to know how this binary works. If we run the binary again with `code.bin` as an argument, we get:
```bash
$ ./eVMoji code.bin
Welcome to eVMoji 😎
🤝 me the 🏳️
```
after we input somehing we get
```
tRy hArder! 💀💀
```
This is again a challenge where we have to input some kind of password to get the flag. And by the name of the challenge, we can guess, that the binary implements some kind of VM and it is in some way connected to emojis. I loaded the binary into [Ghidra](https://ghidra-sre.org/) and started reversing:
This binary has no symbols, so we have  to start reversing from the entry point of the binary.
```c
void entry(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  undefined8 in_stack_00000000;
  undefined auStack8 [8];

  __libc_start_main(FUN_00101165,in_stack_00000000,&stack0x00000008,&LAB_00101270,&DAT_001012e0,
                    param_3,auStack8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}
```
Like in every stripped C program we can find here a call to `__libc_start_main`, were the first argument is the real main function:

```c
undefined8 main(int argc,char **argv)

{
  FILE *__stream;

  if (argc < 2) {
    puts("Usage: ./eVMoji <code.bin>");
  }
  _DAT_00302040 = 0;
  _DAT_00302058 = 0;
  DAT_00302048 = malloc(0x400);
  _DAT_00302050 = malloc(0x400);
  DAT_00302060 = malloc(0x10000);
  __stream = fopen(argv[1],"rb");
  if (__stream == (FILE *)0x0) {
    printf("File not found: %s",argv[1]);
  }
  fread(DAT_00302048,0x200,1,__stream);
  fread(DAT_00302060,0x10000,1,__stream);
  fclose(__stream);
  FUN_00100bc4(&DAT_00302040);
  return 0;
}
```
This function only opens the via argument supplied file and reads the first `0x200` bytes into one buffer and the next `0x10000` into another. A third buffer is also allocated, but not used yet. The addresses of these buffers are stored at a global address together with two zeros. This makes me believe, that a structure is located at this address. It should look link this:
```c
struct {
    uint64_t num1;
    byte[]* buff1;
    byte[]* buff2;
    uint64_t num2;
    byte[]* buff3;
}
```  
We can implement such a structure in Ghidra. At the end of main a function is called with a pointer to our struct. This function has to start the execution of the VM. That's why I named it `exec_vm` and the struct we created `vm`, because it represents the state of the VM.

```c
void exec_vm(vm *vm_state)

{
  byte bVar1;
  byte (*pabVar2) [1024];
  int iVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  byte *pbVar7;
  long in_FS_OFFSET;
  uint local_2c;
  uint local_28;
  uint local_24;
  undefined8 local_20;

  local_20 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  local_2c = 0;
  local_28 = 0;
LAB_00100bf0:
  local_24 = FUN_001009b0(*vm_state->buff3 + *(int *)&vm_state->num1);
  iVar3 = FUN_0010095a(*vm_state->buff3 + *(int *)&vm_state->num1);
  *(int *)&vm_state->num1 = iVar3 + *(int *)&vm_state->num1;
  if (local_24 == 0x80929ff0) {
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  if (local_24 < 0x80929ff1) {
    if (local_24 == 0x959ee2) {
      local_2c = FUN_00100b89(vm_state);
      local_2c = local_2c & 1;
      iVar3 = *(int *)&vm_state->num2;
      *(int *)&vm_state->num2 = iVar3 + 1;
      *(uint *)(*vm_state->buff2 + (long)iVar3 * 4) = local_2c;
      goto LAB_00100bf0;
    }
    if (local_24 < 0x959ee3) {
      if (local_24 == 0x859ce2) {
        uVar5 = FUN_00100b89(vm_state);
        uVar6 = FUN_00100b89();
        iVar3 = *(int *)&vm_state->num2;
        *(int *)&vm_state->num2 = iVar3 + 1;
        *(uint *)(*vm_state->buff2 + (long)iVar3 * 4) = uVar5 | uVar6;
        goto LAB_00100bf0;
      }
      if (local_24 == 0x8f9ce2) {
        uVar5 = FUN_00100b89(vm_state);
        pabVar2 = vm_state->buff1;
        uVar6 = FUN_00100b89(vm_state);
        write(1,*pabVar2 + uVar6,(ulong)uVar5);
        iVar3 = FUN_0010095a(*vm_state->buff3 + *(int *)&vm_state->num1);
        *(int *)&vm_state->num1 = iVar3 + *(int *)&vm_state->num1;
        goto LAB_00100bf0;
      }
    }
    else {
      if (local_24 == 0xa19ee2) {
        iVar3 = FUN_0010095a(*vm_state->buff3 + *(int *)&vm_state->num1);
        *(int *)&vm_state->num1 = iVar3 + *(int *)&vm_state->num1;
        pbVar7 = *vm_state->buff3 + *(int *)&vm_state->num1;
        iVar3 = FUN_00100a89(pbVar7,&local_2c,pbVar7);
        *(int *)&vm_state->num1 = iVar3 + *(int *)&vm_state->num1;
        local_28 = FUN_00100b89(vm_state);
        local_28 = local_28 >> ((byte)local_2c & 0x1f);
        iVar3 = *(int *)&vm_state->num2;
        *(int *)&vm_state->num2 = iVar3 + 1;
        *(uint *)(*vm_state->buff2 + (long)iVar3 * 4) = local_28;
        goto LAB_00100bf0;
      }
      if (local_24 == 0xbc80e2) {
        iVar3 = FUN_0010095a(*vm_state->buff3 + *(int *)&vm_state->num1);
        *(int *)&vm_state->num1 = iVar3 + *(int *)&vm_state->num1;
        local_2c = FUN_00100b89(vm_state);
        iVar3 = *(int *)&vm_state->num2;
        *(int *)&vm_state->num2 = iVar3 + 1;
        *(uint *)(*vm_state->buff2 + (long)iVar3 * 4) = local_2c;
        iVar3 = *(int *)&vm_state->num2;
        *(int *)&vm_state->num2 = iVar3 + 1;
        *(uint *)(*vm_state->buff2 + (long)iVar3 * 4) = local_2c;
        goto LAB_00100bf0;
      }
    }
  }
  else {
    if (local_24 == 0x96939ff0) {
      uVar5 = FUN_00100b89(vm_state);
      pabVar2 = vm_state->buff1;
      uVar6 = FUN_00100b89(vm_state);
      read(0,*pabVar2 + uVar6,(ulong)uVar5);
      goto LAB_00100bf0;
    }
    if (local_24 < 0x96939ff1) {
      if (local_24 == 0x80949ff0) {
        uVar5 = FUN_00100b89(vm_state);
        uVar6 = FUN_00100b89();
        iVar3 = *(int *)&vm_state->num2;
        *(int *)&vm_state->num2 = iVar3 + 1;
        *(uint *)(*vm_state->buff2 + (long)iVar3 * 4) = uVar5 ^ uVar6;
      }
      else {
        if (local_24 != 0x94a49ff0) goto LAB_00101147;
        pbVar7 = *vm_state->buff3 + *(int *)&vm_state->num1;
        iVar3 = FUN_00100a89(pbVar7,&local_2c,pbVar7);
        *(int *)&vm_state->num1 = iVar3 + *(int *)&vm_state->num1;
        iVar3 = FUN_00100b89(vm_state);
        iVar4 = FUN_00100b89(vm_state);
        if (iVar3 == iVar4) {
          *(uint *)&vm_state->num1 = local_2c + *(int *)&vm_state->num1;
        }
      }
      goto LAB_00100bf0;
    }
    if (local_24 == 0xaa929ff0) {
      pbVar7 = *vm_state->buff3 + *(int *)&vm_state->num1;
      iVar3 = FUN_00100a89(pbVar7,&local_2c,pbVar7);
      *(int *)&vm_state->num1 = iVar3 + *(int *)&vm_state->num1;
      iVar3 = *(int *)&vm_state->num2;
      *(int *)&vm_state->num2 = iVar3 + 1;
      *(uint *)(*vm_state->buff2 + (long)iVar3 * 4) = local_2c;
      goto LAB_00100bf0;
    }
    if (local_24 == 0xbea69ff0) {
      pbVar7 = *vm_state->buff3 + *(int *)&vm_state->num1;
      iVar3 = FUN_00100a89(pbVar7,&local_2c,pbVar7);
      *(int *)&vm_state->num1 = iVar3 + *(int *)&vm_state->num1;
      bVar1 = (*vm_state->buff1)[local_2c];
      iVar3 = *(int *)&vm_state->num2;
      *(int *)&vm_state->num2 = iVar3 + 1;
      *(int *)(*vm_state->buff2 + (long)iVar3 * 4) = (int)(char)bVar1;
      goto LAB_00100bf0;
    }
    if (local_24 == 0xa08c9ff0) {
      pbVar7 = *vm_state->buff3 + *(int *)&vm_state->num1;
      iVar3 = FUN_00100a89(pbVar7,&local_2c,pbVar7);
      *(int *)&vm_state->num1 = iVar3 + *(int *)&vm_state->num1;
      iVar3 = *(int *)&vm_state->num2;
      *(int *)&vm_state->num2 = iVar3 + 1;
      *(undefined4 *)(*vm_state->buff2 + (long)iVar3 * 4) =
           *(undefined4 *)(*vm_state->buff1 + local_2c);
      goto LAB_00100bf0;
    }
  }
LAB_00101147:
  printf("Unknown opcode: %x",(ulong)local_24);
  goto LAB_00100bf0;
}

```

This seems to be the main function of the vm, because at the beginning there is a label `LAB_00100bf0` from which we do some function calls and after that we have a lot of if/else blocks which compare the result of these function calls and execute different things bases on the result. After that is done they all jump back to the starting label `LAB_00100bf0`. That means, that the functions at the begin determines, the current optcode (Also the `Unknown optcode` at the label `LAB_00101147` is a clue). The first function call returns the optcode and the second function calculates some number, by which `num1` is advanced. `num1` is also used as an offset into `buff3`. It looks like, `num1` is some sort of instruction pointer and `buff3` is the code of the VM. We rename:

* `num1`         -> `rip`
* `buff3`        -> `code`
* `local_24`     -> `optcode`
* `LAB_00100bf0` -> `next_instr`
* `FUN_001009b0` -> `get_optcode`
* `FUN_0010095a` -> `optcode_len`

(Retyped `num1` to `int`)

Now let's have a look at the optcode returning function : `get_optcode`  
```c
ulong get_optcode(byte *code_ptr)

{
  uint length;
  uint result;
  uint i;

  length = optcode_len(code_ptr);
  result = 0;
  i = 0;
  while (i < length) {
    result = result | 0xff << ((byte)(i << 3) & 0x1f) &
                      (int)(char)code_ptr[(int)i] << ((byte)(i << 3) & 0x1f);
    i = i + 1;
  }
  return (ulong)result;
}
```
I've already rename a few variables:
* `code_ptr` from before we know this is a pointer into the code
* `length` returned by the already identified `optcode_len` function
* `i` just a counter for the loop

If we look at the code, than this transformation seems very random.... Until we change the `i << 3` to `i * 8` which is equivalent.
```
result = result | 0xff << ((i * 8) & 0x1f) & code_ptr[i] << ((i *8) & 0x1f);
```
(I've also removed some annoying casts)
```
result = result | (0xff & code_ptr[i]) << ((i *8) & 0x1f);
```
And with these changes it is more easy to understand. This function just concatinates `length` bytes in reverse order into the result variable and returns this value.
Now let's have a look at the `optcode_len` function:
```c
ulong optcode_len(char *code_ptr)
{
  undefined8 result;
  uint i;

  if (*code_ptr < '\0') {
    i = 2;
    while ((int)i < 5) {
      if ((0x80 >> ((byte)i & 0x1f) & (int)*code_ptr) == 0) {
        return (ulong)i;
      }
      i = i + 1;
    }
    result = 0xffffffff;
  }
  else {
    result = 1;
  }
  return result;
}
```
Renames:
* `code_ptr` from before we know this is a pointer into the code
* `i` just a counter for the loop
* `result` returned by the function

The first check this function does, is the `if`-clause. Here we compare the byte at `code_ptr` against `0`. This is a signed comparison, which means, it checks
whether or not the signbit is set. It essentially checks the highest bit of the byte. If it is not set, this comparison fails and we return 1. Otherwise we search for the first unset byte in the byte (starting at the second). This reminded me of the UTF-8 standard, where the first 0 in the highest byte determines the length of the codepoint.

Copied from [Wikipedia](https://en.wikipedia.org/wiki/UTF-8#Description):

| Number of bytes | Bits forcode point | Firstcode point | Lastcode point |  Byte 1  |  Byte 2  |  Byte 3  |  Byte 4  |
|:--------------:|:------------------:|:---------------:|:--------------:|:--------:|:--------:|:--------:|:--------:|
|        1       |          7         |          U+0000 |         U+007F | 0xxxxxxx |          |          |          |
|        2       |         11         |          U+0080 |         U+07FF | 110xxxxx | 10xxxxxx |          |          |
|        3       |         16         |          U+0800 |         U+FFFF | 1110xxxx | 10xxxxxx | 10xxxxxx |          |
|        4       |         21         |         U+10000 |   U+10FFFF | 11110xxx | 10xxxxxx | 10xxxxxx | 10xxxxxx |

And in the context with the Emoji in the name of the challenge, this makes a lot of sense. We can rename :
* `get_optcode` -> `get_utf8_chr`
* `optcode_len` -> `get_utf8_chr_len`

Without having looked at the `code.bin` file, we know, that each optcode has it's own emoji.
But let's go back to the `exec_vm` function:
```c
if (optcode == 0x80929ff0) {
                  /* WARNING: Subroutine does not return */
  exit(-1);
}
```
This is the first and easied optcode, it just exits the program.
As I plan to write a disassembler for the `code.bin` file, lets note that down:
```python
optcodes = {
    bytes.fromhex("80929ff0") : ("exit",  ""),
}
```
(The second item in the tuple is for possible arguments)
```c
if (optcode == 0x959ee2) {
  local_2c = FUN_00100b89(vm_state);
  local_2c = local_2c & 1;
  iVar3 = *(int *)&vm_state->num2;
  *(int *)&vm_state->num2 = iVar3 + 1;
  *(uint *)(*vm_state->buff2 + (long)iVar3 * 4) = local_2c;
  goto next_instr;
}
```
This is the second optcode. It does a bit more. First of all lets have a look at `FUN_00100b89`.

```c
ulong FUN_00100b89(vm *vm_state)

{
  *(int *)&vm_state->num2 = *(int *)&vm_state->num2 + -1;
  return (ulong)*(uint *)(*vm_state->buff2 + (long)*(int *)&vm_state->num2 * 4);
}
```
Renames / Retypes:
* `long param_1`  -> `vm* vm_state` (As we know from the caller)
* `uint64_t num2` -> `int num2`  (to get rid of the annoying casts)

```c
ulong FUN_00100b89(vm *vm_state)

{
  vm_state->num2 = vm_state->num2 + -1;
  return (ulong)*(uint *)(*vm_state->buff2 + (long)vm_state->num2 * 4);
}
```
We first decrement `num2` and return the `num2 * 4` value in the `buff2` member.
First of all it seems like `buff2` is not a byte array, but rather a `uint32_t` array because of the multiplication by 4.

```c
ulong FUN_00100b89(vm *vm_state)

{
  vm_state->num2 = vm_state->num2 + -1;
  return (ulong)(*vm_state->buff2)[vm_state->num2];
}
```
And this now seems like a very typical `pop` function. `num2` is the stack pointer and `buff2` is the stack itself.
* `FUN_00100b89` -> `pop`
* `num2` -> `rsp`
* `buff2` -> `stack`

Back to the last optcode.
```c
if (optcode == 0x959ee2) {
  local_2c = pop(vm_state);
  local_2c = local_2c & 1;
  iVar3 = vm_state->rsp;
  vm_state->rsp = iVar3 + 1;
  (*vm_state->stack)[iVar3] = local_2c;
  goto next_instr;
}
```
It is now a lot more readable: We first pop a value of the stack. Then we `and` it with 1 and push it again.

```python
optcodes = {
    bytes.fromhex("80929ff0") : ("exit",  ""),
    bytes.fromhex("959ee2")   : ("isodd",  ""),
}
```
```c
if (optcode == 0x859ce2) {
  uVar5 = pop(vm_state);
  uVar6 = pop(vm_state);
  iVar3 = vm_state->rsp;
  vm_state->rsp = iVar3 + 1;
  (*vm_state->stack)[iVar3] = uVar5 | uVar6;
  goto next_instr;
}
```

In this case we pop two values `or` them together and push the result again.
```python
optcodes = {
    bytes.fromhex("80929ff0") : ("exit",  ""),
    bytes.fromhex("959ee2")   : ("isodd",  ""),
    bytes.fromhex("859ce2")   : ("or",  ""),
}
```

```c
if (optcode == 0x8f9ce2) {
  uVar5 = pop(vm_state);
  pabVar2 = vm_state->buff1;
  uVar6 = pop(vm_state);
  write(1,*pabVar2 + uVar6,(ulong)uVar5);
  iVar3 = get_utf8_chr_len(*vm_state->code + vm_state->rip);
  vm_state->rip = iVar3 + vm_state->rip;
  goto next_instr;
}
```
This seems to be a `print` function because of the `write` in the middle of the function. It pops two values : `address` and `length`. `address` is an offset into the `buff1` buffer, where the string is located. `length` is the length of the string which is printed.
* `buff1` -> `data`

The end of the function is still a bit weird, because we advance the instruction point by a UTF-8 codepoint, without actually using it. But after a bit of thinking about what this could mean, I just accepted it as is.
```python
optcodes = {
    bytes.fromhex("80929ff0") : ("exit",  ""),
    bytes.fromhex("959ee2")   : ("isodd",  ""),
    bytes.fromhex("859ce2")   : ("or",  ""),
    bytes.fromhex("8f9ce2")   : ("print",  "-"),
}
```
(The `-` in the arguments means, that the codepoint after the optcode is skipped but not used)
```c
if (optcode == 0xa19ee2) {
  iVar3 = get_utf8_chr_len(*vm_state->code + vm_state->rip);
  vm_state->rip = iVar3 + vm_state->rip;
  pbVar7 = *vm_state->code + vm_state->rip;
  iVar3 = FUN_00100a89(pbVar7,&local_2c,pbVar7);
  vm_state->rip = iVar3 + vm_state->rip;
  local_28 = pop(vm_state);
  local_28 = local_28 >> ((byte)local_2c & 0x1f);
  iVar3 = vm_state->rsp;
  vm_state->rsp = iVar3 + 1;
  (*vm_state->stack)[iVar3] = local_28;
  goto next_instr;
}
```
This optcode seems to be very complex. It also calls a not yet identified function `FUN_00100a89`:

```c
ulong FUN_00100a89(byte *code_ptr,uint *result)

{
  char cVar1;
  long in_FS_OFFSET;
  double dVar2;
  char local_1a;
  char local_19;
  uint length;
  int i;
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  *result = 0;
  length = 0;
  i = 0;
  while (i < 3) {
    cVar1 = FUN_00100a26(code_ptr + (int)length,&local_1a,code_ptr + (int)length);
    length = length + (int)cVar1;
    cVar1 = FUN_00100a26(code_ptr + (int)length,&local_19,code_ptr + (int)length);
    length = length + (int)cVar1;
    dVar2 = pow((double)(int)local_19,(double)(int)local_1a);
    *result = (uint)(long)((double)(ulong)*result + dVar2);
    i = i + 1;
  }
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return (ulong)length;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
Ranamed:
* `code_ptr` we know this from the caller
* `result` caller passes a not jet used pointer to a local variable -> result
* `length` caller advances `rip` by this amount
* `i` just a counter for the loop

The loop loops three times. In each of these it calls `FUN_00100a26`, which modifies the second argument and returns some kind of length again. After these calls, we cast the results to floats and call `pow` on those, which seems very wired.
After now finally having a look at the `code.bin` file I knew what this function was doing. All over `code.bin`, there are strings of codepoint similar to this `1️⃣0️⃣2️⃣4️⃣7️⃣2️⃣`. This number contains 6 codepoints. This is  the same amount of times this function calls `FUN_00100a26`. From this we can conclude, that `FUN_00100a26` somehow parses one of these codepoints. But still the `pow` function call is very weird. At first I thought, that this was a very inefficient implementation of a number parsing system, where the `pow` call is used to calculate `10**n` for the nth digit. But as it turns out this is just a very weird number system.
If we assume, that `FUN_00100a26` writes just the digit we found into `local_1a` or `local_19` respecectifly, than the number earlier would result in : `0 ** 1 + 4 ** 2 + 2 ** 7 = 144`, which is actually true. We can verify this by a bit of debugging.
* `FUN_00100a26` -> `parse_dig`
* `FUN_00100a89` -> `parse_num`

```c
if (optcode == 0xa19ee2) {
  iVar3 = get_utf8_chr_len(*vm_state->code + vm_state->rip);
  vm_state->rip = iVar3 + vm_state->rip;
  iVar3 = parse_num(*vm_state->code + vm_state->rip,&local_2c);
  vm_state->rip = iVar3 + vm_state->rip;
  local_28 = pop(vm_state);
  local_28 = local_28 >> ((byte)local_2c & 0x1f);
  iVar3 = vm_state->rsp;
  vm_state->rsp = iVar3 + 1;
  (*vm_state->stack)[iVar3] = local_28;
  goto next_instr;
}
```

This optcode first drops one codepoint, than parses a number and after that pops a number, which is shifted right by the parsed number.
```python
optcodes = {
    bytes.fromhex("80929ff0") : ("exit",  ""),
    bytes.fromhex("959ee2")   : ("isodd",  ""),
    bytes.fromhex("859ce2")   : ("or",  ""),
    bytes.fromhex("8f9ce2")   : ("print",  "-"),
    bytes.fromhex("a19ee2")   : ("shr",  "-n"),
}
```
(`n` in the arguments stands for a number to be parsed)

```c
if (optcode == 0xbc80e2) {
  iVar3 = get_utf8_chr_len(*vm_state->code + vm_state->rip);
  vm_state->rip = iVar3 + vm_state->rip;
  local_2c = pop(vm_state);
  iVar3 = vm_state->rsp;
  vm_state->rsp = iVar3 + 1;
  (*vm_state->stack)[iVar3] = local_2c;
  iVar3 = vm_state->rsp;
  vm_state->rsp = iVar3 + 1;
  (*vm_state->stack)[iVar3] = local_2c;
  goto next_instr;
}
```
Again here we drop a codepoint, than we pop a value wich is pushed twice.

```python
optcodes = {
    bytes.fromhex("80929ff0") : ("exit",  ""),
    bytes.fromhex("959ee2")   : ("isodd",  ""),
    bytes.fromhex("859ce2")   : ("or",  ""),
    bytes.fromhex("8f9ce2")   : ("print",  "-"),
    bytes.fromhex("a19ee2")   : ("shr",  "-n"),
    bytes.fromhex("bc80e2")   : ("dup",  "-"),
}
```
```c
if (optcode == 0x96939ff0) {
  uVar5 = pop(vm_state);
  pabVar2 = vm_state->data;
  uVar6 = pop(vm_state);
  read(0,*pabVar2 + uVar6,(ulong)uVar5);
  goto next_instr;
}
```
This is similar to the write function, but this optcode reads insted of writing.

```python
optcodes = {
    bytes.fromhex("80929ff0") : ("exit",  ""),
    bytes.fromhex("959ee2")   : ("isodd",  ""),
    bytes.fromhex("859ce2")   : ("or",  ""),
    bytes.fromhex("8f9ce2")   : ("print",  "-"),
    bytes.fromhex("a19ee2")   : ("shr",  "-n"),
    bytes.fromhex("bc80e2")   : ("dup",  "-"),
    bytes.fromhex("96939ff0") : ("read",  ""),
}
```

```c
if (optcode == 0x80949ff0) {
  uVar5 = pop(vm_state);
  uVar6 = pop(vm_state);
  iVar3 = vm_state->rsp;
  vm_state->rsp = iVar3 + 1;
  (*vm_state->stack)[iVar3] = uVar5 ^ uVar6;
}
```
This just `xor`s two popped values and pushes them again.
```python
optcodes = {
    bytes.fromhex("80929ff0") : ("exit",  ""),
    bytes.fromhex("959ee2")   : ("isodd",  ""),
    bytes.fromhex("859ce2")   : ("or",  ""),
    bytes.fromhex("8f9ce2")   : ("print",  "-"),
    bytes.fromhex("a19ee2")   : ("shr",  "-n"),
    bytes.fromhex("bc80e2")   : ("dup",  "-"),
    bytes.fromhex("96939ff0") : ("read",  ""),
    bytes.fromhex("80949ff0") : ("xor",  ""),
}
```

```c
if (optcode != 0x94a49ff0) goto unknown_opcode;
iVar3 = parse_num(*vm_state->code + vm_state->rip,&local_2c);
vm_state->rip = iVar3 + vm_state->rip;
iVar3 = pop(vm_state);
iVar4 = pop(vm_state);
if (iVar3 == iVar4) {
  vm_state->rip = local_2c + vm_state->rip;
}
```
This first parses a number, than it popps two values and increments `rip` by the parsed amount if they match. (Jump if equal)
```python
optcodes = {
    bytes.fromhex("80929ff0") : ("exit",  ""),
    bytes.fromhex("959ee2")   : ("isodd",  ""),
    bytes.fromhex("859ce2")   : ("or",  ""),
    bytes.fromhex("8f9ce2")   : ("print",  "-"),
    bytes.fromhex("a19ee2")   : ("shr",  "-n"),
    bytes.fromhex("bc80e2")   : ("dup",  "-"),
    bytes.fromhex("96939ff0") : ("read",  ""),
    bytes.fromhex("80949ff0") : ("xor",  ""),
    bytes.fromhex("94a49ff0") : ("jeq",  "o"),
}
```
(`o` as an argument states, that this is an offset to the current rip)
```c
if (optcode == 0xaa929ff0) {
  iVar3 = parse_num(*vm_state->code + vm_state->rip,&local_2c);
  vm_state->rip = iVar3 + vm_state->rip;
  iVar3 = vm_state->rsp;
  vm_state->rsp = iVar3 + 1;
  (*vm_state->stack)[iVar3] = local_2c;
  goto next_instr;
}
```
This just pushes a parsed number.
```python
optcodes = {
    bytes.fromhex("80929ff0") : ("exit",  ""),
    bytes.fromhex("959ee2")   : ("isodd",  ""),
    bytes.fromhex("859ce2")   : ("or",  ""),
    bytes.fromhex("8f9ce2")   : ("print",  "-"),
    bytes.fromhex("a19ee2")   : ("shr",  "-n"),
    bytes.fromhex("bc80e2")   : ("dup",  "-"),
    bytes.fromhex("96939ff0") : ("read",  ""),
    bytes.fromhex("80949ff0") : ("xor",  ""),
    bytes.fromhex("94a49ff0") : ("jeq",  "o"),
    bytes.fromhex("aa929ff0") : ("push",  "n"),
}
```
```c
if (optcode == 0xbea69ff0) {
  iVar3 = parse_num(*vm_state->code + vm_state->rip,&local_2c);
  vm_state->rip = iVar3 + vm_state->rip;
  bVar1 = (*vm_state->data)[local_2c];
  iVar3 = vm_state->rsp;
  vm_state->rsp = iVar3 + 1;
  (*vm_state->stack)[iVar3] = (int)(char)bVar1;
  goto next_instr;
}
```
This parses a number and pushes the value `data[number]`
```python
optcodes = {
    bytes.fromhex("80929ff0") : ("exit",  ""),
    bytes.fromhex("959ee2")   : ("isodd",  ""),
    bytes.fromhex("859ce2")   : ("or",  ""),
    bytes.fromhex("8f9ce2")   : ("print",  "-"),
    bytes.fromhex("a19ee2")   : ("shr",  "-n"),
    bytes.fromhex("bc80e2")   : ("dup",  "-"),
    bytes.fromhex("96939ff0") : ("read",  ""),
    bytes.fromhex("80949ff0") : ("xor",  ""),
    bytes.fromhex("94a49ff0") : ("jeq",  "o"),
    bytes.fromhex("aa929ff0") : ("push",  "n"),
    bytes.fromhex("bea69ff0") : ("load",  "n"),
}
```

```c
if (optcode == 0xa08c9ff0) {
  iVar3 = parse_num(*vm_state->code + vm_state->rip,&local_2c);
  vm_state->rip = iVar3 + vm_state->rip;
  iVar3 = vm_state->rsp;
  vm_state->rsp = iVar3 + 1;
  (*vm_state->stack)[iVar3] = *(uint32_t *)(*vm_state->data + local_2c);
  goto next_instr;
}
```
This is the last optcode and it does exactly the same as the one before, but is loads a 32 bit integer instead of only a byte
```python
optcodes = {
    bytes.fromhex("80929ff0") : ("exit",  ""),
    bytes.fromhex("959ee2")   : ("isodd",  ""),
    bytes.fromhex("859ce2")   : ("or",  ""),
    bytes.fromhex("8f9ce2")   : ("print",  "-"),
    bytes.fromhex("a19ee2")   : ("shr",  "-n"),
    bytes.fromhex("bc80e2")   : ("dup",  "-"),
    bytes.fromhex("96939ff0") : ("read",  ""),
    bytes.fromhex("80949ff0") : ("xor",  ""),
    bytes.fromhex("94a49ff0") : ("jeq",  "o"),
    bytes.fromhex("aa929ff0") : ("push",  "n"),
    bytes.fromhex("bea69ff0") : ("load",  "n"),
    bytes.fromhex("a08c9ff0") : ("load32",  "n"),
}
```
Now we can actually start writing a disassembler for this language. First of all I just reimplemented a few functions into python
```python
def get_utf8_chr_len(c):
    if c & 0x80 == 0:
        return 1
    i = 2
    while i < 5:
        if (0x80 >> i) & c == 0:
            return i
        i += 1

def get_utf8_chr(buff):
    l = get_utf8_chr_len(buff[0])
    return buff[:l][::-1]


def parse_dig(buff):
    num = get_utf8_chr(buff)[0] - 0x30
    l = get_utf8_chr_len(buff[1])
    l += get_utf8_chr_len(buff[l + 1])
    return (num, l+1)

def parse_num(buff):
    off = 0
    res = 0
    for _ in range(3):
        e, l = parse_dig(buff[off:])
        off += l
        b, l = parse_dig(buff[off:])
        off += l
        res += b ** e
    return res, off
```
The rest of the script is just some basic logic to parse the code section:

```python
optcodes = {
    bytes.fromhex("80929ff0") : ("exit",  ""),
    bytes.fromhex("959ee2")   : ("isodd",  ""),
    bytes.fromhex("859ce2")   : ("or",  ""),
    bytes.fromhex("8f9ce2")   : ("print",  "-"),
    bytes.fromhex("a19ee2")   : ("shr",  "-n"),
    bytes.fromhex("bc80e2")   : ("dup",  "-"),
    bytes.fromhex("96939ff0") : ("read",  ""),
    bytes.fromhex("80949ff0") : ("xor",  ""),
    bytes.fromhex("94a49ff0") : ("jeq",  "o"),
    bytes.fromhex("aa929ff0") : ("push",  "n"),
    bytes.fromhex("bea69ff0") : ("load",  "n"),
    bytes.fromhex("a08c9ff0") : ("store",  "n"),
}

f = open("code.bin","rb")

data = f.read(0x200)
code = f.read(0x10000)


rip = 0

while True:
    if rip >= len(code):
        break
    optcode = get_utf8_chr(code[rip:])
    orip = rip
    rip    += get_utf8_chr_len(code[rip])

    if optcode not in optcodes:
        print("Unknown optcode : {}".format(optcode.hex()))
        exit()
    name,to_parse = optcodes[optcode]

    args = []

    for c in to_parse:
        if c == "-":
            rip += get_utf8_chr_len(code[rip])
        if c == "n":
            num,l = parse_num(code[rip:])
            rip += l
            args.append(num)
        if c == "o":
            num,l = parse_num(code[rip:])
            rip += l
            args.append(f"-> {hex(rip + num)}")
    print(f"{hex(orip)} :",name, args)
```
If we now run our disassembler we get:

```bash
$ python disassembler.py
0x0 : push [144]
0x2e : push [23]
0x5c : print []
0x62 : push [167]
0x90 : push [20]
0xbe : print []
0xc4 : push [0]
0xf2 : push [27]
0x120 : read []
0x124 : push [0]
....
0x4719 : push [235]
0x4747 : push [21]
0x4775 : print []
0x477b : push [0]
0x47a9 : push [27]
0x47d7 : print []
0x47dd : push [256]
0x480b : push [2]
0x4839 : print []
0x483f : exit []
```
This code can be split in three sections:
* Setup
* First check
* Second check

### Setup
```
0x0 : push [144]
0x2e : push [23]
0x5c : print []         ; print the first message
0x62 : push [167]
0x90 : push [20]
0xbe : print []         ; print the second message
0xc4 : push [0]       
0xf2 : push [27]        ; read the password, stored at 0 (data buffer)
0x120 : read []
```

### First check
At the beginning of this check we have:
```
0x124 : push [0]
```

Than we have the same code over and over again (one time for each char in the password), only with changed constants
```
push [x1]  
load [n]   
xor []       ; xor the nth char of the password with x1
push [x2]
xor []       ; xor the last result with x2
or []        ; or the value with the last pushed value on the stack
```

At the end of the first check we have
```
0xeb5 : push [0]
0xee3 : jeq ['-> 0xf77'] ; jump to 0xf77 if the last pushed value is 0
0xf11 : push [187]
0xf3f : push [25]
0xf6d : print []         ; print the 'tRy hArder' message
0xf73 : exit []
```
As we want to avoid the `tRy hArder` message, we try to pass the check made at `0xee3`. This means at the end of all those code segments we want to have a 0 pushed on the stack. `0` is getting pushed at the beginning of this part, so we don't want this number to change, but this could happen, because of the `or` at the end of each segment. The only way we don't modify this value is by `or` ing with 0. So our xors have to return 0. We essentially `or` with `p_n ^ x1 ^ x2`. This is supposed to be `0` to pass this check which internally means : `p_n = x1 ^ x2`. This gives us a way to calculate the nth char of the password. There are `23` segments so, we can calculate the first 23 chars of the flag : `n3w_ag3_v1rtu4liz4t1on_`

### Second check
At the beginning of this part we have:
```
0xf77 : load32 [140]
```

After that we have got 32 Segments looking like this:
```
0xfa5 : dup []
0xfab : isodd []
0xfae : load32 [23] ; at the address 23 is the rest of our password
0xfdc : shr [n]     ; n is looping from 0 to 31
0x100c : isodd []
0x100f : jeq ['-> 0x1129']
0x103d : shr [1]
0x106d : load32 [128]
0x109b : xor []
0x109f : push [0]
0x10cd : push [0]
0x10fb : jeq ['-> 0x1159']
0x1129 : shr [1]
------ Next Segment
0x1159 : dup []
...
```

The end of this Part we have got :
```
0x4625 : load32 [136]  ; Push 32bit at the address 136
0x4653 : xor []        ; already pushed value xored with value from address [136]
0x4657 : push [0]
0x4685 : jeq ['-> 0x4719'] ; jump to 0x4719 if the result is 0
0x46b3 : push [212]
0x46e1 : push [23]
0x470f : print []          ; print another error message `Gotta go cyclic`
0x4715 : exit []
0x4719 : push [235]        ; After this follows the success message
0x4747 : push [21]
0x4775 : print []
0x477b : push [0]
0x47a9 : push [27]
0x47d7 : print []
0x47dd : push [256]
0x480b : push [2]
0x4839 : print []
0x483f : exit []
```

So basically this part checks the last four chars of our password in one go.
Before and after each segment we have got only one value pushed, I will call this value the accumulator. At the beginning it is loaded with the 32 bit from address [140] after that it gets modified by each segment and it is the value that gets xored with [136] at the end. Each segment is basically a if/else statement.
The first thing that is done in each segment is, that the accumulator is dupped.
Stack:
```
acc
acc
```
After that the clone of the accumulator gets anded with 1 (`isodd` optcode).
Stack:
```
acc
acc & 1
```
Now the 32 bits of our password are loaded.
```
acc
acc & 1
pw
```
It is shifted by n.
```
acc
acc & 1
pw >> n
```
.. and `and`ed with 1
```
acc
acc & 1
(pw >> n) & 1
```
Now we either take the jump or we skip it.
Take the jump:
```
acc >> 1
```
Here is the end of the segment
If we don't take the jump:
```
acc >> 1
v[128]
```
xor:
```
(acc >> 1) ^ v[128]
```
jump to next segment.

--------------
So each of these segments either shifts the accumulator or shifts it and does a xor with a hard-coded value, which of those is done depends on our input.
As I did not want to reverse this algorithm by hand I decided to brute-force the rest of the password.

```c
int is_correct(int in) {
		unsigned int acc = 0xffffffff; // value at [140] is 0xffffffff
		for (int i = 0; i < 32; i++) {
			if ((acc & 1) != ((in >> i) & 1)) {
				acc >>= 1;
				acc ^= 0xedb88320;  // the value at [128] is 0xedb88320
			} else {
				acc >>= 1;
			}
		}
		return (acc ^ 0xf40e845e) == 0; // value at [136] is 0xf40e845e
}
```

In full the code for the bruteforce looks like this :

```c
#include <stdlib.h>
#include <stdio.h>
char alpha[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~ ";

int is_correct(int in) {
		unsigned int acc = 0xffffffff; // value at [140] is 0xffffffff
		for (int i = 0; i < 32; i++) {
			if ((acc & 1) != ((in >> i) & 1)) {
				acc >>= 1;
				acc ^= 0xedb88320;  // the value at [128] is 0xedb88320
			} else {
				acc >>= 1;
			}
		}
		return (acc ^ 0xf40e845e) == 0; // value at [136] is 0xf40e845e
}


int main(int argc, char* argv[]) {
		char input[5];
		input[4] = '\0';
		for (unsigned int num = 0; num < 81450625; num ++) {
			int f = num;
			for (int i = 0; i <4; i++) {
					input[i] = alpha[f % 95];
					f /= 95;
			}
			if (num % 1000000 == 0) {
				printf("At : %d/81450625 %s\n", num, input);
			}
			int* ptr = (int*)input;
			if (is_correct(*ptr)) {
				printf("GOT %s\n", input);
			}
		}
}
```

And after a few seconds I got :
```
$ gcc -o brute brute_force.c
$ ./brute
At : 0/81450625 0000
At : 1000000/81450625 u/f1
....
At : 69000000/81450625 .EJ=
At : 70000000/81450625 amZ>
GOT l0l?
```
So the entire password is `n3w_ag3_v1rtu4liz4t1on_l0l?`
```bash
$ ./eVMoji code.bin
Welcome to eVMoji 😎
🤝 me the 🏳️
n3w_ag3_v1rtu4liz4t1on_l0l?
Thats the flag: CSCG{n3w_ag3_v1rtu4liz4t1on_l0l?}
```
