# Intro Reversing 3
For this challenge we actually need to open a disassembler, because if we run `ltrace` again we get:

```bash
$ ltrace ./rev3
fopen("./flag", "r")                                                                                                                     = 0x55ccb876d2a0
fread(0x55ccb7615040, 256, 1, 0x55ccb876d2a0)                                                                                            = 0
fclose(0x55ccb876d2a0)                                                                                                                   = 0
puts("Give me your password: "Give me your password:
)                                                                                                          = 24
read(AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 31)                                                                                           = 31
strcmp("IHKJMLONQPSRUTWVYX[Z]\\_^a`cbed", "lp`7a<qLw\036kHopt(f-f*,o}V\017\025J")                                                        = -35
puts("Thats not the password!"Thats not the password!
)                                                                                                          = 24
+++ exited (status 0) +++
```
The problem with that is, that we always inputted the same char, but got different results and at first glance I thought, that the encoded password was just the alphabet from some letter, but this is not the case. So I opened [Ghidra](https://ghidra-sre.org/). After the basic anlaysis it decompiles main to:
```c
undefined8 main(void)

{
  int iVar1;
  ssize_t sVar2;
  long in_FS_OFFSET;
  int local_40;
  byte local_38 [40];
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  initialize_flag();
  puts("Give me your password: ");
  sVar2 = read(0,local_38,0x1f);
  local_38[(int)sVar2 + -1] = 0;
  local_40 = 0;
  while (local_40 < (int)sVar2 + -1) {
    local_38[local_40] = local_38[local_40] ^ (char)local_40 + 10U;
    local_38[local_40] = local_38[local_40] - 2;
    local_40 = local_40 + 1;
  }
  iVar1 = strcmp((char *)local_38,"lp`7a<qLw\x1ekHopt(f-f*,o}V\x0f\x15J");
  if (iVar1 == 0) {
    puts("Thats the right password!");
    printf("Flag: %s",flagBuffer);
  }
  else {
    puts("Thats not the password!");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
Which is a very readable decompilation.
If we walk trough the code we can rename variables an make sense of it.
The first interesting thing is the `sVar2 = read(0,local_38,0x1f);` line, which is right after the `Give me your password: ` line. So that read reads our input so we can rename `local_38` to `inpasswd` or something like that. `sVar2` is the length of that input so `inpasswd_len`.
After that, we can see a `local_40 = 0;` and after that a `while` loop that uses `local_40` as a break condition, that means, that `local_40` is some kind of counter: `i`
```c
undefined8 main(void)

{
  int iVar1;
  ssize_t inpasswd_len;
  long in_FS_OFFSET;
  int i;
  byte inpasswd [40];
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  initialize_flag();
  puts("Give me your password: ");
  inpasswd_len = read(0,inpasswd,0x1f);
  inpasswd[(int)inpasswd_len + -1] = 0;
  i = 0;
  while (i < (int)inpasswd_len + -1) {
    inpasswd[i] = inpasswd[i] ^ (char)i + 10U;
    inpasswd[i] = inpasswd[i] - 2;
    i = i + 1;
  }
  iVar1 = strcmp((char *)inpasswd,"lp`7a<qLw\x1ekHopt(f-f*,o}V\x0f\x15J");
  if (iVar1 == 0) {
    puts("Thats the right password!");
    printf("Flag: %s",flagBuffer);
  }
  else {
    puts("Thats not the password!");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
The encoding happens in the `while` loop. It loops over every char and first xors it with `i + 10` and subtracts 2 afterwards. So to reverse that encoding we need to first add 2 and than xor by `i + 10`.
```python
def decode(passwd):
  res = []
  for i, c in enumerate(passwd):
    res.append((c + 2) ^ (i + 10))
  return bytes(res)

print(decode(b"lp`7a<qLw\x1ekHopt(f-f*,o}V\x0f\x15J"))
# dyn4m1c_k3y_gen3r4t10n_y34h
```
Remote :
```bash
$ nc hax1.allesctf.net 9602
Give me your password:
dyn4m1c_k3y_gen3r4t10n_y34h
Thats the right password!
Flag: CSCG{pass_1_g3ts_a_x0r_p4ss_2_g3ts_a_x0r_EVERYBODY_GETS_A_X0R}
```
