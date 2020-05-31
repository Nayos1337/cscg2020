# Intro Reversing 2

This challenge is a bit more tricky, than the last one. Now `strings` is not the way to go, so there is no hard coded password in the binary. But the code has to still compare the right password against ours. A useful tool, that we can use in this case is `ltrace` it traces all libc library calls:
```bash
$ ltrace ./rev2
fopen("./flag", "r")                                                                                                                     = 0x55e3e15c82a0
fread(0x55e3e029d040, 256, 1, 0x55e3e15c82a0)                                                                                            = 0
fclose(0x55e3e15c82a0)                                                                                                                   = 0
puts("Give me your password: "Give me your password:
)                                                                                                          = 24
read(0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 31)                                                                                           = 31
strcmp("\312\312\312\312\312\312\312\312\312\312\312\312\312\312\312\312\312\312\312\312\312\312\312\312\312\312\312\312\312\312", "\374\375\352\300\272\354\350\375\373\275\367\276\357\271\373\366\275\300\272\271\367\350\362\375\350\362\374") = -50
puts("Thats not the password!"Thats not the password!
)                                                                                                          = 24
+++ exited (status 0) +++
```
The call that is interesting here is the `strcmp` call. We compare two strings with each other. If we run the binary again (with another password), than we recognize, that the first string is some kind of encoding of the inputted password and the second one is constant. Our goal now is to somehow reverse that encoding, to get from the constant string to the right password.
```
AAAAAAAAAAA...... maps to  \312\312\312\312\312\312\312\312\312\312\312...
ABCDEFGHIJK...... maps to  \312\313\314\315\316\317\320\321\322\323\324...
```
It seems so, that an `A (0x41)` always maps to `\312 (0xCA)`, a `B (0x42)` maps to `\313 (0xCB)`...
There is always a difference of `137 (0x89)`.
So if we want to encode a string we simply have to add `0x89` to every char. But there is a problem with that : What happens if this addition overflows a byte? Do we carry or do we just drop that?  But luckily we can test that : `z (0x7a)` would map to `259 (0x103)`. If we run our binary we get :
```
zzzzzzz : \003\003\003\003\003\003\003
```
So we don't carry, we just drop the carry. That means that the transformation is `(x + 137) % 0xff` and the reverse of that is: `(x - 137 + 0xff) % 0xff = (x + 118) % 0xff`. If we run this transformation on the constant we get :
```python
data = b"\374\375\352\300\272\354\350\375\373\275\367\276\357\271\373\366\275\300\272\271\367\350\362\375\350\362\374"

passwd = b""

for x in data:
  passwd += bytes([(x + 118) % 255])

print(passwd)
# PASSWD : sta71c_tr4n5f0rm4710n_it_is
```
Remote :
```bash
$ nc hax1.allesctf.net 9601
Give me your password:
sta71c_tr4n5f0rm4710n_it_is
Thats the right password!
Flag: CSCG{1s_th4t_wh4t_they_c4ll_on3way_transf0rmati0n?}
```
