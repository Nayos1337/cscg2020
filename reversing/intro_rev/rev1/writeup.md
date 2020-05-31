# Intro Reversing 1
For this Reversing challenge we are given a binary.
If we run it we get this promt:
```bash
$ ./rev1
Give me your password:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Thats not the password!
```
We are requested to input a password, but as we don't know this password, we have to somehow figure out what it is. The easies implementation for such a password check would be to just compare it to the right password stored somewhere in the binary. `strings` is a utility that searches a binary for strings, so we can use this to find a potentialy stored password.
```bash
$ strings rev1
...
Give me your password:
y0u_5h3ll_p455
Thats the right password!
Flag: %s
Thats not the password!
./flag
flag
File "%s" not found. If this happens on remote, report to an admin. Exiting...
...
```
In this output there is a lot of uninteresting strings but, near the `Give me your password:` string is a suspicious `y0u_5h3ll_p455` string. We can test that as the password and we get:
```bash
$ ./rev1
Give me your password:
y0u_5h3ll_p455
Thats the right password!
Flag: TESTFLAG
```
Remotely this looks like this:
```bash
$ nc hax1.allesctf.net 9600
Give me your password:
y0u_5h3ll_p455
Thats the right password!
Flag: CSCG{ez_pz_reversing_squ33zy}
```
