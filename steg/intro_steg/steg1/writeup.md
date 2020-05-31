# Intro Stegano 1

For this stego challange we are given only an image: `chall.png`
If we run `file` on it we find:

```bash
$ file chall.jpg
chall.jpg: JPEG image data, JFIF standard 1.01, resolution (DPI), density 72x72, segment length 16, comment: "alm1ghty_st3g4n0_pls_g1v_fl4g", baseline, precision 8, 1024x1128, components 3
```
The comment states : `alm1ghty_st3g4n0_pls_g1v_fl4g`, but this is not a valid flag.
So this is only the first stage. After I found this string I just ran a lot of tools on the file.
One of them was `steghide`:
```bash
$ steghide info chall.jpg
"chall.jpg":
  format: jpeg
  capacity: 10.4 KB
Try to get information about embedded data ? (y/n) y
Enter passphrase:
  embedded file "flag.txt":
    size: 24.0 Byte
    encrypted: rijndael-128, cbc
    compressed: yes
```
As password I used the found string : `alm1ghty_st3g4n0_pls_g1v_fl4g`

```bash
$ steghide extract -sf chall.jpg
Enter passphrase:
wrote extracted data to "flag.txt".
$ cat flag.txt
CSCG{Sup3r_s3cr3t_d4t4}
```
