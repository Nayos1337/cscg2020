# Intro to Crypto 1

Crypto 1 was a basic RSA Cryptography challenge of the CSCG.
We are given a RSA-Publickey in the PEM format:
```
-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBRz/RtnuMgltbIBsvH3y0d
O+p+ey/E6CbZ/F4YeZkS3KFQspxlwPnmZFM5bOfeYxoPmmdFE4thJbvNGFqhLrCa
ShvYBhGMl6jeBe0L5rRfwcnpk3GS9YvEpcwnZ4A8CyE0KvXLjzSv+xpuwlIMdl2H
UhxoSNvYMYEuzG2Ls9YXM7Drw1LPZNREXJlVcpIvST1xiZWdsjIeG6xZJfpW3Gn2
hY7+66ClqddroZgYcVOSdCTl97aAmKuMEEQrc9FJAnz8N9AwBWM3w+D0IWz0MiOW
dEG2CO7CpkjozoV4lMZlAwwBJFYpJ5s4f829w1thZ3FbVL1VVhgNmvJQS1J6kPrn
AgMBAAE=
-----END PUBLIC KEY-----
```
and an encrypted message as an integer:
```
4522827319495133992180681297469132393090864882907734433792485591515487678316653190
3857126780723774191152919188448259101874058302520002506307941287681755095001757226
8125225906564512166412410211860913300095930790296413211752657509133637233041227475
9536808500083138400040526445476933659309071594237016007983559466411644234655789758
5086079828847178758643055545942542772105396129409783714603898600988218342899076623
5461201231318868591585270527722072562137068063100561654823703857895618774713522999
5137050892471079696577563496115023198511735672164367020373784482829942657366126399
823845155446354953052034645278225359074399
```
Theoretically is this a secure setup. We don't have access to the private key and since can not decrypt the message. But maybe we can get the private key from the public key.
So I used `openssl` to extract the public modulus :
```bash
$ openssl rsa -inform PEM -pubin -in pubkey.pem --text
RSA Public-Key: (2047 bit)
Modulus:
    51:cf:f4:6d:9e:e3:20:96:d6:c8:06:cb:c7:df:2d:
    1d:3b:ea:7e:7b:2f:c4:e8:26:d9:fc:5e:18:79:99:
    12:dc:a1:50:b2:9c:65:c0:f9:e6:64:53:39:6c:e7:
    de:63:1a:0f:9a:67:45:13:8b:61:25:bb:cd:18:5a:
    a1:2e:b0:9a:4a:1b:d8:06:11:8c:97:a8:de:05:ed:
    0b:e6:b4:5f:c1:c9:e9:93:71:92:f5:8b:c4:a5:cc:
    27:67:80:3c:0b:21:34:2a:f5:cb:8f:34:af:fb:1a:
    6e:c2:52:0c:76:5d:87:52:1c:68:48:db:d8:31:81:
    2e:cc:6d:8b:b3:d6:17:33:b0:eb:c3:52:cf:64:d4:
    44:5c:99:55:72:92:2f:49:3d:71:89:95:9d:b2:32:
    1e:1b:ac:59:25:fa:56:dc:69:f6:85:8e:fe:eb:a0:
    a5:a9:d7:6b:a1:98:18:71:53:92:74:24:e5:f7:b6:
    80:98:ab:8c:10:44:2b:73:d1:49:02:7c:fc:37:d0:
    30:05:63:37:c3:e0:f4:21:6c:f4:32:23:96:74:41:
    b6:08:ee:c2:a6:48:e8:ce:85:78:94:c6:65:03:0c:
    01:24:56:29:27:9b:38:7f:cd:bd:c3:5b:61:67:71:
    5b:54:bd:55:56:18:0d:9a:f2:50:4b:52:7a:90:fa:
    e7
Exponent: 65537 (0x10001)
```
We can generate the needed private key if we can factor this modulus.
[FactorDB](factordb.com) is a database with a lot of factorised numbers and sure enough our modulus was in there:
```
 	1032784903...79<617> = 622751 · 1658423516...29<611>
```
So than I wrote a basic python script which decrypts the message with the usage of the prime factorization.

```python
from Crypto.Util.number import inverse

def decrypt(n,p,q,c,e=65537):
    assert(p*q==n)
    phi = (p - 1)*(q - 1)
    d = inverse(e, phi)
    return bytes.fromhex(hex(pow(c, d, n))[2:])


n = 0x51cff46d....7a90fae7

p = 0x9809f
q = 0x89c105e4....8d47f8b9

with open("message.txt") as f:
    print(decrypt(n,p,q,int(f.read())))

# FLAG : CSCG{factorizing_the_key=pr0f1t}
```
