# Intro to Crypto 3

> After a new potentially deadly disease first occurring in Wuhan, China, the Chinese Corona Response Team sends messages to the remainder of the world. However, to avoid disturbing the population, they send out this message encrypted.
We have intercepted all messages sent by the Chinese government and provide you with the public keys found on the governments' website.
Please, find out if we are all going to die!

For this challenge we are given 4 Files :
* **german_government.pem** / **russian_government.pem** / **us_government.pem** these contain 3 different rsa public keys
* **intercepted-messages.txt** which contain 3 encrypted messages (one for each public key)

This setup was very suspicious. I had an attack on RSA in the back of my mind which involved 3 different public keys and one message encrypted which each of those. But for this attack to work all of the public keys would have to have a public modulus of exactly 3.

So I checked the files :  

```bash
$ openssl rsa -inform PEM -pubin -in german_government.pem --text
RSA Public-Key: (2047 bit)
Modulus:
    <.....>
Exponent: 3 (0x3)
writing RSA key
-----BEGIN PUBLIC KEY-----
MIIBHzANBgkqhkiG9w0BAQEFAAOCAQwAMIIBBwKCAQBp5eXbaoCjLFnsHsY3EPSI
ZAfuAAehBQsiF41a6Ihl2GG2Y3GpMSDVgbpwG8EiHPK0oOPz/xX3nf5m0Penlemw
g2UPOC+l9+W02P16hUI964Jj9ZVwG56GPjtpjT7RYpuTlFgKtQxRHJqcBZ+bfD8C
vewfvk+psTo3bwQkVJNyehnTLoILpKoxU1zuQsxOwmA//OXXclU3alu9aT8nVhjY
wJAOtPTyY77apSS9D7ZQ1Zx966PeS/pPs8pQMS/FhYYOicAb2QZ18yHMftyDkS6e
OpWQ/wixRYUbHPhHvSuvGkptQJ6Lu47NN0dDxl/OrwUsM6QwZwdwq/JNruovJ29n
AgED
-----END PUBLIC KEY-----
```

```bash
$ openssl rsa -inform PEM -pubin -in russian_government.pem --text
RSA Public-Key: (2048 bit)
Modulus:
      <.....>
Exponent: 3 (0x3)
writing RSA key
-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAkU9rlTNWhbo39Plb+Yk+
18ArsTHW16SjfO1ywx9Sg6ZXdOpn04xwKdHnUaglZLLBib9sdsdeB/hzjpc2NoVv
NGHVkhH+lvgYpBk6CtRTLMHllf8YfcjOFJCtGa6eSy6mOgcO5+ktQ2xkUvoHAH46
lmLu60Mq6QNUoHScP8qPpeJepz1kDDUuFlqFfO+hYor6F+Aktz54JG4SQC5xq2Wr
vtztgwZinTEZStiL8HsIWr5yNQD9AuROcEIHnPuBWMbtiLff0lJm5BmfaO0cWC/Z
Wfh6Vy96uMe1TvMnIF9xDH8nCyKd16NzFVguWSGGWtx7dKxzgWviG0LgvdkRfi+x
MwIBAw==
-----END PUBLIC KEY-----
```


```bash
openssl rsa -inform PEM -pubin -in us_government.pem --text
RSA Public-Key: (2047 bit)
Modulus:
    <......>
Exponent: 3 (0x3)
writing RSA key
-----BEGIN PUBLIC KEY-----
MIIBHzANBgkqhkiG9w0BAQEFAAOCAQwAMIIBBwKCAQBykvErl/K7aBCrbejBKxFA
FSSKOP1Ra/UaWOajRDpLcFgGJT1wnnDeC1Z647HcASI57lGK+5s2IxQAVai9OjAl
TqSZh0O7sO3xEpxA4JjOKBB/NtMXdrLxUxQsr3njJeR4CPb1z93fViR6KsKJpb/C
C6cjuota0m33qWWPgk6FCcMlNi/IzTBPcj8z6/CwZcbWCyubnTPvCznOQbHH469U
f20PZcp/tBIoJxu33K+LcH+UF1HrhafSxYV44RIV0wHNcsDRkX8S4VFZXuP+QIp1
SdnphuWCVJUUEOTt0diPN3bfMpPINVs82/N7JtuDjSBGqhhiiFHfxog+FzbA76uj
AgED
-----END PUBLIC KEY-----
```
And sure enough each public exponent was 3. So I had to update my knowledge about that attack :
[Wikipedia](https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Attacks_against_plain_RSA) states:

> If the same clear text message is sent to e or more recipients in an encrypted way, and the receivers share the same exponent e, but different p, q, and therefore n, then it is easy to decrypt the original clear text message via the Chinese remainder theorem. Johan Håstad noticed that this attack is possible even if the clear texts are not equal, but the attacker knows a linear relation between them. This attack was later improved by Don Coppersmith.

Wikipedia mentions the [Chinese Remainder Theorem](https://en.wikipedia.org/wiki/Chinese_remainder_theorem). It is an alogrithm to solve equations (for x) of the type:

```
x = a_1 mod n_1
x = a_2 mod n_2
x = a_3 mod n_3
...
x = a_i-1 mod n_i-1
x = a_i mod n_i
```

In our case we have:

```
m ^ e = m ^ 3 = c_1 mod n_1
m ^ e = m ^ 3 = c_2 mod n_2
m ^ e = m ^ 3 = c_3 mod n_3
```

(c_x are the encrypted messages and n_x are the related public moduli)

So if we would run the algorithm on it we could determine `m ^ 3`. And if we would take the third root of that we would get the desired message `m`.

```python
from functools import reduce
import gmpy


# These 2 Functions were stolen from the rosettacode project which implements
# a lot of useful algorithms in a lot of different programming languages
# https://rosettacode.org/wiki/Chinese_remainder_theorem#Python
def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a*b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * mul_inv(p, n_i) * p
    return sum % prod



def mul_inv(a, b):
    b0 = b
    x0, x1 = 0, 1
    if b == 1: return 1
    while a > 1:
        q = a // b
        a, b = b, a%b
        x0, x1 = x1 - q * x0, x0
    if x1 < 0: x1 += b0
    return x1

# german
n1 = int("""69:e5:e5:db:6a:80:a3:2c:59:ec:1e:c6:37:10:f4:
    88:64:07:ee:00:07:a1:05:0b:22:17:8d:5a:e8:88:
    65:d8:61:b6:63:71:a9:31:20:d5:81:ba:70:1b:c1:
    22:1c:f2:b4:a0:e3:f3:ff:15:f7:9d:fe:66:d0:f7:
    a7:95:e9:b0:83:65:0f:38:2f:a5:f7:e5:b4:d8:fd:
    7a:85:42:3d:eb:82:63:f5:95:70:1b:9e:86:3e:3b:
    69:8d:3e:d1:62:9b:93:94:58:0a:b5:0c:51:1c:9a:
    9c:05:9f:9b:7c:3f:02:bd:ec:1f:be:4f:a9:b1:3a:
    37:6f:04:24:54:93:72:7a:19:d3:2e:82:0b:a4:aa:
    31:53:5c:ee:42:cc:4e:c2:60:3f:fc:e5:d7:72:55:
    37:6a:5b:bd:69:3f:27:56:18:d8:c0:90:0e:b4:f4:
    f2:63:be:da:a5:24:bd:0f:b6:50:d5:9c:7d:eb:a3:
    de:4b:fa:4f:b3:ca:50:31:2f:c5:85:86:0e:89:c0:
    1b:d9:06:75:f3:21:cc:7e:dc:83:91:2e:9e:3a:95:
    90:ff:08:b1:45:85:1b:1c:f8:47:bd:2b:af:1a:4a:
    6d:40:9e:8b:bb:8e:cd:37:47:43:c6:5f:ce:af:05:
    2c:33:a4:30:67:07:70:ab:f2:4d:ae:ea:2f:27:6f:
    67""".replace("\n","").replace(" ","").replace(":",""),16)
c1 = 3999545484320691620582760666106855727053549021662410570083429799334896462058097237449452993493720397790227435476345796746350169898032571754431738796344192821893497314910675156060408828511224220581582267651003911249219982138536071681121746144489861384682069580518366312319281158322907487188395349879852550922320727712516788080905540183885824808830769333571423141968760237964225240345978930859865816046424226809982967625093916471686949351836460279672029156397296634161792608413714942060302950192875262254161154196090187563688426890555569975685998994856798884592116345112968858442266655851601596662913782292282171174885


# us
n2 = int("""72:92:f1:2b:97:f2:bb:68:10:ab:6d:e8:c1:2b:11:
    40:15:24:8a:38:fd:51:6b:f5:1a:58:e6:a3:44:3a:
    4b:70:58:06:25:3d:70:9e:70:de:0b:56:7a:e3:b1:
    dc:01:22:39:ee:51:8a:fb:9b:36:23:14:00:55:a8:
    bd:3a:30:25:4e:a4:99:87:43:bb:b0:ed:f1:12:9c:
    40:e0:98:ce:28:10:7f:36:d3:17:76:b2:f1:53:14:
    2c:af:79:e3:25:e4:78:08:f6:f5:cf:dd:df:56:24:
    7a:2a:c2:89:a5:bf:c2:0b:a7:23:ba:8b:5a:d2:6d:
    f7:a9:65:8f:82:4e:85:09:c3:25:36:2f:c8:cd:30:
    4f:72:3f:33:eb:f0:b0:65:c6:d6:0b:2b:9b:9d:33:
    ef:0b:39:ce:41:b1:c7:e3:af:54:7f:6d:0f:65:ca:
    7f:b4:12:28:27:1b:b7:dc:af:8b:70:7f:94:17:51:
    eb:85:a7:d2:c5:85:78:e1:12:15:d3:01:cd:72:c0:
    d1:91:7f:12:e1:51:59:5e:e3:fe:40:8a:75:49:d9:
    e9:86:e5:82:54:95:14:10:e4:ed:d1:d8:8f:37:76:
    df:32:93:c8:35:5b:3c:db:f3:7b:26:db:83:8d:20:
    46:aa:18:62:88:51:df:c6:88:3e:17:36:c0:ef:ab:
    a3""".replace("\n","").replace(" ","").replace(":",""),16)
c2 = 7156090217741040585758955899433965707162947606350521948050112381514262664247963697650055668324095568121356193295269338497644168513453950802075729741157428606617001908718212348868412342224351012838448314953813036299391241983248160741119053639242636496528707303681650997650419095909359735261506378554601448197330047261478549324349224272907044375254024488417128064991560328424530705840832289740420282298553780466036967138660308477595702475699772675652723918837801775022118361119700350026576279867546392616677468749480023097012345473460622347587495191385237437474584054083447681853670339780383259673339144195425181149815


#russian
n3 = int("""00:91:4f:6b:95:33:56:85:ba:37:f4:f9:5b:f9:89:
    3e:d7:c0:2b:b1:31:d6:d7:a4:a3:7c:ed:72:c3:1f:
    52:83:a6:57:74:ea:67:d3:8c:70:29:d1:e7:51:a8:
    25:64:b2:c1:89:bf:6c:76:c7:5e:07:f8:73:8e:97:
    36:36:85:6f:34:61:d5:92:11:fe:96:f8:18:a4:19:
    3a:0a:d4:53:2c:c1:e5:95:ff:18:7d:c8:ce:14:90:
    ad:19:ae:9e:4b:2e:a6:3a:07:0e:e7:e9:2d:43:6c:
    64:52:fa:07:00:7e:3a:96:62:ee:eb:43:2a:e9:03:
    54:a0:74:9c:3f:ca:8f:a5:e2:5e:a7:3d:64:0c:35:
    2e:16:5a:85:7c:ef:a1:62:8a:fa:17:e0:24:b7:3e:
    78:24:6e:12:40:2e:71:ab:65:ab:be:dc:ed:83:06:
    62:9d:31:19:4a:d8:8b:f0:7b:08:5a:be:72:35:00:
    fd:02:e4:4e:70:42:07:9c:fb:81:58:c6:ed:88:b7:
    df:d2:52:66:e4:19:9f:68:ed:1c:58:2f:d9:59:f8:
    7a:57:2f:7a:b8:c7:b5:4e:f3:27:20:5f:71:0c:7f:
    27:0b:22:9d:d7:a3:73:15:58:2e:59:21:86:5a:dc:
    7b:74:ac:73:81:6b:e2:1b:42:e0:bd:d9:11:7e:2f:
    b1:33""".replace("\n","").replace(" ","").replace(":",""),16)
c3 = 9343715678106945233699669787842699250821452729365496523062308278114178149719235923445953522128410659220617418971359137459068077630717894445019972202645078435758918557351185577871693207368250243507266991929090173200996910881754217374691865096976051997491208921880703490275111904577396998775470664002942232492755888378994040358902392803421017545356248082413409915177589953816030273082416979477368273328755386893089597798104163894528521114946660635364704437632205696975201216810929650384600357902888251066301913255240181601332549134854827134537709002733583099558377965114809251454424800517166814936432579406541946707525


mto3 = chinese_remainder([n1,n2,n3],[c1,c2,c3])
m = gmpy.root(mto3,3)[0]
assert(m ** 3 == mto3)
print(bytes.fromhex(hex(m)[2:]))


# FLAG : CSCG{ch1nes3_g0vernm3nt_h4s_n0_pr0blem_w1th_c0ron4}
```
