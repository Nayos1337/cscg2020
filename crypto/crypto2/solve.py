from Crypto.Util.number import inverse

n = 0x57c88f1c9b9ed47d844f87b29f44796e17ce47c2fe24cc1ab7e34432b335212463d2399d074711800572ea6812e2901202bc5f190ccb4966d570904a41697a6364488ae140b1b6357fc6a6b4accd517a7403bbc996dfd072895f6a9a1ea8f2a6dab69da15575177f4cef1adb90825bbd4fec5001aac01a70e8a10e101334713932be47d1a09d70d31157fe26e553774f8d9e502098472bca8707931e2bc9cb92aac94451be6f1e558b93a8685ce984f4840afaf8d2a8ad0d46545462a918151a50dea1a28f4df1e5e699b0052da523059eb21d56b67c91e56ab75f35bc9f649bea76a136b170d3a676f514b9c8955eaf78a90badd5485bba7f12178b1f8fefef

# computes the integer squareroot of a number
# stolen from the primefac python module
def isqrt(n):
    if n == 0:
        return 0
    x, y = n, (n + 1) // 2
    while y < x:
        x, y = y, (y + n//y) // 2
    return x

def decrypt(n,p,q,c,e=65537):
    assert(p*q==n)
    phi = (p - 1)*(q - 1)
    d = inverse(e, phi)
    return bytes.fromhex(hex(pow(c, d, n))[2:])

s = isqrt(n)

p = s
x = 0
while n % p != 0:
	p = s - x
	x += 1

q = n // p

with open("message.txt") as f:
	print(decrypt(n,p,q,int(f.read())))

#FLAG : CSCG{Ok,_next_time_I_choose_p_and_q_random...}
