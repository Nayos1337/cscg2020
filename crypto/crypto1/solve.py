from Crypto.Util.number import inverse

def decrypt(n,p,q,c,e=65537):
    assert(p*q==n)
    phi = (p - 1)*(q - 1)
    d = inverse(e, phi)
    return bytes.fromhex(hex(pow(c, d, n))[2:])


n = 0x51cff46d9ee32096d6c806cbc7df2d1d3bea7e7b2fc4e826d9fc5e18799912dca150b29c65c0f9e66453396ce7de631a0f9a6745138b6125bbcd185aa12eb09a4a1bd806118c97a8de05ed0be6b45fc1c9e9937192f58bc4a5cc2767803c0b21342af5cb8f34affb1a6ec2520c765d87521c6848dbd831812ecc6d8bb3d61733b0ebc352cf64d4445c995572922f493d7189959db2321e1bac5925fa56dc69f6858efeeba0a5a9d76ba198187153927424e5f7b68098ab8c10442b73d149027cfc37d030056337c3e0f4216cf43223967441b608eec2a648e8ce857894c665030c01245629279b387fcdbdc35b6167715b54bd5556180d9af2504b527a90fae7

p = 0x9809f
q = 0x89c105e4224372b0201df1e8c332b167885a56b198001db8c10e1a4aa8f7d0686220a7868f1a9a9e573f8409a141297d7ecfa6e0e70e2a2a0ecf6709606e54bfc9f5cbdd6b2f91af68e3049acbb2ae54751150fbc70ca4928ab5b78994c4c49e03d8bbe8068bad5cbc08c6482bd989b87bcf54151b692a4a47a5829fe801b8a60a106aa121496e47d1ff5bf41b9d69cc0a684dcc160a2026d2424aff3f49ed8681efb55a25d3e84cc8acb914397027da44d264b56b7593a7d26c8759ca8132b0fa0f5642b62f9d1f85f75b2d397a79ee0e72919eff6972be587e401e42b1fd03da631e81f5de868f6973831a07ad055425b00b791458f8415d18d47f8b9

with open("message.txt") as f:
    print(decrypt(n,p,q,int(f.read())))