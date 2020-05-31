import hexdump

def decode(b):
    r1 = b[0]
    r2 = b[1]
    res = bytes([])
    b = b[2:]
    for i in range(len(b)):
        r1 %= 255
        res += bytes([b[i] ^ r1])
        r1 = (r1 + r2) % 255
        r1 += r1 // 0xff
    return res

def parse(data, port, origin):
    # We only care for packets from the client for now
    if origin == "server":
        return
    arrow = "c --> s" if origin == "client" else "c <-- s"

    raw = decode(data)
    if raw[0] == ord("<") or raw[0] == ord("P"):
        return
    hexdump.hexdump(raw)
