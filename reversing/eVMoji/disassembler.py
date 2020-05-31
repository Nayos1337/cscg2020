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
