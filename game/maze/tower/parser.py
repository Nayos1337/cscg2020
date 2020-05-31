import hexdump
import struct

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

def client_pos(raw, state):
    stime,x,y,z,ax,ay,az,flags,hspeed,vspeed = struct.unpack("=Qiiiiiichh",raw[9:])
    state["last_angle"] = ay
    state["last_time"] = stime
    state["last_pos"] = (x / 10000.0,y / 10000.0,z / 10000.0)




def parse(data, port, origin, state):
    raw = decode(data)
    if origin == "client" and raw[0] == ord("P"):
        client_pos(raw, state)
