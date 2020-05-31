import hexdump
import struct
from PIL import Image
from PIL import *


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

def parse_player_name(raw, state):
    uid = struct.unpack("I", raw[:4])[0]
    name = raw[7:]
    if name == B"The White Rabbit":
      state["rabbit_id"] = uid

def parse_player_info(raw, state):
    while len(raw) > 0:
      uid = struct.unpack("I", raw[:4])[0]
      if uid != state["rabbit_id"]:
          raw = raw[42:]
          continue
      x,y,z = map(lambda x: x / 10000.0,struct.unpack("iii", raw[12:24]))
      return (x,y,z)

def parse(data, port, origin, state):
    if origin == "client":
      return
    raw = decode(data)
    id = raw[0]
    raw = raw[1:]
    if id == ord("I"):
      parse_player_name(raw, state)
    if id == ord("P"):
      x,y,z = parse_player_info(raw, state)
      print(f"c <-- s : Player update : {x} / {y} / {z}")
      ix = int(x)
      iy = int(z)
      if ix < 0 or ix > 500 or iy < 0 or iy > 100:
          print("[!] Rabbit out of image bound!")
          return
      state["img"].putpixel((ix,iy), 0)
      state["img"].save("image.png")
      print("Saved")
