import socket
import os
from threading import Thread
import importlib
import parser
import sys
import struct
import time
import random
import struct
from PIL import Image
image = Image.new("RGB",(500,100),0xffffff)

state = {"rabbit_id":None, "img":image}

class Proxy2Server(Thread):

    def __init__(self, host, port):
        super(Proxy2Server, self).__init__()
        self.port = port
        self.host = host
        self.server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server.connect((host, port))

    def run(self):
        global players
        while True:
            data = self.server.recv(4096)
            if data:
                try:
                    importlib.reload(parser)
                    parser.parse(data, self.port, 'server', state)
                except Exception as e:
                    print('server[{}]'.format(self.port), e)

                self.g2p.forward(data)

    def forward(self,msg):
        self.server.sendall(msg)

class Game2Proxy(Thread):

    def __init__(self, host, port):
        super(Game2Proxy, self).__init__()
        self.port = port
        self.host = host
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))

        print("Listening on {}:{}".format(host,port))

        self.game = sock
        msg, self.addr = self.game.recvfrom(25)
        print("Recved init : {} from : {}".format(msg,self.addr))

    def run(self):
        global players
        while True:
            data = self.game.recv(4096)
            if data:
                try:
                    importlib.reload(parser)
                    parser.parse(data, self.port, 'client', state)
                except Exception as e:
                    print('client[{}]'.format(self.port), e)
                # forward to server
                self.p2s.forward(data)

    def forward(self,msg):
        self.game.sendto(msg,self.addr)


g2p = Game2Proxy("127.0.0.1",1337)
p2s = Proxy2Server("maze.liveoverflow.com",1337)
g2p.p2s = p2s
p2s.g2p = g2p

g2p.start()
p2s.start()

def parse_mc_coord(coord, lastval):
    if coord == "~":
        return lastval
    if coord.startswith("~"):
        return lastval + float(coord[1:])
    return float(coord)

def coord(x):
    return int(x * 10000)

usersecret  = bytes.fromhex("f6f4d1867c73e32a")[::-1]


while True:
    x = input()
    args = x.split()
    try:
        if args[0] == "S":
            data = b"\0\0" + bytes.fromhex(args[1]) # easy way to encode
            p2s.forward(data)
            print("Data was send")
        if args[0] == "C":
            data = b"\0\0" + bytes.fromhex(args[1]) # easy way to encode
            g2p.forward(data)
            print("Data was send")
        if args[0] == "T":
            nx,ny,nz = map(coord, [parse_mc_coord(args[i+1], state["last_pos"][i]) for i in range(3)])

            packetS = b"\0\0P" + usersecret + struct.pack("=QiiiiiiBhh", state["last_time"] + 1,nx,ny,nz,0,state["last_angle"],0,0,0,0)
            packetC = b"\0\0T\x01"          + struct.pack("iii", nx,ny,nz)

            p2s.forward(packetS)
            g2p.forward(packetC)
            print("Teleport done")


    except Exception as e:
        print('injector :', e)
