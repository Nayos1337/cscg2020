import socket
import os
from threading import Thread
import importlib
import parser
import sys
import struct
import time


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
                    parser.parse(data, self.port, 'server')
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
                    parser.parse(data, self.port, 'client')
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
