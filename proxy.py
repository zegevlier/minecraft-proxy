import socket
from threading import Thread
import parser
from importlib import reload

from queue import Queue
import threading

server_queue = Queue()
client_queue = Queue()


class Proxy2Server(Thread):

    def __init__(self, host, port):
        super(Proxy2Server, self).__init__()
        self.game = None # game client socket not known yet
        self.port = port
        self.host = host
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.connect((host, port))

    def run(self):
        while True:
            data = self.server.recv(2097151)
            if data:
                server_queue.put(data)
                self.game.sendall(data)

class Game2Proxy(Thread):

    def __init__(self, host, port):
        super(Game2Proxy, self).__init__()
        self.server = None # real server socket not known yet
        self.port = port
        self.host = host
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(1)
        self.game, addr = sock.accept()

    def run(self):
        while True:
            data = self.game.recv(2097151)
            if data:
                client_queue.put(data)
                self.server.sendall(data)

class Proxy(Thread):

    def __init__(self, from_host, to_host, port):
        super(Proxy, self).__init__()
        self.from_host = from_host
        self.to_host = to_host
        self.port = port

    def run(self):
        while True:
            print("[proxy] setting up")
            self.g2p = Game2Proxy(self.from_host, self.port) # waiting for a client
            self.p2s = Proxy2Server(self.to_host, self.port)
            print("[proxy] connection established")
            self.g2p.server = self.p2s.server
            self.p2s.game = self.g2p.game

            self.g2p.start()
            self.p2s.start()


# master_server = Proxy('127.0.0.1', '34.90.214.148', 25565)
master_server = Proxy('127.0.0.1', 'play.schoolrp.net', 25565)
master_server.start()

threading.Thread(target=parser.c_parse, args=(client_queue, )).start()
threading.Thread(target=parser.s_parse, args=(server_queue, )).start()
