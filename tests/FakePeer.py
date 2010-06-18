import Anomos.Crypto
import os
import sys
from Anomos.P2PConnection import PostConnectionChecker
from M2Crypto import SSL

def init():
    root = os.path.split(os.path.abspath(sys.argv[0]))[0]
    Anomos.Crypto.init(root)

class FakePeer(object):
    def __init__(self):
        self.cert = Anomos.Crypto.Certificate(ephemeral=True)
        self.ctx = self.cert.get_ctx(allow_unknown_ca=True)
        self.ctx.set_cipher_list('HIGH:!ADH:!MD5:@STRENGTH')
        self.sock = None
    def connect(self, addr):
        self.sock = SSL.Connection(self.ctx)
        checker = PostConnectionChecker()
        self.sock.set_post_connection_check_callback(checker)
        self.sock.setblocking(1)
        self.sock.connect(addr)
    def listen(self, port):
        self.sock = SSL.Connection(self.ctx)
        checker = PostConnectionChecker()
        self.sock.set_post_connection_check_callback(checker)
        self.sock.setblocking(1)
        self.sock.bind(('', port))
        self.sock.listen(5)
    def write(self, msg):
        self.sock.write(msg)
    def read(self):
        return self.sock.recv(4096)


if __name__ == '__main__':
    init()
    fp = FakePeer()
    #fp.connect(('127.0.0.1', 53318))
    proto = 'Anomos10'
    #fp.write(chr(len(proto)) + proto + '\0'*8)
    fp.listen(53318)
    socket,addr = fp.sock.accept()
    print socket.recv(1024)
    socket.write(chr(len(proto)) + proto + '\xff' + '\x00'*7)
    import time
    time.sleep(2)
    socket.close()
    socket,addr = fp.sock.accept()
    print socket.recv(1024)
    socket.write(chr(len(proto)+1) + proto + '\0'*8)
    time.sleep(20)

    #fp.write('')
    #fp.sock.set_shutdown(SSL.m2.SSL_SENT_SHUTDOWN|SSL.m2.SSL_RECEIVED_SHUTDOWN)
    #fp.sock.close()
