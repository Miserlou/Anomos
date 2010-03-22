import Anomos.Crypto
import os
import sys
from Anomos.P2PConnection import PostConnectionChecker
from M2Crypto import SSL


class FakePeer(object):
    def __init__(self):
        root = os.path.split(os.path.abspath(sys.argv[0]))[0]
        Anomos.Crypto.init(root)
        self.cert = Anomos.Crypto.Certificate("fake-peer")
        self.ctx = self.cert.get_ctx(allow_unknown_ca=True)
        self.sock = None
    def connect(self, addr):
        self.sock = SSL.Connection(self.ctx)
        checker = PostConnectionChecker()
        self.sock.set_post_connection_check_callback(checker)
        self.sock.setblocking(1)
        self.sock.connect(addr)
    def write(self, msg):
        self.sock.write(msg)
    def read(self):
        return self.sock.recv(4096)


if __name__ == '__main__':
    fp = FakePeer()
    fp.connect(('127.0.0.1', 53318))
    proto = 'Anomos'
    fp.write(chr(len(proto)) + proto + '\0'*8)
    fp.write('')
    fp.sock.set_shutdown(SSL.m2.SSL_SENT_SHUTDOWN|SSL.m2.SSL_RECEIVED_SHUTDOWN)
    fp.sock.close()
