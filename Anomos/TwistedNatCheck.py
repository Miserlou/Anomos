import twisted.internet.protocol as protocol
import twisted.protocols.basic as basic
import M2Crypto.SSL.TwistedProtocolWrapper as wrapper
import M2Crypto.SSL as SSL
 
from Anomos.Protocol import NAT_CHECK_ID, NAME as PROTOCOL_NAME
from Anomos.P2PConnection import PostConnectionChecker

class NatChecker(object):
    reactor = None
    def __init__(self, ctx_factory, callback):
        self.ctx = ctx_factory
        self.callback = callback

    def check(self, ip, port, peerid):
        factory = NatCheckFactory()
        factory.peerid = peerid
        factory.callback = self.callback
        wrapper.connectSSL(ip, port, factory, self.ctx,
                            postConnectionCheck=PostConnectionChecker,
                            reactor=self.reactor)

class NatCheckCTXFactory(object):
    def __init__(self, cert):
        self.ctx = cert.get_ctx(allow_unknown_ca=True)

    def getContext(self):
        return self.ctx

class TwistedNatCheck(protocol.Protocol, basic.StatefulStringProtocol):
    state = "init"
    nid = NAT_CHECK_ID
    protocol_extensions = '\0'*7
    expecting = 1
    msgbuf = ""

    def connectionMade(self):
        self.writeHeader()

    def dataReceived(self, recd):
        self.msgbuf += recd
        while len(self.msgbuf) >= self.expecting:
            msg = self.msgbuf[:self.expecting]
            self.msgbuf = self.msgbuf[self.expecting:]
            self.stringReceived(msg)

    def writeHeader(self):
        hdr = chr(len(PROTOCOL_NAME)) + \
                        PROTOCOL_NAME + \
                        self.nid + self.protocol_extensions
        self.transport.write(hdr)

    def lengthLimitExceeded(self, len):
        self.transport.loseConnection()

    def proto_init(self, msg):
        if ord(msg) != len(PROTOCOL_NAME):
            raise HandshakeError("Protocol name mismatch")
        self.expecting = len(PROTOCOL_NAME)
        return "name"

    def proto_name(self, msg):
        if msg != PROTOCOL_NAME:
            raise HandshakeError("Protocol name mismatch")
        self.expecting = 1
        return "nid"

    def proto_nid(self, msg):
        if msg != self.nid:
            raise HandshakeError("Neighbor ID mismatch")
        self.expecting = 7
        return "flags"

    def proto_flags(self, msg):
        if len(msg) != 7:
            raise HandshakeError("Invalid header")
        if len(self.msgbuf) > 0:
            self.lengthLimitExceeded(len(self.msgbuf))
        self.factory.do_callback(True)
        self.transport.loseConnection()
        return "done"

protocol.ClientFactory.noisy = False

class NatCheckFactory(protocol.ClientFactory):
    protocol = TwistedNatCheck
    callback = lambda x,y: None
    peerid = None
    noisy = False

    def do_callback(self, result):
        self.callback(self.peerid, result)

    def clientConnectionFailed(self, connector, reason):
        self.do_callback(False)

    def clientConnectionLost(self, connector, reason):
        pass

