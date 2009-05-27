"""
Relayer objects, like Uploader and Downloader, serve to take incoming information, store it,
and pass it to the next neighbor in the chain.

@author: Rich Jones, John Schanck
@license: see License.txt
"""

from Anomos.Connecter import AnomosFwdLink
from Anomos.CurrentRateMeasure import Measure
from Anomos import INFO, CRITICAL, WARNING
from threading import Thread

class Relayer(object):
    """ As a tracking code is being sent, each peer it reaches (other than the
        uploader and downloader) creates a Relayer object to maintain the
        association between the incoming socket and the outgoing socket (so
        that the TC only needs to be sent once).
    """
    def __init__(self, rawserver, neighbors, incoming, outnid, config, max_rate_period=20.0):
                    #storage, uprate, downrate, choker, key):
        self.rawserver = rawserver
        self.neighbors = neighbors
        self.errorfunc = rawserver.errorfunc
        self.incoming = incoming
        self.outgoing = None
        self.connections = {self.incoming:None}
        self.config = config
        #self.storage = storage
        #self.choker = choker
        self.relayparts = []
        self.choked = True
        self.unchoke_time = None
        self.uprate = Measure(max_rate_period)
        self.downrate = Measure(max_rate_period)
        self.sent = 0
        self.interested = False
        self.buffer = []
        self.complete = False

        self.tmpnid = outnid
        self.start_connection(outnid)
        self.rawserver.add_task(self.check_if_established, 1)

    def check_if_established(self):
        if self.outgoing:
            for msg in self.buffer:
                self.relay_message(self.incoming, msg)
            self.buffer = []
        else:
            self.rawserver.add_task(self.check_if_established, 1)

    def start_connection(self, nid):
        loc = self.neighbors.get_location(nid)
        self.rawserver.start_ssl_connection(loc, handler=self)

    def sock_success(self, sock, loc):
        if self.connections.has_key(sock):
            return
        con = AnomosFwdLink(self, sock, self.tmpnid, established=True)
        sock.handler = con
        self.errorfunc(INFO, "Relay connection started")
        self.outgoing = con
        self.connections = {self.incoming:self.outgoing, self.outgoing:self.incoming}

    def sock_fail(self, loc, err=None):
        if err:
            self.errorfunc(WARNING, err)
        #TODO: Do something with error message

    def relay_message(self, con, msg):
        if self.connections.has_key(con) and self.connections[con] is not None:
            self.uprate.update_rate(len(msg))
            self.sent += len(msg)
            self.connections[con].send_relay_message(msg)
        elif not self.complete: # 'con' is incomming connection, and the
                                # connection isn't complete, which means the relay
                                # connection hasn't been established yet. Buffer
                                # messages until it has been.
            #TODO: buffer size control, message rejection after a certain point.
            self.buffer.append(msg)

    def connection_lost(self, sock):
        self.incoming.close()
        self.outgoing.close()

    def connection_completed(self, con):
        self.errorfunc(INFO, "Relay connection established")
        con.complete = True
        con.is_relay = True

    def get_rate(self):
        return self.uprate.get_rate()

    def get_sent(self):
        return self.sent

    def choke(self):
        if not self.choked:
            self.choked = True
            self.outgoing.send_choke()

    def unchoke(self, time):
        if self.choked:
            self.choked = False
            self.unchoke_time = time
            self.outgoing.send_unchoke()

    def got_choke(self):
        self.choke(self)
        self.incoming.send_choke()

    def got_unchoke(self, time):
        self.unchoke(time)
        self.incoming.send_unchoke()

    #def sent_choke(self):
    #    assert self.choked
    #    del self.buffer[:]

    def has_queries(self):
        return len(self.buffer) > 0

    def set_owner(self, obj):
        self.owner = obj

    def get_owner(self):
        return self.owner
