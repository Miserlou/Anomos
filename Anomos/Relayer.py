"""
Relayer objects, like Uploader and Downloader, serve to take incoming information, store it, 
and pass it to the next neighbor in the chain.

@author: Rich Jones, John Schanck
@license: see License.txt
"""

from socket import error as socketerror
from Anomos.Connecter import Connection
from Anomos.CurrentRateMeasure import Measure

class Relayer(object):
    """ As a tracking code is being sent, each peer it reaches (other than the
        uploader and downloader) creates a Relayer object to maintain the 
        association between the incoming socket and the outgoing socket (so 
        that the TC only needs to be sent once).
    """
    def __init__(self, rawserver, neighbors, incoming, outnid, config, keyring, max_rate_period=20.0):
                    #storage, uprate, downrate, choker, key):
        """
        @param incoming: The connection to read data from
        @param storage: Where we store data waiting to be sent
        @param uprate: Upload rate measurer
        @param downrate: Download rate measurer
        @type incoming: Connection
        @type outgoing: Connection
        @type uprate: Measure
        @type downrate: Measure
        @param storage: StorageWrapper
        """
        self.rawserver = rawserver
        self.neighbors = neighbors
        self.incoming = incoming
        self.outgoing = self.start_connection(outnid)
        self.connections = {self.incoming:self.outgoing, self.outgoing:self.incoming}
        self.config = config
        self.keyring = keyring
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

    def start_connection(self, nid):
        loc = self.neighbors.get_location(nid)
        try:
            c = self.rawserver.start_ssl_connection(loc)
        except socketerror:
            self.incoming.close("Socket error on Relayer")
        else:
            # Make the local connection for receiving.
            con = Connection(self, c, nid, True, established=True)
            print "Condeets: ", con.ip, con.port
            c.handler = con
            return con
    
    def relay_message(self, con, msg):
        if self.connections.has_key(con) and self.connections[con] is not None:
            self.uprate.update_rate(len(msg))
            self.sent += len(msg)
            self.connections[con].send_relay_message(msg)

    def connection_completed(self, con):
        print "Relay con complete"
        con.complete = True
        con.is_relay = True
    
    def addPart(self, o):
        ##TODO: Where is this object coming from?
        p = key.decrypt(o)
        relayparts.put(p)
        downrate.update_rate(len(o))

    def returnPart(self):
        return relayparts.get()

    def get_rate(self):
        return self.uprate.get_rate()

    def get_sent(self):
        return self.sent

    def choke(self):
        if not self.choked:
            self.choked = True
            self.incoming.send_choke()

    def unchoke(self, time):
        if self.choked:
            self.choked = False
            self.unchoke_time = time
            self.outgoing.send_unchoke()

    def got_choke(self):
        self.choke(self)

    def got_unchoke(self, time):
        self.unchoke(time)
   
    def sent_choke(self): 
        assert self.choked
        del self.buffer[:]

    def has_queries(self):
        return len(self.buffer) > 0
