"""
Relayer objects, like Uploader and Downloader, serve to take incoming information, store it, 
and pass it to the next neighbor in the chain.

@author: Rich Jones, John Schanck
@license: see License.txt
"""

class Relayer(object):
    """ As a tracking code is being sent, each peer it reaches (other than the
        uploader and downloader) creates a Relayer object to maintain the 
        association between the incoming socket and the outgoing socket (so 
        that the TC only needs to be sent once).
    """
    def __init__(self, incoming, outgoing, storage, uprate, downrate, choker, key):
        """
        @param incoming: The connection to read data from
        @param outgoing: The connection to write data to
        @param storage: Where we store data waiting to be sent
        @param uprate: Upload rate measurer
        @param downrate: Download rate measurer
        @type incoming: Connection
        @type outgoing: Connection
        @type uprate: Measure
        @type downrate: Measure
        @param storage: StorageWrapper
        """
        self.incoming = incoming
        self.outgoing = outgoing
        self.storage = storage
        self.choker = choker
        self.relayparts = []
        self.choked = True
        self.unchoke_time = None
        self.uprate = uprate
        self.downrate = downrate            #statistical
        self.interested = False
        self.buffer = []
        self.key = key

    def addPart(self, o):
        ##TODO: Where is this object coming from?
        p = key.decrypt(o)
        relayparts.put(p)
        downrate.update_rate(len(o))

    def returnPart(self):
        return relayparts.get()

    def sendPart(self):
        eprt = self.outgoing.pubkey.encrypt(returnPart())
        self.outconnection.write(eprt)
        self.uprate.update_rate(len(eprt))

    def sendOutMessage(message):
        encm = self.incoming.pubkey.encrypt(message)
        self.inconnection.write(encm)
        self.uprate.update_rate(len(encm))

    def get_rate(self):
        return self.uprate.get_rate()

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
