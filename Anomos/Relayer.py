"""Relayer.py
@author: Rich Jones, John Schanck
@license: see .txt

Relayer objects, like Uploader and Downloader, serve to take incoming information, store it, 
    and pass it to the next neighbor in the chain.

This file is a sort of a mockup and may be rewritten/never used at all.

"""

class Relayer(object):
    """ As a tracking code is being sent, each peer it reaches (other than the
        uploader and downloader) creates a Relayer object to maintain the 
        association between the incoming socket and the outgoing socket (so 
        that the TC only needs to be sent once).
    """
    def __init__(self, incoming, outgoing, storage, choker, key):
        """
        @param incoming: The connection to read data from
        @param outgoing: The connection to write data to
        @param storage: Where we store data waiting to be sent
        
        @type incoming: Connection
        @type outgoing: Connection
        @param storage: StorageWrapper
        """
        self.inconnection = inconnection
        self.outconnection = outconnection # Assumed to containa nextneighor IP
        self.storage = storage
        self.choker = choker
        self.relayparts = []
        self.choked = True
        self.unchoke_time = None
        self.interested = False
        self.buffer = []
        #Neighbor Key is in their Connection object
        #self.neighborpubkey = neighborpubkey 
        self.key = key

    def addPart(self, o):
        ##TODO: Where is this object coming from?
        p = key.decrypt(o)
        relayparts.put(p)

    def returnPart(self):
        return relayparts.get()

    def sendPart(self):
        self.outgoing.pubkey.encrypt(returnPart())
        outconnection.write(returnPart())    ## ??
