"""Relayer.py
@author: Rich Jones, John Schanck
@license: see .txt

Relayer objects, like Uploader and Downloader, serve to take incoming information, store it, 
    and pass it to the next neighbor in the chain.

This file is a sort of a mockup and may be rewritten/never used at all.

"""

from Anomos import Asizer

class Relayer(object):

    def __init__(self, inconnection, outconnection, choker, neighborpubkey, key):
        self.asizer = Asizer()
        self.inconnection = inconnection           """Needed? or handled by Downloader?"""
        self.outconnection = outconnection      '''Assumed to containa nextneighor IP'''        
        self.choker = choker
        self.relayparts = Queue()                       """Queue for now, while we aren't piecemixing"""
        self.choked = True
        self.unchoke_time = None
        self.interested = False
        self.buffer = []
        self.neighborpubkey = neighborpubkey
        self.key = key

    def bytesLessThan(object d, allowedbytes=268435456):
        size = self.asizer.asizeof(d)
        if(size < allowedbytes):
            return true
        return false

    def addPart(object o):
        ##TODO: Where is this object coming from?
        p = key.decrypt(o)
        relayparts.put(p)

    def returnPart():
        return relayparts.get()

     def sendPart():
       neighborpubkey.encrypt(returnPart())
       outconnection.write(returnPart())    ## ??
