from Anomos import Asizer

class Relayer(object):

    def __init__(self, connection, choker, neighborpubkey):
        self.asizer = Asizer()
        self.connection = connection    '''Assumed to containa nextneighor IP'''        
        self.choker = choker
        self.relayparts = Queue()           """Queue for now, while we aren't piecemixing"""
        self.choked = True
        self.unchoke_time = None
        self.interested = False
        self.buffer = []
        self.neighborpubkey = neighborpubkey

    def bytesLessThan(object d, allowedbytes=268435456):
        size = self.asizer.asizeof(d)
        if(size < allowedbytes):
            return true
        return false

    def addPart(object o):
        relayparts.put(o)

    def getPart():
        return relayparts.get()


