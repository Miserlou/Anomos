'''
@author: John Schanck
@license: see License.txt
'''

from socket import error as socketerror
from Anomos.Connecter import Connection

class NeighborManager:
    '''NeighborManager keeps track of the neighbors a peer is connected to
    and which tracker those neighbors are on.
    '''
    def __init__(self, rawserver, config):
        self.rawserver = rawserver
        self.config = config
        self.neighbors = {}
        self.connections = {}
    
    def get_location(self, nid):
        return self.neighbors.get(nid, [None, None])[0]
    
    def lookup_ip(self, ip):
        for nid, loc in self.neighbors.iteritems():
            if loc[0] == ip:
                return nid
    
    def get_key(self, nid):
        return self.neighbors.get(nid, [None, None])[1]
    
    def add_neighbor(self, id, location, key):
        #TODO: Check for conflicts
        print "ADDING NEIGHBOR:", id, location
        self.neighbors[id] = (location, key)
        print "neighbors: ", self.neighbors
    
    def has_id(self, nid):
        return self.neighbors.has_key(nid)
    
    def count(self, tracker=None):
        #TODO: make this actually tracker specific.
        return len(self.neighbors)
    
    def start_connection(self, loc, id):
        """
        @param loc: (IP, Port)
        @param id: The neighbor ID to assign to this connection
        @type loc: tuple
        @type id: int
        """
        # Connection is established if they're one of this peer's neighbors
        conflict = self.neighbors.has_key(id)
        if conflict:
            #TODO: Resolve conflict
            pass
        try:
            c = self.rawserver.start_connection(loc)
        except socketerror:
            pass
        else:
            # Make the local connection for receiving.
            con = Connection(self, c, id, True)
            self.connections[c] = con
            c.handler = con 

    #def send_keepalives(self):
    #   
