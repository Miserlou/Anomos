'''
@author: John Schanck
@license: see License.txt
'''

#XXX: In addition to their NID, we need to differentiate between neighbors 
#     based on the tracker from which we received them.

from socket import error as socketerror
from Anomos.Connecter import Connection

class NeighborManager:
    '''NeighborManager keeps track of the neighbors a peer is connected to
    and which tracker those neighbors are on.
    '''
    def __init__(self, rawserver, config, rsakey, keyring):
        self.rawserver = rawserver
        self.config = config
        self.rsakey = rsakey
        self.keyring = keyring
        self.neighbors = {}
        self.connections = {}
        self.incomplete = {}
        
        #XXX: PORT HACK
        self.port = None
        #self.complete_connections = set()
        self.waiting_tcs = {}
    
    def get_location(self, nid):
        return self.neighbors.get(nid, None)
    
    def lookup_loc(self, loc):
        print "Looking up Loc", loc, self.neighbors
        peers = []
        for nid, data in self.neighbors.iteritems():
            if data[0] == loc:
                peers.append(nid)
        return peers
    
    def add_neighbor(self, id, location, key):
        print "ADDING NEIGHBOR:", hex(ord(id)), location
        self.neighbors[id] = location
        self.keyring.addKey(id, key)
        print "neighbors: ", self.neighbors
    
    def has_neighbor(self, nid):
        #TODO: Make this tracker specific.
        return self.neighbors.has_key(nid)
    
    def is_complete(self, nid):
        #TODO: Make this tracker specific.
        return not self.incomplete.has_key(nid)
    
    def count(self, tracker=None):
        #TODO: Make this tracker specific.
        return len(self.neighbors)
    
    def connection_completed(self, con):
        #TODO: Make this tracker specific.
        if not self.incomplete.has_key(con.id):
            # Completing a complete or non-existant connection...
            return
        con.complete = True
        del self.incomplete[con.id]
        for task in self.waiting_tcs.get(con.id, []):
            self.rawserver.add_task(task, 0) #TODO: add a min-wait time
    
    def schedule_tc(self, sendfunc, id, tc, aeskey):
        '''Sometimes a tracking code is received before a neighbor is fully
        initialized. In those cases we schedule the TC to be sent once we get
        a "connection_completed" from the neighbor.'''
        def sendtc():
            sendfunc(id, tc, aeskey)
        self.waiting_tcs.setdefault(id,[])
        self.waiting_tcs[id].append(sendtc)
        
    def start_connection(self, loc, id):
        """
        @param loc: (IP, Port)
        @param id: The neighbor ID to assign to this connection
        @type loc: tuple
        @type id: int
        """
        # Connection is established if they're one of this peer's neighbors
        if self.has_neighbor(id) or self.incomplete.has_key(id):
            #TODO: Resolve conflict
            return
        try:
            ##SSL THIS
            c = self.rawserver.start_connection(loc)
        except socketerror:
            pass
        else:
            #
            self.incomplete[id] = loc
            # Make the local connection for receiving.
            con = Connection(self, c, id, True, established=False)
            self.connections[c] = con
            c.handler = con 

    #def send_keepalives(self):
    #   
