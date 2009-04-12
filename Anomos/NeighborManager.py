'''
@author: John Schanck, Rich Jones
@license: see License.txt
'''

from Anomos.Connecter import Connection
from Anomos import BTFailure, INFO, WARNING, ERROR, CRITICAL

class NeighborManager:
    '''NeighborManager keeps track of the neighbors a peer is connected to
    and which tracker those neighbors are on.
    '''
    def __init__(self, rawserver, config, certificate, errorfunc):
        self.rawserver = rawserver
        self.config = config
        self.cert = certificate
        self.errorfunc = errorfunc
        self.neighbors = {}
        self.connections = {}
        self.incomplete = {}
        
        #XXX: PORT HACK
        self.port = None
        self.waiting_tcs = {}

        self.failedPeers = []
    
    def failed_connections(self):
        return self.failedPeers

    def get_location(self, nid):
        return self.neighbors.get(nid, None)
    
    def lookup_loc(self, loc):
        self.errorfunc(INFO, "Looking up location: %s\nNeighbors: %s" 
                                % (loc, self.neighbors))
        peers = []
        for nid, data in self.neighbors.iteritems():
            if data[0] == loc:
                peers.append(nid)
        return peers
    
    def add_neighbor(self, id, location):
        self.errorfunc(INFO, "Adding Neighbor: (\\x%02x, %s)" 
                                % (ord(id), location))
        if self.has_loc(location):
            pass
        else:
            self.neighbors[id] = location
    
    def has_neighbor(self, nid):
        #TODO: Make this tracker specific.
        return self.neighbors.has_key(nid)

    def has_loc(self, loc):
        return loc in self.neighbors.values()
    
    def is_complete(self, nid):
        #TODO: Make this tracker specific.
        return self.neighbors.has_key(nid)
    
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
        if self.has_neighbor(id) or \
                self.incomplete.has_key(id) or \
                self.has_loc(loc):
            #TODO: Resolve conflict
            return

        self.incomplete[id] = loc
        self.rawserver.start_ssl_connection(loc, handler=self)

    def sock_success(self, sock, loc):
        """
        @param sock: SingleSocket object for the newly created socket
        """
        if self.connections.has_key(sock):
            # sock_success already called on this socket
            return
        for id,v in self.incomplete.iteritems():
            if v == loc: break
        else: return #loc wasn't found
        # Make the local Connection for receiving.
        con = Connection(self, sock, id, True, established=False)
        self.connections[sock] = con
        sock.handler = con

    def sock_fail(self, loc, err=None):
        #Remove nid,loc pair from incomplete
        for k,v in self.incomplete.items():
            if v == loc:
                self.failedPeers.append(k)
                del self.incomplete[k]
                break
        #TODO: Do something with the error msg.


    #def send_keepalives(self):
    #   
