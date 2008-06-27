"""
@author: John Schanck <john@anomos.info>
@license: See License.txt

The Anomos tracker keeps a running model of the
network at all times, and uses it to control the flow
of file chunks. Each peer is represented by a Vertex
object; the connections between peers are called edges and
are tuples of the form (IP address, weight). Each Vertex
assigns relative IDs to its edges. The IP addresses these 
relative IDs represent are only known by the Anomos tracker 
and the peer which the Vertex object represents.

To determine how a chunk should get from uploader to downloader, the
Anomos tracker computes the shortest path between the two and returns
a colon delimited tracking code consisting of the relative IDs of each
edge in the path. Since the IDs are relative, the tracking code may be
sent to any individual in the network without compromising the identity 
of the original sender or the ultimate receiver of the file chunk.
"""

import random
from sys import maxint
from sha import sha
from crypto import RSAPubKey
from M2Crypto import RSA

INFINITY = maxint-1
TC_DELIMITER = ":"

class SimPeer:
    """
    Container for some information tracker needs to know about each peer, also
    node in Graph model of network topology used for Tracking Code generation.
    """
    def __init__(self, name, pubkey, maxid=100):
        """
        @param name: Peer ID to be assigned to this SimPeer
        @type name: string
        @param pubkey: RSA Public Key to use when encrypting to this peer
        @type pubkey: Anomos.crypto.RSAPubKey
        @param maxid: Maximum value for Neighbor IDs
        """
        self.name = name
        self.pubkey = pubkey
        self.maxid = maxid
        self.neighbors = {}
        self.id_map = {}
    
    def addNeighbor(self, peerid, nid):
        """
        Assign Neighbor ID to peer
        
        @type peerid: string
        @type nid: int
        """
        self.neighbors.setdefault(peerid, {'dist':1,'nid':nid})
        self.id_map[nid] = peerid
    
    def removeEdge(self, peerid):
        """
        Remove connection to neighbor
        
        @type peerid: string
        """
        nid = self.neghbors.get(peerid, {}).get('nid', None)
        if self.edges.has_key(peerid):
            del self.neighbors[peerid]
        if nid:
            del self.id_map['nid']
    
    def getAvailableNIDs(self):
        """
        @return: set object containing NIDs in range 0 -> maxid which are not in use
        @rtype: set of ints
        """
        used = set(self.id_map.keys())
        idrange = set(range(0,self.maxid))
        return idrange - used
    
    def degree(self):
        return len(self.neighbors)
    
    def reWeight(self, peerid, weight):
        """
        Reset the weight between this SimPeer and one referenced by peerid
        @type peerid: string
        @type weight: int in range 0 -> INFINITY
        """
        if self.neighbors.has_key(peerid):
            self.neighbors[peerid]['dist'] = weight
    
    def getWeight(self, nid):
        """
        Returns weight on edge between this peer and
        """
        return self.neighbors.get(nid, {}).get('dist', INFINITY)
    
    def getNID(self, peerid, default=None):
        """ Return the relative ID associated with IP
            return default if the vertices aren't connected """
        return self.neighbors.get(peerid, {}).get('nid', default)
    
    def getNbrs(self):
        return self.redges.keys()
    
    def isConnected(self, peerid):
        return peerid in self.redges.keys()
    
    def printConnections(self):
        """Debugging only. Returns IP-self: IP-0, IP-1, IP-2, ..., IP-n"""
        return self.name + ": " + ", ".join(map(str, self.edges.iteritems()))
    
    def __str__(self):
        return self.name


class NetworkModel:
    """Simple Graph model of network"""
    def __init__(self):
        self.names = {}
    
    def get(self, peerid):
        """
        @type peerid: string
        @return: SimPeer object corresponding to name or None if nonexistant
        @rtype: SimPeer
        """
        return self.names.get(peerid, None)
    
    def getNames(self):
        return self.names.keys()
    
    def getVertices(self):
        return self.names.values()
    
    def addPeer(self, peerid, pubkey):
        """
        @type peerid: string
        @param pubkey: public key to use when encrypting to this peer
        @type pubkey: Anomos.crypto.RSAPubKey
        """
        self.names[peerid] = SimPeer(peerid, pubkey)
    
    def order(self):
        """
        @return: Number of SimPeers in network
        """
        return len(self.names)
    
    def minDegree(self):
        return min([v.degree() for v in self.getVertices()])
    
    def maxDegree(self):
        return max([v.degree() for v in self.getVertices()])
    
    def connect(self, v1, v2):
        """
        Creates connection between two nodes and selects Neighbor ID (NID).
        @param v1: Peer ID
        @type v1: string
        @param v2: Peer ID
        @type v2: string
        """
        nidsV1 = self.get(v1).getAvailableNIDs()
        nidsV2 = self.get(v2).getAvailableNIDs()
        nid = random.choice(list(nidsV1.intersection(nidsV2)))
        self.get(v1).addNeighbor(v2, nid)
        self.get(v2).addNeighbor(v1, nid)
    
    def disconnect(self, peerid):
        """
        Removes designated peer from network
        @param peerid: Peer ID (str) of peer to be removed
        """
        if peerid in self.names:
            for neighborOf in self.names[peerid].getNbrs():
                self.names[neighborOf].removeEdge(peerid)
            del self.names[peerid]
    
    def bfConnected(self, source):
        """
        Breadth first search for all nodes connected to source
        @param source: Peer ID of a node in the network
        @type source: string
        """
        opened = [source]
        closed = []
        while opened:
            n = opened.pop(0)
            if n not in closed:
                opened.extend(self.get(n).getNbrs())
                closed.append(n)
        return closed
    
    def isConnected(self):
        """
        @returns: True if graph is connected, false if not
        @rtype:boolean
        """
        if self.order():
            source = self.getNames()[0]
            #Ensure that the number of vertices connected to any one vertex
            #is equal to the total number of vertices in the network
            if len(self.bfConnected(source)) == self.order():
                return True
        return False
    
    def shortestPath(self, s, d):
        """
        Returns (Dijikstra) shortest path from s to d as a list of peer IDs
        
        @param s: Peer ID (str) of the start node
        @param d: Peer ID (str) of the end node
        
        @type paths: dictionary of Peer IDs each mapped to lists of Peer IDs
        @return: list of Peer IDs
        """
        source = self.get(s)
        dest = self.get(d)     
        paths = dict.fromkeys(self.getNames(), [])
        distances = dict.fromkeys(self.getNames(), INFINITY)
        
        distances[source.name] = 0 # The distance of the source to itself is 0
        dist_to_unknown = distances.copy() # Safe to destroy copy
        last = source
        while last.name != dest.name:
            # Select the next vertex to explore, which is not yet fully explored and which 
            # minimizes the already-known distances.
            cur_name = min([(v, k) for (k, v) in dist_to_unknown.iteritems()])[1]
            cur = self.get(cur_name)
            for n in cur.neighbors:
                d = cur.neighbors[n].get('dist')
                if distances[n] > distances[cur_name] + d:
                    distances[n] = distances[cur_name] + d
                    paths[n] = paths[cur_name] + [n]
                    if dist_to_unknown.has_key(n):
                        dist_to_unknown[n] = distances[n]
            if cur_name in dist_to_unknown: # Delete the completely explored vertex
                del dist_to_unknown[cur_name]
            last = cur
        return paths[dest.name]

    def getTrackingCode(self, source, dest):
        """
        Generate the tracking code for the shortest path from source to dest
        
        @param source: Peer ID (str) of the start node
        @param dest: Peer ID (str) of the end node
        @return: See NetworkModel.encryptTC
        @rtype: string
        """
        v_source = self.get(source)
        v_dest = self.get(dest)
        
        # Block direct connections from source to dest
        sd_temp = v_source.getWeight(dest)
        if sd_temp:
            v_source.reWeight(dest, INFINITY)         
        pathByNames = self.shortestPath(source,dest)
        if sd_temp:
            v_source.reWeight(dest, sd_temp)
        return self.encryptTC(pathByNames)
    
    def encryptTC(self, pathByNames, plaintext='#', msglen=1024):
        """
        Returns an encrypted tracking code
        @see: http://anomos.info/wp/2008/06/19/tracking-codes-revised/
        
        @param pathByNames: List of peer id's belonging to members of chain
        @type pathByNames:  list
        @param plaintext:   Message to be encrypted at innermost onion layer.
        @type plaintext:    str
        @return: E_a(TC_b + E_b(TC_c + E_c(plaintext)))
        @rtype: string
        """
        #TODO: Padding
        message = plaintext # Some easy to check string for recipient to read
        prev_neighbor = None
        for peername in reversed(pathByNames):
            peerobj = self.get(peername)
            if prev_neighbor:
                cipherd = peerobj.pubkey.encrypt(str(prev_neighbor.getNID(peername)))
                message = cipherd + message
            else:
                message = peerobj.pubkey.encrypt(message)
            prev_neighbor = peerobj
        while len(message) < msglen:
            message += chr(random.randint(0,255))
        return message
    
    def __repr__(self):
        return "\n".join(map(Vertex.printConnections, self.names.values()))


###########
##TESTING##
###########
def tcTest(numnodes=10, numedges=20):
    from random import sample
    G_ips = ['.'.join([str(i)]*4) for i in range(numnodes)]
    #Graph = [Vertex(G_ips[0], zip(G_ips[1:3], (1,1))), \
    #   Vertex(G_ips[1], zip(G_ips[2:4], (1,1))), \
    #   Vertex(G_ips[2], ()), \
    #   Vertex(G_ips[3], zip(G_ips[4:6], (1,3))), \
    #   Vertex(G_ips[4], ((G_ips[5],1), (G_ips[0],1))), \
    #   Vertex(G_ips[5], ())]
    graph = NetworkModel()
    for peerid in G_ips:
        en = RSA.gen_key(1024,65537).pub()
        pk = RSAPubKey(en)
        graph.addPeer(peerid, pk)
    #graph.insert(*[Vertex(ip) for ip in G_ips])
    for i in range(numedges):
        v1,v2 = sample(G_ips, 2)
        graph.connect(v1, v2)
    print "Num Nodes: %s, Num Connections: %s" % (numnodes, numedges)
    #print "Graph is connected? ", graph.isConnected()
    for i in range(1):
        n1, n2 = sample(range(graph.order()), 2)
        print len(graph.getTrackingCode(G_ips[n1], G_ips[n2]))
        #print "\t%d, %d:" % (n1, n2), graph.getTrackingCode(G_ips[n1], G_ips[n2])
    #print "\t0, 3:", getTrackingCode(graph, G_ips[0], G_ips[3])
    #print "\t3, 0:", getTrackingCode(graph, G_ips[3], G_ips[0])
    #print "\t5, 2:", getTrackingCode(graph, G_ips[5], G_ips[2])
    #print "\t2, 5:", getTrackingCode(graph, G_ips[2], G_ips[5])
    #print "\t2, 4:", getTrackingCode(graph, G_ips[2], G_ips[4])

if __name__ == "__main__":
    from sys import argv
    options = {}
    for opt in argv[1:]:
        o = opt.strip('-')
        key,val = o.split('=')
        options[key] = int(val)
    tcTest(**options)
