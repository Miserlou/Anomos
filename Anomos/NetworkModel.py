"""
file: NetworkModel.py
author: John Schanck <jmschanck@gmail.com>
license: See License.txt

about:
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

INFINITY = maxint-1
TC_DELIMITER = ":"

class SimPeer:
    def __init__(self, name, pubkey, maxid=100):
        self.name = name
        self.pubKey = pubkey
        self.maxid = maxid
        self.neighbors = {}
        self.id_map = {}
    
    def addNeighbor(self, peerid, nid):
        self.neighbors.setdefault(peerid, {'dist':1,'nid':nid})
        self.id_map[nid] = peerid
    
    def removeEdge(self, peerid):
        nid = self.neghbors.get(peerid, {}).get('nid', None)
        if self.edges.has_key(peerid):
            del self.neighbors[peerid]
        if nid:
            del self.id_map['nid']
    
    def disconnect(self):
        self.neighbors = {}
        self.id_map = {}
    
    def getAvailableNIDs(self):
        '''returns set object containing NIDs in range 0 -> maxid which are not in use'''
        used = set(self.id_map.keys())
        idrange = set(range(0,self.maxid))
        return idrange - used
    
    def degree(self):
        return len(self.neighbors)
    
    def reWeight(self, peerid, weight):
        """ Reset the weight between this vertex and IP """
        if self.neighbors.has_key(peerid):
            self.neighbors[peerid]['dist'] = weight
    
    def getWeight(self, nid):
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
    '''Simple Graph model of network'''
    def __init__(self):
        self.names = {}
    
    def get(self, name):
        """Return the vertex object v with v.name = name"""
        return self.names.get(name, None)
    
    def getNames(self):
        return self.names.keys()
    
    def getVertices(self):
        return self.names.values()
    
    def addPeer(self, peerid, pubkey):
        self.names[peerid] = SimPeer(peerid, pubkey)
    
    def order(self):
        """The order of a graph equals the number of vertices it contains"""
        return len(self.names)
    
    def minDegree(self):
        return min([v.degree() for v in self.getVertices()])
    
    def maxDegree(self):
        return max([v.degree() for v in self.getVertices()])
    
    def connect(self, v1, v2):
        nidsV1 = self.get(v1).getAvailableNIDs()
        nidsV2 = self.get(v2).getAvailableNIDs()
        nid = random.choice(list(nidsV1.intersection(nidsV2)))
        self.get(v1).addNeighbor(v2, nid)
        self.get(v2).addNeighbor(v1, nid)
    
    def disconnect(self, peerid):
        if peerid in self.names:
            for neighborOf in self.names[peerid].getNbrs():
                self.names[neighborOf].removeEdge(peerid)
            del self.names[peerid]
    
    def bfConnected(self, source):
        """Return all vertices connected to source, breadth first"""
        opened = [source]
        closed = []
        while opened:
            n = opened.pop(0)
            if n not in closed:
                opened.extend(self.get(n).getNbrs())
                closed.append(n)
        return closed
    
    def isConnected(self):
        """Returns True if the graph is connected and false if not.
           A graph is connected if for any two vertices V and V' in the vertex
           set there exists a path p which connects them.
        """
        if self.order():
            source = self.getNames()[0]
            #Ensure that the number of vertices connected to any one vertex
            #is equal to the total number of vertices in the network
            if len(self.bfConnected(source)) == self.order():
                return True
        return False
    
    def shortestPath(self, s, d):
        """Returns shortest path from s to d as a list of peer IDs
        
        Arguments:
        s -- name of the source vertex
        d -- name of the dest vertex
        """
        source = self.get(s)
        dest = self.get(d)     
        paths = dict.fromkeys(self.getNames(), [])
        distances = dict.fromkeys(self.getNames(), INFINITY)
        
        distances[source.name] = 0 # The distance of the source to itself is 0
        dist_to_unknown = distances.copy() # Select the next vertex to explore from this dict
        last = source
        while last.name != dest.name:
            # Select the next vertex to explore, which is not yet fully explored and which 
            # minimizes the already-known distances.
            min_name = min([(v, k) for (k, v) in dist_to_unknown.iteritems()])[1]
            next = self.get(min_name)
            for n, info in next.neighbors.iteritems(): # n is the name of an adjacent vertex, info is dict of dist and nid
                d = info.get('dist')
                if distances[next.name] + d < distances[n]:
                    distances[n] = distances[next.name] + d
                    paths[n] = paths[next.name] + [n]
                if n in dist_to_unknown:
                    dist_to_unknown[n] = distances[n]
            last = next
            if last.name in dist_to_unknown: # Delete the completely explored vertex
                del dist_to_unknown[last.name]
        return paths[dest.name]

    def getTrackingCode(self, source, dest):
        """Generate the tracking code for the shortest path from source to dest
        Arguments:
        source -- Name of the start vertex
        dest -- Name of the end vertex
        tclen -- Length of the tracker code to be generated (default 10)
        tcmaxval -- Maximum value allowed to be added as padding (should be
                    equal to the maximum order of any vertex in the graph)
        """
        v_source = self.get(source)
        v_dest = self.get(dest)
        
        # Block direct connections from source to dest
        sd_temp = v_source.getWeight(dest)
        if sd_temp:
            v_source.reWeight(dest, INFINITY) 
        
        pathByNames = self.shortestPath(source,dest)
        tc = pathByNames
        #tc = self.encryptTC(pathByNames)
        
        #Obsolete padding
        #maxval = 5#(graph.maxDegree() + graph.minDegree())/2
        #padding_data = sha(str(hash(v_dest) ^ hash(tuple(tc)))).digest()
        #padding = [str(ord(i)%maxval) for i in padding_data[:(tclen-(len(tc)-1))]]
        #tc.extend(padding)
        
        v_source.reWeight(dest, sd_temp)
        return TC_DELIMITER.join(tc)
    
    def encryptTC(self, pathByNames, plaintext='#'):
        #TODO: Padding
        message = plaintext # Some easy to check string for recipient to read + padding
        prev_neighbor = None
        for peername in reversed(pathByNames):
            peerobj = self.get(peername)
            if prev_neighbor:
                message = prev_neighbor.getnid(peer) + message
            peerobj.pubkey.encrypt(message)
            prev_neighbor = peerobj
        return message # result: E_a(TC_b + E_b(TC_c + E_c(message)))
    
    def __repr__(self):
        return "\n".join(map(Vertex.printConnections, self.names.values()))


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
        graph.addPeer(peerid, None)
    #graph.insert(*[Vertex(ip) for ip in G_ips])
    for i in range(numedges):
        v1,v2 = sample(G_ips, 2)
        graph.connect(v1, v2)
    print "Num Nodes: %s, Num Connections: %s" % (numnodes, numedges)
    #print "Graph is connected? ", graph.isConnected()
    for i in range(10):
        n1, n2 = sample(range(graph.order()), 2)
        print "\t%d, %d:" % (n1, n2), graph.getTrackingCode(G_ips[n1], G_ips[n2])
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
