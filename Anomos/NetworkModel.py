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
from sys import maxint, argv
from sha import sha

_INFINITY = maxint-1
_TC_DELIMITER = ":"

class Vertex:
    def __init__(self, name, edges=[]):
        """Creates a vertex
        
        Arguments:
        name: Client's IP address as a string
        edges: Tuple of form ((IP-1, dist-1), (IP-2, dist-2)...(IP-n, dist-n)) 
        
        """
        self.name = name
        ### Consider changing edges to a dictionary of dictionarys with primary key = IP
        self.edges = {}     # Maps relative IDs to edges ((IP, distance) pairs)
        self.redges = {}    # Maps IP addresses to their relative ids
        map(self.addEdge, edges)
    
    def addEdge(self, edge):
        """Connects this vertex to the vertex with name: edge
        
        Note: there is no actual mapping of objects here, edge
        should be an IP address or otherwise unique string, not a 
        Vertex object. Vertex lookup is performed by Graph objects. 
        The addEdge function only creates a relationship between this
        Vertex and the name of another Vertex.
        """
        if self.edges and self.redges:
            rel_id = self.redges.get(edge[0], max(self.edges) + 1)
            self.edges[rel_id] = edge
            self.redges[edge[0]] = rel_id
        else:
            self.edges[0] = edge
            self.redges[edge[0]] = 0
    
    def removeEdge(self, edge):
        del self.edges[edge]
        del self.redges[edge]
    
    def degree(self):
        return len(self.edges)
    
    def reWeight(self, ip, weight):
        """ Reset the weight between this vertex and IP """
        rel_id = self.getRelId(ip)
        if not rel_id is None:
            self.edges[rel_id] = (ip, weight)
    
    def getWeight(self, ip):
        rel_id = self.getRelId(ip)
        if not rel_id is None:
            return self.edges[rel_id][1]
        return None
    
    def getRelId(self, ip, default=None):
        """ Return the relative ID associated with IP
            return default if the vertices aren't connected """
        return self.redges.get(ip, default)
    
    def getNbrs(self):
        return self.redges.keys()
    
    def isConnected(self, ip):
        return ip in self.redges.keys()
    
    def printConnections(self):
        """Debugging only. Returns IP-self: IP-0, IP-1, IP-2, ..., IP-n"""
        return self.name + ": " + ", ".join(map(str, self.edges.iteritems()))
    
    def __str__(self):
        return self.name


class Graph:
    def __init__(self, vertices=[]):
        self.names = {}
        self.insert(*vertices)
    
    def get(self, name):
        """Return the vertex object v with v.name = name"""
        return self.names[name]
    
    def getNames(self):
        return self.names.keys()
    
    def getVertices(self):
        return self.names.values()
    
    def order(self):
        """The order of a graph equals the number of vertices it contains"""
        return len(self.names)
    
    def minDegree(self):
        return min([v.degree() for v in self.getVertices()])
    
    def maxDegree(self):
        return max([v.degree() for v in self.getVertices()])
    
    def insert(self, *vertices):
        """Insert one or more vertices into the graph"""
        for v in vertices:
            self.names[v.name] = v
    
    def removeVertex(self, vertex):
        if vertex in self.names:
            for otherVertex in self.names[vertex].getNbrs():
                self.names[otherVertex].removeEdge(vertex)
            del self.names[vertex]
    
    def connect(self, v1, v2, w1=1, w2=1):
        """Connect v1 to v2 with weight w1 and v2 to v1 with weight w2"""
        try:
            self.get(v1).addEdge((v2, w1))
            self.get(v2).addEdge((v1, w2))
        except KeyError, k:
            print "Vertex", k, "was not found"
    
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
        """Returns shortest path from s to d as a list of relative IDs
        
        Arguments:
        s -- name of the source vertex
        d -- name of the dest vertex
        """
        source = self.get(s)
        dest = self.get(d)     
        paths = dict.fromkeys(self.getNames(), [])
        distances = dict.fromkeys(self.getNames(), _INFINITY)
        
        distances[source.name] = 0 # The distance of the source to itself is 0
        dist_to_unknown = distances.copy() # Select the next vertex to explore from this dict
        last = source
        while last.name != dest.name:
            # Select the next vertex to explore, which is not yet fully explored and which 
            # minimizes the already-known distances.
            min_name = min([(v, k) for (k, v) in dist_to_unknown.iteritems()])[1]
            next = self.get(min_name)
            for n, d in next.edges.itervalues(): # n is the name of an adjacent vertex, d is the distance to it
                if distances[next.name] + d < distances[n]:
                    distances[n] = distances[next.name] + d
                    paths[n] = paths[next.name] + [next.redges[n]]
                if n in dist_to_unknown:
                    dist_to_unknown[n] = distances[n]
            last = next
            if last.name in dist_to_unknown: # Delete the completely explored vertex
                del dist_to_unknown[last.name]
        return paths[dest.name]
    
    def __repr__(self):
        return "\n".join(map(Vertex.printConnections, self.names.values()))



def getTrackingCode(graph, source, dest, tcmaxval=lambda: 5, tclen=10):
    """Generate the tracking code for the shortest path from source to dest
    Arguments:
    graph -- The graph to be searched
    source -- Name of the start vertex
    dest -- Name of the end vertex
    tclen -- Length of the tracker code to be generated (default 10)
    tcmaxval -- Maximum value allowed to be added as padding (should be
                equal to the maximum order of any vertex in the graph)
    """
    v_source = graph.get(source)
    v_dest = graph.get(dest)
    
    sd_temp = v_source.getWeight(dest)
    if sd_temp:
        # Block direct connections from source to dest
        v_source.reWeight(dest, _INFINITY) 
    
    tc = graph.shortestPath(source,dest)
    tc = map(str, tc)
    
    maxval = 5#(graph.maxDegree() + graph.minDegree())/2
    padding_data = sha(str(hash(v_dest) ^ hash(tuple(tc)))).digest()
    padding = [str(ord(i)%maxval) for i in padding_data[:(tclen-(len(tc)-1))]]
    tc.extend(padding)
    
    
    v_source.reWeight(dest, sd_temp)
    return _TC_DELIMITER.join(tc)


def tcTest(numnodes=10, numedges=20):
    from random import sample
    G_ips = ['.'.join([str(i)]*4) for i in range(numnodes)]
    #Graph = [Vertex(G_ips[0], zip(G_ips[1:3], (1,1))), \
    #   Vertex(G_ips[1], zip(G_ips[2:4], (1,1))), \
    #   Vertex(G_ips[2], ()), \
    #   Vertex(G_ips[3], zip(G_ips[4:6], (1,3))), \
    #   Vertex(G_ips[4], ((G_ips[5],1), (G_ips[0],1))), \
    #   Vertex(G_ips[5], ())]
    graph = Graph()
    graph.insert(*[Vertex(ip) for ip in G_ips])
    for i in range(numedges):
        v1,v2 = sample(G_ips, 2)
        graph.connect(v1, v2, 1, 1)
    print "Num Nodes: %s, Num Connections: %s" % (numnodes, numedges)
    #print "Graph is connected? ", graph.isConnected()
    for i in range(10):
        n1, n2 = sample(range(graph.order()), 2)
        print "\t%d, %d:" % (n1, n2), getTrackingCode(graph, G_ips[n1], G_ips[n2])
    #print "\t0, 3:", getTrackingCode(graph, G_ips[0], G_ips[3])
    #print "\t3, 0:", getTrackingCode(graph, G_ips[3], G_ips[0])
    #print "\t5, 2:", getTrackingCode(graph, G_ips[5], G_ips[2])
    #print "\t2, 5:", getTrackingCode(graph, G_ips[2], G_ips[5])
    #print "\t2, 4:", getTrackingCode(graph, G_ips[2], G_ips[4])

if __name__ == "__main__":
    options = {}
    for opt in argv[1:]:
        o = opt.strip('-')
        key,val = o.split('=')
        options[key] = int(val)
    arglist = []
    if options.has_key('numNodes'):
        arglist.append(options['numNodes'])
    if options.has_key('numEdges'):
        arglist.append(options['numEdges'])
    tcTest(*arglist)
