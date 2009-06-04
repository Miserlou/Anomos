# NetworkModel.py
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Written by John M. Schanck and Rich Jones

########################################################################
# Note:
# The Anomos tracker keeps a running model of the
# network at all times, and uses it to control the flow
# of file chunks. Each peer is represented by a Vertex
# object; the connections between peers are called edges and
# are tuples of the form (IP address, weight). Each Vertex
# assigns relative IDs to its edges. The IP addresses these
# relative IDs represent are only known by the Anomos tracker
# and the peer which the Vertex object represents.
########################################################################

import random
from sys import maxint as INFINITY
import hashlib
import Anomos.crypto as crypto

from Anomos.platform import bttime
from M2Crypto import RSA

# Use psyco if it's available.
try:
    import psyco
    psyco.full()
except ImportError:
    pass

DEBUG_ON = True
def DEBUG(*args):
    if DEBUG_ON:
        print args

class SimPeer:
    """
    Container for some information tracker needs to know about each peer, also
    node in Graph model of network topology used for Tracking Code generation.
    """
    def __init__(self, name, pubkey, loc, sid):
        """
        @param name: Peer ID to be assigned to this SimPeer
        @type name: string
        @param pubkey: RSA Public Key to use when encrypting to this peer
        @type pubkey: Anomos.crypto.RSAPubKey
        """
        self.name = name
        self.loc = loc      # Client (ip, port)
        self.pubkey = crypto.PeerCert(pubkey)
        self.neighbors = {} # {PeerID: {dist:#, nid:#, loc:(#,#)}}
        self.id_map = {}    # {NeighborID : PeerID}
        self.infohashes = {} # {infohash: (downloaded, left)}
        self.last_seen = 0  # Time of last client announce
        self.last_modified = bttime() # Time when client was last modified
        self.failedNeighbors = []
        self.needsNeighbors = 0
        self.sessionid = sid

    def needsUpdate(self):
        return self.last_modified > self.last_seen

    def numNeeded(self):
        return self.needsNeighbors

    def update(self, params):
        self.last_seen = bttime()
        ihash = params.get('info_hash')
        dl = params.get('downloaded')
        left = params.get('left')
        for x in params.get('failed', []):
            self.failed(x)
        if params.get('event') == 'stopped':
            if self.infohashes.has_key(ihash):
                del self.infohashes[ihash]
        elif None not in (ihash, dl, left):
            # Input should have already been validated by
            # tracker.
            self.infohashes[ihash] = (int(dl), int(left))

    def addNeighbor(self, peerid, nid, loc):
        """
        Assign Neighbor ID to peer
        @type peerid: string
        @type nid: int
        """
        #TODO: What happens if we get a new neighbor we're already connected to
        self.neighbors.setdefault(peerid, {'dist':1,'nid':nid,'loc':loc})
        self.id_map[nid] = peerid
        self.last_modified = bttime()

    def rmNeighbor(self, peerid):
        """
        Remove connection to neighbor
        @type peerid: string
        """
        edge = self.neighbors.get(peerid)
        if edge:
            print "rmNeighbor", peerid
            del self.id_map[edge['nid']]
            del self.neighbors[peerid]
            self.last_modified = bttime()

    def failed(self, nid):
        if self.id_map.has_key(nid):
            self.failedNeighbors.append(self.id_map[nid])
            self.rmNeighbor(self.id_map[nid])
            self.needsNeighbors += 1

    def getSessionID(self):
        return self.sessionid

    def getAvailableNIDs(self):
        """
        @return: set object containing NIDs in range 0 -> 255 which are not in use
        @rtype: set of ints
        """
        used = set(self.id_map.keys())
        idrange = set([chr(i) for i in range(0, 256)])
        return idrange - used

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
        return self.neighbors.keys()

    def getOrder(self):
        return len(self.neighbors)

    def numTorrents(self):
        return len(self.infohashes)

    def isSharing(self, infohash):
        return self.infohashes.has_key(infohash)

    def isSeeding(self, infohash):
        return self.isSharing(infohash) and self.infohashes[infohash][1] == 0

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

    def getSwarm(self, infohash, withSeeders=True):
        """
        @param infohash: specifies the torrent
        @param withSeeders: specifies whether returned list should include
        seeders
        @returns: PeerID of each client in Swarm
        """
        return [k for k,v in self.names.iteritems() if v.isSharing(infohash)]

    def getDownloadingPeers(self, infohash):
        return [k for k,v in self.names.iteritems()
                    if v.isSharing(infohash) and not v.isSeeding(infohash)]

    def getSeedingPeers(self, infohash):
        return [k for k,v in self.names.iteritems() if v.isSeeding(infohash)]

    def getNames(self):
        return self.names.keys()

#   def getVertices(self):
#       return self.names.values()

    def initPeer(self, peerid, pubkey, loc, sid, num_neighbors=4):
        """
        @type peerid: string
        @param pubkey: public key to use when encrypting to this peer
        @type pubkey: Anomos.crypto.RSAPubKey
        @returns: a reference to the created peer
        @rtype: SimPeer
        """
        self.names[peerid] = SimPeer(peerid, pubkey, loc, sid)
        self.randConnect(peerid, num_neighbors)
        return self.names[peerid]

#   def order(self):
#       """
#       @return: Number of SimPeers in network
#       """
#       return len(self.names)

#   def minDegree(self):
#       return min([v.degree() for v in self.getVertices()])

#   def maxDegree(self):
#       return max([v.degree() for v in self.getVertices()])

    def connect(self, v1, v2):
        """
        Creates connection between two nodes and selects Neighbor ID (NID).
        @param v1: Peer ID
        @type v1: string
        @param v2: Peer ID
        @type v2: string
        """
        p1 = self.get(v1)
        p2 = self.get(v2)
        nidsP1 = p1.getAvailableNIDs()
        nidsP2 = p2.getAvailableNIDs()
        l = list(nidsP1.intersection(nidsP2))
        if len(l):
            nid = random.choice(l)
            p1.addNeighbor(v2, nid, p2.loc)
            p2.addNeighbor(v1, nid, p1.loc)
        else:
            raise RuntimeError("No available NeighborIDs. It's possible the \
                                network is being attacked.")

    def randConnect(self, peerid, numpeers):
        """
        Assign 'numpeers' many randomly selected neighbors to
        peer with id == peerid
        """
        peer = self.get(peerid)
        others = self.names.keys()
        others.remove(peerid) # Remove source peer
        for pid in peer.neighbors.keys(): # and the peers already connected to
            others.remove(pid)
        for pid in peer.failedNeighbors:
            others.remove(pid)
        for c in range(numpeers): # Connect to numpeers randomly selected peers
            if len(others) == 0: # Unless there aren't that many in the network.
                break
            otherpeerid = random.choice(others)
            self.connect(peerid, otherpeerid)
            others.remove(otherpeerid)

    def disconnect(self, peerid):
        """
        Removes designated peer from network
        @param peerid: Peer ID (str) of peer to be removed
        """
        if peerid in self.names:
            for neighborOf in self.names[peerid].getNbrs():
                self.names[neighborOf].rmNeighbor(peerid)
            del self.names[peerid]

#   def bfConnected(self, source):
#       """
#       Breadth first search for all nodes connected to source
#       @param source: Peer ID of a node in the network
#       @type source: string
#       """
#       opened = [source]
#       closed = []
#       while opened:
#           n = opened.pop(0)
#           if n not in closed:
#               opened.extend(self.get(n).getNbrs())
#               closed.append(n)
#       return closed

#   def isConnected(self):
#       """
#       @returns: True if graph is connected, false if not
#       @rtype:boolean
#       """
#       if self.order():
#           source = self.getNames()[0]
#           #Ensure that the number of vertices connected to any one vertex
#           #is equal to the total number of vertices in the network
#           if len(self.bfConnected(source)) == self.order():
#               return True
#       return False

    def shortestPath(self, s, d):
        """
        Returns (Dijikstra) shortest path from s to d as a list of peer IDs
        @param s: Peer ID (str) of the start node
        @param d: Peer ID (str) of the end node

        @return: list of Peer IDs
        """
        source = self.get(s)
        dest = self.get(d)
        paths = dict.fromkeys(self.getNames(), [])
        distances = dict.fromkeys(self.getNames(), INFINITY)

        distances[source.name] = 0 # The distance of the source to itself is 0
        dist_to_unknown = distances.copy() # Safe to destroy copy
        print distances
        print dist_to_unknown
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

## Little experiment with modified dijikstra
#    def closestWithFile(self, source, infohash, count=1):
#        source = self.get(s)

#        paths = dict.fromkeys(self.getNames(), [])
#        distances = dict.fromkeys(self.getNames(), INFINITY)
#        complete_paths = {}
#
#        distances[source.name] = 0 # The distance of the source to itself is 0
#        dist_to_unknown = distances.copy() # Safe to destroy copy
#        last = source
#        while dist_to_unknown:
#            # Select the next vertex to explore, which is not yet fully explored and which
#            # minimizes the already-known distances.
#            cur_name = min([(v, k) for (k, v) in dist_to_unknown.iteritems()])[1]
#            cur = self.get(cur_name)
#            for n in cur.neighbors:
#                d = cur.neighbors[n].get('dist')
#                if distances[n] > distances[cur_name] + d:
#                    distances[n] = distances[cur_name] + d
#                    paths[n] = paths[cur_name] + [n]
#                    if self.get(n).infohashes.has_key(infohash):
#                        complete_paths[n] = paths[n]
#                    if dist_to_unknown.has_key(n):
#                        dist_to_unknown[n] = distances[n]
#            if cur_name in dist_to_unknown: # Delete the completely explored vertex
#                del dist_to_unknown[cur_name]
#            last = cur
#        return paths[dest.name]

    def getTrackingCode(self, source, dest, plaintext='#', block_direct_connections=True):
        """
        Generate the tracking code for the shortest path from source to dest

        @param source: Peer ID (str) of the start node
        @param dest: Peer ID (str) of the end node
        @return: See NetworkModel.encryptTC
        @rtype: string

        @todo: Some error checking.
        """

        v_source = self.get(source)
        v_dest = self.get(dest)

        # Block direct connections from source to dest
        if block_direct_connections:
            sd_temp = v_source.getWeight(dest)
            v_source.reWeight(dest, INFINITY)
        pathByNames = [source] + self.shortestPath(source,dest)
        DEBUG(pathByNames)
        if block_direct_connections:
            v_source.reWeight(dest, sd_temp)
            if len(pathByNames) == 1:
                return None
        return self.encryptTC(pathByNames, plaintext)

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
        message = plaintext # Some easy to check string for recipient to read
        prev_neighbor = None
        for peername in reversed(pathByNames):
            peerobj = self.get(peername)
            sid = peerobj.getSessionID()
            if prev_neighbor:
                tcnum = str(prev_neighbor.getNID(peername))
                message = peerobj.pubkey.encrypt(tcnum + sid + message, len(tcnum)+len(sid))
            else:
                message = peerobj.pubkey.encrypt(sid + message, len(sid)+len(message))
            prev_neighbor = peerobj
        if len(message) < msglen:
            message += crypto.getRand(msglen-len(message))
        return message

    def __repr__(self):
        return "\n".join(map(Vertex.printConnections, self.names.values()))


###########
##TESTING##
###########
def tcTest(numnodes=1000, numedges=10000):
    import math
    import time
    from binascii import b2a_hex
    crypto.initCrypto('./')
    G_ips = ['.'.join([str(i)]*4) for i in range(numnodes)]
    graph = NetworkModel()
    pk = crypto.RSAKeyPair('WampWamp') # All use same RSA key for testing.
    for peerid in G_ips:
        graph.initPeer(peerid, pk.pub_bin(), (peerid, 8080), int(math.log(1000)//math.log(4)))
    print "Num Nodes: %s, Num Connections: %s" % (numnodes, numedges)
    t = time.time()
    for i in range(20):
        n1, n2 = random.sample(range(graph.order()), 2)
        x = graph.getTrackingCode(G_ips[n1], G_ips[n2])
        tc = []
        m, p = pk.decrypt(x, True)
        repadlen = len(x) - len(p)
        p += crypto.getRand(repadlen)
        tc.append(m)
        while m != '#':
            plen = len(p)
            m, p = pk.decrypt(p, True)
            p += crypto.getRand(plen-len(p))
            tc.append(m)
        #print "Decrypted Tracking Code  ", ":".join(tc)
    print time.time() - t

if __name__ == "__main__":
    from sys import argv
    options = {}
    for opt in argv[1:]:
        o = opt.strip('-')
        key,val = o.split('=')
        options[key] = int(val)
    tcTest(**options)
