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
from operator import itemgetter
from sys import maxint as INFINITY
import Anomos.crypto as crypto

from Anomos import bttime
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

    def cmpCertificate(self, peercert):
        return crypto.compareCerts(self.pubkey.certificate, peercert)

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
        """ Return the relative ID associated with peerid
            return default if the vertices aren't connected """
        return self.neighbors.get(peerid, {}).get('nid', default)

    def getNbrs(self):
        return self.neighbors.keys()

    def numTorrents(self):
        return len(self.infohashes)

    def isSharing(self, infohash):
        return self.infohashes.has_key(infohash)

    def isSeeding(self, infohash):
        return self.isSharing(infohash) and self.infohashes[infohash][1] == 0

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
        return set(i for i in self.names \
                if self.names[i].isSharing(infohash))

    def getSeedingPeers(self, infohash):
        return set(i for i in self.names \
                if self.names[i].isSharing(infohash) and \
                    not self.names[i].isSeeding(infohash))

    def getNames(self):
        return self.names.keys()

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
        toRm = set(peer.neighbors.keys()).union(peer.failedNeighbors)
        for pid in toRm.intersection(set(others)):
            others.remove(pid) # and the peers source is connected to
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

    def getPathsToFile(self, src, infohash, is_seed=False, minpathlen=3):
        """
        Modified Dijkstra with the added condition that if the peer
        corresponding to a vertex is sharing the desired file then paths less
        than minpathlen hops long act as if they have infinite weight.

        @param src: Peer ID (str) of the start node
        @param infohash: File to search for
        @param minpathlen: Minimum path length to accept
        @return: list of Peer IDs
        """
        source = self.get(src)
        if not is_seed:
            dests = self.getDownloadingPeers(infohash)
        else:
            dests = self.getSeedingPeers(infohash)
        paths = dict.fromkeys(self.getNames(), [])
        known = dict.fromkeys(self.getNames(), [INFINITY, 0])
        DIST, PATHLEN = 0, 1 # For easy to read indicies
        known[source.name] = [0, 0] # The distance of the source to itself is 0
        unexplored = known.copy() # Safe to destroy copy
        while len(unexplored) > 0:
            # Select the next vertex to explore, which is not yet fully explored and which
            # minimizes the already-known distances.
            if len(unexplored) > 1:
                cur_name = min(*unexplored.items(), **{'key':itemgetter(1)})[0]
            else:
                cur_name = unexplored.keys()[0]
            cur_obj = self.get(cur_name)
            del unexplored[cur_name] # Remove cur_name from future candidates

            # If the smallest distance is INFINITY, the remaining nodes are all
            # unreachable.
            if known[cur_name][DIST] == INFINITY:
                break
            for n in cur_obj.neighbors:
                distToN = cur_obj.neighbors[n].get('dist')
                # If the distance to N through cur is less than the
                # current shortest distance to N through other nodes,
                # or N is a potential destination and the best path to
                # N is shorter than our minimum allowed path, then update
                # the best distance and path to N so that connections to
                # N will be routed through cur.
                if not known.get(cur_name) or not known.get(n):
                    continue
                if known[cur_name][DIST] + distToN < known[n][DIST] \
                  or (n in dests and known[n][PATHLEN] < minpathlen):
                    known[n][DIST] = known[cur_name][DIST] + distToN
                    known[n][PATHLEN] = len(paths[cur_name]) + 1
                    # Keep unexplored in sync with distances
                    if unexplored.has_key(n):
                        unexplored[n] = known[n]
                    paths[n] = paths[cur_name] + [cur_name]
        gps = [paths[p] for p in paths.iterkeys() if p in dests and
                len(paths[p]) >= minpathlen]
        print "Generated path: ", gps
        return gps

    def getTrackingCodes(self, source, infohash, count=3):
        seedp = self.get(source).isSeeding(infohash)
        paths = self.getPathsToFile(source, infohash, \
                                    is_seed=seedp, minpathlen=4)
        tcs = []
        if len(paths) > count:
            rand.shuffle(paths)
        for p in paths[:min(count, len(paths))]:
            aes = crypto.AESKey()
            kiv = ''.join((aes.key, aes.iv))
            m = self.encryptTC(p, \
                            plaintext=''.join((infohash,kiv)))
            tcs.append([kiv, m])
        return tcs

    def encryptTC(self, pathByNames, prevNbr=None, plaintext='#', msglen=4096):
        """
        Returns an encrypted tracking code
        @see: http://anomos.info/wp/2008/06/19/tracking-codes-revised/

        @param pathByNames: List of peer id's belonging to members of chain
        @type pathByNames:  list
        @param plaintext:   Message to be encrypted at innermost onion layer.
        @type plaintext:    str
        @return: E_a(\\x0 + SID_a + TC_b + E_b(\\x0 + SID_b + TC_c + \\
                    E_c(\\x1 + SID_c + plaintext)))
        @rtype: string
        """
        message = plaintext
        peername = None
        assert len(pathByNames) > 0
        peername = pathByNames.pop(-1)
        peerobj = self.get(peername)
        sid = peerobj.getSessionID()
        if prevNbr:
            nid = str(prevNbr.getNID(peername))
            tocrypt = chr(0) + sid + nid + message
            recvMsgLen = len(sid + nid) + 1 # The 'message' data is for the
                                            # next recipient, not this one.
            message = peerobj.pubkey.encrypt(tocrypt, recvMsgLen)
        else:
            tocrypt = chr(1) + sid + message
            message = peerobj.pubkey.encrypt(tocrypt, len(tocrypt))
        prevNbr = peerobj
        if len(pathByNames) > 0:
            return self.encryptTC(pathByNames, prevNbr, message, msglen)
        elif len(message) < msglen:
            # Pad to msglen
            return message + crypto.getRand(msglen-len(message))
        else:
            # XXX: Disallow messages longer than msglen?
            return message

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
