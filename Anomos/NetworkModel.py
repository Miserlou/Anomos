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

import random
from sys import maxint as INFINITY
import Anomos.Crypto

from Anomos import bttime

# Use psyco if it's available.
try:
    import psyco
    psyco.full()
except ImportError:
    pass

class SimPeer:
    """
    Container for some information tracker needs to know about each peer, also
    node in Graph model of network topology used for Tracking Code generation.
    """
    def __init__(self, name, pubkey, ip, port, sid):
        """
        @param name: Peer ID to be assigned to this SimPeer
        @type name: string
        @param pubkey: RSA Public Key to use when encrypting to this peer
        @type pubkey: Anomos.Crypto.RSAPubKey
        """
        self.name = name
        self.ip = ip
        self.port = port
        self.pubkey = Anomos.Crypto.PeerCert(pubkey)
        self.neighbors = {} # {PeerID: {nid:#, ip:"", port:#}}
        self.id_map = {}    # {NeighborID : PeerID}
        self.infohashes = {} # {infohash: (downloaded, left)}
        self.last_seen = 0  # Time of last client announce
        self.last_modified = bttime() # Time when client was last modified
        self.failed_nbrs = []
        self.nbrs_needed = 0
        self.sessionid = sid
        self.num_natcheck = 0
        self.nat = True # assume NAT

    def needsUpdate(self):
        return self.last_modified > self.last_seen

    def cmpCertificate(self, peercert):
        return self.pubkey.cmp(peercert)

    def numNeeded(self):
        return self.nbrs_needed

    def update(self, ip, params):
        self.last_seen = bttime()
        ihash = params.get('info_hash')
        dl = params.get('downloaded')
        left = params.get('left')
        port = int(params.get('port'))
        # If ip or port changed so we should natcheck again
        if (ip, port) != (self.ip, self.port):
            simpeer.num_natcheck = 0
            simpeer.nat = True
        # Mark any failed peers
        for x in params.get('failed', []):
            self.failed(x)
        # Remove any stopped torrents
        if params.get('event') == 'stopped':
            if self.infohashes.has_key(ihash):
                del self.infohashes[ihash]
        elif None not in (ihash, dl, left):
            # Update download totals
            self.infohashes[ihash] = (int(dl), int(left))

    def addNeighbor(self, peerid, nid, ip, port):
        """
        Assign Neighbor ID to peer
        @type peerid: string
        @type nid: int
        """
        self.neighbors.setdefault(peerid, {'nid':nid,'ip':ip, 'port':port})
        self.id_map[nid] = peerid
        self.last_modified = bttime()
        if self.nbrs_needed > 0:
            self.nbrs_needed -= 1

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
            self.nbrs_needed += 1

    def failed(self, nid):
        if self.id_map.has_key(nid):
            self.failed_nbrs.append(self.id_map[nid])
            self.rmNeighbor(self.id_map[nid])

    def getSessionID(self):
        return self.sessionid

    def getAvailableNIDs(self):
        """
        @return: set object containing NIDs in range 0 -> 254 which are not in use
        @rtype: set of ints
        """
        used = set(self.id_map.keys())
        idrange = set([chr(i) for i in range(0, 255)])
        return idrange - used

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
        return self.infohashes.get(infohash, (None,None))[1] == 0

    def __str__(self):
        return self.name


class NetworkModel:
    """Simple Graph model of network"""
    def __init__(self, config):
        self.names = {}    # {peerid : SimPeer object}
        self.complete = {} # {infohash : set([peerid,...,])}
        self.incomplete = {} # {infohash : set([peerid,...,])}
        self.config = config

    def get(self, peerid):
        """
        @type peerid: string
        @return: SimPeer object corresponding to name or None if nonexistant
        @rtype: SimPeer
        """
        return self.names.get(peerid, None)

    def swarm(self, infohash):
        return set.union(self.leechers(infohash),
                         self.seeders(infohash))
        #return set(i for i in self.names \
        #        if self.names[i].isSharing(infohash))

    def leechers(self, infohash):
        return self.incomplete.get(infohash, set()).copy()
        #return set(i for i in self.names \
        #        if self.names[i].isSharing(infohash) and \
        #            not self.names[i].isSeeding(infohash))

    def seeders(self, infohash):
        return self.complete.get(infohash, set()).copy()
        #return set(i for i in self.names if self.names[i].isSeeding(infohash))

    def initPeer(self, peerid, pubkey, ip, port, sid, num_neighbors=4):
        """
        @type peerid: string
        @param pubkey: public key to use when encrypting to this peer
        @type pubkey: Anomos.Crypto.RSAPubKey
        @returns: a reference to the created peer
        @rtype: SimPeer
        """
        self.names[peerid] = SimPeer(peerid, pubkey, ip, port, sid)
        self.rand_connect(peerid, num_neighbors)
        return self.names[peerid]

    def update_peer(self, peerid, ip, params):
        simpeer = self.get(peerid)
        simpeer.update(ip, params)

        infohash = params.get('info_hash')
        complete = (params.get('left') == 0)
        if params.get('event') == 'stopped':
            self.remove_from_swarm(peerid, infohash)
            if simpeer.numTorrents() == 0:
                self.disconnect(peerid)
        else:
            self.update_swarm(peerid, infohash, complete)


    def update_swarm(self, peerid, infohash, complete):
        seedset = self.complete.get(infohash)
        leechset = self.incomplete.get(infohash)
        if complete:
            # Remove peer from the leecher list
            if leechset and (peerid in leechset):
                leechset.remove(peerid)
                if len(leechset) == 0:
                    del self.incomplete[infohash]
            # Ensure there's a set for this infohash
            if not seedset:
                self.complete[infohash] = set()
                seedset = self.complete[infohash]
            # Add them to the seeder list
            seedset.add(peerid)
        else:
            # Remove peer from the seeder list if they previously
            # reported having the whole file
            if seedset and (peerid in seedset):
                seedset.remove(peerid)
                if len(seedset) == 0:
                    del self.complete[infohash]
            # Ensure there's a set for this infohash
            if not leechset:
                self.incomplete[infohash] = set()
                leechset = self.incomplete[infohash]
            # Add them to the leecher list
            leechset.add(peerid)

    def remove_from_swarm(self, peerid, infohash):
        seedset = self.complete.get(infohash)
        leechset = self.complete.get(infohash)
        # Remove from seeders list
        if seedset and (peerid in seedset):
            seedset.remove(peerid)
            if len(seedset) == 0:
                del self.complete[infohash]
        # Remove from leechers list
        if leechset and (peerid in leechset):
            leechset.remove(peerid)
            if len(leechset) == 0:
                del self.incomplete[infohash]

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
            p1.addNeighbor(v2, nid, p2.ip, p2.port)
            p2.addNeighbor(v1, nid, p1.ip, p2.port)
        else:
            raise RuntimeError("No available NeighborIDs. It's possible the \
                                network is being attacked.")

    def rand_connect(self, peerid, numpeers):
        """
        Assign 'numpeers' many randomly selected neighbors to
        peer with id == peerid
        """
        peer = self.get(peerid)
        order = range(len(self.names.keys()))
        random.shuffle(order)
        candidates = self.names.keys()
        c = 0
        for i in order:
            if c >= numpeers:
                break
            opid = candidates[i]
            # Don't connect peers to: Themselves, peers who
            # they're already neighbors with, peers they've failed
            # to make connections to in the past, or NAT'd peers.
            if  opid == peerid or \
                opid in peer.neighbors.keys() or \
                opid in peer.failed_nbrs or \
                self.get(opid).nat:
                    continue
            if not self.config.get('allow_close_neighbors') and \
                peer.ip == self.get(opid).ip:
                    continue
            self.connect(peerid, opid)
            c += 1

    def disconnect(self, peerid):
        """
        Removes designated peer from network
        @param peerid: Peer ID (str) of peer to be removed
        """
        if peerid in self.names:
            for neighborOf in self.names[peerid].getNbrs():
                if neighborOf in self.names:
                    self.names[neighborOf].rmNeighbor(peerid)
            del self.names[peerid]

    def nbrsOf(self, peerid):
        if not self.get(peerid):
            return []
        return self.get(peerid).neighbors.keys()

    def getPathsToFile(self, src, infohash, how_many=5, is_seed=False, minhops=3):
        source = self.get(src)
        snbrs = set(source.neighbors.keys())
        if is_seed:
            dests = list(self.leechers(infohash))
        else:
            dests = list(self.swarm(infohash))
            if src in dests:
                dests.remove(src)
        if len(dests) == 0:
            return []

        paths = []
        #destination = self.get(random.choice(dests))
        for dname in dests:
            if len(paths) >= how_many:
                break
            destination = self.get(dname)
            # Pick a destination node
            dnbrs = set(destination.neighbors.keys())
            if len(dnbrs) == 0:
                continue
            lvls = [dnbrs,]
            #lvls[0] = the neighbors of destination
            #lvls[1] = the neighbors of neighbors (nbrs^2) of destination
            #lvls[2] = the nbrs^3 of destination
            for i in range(1, minhops-1):
                # Take the union of all the neighbor sets of peers in the last
                # level and append the result to lvls
                t = reduce(set.union, [set(self.nbrsOf(n)) for n in lvls[i-1]])
                lvls.append(t)
            isect = snbrs.intersection(lvls[-1])
            # Keep growing until we find an snbr or exhaust the searchable space
            while isect == set([]) and len(lvls) < self.config['max_path_len']:
                t = reduce(set.union, [set(self.nbrsOf(n)) for n in lvls[i-1]])
                lvls.append(t)
                isect = snbrs.intersection(lvls[-1])
            isect.discard(dname)
            if isect == set([]):
                continue
            cur = random.choice(list(isect))
            path = [cur,]
            c = len(lvls) - 2
            exclude = set([source.name, destination.name])
            while c >= 0:
                exclude.update(path[-1])
                validChoices = lvls[c].difference(exclude)
                nbrsOfLast = set(self.nbrsOf(path[-1]))
                candidates = list(nbrsOfLast.intersection(validChoices))
                if candidates == []: # No non-cyclic path available
                    break
                #TODO: We can fork the path at this point and create an
                #   alternate if there is more than one candidate
                path.append(random.choice(candidates))
                c -= 1
            path.append(destination.name)
            if len(path) < minhops: # Should occur only w/ cyclic paths
                continue
            path.insert(0, source.name)
            paths.append(path)
        print paths
        return paths

    def getTrackingCodes(self, source, infohash, count=3):
        seedp = self.get(source).isSeeding(infohash)
        paths = self.getPathsToFile(source, infohash, \
                                    is_seed=seedp, minhops=3)
        tcs = []
        if len(paths) > count:
            random.shuffle(paths)
        for p in paths[:min(count, len(paths))]:
            aes = Anomos.Crypto.AESKey()
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
        peername = pathByNames.pop(-1)
        peerobj = self.get(peername)
        sid = peerobj.getSessionID()
        if prevNbr:
            #XXX: This should fail rather than create a bad TCode
            #    with a \xff in it
            nid = str(prevNbr.getNID(peername, '\xff'))
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
            return message + Anomos.Crypto.get_rand(msglen-len(message))
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
    Anomos.Crypto.init('./')
    G_ips = ['.'.join([str(i)]*4) for i in range(numnodes)]
    graph = NetworkModel()
    pk = Anomos.Crypto.RSAKeyPair('WampWamp') # All use same RSA key for testing.
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
        p += Anomos.Crypto.get_rand(repadlen)
        tc.append(m)
        while m != '#':
            plen = len(p)
            m, p = pk.decrypt(p, True)
            p += Anomos.Crypto.get_rand(plen-len(p))
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
