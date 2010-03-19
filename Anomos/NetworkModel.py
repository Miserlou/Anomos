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

from Anomos import bttime, is_valid_ip

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
    ID_RANGE = set(chr(i) for i in range(256))

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
        self.infohashes = {} # {infohash: (uploaded, downloaded, left)}
        self.relayed_total = 0
        self.last_seen = 0  # Time of last client announce
        self.last_modified = bttime() # Time when client was last modified
        self.failed_nbrs = []
        self.nbrs_needed = 0
        self.sessionid = sid
        self.num_natcheck = 0
        self.nat = True # assume NAT

    def cmp_certificate(self, peercert):
        return self.pubkey.cmp(peercert)

    def num_needed(self):
        return self.nbrs_needed

    def update(self, ip, params):
        self.last_seen = bttime()
        port = int(params.get('port'))
        # IP or port changed so we should natcheck again
        if (ip, port) != (self.ip, self.port):
            self.nat = True # Assume peer is NAT'd
            if is_valid_ip(ip):
                self.num_natcheck = 0
            else: # Don't natcheck invalid addresses
                self.num_natcheck = INFINITY
        # Mark any failed peers
        for x in params.get('failed', []):
            self.failed(x)
        # Update stats
        ihash = params.get('info_hash')
        rl = params.get('relayed')
        if rl is not None:
            self.relayed_total = rl
        # Remove any stopped torrents
        if params.get('event') == 'stopped':
            if self.infohashes.has_key(ihash):
                del self.infohashes[ihash]
        else:
            # Update upload/download/left
            if self.infohashes.has_key(ihash):
                p_ul, p_dl, p_left = self.infohashes[ihash]
            else:
                p_ul, p_dl, p_left = (0,0,0)
            ul = params.get('uploaded', p_ul)
            dl = params.get('downloaded', p_dl)
            left = params.get('left', p_left)
            self.infohashes[ihash] = (int(ul), int(dl), int(left))

    def needs_natcheck(self, max_nc_attempts=3):
        return self.nat and self.num_natcheck < max_nc_attempts

    def add_neighbor(self, peerid, nid, ip, port):
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

    def rm_neighbor(self, peerid):
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
            self.rm_neighbor(self.id_map[nid])

    def get_session_id(self):
        return self.sessionid

    def get_avail_nids(self):
        """
        @return: set object containing NIDs in range 0 -> 254 which are not in use
        @rtype: set of ints
        """
        used = set(self.id_map.keys())
        return SimPeer.ID_RANGE.copy() - used

    def get_nid(self, peerid, default=None):
        """ Return the relative ID associated with peerid
            return default if the vertices aren't connected """
        return self.neighbors.get(peerid, {}).get('nid', default)

    def get_nbrs(self):
        return self.neighbors.keys()

    def get_torrents(self):
        return self.infohashes.keys()

    def num_torrents(self):
        return len(self.infohashes)

    def __str__(self):
        return self.name


class NetworkModel:
    """Simple Graph model of network"""
    def __init__(self, config):
        self.names = {}    # {peerid : SimPeer object}
        self.complete = {} # {infohash : set([peerid,...,])}
        self.incomplete = {} # {infohash : set([peerid,...,])}
        self.reachable = set() # set(peerid,...)
        self.tracked = set() # set(infohash,...)
        self.config = config

    def get(self, peerid):
        """
        @type peerid: string
        @return: SimPeer object corresponding to name or None if nonexistant
        @rtype: SimPeer
        """
        return self.names.get(peerid, None)

    def get_simpeers(self):
        return self.names.values()

    def get_infohashes(self):
        return self.tracked.copy()

    def swarm(self, infohash):
        return set.union(self.leechers(infohash),
                         self.seeders(infohash))

    def leechers(self, infohash):
        return self.incomplete.get(infohash, set()).copy()

    def seeders(self, infohash):
        return self.complete.get(infohash, set()).copy()

    def init_peer(self, peerid, pubkey, ip, port, sid, num_neighbors=4):
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

    def natcheck_cb(self, peerid, result):
        """
        Called by NatCheck after testing a peer.
        @param result: Result of NatCheck. True on successful connection
                       False if the peer is unreachable.
        @type result: boolean
        """
        record = self.get(peerid)
        if record is not None:
            record.nat = not result
            record.num_natcheck += 1
            if not (record.nat or peerid in self.reachable):
                # Peer is not NAT'd and we don't have them in the reachable list
                self.reachable.add(peerid)

    def update_peer(self, peerid, ip, params):
        simpeer = self.get(peerid)
        simpeer.update(ip, params)

        infohash = params.get('info_hash')
        complete = (int(params.get('left')) == 0)
        if params.get('event') == 'stopped':
            self.remove_from_swarm(peerid, infohash)
            if simpeer.num_torrents() == 0:
                self.disconnect(peerid)
        else:
            if not (simpeer.nat or peerid in self.reachable):
                # Peer is not NAT'd and we don't have them in the reachable list
                self.reachable.add(peerid)
            if simpeer.nbrs_needed > 0:
                self.rand_connect(peerid, simpeer.nbrs_needed)
            self.update_swarm(peerid, infohash, complete)


    def update_swarm(self, peerid, infohash, complete):
        if infohash not in self.tracked:
            self.tracked.add(infohash)
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
        leechset = self.incomplete.get(infohash)
        swarm_size = 0
        # Remove from seeders list
        if seedset and (peerid in seedset):
            seedset.remove(peerid)
            swarm_size += len(seedset)
            if len(seedset) == 0:
                del self.complete[infohash]
        # Remove from leechers list
        if leechset and (peerid in leechset):
            leechset.remove(peerid)
            swarm_size += len(leechset)
            if len(leechset) == 0:
                del self.incomplete[infohash]
        if (swarm_size == 0) and (infohash in self.tracked):
            self.tracked.remove(infohash)

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
        nidsP1 = p1.get_avail_nids()
        nidsP2 = p2.get_avail_nids()
        l = list(nidsP1.intersection(nidsP2))
        if len(l):
            nid = random.choice(l)
            p1.add_neighbor(v2, nid, p2.ip, p2.port)
            p2.add_neighbor(v1, nid, p1.ip, p2.port)
        else:
            raise RuntimeError("No available NeighborIDs. It's possible the \
                                network is being attacked.")

    def rand_connect(self, peerid, numpeers):
        """
        Assign 'numpeers' many randomly selected neighbors to
        peer with id == peerid
        """
        peer = self.get(peerid)
        candidates = random.sample(self.reachable, len(self.reachable))
        for opid in candidates:
            if numpeers <= 0:
                break
            # Don't connect peers to: Themselves, peers who
            # they're already neighbors with, peers they've failed
            # to make connections to in the past.
            if  opid == peerid or \
                opid in peer.neighbors.keys() or \
                opid in peer.failed_nbrs:
                    continue
            if not self.config.get('allow_close_neighbors') and \
                peer.ip == self.get(opid).ip:
                    continue
            self.connect(peerid, opid)
            numpeers -= 1

    def disconnect(self, peerid):
        """
        Removes designated peer from network
        @param peerid: Peer ID (str) of peer to be removed
        """
        simpeer = self.get(peerid)
        if simpeer is None:
            return
        # Remove disconnecting peer from any neighbor lists it's a part of
        for neighborOf in self.names[peerid].get_nbrs():
            if self.names.has_key(neighborOf):
                self.names[neighborOf].rm_neighbor(peerid)
        # Remove disconnecting peer from all swarms
        for infohash in simpeer.get_torrents():
            self.remove_from_swarm(peerid, infohash)
        # Delete the disconnecting peer's SimPeer object
        del self.names[peerid]

    def nbrs_of(self, peerid):
        if not self.get(peerid):
            return []
        return self.get(peerid).get_nbrs()

    def get_paths(self, src, infohash, how_many=5, is_seed=False, minhops=3):
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
            if destination is None:
                continue
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
                t = reduce(set.union, [set(self.nbrs_of(n)) for n in lvls[i-1]])
                lvls.append(t)
            isect = snbrs.intersection(lvls[-1])
            # Keep growing until we find an snbr or exhaust the searchable space
            while isect == set([]) and len(lvls) < self.config['max_path_len']:
                t = reduce(set.union, [set(self.nbrs_of(n)) for n in lvls[i-1]])
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
                nbrsOfLast = set(self.nbrs_of(path[-1]))
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

    def get_tracking_codes(self, source, infohash, count=3):
        seedp = source in self.complete.get(infohash,[])
        paths = self.get_paths(source, infohash, \
                                    is_seed=seedp, minhops=3)
        tcs = []
        if len(paths) > count:
            random.shuffle(paths)
        for p in paths[:min(count, len(paths))]:
            aes = Anomos.Crypto.AESKey()
            kiv = ''.join((aes.key, aes.iv))
            m = self.encrypt_tc(p, \
                            plaintext=''.join((infohash,kiv)))
            tcs.append([kiv, m])
        return tcs

    def encrypt_tc(self, pathByNames, prevNbr=None, plaintext='#', msglen=4096):
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
        sid = peerobj.get_session_id()
        if prevNbr:
            nid = str(prevNbr.get_nid(peername))
            tocrypt = chr(0) + sid + nid + message
            recvMsgLen = len(sid + nid) + 1 # The 'message' data is for the
                                            # next recipient, not this one.
            message = peerobj.pubkey.encrypt(tocrypt, recvMsgLen)
        else:
            tocrypt = chr(1) + sid + message
            message = peerobj.pubkey.encrypt(tocrypt, len(tocrypt))
        prevNbr = peerobj
        if len(pathByNames) > 0:
            return self.encrypt_tc(pathByNames, prevNbr, message, msglen)
        elif len(message) < msglen:
            # Pad to msglen
            return message + Anomos.Crypto.get_rand(msglen-len(message))
        else:
            # XXX: Disallow messages longer than msglen?
            return message

###########
##TESTING##
###########
def tc_test(numnodes=1000, numedges=10000):
    import math
    import time
    from binascii import b2a_hex
    Anomos.Crypto.init('./')
    G_ips = ['.'.join([str(i)]*4) for i in range(numnodes)]
    graph = NetworkModel()
    pk = Anomos.Crypto.RSAKeyPair('WampWamp') # All use same RSA key for testing.
    for peerid in G_ips:
        graph.init_peer(peerid, pk.pub_bin(), (peerid, 8080), int(math.log(1000)//math.log(4)))
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
    tc_test(**options)
