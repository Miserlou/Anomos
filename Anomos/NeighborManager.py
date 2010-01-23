# NeighborManager.py
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

# Written by John Schanck and Rich Jones

import Anomos.Crypto

from Anomos.AnomosNeighborInitializer import AnomosNeighborInitializer
from Anomos.NeighborLink import NeighborLink
from Anomos.P2PConnection import P2PConnection
from Anomos.Protocol.TCReader import TCReader
from Anomos.Protocol import NAT_CHECK_ID
from Anomos.Measure import Measure
from Anomos import BTFailure, LOG as log

class NeighborManager(object):
    '''NeighborManager keeps track of the neighbors a peer is connected to
    and which tracker those neighbors are on.
    '''
    def __init__(self, config, certificate, ssl_ctx, sessionid, schedule, ratelimiter):
        self.config = config
        self.certificate = certificate
        self.ssl_ctx = ssl_ctx
        self.sessionid = sessionid
        self.schedule = schedule
        self.ratelimiter = ratelimiter
        self.neighbors = {}
        self.relay_measure = Measure(self.config['max_rate_period'])
        self.relay_count = 0
        self.incomplete = {}
        self.torrents = {}

        self.waiting_tcs = {}

        self.failedPeers = []

    ## Got new neighbor list from the tracker ##
    def update_neighbor_list(self, list):
        freshids = dict([(i[2],(i[0],i[1])) for i in list]) #{nid : (ip, port)}
        # Remove neighbors not found in freshids
        for id in self.neighbors.keys():
            if not freshids.has_key(id):
                self.rm_neighbor(id)
        # Start connections with the new neighbors
        for id, loc in freshids.iteritems():
            if not self.neighbors.has_key(id) and id not in self.failedPeers:
                self.start_connection(id, loc)
        # Remove the failedPeers that didn't come back as fresh IDs (presumably
        # the tracker has removed them from our potential neighbor list)
        self.failedPeers = [id for id in freshids if id in self.failedPeers]

    ## Start a new neighbor connection ##
    def start_connection(self, id, loc):
        ''' Start a new SSL connection to the peer at loc and 
            assign them the NeighborID id
            @param loc: (IP, Port)
            @param id: The neighbor ID to assign to this connection
            @type loc: tuple
            @type id: int '''
        if self.has_neighbor(id) or self.incomplete.has_key(id):
            # Already had neighbor by that id or at that location
            log.warning('NID collision')
            # To be safe, kill connection with the neighbor we already
            # had with the requested ID and add ID to the failed list
            self.rm_neighbor(id)
            self.failedPeers.append(id)
            return
        if self.config['one_connection_per_ip'] and self.has_ip(loc[0]):
            log.warning('Got duplicate IP address in neighbor list. ' + \
                        'Multiple connections to the same IP are disabled' + \
                        'in your config.')
            return
        self.incomplete[id] = loc
        conn = P2PConnection(addr=loc,
                             ssl_ctx=self.ssl_ctx,
                             connect_cb=self.socket_cb,
                             schedule=self.schedule)

    def socket_cb(self, sock):
        if sock.connected:
            log.info(sock.addr)
            for id,v in self.incomplete.iteritems():
                if v == sock.addr:
                    break
            else:
                return #loc wasn't found
            AnomosNeighborInitializer(self, sock, id)
        else:
            #Remove nid,loc pair from incomplete
            for k,v in self.incomplete.items():
                if v == sock.addr:
                    self.rm_neighbor(k)
            log.info("Failed to open connection to %s\n" %
                                 str(sock.addr))

    def failed_connections(self):
        return self.failedPeers

    ## AnomosNeighborInitializer got a full handshake ##
    def add_neighbor(self, socket, id):
        log.info("Adding Neighbor: \\x%02x" % ord(id))
        self.neighbors[id] = NeighborLink(self, socket, id, \
                self.config, self.ratelimiter)

    def rm_neighbor(self, nid):
        if self.incomplete.has_key(nid):
            self.incomplete.pop(nid)
        if self.has_neighbor(nid):
            self.neighbors.pop(nid)
        if nid is not None:
            self.failedPeers.append(nid)

    #TODO: implement banning
    def ban(self, ip):
        pass

    def has_neighbor(self, nid):
        return self.neighbors.has_key(nid)

    def check_session_id(self, sid):
        return sid == self.sessionid

    def has_ip(self, ip):
        return ip in [n.socket.addr[0] for n in self.neighbors.values()] \
                or ip in [x for x,y in self.incomplete.values()]

    def is_incomplete(self, nid):
        return self.incomplete.has_key(nid)

    def count(self, tracker=None):
        return len(self.neighbors)

    def connection_completed(self, socket, id):
        '''Called by AnomosNeighborInitializer'''
        if self.incomplete.has_key(id):
            del self.incomplete[id]
        if id == NAT_CHECK_ID:
            log.info("NAT check ok.")
            return
        self.add_neighbor(socket, id)
        tasks = self.waiting_tcs.get(id)
        if tasks is None:
            return
        for task in tasks:
            #TODO: Would a minimum wait between these tasks aid anonymity?
            self.schedule(0, task)
        del self.waiting_tcs[id]

    def lost_neighbor(self, id):
        self.rm_neighbor(id)

    def initializer_failed(self, id):
        '''Connection closed before finishing initialization'''
        self.rm_neighbor(id)

    def start_circuit(self, tc, infohash, aeskey):
        '''Called from Rerequester to initialize new circuits we've
        just gotten TCs for from the Tracker'''
        if self.count_streams() >= self.config['max_initiate']:
            log.warning("Not starting circuit -- Stream count exceeds maximum")
            return

        tcreader = TCReader(self.certificate)
        try:
            tcdata = tcreader.parseTC(tc)
        except Anomos.Crypto.CryptoError, e:
            log.error("Decryption Error: %s" % str(e))
            return
        nid = tcdata.neighborID
        sid = tcdata.sessionID
        torrent = self.get_torrent(infohash)
        nextTC = tcdata.nextLayer
        if sid != self.sessionid:
            log.error("Not starting circuit -- SessionID mismatch!")
        elif torrent is None:
            log.error("Not starting circuit -- Unknown torrent")
        elif nid in self.incomplete:
            log.info("Postponing circuit until neighbor \\x%02x completes " % ord(nid))
            self.schedule_tc(nid, infohash, aeskey, nextTC)
        elif nid not in self.neighbors:
            log.error("Not starting circuit -- NID \\x%02x is not assigned" % ord(nid))
        else:
            self.neighbors[nid].start_endpoint_stream(torrent, aeskey, data=nextTC)

    def schedule_tc(self, nid, infohash, aeskey, nextTC):
        '''Sometimes a tracking code is received before a neighbor is fully
        initialized. In those cases we schedule the TC to be sent once we get
        a "connection_completed" from the neighbor.'''
        def sendtc():
            if self.neighbors.has_key(nid): # Could have been deleted during wait
                torrent = self.get_torrent(infohash)
                self.neighbors[nid].start_endpoint_stream(torrent, aeskey, nextTC)
        self.waiting_tcs.setdefault(nid,[])
        self.waiting_tcs[nid].append(sendtc)

    ## Torrent Management ##
    def add_torrent(self, infohash, torrent):
        if infohash in self.torrents:
            raise BTFailure("Can't start two separate instances of the same "
                            "torrent")
        self.torrents[infohash] = torrent

    def remove_torrent(self, infohash):
        self.torrents[infohash].close_all_streams()
        del self.torrents[infohash]
        if len(self.torrents) == 0:
            # Close all streams when the last torrent is removed
            for n in self.neighbors.values():
                n.socket.handle_close()

    def get_torrent(self, infohash):
        return self.torrents.get(infohash, None)

    def count_streams(self):
        return sum(len(x.streams) for x in self.neighbors.itervalues())

    ## Relay Management ##
    def make_relay(self, nid, data, orelay):
        if self.neighbors.has_key(nid):
            self.relay_count += 1
            r = self.neighbors[nid].start_relay_stream(nid, data, orelay)
            orelay.set_other_relay(r)
        elif self.incomplete.has_key(nid):
            def relay_tc():
                self.relay_count += 1
                r = self.neighbors[nid].start_relay_stream(nid,data,orelay)
                orelay.set_other_relay(r)
            self.waiting_tcs.setdefault(nid, [])
            self.waiting_tcs[nid].append(relay_tc)

    def dec_relay_count(self):
        self.relay_count -= 1

    def get_relay_count(self):
        return self.relay_count

    def get_relay_stats(self):
        rate = self.relay_measure.get_rate()
        count = self.relay_count
        sent = self.relay_measure.get_total()
        return {'relayRate' : rate, 'relayCount' : count, 'relaySent' : sent}
