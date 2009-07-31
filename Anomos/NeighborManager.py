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

from Anomos.Connection import AnomosNeighborInitializer
from Anomos.NeighborLink import NeighborLink
from Anomos.Protocol.TCReader import TCReader
from Anomos import BTFailure, INFO, WARNING, ERROR, CRITICAL

class NeighborManager:
    '''NeighborManager keeps track of the neighbors a peer is connected to
    and which tracker those neighbors are on.
    '''
    def __init__(self, rawserver, config, certificate, sessionid, logfunc):
        self.rawserver = rawserver
        self.config = config
        self.certificate = certificate
        self.sessionid = sessionid
        self.logfunc = logfunc
        self.neighbors = {}
        self.relayers = []
        self.incomplete = {}
        self.torrents = {}

        self.port = None
        self.waiting_tcs = {}

        self.failedPeers = []

    ## Got new neighbor list from the tracker ##
    def update_neighbor_list(self, list):
        freshids = dict([(i[2],(i[0],i[1])) for i in list])
        # Remove neighbors not found in freshids
        for id in self.neighbors.keys():
            if not freshids.has_key(id):
                self.rm_neighbor(id)
        # Start connections with the new neighbors
        for id, loc in freshids.iteritems():
            if not self.neighbors.has_key(id) and id not in self.failedPeers:
                self.start_connection(loc, id)
        # Remove the failedPeers that didn't come back as fresh IDs (presumably
        # the tracker has removed them from our potential neighbor list)
        self.failedPeers = [id for id in freshids if id in self.failedPeers]

    ## Start a new neighbor connection ##
    def start_connection(self, loc, id):
        """
        @param loc: (IP, Port)
        @param id: The neighbor ID to assign to this connection
        @type loc: tuple
        @type id: int
        """
        #TODO: block multiple connections to the same location
        if self.has_neighbor(id) or \
                (self.incomplete.get(id) == loc): #or \
            #   self.has_loc(loc):
            #Already had neighbor by that id or at that location
            #TODO: Resolve conflict
            return
        self.incomplete[id] = loc
        self.rawserver.start_ssl_connection(loc, handler=self)

    ## Socket failed to open ##
    def sock_fail(self, loc, err=None):
        #Remove nid,loc pair from incomplete
        for k,v in self.incomplete.items():
            if v == loc:
                self.failedPeers.append(k)
                del self.incomplete[k]
        #TODO: Do something with the error msg.

    def failed_connections(self):
        return self.failedPeers

    ## Socket opened successfully ##
    def sock_success(self, sock, loc):
        """
        @param sock: SingleSocket object for the newly created socket
        """
        for id,v in self.incomplete.iteritems():
            if v == loc:
                break
        else: return #loc wasn't found
        # Exchange the header and hold the connection open
        AnomosNeighborInitializer(self, sock, id, started_locally=True)

    ## AnomosNeighborInitializer got a full handshake ##
    def add_neighbor(self, socket, id):
        self.logfunc(INFO, "Adding Neighbor: \\x%02x" % ord(id))
        self.neighbors[id] = NeighborLink(self, socket, id, logfunc=self.logfunc)

    def rm_neighbor(self, nid):
        if self.incomplete.has_key(nid):
            self.incomplete.pop(nid)
        if self.has_neighbor(nid):
            self.neighbors.pop(nid)

    #TODO: implement banning
    def ban(self, ip):
        pass

    def has_neighbor(self, nid):
        return self.neighbors.has_key(nid)

    def check_session_id(self, sid):
        return sid == self.sessionid

    def has_loc(self, loc):
        return loc in [n.loc for n in self.neighbors.values()]

    def is_incomplete(self, nid):
        return self.incomplete.has_key(nid)

    def count(self, tracker=None):
        return len(self.neighbors)

    def connection_completed(self, socket, id):
        if self.incomplete.has_key(id):
            del self.incomplete[id]
        self.add_neighbor(socket, id)
        for task in self.waiting_tcs.get(id, []):
            #TODO: is it still necessary to queue these with RawServer?
            self.rawserver.add_task(task, 0) #TODO: add a min-wait time

    def connection_closed(self, con):
        self.rm_neighbor(con.id)

    def start_circuit(self, tc, infohash, aeskey):
        '''Called from Rerequester to initialize new circuits we've
        just gotten TCs for from the Tracker'''
        if self.count_streams() >= self.config['max_initiate']:
            self.logfunc(WARNING, "Not starting circuit -- Stream count exceeds maximum")
            return
        tcreader = TCReader(self.certificate)
        tcdata = tcreader.parseTC(tc)
        nid = tcdata.neighborID
        sid = tcdata.sessionID
        torrent = self.get_torrent(infohash)
        nextTC = tcdata.nextLayer
        if sid != self.sessionid:
            self.logfunc(ERROR, "Not starting circuit -- SessionID mismatch!")
            return
        if torrent is None:
            self.logfunc(ERROR, "Not starting circuit -- Unknown torrent")
            return
        if nid in self.incomplete:
            self.logfunc(INFO, "Postponing circuit until neighbor \\x%02x completes " % ord(nid))
            self.schedule_tc(nid, infohash, aeskey, nextTC)
            return
        if nid not in self.neighbors:
            self.logfunc(ERROR, "Not starting circuit -- NID \\x%02x is not assigned" % ord(nid))
            return
        self.neighbors[nid].start_endpoint_stream(torrent, aeskey, data=nextTC)

    def schedule_tc(self, nid, infohash, aeskey, nextTC):
        '''Sometimes a tracking code is received before a neighbor is fully
        initialized. In those cases we schedule the TC to be sent once we get
        a "connection_completed" from the neighbor.'''
        def sendtc():
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
        del self.torrents[infohash]

    def get_torrent(self, infohash):
        return self.torrents.get(infohash, None)

    def count_streams(self):
        return sum(len(x.streams)-1 for x in self.neighbors.itervalues())

    ## Relay Management ##
    def make_relay(self, nid, data, orelay):
        if self.neighbors.has_key(nid):
            self.relayers.append(orelay)
            return self.neighbors[nid].start_relay_stream(nid, data, orelay)
        elif self.incomplete.has_key(nid):
            def relay_tc():
                self.relayers.append(orelay)
                self.neighbors[nid].start_relay_stream(nid,data,orelay)
            self.waiting_tcs.set_default(nid, [])
            self.waiting_tcs[nid].append(relay_tc)

    def get_relay_size(self):
        return len(self.relayers)

    def get_relay_rate(self):
        return sum(r.get_rate() for r in self.relayers)

    def get_relay_sent(self):
        return sum(r.get_sent() for r in self.relayers)
