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

# Originally written by Bram Cohen. Modified by John Schanck and Rich Jones

from Anomos.Connection import AnomosFwdLink
from Anomos import BTFailure

class EndPoint(AnomosEndPointProtocol):
    def __init__(self, make_upload, downloader, choker, numpieces, schedulefunc,
                 context):
        self.make_upload = make_upload
        self.downloader = downloader
        self.choker = choker
        self.numpieces = numpieces
        self.schedulefunc = schedulefunc

        self.ratelimiter = context._ratelimiter
        self.rawserver = context._rawserver
        self.config = context.config
        self.download_id = context.infohash
        self.cert = context.certificate
        self.manager = context.neighbors
        self.context = context

        self.connections = {} # {socket : Connection}
        self.complete_connections = set()
        self.incomplete = {}
        self.banned = set()
        self.everinc = False

        self.sessionid = context.sessionid

#### NOTE: Here be obsolete code, keep it until things are working again ####
    #def start_connection(self, tc, aeskey):
    #    if len(self.connections) >= self.config['max_initiate']:
    #        return
    #    tcdata = self.tcreader.parseTC(tc)
    #    nid = tcdata.neighborID
    #    sid = tcdata.sessionID
    #    if sid != self.sessionid:
    #        #TODO: Log an error
    #        return
    #    nextTC = tcdata.nextLayer
    #    if self.neighbors.is_incomplete(nid):
    #        self.neighbors.schedule_tc(self.send_tc, nid, nextTC, aeskey)
    #    else:
    #        self.send_tc(nid, nextTC, aeskey)

    #def send_tc(self, nid, tc, aeskey):
    #    loc = self.neighbors.get_location(nid)
    #    if loc is None:
    #        return
    #    if self.incomplete.has_key(loc):
    #        #print "Already waiting for TC response from %s" % str(loc)
    #        #print "  Retrying in 30 seconds"
    #        def retry():
    #            self.send_tc(nid,tc,aeskey)
    #        #TODO: Verify this 30 second rate or make it configurable
    #        self.rawserver.add_task(retry, 30)
    #    else:
    #        self.incomplete[loc] = (nid, tc, aeskey)
    #        ssls = self.neighbors.get_ssl_session(nid)
    #        self.rawserver.start_ssl_connection(loc, handler=self, session=ssls)

    #def sock_success(self, sock, loc):
    #    if self.connections.has_key(sock):
    #        return
    #    if not self.incomplete.has_key(loc):
    #        return
    #    id, tc, aeskey = self.incomplete.pop(loc)
    #    print "Sending TC to", hex(ord(id)), "at", loc
    #    # Make the local connection for receiving.
    #    con = AnomosFwdLink(self, sock, id, established=True, e2e=aeskey)
    #    self.connections[sock] = con
    #    con.send_tracking_code(tc)

    #def sock_fail(self, loc, err=None):
    #    if self.incomplete.has_key(loc):
    #        del self.incomplete[loc]
    #    #TODO: Do something with the error msg

    def connection_completed(self, c):
        self.complete_connections.add(c)
        c.upload = self.make_upload(c)
        c.download = self.downloader.make_download(c)
        self.choker.connection_made(c)

    def ever_got_incoming(self):
        return self.everinc

#### NOTE: Here be obsolete code, keep it until things are working again ####
    #def how_many_connections(self):
    #    return len(self.complete_connections)

    #def close_connections(self):
    #    for c in self.connections.values():
    #        if not c.closed:
    #            c.close()

    #def connection_closed(self, con):
    #    # Called by Connecter, which checks that the connection is complete
    #    # prior to call
    #    self.connections.pop(con.connection)
    #    self.complete_connections.discard(con)
    #    self.choker.connection_lost(con)
    #    con.download.disconnected()
    #    con.upload = None
    #    con.close()

    #def singleport_connection(self, listener, con):
    #    #It's one of our neighbors so no need to check if the con is banned
    #    #if con.ip in self.banned:
    #    #    return
    #    m = self.config['max_allow_in']
    #    if m and len(self.connections) >= m:
    #        return
    #    self.connections[con.connection] = con
    #    del listener.connections[con.connection]
    #    con.owner = self
    #    con.connection.context = self.context

    #def ban(self, ip):
    #    self.banned.add(ip)

