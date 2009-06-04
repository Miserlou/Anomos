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

import Anomos.crypto as crypto
from Anomos.Connecter import AnomosFwdLink, AnomosRevLink
from Anomos.Relayer import Relayer
from Anomos import BTFailure

class EndPoint(object):
    ''' Encoder objects exist at the torrent level. A client has an encoder
        object for each torrent they're downloading/seeding. The primary
        purpose of the encoder object is to initialize new connections by
        sending tracking codes and creating the uploader/downloader objects.
    '''
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
        self.neighbors = context.neighbors
        self.context = context

        self.connections = {} # {socket : Connection}
        self.complete_connections = set()
        self.incomplete = {}
        self.banned = set()
        self.everinc = False

        self.sessionid = context.sessionid

    def start_connection(self, tc, aeskey):
        if len(self.connections) >= self.config['max_initiate']:
            return
        nid = None
        tclen = len(tc)
        try:
            #TODO: Check the TC length
            nidsid, tc = self.cert.decrypt(tc, True)
            nid = nidsid[0]
            sid = nidsid[1:]
            if sid != self.sessionid:
                return
        except ValueError, e:
            print "VALUE ERR: ", e
            return #Tampered With
        except Exception, e:
            print "OTHER EXCEPTION", e
            return #Probably a decryption error
        else:
            # Repad to original length
            tc = tc + crypto.getRand(tclen-len(tc))
        if self.neighbors.is_incomplete(nid):
            self.neighbors.schedule_tc(self.send_tc, nid, tc, aeskey)
        else:
            self.send_tc(nid, tc, aeskey)

    def send_tc(self, nid, tc, aeskey):
        loc = self.neighbors.get_location(nid)
        if loc is None:
            return
        if self.incomplete.has_key(loc):
            #print "Already waiting for TC response from %s" % str(loc)
            #print "  Retrying in 30 seconds"
            def retry():
                self.send_tc(nid,tc,aeskey)
            #TODO: Verify this 30 second rate or make it configurable
            self.rawserver.add_task(retry, 30)
        else:
            self.incomplete[loc] = (nid, tc, aeskey)
            ssls = self.neighbors.get_ssl_session(nid)
            self.rawserver.start_ssl_connection(loc, handler=self, session=ssls)

    def sock_success(self, sock, loc):
        if self.connections.has_key(sock):
            return
        if not self.incomplete.has_key(loc):
            return
        id, tc, aeskey = self.incomplete.pop(loc)
        print "Sending TC to", hex(ord(id)), "at", loc
        # Make the local connection for receiving.
        con = AnomosFwdLink(self, sock, id, established=True, e2e=aeskey)
        self.connections[sock] = con
        con.send_tracking_code(tc)

    def sock_fail(self, loc, err=None):
        if self.incomplete.has_key(loc):
            del self.incomplete[loc]
        #TODO: Do something with the error msg

    def connection_completed(self, c):
        self.complete_connections.add(c)
        c.upload = self.make_upload(c)
        c.download = self.downloader.make_download(c)
        self.choker.connection_made(c)

    def ever_got_incoming(self):
        return self.everinc

    def how_many_connections(self):
        return len(self.complete_connections)

    def close_connections(self):
        for c in self.connections.values():
            if not c.closed:
                c.close()

    def connection_closed(self, con):
        # Called by Connecter, which checks that the connection is complete
        # prior to call
        self.connections.pop(con.connection)
        self.complete_connections.discard(con)
        self.choker.connection_lost(con)
        con.download.disconnected()
        con.upload = None
        con.close()

    def singleport_connection(self, listener, con):
        #It's one of our neighbors so no need to check if the con is banned
        #if con.ip in self.banned:
        #    return
        m = self.config['max_allow_in']
        if m and len(self.connections) >= m:
            return
        self.connections[con.connection] = con
        del listener.connections[con.connection]
        con.owner = self
        con.connection.context = self.context

    def ban(self, ip):
        self.banned.add(ip)


class SingleportListener(object):
    '''SingleportListener gets events from the server sockets (of which there
        is one per torrent), initializes connection objects, and determines
        what to do with the connection once some data has been read.
    '''
    def __init__(self, rawserver, config, neighbors, certificate, sessionid):
        self.rawserver = rawserver
        self.config = config
        self.port = 0
        self.ports = {}
        self.torrents = {}
        self.relayers = []
        self.connections = {}
        self.neighbors = neighbors
        self.certificate = certificate
        self.sessionid = sessionid
        self.download_id = None

    def _check_close(self, port):
        if not port or self.port == port or self.ports[port][1] > 0:
            return
        serversocket = self.ports[port][0]
        self.rawserver.stop_listening(serversocket)
        serversocket.close()
        del self.ports[port]

    def open_port(self, port, config):
        if port in self.ports:
            self.port = port
            return
        serversocket = self.rawserver.create_ssl_serversocket(port, config['bind'], True, config['peer_socket_tos'])
        self.rawserver.start_listening(serversocket, self)
        oldport = self.port
        self.port = port
        self.neighbors.port = port
        self.ports[port] = [serversocket, 0]
        self._check_close(oldport)

    def get_port(self):
        if self.port:
            self.ports[self.port][1] += 1
        return self.port

    def release_port(self, port):
        self.ports[port][1] -= 1
        self._check_close(port)

    def close_sockets(self):
        for serversocket, _ in self.ports.itervalues():
            self.rawserver.stop_listening(serversocket)
            serversocket.close()

    def add_torrent(self, infohash, endpoint):
        if infohash in self.torrents:
            raise BTFailure("Can't start two separate instances of the same "
                            "torrent")
        self.torrents[infohash] = endpoint

    def remove_torrent(self, infohash):
        del self.torrents[infohash]

    def xchg_owner_with_endpoint(self, conn, infohash):
        if infohash not in self.torrents:
            return
        self.torrents[infohash].singleport_connection(self, conn)

    def check_session_id(self, sid):
        return sid == self.sessionid

    def xchg_owner_with_relayer(self, conn, neighborid):
        conn.owner = Relayer(self.rawserver, self.neighbors, conn, neighborid,
                                self.config)
        conn.is_relay = True
        self.relayers.append(conn.owner)
        return conn.owner

    def remove_relayer(self, relayer):
        self.relayers.remove(relayer)

    def get_relay_size(self):
        return len(self.relayers)

    def get_relay_rate(self):
        rate = 0
        for r in self.relayers:
            rate  += r.get_rate()
        return rate

    def get_relay_sent(self):
        sent = 0
        for r in self.relayers:
            sent  += r.get_sent()
        return sent

    def xchg_owner_with_nbr_manager(self, conn):
        del self.connections[conn.connection]
        conn.owner = self.neighbors
        self.neighbors.connections[conn.connection] = conn

    def external_connection_made(self, socket):
        """
        Connection came in.
        @param socket: SingleSocket
        """
        con = AnomosRevLink(self, socket)
        self.connections[socket] = con

    def replace_connection(self):
        pass
