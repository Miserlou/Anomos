# SingleportListener.py
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

# Originally written by Bram Cohen. Modified by John Schanck and Rich Jones

from Anomos.Connection import AnomosRevLink
from Anomos.EndPoint import EndPoint
from Anomos import BTFailure

class SingleportListener(object):
    '''SingleportListener gets events from the server sockets (of which there
        is one per torrent), initializes connection objects, and determines
        what to do with the connection once some data has been read.
    '''
    def __init__(self, rawserver, config, neighbors, sessionid):
        self.rawserver = rawserver
        self.config = config
        self.port = 0
        self.ports = {}
        self.torrents = {}
        self.relayers = []
        self.neighbors = neighbors
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

    #def xchg_owner_with_endpoint(self, conn, infohash):
    #    if infohash not in self.torrents:
    #        return
    #    self.torrents[infohash].singleport_connection(self, conn)

    def check_session_id(self, sid):
        return sid == self.sessionid

    #def xchg_owner_with_relayer(self, conn, neighborid):
    #    conn.owner = Relayer(self.rawserver, self.neighbors, conn, neighborid,
    #                            self.config)
    #    conn.is_relay = True
    #    self.relayers.append(conn.owner)
    #    return conn.owner

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

    #def xchg_owner_with_nbr_manager(self, conn):
    #    del self.connections[conn.connection]
    #    conn.owner = self.neighbors
    #    self.neighbors.connections[conn.connection] = conn

    def external_connection_made(self, socket):
        """
        Connection came in.
        @param socket: SingleSocket
        """
        con = AnomosRevLink(self.manager, socket)
        self.connections[socket] = con

    def replace_connection(self):
        pass
