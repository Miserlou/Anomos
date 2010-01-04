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

from Anomos.AnomosNeighborInitializer import AnomosNeighborInitializer
from Anomos import BTFailure

class SingleportListener(object):
    '''SingleportListener gets events from the server sockets (of which there
        is one per **tracker**), initializes connection objects, and determines
        what to do with the connection once some data has been read.
    '''
    def __init__(self, rawserver, config):
        self.rawserver = rawserver
        self.config = config
        self.port = 0
        self.ports = {}
        self.managers = {}
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
        # This #
        serversocket = self.rawserver.create_ssl_serversocket(port, config['bind'], True, config['peer_socket_tos'])
        self.rawserver.start_listening(serversocket, self)
        # Is to be replaced by
        # P2PServer(addr, port, context, self)
        oldport = self.port
        self.port = port
        self.ports[port] = [serversocket, 0]
        self._check_close(oldport)

    def get_port(self, nbrmgr):
        if self.port:
            self.ports[self.port][1] += 1
        self.managers[self.port] = nbrmgr
        return self.port

    def release_port(self, port):
        self.ports[port][1] -= 1
        self._check_close(port)

    def close_sockets(self):
        for serversocket, _ in self.ports.itervalues():
            self.rawserver.stop_listening(serversocket)
            serversocket.close()

    def get_neighbor_manager(self, socket):
        return self.managers[socket.port]

    #def external_connection_made(self, socket):
    #    """
    #    Connection came in.
    #    """
    #    AnomosNeighborInitializer(self.managers[socket.port], socket)

    def replace_connection(self):
        pass
