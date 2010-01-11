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

from Anomos import BTFailure
from Anomos.AnomosNeighborInitializer import AnomosNeighborInitializer
from Anomos.P2PServer import P2PServer

from socket import error as socketerror

class SingleportListener(object):
    '''SingleportListener gets events from the server sockets (of which there
        is one per **tracker**), initializes connection objects, and determines
        what to do with the connection once some data has been read.
    '''
    def __init__(self, config, ssl_ctx):
        self.config = config
        self.port = 0
        self.ports = {}
        self.managers = {}
        self.ssl_ctx = ssl_ctx

    def _check_close(self, port):
        if not port or self.port == port or self.ports[port][1] > 0:
            return
        serversocket = self.ports[port][0]
        serversocket.close()
        del self.ports[port]

    def find_port(self, listen_fail_ok=True):
        e = 'maxport less than minport - no ports to check'
        self.config['minport'] = max(1, self.config['minport'])
        for port in xrange(self.config['minport'], self.config['maxport'] + 1):
            try:
                self.open_port(port)
                break
            except socketerror, e:
                pass
        else:
            if not listen_fail_ok:
                raise BTFailure, "Couldn't open a listening port: " + str(e)
            log.critical("Could not open a listening port: " +
                           str(e) + ". Check your port range settings.")

    def open_port(self, port):
        if port in self.ports:
            self.port = port
            return
        serversocket = P2PServer(self.config['bind'], port, self.ssl_ctx)
        oldport = self.port
        self.port = port
        self.ports[port] = [serversocket, 0]
        self._check_close(oldport)

    def get_port(self, nbrmgr):
        if self.port:
            self.ports[self.port][0].set_neighbor_manager(nbrmgr)
            self.ports[self.port][1] += 1
        self.managers[self.port] = nbrmgr
        return self.port

    def release_port(self, port):
        self.ports[port][1] -= 1
        self._check_close(port)

    def close_sockets(self):
        for serversocket, _ in self.ports.itervalues():
            serversocket.close()
