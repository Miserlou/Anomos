# Neighbor.py
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
from Anomos.Connection import Connection
from Anomos.AnomosProtocol import AnomosProtocol

class NeighborLink(Connection, AnomosProtocol):
    def __init__(self, id, loc, manager):
        self.id = id
        self.loc = loc
        self.manager = manager
        #self.ssl_session = None
        self.complete = False
        self.streams = {}   # {StreamID : Connection type object}
    ## Socket Initialization ##
    def start_connection(self, loc, id):
        """
        @param loc: (IP, Port)
        @param id: The neighbor ID to assign to this connection
        @type loc: tuple
        @type id: int
        """
        self.rawserver.start_ssl_connection(loc, handler=self)
    def sock_success(self, sock, loc):
        """ @param sock: SingleSocket object for the newly created socket """
        Connection.__init__(self, self.manager, sock)
        #self.ssl_session = sock.socket.get_session()
        self.complete = True
        self.manager.connection_completed(self.id)
        self._reader = AnomosProtocol._read_header(self) # Starts the generator
        self._next_len = self._reader.next() # Gets the first yield
        if not self.established: # New neighbor, send header
            self.write_header()
    def _got_full_header(self):
        # Neighbor has responded with a valid header, add them as our neighbor
        # and confirm that we received their message/added them.
        self.owner.connection_completed(self)
        self.send_confirm()
        # Exchange the header and hold the connection open
    def sock_fail(self, loc, err=None):
        self.manager.nbr_fail(self.id)
        #Remove nid,loc pair from incomplete
        for k,v in self.incomplete.items():
            if v == loc:
                self.failedPeers.append(k)
                del self.incomplete[k]
        #TODO: Do something with the error msg.
    def start_new_stream(self, ConnectionType):
        self.streams[self.next_stream_id] = ConnectionType()
