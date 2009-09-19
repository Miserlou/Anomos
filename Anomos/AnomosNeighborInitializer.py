# AnomosNeighborInitializer.py
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

# Written by John M. Schanck

from Anomos.Protocol.Connection import Connection
from Anomos.Protocol import NAT_CHECK_ID
from Anomos import protocol_name as anomos_protocol_name

class AnomosNeighborInitializer(Connection):
    ''' Temporary connection handler created to instantiate
        or receive connections '''
    def __init__(self, manager, socket, id=None):
        Connection.__init__(self, socket)
        self.manager = manager
        self.id = id
        self._reader = self._read_header() # Starts the generator
        self._next_len = self._reader.next() # Gets the first yield
        if self.started_locally:
            self.write_header()
    def _read_header(self):
        '''Each yield puts N bytes from Connection.data_came_in into
           self._message. self._message is then checked for compliance
           to the Anomos protocol'''
        yield 1
        if ord(self._message) != len(anomos_protocol_name):
            raise StopIteration("Protocol name mismatch")
        yield len(anomos_protocol_name) # protocol name -- 'Anomos'
        if self._message != anomos_protocol_name:
            raise StopIteration("Protocol name mismatch")
        yield 1  # NID
        if self.id is None:
            self.id = self._message
        elif self.id != self._message:
            raise StopIteration("Neighbor ID mismatch")
        yield 7  # reserved bytes (ignore these for now)
        self._got_full_header()
    def _got_full_header(self):
        # Reply with a header if we didn't start the connection
        if not self.started_locally:
            self.write_header()
        # Tell the neighbor manager we've got a completed connection
        # so that it can create a NeighborLink
        self.manager.connection_completed(self.socket, self.id)
    def protocol_extensions(self):
        """Anomos puts [1:nid][7:null char] into the
           BitTorrent reserved header bytes"""
        return self.id + '\0\0\0\0\0\0\0'
    def write_header(self):
        """Return properly formatted Anomos connection header
           example with id 255:
                \x06Anomos\xff\x00\x00\x00\x00\x00\x00\x00
        """
        hdr = chr(len(anomos_protocol_name)) + anomos_protocol_name + \
                       self.protocol_extensions()
        self.socket.write(hdr)
    def connection_closed(self):
        self.manager.initializer_failed(self.id)

