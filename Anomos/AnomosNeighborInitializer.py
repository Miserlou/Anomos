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

from Anomos.Protocol import NAT_CHECK_ID, NAME as protocol_name
from Anomos import LOG as log

class AnomosNeighborInitializer(object):
    """ Temporary connection handler created to instantiate
        or receive connections """
    def __init__(self, manager, socket, id=None):
        self.manager = manager
        self.socket = socket
        self.socket.set_collector(self)
        self.id = id
        self._reader = self._read_header() # Starts the generator
        self._message = ''
        self.socket.set_terminator(self._reader.next())
        self.complete = False
        if self.socket.started_locally:
            self.write_header()
    def collect_incoming_data(self, data):
        self._message += data
    def get_reader(self):
        return self._reader
    def _read_header(self):
        """Each yield puts N bytes from Connection.data_came_in into
           self._message. self._message is then checked for compliance
           to the Anomos protocol"""
        yield 1
        if ord(self._message) != len(protocol_name):
            log.info("Dropping connection from %s:%d - Protocol name mismatch." % self.socket.addr)
            return
        self._message = ''
        yield len(protocol_name) # protocol name -- 'Anomos'
        if self._message != protocol_name:
            log.info("Dropping connection from %s:%d - Protocol name mismatch." % self.socket.addr)
            return
        self._message = ''
        yield 1  # NID
        if self.id is None:
            self.id = self._message
        elif self.id != self._message:
            log.info("Dropping connection from %s:%d - Neighbor ID mismatch." % self.socket.addr)
            return
        self._message = ''
        yield 7  # reserved bytes (ignore these for now)
        self._got_full_header()
        self._message = ''
    def _got_full_header(self):
        # Reply with a header if we didn't start the connection
        if not self.socket.started_locally:
            self.write_header()
        # Tell the neighbor manager we've got a completed connection
        # so that it can create a NeighborLink
        self.complete = True
        self.manager.connection_completed(self.socket, self.id)
        if self.id == NAT_CHECK_ID:
            self.socket.handle_close()
        self.socket = None
    def protocol_extensions(self):
        """Anomos puts [1:nid][7:null char] into the
           BitTorrent reserved header bytes"""
        return self.id + '\0\0\0\0\0\0\0'
    def write_header(self):
        """Return properly formatted Anomos connection header
           example with id 255:
                \x06Anomos\xff\x00\x00\x00\x00\x00\x00\x00
        """
        hdr = chr(len(protocol_name)) + protocol_name + \
                       self.protocol_extensions()
        self.socket.push(hdr)
    def socket_closed(self):
        if self.id != NAT_CHECK_ID and self.id != '':
            log.info("Failed to initialize connection to \\x%02x" % ord(self.id))
        if not self.complete:
            self.manager.initializer_failed(self.id)
        self.socket = None
    def socket_flushed(self):
        pass
