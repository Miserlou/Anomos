# Connection.py
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

# Original Connecter.py written by Bram Cohen
# This heavily modified version by John M. Schanck

import array

class Connection(object):
    def __init__(self, socket):
        self.socket = socket
        self.socket.handler = self
        self.started_locally = self.socket.local
        self.closed = False
        self._buffer = array.array('c',"")
    def data_came_in(self, conn, s):
        """Interface between Protocol and raw data stream.
           A protocol "_read_*" method yields a message length
           and this method chops that many bytes off the
           front of the stream and stores it in self._message.

           @param conn: SingleSocket object (not used here)
           @param s: Recv'd data """
        s = array.array('c', s)
        while True:
            if self.closed: # May have been closed by call to _reader.next
                return
            i = self._next_len - len(self._buffer)
            # Case 1: Length of s is less than the amount needed
            if i > len(s):
                self._buffer += s
                return
            # Case 2: Length of s is more than the buffer can hold
            # Load as much of s as we can into the buffer
            self._buffer += s[:i]
            # Delete loaded portion of s
            del s[:i]
            # Move _buffer to _message and delete the contents of _buffer
            self._message = self._buffer.tostring()
            del self._buffer[:]
            try:
                # Hand control over to Protocol until they yield another data length
                self._next_len = self._reader.next()
            except StopIteration, e:
                self.close("Closing. " + str(e))
                return
    def close(self, e=None):
        if self.socket.handler != self:
            # Don't close sockets we don't own anymore.
            # This is sort of a hack, but it prevents uglier
            # hacks elsewhere.
            return
        if not self.closed:
            self.socket.close()
            self._sever()
    def _sever(self):
        self.closed = True
        self._reader = None
        self.connection_closed()
    def connection_flushed(self, socket): pass
    def connection_closed(self): pass # Used by subclasses.
    def connection_lost(self, conn):
        assert conn is self.socket
        self._sever()


##################################################
## Protocol specific mixin types                ##
##################################################
#XXX: BitTorrent protocol support is broken.
## BitTorrentProtocol Connections
#class BTFwdLink(Connection, BitTorrentProtocol):
#    """ Extends BitTorrent specific Forward Link properties of Connection """
#    def __init__(self, connection, established=False):
#        Connection.__init__(self, connection)
#        BitTorrentProtocol.__init__(self) 
#        self._reader = BitTorrentProtocol_read_header(self) # Starts the generator
#        self._next_len = self._reader.next() # Gets the first yield
#        # Connection no longer has self.established. BT things need to be updated
#        if not self.established: # New neighbor, send header
#            self.write_header()
#    def _got_full_header(self):
#        self.connection_completed(self)
#        # Switch from reading the header to reading messages
#        self._reader = self._read_messages()
#        yield self._reader.next()
#
#class BTRevLink(Connection, BitTorrentProtocol):
#    """ Extends BitTorrent specific Reverse Link properties of Connection """
#    def __init__(self, connection, established=False):
#        Connection.__init__(self, connection, established) 
#        BitTorrentProtocol.__init__(self) 
#        self._reader = BitTorrentProtocol_read_header(self) # Starts the generator
#        self._next_len = self._reader.next() # Gets the first yield
#    def _got_full_header(self):
#        self.write_header()
#        # Switch from reading the header to reading messages
#        self._reader = self._read_messages()
#        yield self._reader.next()
