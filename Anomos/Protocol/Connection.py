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
import asyncore

class Connection(asyncore.dispatcher):
    def __init__(self, socket=None, local=True):
        asyncore.dispatcher.__init__(self, socket)

        self.started_locally = local
        self.closed = False

        self.in_buffer = array.array('c',"")
        self.out_buffer = array.array('c',"")

        if self.started_locally:
            self._ssl_accepting = 0
        else:
            self._ssl_accepting = 1

        self.manager = manager
        self.ip, self.port = sock.getsockname()
        self.peer_cert = self.get_peer_cert()

    def handle_write(self):
        if self._ssl_accepting:
            if self.socket.accept_ssl():
                self._ssl_accepting = 0
        else:
            try:
                n = self.send(self.out_buffer.tostring())
                if n == -1:
                    pass
                elif n == 0:
                    self.handle_close()
                else:
                    self.out_buffer = self.out_buffer[n:]
            except SSL.SSLError, err:
                if str(err) == 'unexpected eof':
                    self.handle_close()
                    return
                else:
                    raise

    def handle_read(self):
        if self._ssl_accepting:
            s = self.socket.accept_ssl()
            if s:
                self._ssl_accepting = 0
        else:
            try:
                data = self.recv(4096)
                if data is None:
                    pass
                elif data == '':
                    self.handle_close()
                else:
                    self.data_came_in(data)
            except SSL.SSLError, err:
                if str(err) == 'unexpected eof':
                    self.handle_close()
                    return
                else:
                    raise

    def data_came_in(self, s):
        """Interface between Protocol and raw data stream.
           A protocol "_read_*" method yields a message length
           and this method chops that many bytes off the
           front of the stream and stores it in self._message.

           @param s: Recv'd data """
        s = array.array('c', s)
        while True:
            if self.closed: # May have been closed by call to _reader.next
                return
            i = self._next_len - len(self.in_buffer)
            # Case 1: Length of s is less than the amount needed
            if i > len(s):
                self.in_buffer += s
                return
            # Case 2: Length of s is more than the buffer can hold
            # Load as much of s as we can into the buffer
            self.in_buffer += s[:i]
            # Delete loaded portion of s
            del s[:i]
            # Move in_buffer to _message and delete the contents of in_buffer
            self._message = self.in_buffer.tostring()
            del self.in_buffer[:]
            try:
                # Hand control over to Protocol until they yield another data length
                self._next_len = self._reader.next()
            except StopIteration, e:
                self.close("Closing. " + str(e))
                return

    def close(self, e=None):
        self.closed = True
        self._reader = None
        self.del_channel()
        self.socket.close()
        self.connection_closed()

    #        self._sever()
    #def _sever(self):
    #    self.closed = True
    #    self._reader = None
    #    self.connection_closed()
    def connection_flushed(self, socket): pass
    def connection_closed(self): pass # Used by subclasses.
    #def connection_lost(self, conn):
    #    assert conn is self.socket
    #    self._sever()


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
