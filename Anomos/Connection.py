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

from Anomos import protocol_name as anomos_protocol_name
import array

class Connection(object):
    def __init__(self, socket):
        self.socket = socket
        self.socket.handler = self
        self.ip = socket.ip
        self.complete = False
        self.closed = False
        self.got_anything = False
        self.next_upload = None
        self.upload = None
        self.download = None
        self._buffer = array.array('c',"")
        self._partial_message = None
        self._outqueue = []
        self.choke_sent = True
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
            except StopIteration:
                self.close("Closing. Was not expecting data.")
                return
    ## Methods that must be implemented by a Protocol class ##
    ## Raise RuntimeError if no protocol has been defined
    def format_message(self, *args):
        raise RuntimeError("No protocol defined for this connection.")
    def partial_msg_str(self, *args):
        raise RuntimeError("No protocol defined for this connection.")
    def partial_choke_str(self, *args):
        raise RuntimeError("No protocol defined for this connection.")
    def partial_unchoke_str(self, *args):
        raise RuntimeError("No protocol defined for this connection.")
    def send_message(self, message):
        ''' Prepends message with its length as a 32 bit integer,
            and queues or immediately sends the message '''
        if self._partial_message is not None:
            # Last message has not finished sending yet
            self._outqueue.append(message)
        else:
            self.socket.write(message)
    #TODO: Send Partial is broken.
    def send_partial(self, bytes):
        """ Provides partial sending of messages for RateLimiter """
        #TODO: Comment this method!
        if self.closed:
            return 0
        if self._partial_message is None:
            s = self.upload.get_upload_chunk()
            if s is None:
                return 0
            index, begin, piece = s
            self._partial_message = self.partial_msg_str(index, begin, piece)
        if bytes < len(self._partial_message):
            self.socket.write(buffer(self._partial_message, 0, bytes))
            self._partial_message = buffer(self._partial_message, bytes)
            return bytes
        queue = [str(self._partial_message)]
        self._partial_message = None
        if self.choke_sent != self.upload.choked:
            if self.upload.choked:
                self._outqueue.append(self.partial_choke_str())
                self.upload.sent_choke()
            else:
                self._outqueue.append(self.partial_unchoke_str())
            self.choke_sent = self.upload.choked
        queue.extend(self._outqueue)
        self._outqueue = []
        queue = ''.join(queue)
        self.socket.write(queue)
        return len(queue)
    def close(self, e=None):
        if not self.closed:
            self.socket.close()
            self._sever()
    def _sever(self):
        self.closed = True
        self._reader = None
        if self.complete:
            self.connection_closed(self)
    def connection_closed(self): pass # Used by subclasses.
    def connection_lost(self, conn):
        assert conn is self.socket
        self._sever()
    def connection_flushed(self, socket):
        if not self.complete:
            pass
        elif self.next_upload is None \
             and (self._partial_message is not None or self.upload.buffer):
                self.ratelimiter.queue(self)

##################################################
## Protocol specific mixin types                ##
##################################################

## AnomosProtocol Connections
class AnomosNeighborInitializer(Connection):
    """ Extends Anomos specific Forward Link properties of Connection """
    def __init__(self, manager, socket, id=None, started_locally=True):
        Connection.__init__(self, socket)
        self.manager = manager
        self.id = id
        self.started_locally = started_locally
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

#XXX: BitTorrent protocol support is broken.
## BitTorrentProtocol Connections
#class BTFwdLink(Connection, BitTorrentProtocol):
#    """ Extends BitTorrent specific Forward Link properties of Connection """
#    def __init__(self, connection, established=False):
#        Connection.__init__(self, connection)
#        BitTorrentProtocol.__init__(self) 
#        self._reader = BitTorrentProtocol_read_header(self) # Starts the generator
#        self._next_len = self._reader.next() # Gets the first yield
#        #TODO: Connection no longer has self.established. BT things need to be
#        #       updated
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
