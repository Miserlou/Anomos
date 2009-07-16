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

from Anomos.AnomosProtocol import AnomosProtocol
from Anomos.BitTorrentProtocol import BitTorrentProtocol

class Connection(object):
    def __init__(self, owner, connection, established=False):
        self.owner = owner
        self.connection = connection
        self.connection.handler = self
        self.ip = connection.ip
        self.port = None
        self.established = established
        self.complete = False
        self.closed = False
        self.got_anything = False
        self.next_upload = None
        self.upload = None
        self.download = None
        self.is_relay = False
        self._buffer = ""
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
        while True:
            if self.closed: # May have been closed by call to _reader.next
                return
            i = self._next_len - len(self._buffer)
            if i > len(s):
                self._buffer += s
                return
            m = s[:i]
            if len(self._buffer) > 0:
                m = self._buffer + m
                self._buffer = ""
            s = s[i:]
            self._message = m
            try:
                # Hand control over to Protocol until they yield another data length
                self._next_len = self._reader.next()
            except StopIteration:
                self.close("No more messages")
                return
    ## Methods that must be implemented by a Protocol class ##
    ## Raise RuntimeError if no protocol has been defined
    def format_message(self, type, message):
        raise RuntimeError("No protocol defined for this connection.")
    def partial_msg_str(self, *args):
        raise RuntimeError("No protocol defined for this connection.")
    def partial_choke_str(self, *args):
        raise RuntimeError("No protocol defined for this connection.")
    def partial_unchoke_str(self, *args):
        raise RuntimeError("No protocol defined for this connection.")
    def _send_message(self, type, message):
        ''' Prepends message with its length as a 32 bit integer,
            and queues or immediately sends the message '''
        s = self.format_message(type, message)
        if self._partial_message is not None:
            # Last message has not finished sending yet
            self._outqueue.append(s)
        else:
            self.connection.write(s)
    def send_partial(self, bytes):
        """ Provides partial sending of messages for RateLimiter """
        if self.closed:
            return 0
        if self._partial_message is None:
            s = self.upload.get_upload_chunk()
            if s is None:
                return 0
            index, begin, piece = s
            self._partial_message = self.partial_msg_str(index, begin, piece)
        if bytes < len(self._partial_message):
            self.connection.write(buffer(self._partial_message, 0, bytes))
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
        self.connection.write(queue)
        return len(queue)
    def close(self, e=None):
        if not self.closed:
            self.connection.close()
            self.closed = True
            self._sever()
    def _sever(self):
        self.closed = True
        self._reader = None
        #TODO: relay specific things shouldn't be here
        if self.is_relay:
            self.send_break()
        if self.complete:
            self.owner.connection_closed(self)
    def connection_lost(self, conn):
        assert conn is self.connection
        self._sever()
    def connection_flushed(self, connection):
        if self.is_relay or not self.complete:
            pass
        elif self.next_upload is None \
             and (self._partial_message is not None or self.upload.buffer):
                self.owner.ratelimiter.queue(self)

##################################################
## Protocol specific mixin types                ##
##################################################

## AnomosProtocol Connections
class AnomosFwdLink(Connection, AnomosProtocol):
    """ Extends Anomos specific Forward Link properties of Connection """
    def __init__(self, owner, connection, id, established=False, e2e=None):
        Connection.__init__(self, owner, connection, established)
        AnomosProtocol.__init__(self) 
        self.id = id
        self.e2e_key = e2e # End-to-end encryption key
        self._reader = AnomosProtocol._read_header(self) # Starts the generator
        self._next_len = self._reader.next() # Gets the first yield
        if not self.established: # New neighbor, send header
            self.write_header()
    def _got_full_header(self):
        # Neighbor has responded with a valid header, add them as our neighbor
        # and confirm that we received their message/added them.
        self.owner.connection_completed(self)
        self.send_confirm()

class AnomosRevLink(Connection, AnomosProtocol):
    """ Extends Anomos specific Reverse Link properties of Connection """
    def __init__(self, owner, connection, id=None, established=False):
        Connection.__init__(self, owner, connection, established) 
        AnomosProtocol.__init__(self)
        self.id = id
        self.e2e_key = None # End-to-end encryption key
        self._reader = AnomosProtocol._read_header(self) # Starts the generator
        self._next_len = self._reader.next() # Gets the first yield
    def _got_full_header(self):
        # In the event that AnomosProtocol._read_header finds this connection
        # to be headerless, control will be immediately passed to read_messages
        # and will not return to this method.
        # If control returns to this method then this connection is a new
        # neighbor connection. In which case:
        # Set owner to NeighborManager to finish the new neighbor registration
        self.owner.xchg_owner_with_nbr_manager(self)
        # and respond with a header of our own
        self.write_header()

## BitTorrentProtocol Connections
class BTFwdLink(Connection, BitTorrentProtocol):
    """ Extends BitTorrent specific Forward Link properties of Connection """
    def __init__(self, owner, connection, established=False):
        Connection.__init__(self, owner, connection, established)
        BitTorrentProtocol.__init__(self) 
        self._reader = BitTorrentProtocol_read_header(self) # Starts the generator
        self._next_len = self._reader.next() # Gets the first yield
        if not self.established: # New neighbor, send header
            self.write_header()
    def _got_full_header(self):
        self.owner.connection_completed(self)
        # Switch from reading the header to reading messages
        self._reader = self._read_messages()
        yield self._reader.next()

class BTRevLink(Connection, BitTorrentProtocol):
    """ Extends BitTorrent specific Reverse Link properties of Connection """
    def __init__(self, owner, connection, established=False):
        Connection.__init__(self, owner, connection, established) 
        BitTorrentProtocol.__init__(self) 
        self._reader = BitTorrentProtocol_read_header(self) # Starts the generator
        self._next_len = self._reader.next() # Gets the first yield
    def _got_full_header(self):
        self.write_header()
        # Switch from reading the header to reading messages
        self._reader = self._read_messages()
        yield self._reader.next()
