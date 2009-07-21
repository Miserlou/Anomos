# BitTorrentProtocol.py
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

# Written by John Schanck

from binascii import b2a_hex
from Anomos.bitfield import Bitfield

def toint(s):
    return int(b2a_hex(s), 16)

def tobinary(i):
    return (chr(i >> 24) + chr((i >> 16) & 0xFF) +
        chr((i >> 8) & 0xFF) + chr(i & 0xFF))

CHOKE = chr(0x0) # Single byte
UNCHOKE = chr(0x1) # Single byte
INTERESTED = chr(0x2) # Single byte
NOT_INTERESTED = chr(0x3) # Single byte
HAVE = chr(0x4) # index
BITFIELD = chr(0x5) # index, bitfield
REQUEST = chr(0x6) # index, begin, length
PIECE = chr(0x7) # index, begin, piece
CANCEL = chr(0x8) # index, begin, piece

class BitTorrentProtocol(object):
    """ Should NOT be created directly, must be used as a mixin with a class
        that also inherits a Connection type """

    protocol_name = "BitTorrent"
    def __init__(self):
        #msglens => Provides easy lookup for validation of fixed length messages
        self.msglens= { CHOKE: 1, UNCHOKE: 1, INTERESTED: 1, NOT_INTERESTED: 1, \
                        HAVE: 5, REQUEST: 13, PIECE: 9, CANCEL: 13}
        #msgmap => Lookup table for methods to use when responding to message types
        self.msgmap = {CHOKE: self.got_choke,\
                       UNCHOKE: self.got_unchoke,\
                       INTERESTED: self.got_interested,\
                       NOT_INTERESTED: self.got_not_interested,\
                       HAVE: self.got_have,\
                       BITFIELD: self.got_bitfield,\
                       REQUEST: self.got_request,\
                       PIECE: self.got_piece,\
                       CANCEL: self.got_cancel }
    def write_header(self):
        """Return properly formatted BitTorrent connection header
           example with port 6881 and id 255:
                \xA0BitTorrent\x1a\xe1\x00\x00\x00\x00\x00\x00
        """
        hdr = chr(len(protocol_name)) + protocol_name + \
                       self.protocol_extensions()
        self.connection.write(hdr)
    def protocol_extensions(self):
        """The BitTorrent protocol has 8 reserved bytes in its header"""
        return '\0\0\0\0\0\0\0\0'
    def _read_header(self):
        '''Yield the number of bytes for each section of the header and sanity
           check the received values. If the connection doesn't have a header
           (as in, it's already established) then switch to _read_message and
           reenter the data we read off as if it just came in.
        '''
        yield 1   # header length
        if ord(self._message) != len(protocol_name):
            return
        yield len(protocol_name) # protocol name -- 'BitTorrent'
        if self._message != protocol_name:
            return
        yield 8  # reserved (ignore these for now)
        self._got_full_header()
        self._reader = self._read_messages()
        yield self._reader.next()
    def _got_full_header(self):
        pass
    def _read_messages(self):
        ''' Read messages off the line and relay or process them
            depending on connection type '''
        while True:
            yield 4   # get the message length in self._message
            l = toint(self._message)
            if l > self.owner.config['max_message_length']:
                return
            if l > 0:
                yield l # get the message body
                self.got_message(self._message)
    def _valid_msg_len(self, m):
        ''' Check length of received message m against dictionary
            of valid message lengths '''
        validp = True
        if m[0] in self.msglens:
            # PIECE must be more than 9 bytes
            if m[0] == PIECE and len(m) <= self.msglens[m[0]]:
                validp = False
            if len(m) != self.msglens[m[0]]:
                validp = False
        return validp
    def transfer_ctl_msg(self, type, message=""):
        ''' Send method for file transfer messages. 
            ie. CHOKE, INTERESTED, PIECE '''
        self._send_message(type, message)
    ## Recv messages ##
    def got_message(self, message):
        """ Handles an incoming message. First byte designates message type,
            may be any one of (CHOKE, UNCHOKE, INTERESTED, NOT_INTERESTED,
            HAVE, BITFIELD, REQUEST, PIECE, CANCEL)
        """
        t = message[0]
        if self.msgmap.has_key(t):
            if len(message[1:]) > 0:
                self.msgmap[t](message)
            else:
                self.msgmap[t]()
        else:
            self.close("Invalid message " + b2a_hex(message))
            return
    def got_choke(self):
        if self.download:
            self.download.got_choke()
    def got_unchoke(self):
        if self.download:
            self.download.got_unchoke()
    def got_interested(self):
        if self.upload:
            self.upload.got_interested()
    def got_not_interested(self):
        if self.upload:
            self.upload.got_not_interested()
    def got_have(self, message):
        i = toint(message[1:])
        if i >= self.owner.numpieces:
            self.close("Piece index out of range")
            return
        self.download.got_have(i)
    def got_bitfield(self, message):
        try:
            b = Bitfield(self.owner.numpieces, message[1:])
        except ValueError:
            self.close("Bad Bitfield")
            return
        self.download.got_have_bitfield(b)
    def got_request(self, message):
        i = toint(message[1:5])
        if i >= self.owner.numpieces:
            self.close("Piece index out of range")
            return
        self.upload.got_request(i, toint(message[5:9]), toint(message[9:]))
    def got_cancel(self, message):
        i = toint(message[1:5])
        if i >= self.owner.numpieces:
            self.close("Piece index out of range")
            return
        self.upload.got_cancel(i, toint(message[5:9]), toint(message[9:]))
    def got_piece(self, message):
        i = toint(message[1:5])
        if i >= self.owner.numpieces:
            self.close("Piece index out of range")
            return
        if self.download.got_piece(i, toint(message[5:9]), message[9:]):
            for co in self.owner.complete_connections:
                co.send_have(i)
    ## Send messages ##
    def send_interested(self):
        self.transfer_ctl_msg(INTERESTED)
    def send_not_interested(self):
        self.transfer_ctl_msg(NOT_INTERESTED)
    def send_choke(self):
        if self._partial_message is None:
            self.transfer_ctl_msg(CHOKE)
            self.choke_sent = True
            self.upload.sent_choke()
    def send_unchoke(self):
        if self._partial_message is None:
            self.transfer_ctl_msg(UNCHOKE)
            self.choke_sent = False
    def send_request(self, index, begin, length):
        self.transfer_ctl_msg(REQUEST, tobinary(index) +
            tobinary(begin) + tobinary(length))
    def send_cancel(self, index, begin, length):
        self.transfer_ctl_msg(CANCEL, tobinary(index) +
            tobinary(begin) + tobinary(length))
    def send_bitfield(self, bitfield):
        self.transfer_ctl_msg(BITFIELD, bitfield)
    def send_have(self, index):
        self.transfer_ctl_msg(HAVE, tobinary(index))
    def format_message(self, type, message=""):
        return tobinary(len(type+message)) + \  # Message Length
               type + message                   # Payload
    ## Partial Messages ##
    def partial_msg_str(self, index, begin, piece):
        return ''.join((tobinary(len(piece) + 9), PIECE, tobinary(index), \
                                tobinary(begin), piece))
    def partial_choke_str(self):
        return format_message(CHOKE)
    def partial_unchoke_str(self):
        return format_message(UNCHOKE)

