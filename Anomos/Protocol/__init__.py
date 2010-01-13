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

from binascii import b2a_hex
from Anomos import LOG as log

NAME = "Anomos"

NAT_CHECK_ID = chr(255)

#--Message Control Characters--#
#--BitTorrent--#
CHOKE = chr(0x0) # Single byte
UNCHOKE = chr(0x1) # Single byte
INTERESTED = chr(0x2) # Single byte
NOT_INTERESTED = chr(0x3) # Single byte
HAVE = chr(0x4) # index
BITFIELD = chr(0x5) # index, bitfield
REQUEST = chr(0x6) # index, begin, length
PIECE = chr(0x7) # index, begin, piece
CANCEL = chr(0x8) # index, begin, piece
#--Anomos--#
TCODE = chr(0x9)
CONFIRM = chr(0xA)
ENCRYPTED = chr(0xB) # The data that follows is AES encrypted
RELAY = chr(0xC)
BREAK = chr(0xD)
ACKBREAK = chr(0xE)
PARTIAL = chr(0xF)

_MCODES = ['CHOKE', 'UNCHOKE', 'INTERESTED', 'NOT_INTERESTED', 'HAVE',\
           'BITFIELD', 'REQUEST', 'PIECE', 'CANCEL', 'TCODE', 'CONFIRM',\
           'ENCRYPTED', 'RELAY', 'BREAK', 'PARTIAL']

def mcode_to_name(c):
    return _MCODES[c]

def toint(s):
    return int(b2a_hex(s), 16)

def tobinary(i):
    return (chr(i >> 24) + chr((i >> 16) & 0xFF) +
        chr((i >> 8) & 0xFF) + chr(i & 0xFF))

class AnomosProtocol(object):
    ## Common features of all AnomosProtocols (Neighbor, Relayer, EndPoint) ##
    def __init__(self):
        #msglens => Provides easy lookup for validation of fixed length messages
        self.msglens = { CHOKE: 1, UNCHOKE: 1, INTERESTED: 1, \
                              NOT_INTERESTED: 1, HAVE: 5, REQUEST: 13, \
                              PIECE: 9, CANCEL: 13, BREAK: 1, CONFIRM: 1}
        #msgmap => Lookup table for methods to use when responding to message types
        self.msgmap = {}
    def network_ctl_msg(self, type, message=""):
        ''' Send message for network messages,
            ie. CONFIRM, TCODE and for relaying messages'''
        s = self.format_message(type, message)
        self.neighbor.send_immediately(s)
    def got_message(self, message):
        """ Handles an incoming message. First byte designates message type,
            may be any one of (CHOKE, UNCHOKE, INTERESTED, NOT_INTERESTED,
            HAVE, BITFIELD, REQUEST, PIECE, CANCEL)
        """
        t = message[0]
        if self.msgmap.has_key(t):
            #log.info(self.uniq_id() + " got "+mcode_to_name(ord(t)))
            if len(message[1:]) > 0:
                self.msgmap[t](message)
            else:
                self.msgmap[t]()
        else:
            self.invalid_message(t)
            return
    def invalid_message(self, t):
        raise NotImplementedError("Must be implemented in a subclass")
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
    def format_message(self, type, message=""):
        ''' Anomos messages are slightly different from
            BitTorrent messages because of the virtual
            streams used to keep the number of active connections
            low. All messages are prefixed with a 2-byte Stream ID.
            The format is thus: [StreamID][Message Length][Type][Payload]
            @param type: TCODE, RELAY, BREAK, CHOKE, etc...
            @param message: Message type appropriate payload
            @type type: char (strictly 1 byte)
            @type message: string'''
        return tobinary(self.stream_id)[2:] + \
               tobinary(len(type+message)) + \
               type + message
