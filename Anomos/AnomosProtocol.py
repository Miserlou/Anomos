# AnomosProtocol.py -- Client-side extensions to the BitTorrent protocol
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

from Anomos.BitTorrentProtocol import *
from Anomos.TCReader import TCReader
from crypto import AESKey, CryptoError

TCODE = chr(0x9)
CONFIRM = chr(0xA)
ENCRYPTED = chr(0xB) # The data that follows is AES encrypted
RELAY = chr(0xC)
BREAK = chr(0xD)

class AnomosProtocol(BitTorrentProtocol):
    ## Common features of all AnomosProtocols (Neighbor, Relayer, EndPoint) ##
    from Anomos import protocol_name
    def __init__(self):
        BitTorrentProtocol.__init__(self)
        #msglens => Provides easy lookup for validation of fixed length messages
        self.msglens.update({BREAK: 1, CONFIRM: 1})
        #msgmap => Lookup table for methods to use when responding to message types
        self.msgmap.update({CONFIRM: self.got_confirm, BREAK: self.got_break})
        self.neighbor_manager = None
    def network_ctl_msg(self, type, message=""):
        ''' Send message for network messages,
            ie. CONFIRM, TCODE and for relaying messages'''
        s = self.format_message(type, message)
        self.neighbor.send_message(s)
    def send_confirm(self):
        self.network_ctl_msg(CONFIRM)
    ## Message receiving methods ##
    def got_confirm(self):
        self.connection_completed()
    def got_break(self): pass
    def format_message(self, type, message=""):
        """ [StreamID][Message Length][Type][Payload] """
        return tobinary(self.stream_id)[2:] + \
               tobinary(len(type+message)) + \
               type + message
    ## partial messages are only used by EndPoints ##
    def transfer_ctl_msg(self, *args): pass
    def partial_msg_str(self, index, begin, piece): pass
    def partial_choke_str(self): pass
    def partial_unchoke_str(self): pass

class AnomosNeighborProtocol(AnomosProtocol):
    ## NeighborProtocol is intended to be implemented by NeighborLink ##
    def __init__(self):
        AnomosProtocol.__init__(self)
        #msgmap => Lookup table for methods to use when responding to message types
        self.msgmap.update({TCODE: self.got_tcode})
    def _read_messages(self):
        ''' Read messages off the line and relay or process them
            depending on connection type '''
        while True:
            yield 2
            stream = toint(self._message)
            handler = self.get_stream_handler(stream)
            yield 4   # get the message length in self._message
            l = toint(self._message)
            #TODO: Neighbors need some access to config.
            #if l > self.config['max_message_length']:
            #    return
            if l > 0:
                yield l # get the message body
                handler.got_message(self._message)
    def send_tracking_code(self, trackcode):
        self.network_ctl_msg(TCODE, trackcode)
    def got_tcode(self, message):
        tcreader = TCReader(self.certificate)
        tcdata = tcreader.parseTC(message[1:])
        sid = tcdata.sessionID
        if not self.manager.check_session_id(sid):
            #TODO: Key mismatch is pretty serious, probably want to do
            #      something besides just close the connection
            self.close("Session id mismatch")
        if tcdata.type == chr(0): # Relayer type
            nextTC = tcdata.nextLayer
            nid = tcdata.neighborID
            self.start_relay_stream(nid, nextTC)
        elif tcdata.type == chr(1): # Terminal type
            infohash = tcdata.infohash
            keydata = tcdata.keydata
            aes, iv = keydata[:32], keydata[32:]
            e2e_key = AESKey(aes,iv)
            torrent = self.manager.get_torrent(infohash)
            if not torrent:
                self.close("Requested torrent not found")
                return
            self.start_endpoint_stream(torrent, e2e_key)
            self.send_confirm()
        else:
            self.close("Unsupported TCode Format")
    # Disable these message types.
    #?def got_choke(self): pass
    #?def got_unchoke(self): pass
    def _read_header(self): pass
    def write_header(self): pass
    def network_ctl_msg(self, *args): pass
    def got_interested(self): pass
    def got_not_interested(self): pass
    def got_have(self, message): pass
    def got_bitfield(self, message): pass
    def got_request(self, message): pass
    def got_cancel(self, message): pass
    def got_piece(self, message): pass


class AnomosRelayerProtocol(AnomosProtocol):
    ## RelayerProtocol is intended to be implemented by Relayer ##
    def __init__(self):
        AnomosProtocol.__init__(self)
        #msgmap => Lookup table for methods to use when responding to message types
        self.msgmap.update({RELAY: self.got_relay})
    ## Disable direct message reading. ##
    def _read_header(self): pass
    def _read_messages(self): pass
    #TODO: I have no idea if send break works --John
    def got_break(self):
        self.relay_message(self, BREAK)
        #TODO:
        #else:
        #    Lost uploader, schedule announce for new one..
        if not self.closed:
            self.close()
    def got_relay(self, message):
        #NOTE: message[0] == RELAY, there's no need to
        #      strip this since we'd just have to add
        #      it again in send_relay. As a result,
        #      send_relay does NOT add a control char.
        self.relay_message(self, message)
    def got_confirm(self):
        self.connection_completed()
        self.relay_message(self, CONFIRM)
    # Disable these message types.
    #?def got_choke(self): pass
    #?def got_unchoke(self): pass
    def _read_header(self): pass
    def write_header(self): pass
    def got_interested(self): pass
    def got_not_interested(self): pass
    def got_have(self, message): pass
    def got_bitfield(self, message): pass
    def got_request(self, message): pass
    def got_cancel(self, message): pass
    def got_piece(self, message): pass
    def got_tcode(self, message): pass


class AnomosEndPointProtocol(AnomosProtocol):
    ## EndPointProtocol is intended to be implemented by EndPoint ##
    def __init__(self):
        AnomosProtocol.__init__(self)
        #msgmap => Lookup table for methods to use when responding to message types
        self.msgmap.update({RELAY: self.got_relay,
                            ENCRYPTED: self.got_encrypted})
    def got_relay(self, message):
        self.got_message(message[1:])
    def got_encrypted(self, message):
        if self.complete and self.e2e_key is not None:
            # Message is link- and e2e-encrypted
            m = self.e2e_key.decrypt(message[1:])
            self.got_message(m)
        else:
            raise RuntimeError("Received encrypted data before we were ready")
    def got_break(self, message):
        self.neighbor.end_stream(self.stream_id)
    def transfer_ctl_msg(self, type, message=""):
        ''' Send method for file transfer messages.
            ie. CHOKE, INTERESTED, PIECE '''
        payload = self.e2e_key.encrypt(type + message)
        s = self.format_message(ENCRYPTED, payload)
        self.neighbor.send_message(s)
    ## Partial message sending methods ##
    ## these are used by send_partial, which we inherit from BitTorrentProtocol
    def partial_msg_str(self, index, begin, piece):
        msg = "".join([PIECE, tobinary(index), tobinary(begin), piece])
        return self.format_message(ENCRYPTED, self.e2e_key.encrypt(msg))
    def partial_choke_str(self):
        return self.format_message(ENCRYPTED, self.e2e_key.encrypt(CHOKE))
    def partial_unchoke_str(self):
        return self.format_message(ENCRYPTED, self.e2e_key.encrypt(UNCHOKE))
    def _read_header(self): pass
    def write_header(self): pass
