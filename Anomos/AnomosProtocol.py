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

from Anomos.BitTorrentProtocol \
    import  BitTorrentProtocol, CHOKE, UNCHOKE, INTERESTED, \
            NOT_INTERESTED, HAVE, BITFIELD, REQUEST, PIECE, \
            CANCEL, toint, tobinary

from Anomos.TCReader import TCReader
from Anomos.crypto import AESKey
from Anomos import log_on_call, trace_on_call

TCODE = chr(0x9)
CONFIRM = chr(0xA)
ENCRYPTED = chr(0xB) # The data that follows is AES encrypted
RELAY = chr(0xC)
BREAK = chr(0xD)

class ImproperUseError(Exception):
    pass

def improper_use(fn):
    """ Improper use lets us know that a known message type has
        come in for a stream that is not permitted to answer that
        type of message. For instance, got_piece should not be
        accepted by Relayer types"""
    def ret_fn(self, *args):
        raise ImproperUseError( \
                "Action %s improper for %s."% \
                (fn.__name__,type(self)))
    return ret_fn

class AnomosProtocol(BitTorrentProtocol):
    ## Common features of all AnomosProtocols (Neighbor, Relayer, EndPoint) ##
    from Anomos import protocol_name
    def __init__(self):
        BitTorrentProtocol.__init__(self)
        #msglens => Provides easy lookup for validation of fixed length messages
        self.msglens.update({BREAK: 1, CONFIRM: 1})
        #msgmap => Lookup table for methods to use when responding to message types
        self.msgmap.update({CONFIRM: self.got_confirm, BREAK: self.got_break,
                            TCODE: self.got_tcode, RELAY: self.got_relay,
                            ENCRYPTED: self.got_encrypted})
        self.neighbor_manager = None
    def network_ctl_msg(self, type, message=""):
        ''' Send message for network messages,
            ie. CONFIRM, TCODE and for relaying messages'''
        s = self.format_message(type, message)
        self.neighbor.send_message(self.stream_id, s)
    def send_confirm(self):
        self.network_ctl_msg(CONFIRM)
    def got_confirm(self):
        self.connection_completed()
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
    ## partial messages are only used by EndPoints ##
    @improper_use
    def got_relay(self): pass
    @improper_use
    def got_tcode(self): pass
    @improper_use
    def got_encrypted(self): pass
    @improper_use
    def transfer_ctl_msg(self, *args): pass
    @improper_use
    def partial_msg_str(self, index, begin, piece): pass
    @improper_use
    def partial_choke_str(self): pass
    @improper_use
    def partial_unchoke_str(self): pass

class AnomosNeighborProtocol(AnomosProtocol):
    ## NeighborProtocol is intended to be implemented by NeighborLink ##
    def __init__(self):
        AnomosProtocol.__init__(self)
    def _read_messages(self):
        ''' Read messages off the line and relay or process them
            depending on connection type '''
        while True:
            yield 2 # Stream ID
            stream = toint(self._message)
            handler = self.get_stream_handler(stream)
            yield 4   # Message Length
            l = toint(self._message)
            #TODO: Neighbors need some access to config.
            #if l > self.config['max_message_length']:
            #    return
            yield l # Payload
            handler.got_message(self._message)
    def got_tcode(self, message):
        tcreader = TCReader(self.manager.certificate)
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
            e2e_key = AESKey(keydata[:32],keydata[32:])
            torrent = self.manager.get_torrent(infohash)
            if not torrent:
                self.close("Requested torrent not found")
                return
            self.start_endpoint_stream(torrent, e2e_key)
        else:
            self.close("Unsupported TCode Format")
    ### Methods which should not be called by this class ###
    @improper_use
    def got_bitfield(self): pass
    @improper_use
    def got_break(self): pass
    @improper_use
    def got_cancel(self): pass
    @improper_use
    def got_have(self): pass
    @improper_use
    def got_interested(self): pass
    @improper_use
    def got_not_interested(self): pass
    @improper_use
    def got_piece(self): pass
    @improper_use
    def got_request(self): pass
    @improper_use
    def _read_header(self): pass
    @improper_use
    def write_header(self): pass


class AnomosRelayerProtocol(AnomosProtocol):
    ## RelayerProtocol is intended to be implemented by Relayer ##
    def __init__(self):
        AnomosProtocol.__init__(self)
    ## Disable direct message reading. ##
    def send_tracking_code(self, trackcode):
        self.network_ctl_msg(TCODE, trackcode)
    def send_relay_message(self, msg):
        self.network_ctl_msg('', msg)
    #TODO: I have no idea if send break works --John
    def got_break(self):
        self.relay_message(BREAK)
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
        self.relay_message(message)
    def got_confirm(self):
        self.connection_completed()
        self.relay_message(CONFIRM)
    #TODO: Analyze effective choking strategies for Relayers
    def got_choke(self):
        self.choke(self)
        self.orelay.send_choke()
    def got_unchoke(self, time):
        self.unchoke(time)
        self.orelay.send_unchoke()
    def close(self, e=None):
        self.neighbor.end_stream(self.stream_id)
    ### Methods which should not be called by this class ###
    @improper_use
    def _read_header(self): pass
    @improper_use
    def _read_messages(self): pass
    @improper_use
    def got_bitfield(self, message): pass
    @improper_use
    def got_cancel(self, message): pass
    @improper_use
    def got_encrypted(self, message): pass
    @improper_use
    def got_have(self, message): pass
    @improper_use
    def got_interested(self): pass
    @improper_use
    def got_not_interested(self): pass
    @improper_use
    def got_piece(self, message): pass
    @improper_use
    def got_request(self, message): pass
    @improper_use
    def got_tcode(self, message): pass
    @improper_use
    def write_header(self): pass


class AnomosEndPointProtocol(AnomosProtocol):
    ## EndPointProtocol is intended to be implemented by EndPoint ##
    def __init__(self):
        AnomosProtocol.__init__(self)
    def send_tracking_code(self, trackcode):
        self.network_ctl_msg(TCODE, trackcode)
    def got_confirm(self):
        if not self.complete:
            self.send_confirm()
        self.connection_completed()
    def got_relay(self, message):
        self.got_message(message[1:])
    def got_encrypted(self, message):
        if self.complete and self.e2e_key is not None:
            m = self.e2e_key.decrypt(message[1:])
            self.got_message(m)
        else:
            raise RuntimeError("Received encrypted data before we were ready")
    def got_break(self, message):
        self.neighbor.end_stream(self.stream_id)
    def transfer_ctl_msg(self, type, message=""):
        ''' Send method for file transfer messages.
            ie. CHOKE, INTERESTED, PIECE '''
        payload = ENCRYPTED + self.e2e_key.encrypt(type + message)
        s = self.format_message(RELAY, payload)
        self.neighbor.send_message(self.stream_id, s)
    def send_choke(self):
        if self.queued == False:
            self.transfer_ctl_msg(CHOKE)
            self.choke_sent = True
            self.upload.sent_choke()
    def send_unchoke(self):
        if self.queued == False:
            self.transfer_ctl_msg(UNCHOKE)
            self.choke_sent = False

    ## Partial message sending methods ##
    ## these are used by send_partial, which we inherit from BitTorrentProtocol
    def partial_msg_str(self, index, begin, piece):
        msg = "".join([PIECE, tobinary(index), tobinary(begin), piece])
        return self.format_message(RELAY, ENCRYPTED + self.e2e_key.encrypt(msg))
    def partial_choke_str(self):
        return self.format_message(RELAY, ENCRYPTED + self.e2e_key.encrypt(CHOKE))
    def partial_unchoke_str(self):
        return self.format_message(RELAY, ENCRYPTED + self.e2e_key.encrypt(UNCHOKE))
    def close(self, e=None):
        self.neighbor.end_stream(self.stream_id)
    ### Methods which should not be called by this class ###
    @improper_use
    def _read_header(self): pass
    @improper_use
    def write_header(self): pass
    @improper_use
    def got_tcode(self, message): pass
