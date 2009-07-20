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
    """ Should NOT be created directly, must be used as a mixin with a class
        that also inherits a Connection type """
    from Anomos import protocol_name
    def __init__(self):
        BitTorrentProtocol.__init__(self)
        #msglens => Provides easy lookup for validation of fixed length messages
        self.msglens.update({BREAK: 1, CONFIRM: 1})
        #msgmap => Lookup table for methods to use when responding to message types
        self.msgmap.update({TCODE: self.got_tcode,
                            CONFIRM: self.got_confirm,
                            ENCRYPTED: self.got_encrypted,
                            RELAY: self.got_relay,
                            BREAK: self.send_break })

    def protocol_extensions(self):
        """Anomos puts [1:nid][7:null char] into the 
           BitTorrent reserved header bytes"""
        return self.id + '\0\0\0\0\0\0\0'
    def _read_header(self):
        '''Each yield puts N bytes from Connection.data_came_in into
           self._message. N is the number of bytes in the section of the
           header which is to be checked. This is also called on headerless
           connections (since we don't know they're headerless until we read
           the data), so it also handles the switch from reading the header to
           reading messages.'''
        yield 1
        first = self._message
        # If the first byte doesn't match the length of the protocol
        # name, then it's most likely a headerless connection
        if ord(self._message) != len(protocol_name):
            # So skip right to reading messages
            self._reader = self._read_messages()
            self._buffer = self._message + self._buffer
            yield self._reader.next()
        yield len(protocol_name) # protocol name -- 'Anomos'
        # That said, there's a small chance that first byte just happens
        # to equal the length of the protocol name, so if the recv'd
        # protocol name doesn't match the expected one,
        if self._message != protocol_name:
            # assume that it's a headerless connection and switch to
            # reading messages.
            self._reader = self._read_messages()
            self._buffer = first + self._message + self._buffer
            yield self._reader.next()
        # Upon reaching this point the connection is determined
        # to be a headerless connection and thus a new neighbor.
        yield 1  # NID
        self.id = self._message
        yield 7  # reserved bytes (ignore these for now)
        self._got_full_header() # Does some connection type specific actions
                                # See AnomosFwdLink and AnomosRevLink
        # Switch to reading messages
        self._reader = self._read_messages()
        yield self._reader.next()
    def _read_messages(self):
        ''' Read messages off the line and relay or process them
            depending on connection type '''
        while True:
            yield 2
            stream = toint(self._message)
            handler = self.get_stream_handler(stream)
            yield 4   # get the message length in self._message
            l = toint(self._message)
            if l > self.owner.config['max_message_length']:
                return
            if l > 0:
                yield l # get the message body
                handler.got_message(self._message)
                #if self.is_relay:
                #    self.owner.relay_message(self, self._message)
                #else:
                #    self.got_message(self._message)
    ## Message sending methods ##
    def _send_encrypted_message(self, message):
        '''End-to-End encrypts a message'''
        message = self.e2e_key.encrypt(message)
        self._send_message(ENCRYPTED, message)
    def transfer_ctl_msg(self, message):
        ''' Send method for file transfer messages. 
            ie. CHOKE, INTERESTED, PIECE '''
        self._send_encrypted_message(message)
    def network_ctl_msg(self, type, message):
        ''' Send message for network messages, 
            ie. CONFIRM, TCODE and for relaying messages'''
        self._send_message(type, message)
    def send_confirm(self):
        self.network_ctl_msg(CONFIRM)
    def send_tracking_code(self, trackcode):
        self.network_ctl_msg(TCODE, trackcode)
    def send_relay_message(self, message):
        # NOTE: RELAY character is left at the beginning of the message
        # to avoid the extra string copy, so no type is added here
        self.network_ctl_msg("", message)
    #TODO: I have no idea if send break works --John
    def send_break(self):
        if self.is_relay:
            self.owner.relay_message(self, BREAK)
        #TODO:
        #else:
        #    Lost uploader, schedule announce for new one..
        if not self.closed:
            self.close()
    ## Message receiving methods ##
    def got_encrypted(self, message):
        # Decrypt the message, relay it if we're a relayer, decrypt with
        # e2e key if we have it, then pass the decrypted message back into
        # this method.
        if self.complete and self.e2e_key is not None:
            # Message is link- and e2e-encrypted
            m = self.e2e_key.decrypt(message[1:])
            self.got_message(m)
        else:
            assert(False)
            # Message is only link-encrypted
            #self.got_message(message[1:])
    def got_tcode(self, message):
        tcreader = TCReader(self.owner.certificate)
        tcdata = tcreader.parseTC(message[1:])
        sid = tcdata.sessionID
        idmatch = self.owner.check_session_id(sid)
        if not idmatch:
            #TODO: Key mismatch is pretty serious, probably want to do
            #      something besides just close the connection
            self.close("Session id mismatch")
        if tcdata.type == chr(0): # Relayer type
            nextTC = tcdata.nextLayer
            nid = tcdata.neighborID
            self.owner.xchg_owner_with_relayer(self, nid)   #this changes the value of owner
            self.owner.connection_completed(self)
            self.complete = True
            assert self.is_relay
            self.owner.relay_message(self, TCODE + nextTC)
        elif tcdata.type == chr(1): # Terminal type
            infohash = tcdata.infohash
            keydata = tcdata.keydata
            aes, iv = keydata[:32], keydata[32:]
            self.e2e_key = AESKey(aes,iv)
            self.owner.xchg_owner_with_endpoint(self, infohash)
            if self.owner.download_id is None:
                self.close("Requested torrent not found")
                return
            self.send_confirm()
            self.owner.connection_completed(self)
            self.complete = True
        else:
            self.close("Unsupported TCode Format")
    def got_relay(self, message):
        if self.is_relay:
            #NOTE: message[0] == RELAY, there's no need to
            #      strip this since we'd just have to add
            #      it again in send_relay. As a result,
            #      send_relay does NOT add a control char.
            self.owner.relay_message(self, message)
        else:
            self.got_message(message[1:])
    def got_confirm(self):
        if not self.established:
            self.owner.add_neighbor(self.id, (self.ip, 0))
        self.owner.connection_completed(self)
        self.complete = True
        if self.is_relay:
            self.owner.relay_message(self, CONFIRM)
    def format_message(self, type, message):
        return tobinary(self.stream_id)[2:] + \     # Stream ID
               tobinary(len(type+message)) + \  # Message Length
               type + message                   # Payload
    ## Partial message sending methods ##
    ## these are used by send_partial, which we inherit from BitTorrentProtocol
    def partial_msg_str(self, index, begin, piece):
        msg = "".join([PIECE, tobinary(index), tobinary(begin), piece])
        return self.format_message(ENCRYPTED, self.e2e_key.encrypt(msg))
    def partial_choke_str(self):
        return self.format_message(ENCRYPTED, self.e2e_key.encrypt(CHOKE))
    def partial_unchoke_str(self):
        return self.format_message(ENCRYPTED, self.e2e_key.encrypt(UNCHOKE))
