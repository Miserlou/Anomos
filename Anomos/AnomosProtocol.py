from Anomos.BitTorrentProtocol import *
import crypto

TCODE = chr(0x9)
CONFIRM = chr(0xA)
ENCRYPTED = chr(0xB) # The data that follows is AES encrypted
BREAK = chr(0xC)

class AnomosProtocol(BitTorrentProtocol):
    '''This class assures that we send and receive messages in accordance
       with the Anomos protocol. '''
    from Anomos import protocol_name
    def __init__(self):
        BitTorrentProtocol.__init__(self)
        #msglens => Provides easy lookup for validation of fixed length messages
        self.msglens.update({BREAK: 1, CONFIRM: 1})
        #msgmap => Lookup table for methods to use when responding to message types
        self.msgmap.update({TCODE: self.got_tcode,
                            CONFIRM: self.got_confirm,
                            ENCRYPTED: self.got_encrypted,
                            BREAK: self.send_break })

    def protocol_extensions(self):
        """Anomos puts [2:port][1:nid][5:null char] into the 
           BitTorrent reserved header bytes"""
        return tobinary(self.owner.port)[2:] + self.id + '\0\0\0\0\0'
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
        yield 2  # port number
        self.port = toint(self._message)
        yield 1  # NID
        self.id = self._message
        yield 5  # reserved bytes (ignore these for now)
        self._got_full_header() # Does some connection type specific actions
                                # See AnomosFwdLink and AnomosRevLink
        # Switch to reading messages
        self._reader = self._read_messages()
        yield self._reader.next()
    ## Message sending methods ##
    def _send_encrypted_message(self, message):
        '''End-to-End encrypts a message'''
        message = ENCRYPTED + self.e2e_key.encrypt(message)
        self._send_message(message)
    def transfer_ctl_msg(self, message):
        ''' Send method for file transfer messages. 
            ie. CHOKE, INTERESTED, PIECE '''
        self._send_encrypted_message(message)
    def network_ctl_msg(self, message):
        ''' Send message for network messages, 
            ie. CONFIRM, TCODE and for relaying messages'''
        self._send_message(message)
    def send_confirm(self):
        self.network_ctl_msg(CONFIRM)
    def send_tracking_code(self, trackcode):
        self.network_ctl_msg(TCODE + trackcode)
    def send_relay_message(self, message):
        # Just used by Relayer to accesss _send_encrypted_message
        # Can be removed if someone wants to clean it up.
        self.network_ctl_msg(message)
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
        try:
            plaintext, nextTC = self.owner.certificate.decrypt(message[1:], True)
        except crypto.CryptoError, e:
            # Break?
            self.close("Encryption Error: " + str(e))
        if len(plaintext) == 1: # Single character, NID
            self.owner.xchg_owner_with_relayer(self, plaintext)   #this changes the value of owner
            self.owner.connection_completed(self)
            assert self.is_relay
            self.owner.relay_message(self, TCODE + nextTC)
        else:
            # TC ends at this peer, plaintext contains infohash, aes, iv
            infohash = plaintext[:20]
            aes = plaintext[20:52]
            iv = plaintext[52:74]
            self.e2e_key = crypto.AESKey(aes,iv)
            self.owner.xchg_owner_with_endpoint(self, infohash)
            if self.owner.download_id is None:
                self.close("Requested torrent not found")
                return
            self.send_confirm()
            self.owner.connection_completed(self)
    def got_confirm(self):
        if not self.established:
            self.owner.add_neighbor(self.id, (self.ip, self.port))
        self.owner.connection_completed(self)
        if self.is_relay:
            self.owner.relay_message(self, CONFIRM)
    ## Partial message sending methods ##
    ## these are used by send_partial, which we inherit from BitTorrentProtocol
    def partial_msg_str(self, index, begin, piece):
        msg = "".join([PIECE, tobinary(index), tobinary(begin), piece])
        return tobinary(len(msg)+1) + ENCRYPTED + self.e2e_key.encrypt(msg)
    def partial_choke_str(self):
        return tobinary(2) + ENCRYPTED + self.e2e_key.encrypt(CHOKE)
    def partial_unchoke_str(self):
        return tobinary(2) + ENCRYPTED + self.e2e_key.encrypt(UNCHOKE)
    ## Connection type methods ##
    def connection_flushed(self, connection):
        if not self.is_relay:
            Connection.connection_flushed(self, connection)

