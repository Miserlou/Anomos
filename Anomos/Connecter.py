# The contents of this file are subject to the BitTorrent Open Source License
# Version 1.0 (the License).  You may not copy or use this file, in either
# source code or executable form, except in compliance with the License.  You
# may obtain a copy of the License at http://www.bittorrent.com/license/.
#
# Software distributed under the License is distributed on an AS IS basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
# for the specific language governing rights and limitations under the
# License.

# Originally written by Bram Cohen, heavily modified by Uoti Urpala

# required for python 2.2
from __future__ import generators

from binascii import b2a_hex
from M2Crypto.RSA import RSAError
from Anomos.crypto import AESKey, RSAPubKey, getRand
from Anomos.bitfield import Bitfield
from Anomos.obsoletepythonsupport import *
from Anomos import protocol_name

def toint(s):
    return int(b2a_hex(s), 16)

def tobinary(i):
    return (chr(i >> 24) + chr((i >> 16) & 0xFF) +
        chr((i >> 8) & 0xFF) + chr(i & 0xFF))

CHOKE = chr(0)
UNCHOKE = chr(1)
INTERESTED = chr(2)
NOT_INTERESTED = chr(3)
# index
HAVE = chr(4)
# index, bitfield
BITFIELD = chr(5)
# index, begin, length
REQUEST = chr(6)
# index, begin, piece
PIECE = chr(7)
# index, begin, piece
CANCEL = chr(8)

##Anomos Control Chars##
TCODE = chr(9)
PUBKEY = chr(10) # Sent before a pubkey to be used in an AES key exchange
EXCHANGE = chr(11) # The data that follows is RSA encrypted AES data
CONFIRM = chr(12)
ENCRYPTED = chr(13) # The data that follows is AES encrypted

class ConnectionError(Exception):
    pass

class Connection(object):

    def __init__(self, encoder, connection, id, is_local, established=False):
        self.encoder = encoder
        self.connection = connection
        self.id = id
        self.ip = connection.ip
        #TODO: This port might not always be set
        self.port = connection.port
        self.locally_initiated = is_local
        self.established = established
        self.complete = False
        self.closed = False
        self.got_anything = False
        self.next_upload = None
        self.upload = None
        self.download = None
        self.is_relay = False
        self._buffer = ""
        self._reader = self._read_messages() # Starts the generator
        self._next_len = self._reader.next() # Gets the first yield
        self._partial_message = None
        self._outqueue = []
        self.choke_sent = True
        if self.locally_initiated: # This connection is sending data
            #TODO: Write neighbor ID here.
            connection.write(chr(len(protocol_name)) + protocol_name +
                (chr(0) * 8)) #+ self.encoder.download_id)
            #if self.id is not None:
            #    connection.write(self.encoder.my_id)

    def close(self, e=None):
        print "Closing the connection!"
        if not self.closed:
            self.connection.close()
            self._sever()
        if e:
            raise ConnectionError(e)

    def send_interested(self):
        self._send_encrypted_message(INTERESTED)

    def send_not_interested(self):
        self._send_encrypted_message(NOT_INTERESTED)

    def send_choke(self):
        if self._partial_message is None:
            self._send_encrypted_message(CHOKE)
            self.choke_sent = True
            self.upload.sent_choke()

    def send_unchoke(self):
        if self._partial_message is None:
            self._send_encrypted_message(UNCHOKE)
            self.choke_sent = False

    def send_request(self, index, begin, length):
        self._send_encrypted_message(REQUEST + tobinary(index) +
            tobinary(begin) + tobinary(length))

    def send_cancel(self, index, begin, length):
        self._send_encrypted_message(CANCEL + tobinary(index) +
            tobinary(begin) + tobinary(length))

    def send_bitfield(self, bitfield):
        self._send_encrypted_message(BITFIELD + bitfield)

    def send_have(self, index):
        self._send_encrypted_message(HAVE + tobinary(index))

    def send_keepalive(self):
        self._send_message('')

    def send_partial(self, bytes):
        if self.closed:
            return 0
        if self._partial_message is None:
            s = self.upload.get_upload_chunk()
            if s is None:
                return 0
            index, begin, piece = s
            self._partial_message = ''.join((tobinary(len(piece) + 9), PIECE,
                                    tobinary(index), tobinary(begin), piece))
        if bytes < len(self._partial_message):
            self.connection.write(buffer(self._partial_message, 0, bytes))
            self._partial_message = buffer(self._partial_message, bytes)
            return bytes

        queue = [str(self._partial_message)]
        self._partial_message = None
        if self.choke_sent != self.upload.choked:
            if self.upload.choked:
                self._outqueue.append(tobinary(1) + CHOKE)
                self.upload.sent_choke()
            else:
                self._outqueue.append(tobinary(1) + UNCHOKE)
            self.choke_sent = self.upload.choked
        queue.extend(self._outqueue)
        self._outqueue = []
        queue = ''.join(queue)
        self.connection.write(queue)
        return len(queue)
    
    def send_key_exchange(self, pubkey):
        """
        Sends the NeighborID and AES key for us and our neighbor to share 
        @param pubkey: RSAPubKey to encrypt data with
        """
        aes = AESKey()
        self.tmp_aes = aes
        msg = EXCHANGE + pubkey.encrypt(self.id + tobinary(len(aes.key)) + 
                                        aes.key + tobinary(len(aes.iv)) + 
                                        aes.iv)
        self._send_message(msg)
    
    def send_tracking_code(self, trackcode):
        self._send_encrypted_message(TCODE + trackcode)
    
    def get_aes_key(self):
        return self.encoder.keyring.getKey(self.id)
    
    # yields the number of bytes it wants next, gets those in self._message
    def _read_messages(self):
        yield 1   # header length
        if ord(self._message) != len(protocol_name):
            return
        yield len(protocol_name)
        if self._message != protocol_name:
            return
        yield 8  # reserved
        if not self.locally_initiated:
            self.connection.write(chr(len(protocol_name)) + protocol_name + (chr(0) * 8))
            if not self.established:
                # Non-neighbor connection
                # Respond with PubKey
                pkmsg = PUBKEY + self.encoder.rsakey.pub_bin()
                self._send_message(pkmsg)
        #else:
        #    if self.established:
        #        self.encoder.connection_completed(self)
                # Local Connection, check if we're starting a circuit
         #       self.send_encrypted_message(TCODE + tracking_code)
#        yield 20 # download id
#        if self.encoder.download_id is None:  # incoming connection
#            # modifies self.encoder if successful
#            self.encoder.select_torrent(self, self._message)
#            if self.encoder.download_id is None:
#                return
#        elif self._message != self.encoder.download_id:
#            return
#        if not self.locally_initiated:
#            # Respond with our information.
#            self.connection.write(chr(len(protocol_name)) + protocol_name +
#                (chr(0) * 8) + self.encoder.download_id + self.encoder.my_id)

#        yield 20  # peer id
#        if not self.id:
#            self.id = self._message
#            if self.id == self.encoder.my_id:
#                return
#            for v in self.encoder.connections.itervalues():
#                if v is not self:
#                    if v.id == self.id:
#                        return
#                    if self.encoder.config['one_connection_per_ip'] and \
#                           v.ip == self.ip:
#                        return
#            if self.locally_initiated:
#                self.connection.write(self.encoder.my_id)
#            else:
#                self.encoder.everinc = True
#        else:
#            if self._message != self.id:
#                return
#        self.complete = True
#        self.encoder.connection_completed(self)

        while True:
            yield 4   # message length
            l = toint(self._message)
            if l > self.encoder.config['max_message_length']:
                return
            if l > 0:
                yield l
                self._got_message(self._message)

    def _got_message(self, message):
        """ Handles an incoming message. First byte designates message type,
            may be any one of (CHOKE, UNCHOKE, INTERESTED, NOT_INTERESTED, 
            HAVE, BITFIELD, REQUEST, PIECE, CANCEL, PUBKEY, EXCHANGE, 
            CONFIRM, ENCRYPTED)
        """
        t = message[0]
        #TODO: Find out why this was needed
        #if t == BITFIELD and self.got_anything:
        #    self.close()
        #    return
        self.got_anything = True
        if (t in [CHOKE, UNCHOKE, INTERESTED, NOT_INTERESTED] and
                len(message) != 1):
            self.close("Invalid message length")
            return
        if t == ENCRYPTED:
            key = self.get_aes_key()
            if key:
                m = key.decrypt(message[1:])
                self._got_message(m)
        elif t == CHOKE:
            self.download.got_choke()
        elif t == UNCHOKE:
            self.download.got_unchoke()
        elif t == INTERESTED:
            self.upload.got_interested()
        elif t == NOT_INTERESTED:
            self.upload.got_not_interested()
        elif t == HAVE:
            if len(message) != 5:
                self.close("Invalid message length")
                return
            i = toint(message[1:])
            if i >= self.encoder.numpieces:
                self.close("Piece index out of range")
                return
            self.download.got_have(i)
        elif t == BITFIELD:
            try:
                b = Bitfield(self.encoder.numpieces, message[1:])
            except ValueError:
                self.close("Bad Bitfield")
                return
            self.download.got_have_bitfield(b)
        elif t == REQUEST:
            if len(message) != 13:
                self.close("Bad request length")
                return
            i = toint(message[1:5])
            if i >= self.encoder.numpieces:
                self.close("Piece index out of range")
                return
            self.upload.got_request(i, toint(message[5:9]),
                toint(message[9:]))
        elif t == CANCEL:
            if len(message) != 13:
                self.close("Invalid message length")
                return
            i = toint(message[1:5])
            if i >= self.encoder.numpieces:
                self.close("Piece index out of range")
                return
            self.upload.got_cancel(i, toint(message[5:9]),
                toint(message[9:]))
        elif t == PIECE:
            if len(message) <= 9:
                self.close("Bad message length")
                return
            i = toint(message[1:5])
            if i >= self.encoder.numpieces:
                self.close("Piece index out of range")
                return
            if self.download.got_piece(i, toint(message[5:9]), message[9:]):
                for co in self.encoder.complete_connections:
                    co.send_have(i)
        elif t == TCODE:
            plaintext, nextTC = self.encoder.rsakey.decrypt(message[1:], True)
            if len(plaintext) == 1:
                if self.upload is not None:
                    #This is a new connection
                    self.encoder.start_connection(None, plaintext, self)
                padlen = (len(message)-1) - len(nextTC)
                pad = getRand("randfile.dat", padlen)
            else:
                # TC is for us
                infohash = plaintext[:20]
                aes = plaintext[20:52]
                iv = plaintext[52:74]
                self.encoder.select_torrent(self, infohash)
                if self.encoder.download_id is None:
                    # We don't have that torrent...
                    # TODO: handle this gracefully.
                    return
                self.encoder.connection_completed(self)
        elif t == PUBKEY:
            #TODO: Check size?
            pub = RSAPubKey(message[1:])
            self.send_key_exchange(pub)
        elif t == EXCHANGE:
            # Read in RSA encrypted data and extract NID, AES key and AES IV
            try:
                plaintxt = self.encoder.rsakey.decrypt(message[1:])
                nid = plaintxt[0]
                i = 1
                keylen = toint(plaintxt[i:i+4])
                i += 4
                key = plaintxt[i:i+keylen]
                i += keylen
                ivlen = toint(plaintxt[i:i+4])
                i += 4
                iv = plaintxt[i:i+ivlen]
            except IndexError:
                self.close("Bad message length")
                return
            except RSAError:
                self.close("Bad decrypt, wrong private key?")
                return
            except ValueError:
                self.close("Bad encrypted message checksum")
                return
            # Check that this NID isn't already taken
            if self.encoder.has_neighbor(nid):
                self.close("NID already assigned")
                return
            self.id = nid
            self.encoder.add_neighbor(self.id, (self.ip, self.port), AESKey(key, iv))
            self._send_message(CONFIRM)
            self.encoder.connection_completed(self)
        elif t == CONFIRM:
            self.encoder.add_neighbor(self.id, (self.ip, self.port), self.tmp_aes)
            self.encoder.connection_completed(self)
        else:
            self.close("Invalid message")
            return

    def _sever(self):
        self.closed = True
        self._reader = None
        del self.encoder.connections[self.connection]
        # self.encoder.replace_connection()
        if self.complete:
            del self.encoder.complete_connections[self]
            self.download.disconnected()
            self.encoder.choker.connection_lost(self)
            self.upload = self.download = None
    
    def _send_message(self, message):
        s = tobinary(len(message)) + message
        if self._partial_message is not None:
            self._outqueue.append(s)
        else:
            self.connection.write(s)
    
    def _send_encrypted_message(self, message):
        key = self.get_aes_key()
        if not key:
            #TODO: Raise error here or some other warning
            return
        self._send_message(ENCRYPTED + key.encrypt(message))
    
    def data_came_in(self, conn, s):
        while True:
            if self.closed:
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
                self._next_len = self._reader.next()
            except StopIteration:
                self.close("No more messages")
                return

    def connection_lost(self, conn):
        assert conn is self.connection
        self._sever()

    def connection_flushed(self, connection):
        if self.complete:
            if self.next_upload is None and (self._partial_message is not None
                                             or self.upload.buffer):
                self.encoder.ratelimiter.queue(self)
