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
# Modified for Anomos by John Schanck and Rich Jones.

# required for python 2.2
from __future__ import generators

import Anomos.crypto as crypto

from binascii import b2a_hex
from M2Crypto.RSA import RSAError
from Anomos.bitfield import Bitfield
from Anomos.obsoletepythonsupport import *
from Anomos import protocol_name

def toint(s):
    return int(b2a_hex(s), 16)

def tobinary(i):
    return (chr(i >> 24) + chr((i >> 16) & 0xFF) +
        chr((i >> 8) & 0xFF) + chr(i & 0xFF))

CHOKE = chr(0x0)
UNCHOKE = chr(0x1)
INTERESTED = chr(0x2)
NOT_INTERESTED = chr(0x3)
# index
HAVE = chr(0x4)
# index, bitfield
BITFIELD = chr(0x5)
# index, begin, length
REQUEST = chr(0x6)
# index, begin, piece
PIECE = chr(0x7)
# index, begin, piece
CANCEL = chr(0x8)

##Anomos Control Chars##
TCODE = chr(0x9)
#PUBKEY = chr(0xA) # Sent before a pubkey to be used in an AES key exchange
#EXCHANGE = chr(0xB) # The data that follows is RSA encrypted AES data
CONFIRM = chr(0xC)
ENCRYPTED = chr(0xD) # The data that follows is AES encrypted

class ConnectionError(Exception):
    pass

class Connection(object):

    def __init__(self, owner, connection, id, is_local, established=False):
        self.owner = owner
        self.connection = connection
        self.id = id
        self.locally_initiated = is_local
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
       # self.link_key = None # Link encryption key
        self.e2e_key = None # End-to-end encryption key
        self._buffer = ""
        self._reader = self._read_header() # Starts the generator
        self._next_len = self._reader.next() # Gets the first yield
        self._partial_message = None
        self._outqueue = []
        self.choke_sent = True
        if self.locally_initiated and not self.established:
            connection.write(chr(len(protocol_name)) + protocol_name +
                tobinary(self.owner.port)[2:] + self.id + (chr(0) * 5))

    def close(self, e=None):
        print "Closing the connection!", e
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
        #XXX: This method is awful.
        if self.closed:
            return 0
        #key = self.get_link_aes()
        if self._partial_message is None:
            s = self.upload.get_upload_chunk()
            if s is None:
                return 0
            index, begin, piece = s
            msg = "".join([PIECE, tobinary(index), tobinary(begin), piece])
            self._partial_message = tobinary(len(msg) + 1) + ENCRYPTED + self.e2e_key.encrypt(msg)
        if bytes < len(self._partial_message):
            self.connection.write(buffer(self._partial_message, 0, bytes))
            self._partial_message = buffer(self._partial_message, bytes)
            return bytes

        queue = [str(self._partial_message)]
        self._partial_message = None
        if self.choke_sent != self.upload.choked:
            if self.upload.choked:
                self._outqueue.append(tobinary(2) + ENCRYPTED + self.e2e_key.encrypt(CHOKE))
                self.upload.sent_choke()
            else:
                self._outqueue.append(tobinary(2) + ENCRYPTED + self.e2e_key.encrypt(UNCHOKE))
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
        aes = crypto.AESKey()
        self.tmp_aes = aes
        msg = EXCHANGE + pubkey.encrypt(self.id + tobinary(len(aes.key)) + 
                                        aes.key + tobinary(len(aes.iv)) + 
                                        aes.iv)
        self._send_message(msg)
    
    def send_tracking_code(self, trackcode):
        self._send_message(TCODE + trackcode)
    
    def send_relay_message(self, message):
        self._send_message(message)
    
    #def get_link_aes(self):
    #    if self.link_key is None:
    #        self.link_key = self.owner.keyring.getKey(self.id)
    #    return self.link_key
    
#    def try_all_keys(self, message):
#        '''This method handles conflict resolution when 2 or more of our 
#           neighbors are at the same IP address. We try decrypting the message with 
#           each of the neighbor's AES keys and check if the result is a TCODE.
#           There's an off chance (1/256) that it's a TCODE by chance, so if we
#           get more than one valid plaintext we check if any of the TCODES are
#           valid by decrypting each of them with our RSA key.
#        '''
#        nids = self.owner.lookup_loc(self.connection.ip)
#        pts = {}
#        for id in nids:
#            key = self.owner.keyring.getKey(id)
#            #Create a copy of the key so we don't screw up the cipher state
#            tmpkey = crypto.AESKey(key.key, key.iv)
#            plaintext = tmpkey.decrypt(message)
#            if plaintext[0] == TCODE:
#                pts[id] = plaintext
#        if len(pts) == 1:
#            self.id = pts.items()[0][0]
#            self.established = True
#            #Decrypt with the real key to advance the cipher state
#            return self.owner.keyring.getKey(self.id).decrypt(message)
#        elif len(pts) > 1:
#            for id, text in pts.iteritems():
#                try:
#                    self.rsakey.decrypt(text)
#                except:
#                    pass
#                else:
#                    self.id = id
#                    self.established = True
#                    #Decrypt with the real key to advance the cipher state
#                    return self.get_link_aes.decrypt(message)
#        # Apparently this message isn't for us.
#        self.close("Cannot decrypt message")
    
    def _read_header(self):
        '''Yield the number of bytes for each section of the header and sanity
           check the received values. If the connection doesn't have a header
           (as in, it's already established) then switch to _read_message and
           reenter the data we read off as if it just came in.
        '''
        yield 1   # header length
        first = self._message # Hack in case a headerless connection has the 
                              # a first byte with value == len(protocol_name)
        if ord(self._message) != len(protocol_name):
            self._reader = self._read_messages()
            self._buffer = self._message + self._buffer
            yield self._reader.next()
        
        yield len(protocol_name)
        if self._message != protocol_name:
            self._reader = self._read_messages()
            self._buffer = first + self._message + self._buffer
            yield self._reader.next()
        
        yield 2  # port number
        self.port = toint(self._message)
        yield 1  # NID
        self.id = self._message
        #TODO: Check response id on locally_initiated connections?    
        yield 5  # reserved
        # Got a full header => New Neighbor Connection
        if not self.locally_initiated:
            # This is a new neighbor, so switch owner to a NeighborManager
            self.owner.set_neighbor(self)
            #XXX: PORT HACK
            self.connection.write(chr(len(protocol_name)) + protocol_name + tobinary(self.owner.port)[2:] + self.id + (chr(0) * 5))
        else:
            self.owner.add_neighbor(self.id, (self.ip, self.port))
            self.owner.connection_completed(self)
            self._send_message(CONFIRM)
#            if not self.established:
#                # Non-neighbor connection
#                # Respond with PubKey
#                pkmsg = PUBKEY + self.owner.rsakey.pub_bin()
#                self._send_message(pkmsg)
        self._reader = self._read_messages()
        yield self._reader.next()
    
    def _read_messages(self):
        while True:
            yield 4   # message length
            l = toint(self._message)
            if l > self.owner.config['max_message_length']:
                return
            if l > 0:
                yield l
                if self.is_relay:
                    self.owner.relay_message(self, self._message)
                else:
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
            # Decrypt the message, relay it if we're a relayer, decrypt with
            # e2e key if we have it, then pass the decrypted message back into
            # this method.
            #key = self.get_link_aes()
            #if key:
            #    m = key.decrypt(message[1:])
            #else:
                # This only happens if we have two+ neighbors at the same IP
            #    m = self.try_all_keys(message[1:])
            if self.complete and self.e2e_key is not None:
                # Message is link- and e2e-encrypted
                m = self.e2e_key.decrypt(message[1:])
                self._got_message(m)
            else:
                # Message is only link-encrypted
                self._got_message(message[1:])
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
            if i >= self.owner.numpieces:
                self.close("Piece index out of range")
                return
            self.download.got_have(i)
        elif t == BITFIELD:
            try:
                b = Bitfield(self.owner.numpieces, message[1:])
            except ValueError:
                self.close("Bad Bitfield")
                return
            self.download.got_have_bitfield(b)
        elif t == REQUEST:
            if len(message) != 13:
                self.close("Bad request length")
                return
            i = toint(message[1:5])
            if i >= self.owner.numpieces:
                self.close("Piece index out of range")
                return
            self.upload.got_request(i, toint(message[5:9]),
                toint(message[9:]))
        elif t == CANCEL:
            if len(message) != 13:
                self.close("Invalid message length")
                return
            i = toint(message[1:5])
            if i >= self.owner.numpieces:
                self.close("Piece index out of range")
                return
            self.upload.got_cancel(i, toint(message[5:9]),
                toint(message[9:]))
        elif t == PIECE:
            if len(message) <= 9:
                self.close("Bad message length")
                return
            i = toint(message[1:5])
            if i >= self.owner.numpieces:
                self.close("Piece index out of range")
                return
            if self.download.got_piece(i, toint(message[5:9]), message[9:]):
                for co in self.owner.complete_connections:
                    co.send_have(i)
        elif t == TCODE:
            #XXX: Decrypt might fail and raise an error.
            plaintext, nextTC = self.owner.certificate.decrypt(message[1:], True)
            if len(plaintext) == 1: # Single character, NID
                self.owner.set_relayer(self, plaintext)
                self.owner.connection_completed(self)
                self.owner.relay_message(self, TCODE + nextTC)
            else:
                # TC ends at this peer, plaintext contains infohash, aes, iv
                infohash = plaintext[:20]
                aes = plaintext[20:52]
                iv = plaintext[52:74]
                self.e2e_key = crypto.AESKey(aes,iv)
                self.owner.set_torrent(self, infohash)
                if self.owner.download_id is None:
                    # We don't have that torrent...
                    # TODO: handle this gracefully.
                    return
                self._send_message(CONFIRM)
                self.owner.connection_completed(self)
        elif t == CONFIRM:
            if not self.established:
                self.owner.add_neighbor(self.id, (self.ip, self.port))
            self.owner.connection_completed(self)
            if self.is_relay:
                self.owner.relay_message(self, CONFIRM)
        else:
            self.close("Invalid message " + b2a_hex(message))
            return

    def _sever(self):
        self.closed = True
        self._reader = None
        #del self.owner.connections[self.connection]
        # self.owner.replace_connection()
        if self.complete:
            #XXX: Make this work for all 3 connection types. (and remove try)
            try:
                self.owner.complete_connections.discard(self)
                self.download.disconnected()
                self.owner.choker.connection_lost(self)
                self.upload = self.download = None
            except:
                pass
    
    def _send_message(self, message):
        s = tobinary(len(message)) + message
        if self._partial_message is not None:
            self._outqueue.append(s)
        else:
            self.connection.write(s)
    
    def _send_encrypted_message(self, message):
        '''Sends a /link encrypted/ message. Messages must be end-to-end
           encrypted prior to being passed to this method.
        '''
        message = ENCRYPTED + self.e2e_key.encrypt(message)
        self._send_message(message)
    
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
        if self.complete and not self.is_relay:
            if self.next_upload is None and (self._partial_message is not None
                                             or self.upload.buffer):
                self.owner.ratelimiter.queue(self)
