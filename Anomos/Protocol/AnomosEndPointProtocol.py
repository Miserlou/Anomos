# AnomosNeighborProtocol.py
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

from Anomos.Protocol import CHOKE, UNCHOKE, INTERESTED, NOT_INTERESTED, \
                            HAVE, BITFIELD, REQUEST, PIECE, CANCEL, \
                            TCODE, CONFIRM, ENCRYPTED, RELAY, BREAK
from Anomos.Protocol import tobinary, toint, AnomosProtocol
from Anomos.bitfield import Bitfield
from Anomos import INFO, WARNING, ERROR, CRITICAL

class AnomosEndPointProtocol(AnomosProtocol):
    ## EndPointProtocol is intended to be implemented by EndPoint ##
    def __init__(self):
        AnomosProtocol.__init__(self)
        #msgmap => Lookup table for methods to use when responding to message types
        self.msgmap.update({CHOKE: self.got_choke,\
                            UNCHOKE: self.got_unchoke,\
                            INTERESTED: self.got_interested,\
                            NOT_INTERESTED: self.got_not_interested,\
                            HAVE: self.got_have,\
                            BITFIELD: self.got_bitfield,\
                            REQUEST: self.got_request,\
                            PIECE: self.got_piece,\
                            CANCEL: self.got_cancel,\
                            ENCRYPTED: self.got_encrypted,\
                            RELAY: self.got_relay, \
                            BREAK: self.got_break})
        self.recvd_break = False
    def got_confirm(self):
        if not self.complete:
            self.connection_completed()
        if self.recvd_break:
            self.logfunc(INFO, "Break success")
            self.close()
    def got_relay(self, message):
        self.got_message(message[1:])
    def got_encrypted(self, message):
        if self.complete and self.e2e_key is not None:
            m = self.e2e_key.decrypt(message[1:])
            self.got_message(m)
        else:
            raise RuntimeError("Received encrypted data before we were ready")
    def got_break(self):
        self.logfunc(INFO, 'Encoder Got Break')
        self.recvd_break = True
        self.send_confirm()
        self.close()
    def transfer_ctl_msg(self, type, message=""):
        ''' Send method for file transfer messages.
            ie. CHOKE, INTERESTED, PIECE '''
        payload = ENCRYPTED + self.e2e_key.encrypt(type + message)
        s = self.format_message(RELAY, payload)
        self.neighbor.send_message(self.stream_id, s)
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
        if i >= self.torrent.numpieces:
            self.close("Piece index out of range")
            return
        self.download.got_have(i)
    def got_bitfield(self, message):
        try:
            b = Bitfield(self.torrent.numpieces, message[1:])
        except ValueError:
            self.close("Bad Bitfield")
            return
        self.download.got_have_bitfield(b)
    def got_request(self, message):
        i = toint(message[1:5])
        if i >= self.torrent.numpieces:
            self.close("Piece index out of range")
            return
        self.upload.got_request(i, toint(message[5:9]), toint(message[9:]))
    def got_cancel(self, message):
        i = toint(message[1:5])
        if i >= self.torrent.numpieces:
            self.close("Piece index out of range")
            return
        self.upload.got_cancel(i, toint(message[5:9]), toint(message[9:]))
    def got_piece(self, message):
        i = toint(message[1:5])
        if i >= self.torrent.numpieces:
            self.close("Piece index out of range")
            return
        if self.download.got_piece(i, toint(message[5:9]), message[9:]):
            for ep in self.torrent.active_streams:
                ep.send_have(i)
    ## Send messages ##
    def send_break(self):
        self.recvd_break = True
        self.network_ctl_msg(BREAK)
    def send_confirm(self):
        self.network_ctl_msg(CONFIRM)
    def send_interested(self):
        self.transfer_ctl_msg(INTERESTED)
    def send_not_interested(self):
        self.transfer_ctl_msg(NOT_INTERESTED)
    def send_choke(self):
        if self.queued == 0:
            self.transfer_ctl_msg(CHOKE)
            self.choke_sent = True
            self.upload.sent_choke()
    def send_unchoke(self):
        if self.queued == 0:
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
    def send_tracking_code(self, trackcode):
        self.network_ctl_msg(TCODE, trackcode)

    def invalid_message(self, t):
        self.close()
        self.logfunc(WARNING, \
                "Invalid message of type %02x on %s. Closing stream."% \
                (ord(t), self.uniq_id()))
    def close(self):
        self.neighbor.end_stream(self.stream_id)
    ## Partial message sending methods ##
    ## these are used by send_partial, which we inherit from BitTorrentProtocol
    def partial_msg_str(self, index, begin, piece):
        msg = "".join([PIECE, tobinary(index), tobinary(begin), piece])
        return self.format_message(RELAY, ENCRYPTED + self.e2e_key.encrypt(msg))
    def partial_choke_str(self):
        return self.format_message(RELAY, ENCRYPTED + self.e2e_key.encrypt(CHOKE))
    def partial_unchoke_str(self):
        return self.format_message(RELAY, ENCRYPTED + self.e2e_key.encrypt(UNCHOKE))
