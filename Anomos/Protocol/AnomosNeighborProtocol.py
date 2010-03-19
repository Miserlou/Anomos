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

import Anomos.Crypto

from Anomos.Protocol import PARTIAL, TCODE, tobinary, toint, AnomosProtocol
from Anomos.TCReader import TCReader
from Anomos import LOG as log

class AnomosNeighborProtocol(AnomosProtocol):
    ## NeighborProtocol is intended to be implemented by NeighborLink ##
    def __init__(self):
        AnomosProtocol.__init__(self)

        self.msgmap.update({PARTIAL:self.got_partial,
                            TCODE: self.got_tcode})

    def format_message(self, stream_id, message):
        return tobinary(stream_id)[2:] + \
               tobinary(len(message)) + message
    def invalid_message(self, t):
        log.warning("Invalid message of type %02x on %s. Closing neighbor."% \
                    (ord(t), self.uniq_id()))
        self.socket.close()
    def got_partial(self, message):
        p_remain = toint(message[1:5])
        payload = message[5:]
        self.partial_recv += payload
        if len(self.partial_recv) > self.config['max_message_length']:
            log.error("Received message longer than max length")
            return
        if len(payload) == p_remain:
            self.got_message(self.partial_recv)
            self.partial_recv = ''
    def got_tcode(self, message):
        tcreader = TCReader(self.manager.certificate)
        try:
            tcdata = tcreader.parseTC(message[1:])
        except Anomos.Crypto.CryptoError, e:
            log.error("Decryption Error: %s" % str(e))
            self.socket.close()
            return
        sid = tcdata.sessionID
        if not self.manager.check_session_id(sid):
            #TODO: Key mismatch is pretty serious, probably want to ban the
            # user who sent this TCode
            log.error("Session id mismatch")
            self.socket.close()
            return
        if tcdata.type == chr(0): # Relayer type
            nextTC = tcdata.nextLayer
            nid = tcdata.neighborID
            self.start_relay_stream(nid, nextTC)
        elif tcdata.type == chr(1): # Terminal type
            infohash = tcdata.infohash
            keydata = tcdata.keydata
            e2e_key = Anomos.Crypto.AESKey(keydata[:32],keydata[32:])
            torrent = self.manager.get_torrent(infohash)
            if not torrent:
                log.error("Requested torrent not found")
                self.socket.close()
                return
            self.start_endpoint_stream(torrent, e2e_key)
        else:
            log.error("Unsupported TCode Format")
            self.socket.close()
