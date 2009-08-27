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

from Anomos.Protocol import TCODE, tobinary, toint, AnomosProtocol
from Anomos.Protocol.Connection import Connection
from Anomos.Protocol.TCReader import TCReader
from Anomos.crypto import AESKey
from Anomos import INFO, WARNING, ERROR, CRITICAL

class AnomosNeighborProtocol(Connection, AnomosProtocol):
    ## NeighborProtocol is intended to be implemented by NeighborLink ##
    def __init__(self, socket):
        Connection.__init__(self, socket)
        AnomosProtocol.__init__(self)
        self.msgmap.update({TCODE: self.got_tcode})
        self.incoming_stream_id = 0
    def format_message(self, stream_id, message):
        return tobinary(stream_id)[2:] + \
               tobinary(len(message)) + message
    def _read_messages(self):
        ''' Read messages off the line and relay or process them
            depending on connection type '''
        while True:
            yield 2 # Stream ID
            stream = toint(self._message)
            handler = self.get_stream_handler(stream)
            yield 4   # Message Length
            l = toint(self._message)
            if l > self.config['max_message_length']:
                self.logfunc(WARNING, "Received message longer than max length")
            #    return
            yield l # Payload
            if handler == self:
                self.incoming_stream_id = stream
            handler.got_message(self._message)
    def invalid_message(self, t):
        #self.close()
        self.logfunc(WARNING, \
                "Invalid message of type %02x on %s. Closing neighbor."% \
                (ord(t), self.uniq_id()))
    def got_tcode(self, message):
        tcreader = TCReader(self.manager.certificate)
        tcdata = tcreader.parseTC(message[1:])
        sid = tcdata.sessionID
        if not self.manager.check_session_id(sid):
            #TODO: Key mismatch is pretty serious, probably want to do
            #      something besides just close the connection
            self.logfunc(ERROR, "Session id mismatch")
            self.close()
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
                self.logfunc(ERROR, "Requested torrent not found")
                self.close()
                return
            self.start_endpoint_stream(torrent, e2e_key)
        else:
            self.logfunc(ERROR, "Unsupported TCode Format")
            self.close()
