# NeighborLink.py
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

# Written by John Schanck and Rich Jones
from Anomos.Connection import Connection
from Anomos.EndPoint import EndPoint
from Anomos.Relayer import Relayer
from Anomos.AnomosProtocol import AnomosNeighborProtocol

class NeighborLink(Connection, AnomosNeighborProtocol):
    def __init__(self, manager, socket, id):
        Connection.__init__(self, socket)
        AnomosNeighborProtocol.__init__(self)
        self.id = id
        self.manager = manager
        #self.ssl_session = None
        self.complete = False
        self.streams = {0:self} # {StreamID : Anomos*Protocol implementing obj}
        self.next_stream_id = 1

        #Prepare to read messages
        self._reader = self._read_messages()
        self._next_len = self._reader.next()
    ## Stream Initialization ##
    def start_endpoint_stream(self, torrent, aeskey, data=None):
        nxtid = self.next_stream_id
        self.streams[nxtid] = \
                    EndPoint(self, nxtid, torrent, aeskey, data)
        self.next_stream_id += 1
        return self.streams[nxtid]
    def start_relay_stream(self, nid, data=None, orelay=None):
        nxtid = self.next_stream_id
        self.streams[nxtid] = Relayer(nxtid, self, nid, data, orelay)
        self.next_stream_id += 1
        return self.streams[nxtid]
    def end_stream(self, id):
        if self.streams.has_key(id):
            del self.streams[id]
    def get_stream_handler(self, streamid):
        # Return the handler associated with streamid, otherwise
        # return a reference to self (because receiving an unassociated
        # stream id implies it's a new one).
        return self.streams.get(streamid, self)
