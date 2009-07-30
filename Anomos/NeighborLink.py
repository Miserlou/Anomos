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
from Anomos import default_logger, trace_on_call

class NeighborLink(Connection, AnomosNeighborProtocol):
    ''' NeighborLink handles the socket between two neighbors and keeps
        track of the objects used to manage the active streams between
        those neighbors. '''
    def __init__(self, manager, socket, id, logfunc=default_logger):
        Connection.__init__(self, socket)
        AnomosNeighborProtocol.__init__(self)
        self.id = id
        self.manager = manager
        self.streams = {} # {StreamID : EndPoint or Relayer object}
        self.next_stream_id = 0
        self.logfunc = logfunc

        #Prepare to read messages
        self._reader = self._read_messages()
        self._next_len = self._reader.next()

    ## Stream Management ##
    def start_endpoint_stream(self, torrent, aeskey, data=None):
        ''' Starts an EndPoint stream
            @param torrent: Torrent to be uploaded/downloaded
            @param aeskey: AES-256 key to be used for transfer communication
            @param data: Tracking Code to be sent
            @type torrent: Anomos.Torrent.Torrent
            @type aeskey: Anomos.crypto.AESKey
            @type data: String
            @return: Newly created EndPoint object'''
        nxtid = self.next_stream_id
        self.streams[nxtid] = \
                    EndPoint(nxtid, self, torrent, aeskey, data,
                            logfunc=self.logfunc)
        self.next_stream_id += 1
        return self.streams[nxtid]

    def start_relay_stream(self, nid, data=None, orelay=None):
        ''' Starts one half of a relay stream. The first half started
            will have orelay=None, the second will have orelay=<first relay object>
            @param nid: The Neighbor ID for the other-half of this Relayer
            @param data: The Tracking Code to be forwarded
            @param orelay: The Relayer object corresponding to this ones other-half
            @type nid: char
            @type data: String
            @type orelay: Anomos.Relayer.Relayer
            @return: Newly created Relayer object'''
        nxtid = self.next_stream_id
        self.streams[nxtid] = \
                    Relayer(nxtid, self, nid, data, orelay,
                            logfunc=self.logfunc)
        self.next_stream_id += 1
        return self.streams[nxtid]

    def end_stream(self, id):
        ''' Terminate the stream with specified stream id. Should be
            called by the stream object which is to be terminated to ensure
            proper shutdown of that stream.
            @param id: Stream id of stream to end
            @type id: int in range 0 to 2**16'''
        if self.streams.has_key(id):
            del self.streams[id]

    def get_stream_handler(self, id):
        ''' Return the handler associated with streamid, otherwise
            return a reference to self (because receiving an unassociated
            stream id implies it's a new one).
            @param id: Stream id to fetch
            @type id: int in range 0 to 2**16'''
        return self.streams.get(id, self)

    def connection_flushed(self, socket):
        '''Inform all streams so they can requeue themselves if they need to'''
        for stream in self.streams.itervalues():
            stream.connection_flushed()

    def queue_piece(self, streamid, message):
        self._outqueue.append((streamid, message))

    def send_message(self, streamid, message):
        ''' Prepends message with its length as a 32 bit integer,
            and queues or immediately sends the message '''
        if len(self._outqueue) > 0:
            # Last message has not finished sending yet
            self._outqueue.append((streamid, message))
        else:
            self.socket.write(message)

    def send_partial(self, bytes):
        if len(self._outqueue) == 0:
            return 0
        t = sum(len(i) for i in self._outqueue)
        if t <= bytes:
            # Send the whole _outqueue
            message = ''.join([i[1] for i in self._outqueue])
            for stream in set([i[0] for i in self._outqueue]):
                self.streams[stream].piece_sent()
            del self._outqueue[:]
            self.socket.write(message)
            return len(message)
        # Determine how many of the messages in the _outqueue
        # need to be sent
        indx = 0
        s = 0
        while s < bytes:
            s += len(self._outqueue[indx][1])
            indx += 1
        # Join those messages
        tmp = ''.join([i[1] for i in self._outqueue[:indx]])
        streams = [i[0] for i in self._outqueue[:indx]]
        del self._outqueue[:indx]
        # Result may be longer than "bytes"
        r = min(len(tmp),bytes)
        message = tmp[:r]
        extra = tmp[r:]
        for s in streams[:-1]:
            self.streams[stream].piece_sent()
        # So only send "bytes" bytes
        self.socket.write(message)
        # Then prepend the extra bytes to the _outqueue
        if len(extra) != 0:
            self._outqueue.insert(0, extra)
        else:
            self.streams[streams[-1]].piece_sent()
        return r

    def uniq_id(self):
        return "%02x:*" % (ord(self.id))
