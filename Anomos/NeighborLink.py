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
from Anomos.EndPoint import EndPoint
from Anomos.Relayer import Relayer
from Anomos.PartialMessageQueue import PartialMessageQueue
from Anomos.Protocol.AnomosNeighborProtocol import AnomosNeighborProtocol
from Anomos.Protocol import PIECE
from Anomos import INFO, WARNING, ERROR, default_logger, trace_on_call

class NeighborLink(AnomosNeighborProtocol):
    ''' NeighborLink handles the socket between two neighbors and keeps
        track of the objects used to manage the active streams between
        those neighbors. '''
    def __init__(self, manager, socket, id, config, ratelimiter, logfunc=default_logger):
        AnomosNeighborProtocol.__init__(self, socket)
        self.id = id
        self.manager = manager
        self.streams = {} # {StreamID : EndPoint or Relayer object}
        if self.started_locally:
            self.next_stream_id = 0
        else:
            self.next_stream_id = 1
        self.pmq = PartialMessageQueue()
        self.config = config
        self.ratelimiter = ratelimiter
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
        if data is None: # Incoming stream
            nxtid = self.incoming_stream_id
        else: # Localy initialized stream
            nxtid = self.next_stream_id
            self.next_stream_id += 1
        self.streams[nxtid] = \
                    EndPoint(nxtid, self, torrent, aeskey, data,
                            logfunc=self.logfunc)
        self.logfunc(INFO, "Starting endpoint")
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
        if orelay is None: # Incoming stream
            nxtid = self.incoming_stream_id
        else: # Locally initialized stream
            nxtid = self.next_stream_id
            self.next_stream_id += 2
        self.streams[nxtid] = \
                    Relayer(nxtid, self, nid, data, orelay,
                            logfunc=self.logfunc)
        return self.streams[nxtid]

    def close_relays(self):
        for s in self.streams.values():
            if isinstance(s, Relayer):
                s.close()

    def end_stream(self, id):
        ''' Terminate the stream with specified stream id. Should be
            called by the stream object which is to be terminated to ensure
            proper shutdown of that stream.
            @param id: Stream id of stream to end
            @type id: int in range 0 to 2**16'''
        self.pmq.remove_by_sid(id)
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
        ''' Inform all streams that the connection is
            flushed so they may requeue themselves if
            they need to '''
        for stream in self.streams.itervalues():
            stream.connection_flushed()

    def send_immediately(self, message):
        self.socket.write(message)

    def queue_message(self, streamid, message):
        self.pmq.queue_message(streamid, message)

    def in_queue(self, id):
        return id in self.pmq.sid_map

    def send_partial(self, numbytes):
        ''' Requests numbytes from the PartialMessageQueue
            to be sent.
            @return: Actual number of bytes sent.'''
        sids,msgs = self.pmq.dequeue_partial(numbytes)
        if len(msgs) == 0:
            return 0
        #TODO: There should really be some kind of error handling here
        #      if this write fails.
        snt = 0
        for i in range(len(sids)):
            f = self.format_message(sids[i], msgs[i])
            self.socket.write(f)
            snt += len(f)
        return snt

    def connection_lost(self, conn):
        assert conn is self.socket
        self.logfunc(WARNING, "Connection lost!")
        for s in self.streams.values():
            s.shutdown()

    def uniq_id(self):
        return "%02x:*" % (ord(self.id))
