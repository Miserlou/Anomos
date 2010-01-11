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
from Anomos.Protocol import NAT_CHECK_ID
from Anomos import LOG as log

from Anomos.Protocol import toint

class NeighborLink(AnomosNeighborProtocol):
    ''' NeighborLink handles the socket between two neighbors and keeps
        track of the objects used to manage the active streams between
        those neighbors. '''
    def __init__(self, manager, socket, id, config, ratelimiter):
        AnomosNeighborProtocol.__init__(self, socket)
        self.id = id
        self.manager = manager
        self.streams = {} # {StreamID : EndPoint or Relayer object}
        if self.socket.started_locally:
            self.next_stream_id = 0
        else:
            self.next_stream_id = 1
        self.pmq = PartialMessageQueue()
        self.config = config
        self.ratelimiter = ratelimiter

        self.socket.set_collector(self)
        #Prepare to read messages
        self._reader = self._read_messages()
        self._message = ''

    def get_reader(self):
        return self._reader

    def collect_incoming_data(self, data):
        self._message += data

    def _read_messages(self):
        ''' Read messages off the line and relay or process them
            depending on connection type '''
        while True:
            yield 2 # Stream ID
            stream = toint(self._message)
            handler = self.get_stream_handler(stream)
            self._message = ''
            yield 4   # Message Length
            l = toint(self._message)
            if l > self.config['max_message_length']:
                log.warning("Received message longer than max length")
            #    return
            self._message = ''
            yield l # Payload
            if handler == self:
                # Grab the stream ID to initialize the received stream
                self.incoming_stream_id = stream
            handler.got_message(self._message)
            self._message = ''

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
            self.next_stream_id += 2
        self.streams[nxtid] = \
                    EndPoint(nxtid, self, torrent, aeskey, data)
        log.info("Starting endpoint")
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
                    Relayer(nxtid, self, nid, data, orelay)
        return self.streams[nxtid]

    def close_streams(self):
        for s in self.streams.values():
            if not s.closed:
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
        self.socket.push(message)

    def queue_message(self, streamid, message):
        t = self.streams.has_key(streamid)
        if not t or (t and not self.streams[streamid].sent_break):
            self.pmq.queue_message(streamid, message)

    def in_queue(self, id):
        return self.pmq.msgs.has_key(id) and len(self.pmq.msgs[id]) > 0

    def send_partial(self, sid, numbytes):
        ''' Requests numbytes from the PartialMessageQueue
            to be sent.
            @return: Actual number of bytes sent.'''
        msgs = self.pmq.dequeue_partial(sid, numbytes)
        if len(msgs) == 0:
            return 0
        #TODO: There should really be some kind of error handling here
        #      if this write fails.
        snt = 0
        for i in range(len(msgs)):
            f = self.format_message(sid, msgs[i])
            self.socket.push(f)
            snt += len(f)
        return snt

    def connection_lost(self, conn):
        assert conn is self.socket
        if self.id != NAT_CHECK_ID:
            log.info("Neighbor disconnected")
        self.connection_closed()

    def connection_closed(self):
        self.close_streams()
        self.manager.lost_neighbor(self.id)

    def uniq_id(self):
        return "%02x:*" % (ord(self.id))
