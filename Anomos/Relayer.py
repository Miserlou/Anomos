# Relayer.py
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

# Written by Rich Jones, John Schanck

from Anomos.Protocol.AnomosRelayerProtocol import AnomosRelayerProtocol
from Anomos.Measure import Measure
from Anomos import INFO, CRITICAL, WARNING, ERROR, default_logger

class Relayer(AnomosRelayerProtocol):
    """ As a tracking code is being sent, each peer it reaches (other than the
        uploader and downloader) creates a Relayer object to maintain the
        association between the incoming socket and the outgoing socket (so
        that the TC only needs to be sent once).
    """
    def __init__(self, stream_id, neighbor, outnid,
                    data=None, orelay=None, logfunc=default_logger):
                    #storage, uprate, downrate, choker, key):
        AnomosRelayerProtocol.__init__(self)
        self.stream_id = stream_id
        self.neighbor = neighbor
        self.manager = neighbor.manager
        self.ratelimiter = neighbor.ratelimiter
        self.measurer = self.manager.relay_measure
        self.choked = True
        self.pre_complete_buffer = []
        self.complete = False
        self.closed = False
        self.logfunc = logfunc
        self.next_upload = None
        self.in_queue = 0
        # Make the other relayer which we'll send data through
        if orelay is None:
            self.manager.make_relay(outnid, data, self)
        else:
            self.orelay = orelay
            if data is not None:
                self.send_tracking_code(data)

    def set_other_relay(self, r):
        self.orelay = r

    def set_measurer(self, measurer):
        # Both halves of the relayer should share
        # the same rate measurer.
        self.measurer = measurer

    def _incomplete_relay_message(self, msg):
        if not self.complete:
            # Buffer messages until neighbor connection completes
            self.pre_complete_buffer.append(msg)
        else:
            self.relay_message = self._complete_relay_message
            self.relay_message(msg)

    def _complete_relay_message(self, msg):
        self.orelay.send_relay_message(msg)

    def relay_message(self, msg):
        if self.complete:
            self.relay_message = self._complete_relay_message
            self.relay_message(msg)
        else:
            # Buffer messages until connection is complete
            self.relay_message = self._incomplete_relay_message
            self.relay_message(msg)

    def send_partial(self, bytes):
        b = self.neighbor.send_partial(bytes)
        self.measurer.update_rate(b)
        return b

    def connection_completed(self):
        self.logfunc(INFO, "Relay connection [%02x:%d] established" %
                            (int(ord(self.neighbor.id)),self.stream_id))
        self.complete = True
        self.flush_pre_buffer()
        self.orelay.complete = True
        self.orelay.flush_pre_buffer()

    def connection_closed(self):
        if self.closed:
            return
        self.closed = True
        if not self.recvd_break:
            # Connection must have been closed locally (as opposed to
            # being closed by receiving a BREAK message)
            self.recvd_break = True
            self.send_break()
            # Will be disconnected from NbrLink after CONFIRM
        else:
            # Disconnect from the NeighborLink immediately
            self.neighbor.end_stream(self.stream_id)
        # Tell the NeighborManger to decrease its relay count.
        # Should only be done once per relay pair.
        self.manager.dec_relay_count()
        # Tell our orelay to close.
        self.orelay.ore_closed()
        self.pre_complete_buffer = None

    def ore_closed(self):
        ''' Closes the connection when a Break has been received by our
            other relay (ore). Called by this object by its ore during
            connection_closed '''
        if self.closed:
            return
        self.closed = True
        self.recvd_break = True
        self.send_break()
        self.pre_complete_buffer = None

    def connection_flushed(self):
        if self.next_upload is None and self.in_queue > 0:
            self.ratelimiter.queue(self)

    def close(self):
        self.connection_closed()

    def flush_pre_buffer(self):
        for msg in self.pre_complete_buffer:
            self.relay_message(msg)
        self.pre_complete_buffer = []

    def is_flushed(self):
        return self.neighbor.socket.is_flushed()

    def got_exception(self, e):
        #TODO: This actually needs to be _SingleTorrent.got_exception
        raise e

    def piece_queued(self):
        self.in_queue += 1

    def piece_sent(self):
        self.in_queue -= 1

    def uniq_id(self):
        return "%02x%04x" % (ord(self.neighbor.id), self.stream_id)
