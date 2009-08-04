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
from threading import Thread

class Relayer(AnomosRelayerProtocol):
    """ As a tracking code is being sent, each peer it reaches (other than the
        uploader and downloader) creates a Relayer object to maintain the
        association between the incoming socket and the outgoing socket (so
        that the TC only needs to be sent once).
    """
    def __init__(self, stream_id, neighbor, outnid,
                    data=None, orelay=None, max_rate_period=20.0,
                    logfunc=default_logger):
                    #storage, uprate, downrate, choker, key):
        AnomosRelayerProtocol.__init__(self)
        self.stream_id = stream_id
        self.neighbor = neighbor
        self.manager = neighbor.manager
        self.ratelimiter = neighbor.ratelimiter
        self.measurer = self.manager.relay_measure
        self.choked = True
        self.unchoke_time = None
        self.pre_complete_buffer = []
        self.complete = False
        self.logfunc = logfunc
        self.next_upload = None
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
        if self.next_upload is None and self.is_flushed():
            self.logfunc(INFO, "Queueing relayer")
            self.ratelimiter.queue(self.orelay)
        self.orelay.send_relay_message(msg)
        self.measurer.update_rate(len(msg))

    def relay_message(self, msg):
        if self.complete:
            self.relay_message = self._complete_relay_message
            self.relay_message(msg)
        else:
            # Buffer messages until connection is complete
            self.relay_message = self._incomplete_relay_message
            self.relay_message(msg)

    def send_partial(self, bytes):
        self.logfunc(INFO, "Sending partial on relayer")
        return self.orelay.neighbor.send_partial(bytes)

    def connection_completed(self):
        self.logfunc(INFO, "Relay connection [%02x:%d] established" %
                            (int(ord(self.neighbor.id)),self.stream_id))
        self.complete = True
        self.flush_buffer()
        self.orelay.complete = True
        self.orelay.flush_buffer()

    def connection_closed(self):
        # if not self.recvd_break?...
        if not self.orelay.recvd_break:
            self.manager.dec_relay_count()
            self.logfunc(INFO, "Sending break on orelay")
            self.orelay.send_break()
        self.pre_complete_buffer = None
        self.neighbor.end_stream(self.stream_id)

    def connection_flushed(self):
        pass

    def close(self):
        self.connection_closed()

    def flush_buffer(self):
        #TODO: Check that it's okay to try and send all these at once.
        for msg in self.pre_complete_buffer:
            self.relay_message(msg)
        self.pre_complete_buffer = []

    def choke(self):
        if not self.choked:
            self.choked = True
            self.orelay.send_choke()

    def unchoke(self, time):
        if self.choked:
            self.choked = False
            self.unchoke_time = time
            self.orelay.send_unchoke()

    def is_flushed(self):
        return self.neighbor.socket.is_flushed()

    def got_exception(self, e):
        self.logfunc(ERROR, e)

    def uniq_id(self):
        return "%02x%04x" % (ord(self.neighbor.id), self.stream_id)
