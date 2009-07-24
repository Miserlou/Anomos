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

from Anomos.AnomosProtocol import AnomosRelayerProtocol
from Anomos.CurrentRateMeasure import Measure
from Anomos import INFO, CRITICAL, WARNING, default_logger
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
        self.rate_measure = Measure(max_rate_period)
        # Make the other relayer which we'll send data through
        if orelay is None:
            self.orelay = self.manager.make_relay(outnid, data, self)
            self.orelay.set_rate_measurer(self.rate_measure)
        else:
            self.orelay = orelay
            if data is not None:
                self.send_tracking_code(data)
        self.choked = True
        self.unchoke_time = None
        self.sent = 0
        self.buffer = []
        self.complete = False
        self.logfunc = logfunc

    def set_rate_measurer(self, measurer):
        # Both halves of the relayer should share
        # the same rate measurer.
        self.rate_measure = measurer

    def relay_message(self, msg):
        if self.complete:
            self.orelay.send_relay_message(msg)
            self.rate_measure.update_rate(len(msg))
            self.sent += len(msg)
        else: # Buffer messages until connection is complete
            #TODO: buffer size control, message rejection after a certain point.
            self.buffer.append(msg)

    def connection_closed(self):
        self.neighbor.end_stream(self.stream_id)
        self.orelay.send_break()
        self.orelay.neighbor.end_stream(self.orelay.stream_id)

    def connection_completed(self):
        self.logfunc(INFO, "Relay connection %d established" % self.stream_id)
        self.complete = True
        self.flush_buffer()
        self.orelay.complete = True
        self.orelay.flush_buffer()

    def flush_buffer(self):
        #TODO: Check that it's okay to try and send all these at once.
        for msg in self.buffer:
            self.relay_message(msg)
        self.buffer = []

    def get_rate(self):
        return self.uprate.get_rate()

    def get_sent(self):
        return self.sent

    def choke(self):
        if not self.choked:
            self.choked = True
            self.orelay.send_choke()

    def unchoke(self, time):
        if self.choked:
            self.choked = False
            self.unchoke_time = time
            self.orelay.send_unchoke()

    #def sent_choke(self):
    #    assert self.choked
    #    del self.buffer[:]

    #TODO: Doesn't seem to be used, do we need it?
    #def has_queries(self):
    #    return len(self.buffer) > 0
