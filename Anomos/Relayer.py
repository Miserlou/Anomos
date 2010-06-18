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
from Anomos import LOG as log

class Relayer(AnomosRelayerProtocol):
    """ As a tracking code is being sent, each peer it reaches (other than the
        uploader and downloader) creates a Relayer object to maintain the
        association between the incoming socket and the outgoing socket (so
        that the TC only needs to be sent once).
    """
    def __init__(self, stream_id, neighbor, outnid, data=None, orelay=None):
                    #storage, uprate, downrate, choker, key):
        AnomosRelayerProtocol.__init__(self)
        self.partial_recv = ''
        self.recvd_break = False
        self.sent_break = False

        self.stream_id = stream_id
        self.neighbor = neighbor
        self.manager = neighbor.manager
        self.ratelimiter = neighbor.ratelimiter
        self.measurer = self.manager.relay_measure
        self.choked = True
        self.pre_complete_buffer = []
        self.complete = False
        self.closed = False
        self.next_upload = None
        self.decremented_count = False # Hack to prevent double decrementing of relay count
        self.orelay = orelay
        # Make the other relayer which we'll send data through
        if orelay is None:
            self.manager.make_relay(outnid, data, self)
        elif data is not None:
            self.send_tracking_code(data)

    def set_other_relay(self, r):
        self.orelay = r

    def set_measurer(self, measurer):
        self.measurer = measurer

    def _complete_relay_message(self, msg):
        if not (self.orelay.closed or self.orelay.sent_break):
            self.orelay.send_relay_message(msg)

    def relay_message(self, msg):
        if self.complete:
            self.relay_message = self._complete_relay_message
            self.relay_message(msg)
        else:
            self.pre_complete_buffer.append(msg)

    def send_partial(self, bytes):
        if self.closed or (self.neighbor == None):
            return 0
        b = self.neighbor.send_partial(self.stream_id, bytes)
        self.measurer.update_rate(b)
        return b

    def connection_completed(self):
        log.info("Relay connection %s established" % self.uniq_id())
        self.complete = True
        self.flush_pre_buffer()
        self.orelay.complete = True
        self.orelay.flush_pre_buffer()

    def completion_timeout(self):
        if not self.complete:
            self.close()

    def socket_flushed(self):
        if self.should_queue():
            self.ratelimiter.queue(self)

    def should_queue(self):
        return (self.next_upload is None) and self.neighbor.in_queue(self.stream_id)

    def close(self):
        # Connection was closed locally (as opposed to
        # being closed by receiving a BREAK message)
        if self.closed:
            log.warning("%s: Double close" % self.uniq_id())
            return
        log.info("Closing R %s"%self.uniq_id())
        if self.complete and not self.sent_break:
            self.send_break()
        self.shutdown()

    def shutdown(self):
        if self.closed:
            log.warning("Double close")
            return
        self.closed = True
        if not (self.decremented_count or
                (self.orelay and self.orelay.decremented_count)):
            self.manager.rm_relay(self)
            self.decremented_count = True
        # Tell our orelay to close.
        if self.orelay and not self.orelay.closed:
            self.orelay.ore_closed()
        self.ratelimiter.clean_closed()

    def ore_closed(self):
        """ Closes the connection when a Break has been received by our
            other relay (ore). Called by this object's ore during
            shutdown """
        if self.closed:
            log.warning("Double close")
            return
        if not self.sent_break:
            self.send_break()

    def flush_pre_buffer(self):
        for msg in self.pre_complete_buffer:
            self.relay_message(msg)
        self.pre_complete_buffer = []

    def is_flushed(self):
        return self.neighbor.socket.flushed()

    def got_exception(self, e):
        log.error(e)
        #self.torrent.handle_exception(e)

    def uniq_id(self):
        return "[%02x:%04x]" % (ord(self.neighbor.id), self.stream_id)
