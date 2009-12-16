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

# Originally written by Bram Cohen. Modified by John Schanck and Rich Jones

from Anomos.Protocol.AnomosEndPointProtocol import AnomosEndPointProtocol
from Anomos import LOG as log

class EndPoint(AnomosEndPointProtocol):
    def __init__(self, stream_id, neighbor, torrent, aes, data=None):
        AnomosEndPointProtocol.__init__(self)
        self.stream_id = stream_id
        self.neighbor = neighbor
        self.manager = neighbor.manager
        self.ratelimiter = neighbor.ratelimiter
        self.torrent = torrent
        self.e2e_key = aes
        self.complete = False
        self.closed = False
        self.choker = None
        self.choke_sent = False
        self.upload = None
        self.next_upload = None
        if data is not None:
            self.send_tracking_code(data)
        else:
            self.send_confirm()
            self.connection_completed()
            log.info("Sent confirm")

    def connection_completed(self):
        ''' Called when a CONFIRM message is received
            indicating that our peer has received our
            tracking code '''
        if self.complete:
            log.warning("Double complete")
            return
        self.complete = True
        self.upload = self.torrent.make_upload(self)
        self.choker = self.upload.choker
        self.choker.connection_made(self)
        self.download = self.torrent.make_download(self)
        self.torrent.add_active_stream(self)

    def connection_flushed(self):
        if self.complete and self.should_queue():
            self.ratelimiter.queue(self)

    def should_queue(self):
        return self.next_upload is None and \
                (self.neighbor.in_queue(self.stream_id) or getattr(self.upload, 'buffer', None))

    def shutdown(self):
        if self.complete and not self.closed:
            self.torrent.rm_active_stream(self)
            self.choker.connection_lost(self)# Must come before changes to
                                             # upload and download
            self.download.disconnected()
            self.choker = None
            self.upload = None
        self.closed = True

    def close(self):
        if self.closed:
            log.warning("Double close")
            return
        log.info("Closing %s"%self.uniq_id())
        if self.complete:
            self.send_break()
        self.shutdown()

    def fatal_error(self, msg=""):
        log.error(msg)
        if self.complete:
            self.send_break()
        self.shutdown()

    def is_flushed(self):
        return self.neighbor.socket.is_flushed()

    def got_exception(self, e):
        if self.manager.deep_exception:
            self.manager.deep_exception(e)

    def uniq_id(self):
        return "%02x:%04x" % (ord(self.neighbor.id), self.stream_id)

    def send_partial(self, amount):
        """ Provides partial sending of messages for RateLimiter """
        if self.closed:
            # Send nothing if the connection is closed.
            return 0
        if self.complete and not self.neighbor.in_queue(self.stream_id):
            # Nothing queued, so grab a piece and queue it with neighbor
            s = self.upload.get_upload_chunk()
            if s is None:
                return 0
            self.send_piece(*s) # s = (index, begin, piece)
        # Give neighbor permission to send "amount" bytes
        return self.neighbor.send_partial(self.stream_id, amount)
