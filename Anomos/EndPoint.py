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

from Anomos.AnomosProtocol import AnomosEndPointProtocol
from Anomos import BTFailure, ERROR, default_logger

class EndPoint(AnomosEndPointProtocol):
    def __init__(self, stream_id, neighbor, torrent, aes, data=None,
            logfunc=default_logger):
        AnomosEndPointProtocol.__init__(self)
        self.stream_id = stream_id
        self.neighbor = neighbor
        self.torrent = torrent
        self.e2e_key = aes
        self.logfunc = logfunc
        self.complete = False
        self.closed = False
        self.choker = None
        self.next_upload = None
        self.queued = False
        if data is not None:
            self.send_tracking_code(data)
        else:
            self.send_confirm()

    def connection_completed(self):
        self.complete = True
        self.torrent.add_active_stream(self)
        self.upload = self.torrent.make_upload(self)
        self.ratelimiter = self.upload.ratelimiter
        self.download = self.torrent.make_download(self)
        self.choker = self.upload.choker
        self.choker.connection_made(self)

    def connection_closed(self):
        # Called by Connecter, which checks that the connection is complete
        # prior to call
        self.closed = True
        self.torrent.rm_active_stream(self)
        self.choker.connection_lost(self.con)
        self.download.disconnected()
        self.upload = None
        self.neighbor.end_stream(self.stream_id)

    def connection_flushed(self):
        if self.next_upload is None \
            and (self.queued or self.upload.buffer):
                self.ratelimiter.queue(self)

    def close(self):
        self.connection_closed()

    def is_flushed(self):
        return self.neighbor.socket.is_flushed()

    def got_exception(self, e):
        self.logfunc(ERROR, e)

    def uniq_id(self):
        return "%02x%04x" % (ord(self.neighbor.id), self.stream_id)

    def send_partial(self, amount):
        """ Provides partial sending of messages for RateLimiter """
        if self.closed:
            # Send nothing if the connection is closed.
            return 0
        if self.queued == False:
            # Nothing queued, so grab a piece and queue it with neighbor
            s = self.upload.get_upload_chunk()
            if s is None:
                return 0
            index, begin, piece = s
            partial_message = self.partial_msg_str(index, begin, piece)
            # If upload has choked/unchoked and we haven't sent a message
            # to reflect that, send it now.
            if self.choke_sent != self.upload.choked:
                if self.upload.choked:
                    partial_message += self.partial_choke_str()
                    self.upload.sent_choke()
                else:
                    partial_message += self.partial_unchoke_str()
                self.choke_sent = self.upload.choked
            self.neighbor.queue_piece(self.stream_id, partial_message)
            self.queued = True
        # Give neighbor permission to send "amount" bytes
        return self.neighbor.send_partial(amount)

    def piece_sent(self):
        self.queued = False
