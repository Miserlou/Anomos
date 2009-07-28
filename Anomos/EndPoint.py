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
        if data is not None:
            self.send_tracking_code(data)
        else:
            self.send_confirm()

        self.choker = None
        self._partial_message = None
        self.next_upload = None

    def connection_completed(self):
        self.complete = True
        self.torrent.add_active_stream(self)
        self.upload = self.torrent.make_upload(self)
        self.download = self.torrent.make_download(self)
        self.choker = self.upload.choker
        self.choker.connection_made(self)

    def connection_closed(self):
        # Called by Connecter, which checks that the connection is complete
        # prior to call
        self.send_break()
        self.closed = True
        self.torrent.rm_active_stream(self)
        self.choker.connection_lost(con)
        self.download.disconnected()
        self.upload = None
        self.neighbor.end_stream(self.stream_id)

    def close(self):
        self.connection_closed()

    def send_partial(self, bytes):
        return self.neighbor.send_partial(self, bytes)

    def is_flushed(self):
        return self.neighbor.socket.is_flushed()

    def got_exception(self, e):
        self.logfunc(ERROR, e)

    def uniq_id(self):
        return "%02x%04x" % (ord(self.neighbor.id), self.stream_id)
