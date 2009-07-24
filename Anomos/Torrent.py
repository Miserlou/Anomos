# Torrent.py
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

class Torrent(object):
    def __init__(self, infohash, make_upload, downloader, numpieces):
        self.infohash = infohash
        self.make_upload = make_upload
        self.downloader = downloader
        self.make_download = downloader.make_download
        self.numpieces = numpieces

        self.active_streams = []
        self.ever_got_incoming = False
    def add_active_stream(self, endpoint):
        if endpoint not in self.active_streams:
            self.active_streams.append(endpoint)
    def rm_active_stream(self, endpoint):
        if endpoint in self.active_streams:
            self.active_streams.remove(endpoint)
