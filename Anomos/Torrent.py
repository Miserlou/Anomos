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

    def __init__(self, infohash=None, make_upload=None, downloader=None,
            numpieces=None, context=None):
        ''' Create a new Torrent object
            @param infohash: The torrent's infohash
            @param make_upload: a function for performing uploads
            @param downloader: A downloader object, for downloading
            @param numpieces: the number of pieces
            @type infohash: string
            @type make_upload: function
            @type downloader: downloader
            @type numpieces: int'''
        self.infohash = infohash
        self.make_upload = make_upload
        self.downloader = downloader
        if downloader is not None:
            self.make_download = downloader.make_download
        self.numpieces = numpieces
        #self.metainfo.infohash is the same as should be the same as self.infohash
        self.metainfo = None
        self.dlpath = None
        self.dl = None
        self.state = None
        self.completion = None
        self.finishtime = None
        self.uptotal = 0
        self.uptotal_old = 0
        self.downtotal = 0
        self.downtotal_old = 0
        self.active_streams = []

        self.context = context

    def add_active_stream(self, endpoint):
        if endpoint not in self.active_streams:
            self.active_streams.append(endpoint)

    def rm_active_stream(self, endpoint):
        if endpoint in self.active_streams:
            self.active_streams.remove(endpoint)

    def close_all_streams(self):
        for s in self.active_streams:
            if not s.closed:
                s.close()

    def handle_exception(self, e):
        if self.context and getattr(self.context, 'got_exception', None):
            self.context.got_exception(e)
