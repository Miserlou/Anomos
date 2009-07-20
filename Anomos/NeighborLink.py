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
from Anomos.Connection import Connection
from Anomos.AnomosProtocol import AnomosProtocol

class NeighborLink(object):
    def __init__(self, id, manager):
        self.id = id
        self.manager = manager
        #self.ssl_session = None
        self.complete = False
        self.streams = {}   # {StreamID : Connection type object}
    ## Socket Initialization ##
    def start_new_stream(self, ConnectionType):
        self.streams[self.next_stream_id] = ConnectionType()
        self.next_stream_id += 2
