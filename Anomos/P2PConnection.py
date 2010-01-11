# Connection.py
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

import asynchat
import sys
import traceback

from Anomos import LOG as log
from M2Crypto import SSL

class P2PConnection(asynchat.async_chat):
    def __init__(self, socket=None, addr=None, ssl_ctx=None):
        if socket:
            # Remotely initiated connection
            asynchat.async_chat.__init__(self, socket)
        elif addr and (ssl_ctx is not None):
            # Locally initiated connection
            sslsock = SSL.Connection(ssl_ctx)
            asynchat.async_chat.__init__(self, sslsock)
        else:
            raise RuntimeError("Connection object created without socket or address")

        #XXX XXX XXX XXX XXX XXX XXX XXX XXX XXX#
        #XXX  Proper post connection checks! XXX#
        self.socket.set_post_connection_check_callback(lambda x,y: x != None)
        #########################################

        self.collector = None
        self.new_collector = False
        self.started_locally = (addr != None)
        self.closed = False

        if addr is not None:
            self.connect(addr)

        self.peer_cert = self.get_peer_cert()
        self.peer_ip = self.socket.addr[0]

    def set_collector(self, collector):
        self.collector = collector
        self.new_collector = True

    def get_reader(self):
        if self.collector:
            if self.new_collector:
                self.new_collector = False
            return self.collector.get_reader()
        else:
            log.critical("Request for a reader was made before " + \
                         "a connection was assigned a collector")
            raise RuntimeError("Unable to get data collector")

    ## asynchat.async_chat methods ##

    def collect_incoming_data(self, data):
        if self.collector:
            self.collector.collect_incoming_data(data)
        else:
            log.warning("Dropping %d bytes of data" % len(data))

    def found_terminator(self):
        # Set the terminator equal to the number of bytes
        # the _reader is expecting next
        try:
            self.set_terminator(self.get_reader().next())
        except StopIteration:
            # This represents a context change. The last call to
            # self.get_reader().next() finished the neighbor
            # initialization process and now this object is reading
            # data for a NeighborLink object.
            # TODO: This is kinda ugly. AnomosNeighborInitializer
            # abuses the yield statement to a degree.
            if self.new_collector:
                self.set_terminator(self.get_reader().next())
            else:
                self.close()

    ## asyncore.dispatcher methods ##

    def connect(self, addr):
        self.socket.setblocking(1)
        self.socket.connect(addr)
        self.socket.setblocking(0)

    def handle_write(self):
        try:
            self.initiate_send()
        except SSL.SSLError, err:
            self.handle_error()

    def handle_read(self):
        try:
            asynchat.async_chat.handle_read(self)
        except SSL.SSLError, errstr:
            if "unexpected eof" not in errstr:
                self.handle_error()

    def handle_expt(self):
        log.critical("Exception encountered!")

    def handle_error(self):
        #TODO: Better logging here..
        t, v, tb = sys.exc_info()
        if isinstance(v, KeyboardInterrupt):
            log.critical("Ok")
            raise
        log.critical('\n'+traceback.format_exc())
        self.close()

    def close(self):
        self.closed = True
        if self.collector:
            self.collector.connection_closed()
        self.del_channel()
        self.socket.close()
        self.collector = None
