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
import socket
import threading

from Anomos import LOG as log
from Anomos.Dispatcher import Dispatcher
from M2Crypto import SSL

class P2PConnection(Dispatcher):
    def __init__(self, socket=None, addr=None, ssl_ctx=None, connect_cb=None,
            schedule=None):
        Dispatcher.__init__(self, socket)

        self.ssl_ctx = ssl_ctx
        self.connect_cb = connect_cb
        self.schedule = schedule
        self.collector = None
        self.new_collector = False
        self.started_locally = (addr is not None)
        self.want_write = False

        if self.started_locally:
            t = threading.Thread(target=self.connect, args=(addr,))
            t.start()

    def set_collector(self, collector):
        self.collector = collector
        self.new_collector = True

    def get_reader(self):
        if self.collector:
            if self.new_collector:
                self.new_collector = False
            return self.collector.get_reader()
        else:
            log.critical("Request for a reader was made before " \
                         "a connection was assigned a collector")
            raise RuntimeError("Unable to get data collector")

    def flushed(self):
        return (self.ac_out_buffer == '') and self.producer_fifo.is_empty()

    ## asynchat.async_chat methods ##

    def writable (self):
        "predicate for inclusion in the writable for select()"
        # return len(self.ac_out_buffer) or len(self.producer_fifo) or
        #        (not self.connected) or self.want_write
        # this is about twice as fast, though not as clear.
        return not (
                (self.ac_out_buffer == '') and
                self.producer_fifo.is_empty() and
                self.connected and
                not self.want_write
                )

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
        sslsock = SSL.Connection(self.ssl_ctx)
        checker = PostConnectionChecker()
        sslsock.set_post_connection_check_callback(checker)
        # TODO: Determine good timeout interval
        sslsock.set_socket_read_timeout(SSL.timeout(10))
        sslsock.set_socket_write_timeout(SSL.timeout(10))
        sslsock.setblocking(1)
        try:
            sslsock.connect(addr)
        except (SSL.SSLError, socket.error):
            # will result in connect_cb being called with
            # self.connected = False
            pass
        else:
            # All socket operations after connect() are non-blocking
            # and handled with asyncore
            sslsock.setblocking(0)
            self.addr = addr
            self.set_socket(sslsock) # registers with asyncore
            self.connected = True # connect_cb success
        if self.schedule is not None:
            # Join back into the main thread
            self.schedule(0, self.do_connect_cb)
        else:
            self.do_connect_cb()

    def handle_connect(self):
        pass

    def do_connect_cb(self):
        # Ensures that connect_cb is only called once.
        if self.connect_cb is not None:
            self.connect_cb(self)
            self.connect_cb = None

    def handle_write(self):
        self.want_write = False
        self.initiate_send()
        if self.flushed():
            self.collector.connection_flushed()

    def handle_close(self):
        log.info("Doing Handle Close")
        if self.collector:
            self.collector.connection_closed()
        self.socket.set_shutdown(SSL.m2.SSL_SENT_SHUTDOWN|SSL.m2.SSL_RECEIVED_SHUTDOWN)
        self.close()

    def close(self):
        log.info("Closing")
        self.del_channel()
        if self.socket.get_shutdown():
            self.socket.close() # SSL.Connection.close()
        else:
            self.socket.clear()
        self.collector = None
        self.connected = False


class PostConnectionChecker(SSL.Checker.Checker):
    def __call__(self, peercert, host=None):
        # Ignore host parameter
        return SSL.Checker.Checker.__call__(self,peercert,None)
