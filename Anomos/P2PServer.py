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

import asyncore
import socket
import traceback

from Anomos import LOG as log
from Anomos.AnomosNeighborInitializer import AnomosNeighborInitializer
from Anomos.P2PConnection import P2PConnection
from M2Crypto import SSL

class P2PServer(asyncore.dispatcher):
    def __init__(self, addr, port, ssl_context):
        asyncore.dispatcher.__init__(self)
        self.create_socket(ssl_context)
        self.bound = False     # The bound variable is to prevent handle_error
        self.bind((addr, port))# from logging errors caused by the following
        self.bound = True      # call to bind. Errors from bind are caught by
                               # _find_port in Multitorrent.
        self.listen(socket.SOMAXCONN)

        # Neighbor Manager is set after the torrent is started
        self.neighbor_manager = None

    def set_neighbor_manager(self, mgr):
        self.neighbor_manager = mgr

    ## asyncore.dispatcher methods ##

    def create_socket(self, ssl_context):
        self.ssl_ctx=ssl_context
        conn=SSL.Connection(self.ssl_ctx)
        self.set_socket(conn)
        self.socket.setblocking(0)
        self.set_reuse_addr()
        self.add_channel()

    def writable(self):
        return False

    def handle_accept(self):
        try:
            sock, addr = self.socket.accept()
        except (SSL.SSLError, socket.error), err:
            log.warning("Problem accepting connection: " + str(err))
            return

        if self.neighbor_manager is None:
            log.warning("Received connection attempt without any active" \
                        "torrents, this could be the port checker or another" \
                        "service trying to connect on this port.")
        else:
            conn = P2PConnection(socket=sock)
            AnomosNeighborInitializer(self.neighbor_manager, conn)

    def handle_connect(self):
        # Connect for this socket implies it tried to bind
        # to a port which was already in use.
        self.close()

    def handle_read(self):
        pass

    def handle_error(self):
        if self.bound:
            log.critical('\n'+traceback.format_exc())
            self.clear()

    def handle_expt(self):
        if self.bound:
            log.critical('\n'+traceback.format_exc())
            self.clear()

    def close(self):
        self.del_channel()
        self.socket.close()

    def clear(self):
        self.del_channel()
        self.socket.clear()
