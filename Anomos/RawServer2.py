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
from Anomos import LOG as log
from M2Crypto import Rand, SSL


class P2PServer(SSL.ssl_dispatcher):
    def __init__(self, addr, port, ssl_context, listening_handler):
        SSL.ssl_dispatcher.__init__(self)
        self.create_socket(ssl_context)
        self.socket.setblocking(0)
        self.bind((addr, port))
        self.listen(10)
        self.ssl_ctx = ssl_context
        self.listening_handler = listening_handler

    def handle_accept(self):
        try:
            sock, addr = self.socket.accept()
            mgr = self.listening_handler.get_neighbor_manager(sock)
            AnomosNeighborInitializer(sock, mgr, local=False)
        except:
            import traceback
            log.critical(traceback.format_exc())
            return

    def writable(self):
        return 0


