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

# Written by John Schanck

from Anomos.AnomosNeighborInitializer import AnomosNeighborInitializer
class NatCheck(object):

    def __init__(self, resultfunc, peerid, ip, port, rawserver):
        self.resultfunc = resultfunc
        self.peerid = peerid
        self.ip = ip
        self.port = port
        self.id = chr(255)

        rawserver.start_ssl_connection((ip,port), handler=self)

    def sock_success(self, sock, *args):
        self.socket = sock
        AnomosNeighborInitializer(self, sock, self.id)

    def sock_fail(self, *args):
        self.answer(False)

    def initializer_failed(self, *args):
        self.answer(False)

    def answer(self, result):
        self.closed = True
        try:
            self.socket.close()
        except AttributeError:
            pass
        self.resultfunc(self.peerid, result)

    def connection_completed(self, *args):
        self.answer(True)
