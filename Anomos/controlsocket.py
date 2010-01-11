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

# Written my Uoti Urpala

import os
import socket
import sys
import asyncore
import traceback

from Anomos import BTFailure, LOG as log

from Anomos.Protocol import toint, tobinary

class MessageReceiver(asyncore.dispatcher):

    def __init__(self, sock, callback):
        asyncore.dispatcher.__init__(self, sock)
        self.callback = callback
        self._buffer = []
        self._buffer_len = 0
        self._reader = self._read_messages()
        self._next_len = self._reader.next()

    def writable(self):
        return False
    def readable(self):
        return True

    def handle_read(self):
        s = self.socket.recv(4096)
        while True:
            i = self._next_len - self._buffer_len
            if i > len(s):
                self._buffer.append(s)
                self._buffer_len += len(s)
                return
            m = s[:i]
            if self._buffer_len > 0:
                self._buffer.append(m)
                m = ''.join(self._buffer)
                self._buffer = []
                self._buffer_len = 0
            s = s[i:]
            self._message = m
            try:
                self._next_len = self._reader.next()
            except StopIteration:
                self._reader = None
                self.close()
                return

    def _read_messages(self):
        yield 4
        l = toint(self._message)
        yield l
        action = self._message
        yield 4
        l = toint(self._message)
        yield l
        data = self._message
        self.callback(action, data)


class _ControlSocket(asyncore.dispatcher):
    """ ControlSocket interface which is implemented by UnixControlSocket
        and InetControlSocket """
    def __init__(self, config):
        asyncore.dispatcher.__init__(self)
        self.socket_filename = os.path.join(config['data_dir'], 'ui_socket')
        self.callback = None
    def set_callback(self, callback):
        self.callback = callback
    def writable(self):
        return False
    def readable(self):
        return True
    def handle_connect(self):
        pass
    def handle_accept(self):
        assert self.callback is not None
        try:
            sock, addr = self.socket.accept()
        except socket.error, e:
            raise BTFailure("Could not create control socket: "+str(e))
        else:
            MessageReceiver(sock, self.callback)
    def handle_error(self):
        log.critical('\n'+traceback.format_exc())
        self.close()
    def create_socket(self):
        raise NotImplementedError
    def send_command(self):
        raise NotImplementedError

# Version of _ControlSocket which uses Unix sockets
class UnixControlSocket(_ControlSocket):
    def create_socket(self):
        filename = self.socket_filename
        if os.path.exists(filename):
            # If the file already exists, then either the last shutdown was
            # not clean, or there is another Anomos client running.
            try:
                # Check if another client is listening on the socket by
                # trying to send it a command.
                self.send_command('no-op')
            except BTFailure:
                pass
            else:
                raise BTFailure("Could not create control socket: already in use")

            try:
                os.unlink(filename)
            except OSError, e:
                raise BTFailure("Could not remove old control socket filename:"
                                + str(e))
        try:
            self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.socket.setblocking(0)
            self.bind(filename)
        except socket.error, e:
            raise BTFailure("Could not create control socket: "+str(e))
        self.listen(5)
        self._fileno = self.socket.fileno()
        self.add_channel()

    def send_command(self, action, data=''):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        filename = self.socket_filename
        try:
            s.connect(filename)
            s.send(tobinary(len(action)))
            s.send(action)
            s.send(tobinary(len(data)))
            s.send(data)
            s.close()
        except socket.error, e:
            s.close()
            raise BTFailure('Could not send command: ' + str(e))

    def close(self):
        self.del_channel()
        self.socket.close()
        # Try to remove the ui_socket file
        try:
            os.unlink(self.socket_filename)
        except OSError:
            pass


# Version of _ControlSocket which uses INET sockets
class InetControlSocket(_ControlSocket):
    def create_socket(self):
       try:
           reuse = True
           tos = 0
           self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
           if reuse and os.name != 'nt':
               self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
           self.socket.setblocking(0)
           if tos != 0:
              try:
                  self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, tos)
              except:
                  pass
           self.bind(('127.0.0.1', 56881))
           self.listen(5)
       except socket.error, e:
           raise BTFailure("Could not create control socket: "+str(e))
       self._fileno = self.socket.fileno()
       self.add_channel()

    def send_command(self, action, data=''):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect(('127.0.0.1', 56881))
            s.send(tobinary(len(action)))
            s.send(action)
            s.send(tobinary(len(data)))
            s.send(data)
            s.close()
        except socket.error, e:
            s.close()
            raise BTFailure('Could not send command: ' + str(e))

# Set the proper ControlSocket type for the platform we're running on
if sys.platform != 'win32':
    ControlSocket = UnixControlSocket
else:
    ControlSocket = InetControlSocket


