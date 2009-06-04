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

# Written by Bram Cohen, Modified for Anomos by John Schanck and Rich Jones

import os
import sys
from bisect import insort
import socket
from cStringIO import StringIO
from traceback import print_exc
from errno import EWOULDBLOCK, ENOBUFS
from Anomos.platform import bttime
from Anomos import INFO, CRITICAL, WARNING, FAQ_URL
from Anomos import crypto
from M2Crypto import SSL
from threading import Thread
import random

try:
    from select import poll, error, POLLIN, POLLOUT, POLLERR, POLLHUP
    timemult = 1000
except ImportError:
    from Anomos.selectpoll import poll, error, POLLIN, POLLOUT, POLLERR, POLLHUP
    timemult = 1

class SingleSocket(object):

    def __init__(self, rawserver, sock, handler, context, ip=None):
        self.rawserver = rawserver
        self.socket = sock
        self.handler = handler
        self.context = context
        self.buffer = []
        self.last_hit = bttime()
        self.fileno = sock.fileno()
        self.connected = False
        self.peer_cert = sock.get_peer_cert()
        if ip is not None:
            self.ip = ip
        else: # Try to get the IP from the socket
            try:
                peername = self.socket.getpeername()
            except SSL.SSLError:
                self.ip = 'unknown'
            else:
                try:
                    self.ip = peername[0]
                except:
                    assert isinstance(peername, basestring)
                    self.ip = peername # UNIX socket, not really ip

    def recv(self, bufsize=65536):
        if self.socket is not None:
            return self.socket.recv(bufsize)
        #XXX: This should never happen. Instead, this SingleSocket should be destroyed after the transfer was finished.
        else:
            self.rawserver.errorfunc(WARNING, "recv with no socket")
            return None

    def has_socket(self):
        return self.socket is not None


    def _set_shutdown(self, opt=SSL.SSL_RECEIVED_SHUTDOWN|SSL.SSL_SENT_SHUTDOWN):
        self.socket.set_shutdown(opt)

    def _clear_state(self):
        self.socket = None
        self.buffer = []
        self.handler = None
        self.buffer = None
        self.connected = False

    def close(self):
        self._set_shutdown()
        self.socket.close()
        self._clear_state()
        del self.rawserver.single_sockets[self.fileno]
        self.rawserver.poll.unregister(self.fileno)

#    def clear(self):
#        self._set_shutdown()
#        self.socket.clear()
#        self._clear_state()

    def is_flushed(self):
        return len(self.buffer) == 0

    def write(self, s):
        if self.socket is not None:
            self.buffer.append(s)
            if len(self.buffer) == 1:
                self.try_write()
        else:
            self.rawserver.dead_from_write.append(self)

    def try_write(self):
        if self.connected:
            try:
                while self.buffer:
                    amount = self.socket.send(self.buffer[0])
                    if amount != len(self.buffer[0]):
                        if amount != 0:
                            self.buffer[0] = self.buffer[0][amount:]
                        break
                    del self.buffer[0]
            except SSL.SSLError, e:
                code, msg = e
                if code != EWOULDBLOCK:
                    #self.rawserver.add_task(self.rawserver._safe_shutdown, self)
                    self.rawserver.dead_from_write.append(self)
                    return
        if self.buffer == []:
            self.rawserver.poll.register(self.socket, POLLIN)
        else:
            self.rawserver.poll.register(self.socket, POLLIN | POLLOUT)

def default_error_handler(x, y):
    print x, y


class RawServer(object):

    def __init__(self, doneflag, config, certificate, noisy=True,
            errorfunc=default_error_handler, bindaddr='', tos=0):
        self.config = config
        self.bindaddr = bindaddr
        self.certificate = certificate
        self.tos = tos
        self.poll = poll()
        self.single_sockets = {}
        self.dead_from_write = []
        self.doneflag = doneflag
        self.noisy = noisy
        self.errorfunc = errorfunc
        self.funcs = []
        self.externally_added_tasks = []
        self.listening_handlers = {}
        self.serversockets = {}
        self.live_contexts = {None : True}
        self.add_task(self.scan_for_timeouts, self.config['timeout_check_interval'])
        if sys.platform != 'win32':
            self.wakeupfds = os.pipe()
            self.poll.register(self.wakeupfds[0], POLLIN)
        else:
            # Windows doesn't support pipes with select(). Just prevent sleeps
            # longer than a second instead of proper wakeup for now.
            self.wakeupfds = (None, None)
            def wakeup():
                self.add_task(wakeup, 1)
            wakeup()

    def add_context(self, context):
        self.live_contexts[context] = True

    def remove_context(self, context):
        del self.live_contexts[context]
        self.funcs = [x for x in self.funcs if x[2] != context]

    def add_task(self, func, delay, context=None):
        if context in self.live_contexts:
            insort(self.funcs, (bttime() + delay, func, context))

    def external_add_task(self, func, delay, context=None):
        '''Called from a thread other than RawServer's, queues up tasks to be
           in a threadsafe way
        '''
        self.externally_added_tasks.append((func, delay, context))
        # Wake up the RawServer thread in case it's sleeping in poll()
        if self.wakeupfds[1] is not None:
            os.write(self.wakeupfds[1], 'X')

    def scan_for_timeouts(self):
        self.add_task(self.scan_for_timeouts,
                      self.config['timeout_check_interval'])
        t = bttime() - self.config['socket_timeout']
        tokill = [s for s in self.single_sockets.values() if s.last_hit < t]
        map(self._safe_shutdown, tokill)

    def create_ssl_serversocket(self, port, bind='', reuse=False, tos=0):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        #server.set_post_connection_check_callback(None)
        server.setblocking(0)
        server.bind((bind, port))
        server.listen(10)
        return server

    def start_listening(self, serversocket, handler, context=None):
        self.listening_handlers[serversocket.fileno()] = (handler, context)
        self.serversockets[serversocket.fileno()] = serversocket
        self.poll.register(serversocket, POLLIN)

    def stop_listening(self, serversocket):
        del self.listening_handlers[serversocket.fileno()]
        del self.serversockets[serversocket.fileno()]
        self.poll.unregister(serversocket)

    def start_ssl_connection(self, dns, handler=None, context=None,
                                session=None , do_bind=True):
        t = Thread(target=self._start_ssl_connection, \
                        args=(dns, handler, context, session, do_bind))
        t.start()

    def _start_ssl_connection(self, dns, handler=None, context=None,
            session=None, do_bind=True, timeout=15): #TODO: Is timeout long enough?
        self.errorfunc(INFO, "Starting SSL Connection to %s" % str(dns))

        sock = SSL.Connection(self.certificate.getContext())
        if session:
            sock.set_session(session)
        sock.set_socket_read_timeout(SSL.timeout(timeout))
        sock.set_socket_write_timeout(SSL.timeout(timeout))
        #TODO: Better post connection check, this just ensures that the peer
        #      returned a cert
        sock.set_post_connection_check_callback(lambda x,y: x != None)
        try:
            sock.connect(dns)
        except Exception, e:
            #TODO: verify this is the correct behavior
            sock.close()
            if handler:
                def fail():
                    handler.sock_fail(dns, e)
                self.external_add_task(fail, 0)
        else:
            def reg(): #dummy function for external_add_task
                self.register_sock(sock, dns, handler, context)
            self.external_add_task(reg, 0)

    def register_sock(self, sock, dns, handler=None, context=None):
        self.poll.register(sock, POLLIN)
        s = SingleSocket(self, sock, handler, context, dns[0])
        self.single_sockets[sock.fileno()] = s
        if handler:
            handler.sock_success(s, dns)
        return s


#    def wrap_socket(self, sock, handler, context=None, ip=None):
#        sock.setblocking(0)
#        self.poll.register(sock, POLLIN)
#        s = SingleSocket(self, sock, handler, context, ip)
#        self.single_sockets[sock.fileno()] = s
#        return s

    def _handle_events(self, events):
        for sock, event in events:
            s = self.serversockets.get(sock, None)
            if s is not None:
                if event & (POLLHUP | POLLERR):
                    s.close()
                    self.stop_listening(s)
                    self.errorfunc(CRITICAL, 'lost server socket')
                else:
                    self._handle_connection_attempt(sock)
            else:
                # Data came in on a single_socket
                s = self.single_sockets.get(sock, None)
                if s is None: # Not an external connection
                    if sock == self.wakeupfds[0]:
                        # Another thread wrote this just to wake us up.
                        os.read(sock, 1)
                    continue
                s.connected = True
                if event & POLLERR:
                    self._safe_shutdown(s)
                elif event & (POLLIN | POLLHUP):
                    s.last_hit = bttime()
                    data = None
                    try:
                        data = s.recv()
                        if not data:
                            self._safe_shutdown(s)
                        else:
                            self._make_wrapped_call(s.handler.data_came_in, \
                                                    (s, data), s)
                    except SSL.SSLError, errstr:
                        #TODO: Log error message
                        self._safe_shutdown(s)
                # data_came_in could have closed the socket (s.socket = None)
                if event & POLLOUT and s.socket is not None:
                    s.try_write()
                    if s.is_flushed():
                        self._make_wrapped_call(s.handler.connection_flushed, \
                                                    (s,), s)

    def _handle_connection_attempt(self, sock):
        s = self.serversockets.get(sock, None)
        if s is None:
            return
        handler, context = self.listening_handlers[sock]
        try:
            newsock, addr = s.accept()
            conn = SSL.Connection(self.certificate.getContext(), newsock)
            #TODO: Add post connection check
            #conn.set_post_connection_check_callback(...)
            conn.setup_addr(addr)
            conn.set_accept_state()
            conn.setup_ssl()
            conn.accept_ssl()
        except SSL.SSLError, e:
            self.errorfunc(WARNING, "Error handling accepted "\
                           "connection: " + str(e))
        else:
            nss = SingleSocket(self, conn, handler, context)
            self.single_sockets[conn.fileno()] = nss
            self.poll.register(conn, POLLIN)
            self._make_wrapped_call(handler.external_connection_made,\
                                    (nss,), context=context)

    def _pop_externally_added(self):
        while self.externally_added_tasks:
            task = self.externally_added_tasks.pop(0)
            self.add_task(*task)

    def listen_forever(self):
        while not self.doneflag.isSet():
            try:
                self._pop_externally_added()
                if len(self.funcs) == 0:
                    period = 1e9
                else:
                    period = self.funcs[0][0] - bttime()
                    if period < 0:
                        period = 0
                events = self.poll.poll(period * timemult)
                if self.doneflag.isSet():
                    break
                while len(self.funcs) > 0 and self.funcs[0][0] <= bttime():
                    garbage, func, context = self.funcs.pop(0)
                    self._make_wrapped_call(func, (), context=context)
                self._close_dead()
                self._handle_events(events)
                if self.doneflag.isSet():
                    break
                self._close_dead()
            except error, e:
                if self.doneflag.isSet():
                    break
                # I can't find a coherent explanation for what the behavior
                # should be here, and people report conflicting behavior,
                # so I'll just try all the possibilities
                if isinstance(e, (list, tuple)):
                    code = e[0] # May be ENOBUFS
                else:
                    code = e
                if code == ENOBUFS:
                    self.errorfunc(CRITICAL, "Have to exit due to the TCP " \
                                   "stack flaking out. " \
                                   "Please see the FAQ at %s"%FAQ_URL)
                    break
            except KeyboardInterrupt:
                print_exc()
                break
            except:
                data = StringIO()
                print_exc(file=data)
                self.errorfunc(CRITICAL, data.getvalue())
                break

    def _make_wrapped_call(self, function, args, socket=None, context=None):
        try:
            function(*args)
        except KeyboardInterrupt:
            raise
        except Exception, e:         # hopefully nothing raises strings
            # Incoming sockets can be assigned to a particular torrent during
            # a data_came_in call, and it's possible (though not likely) that
            # there could be a torrent-specific exception during the same call.
            # Therefore read the context after the call.
            if socket is not None:
                context = socket.context
            if self.noisy and context is None:
                data = StringIO()
                print_exc(file=data)
                self.errorfunc(CRITICAL, data.getvalue())
            if context is not None:
                context.got_exception(e)

    def _close_dead(self):
        while len(self.dead_from_write) > 0:
            old = self.dead_from_write
            self.dead_from_write = []
            map(self._safe_shutdown, old)

    def _safe_shutdown(self, s):
        if s.socket is not None:
             self._close_socket(s)
#            if not s.socket.get_shutdown():
#                self._clear_socket(s)
#            else:
#                self._close_socket(s)

    def _close_socket(self, s):
        sock = s.socket.fileno()
        self._make_wrapped_call(s.handler.connection_lost, (s,), s)
        s.close()

#    def _clear_socket(self, s):
#        sock = s.socket.fileno()
#        self._make_wrapped_call(s.handler.connection_lost, (s,), s)
#        self.poll.unregister(sock)
#        del self.single_sockets[sock]
#        s.clear()

    def numsockets(self):
        return len(self.single_sockets)
