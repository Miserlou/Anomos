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
import traceback
import socket

from Anomos import LOG as log
from Anomos.Dispatcher import Dispatcher
from M2Crypto import SSL
from cStringIO import StringIO
from gzip import GzipFile
from time import strftime

class HTTPSConnection(Dispatcher):
    def __init__(self, socket, getfunc, sched):
        Dispatcher.__init__(self, socket)
        self.req = ''
        self.set_terminator('\n')
        self.getfunc = getfunc
        self.sched = sched
        self.timeout_interval = 5
        self.sched(self.timeout_interval, self.timeout)
        self.got_incoming = False
        self.next_func = self.read_type

    def timeout(self):
        if not self.got_incoming:
            self.handle_close()
        else:
            self.got_incoming = False
            self.sched(self.timeout_interval, self.timeout)

    ## HTTP handling methods ##
    def read_type(self, data):
        self.header = data.strip()
        words = data.split()
        if len(words) == 3:
            self.command, self.path, garbage = words
            self.pre1 = False
        elif len(words) == 2:
            self.command, self.path = words
            self.pre1 = True
            if self.command != 'GET':
                return None
        else:
            return None
        if self.command not in ('HEAD', 'GET'):
            return None
        self.headers = {}
        return self.read_header

    def read_header(self, data):
        data = data.strip()
        if data == '':
            # check for Accept-Encoding: header, pick a
            if self.headers.has_key('accept-encoding'):
                ae = self.headers['accept-encoding']
                log.debug("Got Accept-Encoding: " + ae + "\n")
            else:
                #identity assumed if no header
                ae = 'identity'
            # this eventually needs to support multple acceptable types
            # q-values and all that fancy HTTP crap
            # for now assume we're only communicating with our own client
            if ae.find('gzip') != -1:
                self.encoding = 'gzip'
            else:
                #default to identity.
                self.encoding = 'identity'
            r = self.getfunc(self, self.path, self.headers)
            if r is not None:
                self.answer(r)
                return None
        try:
            i = data.index(':')
        except ValueError:
            return None
        self.headers[data[:i].strip().lower()] = data[i+1:].strip()
        log.debug(data[:i].strip() + ": " + data[i+1:].strip())
        return self.read_header

    def answer(self, (responsecode, responsestring, headers, data)):
        if self.encoding == 'gzip':
            #transform data using gzip compression
            #this is nasty but i'm unsure of a better way at the moment
            compressed = StringIO()
            gz = GzipFile(fileobj = compressed, mode = 'wb', compresslevel = 9)
            gz.write(data)
            gz.close()
            compressed.seek(0,0)
            cdata = compressed.read()
            compressed.close()
            if len(cdata) >= len(data):
                self.encoding = 'identity'
            else:
                log.debug("Compressed: %i  Uncompressed: %i\n" % (len(cdata),len(data)))
                data = cdata
                headers['Content-Encoding'] = 'gzip'

        # i'm abusing the identd field here, but this should be ok
        if self.encoding == 'identity':
            ident = '-'
        else:
            ident = self.encoding
        username = '-'
        referer = self.headers.get('referer','-')
        useragent = self.headers.get('user-agent','-')
        timestamp = strftime("%d/%b/%Y:%H:%I:%S")
        log.info('%s %s %s [%s] "%s" %i %i "%s" "%s"' % (
                  self.socket.addr[0], ident, username, timestamp, self.header,
                  responsecode, len(data), referer, useragent))

        r = StringIO()
        r.write('HTTP/1.0 ' + str(responsecode) + ' ' + responsestring + '\r\n')
        if not self.pre1:
            headers['Content-Length'] = len(data)
            for key, value in headers.items():
                r.write(key + ': ' + str(value) + '\r\n')
            r.write('\r\n')
        if self.command != 'HEAD':
            r.write(data)

        self.push(r.getvalue())
        self.close_when_done()

    def getClientIP(self): # For Twisted compatibility
        return self.addr[0]

    ## asynchat.async_chat methods ##
    def collect_incoming_data(self, data):
        self.req += data
        self.got_incoming = True

    def found_terminator(self):
        creq = self.req
        self.req = ''
        if not self.next_func:
            log.info("Malformed request from %s:%d" % self.socket.addr)
            self.handle_close()
            return
        self.next_func = self.next_func(creq)

    def handle_close(self):
        self.socket.set_shutdown(SSL.m2.SSL_SENT_SHUTDOWN|SSL.m2.SSL_RECEIVED_SHUTDOWN)
        self.close()

    def close(self):
        self.del_channel()
        if self.socket.get_shutdown():
            self.socket.close() # SSL.Connection.close()
        else:
            self.socket.clear()
        self.connected = False



class HTTPSServer(asyncore.dispatcher):
    def __init__(self, addr, port, ssl_context, getfunc, sched):
        asyncore.dispatcher.__init__(self)
        self.ssl_ctx=ssl_context
        self.create_socket()
        self.bind((addr, port))
        self.listen(socket.SOMAXCONN)
        self.getfunc = getfunc
        self.sched = sched

    def create_socket(self):
        conn=SSL.Connection(self.ssl_ctx)
        self.set_socket(conn)
        self.socket.setblocking(1)
        self.socket.set_socket_read_timeout(SSL.timeout(5))
        self.socket.set_socket_write_timeout(SSL.timeout(5))
        self.set_reuse_addr()
        self.add_channel()

    def handle_accept(self):
        try:
            sock, addr = self.socket.socket.accept()
        except socket.error, e:
            log.warning("Could not accept socket. %s" % e)
            return

        try:
            ssl = SSL.Connection(self.ssl_ctx, sock)
            ssl.addr = addr
            ssl.setup_ssl()
            ssl.set_accept_state()
            ssl.accept_ssl()
        except SSL.SSLError, e:
            log.warning("Could not accept socket from %s -- %s " % (str(addr), str(e)))
            return
        
        check = getattr(ssl, 'postConnectionCheck', ssl.serverPostConnectionCheck)
        if check is not None and not check(ssl.get_peer_cert(), ssl.addr[0]):
            log.warning('SSL post connection check failed for %s' % str(addr))
            return
        else:
            ssl.setblocking(0)
            HTTPSConnection(ssl, self.getfunc, self.sched)

    def handle_error(self):
        log.critical('\n'+traceback.format_exc())
        self.clear()

    def handle_expt(self):
        log.critical('\n'+traceback.format_exc())
        self.clear()

    def writable(self):
        return False

    def close(self):
        self.del_channel()
        self.socket.close()

    def clear(self):
        self.del_channel()
        self.socket.clear()
