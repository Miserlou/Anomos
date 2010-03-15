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

# Originally written by Bram Cohen. Modified by John Schanck and Rich Jones

from random import random
from socket import gethostbyname
from threading import Thread
from base64 import urlsafe_b64encode as b64encode

from Anomos import bttime, BTFailure, LOG as log
import Anomos.Crypto

from Anomos.bencode import bdecode
from Anomos.btformats import check_peers

from M2Crypto import version_info as m2version
from M2Crypto.httpslib import HTTPSConnection
from urlparse import urlparse, urlunparse

## When can we get rid of this
if m2version < (0, 20, 0):
    from M2Crypto.httpslib import ProxyHTTPSConnection as BrokenHTTPSLib
    import urllib
    class ProxyHTTPSConnection(BrokenHTTPSLib):
        """M2Crypto currently fails to cast the port it gets from the url
           string to an integer -- this class hacks around that."""
        def putrequest(self, method, url, skip_host=0, skip_accept_encoding=0):
            #putrequest is called before connect, so can interpret url and get
            #real host/port to be used to make CONNECT request to proxy
            log.warning("Using ProxyHTTPSConnection")
            proto, rest = urllib.splittype(url)
            if proto is None:
                raise ValueError, "unknown URL type: %s" % url
            #get host
            host, rest = urllib.splithost(rest)
            #try to get port
            host, port = urllib.splitport(host)
            #if port is not defined try to get from proto
            if port is None:
                try:
                    port = self._ports[proto]
                except KeyError:
                    raise ValueError, "unknown protocol for: %s" % url
            self._real_host = host
            self._real_port = int(port) #This whole class exists for this line :/
            HTTPSConnection.putrequest(self, method, url, skip_host, skip_accept_encoding)
else:
    from M2Crypto.httpslib import ProxyHTTPSConnection


STARTED=0
COMPLETED=1
STOPPED=2

class Rerequester(object):

    def __init__(self, url, config, schedule, neighbors, amount_left,
            up, down, local_port, infohash, doneflag,
            diefunc, sfunc, certificate, sessionid):
        ##########################
        self.config = config
        self.schedule = schedule
        self.neighbors = neighbors
        self.amount_left = amount_left
        self.up = up
        self.down = down
        self.local_port = local_port
        self.infohash = infohash
        self.doneflag = doneflag
        self.diefunc = diefunc
        self.successfunc = sfunc
        self.certificate = certificate
        self.ssl_ctx = self.certificate.get_ctx(allow_unknown_ca=False)
        self.sessionid = sessionid
        ### Tracker URL ###
        self.https = True

        parsed = urlparse(url)     # (<scheme>,<netloc>,<path>,<params>,<query>,<fragment>)
        self.url = parsed[1]
        self.remote_port = 5555 # Assume port 5555 by default

        if ":" in self.url:                #   <netloc> = <url>:<port>
            i = self.url.index(":")
            self.remote_port = int(self.url[i+1:])
            self.url = self.url[:i]
        self.path = parsed[2]
        self.basequery = None

        self.failed_peers = []
        self.changed_port = False
        self.announce_interval = 30 * 60
        self.finish = False
        self.current_started = None
        self.fail_wait = None
        self.last_time = None
        self.previous_down = 0
        self.previous_up = 0
        self.warned = False
        self.proxy_url = self.config.get('tracker_proxy', None)
        self.proxy_username = None
        self.proxy_password = None
        if self.proxy_url:
            self.parse_proxy_url()
        if parsed[0] != 'https':
            log.error("You are trying to make an unencrypted connection to a tracker, and this has been disabled for security reasons. Halting.")
            self.https = False

    def parse_proxy_url(self):
        if '@' in self.proxy_url:
            auth, self.proxy_url = self.proxy_url.split('@', 1)
            if ':' in auth:
                self.proxy_username, self.proxy_password = auth.split(':',1)

    def _makequery(self):
        return ('?info_hash=%s&port=%s'%
                (b64encode(self.infohash), str(self.local_port)))

    def change_port(self, port):
        self.local_port = port
        self.changed_port = True
        self._check()

    def begin(self):
        self.schedule(60, self.begin)
        self._check()

    def announce_finish(self):
        self.finish = True
        self._check()

    def announce_stop(self):
        self._announce(STOPPED)

    def _check(self):
        if self.current_started is not None:
            if self.current_started <= bttime() - 58:
                log.warning("Tracker announce still not complete "
                               "%d seconds after starting it" %
                               int(bttime() - self.current_started))
            ## Announce has been hanging for too long, retry it.
            if int(bttime() - self.current_started) >= 180:
                self._announce()
            return
        if self.basequery is None:
            self.basequery = self._makequery()
            self._announce(STARTED)
            return
        if self.changed_port:
            self._announce(STOPPED)
            self.changed_port = False
            self.basequery = None
            self.previous_up = self.up()
            self.previous_down = self.down()
            return
        if self.finish:
            self.finish = False
            self._announce(COMPLETED)
            return
        if self.fail_wait is not None:
            if self.last_time + self.fail_wait <= bttime():
                self._announce(STARTED)
            return
        if self.last_time > bttime() - self.config['rerequest_interval']:
            return
        getmore = bool(self.neighbors.failed_connections())
        #TODO: also reannounce when TCs have failed
        if getmore or bttime() - self.last_time > self.announce_interval:
            self._announce()

    def _announce(self, event=None):
        self.current_started = bttime()
        query = ('%s&uploaded=%d&downloaded=%d&left=%d' %
            (self.basequery, self.up() - self.previous_up,
             self.down() - self.previous_down, self.amount_left()))
        if self.neighbors.count() >= self.config['max_initiate']:
            query += '&numwant=0'
        else:
            query += '&compact=1'
        if event is not None:
            query += '&event=' + ['started', 'completed', 'stopped'][event]
            if event == STARTED:
                query += '&sessionid='+b64encode(self.sessionid)
        if self.config['ip']:
            query += '&ip=' + gethostbyname(self.config['ip'])
        self.failed_peers = self.neighbors.failed_connections()
        if self.failed_peers:
            query += '&failed=' + b64encode(''.join(self.failed_peers))
        Thread(target=self._rerequest, args=[query]).start()

    # Must destroy all references that could cause reference circles
    def cleanup(self):
        self.neighbors = None
        self.connect = None
        self.amount_left = None
        self.up = None
        self.down = None
        self.diefunc = None
        self.successfunc = None

    def _rerequest(self, query):
        """ Make an HTTP GET request to the tracker
            Note: This runs in its own thread.
        """
        log.info("Making announce to " + self.url)
        if not self.https:
            log.warning("Warning: Will not connect to non HTTPS server")
            return
        try:
            if self.proxy_url:
                h = ProxyHTTPSConnection(self.proxy_url, \
                                         username=self.proxy_username, \
                                         password=self.proxy_password, \
                                         ssl_context=self.ssl_ctx)
                s = "https://%s:%d%s%s" % (self.url, self.remote_port, self.path, query)
                h.putrequest('GET', s)
                
                # I suggest that for now, until there is a better solution in python, 
                # that connections with socks proxies be done with:
                #  socat TCP4-LISTEN:5555,fork SOCKS4A:s,socksport=9050 
                #  or use Privoxy:
                #  127.0.0.1:8118
                                    
            else:
                #No proxy url, use normal connection
                h = HTTPSConnection(self.url, self.remote_port, ssl_context=self.ssl_ctx)
                h.putrequest('GET', self.path+query)
            h.endheaders()
            resp = h.getresponse()
            data = resp.read()
            resp.close()
            h.close()
            h = None
        # urllib2 can raise various crap that doesn't have a common base
        # exception class especially when proxies are used, at least
        # ValueError and stuff from httplib
        except Exception, g:
            def f(r='Problem connecting to ' + self.url + ':  ' + str(g)):
                self._postrequest(errormsg=r)
        else:
            def f():
                self._postrequest(data)
        self.schedule(0, f)

    def _fail(self):
        if self.fail_wait is None:
            self.fail_wait = 50
        else:
            self.fail_wait *= 1.4 + random() * .2
        self.fail_wait = min(self.fail_wait,
                                self.config['max_announce_retry_interval'])

    def _postrequest(self, data=None, errormsg=None):
        self.current_started = None
        self.last_time = bttime()
        if errormsg is not None:
            log.warning(errormsg)
            self._fail()
            return
        try:
            # Here's where we receive/decrypt data from the tracker
            r = bdecode(data)
            check_peers(r)
        except BTFailure, e:
            if data != '':
                log.error('bad data from tracker - ' + str(e))
            self._fail()
            return
        if r.has_key('failure reason'):
            if self.neighbors.count() > 0:
                log.error('rejected by tracker - ' + r['failure reason'])
            else:
                log.critical("Aborting the torrent as it was " \
                    "rejected by the tracker while not connected to any peers. " \
                    "Message from the tracker:\n" + r['failure reason'])
            self._fail()
            return
        elif self.neighbors is None:
            # Torrent may have been closed before receiving a response
            # from the tracker.
            self._fail()
            return
        else:
            self.fail_wait = None
            if r.has_key('warning message'):
                log.error('warning from tracker - ' + r['warning message'])
            self.announce_interval = r.get('interval', self.announce_interval)
            self.config['rerequest_interval'] = self.announce_interval
                                                #r.get('min interval', self.config['rerequest_interval'])

            if r.has_key('peers'):
                p = r.get('peers')
                if p is None:
                    return
                peers = self._parsepeers(p)

                # Remove any successfuly reported failed peers
                self.neighbors.remove_reported_failids(self.failed_peers)
                # Initialize any new neighbors
                self.neighbors.update_neighbor_list(peers)
                # Start downloads
                for aes, tc in r.get('tracking codes', []):
                    self.neighbors.start_circuit(tc, self.infohash, Anomos.Crypto.AESKey(aes[:32], aes[32:]))
                if self.basequery is not None: # We've recently made a successful
                    self.successfunc()     # request of type STARTED or COMPLETED
                self._check()

    def _parsepeers(self, p):
        peers = []
        if type(p) == str:
            for x in xrange(0, len(p), 6):
                ip = '.'.join([str(ord(i)) for i in p[x:x+4]])
                log.info("Got peer %s"%ip)
                port = (ord(p[x+4]) << 8) | ord(p[x+5])
                peers.append((ip, port, None))
        else:
            for x in p:
                log.info("Got peer %s"%str(x['ip']))
                peers.append((x['ip'], x['port'], x.get('nid')))
        return peers
