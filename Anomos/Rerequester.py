
# Version 1.0 (the License).  You may not copy or use this file, in either
# source code or executable form, except in compliance with the License.  You
# may obtain a copy of the License at http://www.bittorrent.com/license/.
#
# Software distributed under the License is distributed on an AS IS basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
# for the specific language governing rights and limitations under the reply:
# License.

# Originally written by Bram Cohen. Modified by John Schanck and Rich Jones

import os

from threading import Thread
from socket import error, gethostbyname
from random import random, randrange
from binascii import b2a_hex
from base64 import urlsafe_b64encode

from Anomos.platform import bttime
from Anomos.zurllib import urlopen, quote, Request
from Anomos.btformats import check_peers
from Anomos.bencode import bdecode
from Anomos import BTFailure, INFO, WARNING, ERROR, CRITICAL
import Anomos.crypto as crypto
from urlparse import urlparse, urlunparse
from M2Crypto import httpslib, SSL, X509

STARTED=0
COMPLETED=1
STOPPED=2

class Rerequester(object):

    def __init__(self, url, config, sched, neighbors, connect, externalsched,
            amount_left, up, down, local_port, myid, infohash, errorfunc, doneflag,
            upratefunc, downratefunc, ever_got_incoming, diefunc, sfunc,
            certificate, sessionid):
        self.errorfunc = errorfunc
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

        ### Peer info ###
        self.infohash = infohash
        self.peerid = None
        self.wanted_peerid = myid
        self.local_port = local_port
        self.config = config
        self.last = None
        self.announce_interval = 30 * 60
        self.sched = sched
        self.neighbors = neighbors
        self.peer_connect = connect
        self.externalsched = externalsched
        self.amount_left = amount_left
        self.up = up
        self.down = down
        self.doneflag = doneflag
        self.upratefunc = upratefunc
        self.downratefunc = downratefunc
        self.ever_got_incoming = ever_got_incoming
        self.diefunc = diefunc
        self.successfunc = sfunc
        self.finish = False
        self.current_started = None
        self.fail_wait = None
        self.last_time = None
        self.previous_down = 0
        self.previous_up = 0
        self.certificate = certificate
        self.sessionid = sessionid

        if parsed[0] != 'https':
            self.errorfunc(ERROR, "You are trying to make an unencrypted connection to a tracker, and this has been disabled for security reasons. Halting.")
            self.https = False

    def _makequery(self, peerid, port):
        self.errorfunc(INFO, "Connecting with PeerID: %s" %peerid)
        return ('?info_hash=%s&peer_id=%s&port=%s' %
                (quote(self.infohash), quote(peerid), str(port)))

    def change_port(self, peerid, port):
        self.wanted_peerid = peerid
        self.local_port = port
        self.last = None
        #self.trackerid = None
        self._check()

    def begin(self):
        self.sched(self.begin, 60)
        self._check()

    def announce_finish(self):
        self.finish = True
        self._check()

    def announce_stop(self):
        self._announce(STOPPED)

    def _check(self):
        if self.current_started is not None:
            if self.current_started <= bttime() - 58:
                self.errorfunc(WARNING, "Tracker announce still not complete "
                               "%d seconds after starting it" %
                               int(bttime() - self.current_started))
            return
        if self.peerid is None:
            self.peerid = self.wanted_peerid
            self.basequery = self._makequery(self.peerid, self.local_port)
            self._announce(STARTED)
            return
        if self.peerid != self.wanted_peerid:
            self._announce(STOPPED)
            self.peerid = None
            self.previous_up = self.up()
            self.previous_down = self.down()
            return
        if self.finish:
            self.finish = False
            self._announce(COMPLETED)
            return
        if self.fail_wait is not None:
            if self.last_time + self.fail_wait <= bttime():
                self._announce()
            return
        if self.last_time > bttime() - self.config['rerequest_interval']:
            return
        if self.neighbors.failed_connections():
            getmore = True
        elif self.ever_got_incoming():
            getmore = self.neighbors.count() <= self.config['min_peers'] / 3
        else:
            getmore = self.neighbors.count() < self.config['min_peers']
        if getmore or bttime() - self.last_time > self.announce_interval:
            self._announce()

    def _announce(self, event=None):
        self.current_started = bttime()
        query = ('%s&uploaded=%s&downloaded=%s&left=%s' %
            (self.basequery, str(self.up() - self.previous_up),
             str(self.down() - self.previous_down), str(self.amount_left())))
        if self.last is not None:
            query += '&last=' + quote(str(self.last))
        if self.neighbors.count() >= self.config['max_initiate']:
            query += '&numwant=0'
        else:
            query += '&compact=1'
        if event is not None:
            query += '&event=' + ['started', 'completed', 'stopped'][event]
        if event == 0:
            query += '&sessionid='+quote(self.sessionid)
        if self.config['ip']:
            query += '&ip=' + gethostbyname(self.config['ip'])
        failedPeers = self.neighbors.failed_connections()
        if failedPeers:
            query += '&failed=' + quote(''.join(failedPeers))
        Thread(target=self._rerequest, args=[query, self.peerid]).start()

    # Must destroy all references that could cause reference circles
    def cleanup(self):
        self.sched = None
        self.neighbors = None
        self.connect = None
        self.externalsched = lambda *args: None
        self.amount_left = None
        self.up = None
        self.down = None
        self.errorfunc = None
        self.upratefunc = None
        self.downratefunc = None
        self.ever_got_incoming = None
        self.diefunc = None
        self.successfunc = None

    def _rerequest(self, query, peerid):
        """ Make an HTTP GET request to the tracker
            Note: This runs in its own thread.
        """
        if not self.https:
            return
        dcerts = crypto.getDefaultCerts()
        pcertname = str(self.url) + '.pem'
        if pcertname not in dcerts:
            print "\n\nWARNING!:\nThere is no certificate on file for this tracker."
            print "That means we cannot verify the identify the tracker."
            print "Continuing anyway.\n\n"
            ssl_contextual_healing=self.certificate.getContext()
        else:
            ssl_contextual_healing=self.certificate.getVerifiedContext(pcertname)
        try:
            if self.config['tracker_proxy']:
                h = httpslib.ProxyHTTPSConnection(self.config['tracker_proxy'], ssl_context=ssl_contextual_healing)
                h.putrequest('GET', self.url, self.path+query)
            else:
                h = httpslib.HTTPSConnection(self.url, self.remote_port, ssl_context=ssl_contextual_healing)
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
            def f(r='Problem connecting to tracker - ' + str(g)):
                self._postrequest(errormsg=r, peerid=peerid)
        else:
            def f():
                self._postrequest(data, peerid=peerid)
        self.externalsched(f, 0)

    def _fail(self):
        if self.fail_wait is None:
            self.fail_wait = 50
        else:
            self.fail_wait *= 1.4 + random() * .2
        self.fail_wait = min(self.fail_wait,
                                self.config['max_announce_retry_interval'])

    def _postrequest(self, data=None, errormsg=None, peerid=None):
        self.current_started = None
        self.last_time = bttime()
        if errormsg is not None:
            self.errorfunc(WARNING, errormsg)
            self._fail()
            return
        try:
            # Here's where we receive/decrypt data from the tracker
            r = bdecode(data)
            #if r.has_key('pke'):
            #    r.update(bdecode(self.clientkey.decrypt(r['pke'])))
            #    del r['pke'] # Not necessary, but free some space.
            #TODO: update check_peers for Anomos
            #check_peers(r)
        except BTFailure, e:
            if data != '':
                self.errorfunc(ERROR, 'bad data from tracker - ' + str(e))
            self._fail()
            return
        if r.has_key('failure reason'):
            if self.neighbors.count() > 0:
                self.errorfunc(ERROR, 'rejected by tracker - ' +
                               r['failure reason'])
            else:
                # sched shouldn't be strictly necessary
                def die():
                    self.diefunc(CRITICAL, "Aborting the torrent as it was "
                    "rejected by the tracker while not connected to any peers."
                    " Message from the tracker:     " + r['failure reason'])
                self.sched(die, 0)
            self._fail()
        else:
            self.fail_wait = None
            if r.has_key('warning message'):
                self.errorfunc(ERROR, 'warning from tracker - ' +
                               r['warning message'])
            self.announce_interval = r.get('interval', self.announce_interval)
            self.config['rerequest_interval'] = r.get('min interval',
                                            self.config['rerequest_interval'])
            #self.trackerid = r.get('tracker id', self.trackerid)
            self.last = r.get('last')
            p = r['peers']
            peers = []
            if type(p) == str:
                for x in xrange(0, len(p), 6):
                    ip = '.'.join([str(ord(i)) for i in p[x:x+4]])
                    port = (ord(p[x+4]) << 8) | ord(p[x+5])
                    peers.append((ip, port, None))
            else:
                for x in p:
                    peers.append((x['ip'], x['port'], x.get('peer id')))
            ps = len(peers) + self.neighbors.count()
            if ps < self.config['max_initiate']:
                if self.doneflag.isSet():
                    if r.get('num peers', 1000) - r.get('done peers', 0) > ps * 1.2:
                        self.last = None
                else:
                    if r.get('num peers', 1000) > ps * 1.2:
                        self.last = None
            # Initialize any new neighbors
            self.neighbors.update_neighbor_list(peers)
            #for x in peers:
            #    self.nbr_connect((x[0], x[1]), x[2])
            # Start downloads
            for aes, tc in r.get('tracking codes', []):
                #TODO: add error callback
                self.peer_connect(tc, crypto.AESKey(aes[:32], aes[32:]))
            if peerid == self.wanted_peerid:
                self.successfunc()
            self._check()
