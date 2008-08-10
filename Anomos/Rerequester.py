# The contents of this file are subject to the BitTorrent Open Source License
# Version 1.0 (the License).  You may not copy or use this file, in either
# source code or executable form, except in compliance with the License.  You
# may obtain a copy of the License at http://www.bittorrent.com/license/.
#
# Software distributed under the License is distributed on an AS IS basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
# for the specific language governing rights and limitations under the
# License.

# Written by Bram Cohen

from threading import Thread
from socket import error, gethostbyname
from random import random, randrange
from binascii import b2a_hex
from base64 import urlsafe_b64encode
from urlparse import urlparse, urlunparse

from Anomos.platform import bttime
from Anomos.zurllib import urlopen, quote, Request
from Anomos.btformats import check_peers
from Anomos.bencode import bdecode
from Anomos import BTFailure, INFO, WARNING, ERROR, CRITICAL

STARTED=0
COMPLETED=1
STOPPED=2

class Rerequester(object):

    def __init__(self, url, config, sched, neighbors, connect, externalsched,
            amount_left, up, down, port, myid, infohash, errorfunc, doneflag,
            upratefunc, downratefunc, ever_got_incoming, diefunc, sfunc, clientkey, trackerkey=None):
    #I would like __init__ to look more like this one day
    #def __init__(self, url, context):
        self.baseurl = url
        self.infohash = infohash
        self.peerid = None
        self.wanted_peerid = myid
        self.port = port
        self.url = None
        self.config = config
        self.last = None
        #self.trackerid = None
        self.announce_interval = 30 * 60
        self.sched = sched
        self.neighbors = neighbors
        #self.howmany = howmany
        self.nbr_connect = neighbors.start_connection
        self.peer_connect = connect
        self.externalsched = externalsched
        self.amount_left = amount_left
        self.up = up
        self.down = down
        self.errorfunc = errorfunc
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
        self.clientkey = clientkey
        self.trackerkey = trackerkey
        self.send_key = True
    
    def _makeurl(self, peerid, port):
        print peerid, len(peerid)
        return ('%s?info_hash=%s&peer_id=%s&port=%s&' %
                (self.baseurl, quote(self.infohash), quote(peerid), str(port)))

    def change_port(self, peerid, port):
        self.wanted_peerid = peerid
        self.port = port
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
            self.url = self._makeurl(self.peerid, self.port)
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
        if self.ever_got_incoming():
            getmore = self.neighbors.count() <= self.config['min_peers'] / 3
        else:
            getmore = self.neighbors.count() < self.config['min_peers']
        if getmore or bttime() - self.last_time > self.announce_interval:
            self._announce()

    def _announce(self, event=None):
        self.current_started = bttime()
        s = ('%s&uploaded=%s&downloaded=%s&left=%s' %
            (self.url, str(self.up() - self.previous_up),
             str(self.down() - self.previous_down), str(self.amount_left())))
        if self.last is not None:
            s += '&last=' + quote(str(self.last))
        #if self.trackerid is not None:
        #    s += '&trackerid=' + quote(str(self.trackerid))
        if self.neighbors.count() >= self.config['max_initiate']:
            s += '&numwant=0'
        else:
            s += '&compact=1'
        if event is not None:
            s += '&event=' + ['started', 'completed', 'stopped'][event]
        if self.config['ip']:
            s += '&ip=' + gethostbyname(self.config['ip'])
        if self.send_key:
            s += '&pubkey=' + quote(self.clientkey.pub_bin())
            self.send_key = False
        Thread(target=self._rerequest, args=[s, self.peerid]).start()

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
        self.clientkey = None
        self.trackerkey = None

    def _rerequest(self, url, peerid):
        """ Make an HTTP GET request to the tracker """
        # Encrypt query here.
        if self.trackerkey:
            (scheme, netloc, path, pars, query, fragment) = urlparse(url)
            query = "pke=" + urlsafe_b64encode(self.trackerkey.encrypt(query))
            url = urlunparse((scheme, netloc, path, pars, query, fragment))
        request = Request(url)
        if self.config['tracker_proxy']:
            request.set_proxy(self.config['tracker_proxy'], 'http')
        try:
            h = urlopen(request)
            data = h.read()
            h.close()
        # urllib2 can raise various crap that doesn't have a common base
        # exception class especially when proxies are used, at least
        # ValueError and stuff from httplib
        except Exception, e:
            def f(r='Problem connecting to tracker - ' + str(e)):
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
            if r.has_key('pke'):
                r.update(bdecode(self.clientkey.decrypt(r['pke'])))
                del r['pke']
                print r
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
            for x in peers:
                self.nbr_connect((x[0], x[1]), x[2])
            # Start downloads
            for tc in r.get('tracking codes'):
                self.peer_connect(tc)
            if peerid == self.wanted_peerid:
                self.successfunc()
            self._check()
