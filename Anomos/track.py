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

# Written by Bram Cohen and John Hoffman
# Modified by Anomos Liberty Enhancements

import os
import re
import sys
import socket

from time import gmtime, strftime
from urlparse import urlparse
from base64 import urlsafe_b64encode as b64encode
from base64 import urlsafe_b64decode as b64decode
from cgi import parse_qs
from traceback import print_exc
from cStringIO import StringIO
from binascii import b2a_hex

import Anomos.Crypto

from Anomos.EventHandler import EventHandler
from Anomos.HTTPS import HTTPSServer
from Anomos.NatCheck import NatCheck
from Anomos.NetworkModel import NetworkModel
from Anomos.bencode import bencode, bdecode, Bencached
from Anomos.btformats import statefiletemplate
from Anomos.parseargs import parseargs, formatDefinitions
from Anomos.parsedir import parsedir
from Anomos import bttime, version, LOG as log

defaults = [
    ('port', 80, "Port to listen on."),
    ('bind', '', 'ip to bind to locally'),
    ('socket_timeout', 15, 'timeout for closing connections'),
    ('timeout_downloaders_interval', 45 * 60, 'seconds between expiring downloaders'),
    ('reannounce_interval', 30 * 60, 'seconds downloaders should wait between reannouncements'),
    ('response_size', 10, 'default number of peers to send in an info message if the client does not specify a number'),
    ('timeout_check_interval', 5,
        'time to wait between checking if any connections have timed out'),
    ('nat_check', 3,
        "how many times to check if a downloader is behind a NAT (0 = don't check)"),
    ('log_nat_checks', 0,
        "whether to add entries to the log for nat-check results"),
    ('min_time_between_log_flushes', 3.0,
        'minimum time it must have been since the last flush to do another one'),
    ('min_time_between_cache_refreshes', 600.0,
        'minimum time in seconds before a cache is considered stale and is flushed'),
    ('allowed_dir', os.getcwd(), 'only allow downloads for .atorrents in this dir (and recursively in subdirectories of directories that have no .atorrent files themselves). If set, torrents in this directory show up on infopage/scrape whether they have peers or not'),
    ('parse_dir_interval', 60, 'how often to rescan the torrent directory, in seconds'),
    ('allowed_controls', 0, 'allow special keys in torrents in the allowed_dir to affect tracker access'),
    ('hupmonitor', 0, 'whether to reopen the log file upon receipt of HUP signal'),
    ('show_infopage', 1, "whether to display an info page when the tracker's root dir is loaded"),
    ('infopage_redirect', '', 'a URL to redirect the info page to'),
    ('show_names', 1, 'whether to display names from allowed dir'),
    ('favicon', '', 'file containing x-icon data to return when browser requests favicon.ico'),
    ('infopage_css', '', 'Style sheet to use on the infopage'),
    ('only_local_override_ip', 2, "ignore the ip GET parameter from machines which aren't on local network IPs (0 = never, 1 = always, 2 = ignore if NAT checking is not enabled). HTTP proxy headers giving address of original client are treated the same as --ip."),
    ('logfile', '', 'file to write the tracker logs, use - for stdout (default)'),
    ('allow_get', 0, 'use with allowed_dir; adds a /file?hash={hash} url that allows users to download the torrent file'),
    ('keep_dead', 0, 'keep dead torrents after they expire (so they still show up on your /scrape and web page). Only matters if allowed_dir is not set'),
    ('scrape_allowed', 'full', 'scrape access allowed (can be none, specific or full)'),
    ('max_give', 200, 'maximum number of peers to give with any one request'),
    ('data_dir', '', 'Directory in which to store cryptographic keys'),
    ('max_path_len', 6, 'Maximum number of hops in a circuit'),
    ('allow_close_neighbors', 0, 'Allow multiple peers at the same IP address. (0 = disallow)')
    ]

alas = 'your file may exist elsewhere in the universe\nbut alas, not here\n'

def isotime(secs = None):
    if secs == None:
        secs = bttime()
    return strftime('%Y-%m-%d %H:%M UTC', gmtime(secs))

http_via_filter = re.compile(' for ([0-9.]+)\Z')

def _get_forwarded_ip(headers):
    if headers.has_key('http_x_forwarded_for'):
        header = headers['http_x_forwarded_for']
        try:
            x,y = header.split(',')
        except:
            return header
        if not is_local_ip(x):
            return x
        return y
    if headers.has_key('http_client_ip'):
        return headers['http_client_ip']
    if headers.has_key('http_via'):
        x = http_via_filter.search(headers['http_via'])
        if x.groups > 0:
            return x.group(1)
    if headers.has_key('http_from'):
        return headers['http_from']
    return None

def get_forwarded_ip(headers):
    x = _get_forwarded_ip(headers)
    if x is None or not is_valid_ipv4(x) or is_local_ip(x):
        return None
    return x

def compact_peer_info(ip, port):
    try:
        s = ( ''.join([chr(int(i)) for i in ip.split('.')])
              + chr((port & 0xFF00) >> 8) + chr(port & 0xFF) )
        if len(s) != 6:
            s = ''
    except:
        s = ''  # not a valid IP, must be a domain name
    return s

def is_valid_ipv4(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)
    except socket.error:
        return False
    else:
        return True

def is_local_ip(ip):
    try:
        v = [int(x) for x in ip.split('.')]
        if v[0] == 10 or v[0] == 127 or v[:2] in ([192, 168], [169, 254]):
            return True
        if v[0] == 172 and v[1] >= 16 and v[1] <= 31:
            return True
    except ValueError:
        return False

def params_factory(dictionary, default=None):
    """
    Function factory that lets us easily get info from dictionaries of the
    form { key : [value], ... }
    @param dictionary: the dict to index into
    @param default: the default value to return if key is not found
    @rtype: function
    """
    def params(key, default=default, d=dictionary):
        if d.has_key(key):
            return d[key]
        return default
    return params

class Tracker(object):

    def __init__(self, config, certificate, event_handler):
        self.config = config
        self.response_size = config['response_size']
        self.max_give = config['max_give']
        self.natcheck = config['nat_check']

        # Set the favicon
        favicon = config['favicon']
        self.favicon = None
        if favicon:
            try:
                h = open(favicon,'rb')
                self.favicon = h.read()
                h.close()
            except Exception, e:
                log.warning("**warning** specified favicon file -- %s -- does not exist." % favicon)
                log.warning('Exception: %s' % str(e))

        # Load the infopage css file
        infopage_css = config['infopage_css']
        self.infopage_css = None
        if infopage_css:
            try:
                h = open(infopage_css,'r')
                self.infopage_css = h.read()
                h.close()
            except Exception, e:
                log.warning("**warning** specified css file -- %s -- does not exist." % infopage_css)
                log.warning('Exception: %s' % str(e))

        self.event_handler = event_handler
        self.schedule = self.event_handler.schedule

        self.certificate = certificate
        self.natcheck_ctx = certificate.get_ctx(allow_unknown_ca=True)

        self.networkmodel = NetworkModel(config)

        self.only_local_override_ip = config['only_local_override_ip']
        if self.only_local_override_ip == 2:
            self.only_local_override_ip = not config['nat_check']

        self.reannounce_interval = config['reannounce_interval']
        self.timeout_downloaders_interval = config['timeout_downloaders_interval']
        self.schedule(self.timeout_downloaders_interval, self.expire_downloaders)

        self.parse_dir_interval = config['parse_dir_interval']
        self.parse_blocked()

        self.allow_get = config['allow_get']

        self.allowed = None
        if config['allowed_dir'] != '':
            self.allowed = {}
            self.allowed_dir = config['allowed_dir']
            self.allowed_dir_files = {}
            self.allowed_dir_blocked = {}
            self.parse_allowed()

        self.show_names = config['show_names']

        self.keep_dead = config['keep_dead']
        self.last_expire = bttime()

    def allow_local_override(self, ip, given_ip):
        return is_valid_ipv4(given_ip) and (
            not self.only_local_override_ip or is_local_ip(ip) )

    def get_infopage(self):
        try:
            hashes = self.networkmodel.get_infohashes()
            if not self.config['show_infopage']:
                return (404, 'Not Found', {'Content-Type': 'text/plain', 'Pragma': 'no-cache'}, alas)
            red = self.config['infopage_redirect']
            if red != '':
                return (302, 'Found', {'Content-Type': 'text/html', 'Location': red},
                        '<A HREF="'+red+'">Click Here</A>')

            s = StringIO()
            s.write('<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd">\n' \
                '<html><head><title>Anomos download info</title>\n')
            if self.favicon is not None:
                s.write('<link rel="shortcut icon" href="/favicon.ico">\n')
            if self.infopage_css:
                s.write('<link rel="stylesheet" type="text/css" href="/infopage.css" />\n')
            s.write('</head>\n<body>\n' \
                '<h3>Anomos download info</h3>\n'\
                '<ul>\n'
                '<li><strong>tracker version:</strong> %s</li>\n' \
                '<li><strong>server time:</strong> %s</li>\n' \
                '</ul>\n' % (version, isotime()))
            if self.allowed is not None:
                if self.show_names:
                    names = [ (value['name'], infohash)
                              for infohash, value in self.allowed.iteritems()]
                else:
                    names = [(None, infohash) for infohash in self.allowed]
            else:
                names = [ (None, infohash) for infohash in hashes]
            if not names:
                s.write('<p>not tracking any files yet...</p>\n')
            else:
                names.sort()
                tc = 0
                td = 0
                ts = 0  # Total size
                nf = 0  # Number of files displayed
                if self.allowed is not None and self.show_names:
                    s.write('<table summary="files" border="1">\n' \
                        '<tr><th>info hash</th><th>torrent name</th><th align="right">size</th><th align="right">complete</th><th align="right">downloading</th></tr>\n')
                else:
                    s.write('<table summary="files" border="1">\n' \
                        '<tr><th>info hash</th><th align="right">complete</th><th align="right">downloading</th></tr>\n')
                for name, infohash in names:
                    c = len(self.networkmodel.complete.get(infohash,[]))
                    tc += c
                    d = len(self.networkmodel.incomplete.get(infohash,[]))
                    td += d
                    if self.allowed is not None and self.show_names:
                        if self.allowed.has_key(infohash):
                            nf += 1
                            sz = self.allowed[infohash]['length']  # size
                            ts += sz
                            if self.allow_get == 1:
                                linkname = '<a href="/file?info_hash=' + b64encode(infohash) + '">' + name + '</a>'
                            else:
                                linkname = name
                            s.write('<tr><td><code>%s</code></td><td>%s</td><td align="right">%s</td><td align="right">%i</td><td align="right">%i</td></tr>\n' \
                                % (b2a_hex(infohash), linkname, size_format(sz), c, d))
                    else:
                        nf += 1
                        s.write('<tr><td><code>%s</code></td><td align="right"><code>%i</code></td><td align="right"><code>%i</code></td></tr>\n' \
                            % (b2a_hex(infohash), c, d))
                if self.allowed is not None and self.show_names:
                    s.write('<tr><td align="right" colspan="2">%i files</td><td align="right">%s</td><td align="right">%i</td><td align="right">%i</td></tr>\n'
                            % (nf, size_format(ts), tc, td))
                else:
                    s.write('<tr><td align="right">%i files</td><td align="right">%i</td><td align="right">%i</td></tr>\n'
                            % (nf, tc, td))
                s.write('</table>\n' \
                    '<ul>\n' \
                    '<li><em>info hash:</em> SHA1 hash of the "info" section of the metainfo (*.atorrent)</li>\n' \
                    '<li><em>complete:</em> number of connected clients with the complete file</li>\n' \
                    '<li><em>downloading:</em> number of connected clients still downloading</li>\n' \
                    '</ul>\n')

            s.write('</body>\n' \
                '</html>\n')
            return (200, 'OK', {'Content-Type': 'text/html; charset=iso-8859-1'}, s.getvalue())
        except:
            print_exc()
            return (500, 'Internal Server Error', {'Content-Type': 'text/html; charset=iso-8859-1'}, 'Server Error')

    def scrapedata(self, infohash, return_name = True):
        c = len(self.networkmodel.complete.get(infohash,[]))
        d = len(self.networkmodel.incomplete.get(infohash,[]))
        f = {'complete': c, 'incomplete': d} #, 'downloaded': n}
        if return_name and self.show_names and self.allowed is not None:
            f['name'] = self.allowed[infohash]['name']
        return f

    def get_scrape(self, paramslist):
        params = params_factory(paramslist)
        fs = {}
        if params('info_hash'):
            if self.config['scrape_allowed'] not in ['specific', 'full']:
                return (401, 'Not Authorized', \
                    {'Content-Type': 'text/plain', 'Pragma': 'no-cache'}, \
                    bencode({'failure reason': 'specific scrape function is not available with this tracker.'}))
            hashes = self.networkmodel.get_infohashes()
            for infohash in params('info_hash'):
                if self.allowed is not None and infohash not in self.allowed:
                    continue
                if infohash in hashes:
                    fs[infohash] = self.scrapedata(infohash)
        else:
            if self.config['scrape_allowed'] != 'full':
                return (401, 'Not Authorized', \
                    {'Content-Type': 'text/plain', 'Pragma': 'no-cache'}, \
                    bencode({'failure reason': 'full scrape function is not available with this tracker.'}))
            if self.allowed is not None:
                hashes = self.allowed
            else:
                hashes = self.networkmodel.get_infohashes()
            for infohash in hashes:
                fs[infohash] = self.scrapedata(infohash)
        return (200, 'OK', {'Content-Type': 'text/plain'}, bencode({'files': fs}))

    def get_file(self, infohash):
         if not self.allow_get:
             return (401, 'Not Authorized', {'Content-Type': 'text/plain',
                                             'Pragma': 'no-cache'},
                         'get function is not available with this tracker.')
         if not self.allowed.has_key(infohash):
             return (404, 'Not Found', {'Content-Type': 'text/plain', \
                                        'Pragma': 'no-cache'}, alas)
         fname = self.allowed[infohash]['file']
         fpath = self.allowed[infohash]['path']
         return (200, 'OK', {'Content-Type': 'application/x-bittorrent',
             'Content-Disposition': 'attachment; filename=' + fname},
             open(fpath, 'rb').read())

    def check_allowed(self, infohash):
        if self.allowed is not None:
            if not self.allowed.has_key(infohash):
                return (401, 'Not Authorized', \
                    {'Content-Type': 'text/plain', 'Pragma': 'no-cache'},\
                    bencode({'failure reason': 'Requested download is not authorized for use with this tracker.'}))
            if self.config['allowed_controls']:
                if self.allowed[infohash].has_key('failure reason'):
                    return (401, 'Not Authorized', \
                        {'Content-Type': 'text/plain', 'Pragma': 'no-cache'}, \
                        bencode({'failure reason': self.allowed[infohash]['failure reason']}))
        if b2a_hex(infohash) in self.blockedhashes:
            return (401, 'Not Authorized', \
                {'Content-Type': 'text/plain', 'Pragma': 'no-cache'},\
                bencode({'failure reason': 'Requested download is not authorized for use with this tracker.'}))
        return None

    def update_peer(self, paramslist, ip, peercert):
        """
        @param paramslist: Parameters from client's GET request
        @param ip: Client's IP address
        @param peercert:
        @type paramslist: list
        @type ip: string
        @type peercert: M2Crypto.X509.X509
        """
        params = params_factory(paramslist)
        peerid = peercert.get_fingerprint('sha256')[-20:]
        simpeer = self.networkmodel.get(peerid)
        if simpeer and not simpeer.cmp_certificate(peercert):
            # Certificate mismatch
            raise ValueError("Certificate mismatch")

        if params('ip') is not None and params('ip') != ip: # Substitute in client-specified IP
            ip = params('ip')  # Client cert is rechecked during NatCheck
                               # to prevent abuse.

        if not simpeer: # Create a new simpeer on first announce
            port = int(params('port'))
            skey = params('sessionid')
            if skey is None:
                raise ValueError("Peer did not provide session key")
            simpeer = self.networkmodel.init_peer(peerid, peercert, ip, port, skey)

        self.networkmodel.update_peer(peerid, ip, paramslist)
        if params('event') != 'stopped':
            port = int(params('port'))
            if simpeer.nat and simpeer.num_natcheck < self.natcheck:
                NatCheck(self.natcheck_ctx, simpeer.natcheck_cb,
                        self.schedule, peerid, ip, port)
            needs = simpeer.num_needed()
            if needs:
                self.networkmodel.rand_connect(peerid, needs)
        return simpeer

    def neighborlist(self, peerid):
        """
        @param peerid: The peer to get the neighbors of
        @returns: {'ip': string, 'port': int, 'nid': chr} for each neighbor
        @rtype: list
        """
        sim = self.networkmodel.get(peerid)
        if not sim:
            return []
        return [{'ip':vals['ip'],   \
                 'port':vals['port'], \
                 'nid':vals['nid']} for vals in sim.neighbors.values()]

    def get_tcs(self, peerid, infohash, count=3):
        """
        Gets a set of tracking codes from the specified peer to 'count' random
        peers who are sharing the torrent specified by 'infohash'.
        @param peerid: PeerID of requesting peer
        @param infohash: Infohash of requested file
        @param count: Number of peers requested
        @type peerid: str
        @type infohash: str
        @type count: int
        """
        paths = self.networkmodel.get_tracking_codes(peerid, infohash, count)
        return paths

    def validate_request(self, paramslist):
        """
        NOTE: MUST be called on input before it is passed to
              other methods.
        @param paramslist: get request from client which has
                           been passed through cgi.parse_qs
        """
        params = params_factory(paramslist)
        infohash = params('info_hash')
        if infohash and len(infohash) != 20:
            raise ValueError('infohash not of length 20')
        if params('event') not in ['started', 'completed', 'stopped', None]:
            raise ValueError('invalid event')
        port = int(params('port',-1))
        if not (0 < port < 65535):
            raise ValueError('invalid or unspecified port')
        dl = params('downloaded')
        if dl and int(dl) < 0:
            raise ValueError('invalid amount downloaded')
        left = params('left')
        if left and int(left) < 0:
            raise ValueError('invalid amount left')
        if params('event') == 'started':
            sessionid = params('sessionid')
            if not sessionid or len(sessionid) != 8:
                raise ValueError('invalid session key')

    def get(self, handler, path, headers):
        paramslist = {}
        params = params_factory(paramslist)

        # Parse the requested URL
        (scheme, netloc, path, pars, query, fragment) = urlparse(path)
        # unquote and strip leading / from path
        path = path.lstrip("/")
        pqs = parse_qs(query)
        try:
            # base64_decode the appropriate fields
            for k in ['info_hash', 'sessionid', 'failed']:
                if pqs.has_key(k):
                    pqs[k] = [b64decode(v) for v in pqs[k]]
        except TypeError, e:
            return (400, 'Bad Request', {'Content-Type': 'text/plain'},
                    bencode({'failure reason':
                                'you sent me garbage - ' + str(e)}))

        # parse_qs returns key/vals in the form {key0:[val0],...}
        # this converts them to {key0:val0,...}
        pqs = dict(zip(pqs.keys(), [q[0] for q in pqs.values()]))
        paramslist.update(pqs)

        ip = handler.addr[0]
        nip = get_forwarded_ip(headers)
        if nip and not self.only_local_override_ip:
            ip = nip


        if path != 'announce':
            # Handle non-announce connections. ie: Tracker scrapes, favicon
            # requests, .atorrent file requests
            return self.handle_browser_connections(path, paramslist)
        else:
            # From this point on we can assume this is an announce. So first
            # we need to get the client's certificate.
            peercert = handler.get_peer_cert()
            if peercert is None:
                return (400, 'Bad Request', {'Content-Type': 'text/plain'},
                        bencode({'failure reason':
                                    'You announced without a certificate'}))

        # Validate the GET request
        try:
            self.validate_request(paramslist)
        except ValueError, e:
            return (400, 'Bad Request', {'Content-Type': 'text/plain'},
                bencode({'failure reason':
                            'You sent me garbage - ' + str(e)}))

        # Update Tracker's information about the peer
        try:
            simpeer = self.update_peer(paramslist, ip, peercert)
        except ValueError, e:
            return (400, 'Bad Request', {'Content-Type': 'text/plain'},
                bencode({'failure reason': str(e)}))

        infohash = params('info_hash')

        # Check if Tracker allows this torrent
        notallowed = self.check_allowed(infohash)
        if notallowed:
            return notallowed

        data = {}
        if params('event') != 'stopped':
            data['peers'] = self.neighborlist(simpeer.name)
            data['tracking codes'] = self.get_tcs(simpeer.name, infohash,
                                                 self.config['response_size'])
            data['interval'] = self.reannounce_interval
        #if paramslist.has_key('scrape'):
        #    data['scrape'] = self.scrapedata(infohash, False)
        return (200, 'OK', {'Content-Type': 'text/plain', 'Pragma':\
                            'no-cache'}, bencode(data))

    def handle_browser_connections(self, path, paramslist):
        if path == '' or path == 'index.html':
            return self.get_infopage()
            #return (200, 'OK', {'Content-Type' : 'text/plain'}, "index.html is not yet implemented")
        if path == 'scrape':
            return self.get_scrape(paramslist)
            #return (200, 'OK', {'Content-Type' : 'text/plain'}, "scrape is not yet implemented")
        if (path == 'file') and paramslist.has_key('info_hash'):
            return self.get_file(paramslist.get('info_hash'))
            #return (200, 'OK', {'Content-Type' : 'text/plain'}, "get file is not yet implemented")
        if path == 'favicon.ico' and self.favicon is not None:
            return (200, 'OK', {'Content-Type' : 'image/x-icon'}, self.favicon)
        if path == 'infopage.css' and self.infopage_css is not None:
            return (200, 'OK', {'Content-Type' : 'text/css'}, self.infopage_css)
        return (404, 'Not Found', {'Content-Type': 'text/plain', 'Pragma': 'no-cache'}, alas)

    def parse_allowed(self):
        self.schedule(self.parse_dir_interval, self.parse_allowed)

        # logging broken .atorrent files would be useful but could confuse
        # programs parsing log files, so errors are just ignored for now
        def ignore(message):
            pass
        r = parsedir(self.allowed_dir, self.allowed, self.allowed_dir_files,
                     self.allowed_dir_blocked, ignore,include_metainfo = False)
        ( self.allowed, self.allowed_dir_files, self.allowed_dir_blocked,
          added, garbage2 ) = r

    def parse_blocked(self):
        self.schedule(self.parse_dir_interval, self.parse_blocked)

        self.blocklist = os.path.join(self.config['data_dir'], "blockedhashes")
        if os.path.exists(self.blocklist):
            self.blockedhashes = [x.strip() for x in open(self.blocklist, "r").readlines()]
        else:
            self.blockedhashes = []

    def expire_downloaders(self):
        if not self.keep_dead:
            for simpeer in self.networkmodel.get_simpeers():
                if simpeer.last_seen < self.last_expire:
                    log.info("Timing out " + str(simpeer.name))
                    self.networkmodel.disconnect(simpeer.name)
        self.last_expire = bttime()
        self.schedule(self.timeout_downloaders_interval, self.expire_downloaders)

def track(args):
    if len(args) == 0:
        print formatDefinitions(defaults, 80)
        return
    try:
        config, files = parseargs(args, defaults, 0, 0)
    except ValueError, e:
        print 'error: ' + str(e)
        print 'run with no arguments for parameter explanations'
        return

    Anomos.Crypto.init(config['data_dir'])
    servercert = Anomos.Crypto.Certificate("server", True, True)
    e = EventHandler()
    t = Tracker(config, servercert, e)
    try:
        ctx = servercert.get_ctx(allow_unknown_ca=True,
                                 req_peer_cert=False,
                                 session="tracker")
        HTTPSServer(config['bind'], config['port'], ctx, t.get)
    except Exception, e:
        log.critical("Cannot start tracker. %s" % e)
    else:
        e.loop()
        print '# Shutting down: ' + isotime()

def size_format(s):
    if (s < 1024):
        r = "%d B" % int(s)
    elif (s < 1048576):
        r = "%.2f KiB" % (s/1024.0)
    elif (s < 1073741824):
        r = "%.2f MiB" % (s/1048576.0)
    elif (s < 1099511627776):
        r = "%.2f GiB" % (s/1073741824.0)
    else:
        r = "%.2f TiB" % (s/1099511627776.0)
    return r

