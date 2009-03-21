# The contents of this file are subject to the BitTorrent Open Source License
# Version 1.0 (the License).  You may not copy or use this file, in either
# source code or executable form, except in compliance with the License.  You
# may obtain a copy of the License at http://www.bittorrent.com/license/.
#
# Software distributed under the License is distributed on an AS IS basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
# for the specific language governing rights and limitations under the
# License.

# Originally written by Bram Cohen. Modified by John Schanck and Rich Jones

import Anomos.crypto as crypto
from Anomos.Connecter import Connection
from Anomos.Relayer import Relayer
from Anomos import BTFailure

class EndPoint(object):
    ''' Encoder objects exist at the torrent level. A client has an encoder
        object for each torrent they're downloading/seeding. The primary
        purpose of the encoder object is to initialize new connections by
        sending tracking codes and creating the uploader/downloader objects.
    '''
    def __init__(self, make_upload, downloader, choker, numpieces, schedulefunc,
                 context):
        self.make_upload = make_upload
        self.downloader = downloader
        self.choker = choker
        self.numpieces = numpieces
        self.schedulefunc = schedulefunc

        self.ratelimiter = context._ratelimiter
        self.raw_server = context._rawserver
        self.config = context.config
        self.download_id = context.infohash
        self.cert = context.certificate
        self.neighbors = context.neighbors
        self.keyring = context.keyring
        self.context = context
        
        #XXX: TEMPORARY HACK
        self.port = context._singleport_listener.port
        
        self.connections = {} # {socket : Connection}
        self.complete_connections = set()
        self.banned = set()
        self.everinc = False
        # XXX: Send keepalives on full chains or just neighbor to neighbor?
        # schedulefunc(self.send_keepalives, config['keepalive_interval'])

    def send_keepalives(self):
        self.schedulefunc(self.send_keepalives,
                          self.config['keepalive_interval'])
        for c in self.complete_connections:
            c.send_keepalive()

    def start_connection(self, tc, aeskey, errorfunc=None):
        if len(self.connections) >= self.config['max_initiate']:
            return
        nid = None
        tclen = len(tc)
        try:
            #TODO: There will eventually be an extra piece of data in the TC to 
            # verify the tracker, get that here too.
            #TODO: Check the TC length
            nid, tc = self.cert.decrypt(tc, True)
        except ValueError, e:
            print "VALUE ERR: ", e
            return #Tampered With
        except Exception, e:
            print "OTHER EXCEPTION", e
            return #Probably a decryption error
        else:
            # Repad to original length
            tc = tc + crypto.getRand(tclen-len(tc))
        loc = self.neighbors.get_location(nid)
        if not self.neighbors.is_complete(nid):
            self.neighbors.schedule_tc(self.send_tc, nid, tc, aeskey)
        elif not loc and errorfunc is not None:
            # No longer connected to this neighbor
            errorfunc()
        else:
            self.send_tc(nid, tc, aeskey)
    
    def send_tc(self, nid, tc, aeskey):
        loc = self.neighbors.get_location(nid)
        print "Sending TC to", hex(ord(nid)), "at", loc
        try:
            c = self.raw_server.start_ssl_connection(loc)
        except Exception,e:
            return
        # Make the local connection for receiving.
        con = Connection(self, c, nid, True, established=True)
        con.e2e_key = aeskey
        self.connections[c] = con
        c.handler = con 
        con.send_tracking_code(tc)

    def connection_completed(self, c):
        c.complete = True
        self.complete_connections.add(c)
        c.upload = self.make_upload(c)
        c.download = self.downloader.make_download(c)
        self.choker.connection_made(c)

    def ever_got_incoming(self):
        return self.everinc

    def how_many_connections(self):
        return len(self.complete_connections)

    def close_connections(self):
        for c in self.connections.itervalues():
            if not c.closed:
                c.connection.close()
                c.closed = True

    def singleport_connection(self, listener, con):
        #It's one of our neighbors so no need to check if the con is banned
        #if con.ip in self.banned:
        #    return
        m = self.config['max_allow_in']
        if m and len(self.connections) >= m:
            return
        self.connections[con.connection] = con
        del listener.connections[con.connection]
        con.owner = self
        con.connection.context = self.context

    def ban(self, ip):
        self.banned.add(ip)


class SingleportListener(object):
    '''SingleportListener gets events from the server sockets (of which there
        is one per torrent), initializes connection objects, and determines
        what to do with the connection once some data has been read.
    '''
    def __init__(self, rawserver, config, neighbors, certificate, keyring):
        self.rawserver = rawserver
        self.config = config
        self.port = 0
        self.ports = {}
        self.torrents = {}
        self.relayers = []
        self.connections = {}
        self.neighbors = neighbors
        self.lookup_loc = self.neighbors.lookup_loc
        self.keyring = keyring
        self.certificate = certificate 
        self.download_id = None
    
    def _check_close(self, port):
        if not port or self.port == port or self.ports[port][1] > 0:
            return
        serversocket = self.ports[port][0]
        self.rawserver.stop_listening(serversocket)
        serversocket.close()
        del self.ports[port]

    def open_port(self, port, config):
        if port in self.ports:
            self.port = port
            return
        serversocket = self.rawserver.create_ssl_serversocket(port, config['bind'], True, config['peer_socket_tos'])
        self.rawserver.start_listening(serversocket, self)
        oldport = self.port
        self.port = port
        self.ports[port] = [serversocket, 0]
        self._check_close(oldport)

    def get_port(self):
        if self.port:
            self.ports[self.port][1] += 1
        return self.port

    def release_port(self, port):
        self.ports[port][1] -= 1
        self._check_close(port)

    def close_sockets(self):
        for serversocket, _ in self.ports.itervalues():
            self.rawserver.stop_listening(serversocket)
            serversocket.close()

    def add_torrent(self, infohash, endpoint):
        if infohash in self.torrents:
            raise BTFailure("Can't start two separate instances of the same "
                            "torrent")
        self.torrents[infohash] = endpoint

    def remove_torrent(self, infohash):
        del self.torrents[infohash]

    def set_torrent(self, conn, infohash):
        if infohash not in self.torrents:
            return
        self.torrents[infohash].singleport_connection(self, conn)
    
    def set_relayer(self, conn, neighborid):
        conn.owner = Relayer(self.rawserver, self.neighbors, conn, neighborid,
                                self.config)
        conn.is_relay = True
        self.relayers.append(conn.owner)
        return conn.owner

    def get_relay_size(self):
        return len(self.relayers)

    def get_relay_rate(self):
        rate = 0
        for r in self.relayers:
            rate  += r.get_rate()
        return rate

    def get_relay_sent(self):
        sent = 0
        for r in self.relayers:
            sent  += r.get_sent()
        return sent
    
    def set_neighbor(self, conn):
        del self.connections[conn.connection]
        conn.owner = self.neighbors
        self.neighbors.connections[conn.connection] = conn
    
    def external_connection_made(self, socket):
        """ 
        Connection came in.
        @param socket: SingleSocket
        """
        con = Connection(self, socket, None, False)
        self.connections[socket] = con
        socket.handler = con

    def replace_connection(self):
        pass
