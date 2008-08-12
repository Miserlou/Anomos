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

from socket import error as socketerror

from Anomos.crypto import AESKeyManager
from Anomos.Connecter import Connection
from Anomos import BTFailure


# header, reserved, download id, my id, [length, message]


class Encoder(object):
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
        self.rsakey = context.rsa
        self.neighbors = context.neighbors
        self.keyring = context.keyring
        self.context = context

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
    
    def send_trackingcode(self, nid, tc):
        neighbor = self.neighbors.get(nid)
        if neighbor:
            self.start_connection(neighbor[0], nid)
        
        #Check nid is a neighbor
        #send the TC

    def start_connection(self, tc): #TODO: Error callback?
        if len(self.connections) >= self.config['max_initiate']:
            return
        nid = None
        try:
            #TODO: There will eventually be an extra piece of data in the TC to 
            # verify the tracker, get that here too.
            #TODO: Check the TC length
            nid, tc = self.rsakey.decrypt(tc, True)
            if len(nid) == 1:
                print "NID:", nid
            #TODO: Pad the tc
        except ValueError, e:
            print "VALUE ERR: ", e
            return #Tampered With
        except Exception, e:
            print "OTHER EXCEPTION", e
            return #Probably a decryption error
        loc = self.neighbors.get_location(nid)
        if not self.neighbors.is_complete(nid):
            print "Scheduling"
            self.neighbors.schedule_tc(nid, self.send_tc, tc)
        elif not loc:
                # We're no longer connected to this peer.
                #TODO: Tell the tracker!
                return
        else:
            self.send_tc(nid, tc)
    
    def send_tc(self, nid, tc):
        loc = self.neighbors.get_location(nid)
        print self.neighbors.neighbors
        print "LOCATION:", loc
        try:
            c = self.raw_server.start_connection(loc, None, self.context)
        except socketerror:
            pass
        else:
            # Make the local connection for receiving.
            con = Connection(self, c, nid, True, established=True)
            self.connections[c] = con
            c.handler = con 
            con.send_tracking_code(tc)
            #XXX: Connection_completed only here for testing
            self.connection_completed(con)

    def connection_completed(self, c):
        print "complete"
        self.complete_connections.add(c)
        #if not c.is_relay:
        c.upload = self.make_upload(c)
        c.download = self.downloader.make_download(c)
        
        #else:
        #    r = Relayer(
        #    c.upload = 
        #we're a relayer
        #Initialize outgoing connection: c_out
        #Make a Relayer(c, c_out,...)
        #c.upload = the relayer
        #c.download = the relayer
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
        con.encoder = self
        con.connection.context = self.context

    def ban(self, ip):
        self.banned.add(ip)


class SingleportListener(object):
    '''SingleportListener gets events from the server sockets (of which there
        is one per torrent), initializes connection objects, and determines
        what to do with the connection once some data has been read.
    '''
    def __init__(self, rawserver, config, neighbors, rsakey, keyring):
        self.rawserver = rawserver
        self.config = config
        self.port = 0
        self.ports = {}
        self.torrents = {}
        self.connections = {}
        self.neighbors = neighbors
        self.add_neighbor = neighbors.add_neighbor
        self.keyring = keyring
        self.rsakey = rsakey
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
        serversocket = self.rawserver.create_serversocket(
            port, config['bind'], reuse=True, tos=config['peer_socket_tos'])
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

    def add_torrent(self, infohash, encoder):
        if infohash in self.torrents:
            raise BTFailure("Can't start two separate instances of the same "
                            "torrent")
        self.torrents[infohash] = encoder

    def remove_torrent(self, infohash):
        del self.torrents[infohash]

    def select_torrent(self, conn, infohash):
        if infohash not in self.torrents:
            return
        self.torrents[infohash].singleport_connection(self, conn)

    def external_connection_made(self, socket):
        """ 
        Connection came in.
        @param connection: SingleSocket
        """
        nid = self.neighbors.lookup_loc(socket.ip)
        if nid: 
            # The incomming connection is one of our neighbors
            print "Got an established conn"
            con = Connection(self, socket, nid, False, established=True)
            self.connections[socket] = con
        else:
            # It's a new neighbor, let the NeighborManager handle it.
            con = Connection(self.neighbors, socket, None, False, established=False)
            self.neighbors.connections[socket] = con
        socket.handler = con

    def replace_connection(self):
        pass
