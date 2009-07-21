# Relayer.py
#
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

# Written by Rich Jones, John Schanck

from Anomos.Connection import AnomosFwdLink
from Anomos.CurrentRateMeasure import Measure
from Anomos import INFO, CRITICAL, WARNING
from threading import Thread

class Relayer(object):
    """ As a tracking code is being sent, each peer it reaches (other than the
        uploader and downloader) creates a Relayer object to maintain the
        association between the incoming socket and the outgoing socket (so
        that the TC only needs to be sent once).
    """
    def __init__(self, stream_id, nbrmanager, outnid, max_rate_period=20.0):
                    #storage, uprate, downrate, choker, key):
    #   self.rawserver = rawserver
        self.stream_id = streamid
        self.manager = nbrmanager
    #   self.errorfunc = rawserver.errorfunc
    #   self.incoming = incoming
    #   self.outgoing = None
    #   self.connections = {self.incoming:None}
        self.choked = True
        self.unchoke_time = None
        self.uprate = Measure(max_rate_period)
        self.downrate = Measure(max_rate_period)
        self.sent = 0
        self.buffer = []
        self.complete = False

    #   self.tmpnid = outnid
    #   self.start_connection(outnid)
    #   self.rawserver.add_task(self.check_if_established, 1)

    #def check_if_established(self):
    #    if self.outgoing:
    #        for msg in self.buffer:
    #            self.relay_message(self.incoming, msg)
    #        self.buffer = []
    #    else:
    #        self.rawserver.add_task(self.check_if_established, 1)

#### NOTE: Here be obsolete code, keep it until things are working again ####
    #def start_connection(self, nid):
    #    loc = self.neighbors.get_location(nid)
    #    ssls = self.neighbors.get_ssl_session(nid)
    #    self.rawserver.start_ssl_connection(loc, handler=self, session=ssls)

    #def sock_success(self, sock, loc):
    #    if self.connections.has_key(sock):
    #        return
    #    con = AnomosFwdLink(self, sock, self.tmpnid, established=True)
    #    sock.handler = con
    #    self.errorfunc(INFO, "Relay connection started")
    #    self.outgoing = con
    #    self.connections = {self.incoming:self.outgoing, self.outgoing:self.incoming}

    #def sock_fail(self, loc, err=None):
    #    if err:
    #        self.errorfunc(WARNING, err)
    #    #TODO: Do something with error message

    def relay_message(self, msg):
        if self.complete:
            self.partner.send_message(msg)
            self.connections[con].send_relay_message(msg)
            self.uprate.update_rate(len(msg))
            self.sent += len(msg)
        else: # Buffer messages until connection is complete
            #TODO: buffer size control, message rejection after a certain point.
            self.buffer.append(msg)

#### NOTE: Here be obsolete code, keep it until things are working again ####
    #def connection_closed(self, sock):
    #    if sock == self.incoming.connection:
    #        self.outgoing.close()
    #    elif sock == self.outgoing.connection:
    #        self.incoming.close()

    def connection_completed(self, con):
        self.errorfunc(INFO, "Relay connection established")
        self.complete = True

    def get_rate(self):
        return self.uprate.get_rate()

    def get_sent(self):
        return self.sent

    def choke(self):
        if not self.choked:
            self.choked = True
            self.outgoing.send_choke()

    def unchoke(self, time):
        if self.choked:
            self.choked = False
            self.unchoke_time = time
            self.outgoing.send_unchoke()

    def got_choke(self):
        self.choke(self)
        self.incoming.send_choke()

    def got_unchoke(self, time):
        self.unchoke(time)
        self.incoming.send_unchoke()

    #def sent_choke(self):
    #    assert self.choked
    #    del self.buffer[:]

    def has_queries(self):
        return len(self.buffer) > 0

    def set_owner(self, obj):
        self.owner = obj

    def get_owner(self):
        return self.owner
