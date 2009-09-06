# AnomosNeighborProtocol.py
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

# Written by John Schanck

from Anomos.Protocol import TCODE, CONFIRM, UNCHOKE, CHOKE, RELAY, BREAK, PARTIAL
from Anomos.Protocol import AnomosProtocol, toint
from Anomos import bttime, INFO, WARNING, ERROR, CRITICAL, log_on_call

class AnomosRelayerProtocol(AnomosProtocol):
    ## RelayerProtocol is intended to be implemented by Relayer ##
    def __init__(self):
        AnomosProtocol.__init__(self)
        self.msgmap.update({#CHOKE: self.got_choke,\
                            #UNCHOKE: self.got_unchoke,\
                            CONFIRM: self.got_confirm, \
                            BREAK: self.got_break,\
                            RELAY: self.relay_message,\
                            PARTIAL: self.got_partial})
        self.partial_recv = ''
        self.recvd_break = False
    ## Disable direct message reading. ##
    @log_on_call
    def send_break(self):
        #self.network_ctl_msg(BREAK)
        self.neighbor.queue_message(self.stream_id, BREAK)
        if self.should_queue():
            self.ratelimiter.queue(self)
    def send_tracking_code(self, trackcode):
        self.network_ctl_msg(TCODE, trackcode)
    def send_relay_message(self, msg):
        self.neighbor.queue_message(self.stream_id, msg)
        if self.next_upload is None:
            self.ratelimiter.queue(self)
    def send_confirm(self):
        self.network_ctl_msg(CONFIRM)
    @log_on_call
    def got_break(self):
        self.recvd_break = True
        self.shutdown() # Close inbound connection
    #def got_relay(self, message):
    #    #NOTE: message[0] == RELAY, there's no need to
    #    #      strip this since we'd just have to add
    #    #      it again in send_relay. As a result,
    #    #      send_relay does NOT add a control char.
    #    self.relay_message(message)
    def got_confirm(self):
        self.connection_completed()
        self.relay_message(CONFIRM)
    def got_partial(self, message):
        p_remain = toint(message[1:5])
        self.partial_recv += message[5:]
        if len(self.partial_recv) > self.neighbor.config['max_message_length']:
            self.logfunc(ERROR, "Received message longer than max length, %d"%l)
            return
        if len(message[5:]) == p_remain:
            self.got_message(self.partial_recv)
            self.partial_recv = ''
    #TODO: Analyze effective choking strategies for Relayers
    #def send_choke(self):
    #    self.network_ctl_msg(CHOKE)
    #def send_unchoke(self):
    #    self.network_ctl_msg(UNCHOKE)
    #def got_choke(self):
    #    self.choked = True
    #    self.orelay.send_choke()
    #def got_unchoke(self):
    #    self.choked = False
    #    self.orelay.send_unchoke()
    def invalid_message(self, t):
        self.logfunc(WARNING, \
                "Invalid message of type %02x on %s. Closing stream."% \
                (ord(t), self.uniq_id()))
        self.shutdown()
