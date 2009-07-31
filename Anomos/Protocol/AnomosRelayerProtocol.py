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

from Anomos.Protocol import TCODE, CONFIRM, RELAY, BREAK
from Anomos.Protocol import AnomosProtocol
from Anomos import WARNING

class AnomosRelayerProtocol(AnomosProtocol):
    ## RelayerProtocol is intended to be implemented by Relayer ##
    def __init__(self):
        AnomosProtocol.__init__(self)
        self.msgmap.update({BREAK: self.got_break, RELAY: self.got_relay})
    ## Disable direct message reading. ##
    def send_tracking_code(self, trackcode):
        self.network_ctl_msg(TCODE, trackcode)
    def send_relay_message(self, msg):
        self.network_ctl_msg('', msg)
    #TODO: I have no idea if send break works --John
    def got_break(self):
        self.relay_message(BREAK)
        #TODO: Lost uploader, schedule announce for new one..
        if not self.closed:
            self.close()
    def got_relay(self, message):
        #NOTE: message[0] == RELAY, there's no need to
        #      strip this since we'd just have to add
        #      it again in send_relay. As a result,
        #      send_relay does NOT add a control char.
        self.relay_message(message)
    def got_confirm(self):
        self.connection_completed()
        self.relay_message(CONFIRM)
    #TODO: Analyze effective choking strategies for Relayers
    def got_choke(self):
        self.choke(self)
        self.orelay.send_choke()
    def got_unchoke(self, time):
        self.unchoke(time)
        self.orelay.send_unchoke()

    def invalid_message(self, t):
        self.close()
        self.logfunc(WARNING, \
                "Invalid message of type %02x on %s. Closing stream."% \
                (ord(t), self.uniq_id()))
    def close(self):
        self.neighbor.end_stream(self.stream_id)
