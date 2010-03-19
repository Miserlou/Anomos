# TCReader.py
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

# Written by John Schanck and Rich Jones

import operator
import Anomos.Crypto

class TCReader(object):
    def __init__(self, cert):
        self.cert = cert
    def parseTC(self, tc): # Raises CryptoError!
        # Payload is the readable data at this layer of the onion
        # nextLayer is the encrypted portion for the next peer
        payload, nextLayer = self.cert.decrypt(tc)
        return TCodeData(payload, self.repad(nextLayer, len(tc)))
    def repad(self, layer, size):
        return layer + Anomos.Crypto.get_rand(size-len(layer))

class TCodeData(object):
    # Ranges defined here for easy modification
    TypeRange = (0,1)
    SIDRange = (1,9)
    NIDRange = (9,10)
    IHashRange = (9,29)
    KeyRange = (29,93)

    # TCode Format Types
    RelayType = chr(0)
    TerminalType = chr(1)
    def __init__(self, payload, nextLayer):
        self.type = operator.getslice(payload, *TCodeData.TypeRange)
        self.payload = payload
        self.nextLayer = nextLayer
        if self.type == TCodeData.RelayType:
            self.parseRelayType()
        elif self.type == TCodeData.TerminalType:
            self.parseTerminalType()
    def parseRelayType(self):
        self.sessionID  = operator.getslice(self.payload, *TCodeData.SIDRange)
        self.neighborID = operator.getslice(self.payload, *TCodeData.NIDRange)
    def parseTerminalType(self):
        self.sessionID = operator.getslice(self.payload, *TCodeData.SIDRange)
        self.infohash  = operator.getslice(self.payload, *TCodeData.IHashRange)
        self.keydata   = operator.getslice(self.payload, *TCodeData.KeyRange)
