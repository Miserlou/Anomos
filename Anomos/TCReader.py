import operator

import Anomos.crypto as crypto


class TCReader(object):
    def __init__(self, cert):
        self.cert = cert
    def parseTC(self, tc):
        try:
            # Payload is the readable data at this layer of the onion
            # nextLayer is the encrypted portion for the next peer
            payload, nextLayer = self.cert.decrypt(tc, True)
        except crypto.CryptoError, e:
            #TODO: Log an error message
            return
        else:
            return TCodeData(payload, self.repad(nextLayer, len(tc)))
    def repad(self, layer, size):
        return layer + crypto.getRand(size-len(layer))

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
