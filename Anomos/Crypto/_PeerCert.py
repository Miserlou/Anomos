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

import hashlib

from M2Crypto import RSA, X509, EVP

from Anomos import tobinary
from Anomos.Crypto import global_randfile
import Anomos.Crypto

class PeerCert:
    def __init__(self, certObj):
        self.hash_alg = 'sha256'
        self.fingerprint = certObj.get_fingerprint(self.hash_alg)
        self.pubkey = certObj.get_pubkey().get_rsa()
        # The following prevents a nasty segfault in M2Crypto
        # versions < .19
        # TODO: Ban M2Cryto versions < 0.19 and remove this
        if not isinstance(self.pubkey, RSA.RSA_pub):
            self.pubkey = RSA.new_pub_key((self.pubkey.e, self.pubkey.n))

    def cmp(self, certObj):
        return self.fingerprint == certObj.get_fingerprint(self.hash_alg)

    def encrypt(self, data, payloadlen=None):
        """
        @type data: string
        @return: ciphertext of data, format: {RSA encrypted session key}[Checksum(sessionkey, info, content)][msg length][content][padding]
        @rtype: string
        """
        if payloadlen is None:
            payloadlen = len(data)
        sessionkey = Anomos.Crypto.AESKey()
        enc_asymm = sessionkey.key + sessionkey.iv
        enc_symm = tobinary(payloadlen) + data[:payloadlen]
        # Encrypt the session key which we'll use to bulk encrypt the rest of the data
        esk = self.pubkey.public_encrypt(enc_asymm, RSA.pkcs1_oaep_padding)
        md = EVP.MessageDigest("sha1")
        md.update(enc_asymm + enc_symm)
        checksum = md.digest()
        content = checksum + enc_symm + data[payloadlen:]
        padlen = (-len(content)) % 32
        padding = Anomos.Crypto.get_rand(padlen)
        ciphertext = sessionkey.encrypt(content+padding)
        return esk + ciphertext

