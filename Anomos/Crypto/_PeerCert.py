import hashlib

from M2Crypto import RSA, X509

from Anomos import tobinary
from Anomos.Crypto import global_randfile
import Anomos.Crypto

class PeerCert:
    def __init__(self, certObj):
        self.certificate = certObj
        self.hash_alg = 'sha256'
        self.fingerprint = self.certificate.get_fingerprint(self.hash_alg)
        tmp = X509.load_cert_string(certObj.as_pem()).get_pubkey().get_rsa()
        self.pubkey = RSA.new_pub_key((tmp.e, tmp.n))
        self.randfile = global_randfile

    def cmp(self, certObj):
        return self.fingerprint == certObj.get_fingerprint(self.hash_alg)

    def encrypt(self, data, rmsglen=None):
        """
        @type data: string
        @return: ciphertext of data, format: {RSA encrypted session key}[Checksum(sessionkey, info, content)][msg length][content][padding]
        @rtype: string
        """
        sessionkey = Anomos.Crypto.AESKey()
        # Encrypt the session key which we'll use to bulk encrypt the rest of the data
        esk = self.pubkey.public_encrypt(sessionkey.key+sessionkey.iv, RSA.pkcs1_oaep_padding)
        if rmsglen:
            bmsglen = tobinary(rmsglen)
        else:
            rmsglen = len(data)
            bmsglen = tobinary(len(data))
        checksum = hashlib.sha1(sessionkey.key + bmsglen + data[:rmsglen]).digest()
        content = checksum + bmsglen + data
        padlen = 32-(len(content)%32)
        padding = Anomos.Crypto.get_rand(padlen)
        ciphertext = sessionkey.encrypt(content+padding)
        return esk + ciphertext

