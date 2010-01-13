import cStringIO

from M2Crypto import EVP
from Anomos.Crypto import global_cryptodir, global_randfile
import Anomos.Crypto

from Anomos import LOG as log
class AESKey:
    def __init__(self, key=None, iv=None, algorithm='aes_256_cfb'):
        """
        @param algorithm: encryption algorithm to use
        @param key: 32 byte string to use as key
        @param iv: 32 byte initalization vector to use
        """
        if None in (global_cryptodir, global_randfile):
            raise CryptoError('RNG not initialized, call initCrypto first')
        self.randfile=global_randfile
        self.algorithm = algorithm

        if key:
            self.key = key
        else:
            self.key = Anomos.Crypto.get_rand()
        if iv:
            self.iv = iv
        else:
            self.iv = Anomos.Crypto.get_rand()
        
        ##keep the ciphers warm, iv only needs to be used once
        self.encCipher = EVP.Cipher(self.algorithm, self.key, self.iv, 1)
        self.decCipher = EVP.Cipher(self.algorithm, self.key, self.iv, 0)

    ##this is where the actual ciphering is done
    def cipher_filter(self, cipher, inf, outf):
        buf=inf.read()
        outf.write(cipher.update(buf))
        outf.write(cipher.final())
        return outf.getvalue()

    def encrypt(self, text):
        """
        @param text: Plaintext to encrypt
        @type text: string
        """
        sbuf=cStringIO.StringIO(text)
        obuf=cStringIO.StringIO()
        encoder = self.encCipher
        encrypted = self.cipher_filter(encoder, sbuf, obuf)
        sbuf.close()
        obuf.close()
        return encrypted

    def decrypt(self, text):
        """
        @param text: Ciphertext to decrypt
        @type text: string
        """
        obuf = cStringIO.StringIO(text)
        sbuf = cStringIO.StringIO()
        decoder = self.decCipher
        decrypted = self.cipher_filter(decoder, obuf, sbuf)
        sbuf.close()
        obuf.close()
        return decrypted
