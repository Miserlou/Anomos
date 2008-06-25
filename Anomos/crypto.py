"""
@author: Rich Jones, John Schanck
@license: see License.txt

anomos. very preliminary. rsa should eventually be replaced with real ssl. requires m2crypto.

RSA padding: pkcs1_oaep_padding
AES cipher: aes_128_cfb

for other functions used directly, look at RSA.py and EVP.py in M2Crypto
"""

import sys
import os
import cStringIO
from binascii import hexlify, unhexlify
from M2Crypto import Rand, RSA, m2, util, EVP

class RSAPubKey:
    def __init__(self, en):
        """
        @param en: exponent and n components of key to initialize new public key from
        @type en: tuple of form (e, n)
        """
        self.pubkey = RSA.new_pub_key(en)

    def encrypt(self, data):
        """
        @type data: string
        @return: ciphertext of data
        
        @todo: Write stream encryption for RSA and/or switch to RSA encrypted AES keys for bulk encryption (for speed)
        """
        return self.pubkey.public_encrypt(data, RSA.pkcs1_oaep_padding)

## Apparently the tracker doesn't use the data_dir like clients do. So I'm storing
## keys in a directory called 'crypto/' within wherever the tracker was run.
## you can specify data_dir='somedir' to put it somewhere else.
class RSAKeyPair(RSAPubKey):
    def __init__(self, alias, data_dir='', crypto_dir='crypto', key_size=1024, padding='pkcs1_oaep_padding'):
        """                
        @param alias: Unique name for the key, can be anything.
        @type alias: string
        @param data_dir: Directory where data is stored
        @param crypto_dir: Directory (under data_dir) to store keys and randfiles in
        @param key_size: Size of keys (in bits) to generate
        @param padding: algorithm to use for padding
        @type padding: string in ('pkcs1_oaep_padding', 'pkcs1_padding', 'sslv23_padding', 'no_padding')
        """
        self.alias = alias
        self.crypto_path = os.path.join(data_dir, crypto_dir)
        if not os.path.exists(self.crypto_path):
            os.mkdir(self.crypto_path)
        self.key_size = key_size
        self.padding = getattr(RSA, padding)
        
        self.pvtkeyfilename = os.path.join(self.crypto_path, '%s-pvt.pem' % (self.alias))
        self.pubkeyfilename = os.path.join(self.crypto_path, '%s-pub.pem' % (self.alias))
        self.randfile = os.path.join(self.crypto_path, 'randpool.dat')
        
        self.pubkey = None
        self.pvtkey = None
        try:
            self.loadKeysFromPEM()
        except IOError:
            self.saveNewPEM()
            self.loadKeysFromPEM()
    
    def saveNewPEM(self):
        """
        Generate new RSA key and save it to file
        """
        Rand.load_file(self.randfile, -1)
        
        rsa = RSA.gen_key(self.key_size, m2.RSA_F4)  ## RSA_F4 == 65537; exponent: 65537 is secure
        
        rsa.save_key(self.pvtkeyfilename)
        rsa.save_pub_key(self.pubkeyfilename)
        
        Rand.save_file(self.randfile)

    def loadKeysFromPEM(self):
        """
        @raise IOError: If invalid path for (pvt/pub)keyfilename
        @raise RSA.RSAError: If keys were already loaded
        """
        if self.pubkey and self.pvtkey:
            raise RSA.RSAError("Key already loaded")
        # Don't bother checking if these paths exist, they'll raise
        # an IOError if they don't and we'll catch that to determine if we need to
        # generate a key.
        self.pvtkey = RSA.load_key(self.pvtkeyfilename)
        self.pubkey = RSA.load_pub_key(self.pubkeyfilename)
    
    # Inherits encrypt function from RSAPubKey
    # def encrypt(self, data)
    
    def decrypt(self, data):
        """
        Decrypts data encrypted with this public key
        
        @type data: string
        """
        if self.pubkey and self.pvtkey:
            return self.pvtkey.private_decrypt(data, self.padding)

class AESKeyManager:
    def __init__(self, data_dir='', crypto_dir='crypto', algorithm='aes_128_cfb'):
        """
        @param data_dir: Directory where data is stored
        @param crypto_dir: Directory (under data_dir) to store keys and randfiles in
        @param algorithm: encryption algorithm to use
        """
        self.crypto_path = os.path.join(data_dir, crypto_dir)
        if not os.path.exists(self.crypto_path):
            os.mkdir(self.crypto_path)
        self.randfile = os.path.join(self.crypto_path, 'randpool.dat')
        self.aeskeys = {}
        self.algorithm = algorithm
    
    def addKey(self, alias, key=None):
        """
        Add key to keyring with name alias, if no key given, generate a new one.
        @type alias: string
        @type key: string
        """
        if key:
            self.aeskeys[alias] = key
        else:
            self.aeskeys[alias] = self.getNewAES()
    
    def getKey(self, alias):
        return self.aeskeys.get(alias, '')
    
    def containsKey(self, alias):
        return self.aeskeys.has_key(alias)
    
    ##this is where the actual ciphering is done
    def cipher_filter(self, cipher, inf, outf):
        while 1:
            buf=inf.read() # This will read whole string, should it be 32 bytes instead?
            if not buf:
                break
            outf.write(cipher.update(buf))
        outf.write(cipher.final())
        return outf.getvalue()
    
    def encrypt(self, key, iv, text):
        """
        @param key: Alias of key to encrypt with
        @type key: string
        @param iv: Initialization vector
        @type iv: string
        @param text: Plaintext to encrypt
        @type text: string
        """
        sbuf=cStringIO.StringIO(text)
        obuf=cStringIO.StringIO()
        encoder = EVP.Cipher(self.algorithm, self.getKey(key), iv, 1)
        encrypted = hexlify(self.cipher_filter(encoder, sbuf, obuf))
        sbuf.close()
        obuf.close()
        return encrypted
    
    def decrypt(self, key, iv, text):
        """
        @param key: Alias of key to decrypt with
        @type key: string
        @param iv: Initialization vector
        @type iv: string
        @param text: Ciphertext to decrypt
        @type text: string
        """
        obuf = cStringIO.StringIO(unhexlify(text))
        sbuf = cStringIO.StringIO()
        decoder = EVP.Cipher(self.algorithm, self.getKey(key), iv, 0)
        decrypted = self.cipher_filter(decoder, obuf, sbuf)
        sbuf.close()
        obuf.close()
        return decrypted
    
    def getNewAES(self):
        """
        @return: 32byte AES key
        @rtype: string
        """
        return getRand32(self.randfile)

    def getNewIV(self):
        return getRand32(self.randfile)


##Moved out of AESManager -- general enough to be a module function.
##32 random bytes
def getRand32(randfile):
    """
    @param randfile: Full path to randfile
    @type randfile: string
    """
    Rand.load_file(randfile, -1)
    rb = Rand.rand_bytes(32);
    Rand.save_file(randfile)
    return rb

      
secret = "Call me subwoofa cause I push so much base!"

def testCrypto():
    # Test AESKeyManager
    km = AESKeyManager()
    km.addKey('12345') #'12345' is an alias for the key, 
    iv = km.getRand32()
    
    print "Unencrypted:", secret

    encrypted = km.encrypt('12345', iv, secret)
    print encrypted
    print km.decrypt('12345', iv,encrypted)
    
    # Test RSAKeyPair
    rsa = RSAKeyPair('WampWamp')
    encrypted = rsa.encrypt(secret)
    print encrypted
    print rsa.decrypt(encrypted)

if __name__ == "__main__":
    testCrypto()
