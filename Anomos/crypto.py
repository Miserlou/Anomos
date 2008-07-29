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
import sha
import random
from binascii import b2a_hex, a2b_hex
from M2Crypto import m2, Rand, RSA, util, EVP
##from Anomos import BTFailure

def tobinary(i):
    return (chr(i >> 24) + chr((i >> 16) & 0xFF) + chr((i >> 8) & 0xFF) + chr(i & 0xFF))

def toM2Exp(n):
    return m2.bn_to_mpi(m2.bin_to_bn(tobinary(n)))

class RSAPubKey:
    def __init__(self, keystring, exp=65537, data_dir='', crypto_dir='crypto'):
        """
        @param keystring: "n" value of pubkey to initialize new public key from
        @param exponent: "e" value of pubkey, should always be 65537
        @type keystring: string
        @type exponent: int
        """
        self.pubkey = RSA.new_pub_key((toM2Exp(exp), keystring))
        self.pubkey.check_key()
        self.crypto_path = os.path.join(data_dir, crypto_dir)
        self.randfile = os.path.join(self.crypto_path, 'randpool.dat')
    
    def keyID(self):
        """ 
        @return: SHA digest of string concatenation of exponent and public key
        @rtype: string
        """
        return sha.new(''.join(self.pubkey.pub())).hexdigest()
        
    def encrypt(self, data, rmsglen=None):
        """
        @type data: string
        @return: ciphertext of data, format: {RSA encrypted session key}[Checksum(sessionkey, info, content)][msg length][content][padding]
        @rtype: string
        """
        sessionkey = AESKey(randfile=self.randfile)
        # Encrypt the session key which we'll use to bulk encrypt the rest of the data
        esk = self.pubkey.public_encrypt(sessionkey.key+sessionkey.iv, RSA.pkcs1_oaep_padding)
        if rmsglen:
            bmsglen = tobinary(rmsglen)
        else:
            rmsglen = len(data)
            bmsglen = tobinary(len(data))
        checksum = sha.new(sessionkey.key + bmsglen + data[:rmsglen]).digest()
        content = checksum + bmsglen + data
        padlen = 32-(len(content)%32)
        padding = "".join(chr(random.randint(0,255)) for i in range(padlen))
        ciphertext = sessionkey.encrypt(content+padding)
        return esk + ciphertext
    
    def pub_bin(self):
        """ return: pubkey (without exponent) as binary string """
        # I'm wondering if we shouldn't send the exponent too.
        return self.pubkey.pub()[1]

## Apparently the tracker doesn't use the data_dir like clients do. So I'm storing
## keys in a directory called 'crypto/' within wherever the tracker was run.
## you can specify data_dir='somedir' to put it somewhere else.
class RSAKeyPair(RSAPubKey):
    def __init__(self, alias, data_dir='', crypto_dir='crypto', key_size=1024, padding=RSA.pkcs1_oaep_padding):
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
        self.padding = padding
        
        self.pvtkeyfilename = os.path.join(self.crypto_path, '%s-pvt.pem' % (self.alias))
        self.pubkeyfilename = os.path.join(self.crypto_path, '%s-pub.pem' % (self.alias))
        self.randfile = os.path.join(self.crypto_path, 'randpool.dat')
        
        self.pubkey = None
        self.pvtkey = None
        try:
            self.loadKeysFromPEM()
        except IOError:
            self.saveNewPEM()
    
    def saveNewPEM(self):
        """
        Generate new RSA key, save it to file, and sets this objects 
        pvtkey and pubkey.
        """
        Rand.load_file(self.randfile, -1)
        rsa = RSA.gen_key(self.key_size, m2.RSA_F4)
        self.pvtkey = rsa
        self.pubkey = RSA.new_pub_key(self.pvtkey.pub())
        rsa.save_key(self.pvtkeyfilename)
        rsa.save_pub_key(self.pubkeyfilename)
        Rand.save_file(self.randfile)

    def loadKeysFromPEM(self):
        """
        @raise IOError: If (pvt|pub)keyfilename does not exist
        @raise RSA.RSAError: If wrong password is given
        """
        self.pvtkey = RSA.load_key(self.pvtkeyfilename)
        self.pubkey = RSA.new_pub_key(self.pvtkey.pub())
    
    # Inherits encrypt function from RSAPubKey
    # def encrypt(self, data)

    def sign(self, msg):
        """
        Returns the signature of a message.
        @param msg: The message to sign
        @return signature: The signature of the message from the private key
        """
        dgst = sha1(msg)
        signature = self.pvtkey.private_encrypt(dgst, RSA.pkcs1_padding)
        return signature

    def verify(self, signature, digest):
        """@param: signature: Signature of a document
           @param: digest: the sha1 of that document
           @return: true if verified; false if not
           @rtype: boolean
        """
        ptxt=self.pubkey.public_decrypt(signature, RSA.pkcs1_padding)
        if ptxt!=digest:
            return False
        else:
            return True
    
    def decrypt(self, data, returnpad=False):
        """
        Decrypts data encrypted with this public key
        
        @param data: The data, padding and all, to be decrypted
        @type data: string
        @param returnpad: return "junk" decrypted padding as well as message. Default: False
        @type returnpad: boolean
        
        @raise ValueError: Bad Checksum
        
        @return: tuple (decrypted message, padding) if returnpad is true, string otherwise
        @rtype: tuple
        """
        byte_key_size = self.key_size/8
        # Decrypt the session key and IV with our private key
        tmpsk = self.pvtkey.private_decrypt(data[:byte_key_size], self.padding)
        sk = tmpsk[:32] # Session Key
        iv = tmpsk[32:] # IV
        sessionkey = AESKey(sk, iv, self.randfile)
        # Decrypt the rest of the message with the session key
        content = sessionkey.decrypt(data[byte_key_size:])
        pos = sha.digestsize
        givenchksum = content[:pos] # first 20 bytes
        smsglen = content[pos:pos+4] # next 4 bytes
        imsglen = int(b2a_hex(smsglen), 16)
        pos += 4
        message = content[pos:pos+imsglen]
        pos += imsglen
        mychksum = sha.new(sk+smsglen+message).digest()
        if givenchksum != mychksum:
            raise ValueError("Bad Checksum - Data may have been tampered with") 
        if returnpad:
            return (message, content[pos:])
        else:
            return message


class AESKey:
    def __init__(self, key=None, iv=None, randfile='randpool.dat', algorithm='aes_128_cfb'):
        """
        @param randfile: Path to randfile
        @param algorithm: encryption algorithm to use
        @param key: 32 byte string to use as key
        @param iv: 32 byte initalization vector to use
        """
        #TODO: Check if randfile exists
        self.randfile=randfile
        self.algorithm = algorithm
        
        if key:
            self.key = key
        else:
            self.key = self.newAES()
        if iv:
            self.iv = iv
        else:
            self.iv = self.newIV()

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
        @param key: Alias of key to encrypt with
        @type key: string
        @param iv: Initialization vector
        @type iv: string
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
        @param key: Alias of key to decrypt with
        @type key: string
        @param iv: Initialization vector
        @type iv: string
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
    
    def newAES(self):
        """
        @return: 32byte AES key
        @rtype: string
        """
        return getRand(self.randfile, 32)
    
    def newIV(self):
        return getRand(self.randfile, 32)


class AESKeyManager:
    def __init__(self):
        self.aeskeys = {}
    
    def addKey(self, alias, key):
        """
        Add key to keyring with name alias, if no key given, generate a new one.
        @type alias: string
        @type key: AESKey
        """
        if not self.containsKey(alias):
            self.aeskeys[alias] = key

    def getKey(self, alias):
        return self.aeskeys.get(alias, None)
    
    def containsKey(self, alias):
        return self.aeskeys.has_key(alias)


def getRand(randfile, numBytes=32):
    """
    @param randfile: Full path to randfile
    @type randfile: string
    """
    Rand.load_file(randfile, -1)
    rb = Rand.rand_bytes(numBytes);
    Rand.save_file(randfile)
    return rb

def sha1(msg):
    """
    @param msg: message to digest
    @return: digest: SHA1 digest
    """
    shah=EVP.MessageDigest('sha1')
    shah.update(msg)
    return shah.digest()
    
##class CryptoError(BTFailure):
##    pass

if __name__ == "__main__":
    def testCrypto():
        secret = "Call me subwoofa cause I push so much base!"
        # Test AESKey
        key = AESKey(randfile='crypto/randpool.dat')
        
        print "Unencrypted:", secret

        encrypted = key.encrypt(secret)
        print len(encrypted)
        print b2a_hex(encrypted)
        print key.decrypt(encrypted)
        
        # Test RSAKeyPair
        rsa = RSAKeyPair('tracker')
        encrypted = rsa.encrypt(secret)
        sig = rsa.sign(secret)
        print "Encrypted: ", b2a_hex(encrypted), len(encrypted)
        dec = rsa.decrypt(encrypted)
        dhash = sha1(dec)
        print "Decrypted: ", rsa.decrypt(encrypted)
        print "Verified: ", rsa.verify(sig, dhash)
    testCrypto()
