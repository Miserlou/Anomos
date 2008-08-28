"""
@author: Rich Jones, John Schanck
@license: see License.txt

anomos. very preliminary. rsa should eventually be replaced with real ssl. requires m2crypto.

RSA padding: pkcs1_oaep_padding
AES cipher: aes_256_cfb

for other functions used directly, look at RSA.py and EVP.py in M2Crypto
"""

import sys
import os
import cStringIO
import sha
from binascii import b2a_hex, a2b_hex
from M2Crypto import m2, Rand, RSA, util, EVP
from Anomos import BTFailure


def getRand(*args):
    raise CryptoError("RNG not initialized")

global_cryptodir = None
global_randfile = None
global_dd = None
def initCrypto(data_dir):
    '''Sets the directory in which to store crypto data/randfile
    @param data_dir: path to directory
    @type data_dir: string
    '''
    
    global getRand, global_cryptodir, global_randfile, global_dd
    global_dd = data_dir
    if None not in (global_cryptodir, global_randfile):
        return #TODO: Already initialized, log a warning here.
    global_cryptodir = os.path.join(data_dir, 'crypto')
    if not os.path.exists(data_dir):
        os.mkdir(data_dir, 0700)
    if not os.path.exists(global_cryptodir):
        os.mkdir(global_cryptodir, 0700)
    global_randfile = os.path.join(global_cryptodir, 'randpool.dat')
    if Rand.save_file(global_randfile) == 0:
        raise CryptoError('Rand file not writable')
    def randfunc(numBytes=32):
        Rand.load_file(global_randfile, -1)
        rb = Rand.rand_bytes(numBytes);
        Rand.save_file(global_randfile)
        return rb
    getRand = randfunc

def tobinary(i):
    return (chr(i >> 24) + chr((i >> 16) & 0xFF) + chr((i >> 8) & 0xFF) + chr(i & 0xFF))

def toM2Exp(n):
    return m2.bn_to_mpi(m2.bin_to_bn(tobinary(n)))

class RSAPubKey:
   
    def __init__(self, keystring, exp=65537):
        """
        @param keystring: "n" value of pubkey to initialize new public key from
        @param exp: "e" value of pubkey, should almost always be 65537
        @type keystring: string
        @type exp: int
        """
        if None in (global_cryptodir, global_randfile):
            raise CryptoError('Crypto not initialized, call initCrypto first')
        self.pubkey = RSA.new_pub_key((toM2Exp(exp), keystring))
        self.pubkey.check_key()
        self.randfile = global_randfile

    def saveNewPEM(self, alias):
        """
        Save public PEM
        """
        self.pubkeyfilename = os.path.join(global_dd, '%s-pub.pem' % (alias))
        rsa.save_pub_key(self.pubkeyfilename)
        return self.pubkeyfilename
    
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
        sessionkey = AESKey()
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
        padding = getRand(padlen)
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
    def __init__(self, alias, key_size=1024, padding=RSA.pkcs1_oaep_padding):
        """                
        @param alias: Unique name for the key, can be anything.
        @param key_size: Size of keys (in bits) to generate
        @param padding: algorithm to use for padding
        @type alias: string
        @type padding: string in ('pkcs1_oaep_padding', 'pkcs1_padding', 'sslv23_padding', 'no_padding')
        """
        if None in (global_cryptodir, global_randfile):
            raise CryptoError('Crypto not initialized, call initCrypto first')
        self.alias = alias
        self.key_size = key_size
        self.padding = padding
        
        self.pvtkeyfilename = os.path.join(global_cryptodir, '%s-pvt.pem' % (self.alias))
        self.pubkeyfilename = os.path.join(global_cryptodir, '%s-pub.pem' % (self.alias))
        self.randfile = global_randfile
        
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
        @return: The signature of the message from the private key
        """
        dgst = sha.new(msg).digest()
        signature = self.pvtkey.private_encrypt(dgst, RSA.pkcs1_padding)
        return signature

    def verify(self, signature, digest):
        """@param signature: Signature of a document
           @param digest: the sha1 of that document
           @return: true if verified; false if not
           @rtype: boolean
        """
        ptxt=self.pubkey.public_decrypt(signature, RSA.pkcs1_padding)
        return ptxt == digest
    
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
        try:
            tmpsk = self.pvtkey.private_decrypt(data[:byte_key_size], self.padding)
        except RSA.RSAError:
            raise CryptoError("Data encrypted with wrong public key")
        sk = tmpsk[:32] # Session Key
        iv = tmpsk[32:] # IV
        sessionkey = AESKey(sk, iv)
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

    def getPubKey(self):
        """
        Gives the public key. To get as string, use b2a_hex(self.blahh.getPubKey().pub()[1])
        @return: pubkey instance
        """
        return self.pubkey

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
    
    def newAES(self):
        """
        @return: 32byte AES key
        @rtype: string
        """
        return getRand()
    
    def newIV(self):
        return getRand()


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

class CryptoError(BTFailure):
    pass

if __name__ == "__main__":
    secret = "Call me subwoofa cause I push so much base!"
    initCrypto('crypto-test')
    getRand()
    
    # Test AESKey
    key = AESKey()
    
    print "Plaintext:", secret

    encrypted = key.encrypt(secret)
    print "Ciphertext:", b2a_hex(encrypted)
    print "Ciphertext length:", len(encrypted)
    print "Decrypted:", key.decrypt(encrypted)
    
    # Test RSAKeyPair
    rsa = RSAKeyPair('tracker')
    encrypted = rsa.encrypt(secret)
    sig = rsa.sign(secret)
    print "Encrypted: ", b2a_hex(encrypted), len(encrypted)
    dec = rsa.decrypt(encrypted)
    dhash = sha.new(dec).digest()
    print "Decrypted: ", rsa.decrypt(encrypted)
    print "Verified: ", rsa.verify(sig, dhash)
