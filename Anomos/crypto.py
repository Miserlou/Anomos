"""
crypto.py

anomos. very preliminary. rsa should eventually be replaced with real ssl. requires m2crypto.

RSA padding: pkcs1_oaep_padding
AES cipher: aes_128_cfb

for other functions used directly, look at RSA.py and EVP.py in M2Crypto

"""

import sys
import M2Crypto
import os
import cStringIO
from binascii import hexlify, unhexlify
from M2Crypto import Rand, RSA, util, EVP

key_size=1024
secret = "Call me subwoofa cause I push so much base!"

def saveNewPEM():
    Rand.load_file('randpool.dat', -1) 
    
    pvtkeyfilename = 'rsa%dpvtkey.pem' % (key_size)
    pubkeyfilename = 'rsa%dpubkey.pem' % (key_size)
    
    rsa = RSA.gen_key(key_size, 65537)  ## exponent: 65537 is secure

    print pvtkeyfilename
    print pubkeyfilename

    rsa.save_key(pvtkeyfilename)
    rsa.save_pub_key(pubkeyfilename)

    Rand.save_file('randpool.dat')

def loadKeysFromPEM():

    pvtkeyfilename = 'rsa%dpvtkey.pem' % (key_size)
    pubkeyfilename = 'rsa%dpubkey.pem' % (key_size)
    
    # Don't bother checking if these paths exist, they'll raise
    # an IOError if they don't and we'll catch that to determine if we need to
    # generate a key.
    pvt = RSA.load_key(pvtkeyfilename)
    pub = RSA.load_pub_key(pubkeyfilename)
    
    return (pub, pvt)

##32 random bytes
def getRand32():
    Rand.load_file('randpool.dat', -1)
    rb = Rand.rand_bytes(32);
    Rand.save_file('randpool.dat')
    return rb

def getNewAES():
    return getRand32()

def getNewIV():
    return getRand32()

##this is where the actual ciphering is done
def cipher_filter(cipher, inf, outf):
        while 1:
            buf=inf.read()
            if not buf:
                break
            outf.write(cipher.update(buf))
        outf.write(cipher.final())
        return outf.getvalue()

##does what it says
def AESEncrypt(key, iv, text):
    sbuf=cStringIO.StringIO(text)
    obuf=cStringIO.StringIO()
    encoder = EVP.Cipher('aes_128_cfb', key, iv, 1)
    encrypted = hexlify(cipher_filter(encoder, sbuf, obuf))
    sbuf.close()
    obuf.close()
    return encrypted

##does what it says
def AESDecrypt(key, iv, text):
    obuf = cStringIO.StringIO(unhexlify(text))
    sbuf = cStringIO.StringIO()
    decoder = EVP.Cipher('aes_128_cfb', key, iv, 0)
    decrypted = cipher_filter(decoder, obuf, sbuf)
    sbuf.close()
    obuf.close()
    return decrypted

def testCrypto():
    ##saveNewPEM();
    ##print "Saved!"
    ##rsa = loadKeysFromPEM()  ##Hooray works!
    iv = getRand32()
    iv2 = getRand32()
    key = getNewAES()

    print "Unencrypted:"
    print secret

    encrypted = AESEncrypt(key, iv, secret)
    print encrypted
    print AESDecrypt(key, iv,encrypted)

if __name__ == "__main__":
    testCrypto()







    







