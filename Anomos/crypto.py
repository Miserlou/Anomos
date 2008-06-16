"""
crypto.py

anomos. very preliminary. rsa should eventually be replaced with real ssl. requires m2crypto.

padding: pkcs1_oaep_padding

for other functions used directly, look at RSA.py in M2Crypto

"""

import sys
import M2Crypto
import os
from M2Crypto import Rand, RSA, util

key_size=1024

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

def getRand32():
    Rand.load_file('randpool.dat', -1)
    rb = Rand.rand_bytes(32);
    Rand.save_file('randpool.dat')
    return rb

def getNewAES():
    return getRand32()

def getNewIV():
    return getRand32()

def testCrypto():
    ##saveNewPEM();
    ##print "Saved!"
    ##rsa = loadKeysFromPEM()  ##Hooray works!
    print getRand32()
    print getNewAES()
    print getNewIV()

if __name__ == "__main__":
    testCrypto()







    







