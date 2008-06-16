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

def saveNewPEM():
	Rand.load_file('randpool.dat', -1) 
	
	pvtkeyfilename = 'rsa%dpvtkey.pem' % (1024)
	pubkeyfilename = 'rsa%dpubkey.pem' % (1024)
	
	rsa = RSA.gen_key(1024, 65537)  ## exponent: 65537 is secure

	print pvtkeyfilename
	print pubkeyfilename

	rsa.save_key(pvtkeyfilename)
	rsa.save_pub_key(pubkeyfilename)

	Rand.save_file('randpool.dat')

def loadKeysFromPEM():

	pvtkeyfilename = 'rsa%dpvtkey.pem' % (1024)
	pubkeyfilename = 'rsa%dpubkey.pem' % (1024)
	
	if os.path.exists(pvtkeyfilename)
		pvt = RSA.load_key(pvtkeyfilename)
	if os.path.exists(pubkeyfilename)
		pub = RSA.load_pub_key(pubkeyfilename)
	else return false

	rsa = (pub, pvt)
	return rsa

def getRand32():
	Rand.load_file('randpool.dat', -1)
	rb = Rand.rand_bytes(32);
	Rand.save_file('randpool.dat')
	return rb

def getNewAES():
	return getRand32()

def getNewIV():
	return getRand32()

def main():
	##saveNewPEM();
	##print "Saved!"
	##rsa = loadKeysFromPEM()  ##Hooray works!
	print getRand32()
	print getNewAES()
	print getNewIV()

if __name__ == "__main__":
    main()







	







