"""
crypto.py

anomos. very preliminary. rsa should eventually be replaced with real ssl. requires m2crypto.

"""

from M2Crypto import RSA, Rand
import sys
import util, m2

def saveNewPEM():
	Rand.load_file('randpool.dat', -1) 
	
	pvtkeyfilename = 'rsa%dpvtkey.pem' % (1024)
	pubkeyfilename = 'rsa%dpubkey.pem' % (1024)
	
	rsa = RSA.gen_key(1024, 65537)  ## exponent: 65537 is secure

	rsa.savekey(rsa, pvtkeyfilename, cipher='aes_128_cbc', callback=util.passphrase_callback)
	rsa.save_pub_key(pubkeyfilename)

def loadKeysFromPEM():
	pvtkeyfilename = 'rsa%dpvtkey.pem' % (1024)
	pubkeyfilename = 'rsa%dpubkey.pem' % (1024)
	pvt = RSA.load_key(pvtkeyfilename, callback=util.passphrase_callback):
	pub = RSA.load_key(pubkeyfilename)

	rsa = {pub, pvt}
	return rsa









	







