"""
@author: Rich Jones, John Schanck
@license: see License.txt

anomos. very preliminary. rsa should eventually be replaced with real ssl. requires m2crypto.

RSA padding: pkcs1_oaep_padding
AES cipher: aes_256_cfb

for other functions used directly, look at RSA.py and EVP.py in M2Crypto
"""
import os
import shutil
import sys
import cStringIO
import hashlib
from binascii import b2a_hex, a2b_hex
from M2Crypto import m2, Rand, RSA, EVP, X509, SSL, threading, util
from M2Crypto.m2 import X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT as ERR_SELF_SIGNED
from Anomos import BTFailure
from Anomos.platform import bttime

CTX_VERIFY_FLAGS = SSL.verify_peer | SSL.verify_fail_if_no_peer_cert

def getRand(*args):
    raise CryptoError("RNG not initialized")

global_cryptodir = None
global_randfile = None
global_dd = None
global_certpath = None

def usesRandFile(function):
    """Decorator to ease use of randfile which must
       be opened before crypto operations and closed
       afterwards"""
    def retfun(*args, **kwargs):
        Rand.load_file(global_randfile, -1)
        function(*args, **kwargs)
        Rand.save_file(global_randfile)
    return retfun

def initCrypto(data_dir):
    '''Sets the directory in which to store crypto data/randfile
    @param data_dir: path to directory
    @type data_dir: string
    '''
    threading.init()
    global getRand, global_cryptodir, global_randfile, global_dd

    if None not in (global_cryptodir, global_randfile):
        return #TODO: Already initialized, log a warning here.
    global_dd = data_dir
    global_cryptodir = os.path.join(data_dir, 'crypto')
    if not os.path.exists(data_dir):
        os.mkdir(data_dir, 0600)
    if not os.path.exists(global_cryptodir):
        os.mkdir(global_cryptodir, 0600)
    global_randfile = os.path.join(global_cryptodir, 'randpool.dat')
    if Rand.save_file(global_randfile) == 0:
        raise CryptoError('Rand file not writable')
    @usesRandFile
    def randfunc(numBytes=32):
        rb = Rand.rand_bytes(numBytes);
        return rb
    getRand = randfunc
    copyDefCerts()
    
def copyDefCerts():
    ##If we haven't done it yet, move the default certificates to the user's data folder
    
    global global_certpath, global_dd
    global_certpath = os.path.join(global_cryptodir, 'default_certificates')
    
    if not os.path.exists(global_certpath):
        app_root = os.path.split(os.path.abspath(sys.argv[0]))[0]
        shutil.copytree(os.path.join(app_root, 'default_certificates'), global_certpath)
    
def getDefaultCerts():
    global global_certpath, global_dd
    global_certpath = os.path.join(global_cryptodir, 'default_certificates')
    return os.listdir(global_certpath)
    
def getCertPath():
    global global_certpath
    return global_certpath
    
def compareCerts(c1, c2):
    if (c1.get_fingerprint('sha256') == c2.get_fingerprint('sha256')):
        return True
    else:
        return False
    

def tobinary(i):
    return (chr(i >> 24) + chr((i >> 16) & 0xFF) + chr((i >> 8) & 0xFF) + chr(i & 0xFF))

class Certificate:
    def __init__(self, loc=None, secure=False, tracker=False):
        self.secure = secure
        self.tracker = tracker
        if None in (global_cryptodir, global_randfile):
            raise CryptoError('Crypto not initialized, call initCrypto first')
        self.keyfile = os.path.join(global_cryptodir, '%s-key.pem' % (loc))
        self.ikeyfile = os.path.join(global_cryptodir, '%s-key-insecure.pem' % (loc))
        self.certfile = os.path.join(global_cryptodir, '%s-cert.pem' % (loc))
        self._load()

    def _load(self):
        """Attempts to load the certificate and key from self.certfile and self.keyfile,
           Generates the certificate and key if they don't exist"""
        if not os.path.exists(self.certfile) or not os.path.exists(self.keyfile):
            hostname = 'localhost'
            if self.tracker:
                from socket import gethostname
                hostname = gethostname()
                tmpname = raw_input("Please enter the tracker's hostname "\
                        "for the SSL certificate (default: %s): " % hostname)
                if tmpname.strip(" "):
                    hostname = tmpname
            print "Generating encryption keys"
            self._create(hostname=hostname)
            return
        if self.secure:
            self.rsakey = RSA.load_key(self.keyfile)
        else:
            self.rsakey = RSA.load_key(self.keyfile, util.no_passphrase_callback)
        self.rsakey.save_key(self.ikeyfile, None)
        self.cert = X509.load_cert(self.certfile)

    @usesRandFile
    def _create(self, hostname='localhost'):
        # Make the RSA key
        self.rsakey = RSA.gen_key(2048, m2.RSA_F4)
        # Save the key, aes 256 cbc encrypted
        if self.secure:
            self.rsakey.save_key(self.keyfile, 'aes_256_cbc')
        else:
            # Save the key unencrypted.
            # TODO: Find workaround, M2Crypto doesn't include the function to load
            # a cert from memory, storing them unencrypted on disk isn't safe.
            self.rsakey.save_key(self.keyfile, None, callback=util.no_passphrase_callback)
        self.rsakey.save_key(self.ikeyfile, None, callback=util.no_passphrase_callback)
        # Make the public key
        pkey = EVP.PKey()
        pkey.assign_rsa(self.rsakey, 0)
        # Generate the certificate
        self.cert = X509.X509()
        self.cert.set_serial_number(long(bttime()))
        self.cert.set_version(2)
        self.cert.set_pubkey(pkey)
        # Set the name on the certificate
        name = X509.X509_Name()
        name.CN = hostname
        self.cert.set_subject(name)
        self.cert.set_issuer(name)
        # Set the period of time the cert is valid for (1 year from issue)
        notBefore = m2.x509_get_not_before(self.cert.x509)
        notAfter = m2.x509_get_not_after(self.cert.x509)
        m2.x509_gmtime_adj(notBefore, 0)
        m2.x509_gmtime_adj(notAfter, 60*60*24*365) #TODO: How long should certs be valid?
        # Sign the certificate
        self.cert.sign(pkey, 'ripemd160')
        # Save it
        self.cert.save_pem(self.certfile)

    def getContext(self):
        #XXX: This is almost definitely not secure.
        #for instance, ctx.set_verify needs a proper callback.
        ctx = SSL.Context("sslv23") # Defaults to SSLv23
        ctx.load_cert(self.certfile, keyfile=self.ikeyfile)
        ctx.set_verify(CTX_VERIFY_FLAGS, 0, lambda x,y: True)
        ctx.set_allow_unknown_ca(1)
        #TODO: Update info callback when we switch to using Python's logging module
        #ctx.set_info_callback(lambda *x:None)
        return ctx

    def _verifyCallback(self, preverify_ok, code):
        # Allow self-signed certs
        if x509.get_error() == ERR_SELF_SIGNED:
            return True
        return bool(preverify_ok)

    def getVerifiedContext(self, pem):
        global global_cryptodir
        cloc = os.path.join(global_cryptodir, pem)
        ctx = SSL.Context("sslv23") # Defaults to SSLv23
        ctx.load_cert(self.certfile, keyfile=self.ikeyfile)
        ctx.load_verify_locations(cafile=cloc)
        ctx.set_allow_unknown_ca(0)
        ctx.set_verify(CTX_VERIFY_FLAGS,0,self._verifyCallback)
        #TODO: Update info callback when we switch to using Python's logging module
        #ctx.set_info_callback(lambda *x:None)
        return ctx

    def getPub(self):
        return self.rsakey.pub()[1]

    def fingerprint(self):
        return hashlib.sha1(self.getPub()).hexdigest()

    def decrypt(self, data, returnpad=False):
        """
        Decrypts data encrypted with this public key

        @param data: The data, padding and all, to be decrypted
        @type data: string
        @param returnpad: return "junk" decrypted padding as well as message. Default: False
        @type returnpad: boolean

        @raise CryptoError: Priv. decrypt fail or Bad Checksum

        @return: tuple (decrypted message, padding) if returnpad is true, string otherwise
        @rtype: tuple
        """
        byte_key_size = len(self.rsakey)/8
        # Decrypt the session key and IV with our private key
        try:
            tmpsk = self.rsakey.private_decrypt(data[:byte_key_size], RSA.pkcs1_oaep_padding)
        except RSA.RSAError, e:
            raise CryptoError("A decryption error occurred", e)
        sk = tmpsk[:32] # Session Key
        iv = tmpsk[32:] # IV
        sessionkey = AESKey(sk, iv)
        # Decrypt the rest of the message with the session key
        content = sessionkey.decrypt(data[byte_key_size:])
        #pos = sha.digestsize
        pos = 20
        givenchksum = content[:pos] # first 20 bytes
        smsglen = content[pos:pos+4] # next 4 bytes
        imsglen = int(b2a_hex(smsglen), 16)
        pos += 4
        message = content[pos:pos+imsglen]
        pos += imsglen
        mychksum = hashlib.sha1(sk+smsglen+message).digest()
        if givenchksum != mychksum:
            raise CryptoError("Bad Checksum - Data may have been tampered with")
        if returnpad:
            return (message, content[pos:])
        else:
            return message

class PeerCert:
    def __init__(self, certObj):
        self.certificate = certObj
        tmp = X509.load_cert_string(certObj.as_pem()).get_pubkey().get_rsa()
        self.pubkey = RSA.new_pub_key((tmp.e, tmp.n))
        self.randfile = global_randfile
    def verify():
        # Verify the certificate
        pass
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
        checksum = hashlib.sha1(sessionkey.key + bmsglen + data[:rmsglen]).digest()
        content = checksum + bmsglen + data
        padlen = 32-(len(content)%32)
        padding = getRand(padlen)
        ciphertext = sessionkey.encrypt(content+padding)
        return esk + ciphertext

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

class CryptoError(BTFailure):
    pass

if __name__ == "__main__":
    initCrypto(os.getcwd())

