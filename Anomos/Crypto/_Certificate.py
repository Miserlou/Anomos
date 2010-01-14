import hashlib
import os
import sys
import Anomos.Crypto

from Anomos import bttime, LOG as log
from Anomos.Protocol import toint
from Anomos.Crypto import global_cryptodir, global_randfile, global_certpath
from M2Crypto import m2, RSA, EVP, X509, SSL, util as m2util

## X509 Verification Callbacks ##
CTX_V_FLAGS = SSL.verify_peer | SSL.verify_fail_if_no_peer_cert

SELF_SIGNED_ERR = [
    m2.X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
    m2.X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
    ]

UNKNOWN_ISSUER_ERR = [
    m2.X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
    m2.X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
    m2.X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE,
    m2.X509_V_ERR_CERT_UNTRUSTED,
    ]

def _verify_callback(ok, store, **kwargs):
    errnum = store.get_error()
    errdepth = store.get_error_depth()
    cert = store.get_current_cert()
    # [DEBUGGING] Localhost exemption for self-signed certificates
    if errnum in SELF_SIGNED_ERR:
        if cert.get_subject().CN == 'localhost':
            ok = 1
    # Allow unknown CA if a context requests it
    if errnum in UNKNOWN_ISSUER_ERR:
        if kwargs.get('allow_unknown_ca', False):
            ok = 1
    # TODO: Certificate Revokation Lists?
    return ok

def mk_verify_cb(**kwargs):
    def vcb(ok, store):
        return _verify_callback(ok, store, **kwargs)
    return vcb

## Certificate class ##
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
            self._create(hostname=hostname)
            return
        if self.secure:
            # Allow 3 attempts before quitting
            i = 0
            while i < 3:
                try:
                    self.rsakey = RSA.load_key(self.keyfile)
                    break
                except RSA.RSAError:
                    i += 1
            else:
                log.warning("\nInvalid password entered, exiting.")
                sys.exit()
        else:
            self.rsakey = RSA.load_key(self.keyfile, m2util.no_passphrase_callback)
        self.rsakey.save_key(self.ikeyfile, None)
        self.cert = X509.load_cert(self.certfile)

    @Anomos.Crypto.use_rand_file
    def _create(self, hostname='localhost'):
        # Make the RSA key
        self.rsakey = RSA.gen_key(2048, m2.RSA_F4)
        if self.secure:
            # Save the key, aes 256 cbc encrypted
            self.rsakey.save_key(self.keyfile, 'aes_256_cbc')
        else:
            # Save the key unencrypted.
            self.rsakey.save_key(self.keyfile, None, callback=m2util.no_passphrase_callback)
        self.rsakey.save_key(self.ikeyfile, None, callback=m2util.no_passphrase_callback)
        # Make the public key
        pkey = EVP.PKey()
        pkey.assign_rsa(self.rsakey, 0)
        # Generate the certificate
        self.cert = X509.X509()
        self.cert.set_serial_number(long(bttime()))
        self.cert.set_version(0x2)
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
        m2.x509_gmtime_adj(notAfter, 60*60*24*365*5)
        # Sign the certificate
        self.cert.sign(pkey, 'ripemd160')
        # Save it
        self.cert.save_pem(self.certfile)

    def get_ctx(self, allow_unknown_ca=False):
        cloc = os.path.join(global_certpath, 'cacert.root.pem')
        ctx = SSL.Context("tlsv1") # Defaults to SSLv23
        if ctx.load_verify_locations(cafile=cloc) != 1:
            log.error("Problem loading CA certificates")
            raise Exception('CA certificates not loaded')
        ctx.load_cert(self.certfile, keyfile=self.ikeyfile)
        cb = mk_verify_cb(allow_unknown_ca=allow_unknown_ca)
        ctx.set_verify(CTX_V_FLAGS,3,cb)
        return ctx

    def get_pub(self):
        return self.rsakey.pub()[1]

    def fingerprint(self):
        return hashlib.sha1(self.get_pub()).hexdigest()

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
            raise CryptoError("A decryption error occurred: %s" % str(e))
        sk = tmpsk[:32] # Session Key
        iv = tmpsk[32:] # IV
        sessionkey = Anomos.Crypto.AESKey(sk, iv)
        # Decrypt the rest of the message with the session key
        content = sessionkey.decrypt(data[byte_key_size:])
        #pos = sha.digestsize
        pos = 20
        givenchksum = content[:pos] # first 20 bytes
        smsglen = content[pos:pos+4] # next 4 bytes
        imsglen = toint(smsglen)
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
