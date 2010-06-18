# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import sys
import time
import Anomos.Crypto

from Anomos import bttime, LOG as log
from Anomos.Protocol import toint
from Anomos.Crypto import global_cryptodir, global_randfile, global_certpath, global_tempcerts
from Anomos.Crypto import CryptoError
from M2Crypto import m2, RSA, EVP, X509, SSL, Rand, util as m2util
from binascii import b2a_hex

# Cipher Set:
CIPHER_SET = 'HIGH:!ADH:!MD5:@STRENGTH'
# Translation: Use high grade encryption, no Anonymous Diffie Hellman,
# no MD5, sort by strength.
# On my system, this results in the following cipher set:
# [john:~]$ openssl ciphers 'HIGH:!ADH:!MD5:@STRENGTH'
# DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:AES256-SHA:
# EDH-RSA-DES-CBC3-SHA:EDH-DSS-DES-CBC3-SHA:
# DES-CBC3-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:AES128-SHA

# CTX_OPTIONS: Only allow TLSv1
CTX_OPTIONS = m2.SSL_OP_NO_SSLv2

## X509 Verification Callbacks ##
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
        if None in (global_cryptodir, global_randfile, global_tempcerts):
            raise CryptoError('Crypto not initialized, call initCrypto first')
        if loc is None:
            loc = b2a_hex(Rand.rand_bytes(32))

        if tracker:
            self.keyfile = os.path.join(global_cryptodir, '%s-key.pem' % (loc))
            self.certfile = os.path.join(global_cryptodir, '%s-cert.pem' % (loc))
        else:
            self.keyfile = os.path.join(global_tempcerts, '%s-key.pem' % (loc))
            self.certfile = os.path.join(global_tempcerts, '%s-cert.pem' % (loc))

        self.cert = None
        if not (os.path.exists(self.certfile) and os.path.exists(self.keyfile)):
            if self.tracker:
                hostname = self._gethostname()
            else:
                hostname = 'localhost'
            self._create(hostname=hostname)
        else:
            self._load()

        if self.is_expired():
            if tracker:
                log.critical(
                 "\n*-*-------------------------------------------------------------------*-*\n"
                   "*-* Your certificate is expired. Clients will not be able to connect! *-*\n" +
                   "*-*-------------------------------------------------------------------*-*\n")
            else:
                log.warning("Your certificate is expired. Some trackers may reject your requests.")

    def _gethostname(self):
        from socket import gethostname
        hostname = gethostname()
        tmpname = raw_input("Please enter the tracker's hostname " \
                        "for the SSL certificate (default: %s): " % hostname)
        if tmpname.strip(" "):
            hostname = tmpname
        return hostname

    def _load(self):
        """Attempts to load the certificate and key from self.certfile and self.keyfile,
           Generates the certificate and key if they don't exist"""
        if not self.secure:
            self.rsakey = RSA.load_key(self.keyfile, m2util.no_passphrase_callback)
        else:
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
        self.cert = X509.load_cert(self.certfile)

    @Anomos.Crypto.use_rand_file
    def _create(self, hostname='localhost'):
        # Make the RSA key
        self.rsakey = RSA.gen_key(2048, m2.RSA_F4)
        if self.secure:
            # Save the key, AES256-CBC encrypted
            self.rsakey.save_key(self.keyfile, 'aes_256_cbc')
        else:
            # Save the key unencrypted.
            self.rsakey.save_key(self.keyfile, None, callback=m2util.no_passphrase_callback)
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
        # Set the period of time the cert is valid for (5 years from issue)
        notBefore = m2.x509_get_not_before(self.cert.x509)
        notAfter = m2.x509_get_not_after(self.cert.x509)
        m2.x509_gmtime_adj(notBefore, -60*60*24)
        m2.x509_gmtime_adj(notAfter, 60*60*24*365*5)
        # Sign the certificate
        self.cert.sign(pkey, 'sha1')
        # Save it
        self.cert.save_pem(self.certfile)

    def is_expired(self):
        if self.cert is None:
            return True
        before_time = self.cert.get_not_before()
        after_time = self.cert.get_not_after()
        # M2Crypto < 0.19 doesn't have get_datetime, so
        # checking expiration is a pain.
        # TODO: Disallow M2<.19 or hack up our own get_datetime
        if not hasattr(before_time, 'get_datetime'):
            return False
        before_tuple = before_time.get_datetime().timetuple()
        after_tuple = after_time.get_datetime().timetuple()
        now_tuple = time.gmtime()
        #cert has expired
        if now_tuple > after_tuple:
            return True
        #cert is not yet valid, not likely but should still return True
        if now_tuple < before_tuple:
            return True
        return False


    def get_ctx(self, allow_unknown_ca=False, req_peer_cert=True, session=None):
        ctx = SSL.Context("sslv23")
        # Set certificate and private key
        m2.ssl_ctx_use_x509(ctx.ctx, self.cert.x509)
        m2.ssl_ctx_use_rsa_privkey(ctx.ctx, self.rsakey.rsa)
        if not m2.ssl_ctx_check_privkey(ctx.ctx):
            raise CryptoError('public/private key mismatch')
        # Ciphers/Options
        ctx.set_cipher_list(CIPHER_SET)
        ctx.set_options(CTX_OPTIONS)
        # CA settings
        cloc = os.path.join(global_certpath, 'cacert.root.pem')
        if ctx.load_verify_locations(cafile=cloc) != 1:
            log.error("Problem loading CA certificates")
            raise CryptoError('CA certificates not loaded')
        # Verification
        cb = mk_verify_cb(allow_unknown_ca=allow_unknown_ca)
        CTX_V_FLAGS = SSL.verify_peer
        if req_peer_cert:
            CTX_V_FLAGS |= SSL.verify_fail_if_no_peer_cert
        ctx.set_verify(CTX_V_FLAGS,3,cb)
        # Session
        if session:
            ctx.set_session_id_ctx(session)
        return ctx

    def fingerprint(self):
        md = EVP.MessageDigest("sha1")
        md.update(self.rsakey.pub()[1])
        return b2a_hex(md.digest())

    def decrypt(self, data):
        """
        Decrypts data encrypted with this public key

        @param data: The data, padding and all, to be decrypted
        @type data: string

        @raise CryptoError: Priv. decrypt fail or Bad Checksum

        @return: tuple (decrypted message, padding) if returnpad is true, string otherwise
        @rtype: tuple
        """
        rsa_keysize_B = len(self.rsakey)/8
        # Decrypt the session key and IV with our private key
        try:
            tmpsk = self.rsakey.private_decrypt(data[:rsa_keysize_B], RSA.pkcs1_oaep_padding)
        except RSA.RSAError, e:
            raise CryptoError("A decryption error occurred: %s" % str(e))
        sk = tmpsk[:32] # Session Key
        iv = tmpsk[32:] # IV
        sessionkey = Anomos.Crypto.AESKey(sk, iv)
        # Decrypt the rest of the message with the session key
        content = sessionkey.decrypt(data[rsa_keysize_B:])
        msglen = content[:4] # first 4 bytes
        msglen_int = toint(msglen)
        pos = 4
        message = content[pos:pos+msglen_int] # next msglen_int bytes
        pos += msglen_int
        givenchksum = content[pos:pos+20] # next 20 bytes
        pos += 20
        md = EVP.MessageDigest("sha1")
        md.update(msglen + message)
        mychksum = md.digest()
        if givenchksum != mychksum:
            raise CryptoError("Bad Checksum - Data may have been tampered with")
        return (message, content[pos:])
