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

# Written by Rich Jones, and John Schanck

##################################################
# Notes:
# RSA padding: pkcs1_oaep_padding
# AES cipher: aes_256_cfb
# for other functions used directly, look at RSA.py and EVP.py in M2Crypto
##################################################

import os
import sys
import shutil

from M2Crypto import Rand, threading
from Anomos import bttime, BTFailure, LOG as log

try:
    global_cryptodir
    global_randfile
    global_dd
    global_certpath
except NameError:
    global_cryptodir = None
    global_randfile = None
    global_dd = None
    global_certpath = None

class CryptoError(BTFailure):
    pass

def get_rand(*args):
    raise CryptoError("RNG not initialized")

def use_rand_file(function):
    """Decorator to ease use of a randfile which must
       be opened before crypto operations and closed
       afterwards"""
    def retfun(*args, **kwargs):
        Rand.load_file(global_randfile, -1)
        r = function(*args, **kwargs)
        Rand.save_file(global_randfile)
        return r
    return retfun

def init(data_dir):
    """Sets the directory in which to store crypto data/randfile
    @param data_dir: path to directory
    @type data_dir: string
    """
    # I suppose initializing threading can't hurt, but all of our
    # crypto operations are made from the same thread. So do we need this?
    threading.init()

    global get_rand
    global global_cryptodir, global_randfile, global_dd, global_certpath

    if None not in (global_cryptodir, global_randfile):
        log.warning("Crypto already initialized with root directory: %s. Not using %s." % (global_dd, data_dir))
        return
    # Initialize directory structure #
    global_dd = data_dir
    global_cryptodir = os.path.join(data_dir, 'crypto')
    if not os.path.exists(data_dir):
        os.mkdir(data_dir, 0700)
    if not os.path.exists(global_cryptodir):
        os.mkdir(global_cryptodir, 0700)
    # Copy the default certificates into the user's crypto dir #
    global_certpath = os.path.join(global_cryptodir, 'default_certificates')
    if not os.path.exists(global_certpath):
        # TODO: make sure this method of getting app_root works on all
        # platforms and configurations
        from Anomos import app_root
        shutil.copytree(os.path.join(app_root, 'default_certificates'), global_certpath)
    # Initialize randfile #
    global_randfile = os.path.join(global_cryptodir, 'randpool.dat')
    if Rand.save_file(global_randfile) == 0:
        raise CryptoError('Rand file not writable')
    @use_rand_file
    def randfunc(numBytes=32):
        rb = Rand.rand_bytes(numBytes);
        return rb
    get_rand = randfunc

    global AESKey, Certificate, PeerCert
    import _AESKey, _Certificate, _PeerCert
    AESKey = _AESKey.AESKey
    Certificate = _Certificate.Certificate
    PeerCert = _PeerCert.PeerCert


