## CERTS.PY
## GPLv3 - Anomos Liberty Enhancements

from M2Crypto import m2, Rand, RSA, util, EVP
import pexpect
import os
import subprocess
import time
from random import choice
import string
import sys

def makeNewCert():
    print "Creating certificates. This happens the first time Anomos is started. Please don't touch anything for 30 seconds."
    ##shell = pexpect.spawn('openssl genrsa -des3 -out server.key 4096 ')
    ##ossl = subprocess.Popen('openssl genrsa -des3 -out server.key 4096 ', stdout=sys.stdout, shell=True)
    #time.sleep(10)
    #print ossl
   # genning = False
    #while (genning == False):
     #   stdout = ossl.communicate()[0]
     #   print stdout
     #   if(stdout.find("pass phrase")>0):
      #      genning = True
    ##time.sleep(30)
    ##ossl.read()
    shell = pexpect.spawn('openssl genrsa -des3 -out server.key 4096 ', timeout=5000)

    shell.expect('Enter pass phrase for server.key:')
    randpass = ''.join([choice(string.letters + string.digits) for i in xrange(10)])   
    print randpass
    shell.sendline(randpass)
    shell.expect('Verifying - Enter pass phrase for server.key:')
    ##os.sytem(randpass)
    shell.sendline(randpass)

    print "Key generated, creating request"

    shell = pexpect.spawn('openssl req -new -key /home/rich/anomos/anomos.git/Anomos/server.key -out /home/rich/anomos/anomos.git/Anomos/server.csr', timeout=500000)
    shell.expect('Enter pass phrase for /home/rich/anomos/anomos.git/Anomos/server.key:')
    shell.sendline(randpass)

    shell.expect('.*')
    shell.sendline('XX')
    shell.expect('.*')
    shell.sendline('XXXXXXX')
    shell.expect('.*')
    shell.sendline('XXXXXXX')
    shell.expect('.*')
    shell.sendline('XXXXXXX')
    shell.expect('.*')
    shell.sendline('XXXXXXX')
    shell.expect('.*')
    shell.sendline('XXX XXX')
    shell.expect('.*')
    shell.sendline('XXX@XXX.com')
    shell.expect('.*')
    shell.sendline('')
    shell.expect('.*')
    shell.sendline('')

    print "Request made, signing.."

    shell = pexpect.spawn('openssl x509 -req -days 3650 -in /home/rich/anomos/anomos.git/Anomos/server.csr -signkey /home/rich/anomos/anomos.git/Anomos/server.key -out /home/rich/anomos/anomos.git/Anomos/server.crt ')
    shell.expect('.*Enter pass phrase for /home/rich/anomos/anomos.git/Anomos/server.key:')
    shell.sendline(randpass)

    print "Certificate signed, reorganizing keys.."

    shell = pexpect.spawn('openssl rsa -in /home/rich/anomos/anomos.git/Anomos/server.key -out /home/rich/anomos/anomos.git/Anomos/server.key.insecure')
    shell.expect('Enter pass phrase for /home/rich/anomos/anomos.git/Anomos/server.key:')
    shell.sendline(randpass)

    shell = pexpect.spawn('mv /home/rich/anomos/anomos.git/Anomos/server.key /home/rich/anomos/anomos.git/Anomos/server.key.secure')
    shell = pexpect.spawn('mv /home/rich/anomos/anomos.git/Anomos/server.key.insecure /home/rich/anomos/anomos.git/Anomos/server.key')
    
if __name__ == "__main__":
    makeNewCert()
    


