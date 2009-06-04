# zurllib.py
#
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

# by Robert Stone 2/22/2003

##################################################
# Notes:
# This is (hopefully) a drop-in for urllib which will request gzip/deflate
# compression and then decompress the output if a compressed response is
# received while maintaining the API.
##################################################

from urllib import *
from urllib2 import *
from gzip import GzipFile
from StringIO import StringIO
import pprint

from Anomos import version

DEBUG=1


class HTTPContentEncodingHandler(HTTPHandler):
    """Inherit and add gzip/deflate/etc support to HTTP gets."""
    def http_open(self, req):
        # add the Accept-Encoding header to the request
        # support gzip encoding (identity is assumed)
        req.add_header("Accept-Encoding","gzip")
        req.add_header('User-Agent', 'Anomos/' + version)
        if DEBUG:
            print "Sending:"
            print req.headers
            print "\n"
        fp = HTTPHandler.http_open(self,req)
        headers = fp.headers
        if DEBUG:
             pprint.pprint(headers.dict)
        url = fp.url
        resp = addinfourldecompress(fp, headers, url)
        if hasattr(fp, 'code'):
            resp.code = fp.code
        if hasattr(fp, 'msg'):
            resp.msg = fp.msg
        return resp


class addinfourldecompress(addinfourl):
    """Do gzip decompression if necessary. Do addinfourl stuff too."""
    def __init__(self, fp, headers, url):
        # we need to do something more sophisticated here to deal with
        # multiple values?  What about other weird crap like q-values?
        # basically this only works for the most simplistic case and will
        # break in some other cases, but for now we only care about making
        # this work with the BT tracker so....
        if headers.has_key('content-encoding') and headers['content-encoding'] == 'gzip':
            if DEBUG:
                print "Contents of Content-encoding: " + headers['Content-encoding'] + "\n"
            self.gzip = 1
            self.rawfp = fp
            fp = GzipStream(fp)
        else:
            self.gzip = 0
        return addinfourl.__init__(self, fp, headers, url)

    def close(self):
        self.fp.close()
        if self.gzip:
            self.rawfp.close()

    def iscompressed(self):
        return self.gzip

class GzipStream(StringIO):
    """Magically decompress a file object.

       This is not the most efficient way to do this but GzipFile() wants
       to seek, etc, which won't work for a stream such as that from a socket.
       So we copy the whole shebang info a StringIO object, decompress that
       then let people access the decompressed output as a StringIO object.

       The disadvantage is memory use and the advantage is random access.

       Will mess with fixing this later.
    """

    def __init__(self,fp):
        self.fp = fp

        # this is nasty and needs to be fixed at some point
        # copy everything into a StringIO (compressed)
        compressed = StringIO()
        r = fp.read()
        while r:
            compressed.write(r)
            r = fp.read()
        # now, unzip (gz) the StringIO to a string
        compressed.seek(0,0)
        gz = GzipFile(fileobj = compressed)
        str = ''
        r = gz.read()
        while r:
            str += r
            r = gz.read()
        # close our utility files
        compressed.close()
        gz.close()
        # init our stringio selves with the string
        StringIO.__init__(self, str)
        del str

    def close(self):
        self.fp.close()
        return StringIO.close(self)


def test():
    """Test this module.

       At the moment this is lame.
    """

    print "Running unit tests.\n"

    def printcomp(fp):
        try:
            if fp.iscompressed():
                print "GET was compressed.\n"
            else:
                print "GET was uncompressed.\n"
        except:
            print "no iscompressed function!  this shouldn't happen"

    print "Trying to GET a compressed document...\n"
    fp = urlopen('http://a.scarywater.net/hng/index.shtml')
    print fp.read()
    printcomp(fp)
    fp.close()

    print "Trying to GET an unknown document...\n"
    fp = urlopen('http://www.otaku.org/')
    print fp.read()
    printcomp(fp)
    fp.close()


#
# Install the HTTPContentEncodingHandler that we've defined above.
#
install_opener(build_opener(HTTPContentEncodingHandler, ProxyHandler({})))

if __name__ == '__main__':
    test()

