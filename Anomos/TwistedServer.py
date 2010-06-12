import sys
import M2Crypto.X509 as X509
import M2Crypto.m2 as m2
import M2Crypto.SSL.TwistedProtocolWrapper as wrapper
import twisted.internet.reactor as reactor
import twisted.python.log as twistlog

from twisted.web import http

from Anomos.parseargs import parseargs, formatDefinitions
from Anomos.track import defaults, isotime, Tracker
import Anomos.Crypto
from Anomos.EventHandler import EventHandler
from Anomos import LOG as log

class HTTPSRequestHandler(http.Request):
    tracker = None
    def process(self):
        resp = self.tracker.get(self, self.uri, self.getAllHeaders())
        if resp is not None:
            code, message, headers, data = resp
            self.setResponseCode(code, message=message)
            self.setHeader('Content-Length', len(data))
            for k,v in headers.items():
                self.setHeader(k, v)
            self.write(data)
        self.finish()

    def get_peer_cert(self):
        return X509.X509(m2.ssl_get_peer_cert(self.transport.ssl._ptr()), 1)

class HTTPS(http.HTTPChannel):
    requestFactory = HTTPSRequestHandler

class HTTPSFactory(http.HTTPFactory):
    protocol = HTTPS
    timeOut = 15

class ServerCTXFactory(object):
    def __init__(self, cert):
        self.ctx = cert.get_ctx(allow_unknown_ca=True,
                                req_peer_cert=False,
                                session="tracker")
    def getContext(self):
        return self.ctx

def track(args):
    if len(args) == 0:
        print formatDefinitions(defaults, 80)
        return
    try:
        config, files = parseargs(args, defaults, 0, 0)
    except ValueError, e:
        print 'error: ' + str(e)
        print 'run with no arguments for parameter explanations'
        return

    twistlog.PythonLoggingObserver(loggerName='anomos').start()

    Anomos.Crypto.init(config['data_dir'])
    servercert = Anomos.Crypto.Certificate("server", True, True)
    e = EventHandler()
    t = Tracker(config, servercert, reactor.callLater)
    HTTPSRequestHandler.tracker = t
    try:
        wrapper.listenSSL(config['port'],
                          HTTPSFactory(),
                          ServerCTXFactory(servercert))
    except Exception, e:
        log.critical("Cannot start tracker. %s" % e)
    else:
        reactor.run()
        print '# Shutting down: ' + isotime()

