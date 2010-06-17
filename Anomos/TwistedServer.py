import sys
import M2Crypto.X509 as X509
import M2Crypto.m2 as m2
import twisted.python.log as twistlog
import twisted.web.http as http
import twisted.protocols.policies as policies
import M2Crypto.SSL.TwistedProtocolWrapper as wrapper

from twisted.internet.selectreactor import SelectReactor, _NO_FILENO, _NO_FILEDESC

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
    def requestDone(self, request):
        """
        Called by first request in queue when it is done.
        """
        if request != self.requests[0]: raise TypeError
        del self.requests[0]

        self.transport.loseConnection()

    def timeoutConnection(self):
        policies.TimeoutMixin.timeoutConnection(self)


class HTTPSFactory(http.HTTPFactory):
    protocol = HTTPS
    timeOut = 10
    noisy = False
    def __init__(self, logPath=None):
        if logPath is not None:
            logPath = os.path.abspath(logPath)
        self.logPath = logPath


class ServerCTXFactory(object):
    def __init__(self, cert):
        self.ctx = cert.get_ctx(allow_unknown_ca=True,
                                req_peer_cert=False,
                                session="tracker")
    def getContext(self):
        return self.ctx


class SSLSelectReactor(SelectReactor):
    def _doReadOrWrite(self, selectable, method, dict):
        try:
            why = getattr(selectable, method)()
            handfn = getattr(selectable, 'fileno', None)
            if not handfn:
                why = _NO_FILENO
            elif handfn() == -1:
                why = _NO_FILEDESC
        except:
            why = sys.exc_info()[1]
            log.info(repr(why))
        if why:
            self._disconnectSelectable(selectable, why, method=="doRead")
            selectable.loseConnection()

def install():
    del sys.modules['twisted.internet.reactor']
    reactor = SSLSelectReactor()
    from twisted.internet.main import installReactor
    installReactor(reactor)

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

    install()
    import twisted.internet.reactor as reactor
    twistlog.PythonLoggingObserver(loggerName='anomos').start()

    Anomos.Crypto.init(config['data_dir'])
    servercert = Anomos.Crypto.Certificate("server", True, True)
    e = EventHandler()
    t = Tracker(config, servercert, reactor.callLater)
    t.natchecker.reactor = reactor
    HTTPSRequestHandler.tracker = t
    try:
        from socket import SOMAXCONN
        wrapper.noisy = False
        wrapper.listenSSL(config['port'],
                          HTTPSFactory(),
                          ServerCTXFactory(servercert),
                          interface=config['bind'],
                          backlog=SOMAXCONN,
                          reactor=reactor)
    except Exception, e:
        log.critical("Cannot start tracker. %s" % e)
    else:
        reactor.run()
        print '# Shutting down: ' + isotime()

