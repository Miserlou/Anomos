#!/usr/bin/env python

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

# Written by Anomos Liberty Enhancements

import sys

from Anomos.parseargs import parseargs, formatDefinitions
from Anomos.track import defaults, Tracker

from twisted.internet.main import installReactor
import M2Crypto.SSL.TwistedProtocolWrapper as wrapper
from socket import SOMAXCONN

import Anomos.Crypto
import Anomos.TwistedServer

import twisted.python.log as twistlog
from Anomos import LOG as log

def track(argv):
    if len(argv) == 0:
        print formatDefinitions(defaults, 80)
        return
    try:
        config, files = parseargs(argv, defaults, 0, 0)
    except ValueError, e:
        print 'error: ' + str(e)
        print 'run with no arguments for parameter explanations'
        return

    #Setup Twisted
    # Install the SSLSelectReactor
    del sys.modules['twisted.internet.reactor']
    reactor = Anomos.TwistedServer.SSLSelectReactor()
    installReactor(reactor)
    # Start logging
    twistlog.PythonLoggingObserver(loggerName='anomos').start()

    Anomos.Crypto.init(config['data_dir'])
    servercert = Anomos.Crypto.Certificate(loc="server", tracker=True, ephemeral=False)
    t = Tracker(config, servercert, reactor.callLater)
    t.natchecker.reactor = reactor
    Anomos.TwistedServer.HTTPSRequestHandler.tracker = t
    try:
        wrapper.noisy = False
        wrapper.listenSSL(config['port'],
                          Anomos.TwistedServer.HTTPSFactory(),
                          Anomos.TwistedServer.ServerCTXFactory(servercert),
                          interface=config['bind'],
                          backlog=SOMAXCONN,
                          reactor=reactor)
    except Exception, e:
        log.critical("Cannot start tracker. %s" % e)
    else:
        reactor.run()
        log.info('Shutting down')


if __name__ == '__main__':
    track(sys.argv[1:])
