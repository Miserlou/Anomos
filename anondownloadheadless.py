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

# Written by Bram Cohen, Uoti Urpala and John Hoffman
from __future__ import division

import sys
import os
import threading

from time import time, strftime
from signal import signal, SIGWINCH
from cStringIO import StringIO

from Anomos.download import Feedback, Multitorrent
from Anomos.defaultargs import get_defaults
from Anomos.parseargs import parseargs, printHelp
from Anomos.zurllib import urlopen
from Anomos.bencode import bdecode
from Anomos.ConvertedMetainfo import ConvertedMetainfo
from Anomos import configfile
from Anomos import BTFailure
from Anomos import version
from Anomos import LOG as log


def fmttime(n):
    if n == 0:
        return 'download complete!'
    try:
        n = int(n)
        assert n >= 0 and n < 5184000  # 60 days
    except:
        return '<unknown>'
    m, s = divmod(n, 60)
    h, m = divmod(m, 60)
    return 'finishing in %d:%02d:%02d' % (h, m, s)

def fmtsize(n):
    s = str(n)
    size = s[-3:]
    while len(s) > 3:
        s = s[:-3]
        size = '%s,%s' % (s[-3:], size)
    if n > 999:
        unit = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB']
        i = 1
        while i + 1 < len(unit) and (n >> 10) >= 999:
            i += 1
            n >>= 10
        n /= (1 << 10)
        size = '%s (%.0f %s)' % (size, n, unit[i])
    return size


class HeadlessDisplayer(object):

    def __init__(self, doneflag):
        self.doneflag = doneflag

        self.done = False
        self.percentDone = ''
        self.timeEst = ''
        self.downRate = '---'
        self.upRate = '---'
        self.shareRating = ''
        self.seedStatus = ''
        self.peerStatus = ''
        self.file = ''
        self.downloadTo = ''
        self.fileSize = ''
        self.numpieces = 0
        self.relayRate = '---'
        self.numRelays = 0

    def set_torrent_values(self, name, path, size, numpieces):
        self.file = name
        self.downloadTo = path
        self.fileSize = fmtsize(size)
        self.numpieces = numpieces

    def finished(self):
        self.done = True
        self.downRate = '---'
        self.display({'activity':'download succeeded', 'fractionDone':1})

    def display(self, statistics):
        fractionDone = statistics.get('fractionDone')
        activity = statistics.get('activity')
        timeEst = statistics.get('timeEst')
        downRate = statistics.get('downRate')
        upRate = statistics.get('upRate')
        relayRate = statistics.get('relayRate')
        numRelays = statistics.get('relayCount')
        spew = statistics.get('spew')

        if spew is not None:
            self.print_spew(spew)

        if timeEst is not None:
            self.timeEst = fmttime(timeEst)
        elif activity is not None:
            self.timeEst = activity

        if fractionDone is not None:
            self.percentDone = str(int(fractionDone * 1000) / 10)
        if downRate is not None:
            self.downRate = '%.1f KB/s' % (downRate / (1 << 10))
        if upRate is not None:
            self.upRate = '%.1f KB/s' % (upRate / (1 << 10))
        if relayRate is not None:
            self.relayRate = '%.1f KB/s' % (relayRate / (1 << 10))
        if numRelays is not None:
            self.numRelays = numRelays
        downTotal = statistics.get('downTotal')
        if downTotal is not None:
            upTotal = statistics['upTotal']
            if downTotal <= upTotal / 100:
                self.shareRating = 'oo  (%.1f MB up / %.1f MB down)' % (
                    upTotal / (1<<20), downTotal / (1<<20))
            else:
                self.shareRating = '%.3f  (%.1f MB up / %.1f MB down)' % (
                   upTotal / downTotal, upTotal / (1<<20), downTotal / (1<<20))
            numCopies = statistics['numCopies']
            nextCopies = ', '.join(["%d:%.1f%%" % (a,int(b*1000)/10) for a,b in
                    zip(xrange(numCopies+1, 1000), statistics['numCopyList'])])
            if not self.done:
                self.seedStatus = '%d seen now, plus %d distributed copies ' \
                                  '(%s)' % (statistics['numSeeds'],
                                         statistics['numCopies'], nextCopies)
            else:
                self.seedStatus = '%d distributed copies (next: %s)' % (
                    statistics['numCopies'], nextCopies)
            self.peerStatus = '%d seen now' % statistics['numPeers']

        #print 'saving:        ', self.file
        print '| percent done:  ', self.percentDone
        #print 'time left:     ', self.timeEst
        #print 'download to:   ', self.downloadTo
        print '| download rate: ', self.downRate
        print '| upload rate:   ', self.upRate
        #print 'share rating:  ', self.shareRating
        #print 'seed status:   ', self.seedStatus
        #print 'peer status:   ', self.peerStatus
        #print '|-'
        print '| relay rate:     %s (%s)' % (self.relayRate, self.numRelays)
        print '|-'
        print '| Active threads ', threading.activeCount()

    def print_spew(self, spew):
        s = StringIO()
        s.write('\n\n\n')
        for c in spew:
            s.write('%20s ' % c['ip'])
            if c['initiation'] == 'L':
                s.write('l')
            else:
                s.write('r')
            total, rate, interested, choked = c['upload']
            s.write(' %10s %10s ' % (str(int(total/10485.76)/100),
                                     str(int(rate))))
            if c['is_optimistic_unchoke']:
                s.write('*')
            else:
                s.write(' ')
            if interested:
                s.write('i')
            else:
                s.write(' ')
            if choked:
                s.write('c')
            else:
                s.write(' ')

            total, rate, interested, choked, snubbed = c['download']
            s.write(' %10s %10s ' % (str(int(total/10485.76)/100),
                                     str(int(rate))))
            if interested:
                s.write('i')
            else:
                s.write(' ')
            if choked:
                s.write('c')
            else:
                s.write(' ')
            if snubbed:
                s.write('s')
            else:
                s.write(' ')
            s.write('\n')
        print s.getvalue()

class DL(Feedback):

    def __init__(self, metainfo, config):
        self.doneflag = threading.Event()
        self.metainfo = metainfo
        self.config = config

    def run(self):
        self.d = HeadlessDisplayer(self.doneflag)
        try:
            self.multitorrent = Multitorrent(self.config, self.doneflag)
            # raises BTFailure if bad
            metainfo = ConvertedMetainfo(bdecode(self.metainfo))
            torrent_name = metainfo.name_fs
            if config['save_as']:
                if config['save_in']:
                    raise BTFailure('You cannot specify both --save_as and '
                                    '--save_in')
                saveas = config['save_as']
            elif config['save_in']:
                saveas = os.path.join(config['save_in'], torrent_name)
            else:
                saveas = torrent_name

            self.d.set_torrent_values(metainfo.name, os.path.abspath(saveas),
                                metainfo.file_size, len(metainfo.hashes))
            self.torrent = self.multitorrent.start_torrent(metainfo,
                                self.config, self, saveas)
        except BTFailure, e:
            print str(e)
            return
        self.get_status()
        self.multitorrent.event_handler.loop()
        self.d.display({'activity':'shutting down', 'fractionDone':0})
        self.torrent.shutdown()

    def reread_config(self):
        try:
            newvalues = configfile.get_config(self.config, 'anondownloadcurses')
        except Exception, e:
            log.error('Error reading config: ' + str(e))
            return
        self.config.update(newvalues)
        # The set_option call can potentially trigger something that kills
        # the torrent (when writing this the only possibility is a change in
        # max_files_open causing an IOError while closing files), and so
        # the self.failed() callback can run during this loop.
        for option, value in newvalues.iteritems():
            self.multitorrent.set_option(option, value)
        for option, value in newvalues.iteritems():
            self.torrent.set_option(option, value)

    def get_status(self):
        self.multitorrent.schedule(self.config['display_interval'], self.get_status)
        status = self.torrent.get_status(self.config['spew'])
        self.d.display(status)

    def failed(self, torrent, is_external):
        self.doneflag.set()

    def finished(self, torrent):
        self.d.finished()


if __name__ == '__main__':
    uiname = 'anondownloadheadless'
    defaults = get_defaults(uiname)

    if len(sys.argv) <= 1:
        printHelp(uiname, defaults)
        sys.exit(1)
    try:
        config, args = configfile.parse_configuration_and_args(defaults,
                                      uiname, sys.argv[1:], 0, 1)
        if args:
            if config['responsefile']:
                raise BTFailure, 'must have responsefile as arg or ' \
                      'parameter, not both'
            config['responsefile'] = args[0]
        try:
            if config['responsefile']:
                h = file(config['responsefile'], 'rb')
                metainfo = h.read()
                h.close()
            elif config['url']:
                h = urlopen(config['url'])
                metainfo = h.read()
                h.close()
            else:
                raise BTFailure('you need to specify a .torrent file')
        except IOError, e:
            raise BTFailure('Error reading .torrent file: ', str(e))
    except BTFailure, e:
        print str(e)
        sys.exit(1)

    dl = DL(metainfo, config)
    dl.run()
