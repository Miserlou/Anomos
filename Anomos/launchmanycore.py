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

# Original version written by John Hoffman, heavily modified for different
# multitorrent architecture by Uoti Urpala (over 40% shorter than original)

import os
from cStringIO import StringIO
from traceback import print_exc

from Anomos.parsedir import parsedir
from Anomos.download import Multitorrent, Feedback
from Anomos.ConvertedMetainfo import ConvertedMetainfo
from Anomos import bttime, configfile, BTFailure

from threading import Event


class LaunchMany(Feedback):

    def __init__(self, config, output, configfile_key):
        try:
            self.config = config
            self.output = output
            self.configfile_key = configfile_key

            self.torrent_dir = config['torrent_dir']
            self.torrent_cache = {}
            self.file_cache = {}
            self.blocked_files = {}

            self.torrent_list = []
            self.downloads = {}
            self.doneflag = Event()

            self.hashcheck_queue = []
            self.hashcheck_store = {}
            self.hashcheck_current = None

            self.multitorrent = Multitorrent(config, self.doneflag)

            self.multitorrent.schedule(0, self.scan)
            self.multitorrent.schedule(0, self.stats)

            try:
                import signal
                def handler(signum, frame):
                    self.multitorrent.schedule(0, self.read_config)
                signal.signal(signal.SIGHUP, handler)
            except Exception, e:
                self.output.message('Could not set signal handler: ' + str(e))

            self.multitorrent.event_handler.loop()

            self.output.message('shutting down')
            for infohash in self.torrent_list:
                self.output.message('dropped "'+self.torrent_cache[infohash]['path']+'"')
                torrent = self.downloads[infohash]
                if torrent is not None:
                    torrent.shutdown()
        except:
            data = StringIO()
            print_exc(file = data)
            output.exception(data.getvalue())

    def scan(self):
        self.multitorrent.schedule(self.config['parse_dir_interval'], self.scan)

        r = parsedir(self.torrent_dir, self.torrent_cache,
                     self.file_cache, self.blocked_files,
                     self.output.message)

        ( self.torrent_cache, self.file_cache, self.blocked_files,
            added, removed ) = r

        for infohash, data in removed.items():
            self.output.message('dropped "'+data['path']+'"')
            self.remove(infohash)
        for infohash, data in added.items():
            self.output.message('added "'+data['path']+'"')
            self.add(infohash, data)

    def stats(self):
        self.multitorrent.schedule(self.config['display_interval'], self.stats)
        data = []
        for infohash in self.torrent_list:
            cache = self.torrent_cache[infohash]
            if self.config['display_path']:
                name = cache['path']
            else:
                name = cache['name']
            size = cache['length']
            d = self.downloads[infohash]
            progress = '0.0%'
            peers = 0
            seeds = 0
            seedsmsg = "S"
            dist = 0.0
            uprate = 0.0
            dnrate = 0.0
            upamt = 0
            dnamt = 0
            t = 0
            msg = ''
            if d is None:
                status = 'waiting for hash check'
            else:
                stats = d.get_status()
                status = stats['activity']
                progress = '%.1f%%' % (int(stats['fractionDone']*1000)/10.0)
                if d.started and not d.closed:
                    s = stats
                    dist = s['numCopies']
                    if d.is_seed:
                        seeds = 0 # s['numOldSeeds']
                        seedsmsg = "s"
                    else:
                        if s['numSeeds'] + s['numPeers']:
                            t = stats['timeEst']
                            if t is None:
                                t = -1
                            if t == 0:  # unlikely
                                t = 0.01
                            status = 'downloading'
                        else:
                            t = -1
                            status = 'connecting to peers'
                        seeds = s['numSeeds']
                        dnrate = stats['downRate']
                    peers = s['numPeers']
                    uprate = stats['upRate']
                    upamt = s['upTotal']
                    dnamt = s['downTotal']
                if d.messages and (d.closed or d.messages[-1][0] + 300 > bttime()):
                    msg = d.messages[-1][2]

            data.append(( name, status, progress, peers, seeds, seedsmsg, dist,
                          uprate, dnrate, upamt, dnamt, size, t, msg ))
        stop = self.output.display(data)
        if stop:
            self.doneflag.set()

    def remove(self, infohash):
        self.torrent_list.remove(infohash)
        if self.downloads[infohash] is not None:
            self.downloads[infohash].shutdown()
        self.was_stopped(infohash)
        del self.downloads[infohash]

    def add(self, infohash, data):
        self.torrent_list.append(infohash)
        self.downloads[infohash] = None
        self.hashcheck_queue.append(infohash)
        self.hashcheck_store[infohash] = data['metainfo']
        self.check_hashcheck_queue()

    def check_hashcheck_queue(self):
        if self.hashcheck_current is not None or not self.hashcheck_queue:
            return
        self.hashcheck_current = self.hashcheck_queue.pop(0)
        metainfo = self.hashcheck_store[self.hashcheck_current]
        del self.hashcheck_store[self.hashcheck_current]
        filename = self.determine_filename(self.hashcheck_current)
        self.downloads[self.hashcheck_current] = self.multitorrent. \
                          start_torrent(ConvertedMetainfo(metainfo),
                                        self.config, self, filename)

    def determine_filename(self, infohash):
        x = self.torrent_cache[infohash]
        name = x['name']
        savein = self.config['save_in']
        isdir = not x['metainfo'].has_key('length')
        style = self.config['saveas_style']
        if style == 1 or style == 3:
            if savein:
                name = x['file']
                ext = max(name.find('.torrent'), name.find('.atorrent'))
                saveas = os.path.join(savein,name[:ext]) # strip '.[a]torrent'
            else:
                name = x['path']
                ext = max(name.find('.torrent'), name.find('.atorrent'))
                saveas = x['path'][:ext] # strip '.[a]torrent'
            if style == 3 and not isdir:
                saveas = os.path.join(saveas, name)
        else:
            if savein:
                saveas = os.path.join(savein, name)
            else:
                saveas = os.path.join(os.path.split(x['path'])[0], name)
        return saveas

    def was_stopped(self, infohash):
        try:
            self.hashcheck_queue.remove(infohash)
        except:
            pass
        else:
            del self.hashcheck_store[infohash]
        if self.hashcheck_current == infohash:
            self.hashcheck_current = None
        self.check_hashcheck_queue()

    def exchandler(self, s):
        self.output.exception(s)

    def read_config(self):
        try:
            newvalues = configfile.get_config(self.config, self.configfile_key)
        except Exception, e:
            self.output.message('Error reading config: ' + str(e))
            return
        self.output.message('Rereading config file')
        self.config.update(newvalues)
        # The set_option call can potentially trigger something that kills
        # the torrent (when writing this the only possibility is a change in
        # max_files_open causing an IOError while closing files), and so
        # the self.failed() callback can run during this loop.
        for option, value in newvalues.iteritems():
            self.multitorrent.set_option(option, value)
        for torrent in self.downloads.values():
            if torrent is not None:
                for option, value in newvalues.iteritems():
                    torrent.set_option(option, value)

    # rest are callbacks from torrent instances

    def started(self, torrent):
        self.hashcheck_current = None
        self.check_hashcheck_queue()

    def failed(self, torrent, is_external):
        infohash = torrent.infohash
        self.was_stopped(infohash)
        if self.torrent_cache.has_key(infohash):
            self.output.message('DIED: "'+self.torrent_cache[infohash]['path']+'"')

    def exception(self, torrent, text):
        self.exchandler(text)
