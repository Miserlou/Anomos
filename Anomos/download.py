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

# Written by Bram Cohen and Uoti Urpala

from __future__ import division
# required for python 2.2
from __future__ import generators

import os
import sys
import threading
import gc
from socket import error as socketerror
from cStringIO import StringIO
from traceback import print_exc
from math import sqrt

import random

from Anomos.Choker import Choker
from Anomos.ConvertedMetainfo import set_filesystem_encoding
from Anomos.CurrentRateMeasure import Measure
from Anomos.Downloader import Downloader
from Anomos.DownloaderFeedback import DownloaderFeedback
from Anomos.EndPoint import EndPoint
from Anomos.NeighborManager import NeighborManager
from Anomos.PiecePicker import PiecePicker
from Anomos.RateLimiter import RateLimiter
from Anomos.RateMeasure import RateMeasure
from Anomos.RawServer import RawServer
from Anomos.Rerequester import Rerequester
from Anomos.SingleportListener import SingleportListener
from Anomos.Storage import Storage, FilePool
from Anomos.StorageWrapper import StorageWrapper
from Anomos.Torrent import Torrent
from Anomos.Uploader import Upload
from Anomos.platform import bttime
from Anomos import version
from Anomos import BTFailure, BTShutdown, INFO, WARNING, ERROR, CRITICAL

from Anomos.crypto import Certificate, initCrypto
import Anomos.crypto as crypto

class Feedback(object):

    def finished(self, torrent):
        pass

    def failed(self, torrent, is_external):
        pass

    def error(self, torrent, level, text):
        pass

    def exception(self, torrent, text):
        self.error(torrent, CRITICAL, text)

    def started(self, torrent):
        pass


class Multitorrent(object):

    def __init__(self, config, doneflag, logfunc, listen_fail_ok=False):
        self.config = dict(config)
        self.logfunc = logfunc
        initCrypto(self.config['data_dir'])
        self.sessionid = crypto.getRand(8)
        self.certificate = Certificate(self.config['identity'])
        self.rawserver = RawServer(doneflag, config, self.certificate, logfunc=logfunc,
                                   bindaddr=config['bind'])
        self.neighbors = NeighborManager(self.rawserver, config,
                                           self.certificate, self.logfunc,
                                           self.sessionid)
        self.singleport_listener = SingleportListener(self.rawserver, self.config,
                                                      self.neighbors,
                                                      self.certificate,
                                                      self.sessionid)
        self._find_port(listen_fail_ok)
        self.filepool = FilePool(config['max_files_open'])
        self.ratelimiter = RateLimiter(self.rawserver.add_task)
        self.ratelimiter.set_parameters(config['max_upload_rate'],
                                        config['upload_unit_size'])
        set_filesystem_encoding(config['filesystem_encoding'],
                                                 logfunc)

    def _find_port(self, listen_fail_ok=True):
        e = 'maxport less than minport - no ports to check'
        self.config['minport'] = max(1, self.config['minport'])
        for port in xrange(self.config['minport'], self.config['maxport'] + 1):
            try:
                self.singleport_listener.open_port(port, self.config)
                break
            except socketerror, e:
                pass
        else:
            if not listen_fail_ok:
                raise BTFailure, "Couldn't open a listening port: " + str(e)
            self.logfunc(CRITICAL, "Could not open a listening port: " +
                           str(e) + ". Check your port range settings.")

    def close_listening_socket(self):
        self.singleport_listener.close_sockets()

    def start_torrent(self, metainfo, config, feedback, filename):
        torrent = _SingleTorrent(self.rawserver, self.singleport_listener,
                                 self.ratelimiter, self.filepool, config,
                                 self.neighbors, self.certificate,
                                 self.sessionid)
        self.rawserver.add_context(torrent)
        def start():
            torrent.start_download(metainfo, feedback, filename)
        self.rawserver.add_task(start, 0, torrent)
        return torrent

    def set_option(self, option, value):
        if option not in self.config or self.config[option] == value:
            return
        if option not in 'max_upload_rate upload_unit_size '\
               'max_files_open minport maxport'.split():
            return
        self.config[option] = value
        if option == 'max_files_open':
            self.filepool.set_max_files_open(value)
        elif option == 'max_upload_rate':
            self.ratelimiter.set_parameters(value,
                                            self.config['upload_unit_size'])
        elif option == 'upload_unit_size':
            self.ratelimiter.set_parameters(self.config['max_upload_rate'],
                                            value)
        elif option == 'maxport':
            if not self.config['minport'] <= self.singleport_listener.port <= \
                   self.config['maxport']:
                self._find_port()

    def get_completion(self, config, metainfo, save_path, filelist=False):
        if not config['data_dir']:
            return None
        infohash = metainfo.infohash
        if metainfo.is_batch:
            myfiles = [os.path.join(save_path, f) for f in metainfo.files_fs]
        else:
            myfiles = [save_path]

        if metainfo.total_bytes == 0:
            if filelist:
                return None
            return 1
        try:
            s = Storage(None, None, zip(myfiles, metainfo.sizes),
                        check_only=True)
        except:
            return None
        filename = os.path.join(config['data_dir'], 'resume',
                                infohash.encode('hex'))
        try:
            f = file(filename, 'rb')
        except:
            f = None
        try:
            r = s.check_fastresume(f, filelist, metainfo.piece_length,
                                   len(metainfo.hashes), myfiles)
        except:
            r = None
        if f is not None:
            f.close()
        if r is None:
            return None
        if filelist:
            return r[0] / metainfo.total_bytes, r[1], r[2]
        return r / metainfo.total_bytes

        ##Relayers don't exist at the torrent level, so we need these methods
        ## to access their stats through the SinglePortListener.
    def get_relay_rate(self):
        return self.singleport_listener.get_relay_rate()

    def get_relay_size(self):
        return self.singleport_listener.get_relay_size()

    def get_relay_sent(self):
        return self.singleport_listener.get_relay_sent()


class _SingleTorrent(object):

    def __init__(self, rawserver, singleport_listener, ratelimiter, filepool,
                 config, neighbors, certificate, sessionid):
        self._rawserver = rawserver
        self._singleport_listener = singleport_listener
        self._ratelimiter = ratelimiter
        self._filepool = filepool
        self.config = dict(config)
        self._storage = None
        self._storagewrapper = None
        self._ratemeasure = None
        self._upmeasure = None
        self._downmeasure = None
        self._torrent = None
        self._rerequest = None
        self._statuscollecter = None
        self._announced = False
        self._listening = False
        self.reserved_ports = []
        self.reported_port = None
        self._myfiles = None
        self.started = False
        self.is_seed = False
        self.closed = False
        self.infohash = None
        self.total_bytes = None
        self._doneflag = threading.Event()
        self.finflag = threading.Event()
        self._hashcheck_thread = None
        self._contfunc = None
        self._activity = ('Initial startup', 0)
        self.feedback = None
        self.messages = []
        self.neighbors = neighbors
        self.certificate = certificate
        self.sessionid = sessionid

    def start_download(self, *args, **kwargs):
        it = self._start_download(*args, **kwargs)
        def cont():
            try:
                it.next()
            except StopIteration:
                self._contfunc = None
        def contfunc():
            self._rawserver.external_add_task(cont, 0, self)
        self._contfunc = contfunc
        contfunc()

    def _start_download(self, metainfo, feedback, save_path):
        self.feedback = feedback
        self._set_auto_uploads()

        self.infohash = metainfo.infohash
        self.total_bytes = metainfo.total_bytes
        if not metainfo.reported_errors:
            metainfo.show_encoding_errors(self._log)

        def schedfunc(func, delay):
            self._rawserver.add_task(func, delay, self)
        def externalsched(func, delay):
            self._rawserver.external_add_task(func, delay, self)
        if metainfo.is_batch:
            myfiles = [os.path.join(save_path, f) for f in metainfo.files_fs]
        else:
            myfiles = [save_path]
        self._filepool.add_files(myfiles, self)
        self._myfiles = myfiles
        self._storage = Storage(self.config, self._filepool, zip(myfiles,
                                                            metainfo.sizes))
        resumefile = None
        if self.config['data_dir']:
            filename = os.path.join(self.config['data_dir'], 'resume',
                                    self.infohash.encode('hex'))
            if os.path.exists(filename):
                try:
                    resumefile = file(filename, 'rb')
                    if self._storage.check_fastresume(resumefile) == 0:
                        resumefile.close()
                        resumefile = None
                except Exception, e:
                    self._log(WARNING, 'Could not load fastresume data: '+
                                str(e) + '. Will perform full hash check.')
                    if resumefile is not None:
                        resumefile.close()
                    resumefile = None
        def data_flunked(amount, index):
            self._ratemeasure.data_rejected(amount)
            self._log(INFO, 'piece %d failed hash check, '
                        're-downloading it' % index)
        backthread_exception = []
        def safelogfunc(level, text):
            def e():
                self._log(level, text)
            externalsched(e, 0)
        def hashcheck():
            def statusfunc(activity = None, fractionDone = 0):
                if activity is None:
                    activity = self._activity[0]
                self._activity = (activity, fractionDone)
            try:
                self._storagewrapper = StorageWrapper(self._storage,
                     self.config, metainfo.hashes, metainfo.piece_length,
                     self._finished, statusfunc, self._doneflag, data_flunked,
                     self.infohash, safelogfunc, resumefile)
            except:
                backthread_exception.append(sys.exc_info())
            self._contfunc()
        thread = threading.Thread(target = hashcheck)
        thread.setDaemon(False)
        self._hashcheck_thread = thread
        thread.start()
        yield None
        self._hashcheck_thread = None
        if resumefile is not None:
            resumefile.close()
        if backthread_exception:
            a, b, c = backthread_exception[0]
            raise a, b, c

        if self._storagewrapper.amount_left == 0:
            self._finished()
        choker = Choker(self.config, schedfunc, self.finflag.isSet)
        upmeasure = Measure(self.config['max_rate_period'])
        upmeasure_seedtime = Measure(self.config['max_rate_period_seedtime'])
        downmeasure = Measure(self.config['max_rate_period'])
        self._upmeasure = upmeasure
        self._downmeasure = downmeasure
        self._ratemeasure = RateMeasure(self._storagewrapper.
                                        amount_left_with_partials)
        picker = PiecePicker(len(metainfo.hashes), self.config)
        for i in xrange(len(metainfo.hashes)):
            if self._storagewrapper.do_I_have(i):
                picker.complete(i)
        for i in self._storagewrapper.stat_dirty:
            picker.requested(i)
        def kickpeer(connection):
            def kick():
                connection.close()
            schedfunc(kick, 0)
        def banpeer(ip):
            self.neighbors.ban(ip)
        downloader = Downloader(self.config, self._storagewrapper, picker,
            len(metainfo.hashes), downmeasure, self._ratemeasure.data_came_in,
                                kickpeer, banpeer)
        def make_upload(connection):
            return Upload(connection, self._ratelimiter, upmeasure,
                        upmeasure_seedtime, choker, self._storagewrapper,
                        self.config['max_slice_length'], self.config['max_rate_period'])
        self._torrent = Torrent(self.infohash, make_upload,
                                downloader, len(metainfo.hashes)) 
        self.reported_port = self.config['forwarded_port']
        if not self.reported_port:
            self.reported_port = self._singleport_listener.get_port()
            self.reserved_ports.append(self.reported_port)
        self._singleport_listener.add_torrent(self.infohash, self._torrent)
        self._listening = True
        self._rerequest = Rerequester(metainfo.announce, self.config,
            schedfunc, self.neighbors, externalsched,
            self._storagewrapper.get_amount_left, upmeasure.get_total,
            downmeasure.get_total, self.reported_port, self.infohash,
            self._log, self.finflag, upmeasure.get_rate,
            downmeasure.get_rate, self._torrent.ever_got_incoming,
            self.internal_shutdown, self._announce_done, self.certificate,
            self.sessionid)
            # = Requester(metainfo.announce, schedfunc, externalsched, upmeasure
            #             downmeasure, self)
        self._statuscollecter = DownloaderFeedback(choker, upmeasure.get_rate,
            upmeasure_seedtime.get_rate, downmeasure.get_rate,
            upmeasure.get_total, downmeasure.get_total,
            self._ratemeasure.get_time_left, self._ratemeasure.get_size_left,
            self.total_bytes, self.finflag, downloader, self._myfiles)

        self._announced = True
        self._rerequest.begin()
        self.started = True
        if not self.finflag.isSet():
            self._activity = ('downloading', 0)
        self.feedback.started(self)

    def got_exception(self, e):
        is_external = False
        if isinstance(e, BTShutdown):
            self._log(ERROR, str(e))
            is_external = True
        elif isinstance(e, BTFailure):
            self._log(CRITICAL, str(e))
            self._activity = ('download failed: ' + str(e), 0)
        elif isinstance(e, IOError):
            self._log(CRITICAL, 'IO Error ' + str(e))
            self._activity = ('killed by IO error: ' + str(e), 0)
        elif isinstance(e, OSError):
            self._log(CRITICAL, 'OS Error ' + str(e))
            self._activity = ('killed by OS error: ' + str(e), 0)
        else:
            data = StringIO()
            print_exc(file=data)
            self._log(CRITICAL, data.getvalue(), True)
            self._activity = ('killed by internal exception: ' + str(e), 0)
        try:
            self._close()
        except Exception, e:
            self._log(ERROR, 'Additional error when closing down due to '
                        'error: ' + str(e))
        if is_external:
            self.feedback.failed(self, True)
            return
        if self.config['data_dir'] and self._storage is not None:
            filename = os.path.join(self.config['data_dir'], 'resume',
                                    self.infohash.encode('hex'))
            if os.path.exists(filename):
                try:
                    os.remove(filename)
                except Exception, e:
                    self._log(WARNING, 'Could not remove fastresume file '
                                'after failure:' + str(e))
        self.feedback.failed(self, False)

    def _finished(self):
        self.finflag.set()
        # Call self._storage.close() to flush buffers and change files to
        # read-only mode (when they're possibly reopened). Let exceptions
        # from self._storage.close() kill the torrent since files might not
        # be correct on disk if file.close() failed.
        self._storage.close()
        # If we haven't announced yet, normal first announce done later will
        # tell the tracker about seed status.
        self.is_seed = True
        if self._announced:
            self._rerequest.announce_finish()
        self._activity = ('seeding', 1)
        if self.config['check_hashes']:
            self._save_fastresume(True)
        self.feedback.finished(self)

    def _save_fastresume(self, on_finish=False):
        if not on_finish and (self.finflag.isSet() or not self.started):
            return
        if not self.config['data_dir']:
            return
        if on_finish:    # self._ratemeasure might not exist yet
            amount_done = self.total_bytes
        else:
            amount_done = self.total_bytes - self._ratemeasure.get_size_left()
        filename = os.path.join(self.config['data_dir'], 'resume',
                                self.infohash.encode('hex'))
        resumefile = None
        try:
            resumefile = file(filename, 'wb')
            self._storage.write_fastresume(resumefile, amount_done)
            self._storagewrapper.write_fastresume(resumefile)
            resumefile.close()
        except Exception, e:
            self._log(WARNING, 'Could not write fastresume data: ' + str(e))
            if resumefile is not None:
                resumefile.close()

    def shutdown(self):
        if self.closed:
            return
        try:
            self._close()
            self._save_fastresume()
            self._activity = ('shut down', 0)
        except Exception, e:
            self.got_exception(e)

    def internal_shutdown(self, level, text):
        # This is only called when announce fails with no peers,
        # don't try to announce again telling we're leaving the torrent
        self._announced = False
        self._log(level, text)
        self.shutdown()
        self.feedback.failed(self, True)

    def _close(self):
        if self.closed:
            return
        self.closed = True
        self._rawserver.remove_context(self)
        self._doneflag.set()
        self._log(INFO, "Closing connections, please wait...")
        if self._announced:
            self._rerequest.announce_stop()
            self._rerequest.cleanup()
        if self._hashcheck_thread is not None:
            self._hashcheck_thread.join() # should die soon after doneflag set
        if self._myfiles is not None:
            self._filepool.remove_files(self._myfiles)
        if self._listening:
            self._singleport_listener.remove_torrent(self.infohash)
        for port in self.reserved_ports:
            self._singleport_listener.release_port(port)
        #TODO: Close NeighborManager connections
        if self._storage is not None:
            self._storage.close()
        self._ratelimiter.clean_closed()
        self._rawserver.add_task(gc.collect, 0, None)

    def get_status(self, spew = False, fileinfo=False):
        if self.started and not self.closed:
            r = self._statuscollecter.get_statistics(spew, fileinfo)
            r['activity'] = self._activity[0]
        else:
            r = dict(zip(('activity', 'fractionDone'), self._activity))
        return r

    def get_total_transfer(self):
        if self._upmeasure is None:
            return (0, 0)
        return (self._upmeasure.get_total(), self._downmeasure.get_total())

    def set_option(self, option, value):
        if self.closed:
            return
        if option not in self.config or self.config[option] == value:
            return
        if option not in 'min_uploads max_uploads max_initiate max_allow_in '\
           'data_dir ip max_upload_rate retaliate_to_garbled_data'.split():
            return
        # max_upload_rate doesn't affect upload rate here, just auto uploads
        self.config[option] = value
        self._set_auto_uploads()

    def change_port(self):
        if not self._listening:
            return
        r = self.config['forwarded_port']
        if r:
            for port in self.reserved_ports:
                self._singleport_listener.release_port(port)
            del self.reserved_ports[:]
            if self.reported_port == r:
                return
        elif self._singleport_listener.port != self.reported_port:
            r = self._singleport_listener.get_port()
            self.reserved_ports.append(r)
        else:
            return
        self.reported_port = r
        self._rerequest.change_port(r)

    def _announce_done(self):
        for port in self.reserved_ports[:-1]:
            self._singleport_listener.release_port(port)
        del self.reserved_ports[:-1]

    def _set_auto_uploads(self):
        uploads = self.config['max_uploads']
        rate = self.config['max_upload_rate']
        if uploads > 0:
            pass
        elif rate <= 0:
            uploads = 7 # unlimited, just guess something here...
        elif rate < 9:
            uploads = 2
        elif rate < 15:
            uploads = 3
        elif rate < 42:
            uploads = 4
        else:
            uploads = int(sqrt(rate * .6))
        self.config['max_uploads_internal'] = uploads

    def _log(self, level, text, exception=False):
        self.messages.append((bttime(), level, text))
        if exception:
            self.feedback.exception(self, text)
        else:
            self.feedback.error(self, level, text)
