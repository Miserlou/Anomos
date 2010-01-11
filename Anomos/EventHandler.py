import asyncore
import bisect
import os
import select
import threading
import time
import traceback

from Anomos import bttime, LOG as log

if os.name == 'posix':
    class WakeupFD(asyncore.file_dispatcher):
        def __init__(self, fd):
            asyncore.file_dispatcher.__init__(self, fd)
        def now(self):
            self.write("!")
        def handle_read(self):
            self.read(1)
        def handle_close(self):
            self.close()
        def handle_error(self):
            pass
        def writable(self):
            return False

    class WakeupPipe(object):
        def __init__(self):
            r,w = os.pipe()
            self.r = WakeupFD(r)
            self.w = WakeupFD(w)
        def now(self):
            self.w.now()

class EventHandler(object):
    def __init__(self, doneflag=None, map=None):
        if doneflag is not None:
            self.doneflag = doneflag
        else:
            from threading import Event
            self.doneflag = Event()

        self.map = map
        if self.map is None:
            self.map = asyncore.socket_map

        self.tasks = [] # [[time, function, [arg0,...,argN]], ...]
        self.externally_added = []
        self.thread = threading.currentThread()

        if os.name == 'posix':
            self.wakeup = WakeupPipe()
        else:
            # Make this thread wake every second for systems that do
            # not support pipes with select.
            self.wakeup = None
            def wakeup():
                self.schedule(1, wakeup)
            wakeup()

    def _external_schedule(self, delay, func, args=[]):
        self.externally_added.append([delay, func, args])
        if self.wakeup is not None:
            self.wakeup.now()

    def _pop_externally_added(self):
        while self.externally_added:
            self.schedule(*self.externally_added.pop(0))

    def schedule(self, delay, func, args=[]):
        """ Insert a task into the queue in a threadsafe manner """
        if threading.currentThread() == self.thread:
            bisect.insort(self.tasks, (bttime() + delay, func, args))
        else:
            self._external_schedule(delay, func, args)

    def loop(self):
        while not self.doneflag.isSet():
            try:
                self._pop_externally_added()
                period = 1e9
                if len(self.tasks) > 0:
                    # Poll until the next task is set to execute
                    period = max(0, self.tasks[0][0] - bttime())
                asyncore.poll(period)
                # Do all tasks with timestamps <= than current time
                while len(self.tasks) > 0 and self.tasks[0][0] <= bttime():
                    _, f, args = self.tasks.pop(0)
                    apply(f, args)
            except KeyboardInterrupt:
                break
            except:
                log.critical('\n'+traceback.format_exc())
                break
