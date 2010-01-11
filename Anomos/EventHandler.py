import asyncore
import bisect
import os
import select
import threading
import time
import traceback

from Anomos import bttime, LOG as log

class EventHandler(object):
    def __init__(self, doneflag=None, map=None):
        if doneflag is not None:
            self.doneflag = doneflag
        else:
            self.doneflag = threading.Event()

        self.map = map
        if self.map is None:
            self.map = asyncore.socket_map

        self.tasks = [] # [[time, function, [arg0,...,argN]], ...]
        self.externally_added = []
        self.thread = threading.currentThread()

        if os.name == 'posix':
            self.wakeup = WakeupPipe(*os.pipe())
        else:
            # Make this thread wake every second for systems that do
            # not support pipes with select.
            self.wakeup = None
            def wakeup():
                self.schedule(1, wakeup)
            wakeup()

    def _external_schedule(self, delay, func, context=None):
        self.externally_added.append([delay, func, context])
        if self.wakeup is not None:
            self.wakeup.now()

    def _pop_externally_added(self):
        while self.externally_added:
            self.schedule(*self.externally_added.pop(0))

    def schedule(self, delay, func, context=None):
        """ Insert a task into the queue in a threadsafe manner """
        if threading.currentThread() == self.thread:
            bisect.insort(self.tasks, (bttime() + delay, func, context))
        else:
            self._external_schedule(delay, func, context)

    def do_tasks(self):
        """ Do all tasks with timestamps <= than current time """
        context = None
        try:
            while len(self.tasks) > 0 and self.tasks[0][0] <= bttime():
                _, f, context = self.tasks.pop(0)
                apply(f)
        except Exception, e:
            if context is not None:
                context.got_exception(e)

    def loop(self):
        while not self.doneflag.isSet():
            try:
                self._pop_externally_added()
                period = 1e9
                if len(self.tasks) > 0:
                    # Poll until the next task is set to execute
                    period = max(0, self.tasks[0][0] - bttime())
                asyncore.poll(period)
                self.do_tasks()
            except KeyboardInterrupt:
                break
            except:
                log.critical('\n'+traceback.format_exc())
                break

if os.name == 'posix':
    class WakeupFD(asyncore.file_dispatcher):
        def handle_read(self):
            self.read(1)
        def handle_close(self):
            self.close()
        def writable(self):
            return False

    class WakeupPipe(object):
        def __init__(self, r, w):
            self.r = WakeupFD(r)
            self.w = w
        def now(self):
            os.write(self.w, '!')
