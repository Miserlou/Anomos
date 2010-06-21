import asyncore
import socket
import sys
import traceback

from collections import deque

from errno import ECONNRESET, ENOTCONN, ESHUTDOWN
from Anomos import LOG as log
from M2Crypto import SSL

class Dispatcher (asyncore.dispatcher):
    """This is an abstract class.  You must derive from this class, and add
    the two methods collect_incoming_data() and found_terminator()"""

    # these are overridable defaults

    ac_in_buffer_size       = 4096
    ac_out_buffer_size      = 4096

    def __init__(self, conn=None):
        self.ac_in_buffer = ''
        self.ac_out_buffer = ''
        self.producer_fifo = fifo()
        self.zero_count = 0
        asyncore.dispatcher.__init__ (self, conn)

    def collect_incoming_data(self, data):
        raise NotImplementedError, "must be implemented in subclass"

    def found_terminator(self):
        raise NotImplementedError, "must be implemented in subclass"

    def recv(self, buffer_size):
        data = self._read_nbio(buffer_size)
        if not data:
            self.want_write = True
            data = ''
        return data

    def set_terminator (self, term):
        "Set the input delimiter.  Can be a fixed string of any length, an integer, or None"
        self.terminator = term

    def get_terminator (self):
        return self.terminator

    # grab some more data from the socket,
    # throw it to the collector method,
    # check for the terminator,
    # if found, transition to the next state.

    def handle_read (self):
        """ Essentially copied from asynchat. Main differences are
            SSL friendly recv error handling, and the removal of
            some terminator cases which don't occur in Anomos """
        try:
            data = self.recv (self.ac_in_buffer_size)
        except SSL.SSLError, err:
            if "unexpected eof" in err.message:
                self.handle_close()
            elif "retry" in err.message:
                log.info("Ignoring SSLError: %s" % err.message)
                pass
            elif err[0] in [ECONNRESET, ENOTCONN, ESHUTDOWN]:
                self.handle_close()
            else:
                self.handle_error()
            return
        except Exception, e:
            log.info(e)

        # XXX: This is a hack. When a connection is closed abruptly
        # without a shutdown notification, we get left in a CLOSE_WAIT
        # state, and do zero reads forever. We need to allow a few zero
        # reads to occur normally, but 100 almost certainly means we're
        # stuck in CLOSE_WAIT.
        if len(data) == 0:
            self.zero_count += 1
            if self.zero_count >= 100:
                self.handle_close()
                return
        else:
            self.zero_count = 0
        ##############################################################

        self.ac_in_buffer = self.ac_in_buffer + data

        # Continue to search for self.terminator in self.ac_in_buffer,
        # while calling self.collect_incoming_data.  The while loop
        # is necessary because we might read several data+terminator
        # combos with a single recv(1024).

        while self.ac_in_buffer:
            lb = len(self.ac_in_buffer)
            terminator = self.get_terminator()
            if isinstance(terminator, (int, long)):
                # numeric terminator
                n = terminator
                if lb < n:
                    self.collect_incoming_data (self.ac_in_buffer)
                    self.ac_in_buffer = ''
                    self.terminator = self.terminator - lb
                else:
                    self.collect_incoming_data (self.ac_in_buffer[:n])
                    self.ac_in_buffer = self.ac_in_buffer[n:]
                    self.terminator = 0
                    self.found_terminator()
            else:
                # 3 cases:
                # 1) end of buffer matches terminator exactly:
                #    collect data, transition
                # 2) end of buffer matches some prefix:
                #    collect data to the prefix
                # 3) end of buffer does not match any prefix:
                #    collect data
                terminator_len = len(terminator)
                index = self.ac_in_buffer.find(terminator)
                if index != -1:
                    # we found the terminator
                    if index > 0:
                        # don't bother reporting the empty string (source of subtle bugs)
                        self.collect_incoming_data (self.ac_in_buffer[:index])
                    self.ac_in_buffer = self.ac_in_buffer[index+terminator_len:]
                    # This does the Right Thing if the terminator is changed here.
                    self.found_terminator()
                else:
                    # check for a prefix of the terminator
                    index = find_prefix_at_end (self.ac_in_buffer, terminator)
                    if index:
                        if index != lb:
                            # we found a prefix, collect up to the prefix
                            self.collect_incoming_data (self.ac_in_buffer[:-index])
                            self.ac_in_buffer = self.ac_in_buffer[-index:]
                        break
                    else:
                        # no prefix, collect it all
                        self.collect_incoming_data (self.ac_in_buffer)
                        self.ac_in_buffer = ''

    def handle_write (self):
        self.initiate_send ()

    def handle_close (self):
        self.close()

    def handle_expt(self):
        log.critical("Exception encountered!")
        self.handle_close()

    def handle_error(self):
        t, v, tb = sys.exc_info()
        if isinstance(v, KeyboardInterrupt):
            raise
        else:
            log.info(traceback.format_exc())
            self.handle_close()

    def push (self, data):
        self.producer_fifo.push (simple_producer (data))
        self.initiate_send()

    def push_with_producer (self, producer):
        self.producer_fifo.push (producer)
        self.initiate_send()

    def readable (self):
        "predicate for inclusion in the readable for select()"
        return (len(self.ac_in_buffer) <= self.ac_in_buffer_size)

    def writable (self):
        "predicate for inclusion in the writable for select()"
        # return len(self.ac_out_buffer) or len(self.producer_fifo) or (not self.connected)
        # this is about twice as fast, though not as clear.
        return not (
                (self.ac_out_buffer == '') and
                self.producer_fifo.is_empty() and
                self.connected
                )

    def close_when_done (self):
        "automatically close this channel once the outgoing queue is empty"
        self.producer_fifo.push (None)

    # refill the outgoing buffer by calling the more() method
    # of the first producer in the queue
    def refill_buffer (self):
        while 1:
            if len(self.producer_fifo):
                p = self.producer_fifo.first()
                # a 'None' in the producer fifo is a sentinel,
                # telling us to close the channel.
                if p is None:
                    if not self.ac_out_buffer:
                        self.producer_fifo.pop()
                        self.handle_close()
                    return
                elif isinstance(p, str):
                    self.producer_fifo.pop()
                    self.ac_out_buffer = self.ac_out_buffer + p
                    return
                data = p.more()
                if data:
                    self.ac_out_buffer = self.ac_out_buffer + data
                    return
                else:
                    self.producer_fifo.pop()
            else:
                return

    def initiate_send (self):
        obs = self.ac_out_buffer_size
        # try to refill the buffer
        if (len (self.ac_out_buffer) < obs):
            self.refill_buffer()

        if self.ac_out_buffer and self.connected:
            # try to send the buffer
            try:
                num_sent = self._write_nbio(self.ac_out_buffer[:obs])
            except SSL.SSLError:
                self.handle_error()
                return
            if num_sent:
                self.ac_out_buffer = self.ac_out_buffer[num_sent:]

    def discard_buffers (self):
        # Emergencies only!
        self.ac_in_buffer = ''
        self.ac_out_buffer = ''
        while self.producer_fifo:
            self.producer_fifo.pop()


class simple_producer:

    def __init__ (self, data, buffer_size=1024):
        self.data = data
        self.buffer_size = buffer_size

    def more (self):
        if len (self.data) > self.buffer_size:
            result = self.data[:self.buffer_size]
            self.data = self.data[self.buffer_size:]
            return result
        else:
            result = self.data
            self.data = ''
            return result

class fifo:
    def __init__ (self, list=None):
        if not list:
            self.list = deque()
        else:
            self.list = deque(list)

    def __len__ (self):
        return len(self.list)

    def is_empty (self):
        return not self.list

    def first (self):
        return self.list[0]

    def push (self, data):
        self.list.append(data)

    def pop (self):
        if self.list:
            return (1, self.list.popleft())
        else:
            return (0, None)

# Given 'haystack', see if any prefix of 'needle' is at its end.  This
# assumes an exact match has already been checked.  Return the number of
# characters matched.
# for example:
# f_p_a_e ("qwerty\r", "\r\n") => 1
# f_p_a_e ("qwertydkjf", "\r\n") => 0
# f_p_a_e ("qwerty\r\n", "\r\n") => <undefined>

# this could maybe be made faster with a computed regex?
# [answer: no; circa Python-2.0, Jan 2001]
# new python:   28961/s
# old python:   18307/s
# re:        12820/s
# regex:     14035/s

def find_prefix_at_end (haystack, needle):
    l = len(needle) - 1
    while l and not haystack.endswith(needle[:l]):
        l -= 1
    return l
