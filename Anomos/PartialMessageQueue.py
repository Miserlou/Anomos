# PartialMessageQueue.py
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

# Written by John Schanck and Rich Jones

# PartialMessageQueue is used by NeighborLink to queue
# partial messages sent by EndPoints. The partial messages
# must be queued so that EndPoints do not accidentally insert
# file chunks into the streams of other EndPoints communicating
# on the same NeighborLink. PartialMessageQueue also holds the id
# of the stream which sent each message in the queue, so that the
# stream can be notified when the message is dequeued for sending.

from Anomos.Protocol import tobinary, PARTIAL

PARTIAL_FMT_LEN = len(PARTIAL+tobinary(0))

class PartialMessageQueue(object):
    #TODO: Give this a maximum length.
    def __init__(self):
        self._deeplen = 0
        self.msgs = {}
    def queue_message(self, sid, message):
        ''' Add a message to the message queue 
            @param streamid: Stream ID of message sender
            @param message: Message to be sent
            @type streamid: int
            @type message: string'''
        self._deeplen += len(message)
        self.msgs.setdefault(sid, []).append(message)
    def is_partial(self, message):
        return message[0] == PARTIAL
    def mk_partial(self, message):
        fmt = PARTIAL + tobinary(len(message))
        self._deeplen += PARTIAL_FMT_LEN
        return fmt + message
    def dequeue_partial(self, sid, numbytes):
        ''' Dequeue numbytes from the message queue. Return
            the stream IDs associated with the messages which
            were dequeued in full and the message to be sent.
            @param numbytes: Number of bytes to be sent
            @type numbytes: int
            @return: ([Stream IDs...], "Message")'''
        if self._deeplen == 0 or not self.msgs.has_key(sid):
            return ''
        i, r = self._pindex(sid, numbytes)
        deq = self.msgs[sid][:i]
        # If numbytes fell within a message, not on a message
        # boundary, then add the remaining bytes (r) to the
        # dequeued portion.
        if r > PARTIAL_FMT_LEN and i < len(self.msgs):
            if not self.is_partial(self.msgs[i]):
                self.msgs[sid][i] = self.mk_partial(self.msgs[sid][i])
            deq.append(self.msgs[sid][i][:r])
            self.msgs[sid][i] = self.mk_partial(self.msgs[sid][i][r:])
        # Delete the sent messages/informed stream ids
        del self.msgs[sid][:i]
        self._deeplen -= sum([len(i) for i in deq])
        return deq
    def remove_by_sid(self, sid):
        ''' Removes all messages queued by the stream given by sid '''
        if not self.msgs.has_key(sid):
            return
        del self.msgs[sid]
    def _pindex(self, sid, p):
        # Returns index of p'th byte in message queue
        # (Treating the queue as an irregular 2d array)
        if len(self.msgs[sid]) <= p:
            return (len(self.msgs[sid]), 0)
        i = t = 0
        while i < len(self.msgs[sid]) and t + len(self.msgs[sid][i]) <= p:
            t += len(self.msgs[sid][i])
            i += 1
        return (i, p-t)
    def __len__(self):
        return self._deeplen
