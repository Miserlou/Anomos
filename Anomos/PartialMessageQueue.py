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

class PartialMessageQueue(object):
    #TODO: Give this a maximum length.
    def __init__(self):
        self._deeplen = 0
        self.msgs = []
        self.sid_map = []
    def queue_message(self, streamid, message):
        ''' Add a message to the message queue 
            @param streamid: Stream ID of message sender
            @param message: Message to be sent
            @type streamid: int
            @type message: string'''
        self._deeplen += len(message)
        self.msgs.append(message)
        self.sid_map.append(streamid)
    def dequeue_partial(self, numbytes):
        ''' Dequeue numbytes from the message queue. Return
            the stream IDs associated with the messages which
            were dequeued in full and the message to be sent.
            @param numbytes: Number of bytes to be sent
            @type numbytes: int
            @return: ([Stream IDs...], "Message")'''
        if self._deeplen == 0:
            return ([], '')
        i, r = self._pindex(numbytes)
        deq = ''.join(self.msgs[:i])
        # If numbytes fell within a message, not on a message
        # boundary, then add the remaining bytes (r) to the
        # dequeued portion.
        if i < len(self.msgs) and r > 0:
            deq += self.msgs[i][:r]
            self.msgs[i] = self.msgs[i][r:]
        streams = self.sid_map[:i]
        # Delete the sent messages/informed stream ids
        del self.msgs[:i]
        del self.sid_map[:i]
        self._deeplen -= len(deq)
        return (streams, deq)
    def remove_by_sid(self, sid):
        ''' Removes all messages queued by the stream given by sid '''
        if sid not in self.sid_map:
            return
        tmpm = []
        tmps = []
        for i in range(len(self.msgs)):
            if self.sid_map[i] != sid:
                tmpm.append(self.msgs[i])
                tmps.append(self.sid_map[i])
        self.msgs = tmpm
        self.sid_map = tmps
    def _pindex(self, p):
        # Returns index of p'th byte in message queue
        # (Treating the queue as an irregular 2d array)
        if self._deeplen <= p:
            return (len(self.msgs), 0)
        i = t = 0
        while i < len(self.msgs) and t + len(self.msgs[i]) <= p:
            t += len(self.msgs[i])
            i += 1
        return (i, p-t)
    def __len__(self):
        return self._deeplen
