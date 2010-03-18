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

# Written by Bram Cohen

import re

from types import IntType, LongType, StringType, DictType
from Anomos import BTFailure

allowed_path_re = re.compile(r'^[^/\\.~][^/\\]*$')

ints = (long, int)

def check_info(info, check_paths=True):
    if type(info) != dict:
        raise BTFailure('bad metainfo - not a dictionary')
    pieces = info.get('pieces')
    if type(pieces) != str or len(pieces) % 20 != 0:
        raise BTFailure('bad metainfo - bad pieces key')
    piecelength = info.get('piece length')
    if type(piecelength) not in ints or piecelength <= 0:
        raise BTFailure('bad metainfo - illegal piece length')
    name = info.get('name')
    if type(name) != str:
        raise BTFailure('bad metainfo - bad name')
    if not allowed_path_re.match(name):
        raise BTFailure('name %s disallowed for security reasons' % name)
    if info.has_key('files') == info.has_key('length'):
        raise BTFailure('single/multiple file mix')
    if info.has_key('length'):
        length = info.get('length')
        if type(length) not in ints or length < 0:
            raise BTFailure('bad metainfo - bad length')
    else:
        files = info.get('files')
        if type(files) != list:
            raise BTFailure('bad metainfo - "files" is not a list of files')
        for f in files:
            if type(f) != dict:
                raise BTFailure('bad metainfo - bad file value')
            length = f.get('length')
            if type(length) not in ints or length < 0:
                raise BTFailure('bad metainfo - bad length')
            path = f.get('path')
            if type(path) != list or path == []:
                raise BTFailure('bad metainfo - bad path')
            for p in path:
                if type(p) != str:
                    raise BTFailure('bad metainfo - bad path dir')
                if check_paths and not allowed_path_re.match(p):
                    raise BTFailure('path %s disallowed for security reasons' % p)
        f = ['/'.join(x['path']) for x in files]
        f.sort()
        i = iter(f)
        try:
            name2 = i.next()
            while True:
                name1 = name2
                name2 = i.next()
                if name2.startswith(name1):
                    if name1 == name2:
                        raise BTFailure('bad metainfo - duplicate path')
                    elif name2[len(name1)] == '/':
                        raise BTFailure('bad metainfo - name used as both '
                                        'file and subdirectory name')
        except StopIteration:
            pass

def check_message(message, check_paths=True):
    if type(message) != dict:
        raise BTFailure('bad metainfo - wrong object type')
    check_info(message.get('info'), check_paths)
    if type(message.get('announce')) != str:
        raise BTFailure('bad metainfo - no announce URL string')

def check_peers(message):
    if type(message) != dict:
        raise BTFailure
    if message.has_key('failure reason'):
        if type(message['failure reason']) != str:
            raise BTFailure('non-text failure reason')
        return
    if message.has_key('warning message'):
        if type(message['warning message']) != str:
            raise BTFailure('non-text warning message')
    peers = message.get('peers', [])
    if type(peers) != list:
        raise BTFailure('invalid peer list')
    for p in peers:
        if type(p) != dict:
            raise BTFailure('invalid entry in peer list')
        if type(p.get('ip')) != str:
            raise BTFailure('invalid entry in peer list')
        port = p.get('port')
        if type(port) not in ints or p <= 0:
            raise BTFailure('invalid entry in peer list')
        if p.has_key('nid'):
            nid = p.get('nid')
            if type(nid) != str or len(nid) != 1:
                raise BTFailure('invalid entry in peer list')
        #PeerID only used in BitTorrent
        #if p.has_key('peer id'):
        #    peerid = p.get('peer id')
        #    if type(peerid) != str or len(peerid) != 20:
        #        raise BTFailure('invalid entry in peer list')
    interval = message.get('interval', 1)
    if type(interval) not in ints or interval <= 0:
        raise BTFailure('invalid announce interval')
    minint = message.get('min interval', 1)
    if type(minint) not in ints or minint <= 0:
        raise BTFailure('invalid min announce interval')
    tcodes = message.get('tracking codes', [])
    if type(tcodes) != list:
        raise BTFailure('invalid tracking code list')
    for t in tcodes:
        if type(t) != list:
            raise BTFailure('invalid entry in tracking code list')
        if len(t) != 2:
            raise BTFailure('invalid tracking code entry length')
        if type(t[0]) != str or type(t[1]) != str:
            raise BTFailure('invalid format for tracking code components')


#def statefiletemplate(x):
#    if type(x) != DictType:
#        raise ValueError
#    for cname, cinfo in x.items():
#        if cname == 'peers':
#            for y in cinfo.values():      # The 'peers' key is a dictionary of SHA hashes (torrent ids)
#                 if type(y) != DictType:   # ... for the active torrents, and each is a dictionary
#                     raise ValueError
#                 for peerid, info in y.items(): # ... of client ids interested in that torrent
#                     if (len(peerid) != 20):
#                         raise ValueError
#                     if type(info) != DictType:  # ... each of which is also a dictionary
#                         raise ValueError # ... which has an IP, a Port, and a Bytes Left count for that client for that torrent
#                     if type(info.get('ip', '')) != StringType:
#                         raise ValueError
#                     port = info.get('port')
#                     if type(port) not in (IntType, LongType) or port < 0:
#                         raise ValueError
#                     left = info.get('left')
#                     if type(left) not in (IntType, LongType) or left < 0:
#                         raise ValueError
#        elif cname == 'completed':
#            if (type(cinfo) != DictType): # The 'completed' key is a dictionary of SHA hashes (torrent ids)
#                raise ValueError          # ... for keeping track of the total completions per torrent
#            for y in cinfo.values():      # ... each torrent has an integer value
#                if type(y) not in (IntType,LongType):
#                    raise ValueError      # ... for the number of reported completions for that torrent
#        elif cname == 'allowed':
#            if (type(cinfo) != DictType): # a list of info_hashes and included data
#                raise ValueError
#            if x.has_key('allowed_dir_files'):
#                adlist = [z[1] for z in x['allowed_dir_files'].values()]
#                for y in cinfo.keys():        # and each should have a corresponding key here
#                    if not y in adlist:
#                        raise ValueError
#        elif cname == 'allowed_dir_files':
#            if (type(cinfo) != DictType): # a list of files, their attributes and info hashes
#                raise ValueError
#            dirkeys = {}
#            for y in cinfo.values():      # each entry should have a corresponding info_hash
#                if not y[1]:
#                    continue
#                if not x['allowed'].has_key(y[1]):
#                    raise ValueError
#                if dirkeys.has_key(y[1]): # and each should have a unique info_hash
#                    raise ValueError
#                dirkeys[y[1]] = 1
#
