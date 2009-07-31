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

app_name = "Anomos"
version = '0.5.1'

protocol_name = "Anomos"

URL = 'http://www.anomos.info/'
DONATE_URL = 'http://sourceforge.net/donate/index.php?group_id=203746'# + 'donate.html'
FAQ_URL = URL# + 'FAQ.html'
HELP_URL = URL# + 'documentation.html'

import sys
#TODO: Check actual earliest supported version
assert sys.version_info >= (2, 4, 0), "Python 2.4.0 or newer required"
import os

if sys.platform == 'win32':
    import time.clock as bttime
else:
    import time.time as bttime

def calc_unix_dirs():
    appdir = '%s-%s'%(app_name, version)
    ip = os.path.join('share', 'pixmaps', appdir)
    dp = os.path.join('share', 'doc'    , appdir)
    return ip, dp

app_root = os.path.split(os.path.abspath(sys.argv[0]))[0]
image_root = os.path.join(app_root, 'images')
doc_root = app_root

if app_root.startswith(os.path.join(sys.prefix,'bin')):
    # I'm installed on *nix
    image_root, doc_root = map( lambda p: os.path.join(sys.prefix, p), calc_unix_dirs() )


# a cross-platform way to get user's home directory
def get_config_dir():
    shellvars = ['${APPDATA}', '${HOME}', '${USERPROFILE}']
    return get_dir_root(shellvars)

def get_home_dir():
    shellvars = ['${HOME}', '${USERPROFILE}']
    return get_dir_root(shellvars)

def get_dir_root(shellvars):
    def check_sysvars(x):
        y = os.path.expandvars(x)
        if y != x and os.path.isdir(y):
            return y
        return None

    dir_root = None
    for d in shellvars:
        dir_root = check_sysvars(d)
        if dir_root is not None:
            break
    else:
        dir_root = os.path.expanduser('~')
        if dir_root == '~' or not os.path.isdir(dir_root):
            dir_root = None
    return dir_root


is_frozen_exe = (os.name == 'nt') and hasattr(sys, 'frozen') and (sys.frozen == 'windows_exe')

if is_frozen_exe:
    baseclass = sys.stderr.__class__
    class Stderr(baseclass):
        """ Hackery to get around bug in py2exe that tries to write log files to
            application directories, which may not be writable by non-admin users
        """
        logroot = get_home_dir()
        if logroot is None:
            logroot = os.path.splitdrive(sys.executable)[0]
        logname = os.path.splitext(os.path.split(sys.executable)[1])[0] + '_errors.log'
        logpath = os.path.join(logroot, logname)
        def write(self, text, alert=None, fname=logpath):
            baseclass.write(self, text, fname=fname)
    sys.stderr = Stderr()

del sys

INFO = 0
WARNING = 1
ERROR = 2
CRITICAL = 3

def default_logger(x, y):
    print x, y

class BTFailure(Exception):
    pass

class BTShutdown(BTFailure):
    pass

def trace_on_call(fn):
    '''Starts PDB when the decorated method is called'''
    import pdb
    def ret_fn(self, *args, **kwargs):
        pdb.set_trace()
        return fn(self, *args, **kwargs)
    return ret_fn

def log_on_call(fn):
    '''Logs a message when the decorated method is called'''
    def ret_fn(self, *args, **kwargs):
        self.logfunc(INFO, "Calling %s" % fn.__name__)
        return fn(self, *args, **kwargs)
    return ret_fn
