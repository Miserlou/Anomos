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

# Written by Uoti Urpala

import os
import sys
import shutil
from ConfigParser import SafeConfigParser

from Anomos import get_config_dir, parseargs, version

def get_config(defaults, section):
    configdir = get_config_dir()

    if configdir is None:
        return {}

    p = SafeConfigParser()
    p.read(os.path.join(configdir, 'config'))
    values = {}
    values['data_dir'] = configdir
    if p.has_section(section):
        for name, value in p.items(section):
            if name in defaults:
                values[name] = value
    if p.has_section('common'):
        for name, value in p.items('common'):
            if name in defaults and name not in values:
                values[name] = value
    parseargs.parse_options(defaults, values)
    return values

def save_ui_config(defaults, section, save_options, error_callback):
    p = SafeConfigParser()
    filename = os.path.join(defaults['data_dir'], 'ui_config')
    p.read(filename)
    p.remove_section(section)
    p.add_section(section)
    for name in save_options:
        p.set(section, name, defaults[name])
    try:
        f = file(filename, 'w')
        p.write(f)
        f.close()
    except Exception, e:
        try:
            f.close()
        except:
            pass
        error_callback(ERROR, 'Could not permanently save options: '+
                       str(e))


def parse_configuration_and_args(defaults, uiname, arglist=[], minargs=0,
                                 maxargs=0):
    defconfig = dict([(name, value) for (name, value, doc) in defaults])
    if arglist[0:] == ['--version']:
        print version
        sys.exit(0)

    if arglist[0:] in (['--help'], ['-h'], ['--usage'], ['-?']):
        parseargs.printHelp(uiname, defaults)
        sys.exit(0)

    presets = get_config(defconfig, uiname)
    config, args = parseargs.parseargs(arglist, defaults, minargs, maxargs,
                                       presets)
    datadir = config['data_dir']
    if datadir:
        if uiname in ('anondownloadgui', 'anonmaketorrentgui'):
            p = SafeConfigParser()
            values = {}
            p.read(os.path.join(datadir, 'ui_config'))
            if p.has_section(uiname):
                for name, value in p.items(uiname):
                    if name in defconfig:
                        values[name] = value
            parseargs.parse_options(defconfig, values)
            presets.update(values)
            config, args = parseargs.parseargs(arglist, defaults, minargs,
                                               maxargs, presets)
        rdir = os.path.join(datadir, 'resume')
        mdir = os.path.join(datadir, 'metainfo')
        cdir = os.path.join(datadir, 'crypto')
        try:
            if not os.path.exists(datadir):
                os.mkdir(datadir, 0700)
            if not os.path.exists(mdir):
                os.mkdir(mdir, 0700)
            if not os.path.exists(rdir):
                os.mkdir(rdir, 0700)
            if not os.path.exists(cdir):
                os.mkdir(cdir, 0700)
        except:
            pass
    return config, args
