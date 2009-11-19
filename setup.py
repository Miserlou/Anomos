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

# Written by Bram Cohen and Matt Chisholm

import sys
import os
from distutils.core import setup, Extension
import Anomos

import glob

if (os.name == 'nt')
    import py2exe

scripts = ["anondownloadgui.py", "anondownloadcurses.py", "anondownloadheadless.py", 
           "makeatorrentgui.py", "makeatorrent.py",
           "anonlaunchmany.py", "anonlaunchmanycurses.py", 
           "anontrack.py", "anonreannounce.py", "anonrename.py", "anonshowmetainfo.py"]

img_root, doc_root = Anomos.calc_unix_dirs()

data_files = [ (img_root        , glob.glob('images/*png')+['images/anomos.ico',]),
               (img_root+'/logo', glob.glob('images/logo/anomos_[0-9]*.png')     ),
               (doc_root        , ['credits.txt', 'LICENSE.txt',
                                   'README.txt', 'redirdonate.html']       ),
               ]

setup(
    name = "Anomos",
    version = Anomos.version,
    author = "John Schanck",
    author_email = "john@anomos.info",
    url = "http://anomos.info/",
    license = "GPL",
    scripts = scripts,
    packages = ["Anomos"],
    data_files = data_files,
    )
