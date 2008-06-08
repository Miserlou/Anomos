#!/usr/bin/env python

# The contents of this file are subject to the BitTorrent Open Source License
# Version 1.0 (the License).  You may not copy or use this file, in either
# source code or executable form, except in compliance with the License.  You
# may obtain a copy of the License at http://www.bittorrent.com/license/.
#
# Software distributed under the License is distributed on an AS IS basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied.  See the License
# for the specific language governing rights and limitations under the
# License.

# Written by Bram Cohen and Matt Chisholm

import sys
import os
from distutils.core import setup, Extension
import Anomos

import glob

scripts = ["btdownloadgui.py", "btdownloadcurses.py", "btdownloadheadless.py", 
           "btmaketorrentgui.py", "btmaketorrent.py",
           "btlaunchmany.py", "btlaunchmanycurses.py", 
           "bttrack.py", "btreannounce.py", "btrename.py", "btshowmetainfo.py",
           "bttest.py"]

img_root, doc_root = Anomos.calc_unix_dirs()

data_files = [ (img_root        , glob.glob('images/*png')+['images/bittorrent.ico',]),
               (img_root+'/logo', glob.glob('images/logo/bittorrent_[0-9]*.png')     ),
               (doc_root        , ['credits.txt', 'LICENSE.txt',
                                   'README.txt', 'redirdonate.html']       ),
               ]

setup(
    name = "Anomos",
    version = Anomos.version,
    author = "John Schanck",
    author_email = "john@anomos.info",
    url = "http://anomos.info/",
    license = "MIT License",
    scripts = scripts,
    packages = ["Anomos"],
    data_files = data_files,
    )
