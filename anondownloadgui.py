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

# Written by Uoti Urpala and Matt Chisholm
# Modified heavily by Anomos Liberty Enhancements

from __future__ import division

import sys

assert sys.version_info >= (2, 5), "Install Python 2.5 or greater"

import itertools
import math
import os
import os.path
import threading
import datetime
import random
import gtk
import pango
import gobject
import webbrowser
import logging
from urllib import quote, url2pathname, urlopen
import socket
import locale
import gettext

from Anomos.TorrentQueue import RUNNING, QUEUED, KNOWN, ASKING_LOCATION
from Anomos.controlsocket import ControlSocket
from Anomos.defaultargs import get_defaults
from Anomos.parseargs import parseargs, makeHelp
from Anomos.GUI import * 
from Anomos.bencode import bdecode, bencode
import makeatorrentgui
from Anomos import configfile
from Anomos import HELP_URL, DONATE_URL
from Anomos import is_frozen_exe
from Anomos import version, doc_root, image_root
from Anomos import TorrentQueue
from Anomos import BTFailure
from Anomos import OpenPath
from Anomos import Desktop
from Anomos import LOG as log
from Anomos import pygeoip

#This sets the locale information when using translations
locale.setlocale(locale.LC_ALL, '')
gettext.bindtextdomain('anomos', os.path.join(doc_root, 'locale'))
gettext.textdomain('anomos')
_ = gettext.gettext

defaults = get_defaults('anondownloadgui')
defaults.extend((('donated', '', ''),
                 ))

NAG_FREQUENCY = 0
PORT_RANGE = 5

defconfig = dict([(name, value) for (name, value, doc) in defaults])
del name, value, doc

ui_options = 'max_upload_rate minport maxport '\
             'next_torrent_time next_torrent_ratio '\
             'last_torrent_ratio '\
             'ask_for_save save_in ip dnd_behavior '\
             'min_uploads max_uploads max_initiate '\
             'max_allow_in max_files_open display_interval '\
             'donated pause auto_ip tracker_proxy anonymizer'.split()
advanced_ui = 0
advanced_ui_options_index = 10


main_torrent_dnd_tip = _('Press the i for information')
torrent_menu_tip = _('Press the X to remove this download')
torrent_tip_format = '%s:\n %s\n %s'

rate_label = ' rate: %s'

speed_classes = {
    (   4,    5): 'dialup'           ,
    (   6,   14): 'DSL/cable 128k up',
    (  15,   29): 'DSL/cable 256k up',
    (  30,   91): 'DSL 768k up'      ,
    (  92,  137): 'T1'               ,
    ( 138,  182): 'T1/E1'            ,
    ( 183,  249): 'E1'               ,
    ( 250, 5446): 'T3'               ,
    (5447,18871): 'OC3'              ,
    }

def find_dir(path):
    if os.path.isdir(path):
        return path
    directory, garbage = os.path.split(path)
    while directory:
        if os.access(directory, os.F_OK) and os.access(directory, os.W_OK):
            return directory
        directory, garbage = os.path.split(directory)
        if garbage == '':
            break        
    return None

def smart_dir(path):
    path = find_dir(path)
    if path is None:
        path = Desktop.desktop
    return path

def build_menu(menu_items, accel_group=None):
    menu = gtk.Menu()
    for label,func in menu_items:
        if label == '----':
            s = gtk.SeparatorMenuItem()
            s.show()
            menu.add(s)
        else:
            item = gtk.MenuItem(label)
            if func is not None:
                item.connect("activate", func)
            else:
                item.set_sensitive(False)
            if accel_group is not None:
                accel_index = label.find('_')
                if accel_index > -1:
                    accel_key = label[accel_index+1]
                    item.add_accelerator("activate", accel_group,
                                         ord(accel_key),
                                         gtk.gdk.CONTROL_MASK, gtk.ACCEL_VISIBLE)

            item.show()
            menu.add(item)
    return menu

class Validator(gtk.Entry):
    valid_chars = '1234567890'
    minimum = None
    maximum = None
    cast = int
    
    def __init__(self, option_name, config, setfunc):
        gtk.Entry.__init__(self)
        self.modify_text(gtk.STATE_NORMAL, gtk.gdk.color_parse("#000000"))
        self.option_name = option_name
        self.config      = config
        self.setfunc     = setfunc

        self.original_value = config[option_name]
        self.set_text(str(self.original_value))
            
        self.set_size_request(self.width,-1)
        
        self.connect('insert-text', self.text_inserted)
        self.connect('focus-out-event', self.focus_out)

    def get_value(self):
        value = None
        try:
            value = self.cast(self.get_text())
        except ValueError:
            pass
        return value

    def set_value(self, value):
        self.set_text(str(value))
        self.setfunc(self.option_name, value)        
        
    def focus_out(self, entry, widget):
        value = self.get_value()

        if value is None:
            return

        if (self.minimum is not None) and (value < self.minimum):
            value = self.minimum
        if (self.maximum is not None) and (value > self.maximum):
            value = self.maximum

        self.set_value(value)

    def text_inserted(self, entry, input, position, user_data):
        for i in input:
            if (self.valid_chars is not None) and (i not in self.valid_chars):
                self.emit_stop_by_name('insert-text')
                return True

    def revert(self):
        self.set_value(self.original_value)


class IPValidator(Validator):
    valid_chars = '1234567890.'
    width = 128
    cast = str

#TODO: Add real validation
class URLValidator(Validator):
    valid_chars = '1234567890.:/abcdefghijklmnopqrstuvwxyz-_!@#$%^&*()+=~]['
    width = 128
    cast = str

class PortValidator(Validator):
    width = 64
    minimum = 0
    maximum = 65535

    def __init__(self, option_name, config, setfunc, main):
        gtk.Entry.__init__(self)
        self.modify_text(gtk.STATE_NORMAL, gtk.gdk.color_parse("#000000"))
        self.option_name = option_name
        self.config      = config
        self.setfunc     = setfunc

        self.original_value = config[option_name]
        self.set_text(str(self.original_value))
            
        self.set_size_request(self.width,-1)
        
        self.connect('insert-text', self.text_inserted)
        self.connect('focus-out-event', self.focus_out)
        self.main = main

    def add_end(self, end_name):
        self.end_option_name = end_name

    def set_value(self, value):
        self.main.stopbutton.toggle()
        self.set_text(str(value))
        self.setfunc(self.option_name, value)
        self.setfunc(self.end_option_name, value+PORT_RANGE)
        self.main.startbutton.toggle()

    def focus_out(self, entry, widget):
        value = self.get_value()

        if value is None:
            return

        if (self.minimum is not None) and (value < self.minimum):
            value = self.minimum
        if (self.maximum is not None) and (value > self.maximum):
            value = self.maximum

        self.set_value(value)
        
        self.main.warning.set_tooltip_text(_("The ports on your router are not configured properly. This will interefere with file transfers. Please forward port ") + str(value) + _(" to your machine."))
            
        self.main.checkPort()

class PercentValidator(Validator):
    width = 48
    minimum = 0

class MinutesValidator(Validator):
    width = 48
    minimum = 0


class RateSliderBox(gtk.VBox):
    base = 10
    multiplier = 4
    max_exponent = 3.3
    
    def __init__(self, config, torrentqueue):
        gtk.VBox.__init__(self, homogeneous=False)
        self.config = config
        self.torrentqueue = torrentqueue

        if self.config['max_upload_rate'] < self.slider_to_rate(0):
            self.config['max_upload_rate'] = self.slider_to_rate(0)

        self.rate_slider_label = gtk.Label(
            self.value_to_label(self.config['max_upload_rate']))

        self.rate_slider_adj = gtk.Adjustment(
            self.rate_to_slider(self.config['max_upload_rate']), 0,
            self.max_exponent, 0.01, 0.1)
        
        self.rate_slider = gtk.HScale(self.rate_slider_adj)
        self.rate_slider.set_draw_value(False)
        self.rate_slider_adj.connect('value_changed', self.set_max_upload_rate)

        self.pack_start(self.rate_slider_label , expand=False, fill=False)
        self.pack_start(self.rate_slider       , expand=False, fill=False)

        if False: # this shows the legend for the slider
            self.rate_slider_legend = gtk.HBox(homogeneous=True)
            for i in range(int(self.max_exponent+1)):
                label = gtk.Label(str(self.slider_to_rate(i)))
                alabel = halign(label, i/self.max_exponent)
                self.rate_slider_legend.pack_start(alabel,
                                                   expand=True, fill=True)
            self.pack_start(self.rate_slider_legend, expand=False, fill=False)


    def start(self):
        self.set_max_upload_rate(self.rate_slider_adj)

    def rate_to_slider(self, value):
        return math.log(value/self.multiplier, self.base)

    def slider_to_rate(self, value):
        return int(round(self.base**value * self.multiplier))

    def value_to_label(self, value):
        conn_type = ''
        for key, conn in speed_classes.items():
            min_v, max_v = key
            if min_v <= value <= max_v:
                conn_type = ' (%s)'%conn
                break
        label = 'Maximum upload'+(rate_label % Rate(value*1024)) + \
                conn_type
        return label

    def set_max_upload_rate(self, adj):
        option = 'max_upload_rate'
        value = self.slider_to_rate(adj.get_value())
        self.config[option] = value
        self.torrentqueue.set_config(option, value)
        self.rate_slider_label.set_text(self.value_to_label(int(value)))

class OpenFileButton(gtk.Button):
    open_tip = _('Open a torrent')

    def __init__(self, main):
        gtk.Button.__init__(self)
        self.main = main
        self.connect('clicked', self.open_file)
        self.set_tooltip_text(self.open_tip)
        self.set_relief(gtk.RELIEF_NONE)

        self.open_image = gtk.Image()
        self.open_image.set_from_stock(gtk.STOCK_OPEN, gtk.ICON_SIZE_BUTTON)
        self.open_image.show()
        self.add(self.open_image)

    def open_file(self, widget):
        self.main.select_torrent_to_open(widget)

class SettingsButton(gtk.Button):
    open_tip = _('Change the settings')

    def __init__(self, main):
        gtk.Button.__init__(self)
        self.main = main
        self.connect('clicked', self.open_settings)
        self.set_tooltip_text(self.open_tip)
        self.set_relief(gtk.RELIEF_NONE)

        self.settings_image = gtk.Image()
        self.settings_image.set_from_stock(gtk.STOCK_PREFERENCES, gtk.ICON_SIZE_BUTTON)
        self.settings_image.show()
        self.add(self.settings_image)

    def open_settings(self, widget):
        self.main.open_window('settings')

class StartButton(gtk.Button):
    start_tip = 'Begin downloading'

    def __init__(self, main):
        gtk.Button.__init__(self)
        self.main = main
        self.connect('clicked', self.toggle)
        self.set_relief(gtk.RELIEF_NONE)
        self.set_tooltip_text(self.start_tip)

        self.start_image = gtk.Image()
        self.start_image.set_from_stock(gtk.STOCK_MEDIA_PLAY, gtk.ICON_SIZE_BUTTON)
        self.start_image.show()
        self.add(self.start_image)

    def toggle(self, widget=None):
        self.set_paused(not self.main.config['pause'])

    def set_paused(self, paused):
        if not paused:
            self.main.restart_queue()
            self.main.dbutton.show_downloading()
            self.main.dbutton.update_label()
            self.main.sbutton.show_seeding()
            self.main.dbutton.show_downloading()
            self.set_sensitive(False)
            self.main.stopbutton.set_sensitive(True)

class StopButton(gtk.Button):
    stop_tip  = 'Temporarily stop all running torrents'

    def __init__(self, main):
        gtk.Button.__init__(self)
        self.main = main
        self.connect('clicked', self.toggle)
        self.set_tooltip_text(self.stop_tip)
        self.set_relief(gtk.RELIEF_NONE)

        self.stop_image = gtk.Image()
        self.stop_image.set_from_stock(gtk.STOCK_MEDIA_PAUSE, gtk.ICON_SIZE_BUTTON)
        self.stop_image.show()
        self.add(self.stop_image)
    
    def toggle(self, widget=None):
        self.set_paused(not self.main.config['pause'])

    def set_paused(self, paused):
        if paused:
            self.main.stop_queue()
            self.main.dbutton.show_downloading()
            self.main.dbutton.update_label()
            self.main.sbutton.show_seeding()
            self.main.dbutton.show_downloading()
            self.set_sensitive(False)
            self.main.startbutton.set_sensitive(True)

class NewTorrentButton(gtk.Button):
    tip = _("Create a new torrent")

    def __init__(self, main):
        gtk.Button.__init__(self)
        self.main = main
        self.set_tooltip_text(self.tip)
        self.set_relief(gtk.RELIEF_NONE)
        self.connect('clicked', self.toggle)

        self.new_image = gtk.Image()
        self.new_image.set_from_stock(gtk.STOCK_NEW, gtk.ICON_SIZE_BUTTON)
        self.new_image.show()
        self.add(self.new_image)

    def toggle(self, widget):
        self.launch_maketorrent_gui()
    
    def launch_maketorrent_gui(self):
        makeatorrentgui.main(parent=self)

class SeedingButton(gtk.Button):
    tip = _("List torrents you're seeding")

    def __init__(self, main, torrents):
        gtk.Button.__init__(self)
        self.main = main
        self.set_tooltip_text(self.tip)
        self.torrents = torrents
        self.connect('clicked', self.toggle)
        self.update_label()
        
    def toggle(self, widget):
        self.show_seeding()
        self.update_label()
        self.main.dbutton.update_label()

    def show_seeding(self):
        if self.main.dlclicked == True:
            self.main.dlclicked=False
            self.main.update_torrent_widgets()

    def update_label(self):
        self.set_label("Seeds (%d)" % self.count_torrents())

    def count_torrents(self):
        return sum([1 for _,t in self.main.torrents.iteritems() if t.completion >= 1])

class DownloadingButton(gtk.Button):
    tip = _("List torrents you're downloading")

    def __init__(self, main, torrents):
        gtk.Button.__init__(self)
        self.main = main
        self.set_tooltip_text(self.tip)
        self.torrents = torrents
        self.connect('clicked', self.toggle)
        self.update_label()

    def toggle(self, widget):
        self.show_downloading()
        self.update_label()
        self.main.sbutton.update_label()

    def update_label(self):
        self.set_label("Downloads (%d)" % self.count_torrents())

    def show_downloading(self):
        if self.main.dlclicked == False:
            self.main.dlclicked=True
            self.main.update_torrent_widgets()

    def count_torrents(self):
        return sum([1 for _,t in self.main.torrents.iteritems() if t.completion < 1])

class VersionWindow(Window):
    def __init__(self, main, newversion, download_url):
        Window.__init__(self)
        self.set_title(_('New %s version available'%app_name))
        self.set_border_width(SPACING)
        self.set_resizable(False)
        self.main = main
        self.download_url = download_url
        self.connect('destroy', lambda w: self.main.window_closed('version'))
        self.vbox = gtk.VBox(spacing=SPACING)
        self.hbox = gtk.HBox(spacing=SPACING)
        self.image = gtk.Image()
        self.image.set_from_stock(gtk.STOCK_DIALOG_INFO, gtk.ICON_SIZE_DIALOG)
        self.hbox.pack_start(self.image)
        
        self.label = gtk.Label()
        self.label.set_markup(
            ("A newer version of %s is available.\n" % app_name) +
            ("You are using %s, and the new version is %s.\n" % (version, newversion)) +
            ("You can always get the latest version from \n%s" % self.download_url)
            ) 
        self.label.set_selectable(True)
        self.hbox.pack_start(self.label)
        self.vbox.pack_start(self.hbox)
        self.bbox = gtk.HBox(spacing=SPACING)

        self.closebutton = gtk.Button('Remind me later')
        self.closebutton.connect('clicked', self.close)

        self.newversionbutton = gtk.Button('Download new version now')
        self.newversionbutton.connect('clicked', self.newversion)

        self.bbox.pack_start(self.closebutton)
        self.bbox.pack_start(self.newversionbutton)
        self.vbox.pack_start(self.bbox)
        self.add(self.vbox)
        self.show_all()

    def close(self, widget):
        self.destroy()

    def newversion(self, widget):
        self.main.visit_url(self.download_url)
        self.destroy()


class AboutWindow(object):

    def __init__(self, main, donatefunc):
        self.win = Window()
        self.win.set_position(gtk.WIN_POS_CENTER)
        self.win.set_title(_('About %s'%app_name))
        self.win.set_size_request(300,400)
        self.win.set_border_width(SPACING)
        self.win.set_resizable(False)
        self.win.connect('destroy', lambda w: main.window_closed('about'))
        self.scroll = gtk.ScrolledWindow()
        self.scroll.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_ALWAYS)
        self.scroll.set_shadow_type(gtk.SHADOW_IN)

        self.outervbox = gtk.VBox()

        self.outervbox.pack_start(get_logo(96), expand=False, fill=False)

        self.outervbox.pack_start(gtk.Label(_('Version %s'%version)), expand=False, fill=False)

        self.vbox = gtk.VBox()
        self.vbox.set_size_request(250, -1)

        credits_f = file(os.path.join(doc_root, 'credits.txt'))
        l = credits_f.read()
        credits_f.close()
        label = gtk.Label(l.strip())
        label.set_line_wrap(True)
        #HACK: Gtk auto selects anything it can, and select_region doesn't work.
        label.set_selectable(False)
        label.set_justify(gtk.JUSTIFY_CENTER)
        label.set_size_request(250,-1)
        self.vbox.pack_start(label, expand=False, fill=False)

        self.scroll.add_with_viewport(self.vbox)

        self.outervbox.pack_start(self.scroll, padding=SPACING)

        self.donatebutton = gtk.Button(_("Donate"))
        self.donatebutton.connect('clicked', donatefunc)
        self.donatebuttonbox = gtk.HButtonBox()
        self.donatebuttonbox.pack_start(self.donatebutton,
                                        expand=False, fill=False)
        self.outervbox.pack_end(self.donatebuttonbox, expand=False, fill=False)

        self.win.add(self.outervbox)

        self.win.show_all()

    def close(self, widget):
        self.win.destroy()    


class LogWindow(object):
    def __init__(self, main, logbuffer, config):
        self.config = config
        self.main = main
        self.win = Window()
        self.win.set_title(_('%s Activity Log'%app_name))
        self.win.set_default_size(600, 200)
        self.win.set_border_width(SPACING)
        self.win.set_position(gtk.WIN_POS_CENTER)
            
        self.buffer = logbuffer
        self.text = gtk.TextView(self.buffer)
        self.text.set_editable(False)
        self.text.set_cursor_visible(False)
        self.text.set_wrap_mode(gtk.WRAP_WORD)

        self.scroll = gtk.ScrolledWindow()
        self.scroll.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_ALWAYS)
        self.scroll.set_shadow_type(gtk.SHADOW_IN)
        self.scroll.add(self.text)

        self.vbox = gtk.VBox(spacing=SPACING)
        self.vbox.pack_start(self.scroll)

        self.buttonbox = gtk.HButtonBox()
        self.buttonbox.set_spacing(SPACING)
        
        self.closebutton = gtk.Button(stock='gtk-close')
        self.closebutton.connect('clicked', self.close)
        
        self.savebutton = gtk.Button(stock='gtk-save')
        self.savebutton.connect('clicked', self.save_log_file_selection)

        self.clearbutton = gtk.Button(stock='gtk-clear')
        self.clearbutton.connect('clicked', self.clear_log)

        self.buttonbox.pack_start(self.savebutton)
        self.buttonbox.pack_start(self.closebutton)

        self.hbox2 = gtk.HBox(homogeneous=False)

        self.hbox2.pack_end(self.buttonbox, expand=False, fill=False)

        bb = gtk.HButtonBox()
        bb.pack_start(self.clearbutton)
        self.hbox2.pack_start(bb, expand=False, fill=True)

        self.vbox.pack_end(self.hbox2, expand=False, fill=True)

        self.win.add(self.vbox)        
        self.win.connect("destroy", lambda w: self.main.window_closed('log'))
        self.scroll_to_end()
        self.win.show_all()

    def scroll_to_end(self):
        mark = self.buffer.create_mark(None, self.buffer.get_end_iter())
        self.text.scroll_mark_onscreen(mark)

    def save_log_file_selection(self, *args):
        name = 'anomos.log'
        path = smart_dir(self.config['save_in'])
        fullname = os.path.join(path, name)
        self.main.open_window('savefile',
                              title="Save log in:",
                              fullname=fullname,
                              got_location_func=self.save_log,
                              no_location_func=lambda: self.main.window_closed('savefile'))


    def save_log(self, saveas):
        self.main.window_closed('savefile')
        f = file(saveas, 'w')
        f.write(self.buffer.get_text(self.buffer.get_start_iter(),
                                     self.buffer.get_end_iter()))
        log.info('log saved')
        f.close()

    def clear_log(self, *args):
        self.buffer.clear_log()

    def close(self, widget):
        self.win.destroy()
        
class ConnectionsWindow(object):
    def __init__(self, main):
        self.config = config
        self.main = main
        self.win = Window()
        self.win.set_title(_('Active Connections'))
        self.win.set_default_size(350, 200)
        self.win.set_border_width(SPACING)
        self.win.set_position(gtk.WIN_POS_CENTER)
        
        nbr_mngrs = self.main.torrentqueue.wrapped.multitorrent.nbr_mngrs
        
        ips = []
        for url in nbr_mngrs:
            ips.append(nbr_mngrs[url].get_ips())
        
        GEOIP = pygeoip.GeoIP(os.path.join(doc_root, 'GeoIP.dat'))
            
        store = gtk.ListStore(str,str,str,str)       
        for ips in ips:
            for ip in ips: 
                store.append([ip[0], ip[1], "\\x%02x"%ord(ip[2]), GEOIP.country_name_by_addr(ip[0])])
        
        self.treeView = gtk.TreeView(store)
        self.treeView.connect("row-activated", self.on_activated)
        self.treeView.set_rules_hint(True)
        self.create_columns()

        self.scroll = gtk.ScrolledWindow()
        self.scroll.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_ALWAYS)
        self.scroll.set_shadow_type(gtk.SHADOW_IN)
        self.scroll.add(self.treeView)

        self.vbox = gtk.VBox(spacing=SPACING)
        self.vbox.pack_start(self.scroll)

        self.win.add(self.vbox)        
        self.win.connect("destroy", lambda w: self.main.window_closed('conns'))
        self.win.show_all()
        
    def create_columns(self):
    
        rendererText = gtk.CellRendererText()
        column = gtk.TreeViewColumn("IP", rendererText, text=0)
        column.set_sort_column_id(0)    
        self.treeView.append_column(column)
        
        rendererText = gtk.CellRendererText()
        column = gtk.TreeViewColumn(_("Port"), rendererText, text=1)
        column.set_sort_column_id(1)
        self.treeView.append_column(column)

        rendererText = gtk.CellRendererText()
        column = gtk.TreeViewColumn(_("ID"), rendererText, text=2)
        column.set_sort_column_id(2)
        self.treeView.append_column(column)
        
        rendererText = gtk.CellRendererText()
        column = gtk.TreeViewColumn(_("Country"), rendererText, text=3)
        column.set_sort_column_id(3)
        self.treeView.append_column(column)

    def on_activated(self, widget, row, col):
        return

    def close(self, widget):
        self.win.destroy()

class LogBuffer(gtk.TextBuffer, logging.Handler):
    def __init__(self):
        gtk.TextBuffer.__init__(self)
        logging.Handler.__init__(self)
        logging.getLogger().addHandler(self)

        tt = self.get_tag_table()

        size_tag = gtk.TextTag('small')
        size_tag.set_property('size-points', 10)
        tt.add(size_tag)

        info_tag = gtk.TextTag('info')
        info_tag.set_property('foreground', '#00a040')
        tt.add(info_tag)

        warning_tag = gtk.TextTag('warning')
        warning_tag.set_property('foreground', '#a09000')
        tt.add(warning_tag)

        error_tag = gtk.TextTag('error')
        error_tag.set_property('foreground', '#b00000')
        tt.add(error_tag)

        critical_tag = gtk.TextTag('critical')
        critical_tag.set_property('foreground', '#b00000')
        critical_tag.set_property('weight', pango.WEIGHT_BOLD)
        tt.add(critical_tag)

    def emit(self, record):
        gobject.idle_add(self._emit, record)

    def _emit(self, record):
        gtk.gdk.threads_enter()
        now_str = datetime.datetime.strftime(datetime.datetime.now(), '[%Y-%m-%d %H:%M:%S] ')
        self.insert_with_tags_by_name(self.get_end_iter(), now_str, 'small')
        text = record.msg
        level = record.levelname.lower()
        self.insert_with_tags_by_name(self.get_end_iter(), '%s\n'%str(text), 'small', level)
        gtk.gdk.flush()
        gtk.gdk.threads_leave()

    def clear_log(self):
        self.set_text('')
        log.info('log cleared')


class SettingsWindow(object):

    def __init__(self, main, config, setfunc, torrentqueue):
        self.main = main
        self.setfunc = setfunc
        self.config = config
        self.win = Window()
        self.win.set_position(gtk.WIN_POS_CENTER)
        self.win.connect("destroy", lambda w: main.window_closed('settings'))
        self.win.set_title(_('%s Settings') %app_name)
        self.win.set_border_width(SPACING)
        self.torrentqueue = torrentqueue

        self.vbox = gtk.VBox(spacing=SPACING)

        self.rate_frame = gtk.Frame(_('Upload rate:'))
        self.rate_box = gtk.VBox()
        self.rate_box.set_border_width(SPACING)
        self.rate_slider = RateSliderBox(self.config, self.torrentqueue)
        self.rate_box.pack_start(self.rate_slider, expand=False, fill=False)
        self.rate_frame.add(self.rate_box)
        self.vbox.pack_start(self.rate_frame, expand=False, fill=False)

        self.next_torrent_frame = gtk.Frame(_('Seed completed torrents:'))
        self.next_torrent_box   = gtk.VBox(spacing=SPACING, homogeneous=True)
        self.next_torrent_box.set_border_width(SPACING) 
        
        self.next_torrent_frame.add(self.next_torrent_box)


        self.next_torrent_ratio_box = gtk.HBox()
        self.next_torrent_ratio_box.pack_start(gtk.Label(_('until share ratio reaches ')),
                                               fill=False, expand=False)
        self.next_torrent_ratio_field = PercentValidator('next_torrent_ratio',
                                                         self.config, self.setfunc)
        self.next_torrent_ratio_box.pack_start(self.next_torrent_ratio_field,
                                               fill=False, expand=False)
        self.next_torrent_ratio_box.pack_start(gtk.Label(' percent, or'),
                                               fill=False, expand=False)
        self.next_torrent_box.pack_start(self.next_torrent_ratio_box)


        self.next_torrent_time_box = gtk.HBox()
        self.next_torrent_time_box.pack_start(gtk.Label(_('for ')),
                                              fill=False, expand=False)
        self.next_torrent_time_field = MinutesValidator('next_torrent_time',
                                                        self.config, self.setfunc)
        self.next_torrent_time_box.pack_start(self.next_torrent_time_field,
                                              fill=False, expand=False)
        self.next_torrent_time_box.pack_start(gtk.Label(_(' minutes, whichever comes first. 0 is unlimited.')),
                                              fill=False, expand=False)
        self.next_torrent_box.pack_start(self.next_torrent_time_box)

        
        self.vbox.pack_start(self.next_torrent_frame, expand=False, fill=False)

        self.port_range_frame = gtk.Frame(_('Look for available port:'))       
        self.port_range = gtk.HBox()
        self.port_range.set_border_width(SPACING)
        self.port_range.pack_start(gtk.Label(_('starting at port: ')),
                                   expand=False, fill=False)
        self.minport_field = PortValidator('minport', self.config, self.setfunc, self.main)
        self.minport_field.add_end('maxport')
        self.port_range.pack_start(self.minport_field, expand=False, fill=False)
        self.minport_field.settingswindow = self
        self.port_range.pack_start(gtk.Label(' (0-65535)'),
                                   expand=False, fill=False)

        self.port_range_frame.add(self.port_range)
        self.vbox.pack_start(self.port_range_frame, expand=False, fill=False)

        self.dl_frame = gtk.Frame(_("Download folder:")) 
        self.dl_box = gtk.VBox(spacing=SPACING)
        self.dl_box.set_border_width(SPACING)
        self.dl_frame.add(self.dl_box)
        self.save_in_box = gtk.HBox(spacing=SPACING)
        self.save_in_box.pack_start(gtk.Label(_("Default:")), expand=False, fill=False)

        self.dl_save_in = gtk.Entry()
        self.dl_save_in.set_editable(False)
        self.dl_save_in.original_value = self.config['save_in']
        self.dl_save_in.modify_text(gtk.STATE_NORMAL, gtk.gdk.color_parse("#000000"))
        
        self.set_save_in(self.config['save_in'])
        self.save_in_box.pack_start(self.dl_save_in, expand=True, fill=True)

        self.dl_save_in_button = gtk.Button(_('Change..'))
        self.dl_save_in_button.connect('clicked', self.get_save_in)
        self.save_in_box.pack_start(self.dl_save_in_button, expand=False, fill=False)
        
        self.dl_box.pack_start(self.save_in_box, expand=False, fill=False)
        self.dl_ask_checkbutton = gtk.CheckButton(_("Ask where to save each download"))
        self.dl_ask_checkbutton.set_active( bool(self.config['ask_for_save']) )
        self.dl_ask_checkbutton.original_value = bool(self.config['ask_for_save'])

        def toggle_save(w):
            self.config['ask_for_save'] = int(not self.config['ask_for_save'])
            self.setfunc('ask_for_save', self.config['ask_for_save'])
            
        self.dl_ask_checkbutton.connect('toggled', toggle_save)
        self.dl_box.pack_start(self.dl_ask_checkbutton, expand=False, fill=False)

        self.vbox.pack_start(self.dl_frame, expand=False, fill=False)

        self.anon_frame = gtk.Frame(_('Torrent anonymizer tracker URL:'))
        self.anon_box = gtk.VBox()
        self.anon_box.set_border_width(SPACING)
        self.anon_field = URLValidator('anonymizer', self.config, self.setfunc)
        self.anon_field.set_tooltip_text(_('The tracker to use instead of the old torrent tracker'))
        self.anon_box.pack_start(self.anon_field, expand=False, fill=False)
        self.anon_frame.add(self.anon_box)
        self.vbox.pack_start(self.anon_frame, expand=False, fill=False)

        self.proxy_frame = gtk.Frame(_('Proxy address to use (Tor+Privoxy is 127.0.0.1:8118):'))
        self.proxy_box = gtk.VBox()
        self.proxy_box.set_border_width(SPACING)
        self.proxy_field = URLValidator('tracker_proxy', self.config, self.setfunc)
        self.proxy_field.set_tooltip_text(_('Where is your proxy?'))
        self.proxy_box.pack_start(self.proxy_field, expand=False, fill=False)
        self.proxy_frame.add(self.proxy_box)
        self.vbox.pack_start(self.proxy_frame, expand=False, fill=False)

        self.ip_frame = gtk.Frame(_('IP to report to the tracker:'))
        self.ip_box = gtk.VBox()
        self.ip_box.set_border_width(SPACING)
        self.ip_field = IPValidator('ip', self.config, self.setfunc)
        self.ip_field.set_tooltip_text(_('If you want to connect through Tor'))
        self.ip_box.pack_start(self.ip_field, expand=False, fill=False)
        self.ip_frame.add(self.ip_box)
        self.vbox.pack_start(self.ip_frame, expand=False, fill=False)

        self.auto_ip_checkbutton = gtk.CheckButton(_("Automatically fetch external IP (uses anomos.info)"))
        self.auto_ip_checkbutton.set_active( bool(self.config['auto_ip']) )
        self.auto_ip_checkbutton.original_value = bool(self.config['auto_ip'])

        def toggle_auto_ip(w):
            self.config['auto_ip'] = int(not self.config['auto_ip'])
            self.setfunc('auto_ip', self.config['auto_ip'])
            if self.config['auto_ip'] == 1:
                self.ip_field.set_value(getExternalIP())
            
        self.auto_ip_checkbutton.connect('toggled', toggle_auto_ip)
        self.ip_box.pack_start(self.auto_ip_checkbutton, expand=False, fill=False)

        self.buttonbox = gtk.HButtonBox()
        self.buttonbox.set_spacing(SPACING)
        
        self.savebutton = gtk.Button(stock='gtk-close')
        self.savebutton.connect('clicked', self.close)

        self.buttonbox.pack_end(self.savebutton, expand=False, fill=False)
        
        self.vbox.pack_end(self.buttonbox, expand=False, fill=False)
        
        if advanced_ui:
            advanced_label = "Advanced"
            self.advanced = gtk.Frame(label=advanced_label)
            self.store = gtk.ListStore(*[gobject.TYPE_STRING] * 2)
            for option in ui_options[advanced_ui_options_index:]:
                self.store.append((option, str(self.config[option])))

            self.treeview = gtk.TreeView(self.store)
            r = gtk.CellRendererText()
            column = gtk.TreeViewColumn('Option', r, text=0)
            self.treeview.append_column(column)
            r = gtk.CellRendererText()
            r.set_property('editable', True)
            r.connect('edited', self.store_value_edited)
            column = gtk.TreeViewColumn('Value', r, text=1)
            self.treeview.append_column(column)
            self.advanced.add(self.treeview)
            self.vbox.pack_end(self.advanced, expand=False, fill=False)

        self.win.add(self.vbox)
        self.win.show_all()

    def get_save_in(self, widget=None):
        self.file_selection = self.main.open_window('choosefolder',
                                                    title=_('Choose default download directory'),
                                                    fullname=self.config['save_in'],
                                                    got_location_func=self.set_save_in,
                                                    no_location_func=lambda: self.main.window_closed('choosefolder'))

    def set_save_in(self, save_location):
        self.main.window_closed('choosefolder')
        if os.path.isdir(save_location):
            if save_location[-1] != os.sep:
                save_location += os.sep
            self.config['save_in'] = save_location
            self.dl_save_in.set_text(self.config['save_in'])
            self.setfunc('save_in', self.config['save_in'])


    def set_dnd_behavior(self, state_name):
        if state_name in self.dnd_states:
            for r in self.dnd_group:
                if r.state_name == state_name:
                    r.set_active(True)
                else:
                    r.set_active(False)
        else:
            self.always_replace_radio.set_active(True)        
        

    def dnd_behavior_changed(self, radiobutton):
        if radiobutton.get_active():
            self.setfunc('dnd_behavior', radiobutton.state_name)

    def store_value_edited(self, cell, row, new_text):
        it = self.store.get_iter_from_string(row)
        option = ui_options[int(row)+advanced_ui_options_index]
        t = type(defconfig[option])
        try:
            if t is type(None) or t is str:
                value = new_text
            elif t is int or t is long:
                value = int(new_text)
            elif t is float:
                value = float(new_text)
        except ValueError:
            return
        self.setfunc(option, value)
        self.store.set(it, 1, str(value))

    def revert(self, widget):
        for foo in (self.next_torrent_time_field,
                    self.minport_field,
                    self.ip_field):
            foo.revert()
        self.dl_ask_checkbutton.set_active(self.dl_ask_checkbutton.original_value)
        self.set_save_in(self.dl_save_in.original_value)
        self.set_dnd_behavior(self.dnd_original_state)

    def close(self, widget):
        self.win.destroy()


class FileListWindow(object):

    def __init__(self, metainfo, closefunc):
        self.metainfo = metainfo
        self.setfunc = None
        self.allocfunc = None
        priorities = [0, 0]
        self.win = Window()
        self.win.set_title(_('Files in "%s"') % self.metainfo.name)
        self.win.connect("destroy", closefunc)
        self.win.set_position(gtk.WIN_POS_CENTER)

        self.box1 = gtk.VBox()

        size_request = [0,0]
        
        if advanced_ui and False:
            self.toolbar = gtk.Toolbar()
            for label, stockicon, method, arg in (("Apply"         , gtk.STOCK_APPLY  , self.set_priorities, None ),
                                                  ("Allocate"      , gtk.STOCK_SAVE   , self.dosomething, 'alloc',),
                                                  ("Never download", gtk.STOCK_DELETE , self.dosomething, 'never',),
                                                  ("Decrease"      , gtk.STOCK_GO_DOWN, self.dosomething, -1     ,),
                                                  ("Increase"      , gtk.STOCK_GO_UP  , self.dosomething, +1     ,),):
                self.make_tool_item(label, stockicon, method, arg)
            self.box1.pack_start(self.toolbar, False)
            size_request = [450,54]
            
        self.sw = gtk.ScrolledWindow()
        self.sw.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        self.box1.pack_start(self.sw)
        self.win.add(self.box1)

        columns = [_('Filename'),_('Length'),'%']
        pre_size_list = ['MMMMMMMMMMMMMMMMMMMMMMMM', '6666 MB', '100.0']
        if advanced_ui:
            columns += ['A','Order']
            pre_size_list += ['*','None','black']
        num_columns = len(pre_size_list)

        self.store = gtk.ListStore(*[gobject.TYPE_STRING] * num_columns)
        self.store.append(pre_size_list)
        self.treeview = gtk.TreeView(self.store)
        cs = []
        for i, name in enumerate(columns):
            r = gtk.CellRendererText()
            r.set_property('xalign', (0, 1, 1, .5, 1)[i])
            if i != 4:
                column = gtk.TreeViewColumn(name, r, text = i)
            else:
                column = gtk.TreeViewColumn(name, r, text = i, foreground = i + 1)
            column.set_resizable(True)
            self.treeview.append_column(column)
            cs.append(column)

        self.sw.add(self.treeview)
        self.treeview.set_headers_visible(False)
        self.treeview.columns_autosize()
        self.box1.show_all()
        self.treeview.realize()

        for column in cs:
            column.set_fixed_width(max(5,column.get_width()))
            column.set_sizing(gtk.TREE_VIEW_COLUMN_FIXED)
        self.treeview.set_headers_visible(True)
        self.store.clear()
        self.treeview.get_selection().set_mode(gtk.SELECTION_MULTIPLE)
        self.piecelen = self.metainfo.piece_length
        self.lengths = self.metainfo.sizes
        self.initialize_file_priorities(priorities)
        for name, size, priority in itertools.izip(self.metainfo.orig_files,
                                        self.metainfo.sizes, self.priorities):
            row = [name, Size(size), '?',]
            if advanced_ui:
                row += ['', priority == 255 and 'None' or str(priority), 'black']
            self.store.append(row)

        tvsr = self.treeview.size_request()
        vertical_padding = 18 
        size_request = [max(size_request[0],tvsr[0]),
                        (size_request[1] + tvsr[1] ) + vertical_padding]
        maximum_height = 300
        if size_request[1] > maximum_height - SCROLLBAR_WIDTH:
            size_request[1] = maximum_height
            size_request[0] = size_request[0] + SCROLLBAR_WIDTH
        self.win.set_default_size(*size_request)
                                  
        self.win.show_all()

    def make_tool_item_24(self, label, stockicon, method, arg): # for pygtk 2.4
        icon = gtk.Image()
        icon.set_from_stock(stockicon, gtk.ICON_SIZE_SMALL_TOOLBAR)
        item = gtk.ToolButton(icon_widget=icon, label=label)
        item.set_homogeneous(True)
        if arg is not None:
            item.connect('clicked', method, arg)
        else:
            item.connect('clicked', method)
        self.toolbar.insert(item, 0)

    def make_tool_item_22(self, label, stockicon, method, arg): # for pygtk 2.2
        icon = gtk.Image()
        icon.set_from_stock(stockicon, gtk.ICON_SIZE_SMALL_TOOLBAR)
        self.toolbar.prepend_item(label, None, None, icon, method, user_data=arg)

    if gtk.pygtk_version >= (2, 4):
        make_tool_item = make_tool_item_24
    else:
        make_tool_item = make_tool_item_22
        
    def set_priorities(self, widget):
        r = []
        piece = 0
        pos = 0
        curprio = prevprio = 1000
        for priority, length in itertools.izip(self.priorities, self.lengths):
            pos += length
            curprio = min(priority, curprio)
            while pos >= (piece + 1) * self.piecelen:
                if curprio != prevprio:
                    r.extend((piece, curprio))
                prevprio = curprio
                if curprio == priority:
                    piece = pos // self.piecelen
                else:
                    piece += 1
                if pos == piece * self.piecelen:
                    curprio = 1000
                else:
                    curprio = priority
        if curprio != prevprio:
            r.extend((piece, curprio))
        self.setfunc(r)
        it = self.store.get_iter_first()
        for i in xrange(len(self.priorities)):
            self.store.set_value(it, 5, "black")
            it = self.store.iter_next(it)
        self.origpriorities = list(self.priorities)

    def initialize_file_priorities(self, piecepriorities):
        self.priorities = []
        piecepriorities = piecepriorities + [999999999]
        it = iter(piecepriorities)
        assert it.next() == 0
        pos = piece = curprio = 0
        for length in self.lengths:
            pos += length
            priority = curprio
            while pos >= piece * self.piecelen:
                curprio = it.next()
                if pos > piece * self.piecelen:
                    priority = max(priority, curprio)
                piece = it.next()
            self.priorities.append(priority)
        self.origpriorities = list(self.priorities)

    def dosomething(self, widget, dowhat):
        self.treeview.get_selection().selected_foreach(self.adjustfile, dowhat)

    def adjustfile(self, treemodel, path, it, dowhat):
        row = path[0]
        if dowhat == "alloc":
            self.allocfunc(row)
            return
        if self.priorities[row] == 255:
            return
        if dowhat == 'never':
            self.priorities[row] = 255
        else:
            if self.priorities[row] == 0 and dowhat < 0:
                return
            self.priorities[row] += dowhat
        treemodel.set_value(it, 4, self.priorities[row] == 255 and 'None' or str(self.priorities[row]))
        treemodel.set_value(it, 5, self.priorities[row] == self.origpriorities[row] and 'black' or 'red')

    def update(self, left, allocated):
        it = self.store.get_iter_first()
        for left, total, alloc in itertools.izip(left, self.lengths,
                                                 allocated):
            if total == 0:
                p = 1
            else:
                p = (total - left) / total
            self.store.set_value(it, 2, "%.1f" % (int(p * 1000)/10))
            if advanced_ui:
                self.store.set_value(it, 3, '*' * alloc)
            it = self.store.iter_next(it)

    def close(self):
        self.win.destroy()


class TorrentInfoWindow(object):

    def __init__(self, torrent_box, closefunc):
        self.win = Window()
        self.win.set_position(gtk.WIN_POS_CENTER)
        self.torrent_box = torrent_box
        name = self.torrent_box.metainfo.name
        self.win.set_title(_('Info for "%s"'%name))
        self.win.set_size_request(-1,-1)
        self.win.set_border_width(SPACING)
        self.win.set_resizable(False)
        self.win.connect('destroy', closefunc)
        self.vbox = gtk.VBox(spacing=SPACING)

        self.table = gtk.Table(rows=4, columns=3, homogeneous=False)
        self.table.set_row_spacings(SPACING)
        self.table.set_col_spacings(SPACING)
        y = 0

        def add_item(key, val, y):
            self.table.attach(ralign(gtk.Label(key)), 0, 1, y, y+1)
            v = gtk.Label(val)
            v.set_selectable(True)
            self.table.attach(lalign(v), 1, 2, y, y+1)

        add_item(_('Torrent name:'), name, y)
        y+=1

        add_item(_('Announce url:'), self.torrent_box.metainfo.announce, y)
        y+=1
        
        # Holy shit!
        s_thread = getScrapeThread(self, self.torrent_box.infohash)
        s_thread.start()

        size = Size(self.torrent_box.metainfo.file_size)
        num_files = _(', in one file')
        if self.torrent_box.is_batch:
            num_files = _(', in %d files') % len(self.torrent_box.metainfo.sizes)
        add_item(_('Total size:'),  str(size)+num_files, y)
        y+=1

        pl = self.torrent_box.metainfo.piece_length
        count, lastlen = divmod(size, pl)
        sizedetail = '%d x %d + %d = %d' % (count, pl, lastlen, int(size))
        add_item(_('Pieces:'), sizedetail, y)
        y+=1
        add_item(_('Info hash:'), self.torrent_box.infohash.encode('hex'), y)
        y+=1

        path = self.torrent_box.dlpath 
        filename = ''
        if not self.torrent_box.is_batch:
            path,filename = os.path.split(self.torrent_box.dlpath)
        if path[-1] != os.sep:
            path += os.sep
        add_item(_('Save in:'), path, y)
        y+=1

        if not self.torrent_box.is_batch:
            add_item(_('File name:'), filename, y)
            y+=1
        
        self.vbox.pack_start(self.table)

        self.vbox.pack_start(gtk.HSeparator(), expand=False, fill=False)

        self.hbox = gtk.HBox(spacing=SPACING)
        lbbox = gtk.HButtonBox()
        rbbox = gtk.HButtonBox()
        lbbox.set_spacing(SPACING)

        if OpenPath.can_open_files:
            opendirbutton = IconButton(_("Open directory"), stock=gtk.STOCK_OPEN)
            opendirbutton.connect('clicked', self.torrent_box.open_dir)
            lbbox.pack_start(opendirbutton, expand=False, fill=False)

        opendirbutton.set_sensitive(self.torrent_box.can_open_dir())

        filelistbutton = IconButton(_("Show file list"), stock='gtk-index')
        if self.torrent_box.is_batch:
            filelistbutton.connect('clicked', self.torrent_box.open_filelist)
        else:
            filelistbutton.set_sensitive(False)
        lbbox.pack_start(filelistbutton, expand=False, fill=False)

        closebutton = gtk.Button(stock='gtk-close')
        closebutton.connect('clicked', lambda w: self.close())
        rbbox.pack_end(closebutton, expand=False, fill=False)

        self.hbox.pack_start(lbbox, expand=False, fill=False)
        self.hbox.pack_end(  rbbox, expand=False, fill=False)

        self.vbox.pack_end(self.hbox, expand=False, fill=False)

        self.win.add(self.vbox)
        
        self.win.show_all()

    def close(self):
        self.win.destroy()

class TorrentBox(gtk.EventBox):
    
    def __init__(self, infohash, metainfo, dlpath, completion, main):
        gtk.EventBox.__init__(self)

        self.connect('drag_data_received', main.on_drag_data_received)

        self.modify_bg(gtk.STATE_NORMAL,
                            self.get_colormap().alloc_color("white"))

        self.infohash = infohash
        self.metainfo = metainfo
        self.dlpath = dlpath
        self.completion = completion
        self.main = main

        self.uptotal   = self.main.torrents[self.infohash].uptotal
        self.downtotal = self.main.torrents[self.infohash].downtotal
        if self.downtotal > 0:
            self.up_down_ratio = self.uptotal / self.downtotal
        else:
            self.up_down_ratio = None

        self.infowindow = None
        self.filelistwindow = None
        self.is_batch = metainfo.is_batch
        self.menu = None
        self.menu_handler = None

        self.vbox = gtk.VBox(homogeneous=False, spacing=SPACING)

        self.vbox.modify_bg(gtk.STATE_NORMAL,
                            self.vbox.get_colormap().alloc_color("white"))

        self.label = gtk.Label()
        self.set_name()
        
        self.vbox.pack_start(lalign(self.label), expand=False, fill=False)

        self.hbox = gtk.HBox(homogeneous=False, spacing=SPACING)

        self.hbox.modify_bg(gtk.STATE_NORMAL,
                            self.hbox.get_colormap().alloc_color("white"))

        self.icon = gtk.Image()
        self.icon.set_size_request(-1, 29)

        self.iconbox = gtk.VBox()
        self.iconevbox = gtk.EventBox()        
        self.iconevbox.add(self.icon)

        self.iconevbox.modify_bg(gtk.STATE_NORMAL,
                            self.iconevbox.get_colormap().alloc_color("white"))

        self.iconbox.pack_start(self.iconevbox, expand=False, fill=False)
        self.hbox.pack_start(self.iconbox, expand=False, fill=False)
        
        self.vbox.pack_start(self.hbox)
        
        self.infobox = gtk.VBox(homogeneous=False, spacing=5)

        self.progressbarbox = gtk.HBox(homogeneous=False, spacing=10)
        self.progressbar = gtk.ProgressBar()

        if is_frozen_exe:
            # XXX: INVESTIGATE THIS FURTHER. THIS IS IMPORTANT.
            # Hack around broken GTK-Wimp theme:
            # make progress bar text always black
            # see task #694
            style = self.progressbar.get_style().copy()
            black = style.black
            self.progressbar.modify_fg(gtk.STATE_PRELIGHT, black)
        
        if self.completion is not None:
            self.progressbar.set_fraction(0)
            if self.completion >= 1:
                done_label = self.make_done_label()
                self.progressbar.set_text(done_label)
            else:
                self.progressbar.set_text('%.1f%%'%(self.completion*100))
        else:
            self.progressbar.set_text('?')
            
        self.progressbarbox.pack_start(self.progressbar,
                                       expand=True, fill=True)

        self.buttonevbox = gtk.EventBox()
        self.buttonbox = gtk.HBox(homogeneous=True, spacing=SPACING)

        self.buttonevbox.modify_bg(gtk.STATE_NORMAL,
                            self.buttonevbox.get_colormap().alloc_color("white"))

        self.infobutton = gtk.Button()
        self.infoimage = gtk.Image()
        self.infoimage.set_from_stock('anon-info', gtk.ICON_SIZE_BUTTON)
        self.infobutton.add(self.infoimage)
        self.infobutton.connect('clicked', self.open_info)
        self.infobutton.set_tooltip_text(_('Torrent info'))

        self.buttonbox.pack_start(self.infobutton, expand=True)

        self.cancelbutton = gtk.Button()
        self.cancelimage = gtk.Image()
        if self.completion is not None and self.completion >= 1:
            self.cancelimage.set_from_stock(gtk.STOCK_CANCEL, gtk.ICON_SIZE_BUTTON)
            self.cancelbutton.set_tooltip_text(_('Remove torrent'))
        else:
            self.cancelimage.set_from_stock(gtk.STOCK_CANCEL, gtk.ICON_SIZE_BUTTON)
            self.cancelbutton.set_tooltip_text(_('Cancel torrent'))
            
        self.cancelbutton.add(self.cancelimage)
        self.cancelbutton.connect('clicked', self.confirm_remove)
        
        self.buttonbox.pack_start(self.cancelbutton, expand=True, fill=False)
        self.buttonevbox.add(self.buttonbox)

        vbuttonbox = gtk.VBox(homogeneous=False)
        vbuttonbox.pack_start(self.buttonevbox, expand=False, fill=False)
        self.hbox.pack_end(vbuttonbox, expand=False, fill=False)

        self.infobox.pack_start(self.progressbarbox, expand=False, fill=False)

        self.hbox.pack_start(self.infobox, expand=True, fill=True)
        self.add( self.vbox )

        self.vbox.pack_start(DroppableHSeparator(self))
        
    def drag_data_get(self, widget, context, selection, targetType, eventTime):
        pass

    def drag_begin(self, *args):
        pass

    def drag_end(self, *args):
        pass

    def make_done_label(self, statistics=None):
        s = ''
        if statistics and statistics['timeEst'] is not None:
            s = _(', will seed for %s') % Duration(statistics['timeEst'])
        elif statistics:
            s = _(', will seed indefinitely.')

        if self.up_down_ratio is not None:
            done_label = _('Done, share ratio: %d%%') % \
                         (self.up_down_ratio*100) + s
        elif statistics is not None:
            done_label = _('Done, %s uploaded') % \
                         Size(statistics['upTotal']) + s
        else:
            done_label = _('Done')

        return done_label
        

    def set_name(self):
        self.label.set_text(self.metainfo.name)

    def make_menu(self):
        filelistfunc = None
        if self.is_batch:
            filelistfunc = self.open_filelist

        menu_items = [(_("Torrent _info"), self.open_info),('----', None),]

        if OpenPath.can_open_files:
            func = None
            if self.can_open_dir():
                func = self.open_dir
            menu_items += [(_('_Open directory'), func), ]

        menu_items += [(_("_File list")  , filelistfunc),]

        self.menu = build_menu(menu_items+self.menu_items)
                
        self.menu_handler = self.connect_object("event", self.show_menu, self.menu)
        

    def open_info(self, widget=None):
        if self.infowindow is None:
            self.infowindow = TorrentInfoWindow(self, self.infoclosed)
    
    def infoclosed(self, widget=None):
        self.infowindow = None

    def close_info(self):
        if self.infowindow is not None:
            self.infowindow.close()

    def open_filelist(self, widget):
        if not self.is_batch:
            return
        if self.filelistwindow is None:
            self.filelistwindow = FileListWindow(self.metainfo,
                                                 self.filelistclosed)
            self.main.torrentqueue.check_(self.infohash, True)

    def filelistclosed(self, widget):
        self.filelistwindow = None

    def close_filelist(self):
        if self.filelistwindow is not None:
            self.filelistwindow.close()

    def close_child_windows(self):
        self.close_info()
        self.close_filelist()

    def destroy(self):
        if self.menu is not None:
            self.menu.destroy()
        self.menu = None
        gtk.EventBox.destroy(self)

    def show_menu(self, widget, event):
        if event.type == gtk.gdk.BUTTON_PRESS and event.button == 3:
            widget.popup(None, None, None, event.button, event.time)
            return True
        return False

    def _short_path(self, dlpath):
        path_length = 40
        sep = '...'
        ret = os.path.split(dlpath)[0]
        if len(ret) > path_length+len(sep):
            return ret[:int(path_length/2)]+sep+ret[-int(path_length/2):]
        else:
            return ret

    def get_path_to_open(self):
        path = self.dlpath
        if not self.is_batch:
            path = os.path.split(self.dlpath)[0]
        return path

    def can_open_dir(self):
        return os.access(self.get_path_to_open(), os.F_OK|os.R_OK)
        
    def open_dir(self, widget):
        OpenPath.opendir(self.get_path_to_open())


    def confirm_remove(self, widget):
        message = _('Are you sure you want to remove "%s"?') % self.metainfo.name
        if self.completion >= 1:
            if self.up_down_ratio is not None:
                message = _('Your share ratio for this torrent is %d%%. ') %(self.up_down_ratio*100) + message
            else:
                message = _('You have uploaded %s to this torrent. ') %(Size(self.uptotal)) + message
            
        d = MessageDialog(self.main.mainwindow,
                          _('Remove this torrent?'),
                          message, 
                          type=gtk.MESSAGE_QUESTION,
                          buttons=gtk.BUTTONS_OK_CANCEL,
                          yesfunc=self.remove,
                          )

    def remove(self):
        ##Improve
        self.main.torrentqueue.remove_torrent(self.infohash)
        if len(self.main.torrentqueue.wrapped.running_torrents) <= 1:
            self.main.stausIcon = _("Anomos has no running torrents")

    def complete(self):
        self.main.torrents[self.infohash].completion = 1.0


class KnownTorrentBox(TorrentBox):

    def __init__(self, infohash, metainfo, dlpath, completion, main):
        TorrentBox.__init__(self, infohash, metainfo, dlpath, completion, main)

        status_tip = ''
        if completion >= 1:
            self.icon.set_from_stock('anon-finished', gtk.ICON_SIZE_LARGE_TOOLBAR)
            status_tip = _('Finished')
            known_torrent_dnd_tip = _('drag into list to seed')
        else:
            self.icon.set_from_stock('anon-broken', gtk.ICON_SIZE_LARGE_TOOLBAR)
            status_tip = _('Failed')
            known_torrent_dnd_tip = _('drag into list to resume')

        self.iconevbox.set_tooltip_text(torrent_tip_format % (status_tip,
                                                         known_torrent_dnd_tip,
                                                         torrent_menu_tip))

        self.menu_items = [('----', None),
                           (_('Re_start')  , self.move_to_end  ),
                           (_('_Remove torrent') , self.confirm_remove),
                           ]


        self.make_menu()

        self.show_all()

    def move_to_end(self, widget):
        self.main.change_torrent_state(self.infohash, QUEUED)
        

class DroppableTorrentBox(TorrentBox):

    def __init__(self, infohash, metainfo, dlpath, completion, main):
        TorrentBox.__init__(self, infohash, metainfo, dlpath, completion, main)
        self.index = None

    def drag_data_received(self, widget, context, x, y, selection, targetType, time):
        pass

    def drag_motion(self, widget, context, x, y, time):
        pass

    def drag_end(self, *args):
        pass

    def get_current_index(self):
        self.index = self.parent.get_index_from_child(self)


class QueuedTorrentBox(DroppableTorrentBox):

    icon_name = 'anon-queued'
    state_name = _('Waiting')

    def __init__(self, infohash, metainfo, dlpath, completion, main):
        DroppableTorrentBox.__init__(self, infohash, metainfo, dlpath, completion, main)

        self.iconevbox.set_tooltip_text(torrent_tip_format % (self.state_name,
                                                         main_torrent_dnd_tip,
                                                         torrent_menu_tip))

        self.icon.set_from_stock(self.icon_name, gtk.ICON_SIZE_LARGE_TOOLBAR)
        self.menu_items = [("----"            , None),
                           (_('Download _now'), self.start),
                           ]


        if self.completion is not None and self.completion >= 1:
            self.menu_items += [(_('_Remove torrent'), self.confirm_remove),]
        else:
            self.menu_items += [(_('_Cancel download'), self.confirm_remove),]
            
        self.make_menu()

        self.show_all()

        self.start(self)

    def start(self, widget):
        self.main.runbox.put_infohash_last(self.infohash)

    def finish(self, widget):
        self.main.change_torrent_state(self.infohash, KNOWN)


class PausedTorrentBox(DroppableTorrentBox):
    icon_name = 'anon-paused'
    state_name = _('Paused')

    def __init__(self, infohash, metainfo, dlpath, completion, main):
        DroppableTorrentBox.__init__(self, infohash, metainfo, dlpath, completion, main)

        self.iconevbox.set_tooltip_text(torrent_tip_format % (self.state_name,
                                                         main_torrent_dnd_tip,
                                                         torrent_menu_tip))

        self.icon.set_from_stock(self.icon_name, gtk.ICON_SIZE_LARGE_TOOLBAR)

        
        menu_items = [(_("_Cancel download")        , self.confirm_remove)] #[("Download _later", self.move_to_end   ),
                      

        if self.completion >= 1:
            menu_items = [(_("_Remove torrent"), self.confirm_remove)]

        self.menu_items = [("----", None), ] + menu_items

        self.make_menu()

        self.show_all()

    def move_to_end(self, widget):
        self.main.change_torrent_state(self.infohash, QUEUED)

    def finish(self, widget):
        self.main.change_torrent_state(self.infohash, KNOWN)


class RunningTorrentBox(DroppableTorrentBox):

    def __init__(self, infohash, metainfo, dlpath, completion, main):
        DroppableTorrentBox.__init__(self, infohash, metainfo, dlpath, completion, main)

        self.anon = metainfo.is_anon()

        self.iconevbox.set_tooltip_text(torrent_tip_format % (_('Running'),
                                                         main_torrent_dnd_tip,
                                                         torrent_menu_tip))

        self.seed = False

        self.icon.set_from_stock('anon-running', gtk.ICON_SIZE_LARGE_TOOLBAR)

        self.rate_label_box = gtk.HBox(homogeneous=True)

        self.up_rate   = gtk.Label()
        self.down_rate = gtk.Label()
        self.relay_rate = gtk.Label()
        self.rate_label_box.pack_start(lalign(self.up_rate  ),
                                       expand=True, fill=True)
        self.rate_label_box.pack_start(self.down_rate,
                                       expand=True, fill=True)
        self.rate_label_box.pack_start(ralign(self.relay_rate),
                                       expand=True, fill=True)

        self.infobox.pack_start(self.rate_label_box)        

        if advanced_ui:
            self.extrabox = gtk.VBox(homogeneous=False)

            self.table = gtk.Table(2, 7, False)
            self.labels = []
            lnames = ('peers','seeds','distr','up curr.','down curr.','up prev.','down prev.')
            
            for i, name in enumerate(lnames):
                label = gtk.Label(name)
                self.table.attach(label, i, i+1, 0, 1, xpadding = SPACING)
                label = gtk.Label('-')
                self.labels.append(label)
                self.table.attach(label, i, i+1, 1, 2, xpadding = SPACING)
            self.extrabox.pack_start(self.table)

            # extra info
            self.elabels = []
            for i in range(4):
                label = gtk.Label('-')
                self.extrabox.pack_start(lalign(label))
                self.elabels.append(label)

            pl = self.metainfo.piece_length
            tl = self.metainfo.file_size
            count, lastlen = divmod(tl, pl)
            self.piece_count = count + (lastlen > 0)

            self.elabels[0].set_text(_("Share ratio: -"))

            self.infobox.pack_end(self.extrabox, expand=False, fill=False)

        self.make_menu()
        self.show_all()


    def change_to_completed(self):
        self.completion = 1.0
        self.cancelimage.set_from_stock(gtk.STOCK_CANCEL, gtk.ICON_SIZE_BUTTON)
        self.cancelbutton.set_tooltip_text(_('Remove torrent'))
        
        self.make_menu()
        self.complete()
        self.main.dbutton.show_downloading()
        self.main.sbutton.show_seeding()
        self.main.dbutton.show_downloading()
        self.main.dbutton.update_label()
        self.main.sbutton.update_label()


    def make_menu(self):

        menu_items = [(_("_Cancel download")  , self.confirm_remove)]

        if self.completion >= 1:
            menu_items = [(_("_Remove torrent"), self.confirm_remove)]
                          

        self.menu_items = [('----'        , None),
                           ] + menu_items

        if self.menu_handler:
            self.disconnect(self.menu_handler)
            
        TorrentBox.make_menu(self)

    def move_to_end(self, widget):
        self.main.change_torrent_state(self.infohash, QUEUED)

    def finish(self, widget):
        self.main.change_torrent_state(self.infohash, KNOWN)

    def close_child_windows(self):
        TorrentBox.close_child_windows(self)

    def open_filelist(self, widget):
        if not self.is_batch:
            return
        if self.filelistwindow is None:
            self.filelistwindow = FileListWindow(self.metainfo,
                                                 self.filelistclosed)
            self.main.make_statusrequest()

    def update_status(self, statistics):
        fractionDone = statistics.get('fractionDone')
        activity = statistics.get('activity')

        self.main.set_title(torrentName=self.metainfo.name,
                            fractionDone=fractionDone)

        dt = self.downtotal
        if statistics.has_key('downTotal'):
            dt += statistics['downTotal']

        ut = self.uptotal
        if statistics.has_key('upTotal'):
            ut += statistics['upTotal']

        if dt > 0:
            self.up_down_ratio = ut / dt
        
        eta_label = '?'
        done_label = 'Done' 
        if 'numPeers' in statistics:
            eta = statistics.get('timeEst')
            if eta is not None:
                eta_label = Duration(eta)
            if fractionDone == 1:
                done_label = self.make_done_label(statistics)

        if fractionDone == 1:
            self.progressbar.set_fraction(1)
            self.progressbar.set_text(done_label)
            if not self.completion >= 1:
                self.change_to_completed()
        else:
            self.progressbar.set_fraction(fractionDone)
            ## TODO: This is not gettext friendly
            progress_bar_label = '%.1f%% done, %s remaining' % \
                                 (int(fractionDone*1000)/10, eta_label) 
            self.progressbar.set_text(progress_bar_label)
            

        if 'numPeers' not in statistics:
            return

        self.down_rate.set_text(_('Download') + rate_label %
                                Rate(statistics['downRate']))
        self.up_rate.set_text (_('Upload')  + rate_label %
                                Rate(statistics['upRate']))
        self.relay_rate.set_text (_('Relay')  + rate_label %
                                Rate(statistics['relayRate']))


        if advanced_ui:
            self.labels[0].set_text(str(statistics['numPeers']))
            if self.seed:
                statistics['numOldSeeds'] = 0 # !@# XXX
                self.labels[1].set_text('(%d)' % statistics['numOldSeeds'])
            else:
                self.labels[1].set_text(str(statistics['numSeeds']))
            self.labels[2].set_text(str(statistics['numCopies']))
            self.labels[3].set_text(str(Size(statistics['upTotal'])))
            self.labels[4].set_text(str(Size(statistics['downTotal'])))
            self.labels[5].set_text(str(Size(self.uptotal)))
            self.labels[6].set_text(str(Size(self.downtotal)))

        if advanced_ui:
            # refresh extra info
            if self.up_down_ratio is not None:
                self.elabels[0].set_text('Share ratio: %.2f%%' % (self.up_down_ratio*100))
            self.elabels[1].set_text('Pieces: %d total, %d complete, %d partial, %d active (%d empty)'
                                     % (self.piece_count                 ,
                                        statistics['storage_numcomplete'],
                                        statistics['storage_dirty'],
                                        statistics['storage_active'],
                                        statistics['storage_new']))
            self.elabels[2].set_text('Next distributed copies: ' + ', '.join(["%d:%.1f%%" % (a, int(b*1000)/10) for a, b in zip(itertools.count(int(statistics['numCopies']+1)), statistics['numCopyList'])]))
            self.elabels[3].set_text('%d bad pieces + %s in discarded requests' % (statistics['storage_numflunked'], Size(statistics['discarded'])))

        if self.filelistwindow is not None:
            if 'files_left' in statistics:
                self.filelistwindow.update(statistics['files_left'],
                                           statistics['files_allocated'])


class DroppableHSeparator(PaddedHSeparator):

    def __init__(self, main, spacing=6):
        PaddedHSeparator.__init__(self, spacing)
        self.main = main

    def drag_highlight(self):
        pass

    def drag_unhighlight(self):
        pass

    def drag_data_received(self, widget, context, x, y, selection, targetType, time):
        pass

    def drag_motion(self, *args):
        pass


class DroppableBox(HSeparatedBox):
    def __init__(self, main, spacing=0):
        HSeparatedBox.__init__(self, spacing=spacing)
        self.main = main

    def drag_motion(self, *args):
        pass

    def drag_data_received(self, *args):
        pass


class KnownBox(DroppableBox):

    def __init__(self, main, spacing=0):
        DroppableBox.__init__(self, main, spacing=spacing)

    def pack_start(self, widget, *args, **kwargs):
        old_len = len(self.get_children())
        DroppableBox.pack_start(self, widget, *args, **kwargs)
        if old_len <= 0:
            self.main.maximize_known_pane()
        self.main.knownscroll.scroll_to_bottom()

    def remove(self, widget, *args, **kwargs):
        DroppableBox.remove(self, widget, *args, **kwargs)
        new_len = len(self.get_children())
        if new_len == 0:
            self.main.maximize_known_pane()

    def drag_data_received(self, widget, context, x, y, selection, targetType, time):
        pass

    def drag_motion(self, *args):
        pass
    
    def drag_highlight(self):
        pass

    def drag_unhighlight(self):
        pass


class RunningAndQueueBox(gtk.VBox):

    def __init__(self, main, **kwargs):
        gtk.VBox.__init__(self, **kwargs)
        self.main = main

    def drop_on_separator(self, sep, infohash):
        pass

    def highlight_between(self):
        self.drag_highlight()

    def drag_highlight(self):
        pass

    def drag_unhighlight(self):
        pass
        

class SpacerBox(DroppableBox):
    
    def drag_data_received(self, widget, context, x, y, selection, targetType, time):
        pass

BEFORE = -1
AFTER  =  1

class ReorderableBox(DroppableBox):

    def new_separator(self):
        self.dhs = DroppableHSeparator(self)
        return self.dhs
    
    def __init__(self, main):
        DroppableBox.__init__(self, main)
        self.main = main


    def drag_data_received(self, widget, context, x, y, selection, targetType, time):
        pass

    def drag_motion(self, *args):
        pass

    def drag_highlight(self):
        pass

    def drag_unhighlight(self): 
        pass

    def highlight_before_index(self, index):
        pass

    def highlight_after_index(self, index):
        pass

    def highlight_child(self, index=None):
        for i, child in enumerate(self._get_children()):
            if index is not None and i == index*2:
                child.drag_highlight()
            else:
                child.drag_unhighlight()


    def drop_on_separator(self, sep, infohash):
        pass

    def put_infohash_at_index(self, infohash, target_index):
        pass

    def get_queue(self):
        queue = []
        c = self.get_children()
        for t in c:
            queue.append(t.infohash)
        return queue

    def put_infohash_first(self, infohash):
        self.highlight_child()
        children = self.get_children()
        if len(children) > 1 and infohash == children[0].infohash:
            return
        
        self.put_infohash_at_index(infohash, 0)

    def put_infohash_last(self, infohash):
        self.highlight_child()
        children = self.get_children()
        end = len(children)
        if len(children) > 1 and infohash == children[end-1].infohash:
            return

        self.put_infohash_at_index(infohash, end)

    def put_infohash_at_child(self, infohash, reference_child, where):
        self.highlight_child()
        if infohash == reference_child.infohash:
            return
        
        target_index = self.get_index_from_child(reference_child)
        if where == AFTER:
            target_index += 1
        self.put_infohash_at_index(infohash, target_index)

    def get_index_from_child(self, child):
        c = self.get_children()
        ret = -1
        try:
            ret = c.index(child)
        except ValueError:
            pass
        return ret


class RunningBox(ReorderableBox):

    def put_infohash_at_index(self, infohash, target_index):

        l = self.get_queue()
        replaced = None
        if l:
            replaced = l[-1]
        self.main.confirm_replace_running_torrent(infohash, replaced,
                                                  target_index)

    def highlight_at_top(self):
        pass
        # BUG: Don't know how I will indicate in the UI that the top of the list is highlighted

    def highlight_at_bottom(self):
        self.parent.highlight_between()


class QueuedBox(ReorderableBox):

    def put_infohash_at_index(self, infohash, target_index):
        self.main.change_torrent_state(infohash, QUEUED, target_index)

    def highlight_at_top(self):
        self.parent.highlight_between()

    def highlight_at_bottom(self):
        pass
        # BUG: Don't know how I will indicate in the UI that the bottom of the list is highlighted

class Struct(object):
    def __init__(self):
        self.metainfo = None
        self.dlpath = None
        self.state = None
        self.completion = None
        self.uptotal = None
        self.downtotal = None
        self.widget = None

class DownloadInfoFrame(object):

    def __init__(self, config, torrentqueue):
        self.config = config
        if self.config['save_in'] == '':
           self.config['save_in'] = smart_dir('')
        
        self.torrentqueue = torrentqueue
        self.torrents = {}
        self.running_torrents = {}
        self.lists = {}
        self.update_handle = None
        self.unhighlight_handle = None
        self.dlclicked = False
        gtk.gdk.threads_enter()
        self.mainwindow = Window(gtk.WINDOW_TOPLEVEL)
        self.mainwindow.set_border_width(0)
        self.mainwindow.set_size_request(800,400)
        self.mainwindow.resize(800,400)
        self.mainwindow.set_position(gtk.WIN_POS_CENTER)

        self.mainwindow.connect('destroy', self.cancel)
        self.mainwindow.connect('delete-event', self.ask_quit)
        self.mainwindow.connect('window-state-event', self.on_window_event)
        self.mainwindow.connect('drag_data_received', self.on_drag_data_received)
        TARGET_TYPE_URI_LIST = 80
        dnd_list = [ ( 'text/uri-list', 0, TARGET_TYPE_URI_LIST ) ]
        self.mainwindow.drag_dest_set( gtk.DEST_DEFAULT_MOTION |
                  gtk.DEST_DEFAULT_HIGHLIGHT | gtk.DEST_DEFAULT_DROP,
                  dnd_list, gtk.gdk.ACTION_COPY)
        self.mainwindow.set_resizable(True)
        self.mainwindow.set_icon_from_file(os.path.join(image_root, 'small.png'))

        self.accel_group = gtk.AccelGroup()

        self.mainwindow.add_accel_group(self.accel_group)

        self.logbuffer = LogBuffer()
        log.info('%s started'%app_name)

        self.box1 = gtk.VBox(homogeneous=False, spacing=0)

        self.box2 = gtk.VBox(homogeneous=False, spacing=0)
        self.box2.set_border_width(SPACING)

        self.box2.connect('drag_data_received', self.on_drag_data_received)
        self.box2.drag_dest_set( gtk.DEST_DEFAULT_MOTION |
                  gtk.DEST_DEFAULT_HIGHLIGHT | gtk.DEST_DEFAULT_DROP,
                  dnd_list, gtk.gdk.ACTION_COPY)
        self.box1.connect('drag_data_received', self.on_drag_data_received)

        self.menubar = gtk.MenuBar()
        self.box1.pack_start(self.menubar, expand=False, fill=False)

        self.startbutton = StartButton(self)
        self.stopbutton = StopButton(self)
        self.ofbutton = OpenFileButton(self)
        self.ntbutton = NewTorrentButton(self)
        self.osbutton = SettingsButton(self)

        self.dbutton = DownloadingButton(self, self.torrents)
        self.dbutton.set_label(_("Downloads (0)"))
        self.sbutton = SeedingButton(self, self.torrents)
        self.sbutton.set_label(_("Seeds (0)"))

        file_menu_items = ((_('_Open an .atorrent file'), self.select_torrent_to_open),
			               (_('_Anonymize and open a .torrent file'), self.select_old_torrent_to_open),
                           ('----',                 None),
                           (_('_Play '),               self.startbutton.toggle),
                           (_('Pa_use '),              self.stopbutton.toggle),
                           ('----',                 None),
			               (_('Make a _new .atorrent file'), self.ntbutton.toggle),
			               ('----',                 None),
			               (_('S_ettings'),            lambda w: self.open_window('settings')),
			               ('----',                 None),
                           (_('_Quit'),                lambda w: self.mainwindow.destroy()),
                           )
                           
        view_menu_items = ((_('_Downloads'),           self.dbutton.toggle),
                           (_('_Seeds'),               self.sbutton.toggle),
                           ('----',                 None),
                           (_('_Connections'),         lambda w: self.open_window('connections')),
                           (_('_Log'),                 lambda w: self.open_window('log')),
                           (_('Settings'),             lambda w: self.open_window('settings')))
        
        control_menu_items = ((_('_Go'),               self.startbutton.toggle),
                           (_('S_top'),                self.stopbutton.toggle),
                            ('----',                   None),
                            (_('Remove all'),          self.remove_all_torrents)
                           )
                           
        help_menu_items = ((_('_Help'),                self.open_help),
                           (_('A_bout'),               lambda w: self.open_window('about')),
                           (_('Donate'),               lambda w: self.donate()), 
                           )
        
        self.filemenu = gtk.MenuItem(_("_File"))
        self.filemenu.set_submenu(build_menu(file_menu_items, self.accel_group))
        self.filemenu.show()
        
        self.controlmenu = gtk.MenuItem(_("_Control"))
        self.controlmenu.set_submenu(build_menu(control_menu_items, self.accel_group))
        self.controlmenu.show()

        self.viewmenu = gtk.MenuItem(_("_View"))
        self.viewmenu.set_submenu(build_menu(view_menu_items, self.accel_group))
        self.viewmenu.show()

        self.helpmenu = gtk.MenuItem(_("_Help"))
        self.helpmenu.set_submenu(build_menu(help_menu_items, self.accel_group))
        self.helpmenu.set_right_justified(True)
        self.helpmenu.show()

        self.menubar.append(self.filemenu)
        self.menubar.append(self.controlmenu)
        self.menubar.append(self.viewmenu)
        self.menubar.append(self.helpmenu)
        self.menubar.show()

        self.header = gtk.HBox(homogeneous=False)

        self.box1.pack_start(self.box2, expand=False, fill=False)
        
        self.rate_slider_box = RateSliderBox(self.config, self.torrentqueue)

        self.ofb = gtk.VBox()
        self.ofb.pack_end(self.ofbutton, expand=False, fill=True)

        self.ntb = gtk.VBox()
        self.ntb.pack_end(self.ntbutton, expand=False, fill=True)

        self.stb = gtk.VBox()
        self.stb.pack_end(self.osbutton, expand=False, fill=True)

        self.sta = gtk.VBox()
        self.sta.pack_end(self.startbutton, expand=False, fill=True)

        self.sto = gtk.VBox()
        self.sto.pack_end(self.stopbutton, expand=False, fill=True)

        self.db = gtk.VBox()
        self.db.pack_end(self.dbutton, expand=False, fill=True)

        self.sb = gtk.VBox()
        self.sb.pack_end(self.sbutton, expand=False, fill=True)
        
        self.controlbox = gtk.HBox(homogeneous=False)

        self.controlbox.pack_start(self.sta, expand=False, fill=False, padding=3)
        self.controlbox.pack_start(self.sto, expand=False, fill=False, padding=3)

        self.separator = gtk.VSeparator()
        self.separator.show()
        self.controlbox.pack_start(self.separator, expand=False, fill=False, padding=5)
        
        self.controlbox.pack_start(self.ofb, expand=False, fill=False, padding=3)
        self.controlbox.pack_start(self.ntb, expand=False, fill=False, padding=3)
        self.controlbox.pack_start(self.stb, expand=False, fill=False, padding=3)

        self.separator2 = gtk.VSeparator()
        self.separator2.show()
        self.controlbox.pack_start(self.separator2, expand=False, fill=False, padding=5)

        self.warnIcon()
        self.checkPort()

        self.controlbox.pack_end(get_logo(32), expand=False, fill=False,
                                   padding=5)
        self.controlbox.pack_end(self.sb, expand=False, fill=False, padding=5)
        self.controlbox.pack_end(self.db, expand=False, fill=False)

        self.box2.pack_start(self.controlbox, expand=False, fill=False, padding=0)

        #This is the splitter thingy.
        self.paned = gtk.VPaned()
        self.paned.connect('drag_data_received', self.on_drag_data_received)

        self.knownscroll = ScrolledWindow()
        self.knownscroll.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        self.knownscroll.set_shadow_type(gtk.SHADOW_IN)
        self.knownscroll.set_size_request(-1, SPACING)
        self.knownscroll.set_border_width(SPACING)

        self.knownbox = KnownBox(self)
        self.knownbox.set_border_width(SPACING)
        self.knownbox.connect('drag_data_received', self.on_drag_data_received)
        self.knownbox.drag_dest_set( gtk.DEST_DEFAULT_MOTION |
                  gtk.DEST_DEFAULT_HIGHLIGHT | gtk.DEST_DEFAULT_DROP,
                  dnd_list, gtk.gdk.ACTION_COPY)

        self.knownscroll.add_with_viewport(self.knownbox)
        self.knownscroll.connect('drag_data_received', self.on_drag_data_received)
        self.knownscroll.drag_dest_set( gtk.DEST_DEFAULT_MOTION |
                  gtk.DEST_DEFAULT_HIGHLIGHT | gtk.DEST_DEFAULT_DROP,
                  dnd_list, gtk.gdk.ACTION_COPY)        
        #self.paned.pack1(self.knownscroll, resize=False, shrink=True)
        
        self.mainscroll = AutoScrollingWindow()
        self.mainscroll.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
        self.mainscroll.set_shadow_type(gtk.SHADOW_IN)
        self.mainscroll.set_size_request(-1, SPACING)
        self.mainscroll.set_border_width(SPACING)
        self.mainscroll.connect('drag_data_received', self.on_drag_data_received)
        self.mainscroll.drag_dest_set( gtk.DEST_DEFAULT_MOTION |
                  gtk.DEST_DEFAULT_HIGHLIGHT | gtk.DEST_DEFAULT_DROP,
                  dnd_list, gtk.gdk.ACTION_COPY)

        self.event_box = gtk.EventBox()
        self.event_box.connect('drag_data_received', self.on_drag_data_received)
        self.event_box.drag_dest_set( gtk.DEST_DEFAULT_MOTION |
                  gtk.DEST_DEFAULT_HIGHLIGHT | gtk.DEST_DEFAULT_DROP,
                  dnd_list, gtk.gdk.ACTION_COPY)        
        self.mainscroll.add_with_viewport(self.event_box)
        self.event_box.show()        
        self.event_box.modify_bg(gtk.STATE_NORMAL,
                            self.event_box.get_colormap().alloc_color("white"))

        self.scrollbox = RunningAndQueueBox(self, homogeneous=False)
        self.scrollbox.set_border_width(SPACING)
        self.scrollbox.connect('drag_data_received', self.on_drag_data_received)
        
        self.runbox = RunningBox(self)
        self.runbox.connect('drag_data_received', self.on_drag_data_received)
        self.scrollbox.pack_start(self.runbox, expand=False, fill=False)

        self.queuebox = QueuedBox(self)
        self.queuebox.connect('drag_data_received', self.on_drag_data_received)
        self.scrollbox.pack_start(self.queuebox, expand=False, fill=False)

        self.scrollbox.pack_start(SpacerBox(self), expand=True, fill=True) 

        self.event_box.add(self.scrollbox)

        self.paned.pack2(self.mainscroll, resize=True, shrink=False)

        self.box1.pack_start(self.paned)

        self.box1.connect('drag_data_received', self.on_drag_data_received)
        self.box1.show_all()

        self.mainwindow.add(self.box1)
        self.child_windows = {}
        self.postponed_save_windows = []

        self.helpwindow     = None
        self.errordialog    = None
        self.warningwindow    = None

        self.set_title()
        self.set_size()
        self.mainwindow.show()
        self.paned.set_position(0)
        self.iconified = False

        self.statusIcon = gtk.StatusIcon()

        self.menu = gtk.Menu()

        self.pauseItem = gtk.ImageMenuItem(gtk.STOCK_MEDIA_PAUSE) 
        self.pauseItem.connect('activate', self.stopbutton.toggle) 
        self.menu.append(self.pauseItem) 

        self.playItem = gtk.ImageMenuItem(gtk.STOCK_MEDIA_PLAY) 
        self.playItem.connect('activate', self.startbutton.toggle)
        self.menu.append(self.playItem)

        self.spacer = gtk.MenuItem(None)
        self.menu.append(self.spacer)

        self.menuItem = gtk.ImageMenuItem(gtk.STOCK_QUIT) 
        self.menuItem.connect('activate', self.ask_quit, self.statusIcon) 
        self.menu.append(self.menuItem) 

        self.statusIcon.set_from_file(os.path.join(image_root, 'small.png'))
        self.statusIcon.set_tooltip("Anomos")
        self.statusIcon.connect('activate', self.onStatusIconActivate)
        self.statusIcon.connect('popup-menu', self.popup_menu_cb, self.menu)

        gtk.gdk.flush()
        gtk.gdk.threads_leave()   

    def onStatusIconActivate(self, widget):
        if self.iconified:
            self.mainwindow.deiconify()
            self.mainwindow.show()
            self.iconified = False
        else:
            self.mainwindow.iconify()
            self.mainwindow.hide()
            self.iconified = True

    def popup_menu_cb(self, widget, button, time, data = None): 
	    if button == 3: 
	        if data: 
	            data.show_all() 
	            data.popup(None, None, None, 3, time) 

    def quitDialog(self, yes_text=_("Yes"), no_text=_("No"), cancel_text=_("Cancel")):
        message = gtk.MessageDialog(self.mainwindow, gtk.DIALOG_MODAL, gtk.MESSAGE_QUESTION, gtk.BUTTONS_NONE, _("Do you really want to quit?"))
        message.add_button(gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL)
        message.add_button(gtk.STOCK_QUIT, gtk.RESPONSE_CLOSE)
	message.set_title(_("Really quit?"))
        resp = message.run()
        message.destroy()
        if resp == gtk.RESPONSE_CLOSE:
            return 1
        else:
            return 0

    def main(self):
        gtk.gdk.threads_enter()

        self.startbutton.set_paused(self.config['pause'])
        self.stopbutton.set_paused(self.config['pause'])
        self.rate_slider_box.start()
        self.init_updates()

        try:
            gtk.main() 
        except KeyboardInterrupt:
            self.torrentqueue.set_done()
            self.torrentqueue._dump_state()
            raise
        finally:
            gtk.gdk.threads_leave()


    def drag_leave(self, *args):
        self.drag_end()

    def on_drag_data_received(self, widget, context, x, y, selection, target_type, timestamp):
        uri = selection.data.strip('\r\n\x00')
        uri_splitted = uri.split() # we may have more than one file dropped
        for uri in uri_splitted:
            path = self.get_file_path_from_dnd_dropped_uri(uri)
            if os.path.isfile(path): # is it file?
                log.info("Opening dragged file %s"%path)
                self.open_torrent(path)

    def get_file_path_from_dnd_dropped_uri(self, uri):
        # get the path to file
        path = ""
        if uri.startswith('file:\\\\\\'): # windows
            path = uri[8:] # 8 is len('file:///')
        elif uri.startswith('file://'): # nautilus, rox
            path = uri[7:] # 7 is len('file://')
        elif uri.startswith('file:'): # xffm
            path = uri[5:] # 5 is len('file:')

        path = url2pathname(path) # escape special chars
        path = path.strip('\r\n\x00') # remove \r\n and NULL
        return path

    def drag_highlight(self, widget=None):
        widgets = (self.knownbox, self.runbox, self.queuebox) 
        for w in widgets:
            if w != widget:
                w.drag_unhighlight()
        for w in widgets:
            if w == widget:
                w.drag_highlight()
                self.add_unhighlight_handle()

    def drag_end(self):
        self.drag_highlight(widget=None)
        self.mainscroll.stop_scrolling()

    def set_title(self, torrentName=None, fractionDone=None):
        title = app_name
        trunc = '...'
        sep = ': '

        if self.config['pause']:
            title += sep+'(stopped)'
        elif len(self.running_torrents) == 1 and torrentName and \
               fractionDone is not None:
            maxlen = WINDOW_TITLE_LENGTH - len(app_name) - len(trunc) - len(sep)
            if len(torrentName) > maxlen:
                torrentName = torrentName[:maxlen] + trunc
            title = '%s%s%0.1f%%%s%s'% (app_name,
                                            sep,
                                            (int(fractionDone*1000)/10),
                                            sep,
                                            torrentName)
        elif len(self.running_torrents) > 1:
            title += sep+'(multiple)'

        self.mainwindow.set_title(title)

    def set_size(self):
        paned_height = self.scrollbox.size_request()[1]
        paned_height += self.paned.style_get_property('handle-size')
        paned_height += self.paned.get_position()
        paned_height += 4 # fudge factor, probably from scrolled window beveling ?
        paned_height = max(paned_height, MIN_MULTI_PANE_HEIGHT)

        new_height = self.menubar.size_request()[1] + \
                     self.box2.size_request()[1] + \
                     paned_height
        new_height = min(new_height, MAX_WINDOW_HEIGHT)
        self.mainwindow.set_size_request(WINDOW_WIDTH, new_height)

    def split_pane(self):
        pos = self.paned.get_position()
        if pos > 0:
            self.paned.old_position = pos
            self.paned.set_position(0)
        else:
            if hasattr(self.paned, 'old_position'):
                self.paned.set_position(self.paned.old_position)
            else:
                self.maximize_known_pane()

    def maximize_known_pane(self):
        self.set_pane_position(self.knownbox.size_request()[1])        

    def set_pane_position(self, pane_position):
            pane_position = min(MAX_WINDOW_HEIGHT//2, pane_position)
            self.paned.set_position(pane_position)

    def toggle_known(self, widget=None):
        self.split_pane()

    def open_window(self, window_name, *args, **kwargs):
        if window_name == 'log'       :
            self.child_windows[window_name] = LogWindow(self, self.logbuffer, self.config)
        elif window_name == 'about'   :
            self.child_windows[window_name] = AboutWindow(self, lambda w: self.donate())
        elif window_name == 'help'    :
            self.child_windows[window_name] = HelpWindow(self, makeHelp('anondownloadgui', defaults))
        elif window_name == 'settings':
            self.child_windows[window_name] = SettingsWindow(self, self.config, self.set_config, self.torrentqueue)
        elif window_name == 'version' :
            self.child_windows[window_name] = VersionWindow(self, *args)
        elif window_name == 'openfile':
            self.child_windows[window_name] = OpenFileSelection(self, **kwargs)
        elif window_name == 'savefile':
            self.child_windows[window_name] = SaveFileSelection(self, **kwargs)
        elif window_name == 'choosefolder':
            self.child_windows[window_name] = ChooseFolderSelection(self, **kwargs)
        elif window_name == 'connections':
            self.child_windows[window_name] = ConnectionsWindow(self, **kwargs)                   

        return self.child_windows[window_name]

    def window_closed(self, window_name):
        if self.child_windows.has_key(window_name):
            del self.child_windows[window_name]
        if window_name == 'savefile' and self.postponed_save_windows:
            newwin = self.postponed_save_windows.pop(-1)
            newwin.show()
            self.child_windows['savefile'] = newwin
    
    def close_window(self, window_name):
        self.child_windows[window_name].close(None)

    def new_version(self, newversion, download_url):
        self.open_window('version', newversion, download_url)


    def open_help(self,widget):
        if self.helpwindow is None:
            msg = _('Anomos help is at \n%s\n Would you like to go there now?')%HELP_URL
            self.helpwindow = MessageDialog(self.mainwindow,
                                            _('Visit help web page?'),
                                            msg,
                                            type=gtk.MESSAGE_QUESTION,
                                            buttons=gtk.BUTTONS_OK_CANCEL,
                                            yesfunc=self.visit_help,
                                            nofunc =self.help_closed,
                                            )

    def open_warning(self,widget):
        if self.warningwindow is None:
            msg = 'Warning! This file is not an anonymous torrent, which means you will be completely exposed while downloading! Do you still want to continue?'
            self.warningwindow = MessageDialog(self.mainwindow,
                                            'Warning!',
                                            msg,
                                            type=gtk.MESSAGE_WARNING,
                                            buttons=gtk.BUTTONS_YES_NO,
                                            yesfunc= lambda : self.cont(widget),
                                            nofunc = lambda : self.discont(widget),
                                            )

    def cont(self, widget):
        self.torrentqueue.start_new_torrent(widget)
        self.warningwindow = None
    
    def discont(self, widget):
        self.warningwindow = None

    def visit_help(self):
        self.visit_url(HELP_URL)
        self.help_closed()
        
    def close_help(self):
        self.helpwindow.close()

    def help_closed(self, widget=None):
        self.helpwindow = None

    def set_config(self, option, value):
        self.config[option] = value
        if option == 'display_interval':
            self.init_updates()
        self.torrentqueue.set_config(option, value)

    def hide_completed(self):
        return

    def confirm_remove_finished_torrents(self,widget):
        count = 0
        for infohash, t in self.torrents.iteritems():
            if t.state == KNOWN and t.completion >= 1:
                count += 1
        if count:
            if self.paned.get_position() == 0:
                self.toggle_known()
            msg = ''
            if count == 1:
                msg = _('There is one finished torrent in the list. ') +\
                      _('Do you want to remove it?')
            else:
                msg = _('There are %d finished torrents in the list. ')%count +\
                      _('Do you want to remove all of them?')
            MessageDialog(self.mainwindow,
                          _('Remove all finished torrents?'),
                          msg,
                          type=gtk.MESSAGE_QUESTION,
                          buttons=gtk.BUTTONS_OK_CANCEL,
                          yesfunc=self.remove_finished_torrents)
        else:
            MessageDialog(self.mainwindow,
                          _('No finished torrents'),
                          _('There are no finished torrents to remove.'),
                          type=gtk.MESSAGE_INFO)
        

    def remove_finished_torrents(self):
        for infohash, t in self.torrents.iteritems():
            if t.state == KNOWN and t.completion >= 1:
                self.torrentqueue.remove_torrent(infohash)
        if self.paned.get_position() > 0:
            self.toggle_known()

    def remove_all_torrents(self, widget):
        message = gtk.MessageDialog(self.mainwindow, gtk.DIALOG_MODAL, gtk.MESSAGE_QUESTION, gtk.BUTTONS_NONE, "Do you really want remove all torrents?")
        message.add_button(gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL)
        message.add_button(gtk.STOCK_YES, gtk.RESPONSE_YES)
        message.set_title("Remove all?")
        resp = message.run()
        message.destroy()
        if resp == gtk.RESPONSE_YES:
            self.torrentqueue.remove_all_torrents()
        else:
            return

    def on_window_event(self, widget, event):
        state = event.new_window_state
        # One day, we may need this again. Now, the WIMP bug is fixed by
        # using GTK 2.16 rather than 2.18        
        if state == gtk.gdk.WINDOW_STATE_ICONIFIED:
            pass
        else:
            pass

    def ask_quit(self, widget, event):
        x = self.quitDialog()
        if x == 1:
            self.cancel(widget)
        return True

    def cancel(self, widget):
        for window_name in self.child_windows.keys():
            self.close_window(window_name)
            
        if self.errordialog is not None:
            self.errordialog.destroy()
            self.errors_closed()

        for t in self.torrents.itervalues():
            if t.widget is not None:
                t.widget.close_child_windows()

        if self.statusIcon is not None:
            self.statusIcon.set_visible(False)
            self.statusIcon = None

        self.torrentqueue.set_done()
        gtk.main_quit()

    def make_statusrequest(self):
        if self.config['pause']:
            return True
        for infohash, t in self.running_torrents.iteritems():
            self.torrentqueue.request_status(infohash, False, t.widget.filelistwindow is not None)
        return True


    def select_torrent_to_open(self, widget):
        path = smart_dir(self.config['save_in'])
        self.open_window('openfile',
                         title="Open .atorrent:",
                         fullname=path,
                         got_location_func=self.open_torrent,
                         no_location_func=lambda: self.window_closed('openfile'))

    def select_old_torrent_to_open(self, widget):
        path = smart_dir(self.config['save_in'])
        self.open_window('openfile',
                         title="Open .torrent:",
                         fullname=path,
                         got_location_func=self.open_old_torrent,
                         no_location_func=lambda: self.window_closed('openfile'))


    def open_torrent(self, name):
        self.window_closed('openfile')
        f = None
        try:
            f = file(name, 'rb')
            data = f.read()
        except IOError: 
            pass # the user has selected a directory or other non-file object
        else:
            if not '.atorrent' in name:
                #self.open_warning(data)
		data = anomosify(data, self.config)
		self.torrentqueue.start_new_torrent(data)
            else:
                self.torrentqueue.start_new_torrent(data)
        if f is not None:
            f.close()  # shouldn't fail with read-only file (well hopefully)

    def open_old_torrent(self, name):
        self.window_closed('openfile')
        f = None
        try:
            f = file(name, 'rb')
            data = f.read()
        except IOError: 
            pass # the user has selected a directory or other non-file object
        else:
            if not '.torrent' in name:
                #self.open_warning(data)
		self.torrentqueue.start_new_torrent(data)
            else:
		data = anomosify(data, self.config)
                self.torrentqueue.start_new_torrent(data)
        if f is not None:
            f.close()  # shouldn't fail with read-only file (well hopefully)


    def save_location(self, infohash, metainfo):
        name = metainfo.name_fs

        if self.config['save_as']:
            path = self.config['save_as']
            self.got_location(infohash, path)
            self.config['save_as'] = ''
            return

        path = smart_dir(self.config['save_in'])

        fullname = os.path.join(path, name)

        if not self.config['ask_for_save']:
            if os.access(fullname, os.F_OK):
                message = MessageDialog(self.mainwindow, _('File exists!'),
                                        _('"%s" already exists.\n Do you want to choose a different file name?.')%name,
                                        buttons=gtk.BUTTONS_YES_NO,
                                        nofunc= lambda : self.got_location(infohash, fullname),
                                        yesfunc=lambda : self.get_save_location(infohash, metainfo, fullname),)

            else:
                self.got_location(infohash, fullname)
        else:
            self.get_save_location(infohash, metainfo, fullname)

    def get_save_location(self, infohash, metainfo, fullname):
        def no_location():
            self.window_closed('savefile')
            self.torrentqueue.remove_torrent(infohash)
            
        if len(metainfo.sizes) < 2:
            selector = self.open_window('savefile',
                title="Save location for " + metainfo.name,
                fullname=fullname,
                got_location_func = lambda fn: self.got_location(infohash, fn),
                no_location_func=no_location)
        else:
            selector = self.open_window('choosefolder',
                                            title="Save location for " + metainfo.name,
                                            fullname=fullname,
                                            got_location_func = lambda fn: self.got_location(infohash, fn),
                                            no_location_func=no_location)

        self.torrents[infohash].widget = selector

    def got_location(self, infohash, fullpath):
        self.window_closed('savefile')
        self.torrents[infohash].widget = None
        save_in = os.path.split(fullpath)[0]
        if save_in[-1] != os.sep:
            save_in += os.sep
        self.set_config('save_in', save_in)        
        self.torrents[infohash].dlpath = fullpath
        self.torrentqueue.set_save_location(infohash, fullpath)

    def add_unhighlight_handle(self):
        if self.unhighlight_handle is not None:
            gobject.source_remove(self.unhighlight_handle)
            
        self.unhighlight_handle = gobject.timeout_add(2000,
                                                      self.unhighlight_after_a_while,
                                                      priority=gobject.PRIORITY_LOW)

    def unhighlight_after_a_while(self):
        self.drag_highlight()
        gobject.source_remove(self.unhighlight_handle)
        self.unhighlight_handle = None
        return False

    def init_updates(self):
        if self.update_handle is not None:
            gobject.source_remove(self.update_handle)
        self.update_handle = gobject.timeout_add(
            int(self.config['display_interval'] * 1000),
            self.make_statusrequest)

    def update_torrent_widgets(self):
        # Separate by downloading/seeding status
        dl = [t for _,t in self.torrents.items() if t.completion < 1]
        sd = [t for _,t in self.torrents.items() if t.completion >= 1]
        if self.dlclicked:
            to_show, to_hide = dl, sd
        else:
            to_show, to_hide = sd, dl
        for i,s in enumerate(to_show):
            if s.widget:
                s.widget.show()
                try:
                    self.runbox.reorder_child(s.widget, i)
                except ValueError:
                    pass
        for h in to_hide:
            if h.widget:
                h.widget.hide()

    def remove_torrent_widget(self, infohash):
        t = self.torrents[infohash]
        self.lists[t.state].remove(infohash)
        if t.state == RUNNING:
            del self.running_torrents[infohash]
            self.set_title()
        if t.state == ASKING_LOCATION:
            if t.widget is not None:
                t.widget.destroy()
            return

        if t.state in (KNOWN, RUNNING, QUEUED):
            t.widget.close_child_windows()

        if t.state == RUNNING:
            self.runbox.remove(t.widget)
        elif t.state == QUEUED:
            self.queuebox.remove(t.widget)
        elif t.state == KNOWN:
            self.knownbox.remove(t.widget)
          
        t.widget.destroy()


    def create_torrent_widget(self, infohash, queuepos=None):
        t = self.torrents[infohash]
        l = self.lists.setdefault(t.state, [])
        if queuepos is None:
            l.append(infohash)
        else:
            l.insert(queuepos, infohash)
        if t.state == ASKING_LOCATION:
            self.save_location(infohash, t.metainfo)
            return
        elif t.state == RUNNING:
            self.running_torrents[infohash] = t
            if not self.config['pause']:
                t.widget = RunningTorrentBox(infohash, t.metainfo, t.dlpath,
                                             t.completion, self)
            else:
                t.widget = PausedTorrentBox(infohash, t.metainfo, t.dlpath,
                                             t.completion, self)
            box = self.runbox
        elif t.state == QUEUED:
            t.widget = QueuedTorrentBox(infohash, t.metainfo, t.dlpath,
                                        t.completion, self)
            box = self.queuebox
        elif t.state == KNOWN:
            t.widget = KnownTorrentBox(infohash, t.metainfo, t.dlpath,
                                       t.completion, self)
            box = self.knownbox
        box.pack_start(t.widget, expand=False, fill=False)
        if queuepos is not None:
            box.reorder_child(t.widget, queuepos)

    #TODO: Make this better fit the current logging model.
    def error(self, infohash, severity, text):
        #XXX: Temporary fix
        try:
            name = self.torrents[infohash].metainfo.name
        except Exception, e:
            return
        err_str = '"%s" : %s'%(name,text)
        err_str = err_str.decode('utf-8', 'replace').encode('utf-8')
        if severity.lower() in (_("error"), _("critical")):
            self.error_modal(err_str)
        logfunc = getattr(log, severity.lower()) # hacky
        logfunc(err_str)

    def global_error(self, severity, text):
        err_str = _('(global message) : %s')%text
        err_str = err_str.decode('utf-8', 'replace').encode('utf-8')
        if severity.lower() in (_("error"), _("critical")):
            self.error_modal(text)
        logfunc = getattr(log, severity.lower()) # hacky
        logfunc(err_str)

    def error_modal(self, text):
        title = _('%s Error') % app_name
        
        if self.errordialog is not None:
            if not self.errordialog.multi:
                self.errordialog.destroy()
                self.errordialog = MessageDialog(self.mainwindow, title, 
                                                 _('Multiple errors have occurred. '),
                                                 _('Click OK to view the error log.'),
                                                 buttons=gtk.BUTTONS_OK_CANCEL,
                                                 yesfunc=self.multiple_errors_yes,
                                                 nofunc=self.errors_closed,
                                                 )
                self.errordialog.multi = True
            else:
                # already showing the multi error dialog, so do nothing
                pass
        else:
            self.errordialog = MessageDialog(self.mainwindow, title, text,
                                             yesfunc=self.errors_closed)
            self.errordialog.multi = False


    def multiple_errors_yes(self):
        self.errors_closed()
        self.open_window('log')

    def errors_closed(self):
        self.errordialog = None

    def stop_queue(self):
        self.set_config('pause', 1)
        self.set_title()
        q = list(self.runbox.get_queue())
        for infohash in q:
            t = self.torrents[infohash]
            self.remove_torrent_widget(infohash)
            self.create_torrent_widget(infohash)

    def restart_queue(self):
        self.set_config('pause', 0)
        q = list(self.runbox.get_queue())
        for infohash in q:
            t = self.torrents[infohash]
            self.remove_torrent_widget(infohash)
            self.create_torrent_widget(infohash)

    def update_status(self, torrent, statistics):
        if self.config['pause']:
            return
        self.running_torrents[torrent].widget.update_status(statistics)
        try:
            ## Windows doesn't allow /t in tooltips
            if (sys.platform == "win32" or sys.platform == "nt"):
                self.statusIcon.set_tooltip(_('Complete: ') + (str(statistics['fractionDone']*100)[:3]) + _('%\nDown: ') + str(Rate(statistics['downRate'])) + _('\nUp: ') + str(Rate(statistics['upRate'])) + _('\nRelay: ') + str(Rate(statistics['relayRate'])))
            else:
                self.statusIcon.set_tooltip(_('Complete:\t') + (str(statistics['fractionDone']*100)[:3]) + _('%\nDown:\t\t') + str(Rate(statistics['downRate'])) + _('\nUp:\t\t\t') + str(Rate(statistics['upRate'])) + _('\nRelay:\t\t') + str(Rate(statistics['relayRate'])))
        except KeyError:
            ##Stupid race
            self.statusIcon.set_tooltip('Anomos')

    def new_displayed_torrent(self, infohash, metainfo, dlpath, state,
                              completion=None, uptotal=0, downtotal=0):
        t = Struct()
        t.metainfo = metainfo
        t.dlpath = dlpath
        t.state = state
        t.completion = completion
        t.uptotal = uptotal
        t.downtotal = downtotal
        self.torrents[infohash] = t
        self.create_torrent_widget(infohash)
        if t.completion < 1:
            self.dbutton.show_downloading()
        else:
            self.sbutton.show_seeding()
        self.dbutton.update_label()
        self.sbutton.update_label()

    def torrent_state_changed(self, infohash, state, completion,
                              uptotal, downtotal, queuepos=None):
        t = self.torrents[infohash]
        self.remove_torrent_widget(infohash)
        t.state = state
        t.completion = completion
        t.uptotal = uptotal
        t.downtotal = downtotal
        self.create_torrent_widget(infohash, queuepos)
        self.update_torrent_widgets()
        self.dbutton.update_label()
        self.sbutton.update_label()

    def reorder_torrent(self, infohash, queuepos):
        self.remove_torrent_widget(infohash)
        self.create_torrent_widget(infohash, queuepos)

    def update_completion(self, infohash, completion, files_left=None,
                          files_allocated=None):
        t = self.torrents[infohash]
        if files_left is not None and t.widget.filelistwindow is not None:
            t.widget.filelistwindow.update(files_left, files_allocated)
        self.dbutton.update_label()
        self.sbutton.update_label()
        self.update_torrent_widgets()

    def removed_torrent(self, infohash):
        self.remove_torrent_widget(infohash)
        del self.torrents[infohash]
        self.dbutton.update_label()
        self.sbutton.update_label()
        self.update_torrent_widgets()

    def change_torrent_state(self, infohash, newstate, index=None,
                             replaced=None, force_running=False):
        t = self.torrents[infohash]
        pred = succ = None
        if index is not None:
            l = self.lists.setdefault(newstate, [])
            if index > 0:
                pred = l[index - 1]
            if index < len(l):
                succ = l[index]
        self.torrentqueue.change_torrent_state(infohash, t.state, newstate,
                                         pred, succ, replaced, force_running)
        self.dbutton.update_label()
        self.sbutton.update_label()
        self.update_torrent_widgets()

    def finish(self, infohash):
        t = self.torrents[infohash]
        if t is None or t.state == KNOWN:
            return
        self.change_torrent_state(infohash, KNOWN)
        self.dbutton.update_label()
        self.sbutton.update_label()
        self.update_torrent_widgets()

    def confirm_replace_running_torrent(self, infohash, replaced, index):
        replace_func = lambda *args: self.change_torrent_state(infohash,
                                RUNNING, index, replaced)
        add_func     = lambda *args: self.change_torrent_state(infohash,
                                RUNNING, index, force_running=True)
        moved_torrent = self.torrents[infohash]

        if moved_torrent.state == RUNNING:
            self.change_torrent_state(infohash, RUNNING, index)
            return

        if self.config['dnd_behavior'] == 'replace':
            replace_func()
            return
        elif self.config['dnd_behavior'] == 'add':
            add_func()
            return
        
        moved_torrent_name = moved_torrent.metainfo.name
        confirm = MessageDialog(self.mainwindow,
                                _('Stop running torrent?'),
                                _('You are about to start "%s". Do you want to stop the last running torrent as well?')%(moved_torrent_name),
                                type=gtk.MESSAGE_QUESTION,
                                buttons=gtk.BUTTONS_YES_NO,
                                yesfunc=replace_func,
                                nofunc=add_func,
                                default=gtk.RESPONSE_YES)

    ##Naggers!
    def nag(self):
        return
        if ((self.config['donated'] != version) and
            (random.random() * NAG_FREQUENCY) < 1):
            title = _('Have you donated?')
            message = _('Welcome to the new version of %s. Have you donated?')%app_name
            self.nagwindow = MessageDialog(self.mainwindow,
                                           title,
                                           message,
                                           type=gtk.MESSAGE_QUESTION,
                                           buttons=gtk.BUTTONS_YES_NO,
                                           yesfunc=self.nag_yes, nofunc=self.nag_no,)
            
    def nag_no(self):
        self.donate()

    def nag_yes(self):
        self.set_config('donated', version)
        MessageDialog(self.mainwindow,
                      _('Thanks!'),
                      _('Thanks for donating! To donate again, '),
                      _('select "Donate" from the "Help" menu.'))

    def donate(self):
        self.visit_url(DONATE_URL)


    def visit_url(self, url):
        t = threading.Thread(target=webbrowser.open,
                             args=(url,))
        t.start()

    def raiseerror(self, *args):
        raise ValueError('test traceback behavior')

    def warnIcon(self, value=None):
        if value == None:
            value = self.config['minport']
        self.warning = get_warning()
        self.setWarnIconText(value)
        self.controlbox.pack_start(self.warning, expand=False, fill=True, padding=5)
            
    def setWarnIconText(self, value):
        self.warning = get_warning()         
        self.warning.set_tooltip_text(_("The ports on your router are not configured properly. This will interefere with file transfers. Please forward port ") + str(value) + _(" to your machine."))

    def checkPort(self):
        t = checkPortThread(self.config['minport'], self.controlbox, self.warning, self.separator2)
        t.start()

#This works most of the time, however, it is not elegant or foolproof.        
class checkPortThread(threading.Thread):
    def __init__(self, port, cbox, w, s):
        threading.Thread.__init__(self)
        self.port = str(port)
        self.controlbox = cbox
        self.warning = w
        self.separator2 = s
    def run(self):
        try:
            f = urlopen("http://anomos.info/chkport/?port=" + self.port)
            the_page = str(f.read())
            f.close()
            if 'closed' in the_page:
                log.info(_("Ports are closed!"))
                return
            else:
                log.info(_("Ports are open!"))
                gtk.gdk.threads_enter()
                self.controlbox.remove(self.warning)
                self.controlbox.remove(self.separator2)
                gtk.gdk.threads_leave()
        except Exception, e:
            return
            
#This works most of the time, however, it is not elegant or foolproof.        
class getScrapeThread(threading.Thread):
    def __init__(self, box, infohash):
        threading.Thread.__init__(self)
        self.box = box
        self.infohash = infohash
        self.table = self.box.table
        
    def add_item(self, key, val, y):
        self.table.attach(ralign(gtk.Label(key)), 0, 1, y, y+1)
        v = gtk.Label(val)
        v.set_selectable(True)
        self.table.attach(lalign(v), 1, 2, y, y+1)
        
    def run(self):
        try:
            # :( :( :(
            y = 7
            scrape_data = self.box.torrent_box.main.torrentqueue.wrapped.multitorrent.torrents[self.infohash]._rerequest.scrape()
            
            if isinstance(scrape_data, dict):
                self.add_item(_('Seeds:'), scrape_data['files'][self.infohash]['complete'], y)
                y = y+1
                
                self.add_item(_('Leechers:'), scrape_data['files'][self.infohash]['incomplete'], y)
                y+=1
            
                #Gtk shits here.. not sure how to resolve
                self.box.vbox.pack_start(self.table)
                self.box.win.show_all()
        
        except Exception, e:
            log.info(e)
            return
        
#is this a privacy concern?
def getExternalIP():
    try:
        ## XXX: Broken with HTTPS
        f = urlopen("http://anomos.info/getip/")
        s = str(f.read())
        f.close()
        return s
    except:
        return ""

def anomosify(data, config):

	r = bdecode(data)
	if 'announce-list' in r:
	    for a,l in enumerate(r['announce-list']):
	        if a == 0:
	            r['announce-list'][a] = config['anonymizer']
	        else: 
	            del r['announce-list'][a:]
	r['announce'] = config['anonymizer']

	return bencode(r)
	
if __name__ == '__main__':

    try:
        config, args = configfile.parse_configuration_and_args(defaults,
                                        'anondownloadgui', sys.argv[1:], 0, None)
    except BTFailure, e:
        print str(e)
        sys.exit(1)

    if (sys.platform == "win32" or sys.platform == "nt"):
        pth = os.path.join(config['data_dir'], "logfile.txt")
        sys.stdout = open(pth, "w")
        sys.stderr = open(pth, "w")
    sys.argv[0] = 'anomos'

    advanced_ui = config['advanced']
    ##advanced UI always on!
    ##advanced_ui = 1

    if config['responsefile']:
        if args:
            raise BTFailure("Can't have both --responsefile and non-option "
                            "arguments")
        newtorrents = [config['responsefile']]
    else:
        newtorrents = args
    controlsocket = ControlSocket(config)

    if config['auto_ip'] == 1:
        config['ip'] = getExternalIP()

    got_control_socket = True
    try:
        controlsocket.create_socket()
    except BTFailure:
        got_control_socket = False
        try:
            controlsocket.send_command('no-op')
        except BTFailure:
            # XXX: this should pop up an error message for the user
            raise

    datas = []
    errors = []
    if newtorrents:
        for filename in newtorrents:
            f = None
            try:
                f = file(filename, 'rb')
                data = f.read()
                f.close()
            except Exception, e:
                if f is not None:
                    f.close()
                errors.append('Could not read %s: %s' % (filename, str(e)))
            else:
                datas.append(data)

        # Not sure if anything really useful could be done if
        # these send_command calls fail
        if not got_control_socket:
            for data in datas:
                controlsocket.send_command('start_torrent', data)
            for error in errors:
                controlsocket.send_command('show_error', error)
            sys.exit(0)
    elif not got_control_socket:
        controlsocket.send_command('show_error', '%s already running'%app_name)
        sys.exit(1)

    gtk.gdk.threads_init()

    torrentqueue = TorrentQueue.TorrentQueue(config, ui_options, controlsocket)
    d = DownloadInfoFrame(config,TorrentQueue.ThreadWrappedQueue(torrentqueue))

    def lock_wrap(function, *args):
        gtk.gdk.threads_enter()
        function(*args)
        gtk.gdk.flush()
        gtk.gdk.threads_leave()

    def gtk_wrap(function, *args):
        gtk.gdk.threads_enter()
        gobject.idle_add(lock_wrap, function, *args)
        gtk.gdk.threads_leave()
    startflag = threading.Event()
    dlthread = threading.Thread(target = torrentqueue.run,
                                args = (d, gtk_wrap, startflag))
    dlthread.setDaemon(False)
    dlthread.start()
    startflag.wait()
    for data in datas:
        d.torrentqueue.start_new_torrent(data)
    for error in errors:
        d.global_error("ERROR", error)

    try:
        d.main()
    except KeyboardInterrupt:
        # the gtk main loop is closed in DownloadInfoFrame
        sys.exit(1)

