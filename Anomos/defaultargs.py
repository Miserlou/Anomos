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

common_options = [
    ('ip', '',
        "ip to report to the tracker (has no effect unless you are on the same local network as the tracker)"),
    ('forwarded_port', 0,
        "world-visible port number if it's different from the one the client "
        "listens on locally"),
    ('minport', 6881, 'minimum port to listen on, counts up if unavailable'),
    ('maxport', 6999, 'maximum port to listen on'),
    ('bind', '',
        'ip to bind to locally'),
    ('display_interval', .5,
        'seconds between updates of displayed information'),
    ('rerequest_interval', 5 * 60,
        'minutes to wait between requesting more peers'),
    ('min_peers', 20,
        'minimum number of peers to not do rerequesting'),
    ('max_initiate', 200,
        'number of peers at which to stop initiating new connections'),
    ('max_allow_in', 200,
        'maximum number of connections to allow, after this new incoming connections will be immediately closed'),
    ('check_hashes', 1,
        'whether to check hashes on disk'),
    ('max_upload_rate', 100,
        'maximum kB/s to upload at, 0 means no limit'),
    ('min_uploads', 2,
        "the number of uploads to fill out to with extra optimistic unchokes"),
    ('data_dir', '',
         "directory under which variable data such as fastresume information "
         "and GUI state is saved. Defaults to subdirectory 'data' of the "
         "bittorrent config directory."),
    ('max_files_open', 50,
     'the maximum number of files in a multifile torrent to keep open at a time, 0 means no limit. Used to avoid running out of file descriptors.'),
    ('identity', 'peer', 'the identity to use (basename of pub/pvt key)'),
    ('auto_ip', 0, 'whether to automatically fetch an external ip to report to the tracker')
    ]


rare_options = [
    ('download_slice_size', 2 ** 14,
        "how many bytes to query for per request."),
    ('max_message_length', 2 ** 23,
        "maximum length prefix encoding you'll accept over the wire - larger values get the connection dropped."),
    ('socket_timeout', 300.0,
        'seconds to wait between closing sockets which nothing has been received on'),
    ('timeout_check_interval', 60.0,
        'seconds to wait between checking if any connections have timed out'),
    ('max_slice_length', 16384,
        "maximum length slice to send to peers, close connection if a larger request is received"),
    ('max_rate_period', 20.0,
        "maximum amount of time to guess the current rate estimate represents"),
    ('max_rate_period_seedtime', 100.0,
        "maximum amount of time to guess the current rate estimate represents"),
    ('max_announce_retry_interval', 1800,
        'maximum time to wait between retrying announces if they keep failing'),
    ('snub_time', 30.0,
        "seconds to wait for data to come in over a connection before assuming it's semi-permanently choked"),
    ('rarest_first_cutoff', 4,
        "number of downloads at which to switch from random to rarest first"),
    ('upload_unit_size', 1380,
        'how many bytes to write into network buffers at once.'),
    ('retaliate_to_garbled_data', 1,
     'refuse further connections from addresses with broken or intentionally '
     'hostile peers that send incorrect data'),
    ('one_connection_per_ip', 1,
     'do not connect to several peers that have the same IP address'),
    ('peer_socket_tos', 8,
     'if nonzero, set the TOS option for peer connections to this value'),
    ('filesystem_encoding', '',
     "character encoding used on the local filesystem. If left empty, autodetected. Autodetection doesn't work under python versions older than 2.3"),
    ('enable_bad_libc_workaround', 0,
     'enable workaround for a bug in BSD libc that makes file reads very slow.'),
    ('tracker_proxy', '',
        'address of HTTP proxy to use for tracker connections. Format: [username:password@]host:port'),
    ]

def get_defaults(ui):
    assert ui in "anondownloadheadless anondownloadcurses anondownloadgui " \
           "anonlaunchmany anonlaunchmanycurses anonmaketorrentgui".split()

    r = list(common_options)

    if ui == 'anondownloadgui':
        r.extend([
            ('save_as', '',
             'file name (for single-file torrents) or directory name (for batch torrents) to save the torrent as, overriding the default name in the torrent. See also --save_in, if neither is specified the user will be asked for save location'),
            ('advanced', 0,
             "display advanced user interface"),
            ('next_torrent_time', 99999,
             'the maximum number of minutes to seed a completed torrent before stopping seeding'),
            ('next_torrent_ratio', 0,
             'the minimum upload/download ratio, in percent, to achieve before stopping seeding. 0 means no limit.'),
            ('last_torrent_ratio', 0,
             'the minimum upload/download ratio, in percent, to achieve before stopping seeding the last torrent. 0 means no limit.'),
            ('pause', 0,
             'start downloader in paused state'),
            ('dnd_behavior', 'add',
             ''),
            ])

    if ui in ('anondownloadcurses', 'anondownloadheadless'):
        r.append(
            ('save_as', '',
             'file name (for single-file torrents) or directory name (for batch torrents) to save the torrent as, overriding the default name in the torrent. See also --save_in'))

    if ui.startswith('anondownload'):
        r.extend([
            ('max_uploads', -1,
             "the maximum number of uploads to allow at once. -1 means a (hopefully) reasonable number based on --max_upload_rate. The automatic values are only sensible when running one torrent at once."),
            ('save_in', '',
             'local directory where the torrent contents will be saved. The file (single-file torrents) or directory (batch torrents) will be created under this directory using the default name specified in the .atorrent file. See also --save_as.'),
            ('responsefile', '',
             'file the server response was stored in, alternative to url'),
            ('url', '',
             'url to get file from, alternative to responsefile'),
            ('ask_for_save', 0,
             'whether or not to ask for a location to save downloaded files in'),
            ])

    if ui.startswith('anonlaunchmany'):
        r.extend([
            ('max_uploads', 6,
             "the maximum number of uploads to allow at once. -1 means a (hopefully) reasonable number based on --max_upload_rate. The automatic values are only sensible when running one torrent at once."),
            ('save_in', '',
             'local directory where the torrents will be saved, using a name determined by --saveas_style. If this is left empty each torrent will be saved under the directory of the corresponding .atorrent file'),
            ('parse_dir_interval', 60,
              "how often to rescan the torrent directory, in seconds" ),
            ('saveas_style', 1,
              "How to name torrent downloads (1 = rename to torrent name, " +
              "2 = save under name in torrent, 3 = save in directory under torrent name)" ),
            ('display_path', ui == 'anonlaunchmany' and 1 or 0,
              "whether to display the full path or the torrent contents for each torrent" ),
            ])

    if ui.startswith('anonlaunchmany') or ui == 'anonmaketorrentgui':
        r.append(
            ('torrent_dir', '',
             'directory to look for .atorrent files (semi-recursive)'),)

    if ui in ('anondownloadcurses', 'anondownloadheadless'):
        r.append(
            ('spew', 0,
             "whether to display diagnostic info to stdout"))

    if ui == 'anonmaketorrentgui':
        r.extend([
            ('piece_size_pow2', 18,
             "which power of two to set the piece size to"),
            ('tracker_name', 'http://my.tracker:6969/announce',
             "default tracker name"),
            ])

    r.extend(rare_options)
    return r
