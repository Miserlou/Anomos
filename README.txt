Anomos is a pseudonymous, encrypted multi-peer-to-peer file distribution protocol. It is based on the peer/tracker concept of BitTorrent in combination with an onion routing anonymization layer, with the added benefit of end-to-end encryption. By combining these technologies, we have created a platform where by no party outside of the trusted tracker will have any information about who a peer is or what they are downloading.

Anomos is designed to be easy to use – you won’t even be aware of the security that it provides. Anybody who is already familiar with BitTorrent won’t have to do anything differently.

If you are on a Unix machine, you will need to have python2.6, openssl and python-m2crypto installed. To run the gui client, type
python anondownloadgui.py

To use the command-line version,
python anondownloadheadless.py torrentfilename.atorrent --save_as outputfliename --identity your_identity_name

You will also need to have the appropriate port range (5061-5069 by default) forwarded to your machine.

Anomos Liberty Enhancements
http://www.anomos.info
#anomos on irc.freenode.org
