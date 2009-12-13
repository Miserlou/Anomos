import urlparse

magnet = "magnet:?xt=urn:btih:afa23e62c4ca6965800815329553c6a705cdb2f4&dn=%5BPSP%5DHello.Kitty.Happy.Accessory.%5BJAP%5D.-..rar"
invalid = 'Invalid'

if magnet[:8] != "magnet:?":
    print invalid
else:
    magnet = magnet[8:]
args =  urlparse.parse_qs(magnet)
print args

btih = "xt=urn:btih:"
# magnet is retardedly designed so this hack is needed to get the has
if magnet.find(btih) == -1:
    print invalid
else:
    bindex = magnet.find(btih)
    qindex = magnet.find('&')
    hsh = magnet[bindex+12:qindex]
    print hsh

if not 'dn' in args:
    dn = "Missing name"
else:
    dn = str(args['dn'])
    dn = dn[2:]
    dn = dn[:-2]

print hsh, dn
