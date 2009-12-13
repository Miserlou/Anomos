import urlparse

def parse_magnet(magnet):
    if magnet[:8] != "magnet:?":
        raise NameError("Invalid")
    else:
        magnet = magnet[8:]
    args =  urlparse.parse_qs(magnet)

    btih = "xt=urn:btih:"
    # magnet is retardedly designed so this hack is needed to get the has
    if magnet.find(btih) == -1:
        raise NameError("Invalid")
    else:
        bindex = magnet.find(btih)
        qindex = magnet.find('&')
        hsh = magnet[bindex+12:qindex]

    if not 'dn' in args:
        dn = "Missing name"
    else:
        dn = str(args['dn'])
        dn = dn[2:]
        dn = dn[:-2]

    return dict(info=hsh, name=dn)
