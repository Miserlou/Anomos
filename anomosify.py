#!/usr/bin/env python

## Mass Anomosification Script - Rich Jones, Anomos Liberty Enhancements
## Public Domain, 2010
## Patches, Flames: rich@anomos.info

from Anomos.bencode import bdecode, bencode
import os
import sys
import getopt

def anomosify(data, announce="https://tracker.anomos.info:5555/announce"):

	r = bdecode(data)
	if 'announce-list' in r:
	    for a,l in enumerate(r['announce-list']):
	        if a == 0:
	            r['announce-list'][a] = announce
	        else: 
	            del r['announce-list'][a:]
	r['announce'] = announce
	r['anon'] = '1'

	return bencode(r)
	
def process_file(fname, announce):
    try:
        f = file(fname, 'rb')
        data = f.read()
        anomosified = anomosify(data)

        f = open(fname[:-7] + "atorrent", 'w')
        f.write(anomosified)
        f.close()
    except IOError, e:
        print e 
        pass 
    except Exception, e:
        print e
        pass

def main(argv):

    try:
        opts, args = getopt.getopt(argv, "a:p:", ["announce=", "path="])
    except getopt.GetoptError:
        print "Hey, you need to supply --announce and --path"
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-a", "--announce"):
            announce = arg
        else:
            announce = "https://tracker.anomos.info:5555/announce"
            
        if opt in ("-p", "--path"):
            path = arg
        else:
            path = '.'
            
    if not os.path.isfile(path):
        for fname in os.listdir(path):
            fp = os.path.join(path, fname)
            print fp
            process_file(fp, announce)
    else:
        process_file(path, announce)
     
if __name__ == "__main__":
    main(sys.argv[1:])
