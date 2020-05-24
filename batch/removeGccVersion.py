#!/usr/bin/env python2.7

import sys
import struct
import os

# replaces 'GCC: (GNU) 4.9.4' with zeroes (.rdata$zzz)
needle  = '\x47\x43\x43\x3a\x20\x28\x47\x4e\x55\x29\x20\x34\x2e\x39\x2e\x34'
# zeroing major+minor linker version (0x010b = magic, 0x02 major, 0x19 minor => GNU ld 2.25)
needle2 = '\x0b\x01\x02\x19'

def main(argv):
    found    = 0
    absfound = 0
    buf      = bytearray()
    with open(argv[0], "rb") as fin:
        for line in fin:
            buf += line
    with open(argv[0], "wb") as fout:
        pos = str(buf).find(needle)
        while pos > -1:
            poslen = 0
            if pos > -1:
                for v in buf[pos:]:
                    if v == 0:
                        break
                    poslen += 1
                buf[pos:pos+poslen] = '\x00'*poslen
                found += 1
                absfound += poslen
            pos = str(buf).find(needle)

        pos = str(buf).find(needle2)
        ldsig = False
        if pos > -1 and pos <= 0x200:
            ldsig = True
            buf[pos+2] = '\x00'
            buf[pos+3] = '\x00'

        fout.write(str(buf))
        fout.flush()
    return ( bool(ldsig), int(found), int(absfound) )

if __name__ == "__main__":
    bname = os.path.basename(sys.argv[0])
    if len(sys.argv) < 2:
        sys.stderr.write(bname + ' usage: ' + sys.argv[0] + ' [WIN32_PE]\n')
        sys.exit(1)
    if not os.access(sys.argv[1], os.W_OK):
        sys.stderr.write(bname + ': No write access: ' + sys.argv[1] + '\n')
        sys.exit(2)
    print bname + ': Searching for GCC Fingerprint:', needle.encode('hex')
    (ldsig, found, abslen) = main(sys.argv[1:])
    if found > 0:
        print bname + ': Found', found, 'occurences; Zero\'d:', found * len(needle) + abslen, 'bytes'
    else:
        print bname + ': None found .. (.rdata$zzz already removed)'
    if ldsig:
        print bname + ': Linker signature removed ..'
    else:
        print bname + ': No Linker signature found'

    sys.exit(0)
