#!/usr/bin/env python2.7

import sys
import struct
import os

def main(argv):
    buf      = bytearray()
    with open(argv[0], "rb") as fin:
        for line in fin:
            buf += line
    buf[0xF8:0x100]  = '\x00' * (0x100-0xF8)  # export table
    buf[0x100:0x108] = '\x00' * (0x108-0x100) # import table
    with open(argv[0], "wb") as fout:
        fout.write(str(buf))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print os.path.basename(sys.argv[0]) + ' usage: ' + sys.argv[0] + ' [PE-FILE]'
        sys.exit(1)
    print os.path.basename(sys.argv[0]) + ': NULL\'ing Import/Export Data Directory Entries ..'
    main(sys.argv[1:])
    sys.exit(0)
