#!/usr/bin/env python2.7

import sys
import struct
import os
import binascii


e_lfanew_OFFSET = 0x40
SizeOfHeaders_OFFSET = 0x04 + 0x14 + 0x3C # sizeof(PE_sig) + sizeof(COFF_hdr) + Optional_hdr->SizeOfHeaders
SizeOfHeaders_DEFAULT = 0x400 # default value for GCC


def main(argv):
    found    = 0
    absfound = 0
    buf      = bytearray()
    with open(argv[0], "rb") as fin:
        for line in fin:
            buf += line
    if buf[0:2] != '\x4d\x5a':
        return False
    
    e_lfanew = struct.unpack("<L", buf[e_lfanew_OFFSET-0x4:e_lfanew_OFFSET])[0]
    dosStubSiz = e_lfanew - e_lfanew_OFFSET
    if buf[e_lfanew:e_lfanew+0x2] != '\x50\x45':
        return False
    i = int(e_lfanew) + SizeOfHeaders_OFFSET
    SizeOfHeaders = struct.unpack("<L", buf[i:i+0x4])[0]
    if SizeOfHeaders > SizeOfHeaders_DEFAULT or SizeOfHeaders <= 0:
        return False

    newstart = (e_lfanew - dosStubSiz)
    if newstart <= 0:
        return False
    newstart = struct.pack("<L", newstart)

    buf[0x2:0x3C] = '\x00'*(0x3C-0x2)
    buf[0x3C:0x40] = newstart
    buf[0x40:0x40+dosStubSiz] = '\x00'*(0x80-0x40)
    buf[e_lfanew_OFFSET:] = buf[e_lfanew:SizeOfHeaders] + bytearray('\x00'*dosStubSiz) + buf[SizeOfHeaders:]

    with open(argv[0], "wb") as fout:
        fout.write(str(buf))
        fout.flush()
    return True
 
if __name__ == "__main__":
    bname = os.path.basename(sys.argv[0])
    if len(sys.argv) < 2:
        sys.stderr.write(bname + ' usage: ' + sys.argv[0] + ' [WIN32_PE]\n')
        sys.exit(1)
    if not os.access(sys.argv[1], os.W_OK):
        sys.stderr.write(bname + ': No write access: ' + sys.argv[1] + '\n')
        sys.exit(2)
    print bname + ': Checking DOS/PE Header'
    if main(sys.argv[1:]):
        print bname + ': NULL\'d/REMOVED unused DOS header values/stub'
    else:
        print bname + ': Not a valid DOS/PE Header/Stub'
        sys.exit(3)

    sys.exit(0)
