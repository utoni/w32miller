#!/usr/bin/env python2.7

import sys
import os
import re
import subprocess
from optparse import OptionParser, OptionGroup


objdmp_bin  = os.path.dirname(sys.argv[0]) + '/../deps/sysroot/i686-w64-mingw32/bin/i686-w64-mingw32-objdump'
objdmp_args = '-z -D -j %s %s'
bname       = os.path.basename(sys.argv[0])


def objdump_section(section, binary):
    full_cmd = str(objdmp_bin)+' '+(str(objdmp_args) % (section,binary))
    p = subprocess.Popen(full_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    repat = re.compile(r'^(?:\s+[0-9A-Fa-f]+:\s+)(([0-9A-Fa-f]{2}\s{1})+)')
    insts = 0
    scode = bytearray()
    p.wait()
    if p.returncode != 0:
        sys.stderr.write(bname + ': objdump command failed with %d: %s\n' % (p.returncode, full_cmd))
        sys.exit(1)
    for line in p.stdout.readlines():
        r = repat.match(line)
        if r:
            insts += 1
            insthex = str(r.group(1))
            for byte in str(insthex).split(' '):
                if len(byte) == 2:
                    scode += str(byte).decode('hex')
                elif len(byte) != 0:
                    raise TypeError('Invalid byte in hex str: ' + str(byte))
    return (scode, insts)

def gen_cstr(bytebuf):
    cstr = str()
    for byte in bytebuf:
        cstr += '\\x'+str(hex(byte))[2:].zfill(2)
    return cstr

def write_header(path, dpref, cstr, csiz, insts):
    with open(path, 'a+b') as out_hdr:
        outstr = \
            '#undef {0}\n' \
            '#undef {0}_SIZE\n' \
            '#undef {0}_INSTS\n\n' \
            '#define {0} "{1}"\n' \
            '#define {0}_SIZE {2}\n' \
            '#define {0}_INSTS {3}\n\n\n'.format(dpref, cstr, csiz, insts)
        out_hdr.write(outstr)
        out_hdr.flush()

# example: genShellcode.py --section=.minit --binary=lib/libloader_x86.a --define-prefix=LOADER_SHELLCODE --file=include/loader_x86.h
if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-o', '--objdump', dest='objdmp_bin', default=objdmp_bin,
                                                            help='path to objdump binary [default: %default]')
    parser.add_option('-s', '--section', dest='section',    help='target section which shellcode will be extracted [required]')
    parser.add_option('-b', '--binary',  dest='binary',     help='target binary which we want extract shellcode from [required]')
    parser.add_option('-d', '--define-prefix',
                                         dest='prefix',     help='set #define prefix name [required]')
    parser.add_option('-f', '--file',    dest='file',       help='set output header file [required]')
    (options, args) = parser.parse_args()

    doAbort = False
    if options.section is None:
        sys.stderr.write(bname + ': Target section is required.\n')
        doAbort = True
    if options.binary is None:
        sys.stderr.write(bname + ': Target binary is required.\n')
        doAbort = True
    if options.prefix is None:
        sys.stderr.write(bname + ': A `#define` prefix is required.\n')
        doAbort = True
    if options.file is None:
        sys.stderr.write(bname + ': A output header filename is required.\n')
        doAbort = True

    if doAbort is True:
        sys.exit(1)

    (shellcode, instructions) = objdump_section(options.section, options.binary)
    cstr = gen_cstr(shellcode)
    write_header(options.file, options.prefix, cstr, len(shellcode), instructions)

    sys.exit(0)
