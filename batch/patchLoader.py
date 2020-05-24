#!/usr/bin/env python2.7

import sys
import struct
import os
import re
import subprocess
import random
from optparse import OptionParser, OptionGroup


objdmp_bin    = os.path.dirname(sys.argv[0]) + '/../deps/sysroot/i686-w64-mingw32/bin/i686-w64-mingw32-objdump'
pyload_name   = 'pyloader'
pyload_so     = os.path.dirname(sys.argv[0]) + '/../bin/'+pyload_name
pycrypt_name  = 'pycrypt'
pycrypt_so    = os.path.dirname(sys.argv[0]) + '/../bin/'+pycrypt_name
objdmp_sargs  = '-h'
objdmp_dargs  = '-x'
objdmp_retval = None


def require_pyso(name, path):
    try:
        import imp
        pymod = imp.load_dynamic(name, path)
    except (ImportError, IOError):
        return None
    return pymod

def parse_c_array(carr):
    m = re.finditer(r'(([0-9a-fA-F]){2})+', carr)
    ret = bytearray()
    for val in m:
        for byte in bytearray.fromhex(val.group()):
            ret += struct.pack("B", byte & 0xFF)
    return ret

def objdump_print_err(bname):
    if objdmp_retval is not None:
        sys.stderr.write(bname + ': objdump ('+objdmp_bin+') returned: ' + str(objdmp_retval) + '\n')

def objdump_data(path):
    p = subprocess.Popen(str(objdmp_bin)+' '+objdmp_dargs+' '+str(path), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    found = 0
    OBJDMP_NEED = [ 'ImageBase', 'SizeOfImage', 'SizeOfHeaders' ]
    regexmstr = str().join(['|'+s for s in OBJDMP_NEED])[1:]
    matchdict = {key: int(-1) for key in OBJDMP_NEED}
    for line in p.stdout.readlines():
        regex = re.match(r'^\s*('+regexmstr+')\s+([0-9a-fA-F]+)', line)
        if regex:
            found += 1
            matchdict[regex.group(1)] = int(regex.group(2), 16)
    retval = p.wait()
    global objdmp_retval
    objdmp_retval = retval
    retlst = list()
    retlst += [(retval,found)]
    for key in OBJDMP_NEED:
        retlst += [matchdict[key]]
    return retlst

def objdump_sections(path, section):
    p = subprocess.Popen(str(objdmp_bin)+' '+objdmp_sargs+' '+str(path), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    r = False
    for line in p.stdout.readlines():
        regex = re.match(r'^\s+[0-9]+\s+'+section+r'\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+[0-9a-fA-F]+\s+([0-9a-fA-F]+)', line)
        if regex:
            secPtr = int(regex.group(3), 16)
            secVma = int(regex.group(2), 16)
            secSiz = int(regex.group(1), 16)
            r = True
            break
    retval = p.wait()
    global objdmp_retval
    objdmp_retval = retval
    if r and retval == 0:
        return ( secVma, secPtr, secSiz )
    else:
        return ( None, None, None )

def file_to_buf(path):
    buf = bytearray()
    with open(path, "rb") as fin:
        for line in fin:
            buf += line
        return buf
    return None

def buf_to_file(path, buf):
    with open(path, "wb") as fout:
        fout.write(str(buf))
        fout.flush()
        return True
    return False

def find_endmarker_offset(endmarker, bytebuf, ldrPtr, ldrSiz):
    if type(bytebuf) is not bytearray:
        return -1
    return str(buf).find(endmarker, 0 if ldrPtr is None else ldrPtr, 0 if ldrSiz is None or ldrSiz is None else ldrPtr+ldrSiz)

def swapByteOrder32(bytebuf, offset):
    if type(offset) == int and (type(bytebuf) == int or bytebuf is None):
        intval = struct.unpack("<I", struct.pack(">I", offset))[0]
    elif type(offset) == int and type(bytebuf) == bytearray:
        intval = struct.unpack('<I', bytebuf[offset:offset+0x4])[0]
    else: raise TypeError('bytebuf must be either int or bytearray')
    return bytearray([(intval >> i & 0xff) for i in (24,16,8,0)])

def setInt32(bytebuf, offset, intbuf):
    if type(bytebuf) != bytearray or \
            type(intbuf) != int or \
            type(offset) != int:
        raise TypeError('Check your arguments: f(%s,%s,%s)' % (type(bytebuf),type(offset),type(intbuf)))
    bytebuf[offset:offset+4] = swapByteOrder32(None, intbuf)

def getInt32(bytebuf, offset):
    if type(bytebuf) != bytearray or \
            type(offset) != int:
        raise TypeError('Check your arguments: f(%s,%s)' % (type(bytebuf),type(offset)))
    return swapByteOrder32(bytebuf, offset)

def setInt32Buf(bytebuf, offset, buf):
    if type(bytebuf) != bytearray or \
            type(buf) != bytearray or \
            type(offset) != int:
        raise TypeError('Check your arguments: f(%s,%s,%s)' % (type(bytebuf),type(offset),type(buf)))
    if len(buf) % 4 != 0:
        raise TypeError('buffer length is not a multiple of 4: %d' % (len(buf)))
    for i in range(0, len(buf), 4):
        setInt32(bytebuf, offset+i, int(str(buf[i:i+4]).encode('hex'), 16))

def getInt32Buf(bytebuf, offset, maxlen=4):
    if type(bytebuf) != bytearray or \
            type(offset) != int or \
            type(maxlen) != int:
        raise TypeError('Check your arguments: f(%s,%s,%s)' % (type(bytebuf),type(offset),type(buf)))
    if maxlen % 4 != 0:
        raise TypeError('max length is not a multiple of 4: %d' % (maxlen))
    retbuf = bytearray(maxlen)
    for i in range(0, maxlen, 4):
        retbuf[i:i+4] = getInt32(bytebuf, offset+i)
    return retbuf

def calcLoaderStructOffset(endmarkerOffset, loaderOffsets):
    structsiz = loaderOffsets['structSize']
    endmarkersiz = loaderOffsets['endMarkerSize']
    return endmarkerOffset + endmarkersiz - structsiz

# patches ptrToDLL, sizOfDLL
def patchLoader(bytebuf, loaderOffsets, endmarkerOffset, (dllVma, dllPtr, dllSiz)):
    buf = bytebuf
    if buf is None:
        return False
    structbase = calcLoaderStructOffset(endmarkerOffset, loaderOffsets)

    # loader: uint32_t ptrToDLL, uint32_t sizOfDLL
    setInt32(bytebuf, structbase + loaderOffsets['ptrToDLL'], dllVma)
    setInt32(bytebuf, structbase + loaderOffsets['sizOfDLL'], dllSiz)
    return True

# get loader iv/key or generate (and patch) it if user want so
def getXorKeyIv(bytebuf, loaderOffsets, endmarkerOffset, gen_func=None):
    buf = bytebuf
    if buf is None:
        return (None,None)
    structbase = calcLoaderStructOffset(endmarkerOffset, loaderOffsets)

    ldr_key = loaderOffsets['key[0]']
    ldr_iv = loaderOffsets['iv[0]']
    ldr_ivkeylen = loaderOffsets['ldrIvKeyLen']
    ldr_ivkeysiz = loaderOffsets['ldrIvKeySiz']

    keybuf = getInt32Buf(buf, structbase + ldr_key, ldr_ivkeylen*ldr_ivkeysiz)
    ivbuf = getInt32Buf(buf, structbase + ldr_iv, ldr_ivkeylen*ldr_ivkeysiz)
    keypatched = False
    ivpatched = False
    if keybuf == '\x00'*(ldr_ivkeylen*ldr_ivkeysiz) and gen_func is not None:
        setInt32Buf(buf, structbase + ldr_key, gen_func(ldr_ivkeylen))
        keybuf = getInt32Buf(buf, structbase + ldr_key, ldr_ivkeylen*ldr_ivkeysiz)
        keypatched = True
    if ivbuf == '\x00'*(ldr_ivkeylen*ldr_ivkeysiz) and gen_func is not None:
        setInt32Buf(buf, structbase + ldr_iv, gen_func(ldr_ivkeylen))
        ivbuf = getInt32Buf(buf, structbase + ldr_iv, ldr_ivkeylen*ldr_ivkeysiz)
        ivpatched = True
    return ( (keybuf, keypatched), (ivbuf, ivpatched) )

def isLoaderStringsEncrypted(bytebuf, loaderOffsets, endmarkerOffset, xorkey, xoriv, xor_npcbc_func=None):
    buf = bytebuf
    if buf is None:
        return False
    structbase = calcLoaderStructOffset(endmarkerOffset, loaderOffsets)

    (ldr_sVALen, ldr_sIBRPLen) = loaderOffsets['ldrStrLen'] # NULL-char included
    ldr_strivkeylen = loaderOffsets['ldrStrIvKeyLen']
    ldr_ivkeysiz = loaderOffsets['ldrIvKeySiz']

    abs_siz = ldr_strivkeylen*ldr_ivkeysiz
    key = xorkey[:abs_siz]
    iv = xoriv[:abs_siz]

    (ldr_sVALen, ldr_sIBRPLen) = loaderOffsets['ldrStrLen'] # NULL-char included
    idxVA = structbase + loaderOffsets['strVirtualAlloc[0]']
    idxIBRP = structbase + loaderOffsets['strIsBadReadPtr[0]']
    strVA = getInt32Buf(buf, idxVA, ldr_sVALen-1)
    strIBRP = getInt32Buf(buf, idxIBRP, ldr_sIBRPLen-1)

    retplain = bool(str(strVA).isalpha() is True and str(strIBRP).isalpha() is True)
    if retplain is True:
        retvalid = True
    else:
        decVA = getInt32Buf(xor_npcbc_func(strVA, key, iv), 0, ldr_sVALen-1)
        decIBRP = getInt32Buf(xor_npcbc_func(strIBRP, key, iv), 0, ldr_sIBRPLen-1)
        retvalid = bool(decVA.isalpha()) is True and bool(decIBRP.isalpha()) is True
    return (retplain, retvalid)

# patches (encrypt) loader strings
def patchLoaderStrings(bytebuf, loaderOffsets, endmarkerOffset, xorkey, xoriv, xor_npcbc_func=None):
    buf = bytebuf
    if buf is None or xor_npcbc_func is None:
        return False
    structbase = calcLoaderStructOffset(endmarkerOffset, loaderOffsets)

    (ldr_sVALen, ldr_sIBRPLen) = loaderOffsets['ldrStrLen'] # NULL-char included
    ldr_strivkeylen = loaderOffsets['ldrStrIvKeyLen']
    ldr_ivkeysiz = loaderOffsets['ldrIvKeySiz']

    abs_siz = ldr_strivkeylen*ldr_ivkeysiz
    key = xorkey[:abs_siz]
    iv = xoriv[:abs_siz]

    idxVA = structbase + loaderOffsets['strVirtualAlloc[0]']
    idxIBRP = structbase + loaderOffsets['strIsBadReadPtr[0]']
    strVA = getInt32Buf(buf, idxVA, ldr_sVALen-1)
    strIBRP = getInt32Buf(buf, idxIBRP, ldr_sIBRPLen-1)

    (cipherVA, cipherIBRP) = ( xor_npcbc_func(strVA, key, iv), xor_npcbc_func(strIBRP, key, iv) )
    if len(cipherVA) != ldr_sVALen -1 or len(cipherIBRP) != ldr_sIBRPLen -1:
        return False
    (plainVA, plainIBRP) = ( xor_npcbc_func(cipherVA, key, iv), xor_npcbc_func(cipherIBRP, key, iv) )
    if plainVA != strVA or plainIBRP != strIBRP:
        return False

    setInt32Buf(buf, idxVA, cipherVA)
    setInt32Buf(buf, idxIBRP, cipherIBRP)
    return True

def isDllHeaderEncrypted(buf, dllPtr):
    e_lfanew_OFFSET = 0x3C
    e_lfanew = struct.unpack("<L", buf[e_lfanew_OFFSET:e_lfanew_OFFSET+0x4])[0]
    if buf[dllPtr:dllPtr+0x2] != '\x4d\x5a' or e_lfanew < 0x40 or e_lfanew > 0x400:
        return (False, False)
    if len(buf) < e_lfanew+2:
        return (True, False)
    if buf[dllPtr+e_lfanew:dllPtr+e_lfanew+2] == '\x50\x45':
        return (True, False)
    return (True, True)

def patchEncryptDll(buf, dllPtr, dllSiz, xorkey, xoriv, xor_npcbc_func=None):
    if dllPtr+dllSiz < len(buf) or dllSiz % 8 != 0:
        return (False, False, False)
    hdrbuf = getInt32Buf(buf, dllPtr, dllSiz)
    cipherHeader = xor_npcbc_func(hdrbuf, xorkey, xoriv)
    if len(cipherHeader) != len(hdrbuf):
        return (True, False, False)
    plainHeader = xor_npcbc_func(cipherHeader, xorkey, xoriv)
    if len(cipherHeader) != len(plainHeader):
        return (True, True, False)
    if hdrbuf != plainHeader:
        return (True, True, False)
    setInt32Buf(buf, dllPtr, cipherHeader)
    return (True, True, True)


if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-q", "--quiet", action="store_false", dest="verbose", default=True, help="don't print status messages to stdout")
    parser.add_option("-o", "--objdump", dest="objdmp_bin", default=objdmp_bin, help="path to mingw objdump binary [default: %default]")
    parser.add_option("-f", "--out-file", dest="out_file", help="set output file [default: same as --win32]")
    parser.add_option("-l", "--pyload", dest="pyload", default=pyload_so, help="set "+pyload_name+" path [required, default: %default]")
    parser.add_option("-c", "--pycrypt", dest="pycrypt", default=pycrypt_so, help="set "+pycrypt_name+" path [required, default: %default]")
    bingrp = OptionGroup(parser, "Binary Options", None)
    bingrp.add_option("-w", "--win32", dest="win32_pe", help="path to windows pe binary which contains the loader [required]")
    bingrp.add_option("-b", "--binary", dest="miller_bin", help="patch loader with sections from miller dll")
    parser.add_option_group(bingrp)
    ldrgrp = OptionGroup(parser, "WIN32_PE Options", None)
    ldrgrp.add_option("-e", "--endmarker", dest="endmarker", help="set the loader endmarker value (4*n bytes)")
    ldrgrp.add_option("-s", "--ldr-section", dest="section", help="specify the loader section name [required]")
    ldrgrp.add_option("-t", "--dll-section", dest="target_section", help="psecify the dll section name")
    ldrgrp.add_option("-r", "--crypt-strings", action="store_true", dest="crypt_strings", help="encrypt loader strings")
    ldrgrp.add_option("-H", "--crypt-dll", action="store_true", dest="crypt_dll", help="encrypt dll pe header")
    parser.add_option_group(ldrgrp)
    actgrp = OptionGroup(parser, "Actions", None)
    actgrp.add_option("-a", "--show-address", action="store_true", dest="show_adr", help="shows section offset (if found) from the pe binary")
    actgrp.add_option("-z", "--show-size", action="store_true", dest="show_siz", help="shows section size (if found) from the pe binary")
    actgrp.add_option("-m", "--show-marker", action="store_true", dest="show_marker", help="shows the endmarker (offset)")
    actgrp.add_option("-k", "--show-xorkey", action="store_true", dest="show_xorkey", help="print XOR key to stdout")
    actgrp.add_option("-i", "--show-xoriv", action="store_true", dest="show_xoriv", help="print XOR iv to stdout")
    actgrp.add_option("-p", "--patch", action="store_true", dest="patch", default=False, help="patch the --section with address and size information from --target-section")
    parser.add_option_group(actgrp)
    (options, args) = parser.parse_args()

    bname = os.path.basename(sys.argv[0])
    # load *.so's if necessary
    pyload = require_pyso(pyload_name, options.pyload)
    # some commands need pycrypt module
    pycrypt = require_pyso(pycrypt_name, options.pycrypt)
    if pycrypt is None:
        sys.stderr.write(bname + ': Could not import '+pycrypt_name+': ' + options.pycrypt + '.\n')
        sys.exit(1)

    endmarker = None
    if pyload is None:
        sys.stderr.write(bname + ': WARNING: Could not import '+pyload_name+': ' + options.pyload + '.\n')
        if options.patch:
            sys.stderr.write(bname + ': Patching requires '+pyload_name+'\n')
            sys.exit(1)
    else:
        endmarker = pyload.getEndmarker()
        loaderdict = pyload.getStructOffset()

    # argument checks
    # pyloader python lib and endmarker
    if not options.endmarker and pyload is None:
        sys.stderr.write(bname + ': missing --endmarker and '+pyload_name+' ('+options.pyload+') not imported\n')
        sys.exit(1)
    elif not options.endmarker:
        sys.stderr.write(bname + ': using default endmarker 0x'+str(endmarker).encode('hex')+'\n')
    else:
        tmp = str(parse_c_array(options.endmarker))
        if endmarker is not None and tmp != endmarker:
            sys.stderr.write(bname + ': WARNING: LOADER_ENDMARKER is not equal --endmarker: '+str(endmarker).encode('hex')+' != '+str(tmp).encode('hex')+'\n')
            sys.stderr.write(bname + ': using '+str(tmp).encode('hex')+'\n')
        endmarker = tmp
        if len(endmarker) % 4 != 0:
            sys.stderr.write(bname + ': endmarker length MUST be a multiple of 4 and not ' + str(len(endmarker)) + '\n')
            sys.exit(1)
        if options.verbose:
            print bname + ': using 0x' + endmarker.encode('hex') + ' as endmarker'
    # win32_pe is required for all operations
    if options.win32_pe is None:
        sys.stderr.write(bname + ': WIN32_PE is required for all operations\n')
        parser.print_help()
        sys.exit(1)
    # same applies for section (TODO: Maybe discard section and search for endmarker in whole pe file)
    if options.section is None:
       sys.stderr.write(bname + ':  --win32 needs --section\n')
       parser.print_help()
       sys.exit(1)
    # target section is required (specifies the DLL section)
    if options.patch and options.target_section is None:
        sys.stderr.write(bname + ': --patch needs --target-section\n')
        parser.print_help()
        sys.exit(1)
    # patch win32_pe directly if possible
    if options.out_file is None:
        options.out_file = options.win32_pe

    for binary in [options.win32_pe, options.miller_bin]:
        if binary is not None:
            if not os.access(binary, os.R_OK):
                sys.stderr.write(bname + ': No read access ' + binary + '\n')
                sys.exit(2)

    if not(os.path.isfile(objdmp_bin) or os.access(objdmp_bin, os.X_OK)):
        sys.stderr.write(bname + ': objdump ('+objdmp_bin+') does not exist or is not executable\n')
        sys.exit(2)

    # read win32pe/miller_bin
    buf = None
    (ldrVma, ldrPtr, ldrSiz) = objdump_sections(options.win32_pe, options.section)
    if (ldrVma or ldrPtr or ldrSiz) is None:
        sys.stderr.write(bname + ': Error: Loader section missing or objdump binary does not work.\n')
        objdump_print_err(bname)
        sys.exit(3)
    # print section offset/size
    if options.verbose:
        print bname + (': found section %s in %s (RVA: 0x%08X | PTR: 0x%08X | SIZ: 0x%08X)' % (options.section, options.win32_pe, ldrVma, ldrPtr, ldrSiz))
    # load file to memory
    buf = file_to_buf(options.win32_pe)
    if buf is None:
        sys.stderr.write(bname + ': could not load file '+options.win32_pe+' into memory\n')
        sys.exit(3)
    # search loader endmarker
    endoff = find_endmarker_offset(endmarker, buf, ldrPtr, ldrSiz)
    if endoff == -1:
        sys.stderr.write(bname + ': endmarker(`'+endmarker.encode('hex')+'`) not found\n')
        sys.exit(3)
    if options.verbose:
        print bname + ': endmarker(`'+endmarker.encode('hex')+'`) found at '+str(endoff)+' ('+str(hex(endoff))+')'
    # -a, -z, -m
    if options.show_adr:
        print str(ldrPtr) if not options.verbose else str(bname) + ': '+options.section+' offset: '+str(ldrPtr)+' ('+str(hex(ldrPtr))+')'
    if options.show_siz:
        print str(ldrSiz) if not options.verbose else str(bname) + ': '+options.section+' size: '+str(ldrSiz)+' ('+str(hex(ldrSiz))+')'
    if options.show_marker:
        print str(endoff) if not options.verbose else str(bname) + ': '+options.section+' endmarker: '+str(endoff)+' ('+str(hex(endoff))+')'

    # parse dll and patch loader
    if options.win32_pe is not None:
        if options.target_section is None:
            sys.stderr.write(bname + ': Dumping data from target section requires --dll-section\n')
            sys.exit(3)
        (dllVma, dllPtr, dllSiz) = objdump_sections(options.win32_pe, options.target_section)
        if (dllVma or dllPTr or dllSiz) is None:
            sys.stderr.write(bname + ': Error: DLL (target)section missing or objdump binary does not work.\n')
            objdump_print_err(bname)
            sys.exit(3)
        if options.verbose:
            print bname + (': found section %s in %s (RVA: 0x%08X | PTR: 0x%08X | SIZ: 0x%08X)' % (options.target_section, options.win32_pe, dllVma, dllPtr, dllSiz))

    # let's encrypt
    if pycrypt is not None and options.win32_pe is not None and buf is not None:
        ((keybuf,keypatched), (ivbuf,ivpatched)) = getXorKeyIv(buf, loaderdict, endoff, pycrypt.xorRandomKeyIv)
        if options.verbose:
            print bname + ': ' + ('XOR(KEY) patched' if keypatched is True else 'XOR(KEY) !patched') + ', ' + ('XOR(IV) patched' if ivpatched is True else 'XOR(IV) !patched')
            print (bname + ': XOR(KEY,LEN): %s (%d bytes)\n' + bname + ': XOR(IV ,LEN): %s (%d bytes)') % (str(keybuf).encode('hex'), len(keybuf), str(ivbuf).encode('hex'), len(ivbuf))
        else:
            if options.show_xorkey:
                print str(keybuf).encode('hex')
            if options.show_xoriv:
                print str(ivbuf).encode('hex')

        # Loader string encryption
        if options.crypt_strings is True:
            (isPlain, isValid) = isLoaderStringsEncrypted(buf, loaderdict, endoff, keybuf, ivbuf, pycrypt.xorCrypt)
            if not isValid:
                sys.stderr.write(bname + ': XOR Loader Strings are not valid, wrong XOR key/iv?\n')
                sys.exit(4)
            if not isPlain:
                sys.stderr.write(bname + ': XOR Loader Strings already encrypted\n')
            elif patchLoaderStrings(buf, loaderdict, endoff, keybuf, ivbuf, pycrypt.xorCrypt) is not True:
                sys.stderr.write(bname + ': XOR Crypt Loader Strings failed\n')
                sys.exit(4)
            elif options.verbose:
                print bname + ': String encryption succeeded!'

        # PE binary encryption
        if options.crypt_dll is True:
            (validDOS, validPE) = isDllHeaderEncrypted(buf, dllPtr)
            if validDOS is not True or validPE is not True:
                sys.stderr.write(bname + ': Not a valid DOS/PE Header, already encrypted?\n')
            else:
                ret = patchEncryptDll(buf, dllPtr, dllSiz, keybuf, ivbuf, pycrypt.xorCrypt)
                if ret != (True, True, True):
                    sys.stderr.write(bname + ': PE encryption failed! Returned: %s\n' % (str(ret)))
                    sys.exit(4)
            if options.verbose:
                print bname + ': PE encryption done'

    # parse dll and patch loader
    if options.patch and pyload is not None and buf is not None:
        if options.verbose:
            print bname + (': Patching Loader with dll section (RVA: 0x%08X | PTR: 0x%08X | SIZ: 0x%08X)' % (dllVma,dllPtr,dllSiz))
        found = patchLoader(buf, loaderdict, endoff, (dllVma,dllPtr,dllSiz))
        if found:
            if not buf_to_file(options.out_file, buf):
                sys.stderr.write(bname + ': could not write buffer to disk\n')
                sys.exit(4)
            if options.verbose:
                print bname + ': Patching succeeded!'
        else:
            sys.stderr.write(bname + ': None found ..\n')
            sys.exit(4)

    sys.exit(0)
