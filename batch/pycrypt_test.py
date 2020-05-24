#!/usr/bin/env python2.7

import binascii, imp, time, sys, os.path


m = imp.load_dynamic('pycrypt',os.path.dirname(sys.argv[0])+'/../bin/pycrypt')
m.info()

def check_str(d, p):
    if str(d).find(str(p)) != 0 and len(d) != len(p):
        sys.stderr.write('ERROR: "' + str(d) + '" != "' + str(p) + '"\n')
        sys.stderr.write('        ' + str(len(d)) + ' , ' + str(len(p)) + ' , ' + str(len(binascii.hexlify(d))) + ' , ' + str(len(binascii.hexlify(p))) + '\n')
        sys.stderr.write('       "' + binascii.hexlify(d) + '"\n')
        sys.stderr.write('       "' + binascii.hexlify(p) + '"\n')

count = int(sys.argv[1]) if len(sys.argv) > 1 else -1
while count != 0:
    k = m.aesRandomKey(m.KEY_256)
    print 'AESKey:', binascii.hexlify(k)

    p = 'Top Secret Message!' + str('#'*0)

    x = m.aesAllocCtx(k)
    print 'AESCtx:', binascii.hexlify(x)

    c = m.aesCrypt(x, p, True)
    print 'AESMsg:', binascii.hexlify(c), '(%d)' % (len(c))

    d = m.aesCrypt(x, c, False)
    print 'OrgMsg:', binascii.hexlify(d), binascii.hexlify(p)
    print '       ', str(d), '(%d)' % (len(d))

    check_str(d,p)

    xork = m.xorRandomKeyIv(8)
    xori = m.xorRandomKeyIv(8)
    print 'XorKey:', binascii.hexlify(xork)
    print 'XorIv.:', binascii.hexlify(xori)

    c = m.xorCrypt(p, xork, xori)
    print 'XorMsg:', binascii.hexlify(c), '(%d)' % (len(c))

    d = m.xorCrypt(c, xork, xori)
    print 'OrgMsg:', binascii.hexlify(d)
    print '       ', str(d), '(%d)' % (len(d))

    check_str(d,p)

    time.sleep(0.01)

    if count > 0:
        count -= 1
