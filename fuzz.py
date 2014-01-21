
from __future__ import print_function

import difflib,os,traceback
from random import randrange
from dnslib import *

packet = bytearray(binascii.unhexlify(b'd5ad818000010005000000000377777706676f6f676c6503636f6d0000010001c00c0005000100000005000803777777016cc010c02c0001000100000005000442f95b68c02c0001000100000005000442f95b63c02c0001000100000005000442f95b67c02c0001000100000005000442f95b93'))

def fuzz_delete(b):
    """ Delete byte """
    f = b[:]
    del f[randrange(len(b))]
    return f

def fuzz_add(b):
    """ Add byte """
    f = b[:]
    f.insert(randrange(len(b)),randrange(256))
    return f

def fuzz_change(b):
    """ Change byte """
    f = b[:]
    f[randrange(len(b))] = randrange(256)
    return f

def fname(f):
    try:
        return f.func_name
    except AttributeError:
        return f.__name__

uncaught = 0

def p(*args):
    if 'DEBUG' in os.environ:
        print(*args)

for f in (fuzz_delete,fuzz_add,fuzz_change):
    for i in range(100):
        p("! %s [%d]" % (fname(f),i))
        try:
            original = DNSRecord.parse(packet)
            fuzzed = DNSRecord.parse(f(packet))
            diff = difflib.unified_diff(original.records(),fuzzed.records(),n=0)
            diff = [ l for l in diff if l[0] in ['-','+'] and l[1] == '<']
            if diff:
                p("  " + "\n  ".join(diff))
        except DNSError as e:
            print("  >>> " + str(e))
        except Exception as e:
            uncaught += 1
            print(traceback.format_exc())

print("Uncaught Exceptions: %d" % uncaught)

