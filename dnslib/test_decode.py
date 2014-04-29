# -*- coding: utf-8 -*-

from __future__ import print_function

from dnslib.dns import DNSRecord
from dnslib.digparser import DigParser

import argparse,binascii,code,glob,os,os.path

try: 
    input = raw_input
except NameError: 
    pass

def new_test(domain,qtype,address="8.8.8.8",port=53):
    tcp = False
    q = DNSRecord.question(domain,qtype)
    a_pkt = q.send(address,port)
    a = DNSRecord.parse(a_pkt)
    if a.header.tc:
        tcp = True
        a_pkt = q.send(address,port,tcp)
        a = DNSRecord.parse(a_pkt)

    print("Writing test file: %s-%s" % (domain,qtype))
    f = open("%s-%s" % (domain,qtype),"w")

    print(";; Sending:",file=f)
    print(";; QUERY:",binascii.hexlify(q.pack()).decode(),file=f)
    print(q,file=f)
    print(file=f)
    print(";; Got answer:",file=f)
    print(";; RESPONSE:",binascii.hexlify(a_pkt).decode(),file=f)
    print(a,file=f)
    print(file=f)

    f.close()

if __name__ == '__main__':

    testdir = os.path.join(os.path.dirname(__file__),"test")

    p = argparse.ArgumentParser(description="Test Decode")
    p.add_argument("--new","-n",nargs=2,
                    help="New test <domain> <type>")
    p.add_argument("--glob","-g",default="*",
                    help="Glob pattern")
    p.add_argument("--testdir","-t",default=testdir,
                    help="Test dir (%s)" % testdir)
    p.add_argument("--debug",action='store_true',default=False,
                    help="Debug (DiG parser)")
    args = p.parse_args()

    os.chdir(args.testdir)

    if args.new:
        new_test(*args.new)
    else:
        for f in glob.iglob(args.glob):
            errors = 0
            print("\n",f,"\n","-"*len(f),sep='')
            # Parse the q/a records
            q,r = DigParser(open(f),args.debug)
            # Grab the hex data
            for l in open(f,'rb').readlines():
                if l.startswith(b';; QUERY:'):
                    qdata = binascii.unhexlify(l.split()[-1])
                elif l.startswith(b';; RESPONSE:'):
                    rdata = binascii.unhexlify(l.split()[-1])
            qparse = DNSRecord.parse(qdata)
            rparse = DNSRecord.parse(rdata)
            qpack = qparse.pack()
            rpack = rparse.pack()

            # Check records generated from DiG input matches
            # records parsed from packet data
            if q != qparse:
                errors += 1
                print("Question error:")
                for (d1,d2) in q.diff(qparse):
                    if d1:
                        print(";; - %s" % d1)
                    if d2:
                        print(";; + %s" % d2)
            if r != rparse:
                errors += 1
                print("Reply error:")
                for (d1,d2) in r.diff(rparse):
                    if d1:
                        print(";; - %s" % d1)
                    if d2:
                        print(";; + %s" % d2)

            # Check if repacked question data matches original 
            # We occasionally get issues where original packet did not 
            # compress all labels - in this case we reparse packed
            # record, repack this and compare with the packed data
            if qpack != qdata and DNSRecord.parse(qpack).pack() != qpack:
                errors += 1
                print("Question repack error")
                print("QDATA:",binascii.hexlify(qdata))
                print(qparse)
                print("QPACK:",binascii.hexlify(qpack))
                print(DNSRecord.parse(qpack))
            # Same for reply
            if rpack != rdata and DNSRecord.parse(rpack).pack() != rpack:
                errors += 1
                print("Response repack error")
                print("RDATA:",binascii.hexlify(rdata))
                print(rparse)
                print("RPACK:",binascii.hexlify(rpack))
                print(DNSRecord.parse(rpack))

            if errors == 0:
                print("OK")
            elif input("Inspect [y/n]?").lower().startswith('y'):
                code.interact(local=locals())


