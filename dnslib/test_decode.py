#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
    Test dnslib packet encoding/decoding

    Reads test files from dnslib/test (by default) containing
    dump of DNS exchange (packet dump & parse output) and test
    round-trip parsing - specifically:

        - Parse packet data and zone format data and compare
        - Repack parsed packet data and compare with original

    This should test the 'parse', 'fromZone' and 'pack' methods of the
    associated record types.

    The original parsed output is created using dnslib by default so systematic
    encode/decode errors will not be found. By default the test data is
    checked against 'dig' to ensure that it is correct when generated
    using the --new option.

    By default the module runs in 'unittest' mode (and supports unittest
    --verbose/--failfast options)

    The module can also be run in interactive mode (--interactive) and inspect
    failed tests (--debug)

    New test data files can be automatically created using the:

        --new <domain> <type>

    option. The data is checked against dig output and an error raised if
    this does not match. This is effectively the same as running:

        python -m dnslib.client --query --hex --dig <domain> <type>

    It is possible to manually generate test data files using dnslib.client
    even if the dig data doesn't match (this is usually due to an unsupported
    RDATA type which dnslib will output in hex rather then parsing contents).
    The roundtrip tests will still work in this case (the unknown RDATA is
    handled as an opaque blob).

    In some cases the tests will fail as a result of the zone file parser
    being more fragile than the packet parser (especially with broken data)

    Note - unittests are dynamically generated from the test directory contents
    (matched against the --glob parameter)

"""

from __future__ import print_function

from dnslib.dns import DNSRecord,DNSBuffer,DNSError,EDNS0,RR,RD,A
from dnslib.digparser import DigParser

import argparse,binascii,code,glob,os,os.path,struct,sys,unittest

try:
    from subprocess import getoutput
except ImportError:
    from commands import getoutput

try:
    input = raw_input
except NameError:
    pass

class TestContainer(unittest.TestCase):
    pass

class TestUpdate(unittest.TestCase):

    def packet(self,section="auth",rclass=255,rtype=1,ttl=0,opcode=5,
               rdata=b""):
        # RFC 2136: question = zone, answer = prerequisite, authority = update.
        header = struct.pack("!HHHHHH",1,opcode << 11,1,
                             int(section == "rr"),int(section == "auth"),
                             int(section == "ar"))
        zone = b"\x07example\x03com\x00\x00\x06\x00\x01"
        rr = b"\x03foo\xc0\x0c" + struct.pack("!HHIH",rtype,rclass,ttl,
                                               len(rdata)) + rdata
        return header + zone + rr

    def check_empty(self,packet,section,rtype,rclass):
        record = DNSRecord.parse(packet)
        rr = getattr(record,section)[0]
        self.assertEqual((rr.rtype,rr.rclass,rr.ttl),(rtype,rclass,0))
        self.assertEqual(type(rr.rdata),RD)
        self.assertEqual(rr.rdata.data,b"")
        self.assertEqual(rr.rdata.toZone(),"\\# 0")
        self.assertIn("\\# 0",str(record))
        self.assertIn("\\# 0",repr(record))
        self.assertEqual(record.pack(),packet)
        self.assertEqual(DNSRecord.parse(record.pack()),record)

    def test_delete_rrset(self):
        # Captured from BIND nsupdate: update delete foo.example.com. A
        packet = binascii.unhexlify(
            b"ab1b28000001000000010000076578616d706c6503636f6d0000060001"
            b"03666f6fc00c000100ff000000000000")
        self.check_empty(packet,"auth",1,255)

    def test_delete_name(self):
        # Captured from BIND nsupdate: update delete foo.example.com.
        packet = binascii.unhexlify(
            b"c93228000001000000010000076578616d706c6503636f6d0000060001"
            b"03666f6fc00c00ff00ff000000000000")
        self.check_empty(packet,"auth",255,255)

    def test_empty_prerequisites(self):
        # RRset/name exists (ANY) and does not exist (NONE).
        for rclass in (254,255):
            for rtype in (1,255):
                packet = self.packet(section="rr",rclass=rclass,rtype=rtype)
                self.check_empty(packet,"rr",rtype,rclass)

    def test_empty_records_rejected_outside_update(self):
        for opcode in (0,4):
            for section in ("rr","auth","ar"):
                for rclass in (1,254,255):
                    with self.assertRaises(DNSError):
                        DNSRecord.parse(self.packet(section=section,
                                            rclass=rclass,opcode=opcode))

    def test_invalid_empty_update_records(self):
        for section,rclass,ttl in (("rr",1,0),("auth",1,0),
                                  ("rr",3,0),("auth",3,0),("ar",1,0),
                                  ("auth",254,0),("ar",255,0),
                                  ("ar",254,0),("rr",255,1),
                                  ("rr",254,1),("auth",255,1)):
            with self.assertRaises(DNSError):
                DNSRecord.parse(self.packet(section=section,
                                            rclass=rclass,ttl=ttl))

    def test_standalone_rr_rejects_empty_data(self):
        # Without message context RR.parse must retain its default behavior.
        buffer = DNSBuffer(b"\x00" + struct.pack("!HHIH",1,255,0,0))
        with self.assertRaises(DNSError):
            RR.parse(buffer)

    def test_nonempty_update_records(self):
        # Addition, deletion of one RR, and value-dependent prerequisite.
        for section,rclass,ttl in (("auth",1,60),("auth",254,0),("rr",1,0)):
            packet = self.packet(section=section,rclass=rclass,ttl=ttl,
                                 rdata=b"\x7f\x00\x00\x01")
            record = DNSRecord.parse(packet)
            self.assertEqual(getattr(record,section)[0].rdata,A("127.0.0.1"))
            self.assertEqual(record.pack(),packet)

    def test_mixed_update_records(self):
        # Empty markers must not consume following RRs or affect EDNS parsing.
        record = DNSRecord.parse(self.packet(section="rr",rclass=254))
        record.add_auth(RR("foo.example.com",rtype=28,rclass=255,rdata=RD()),
                        RR("foo.example.com",rdata=A("127.0.0.1"),ttl=60))
        record.add_ar(EDNS0(udp_len=1232))
        packet = record.pack()
        parsed = DNSRecord.parse(packet)
        self.assertEqual(parsed,record)
        self.assertEqual(parsed.auth[1].rdata,A("127.0.0.1"))
        self.assertEqual(parsed.ar[0].rdata,[])
        self.assertEqual(parsed.pack(),packet)

    def test_truncated_update_records(self):
        for section in ("rr","auth"):
            packet = self.packet(section=section)
            for length in range(len(packet)):
                with self.assertRaises(DNSError):
                    DNSRecord.parse(packet[:length])

def new_test(domain,qtype,address="8.8.8.8",port=53,nodig=False,dnssec=False):
    tcp = False
    q = DNSRecord.question(domain,qtype)
    if dnssec:
        q.add_ar(EDNS0(flags="do",udp_len=4096))
        q.header.ad = 1
    a_pkt = q.send(address,port)
    a = DNSRecord.parse(a_pkt)
    if a.header.tc:
        tcp = True
        a_pkt = q.send(address,port,tcp)
        a = DNSRecord.parse(a_pkt)

    if not nodig:
        if dnssec:
            dig = getoutput("dig +qr +dnssec -p %d %s %s @%s" % (
                            port, domain, qtype, address))
        else:
            dig = getoutput("dig +qr +noedns +noadflag -p %d %s %s @%s" % (
                            port, domain, qtype, address))
        dig_reply = list(iter(DigParser(dig)))
        # DiG might have retried in TCP mode so get last q/a
        q_dig = dig_reply[-2]
        a_dig = dig_reply[-1]

        if q != q_dig or a != a_dig:
            if q != q_dig:
                print(";;; ERROR: Diff Question differs")
                for (d1,d2) in q.diff(q_dig):
                    if d1:
                        print(";; - %s" % d1)
                    if d2:
                        print(";; + %s" % d2)
            if a != a_dig:
                print(";;; ERROR: Diff Response differs")
                for (d1,d2) in a.diff(a_dig):
                    if d1:
                        print(";; - %s" % d1)
                    if d2:
                        print(";; + %s" % d2)
            return

    if dnssec:
        fname = "%s-%s-dnssec" % (domain,qtype)
    else:
        fname = "%s-%s" % (domain,qtype)
    print("Writing test file: %s" % (fname))
    with open(fname,"w") as f:
        print(";; Sending:",file=f)
        print(";; QUERY:",binascii.hexlify(q.pack()).decode(),file=f)
        print(q,file=f)
        print(file=f)
        print(";; Got answer:",file=f)
        print(";; RESPONSE:",binascii.hexlify(a_pkt).decode(),file=f)
        print(a,file=f)
        print(file=f)

def check_decode(f,debug=False):
    errors = []

    # Parse the q/a records
    with open(f) as x:
        q,r = DigParser(x)

    # Grab the hex data
    with open(f,'rb') as x:
        for l in x.readlines():
            if l.startswith(b';; QUERY:'):
                qdata = binascii.unhexlify(l.split()[-1])
            elif l.startswith(b';; RESPONSE:'):
                rdata = binascii.unhexlify(l.split()[-1])

    # Parse the hex data
    qparse = DNSRecord.parse(qdata)
    rparse = DNSRecord.parse(rdata)

    # Check records generated from DiG input matches
    # records parsed from packet data
    if q != qparse:
        errors.append(('Question',q.diff(qparse)))
    if r != rparse:
        errors.append(('Reply',r.diff(rparse)))

    # Repack the data
    qpack = qparse.pack()
    rpack = rparse.pack()

    # Check if repacked question data matches original
    # We occasionally get issues where original packet did not
    # compress all labels - in this case we reparse packed
    # record, repack this and compare with the packed data
    if qpack != qdata:
        if len(qpack) < len(qdata):
            # Shorter - possibly compression difference
            if DNSRecord.parse(qpack).pack() != qpack:
                errors.append(('Question Pack',(qdata,qpack)))
        else:
            errors.append(('Question Pack',(qdata,qpack)))
    if rpack != rdata:
        if len(rpack) < len(rdata):
            if DNSRecord.parse(rpack).pack() != rpack:
                errors.append(('Reply Pack',(rdata,rpack)))
        else:
            errors.append(('Reply Pack',(rdata,rpack)))

    if debug:
        if errors:
            print("ERROR\n")
            print_errors(errors)
            print()
            if input(">>> Inspect [y/n]? ").lower().startswith('y'):
                code.interact(local=locals())
            print()
        else:
            print("OK")

    return errors

def print_errors(errors):
    for err,err_data in errors:
        if err == 'Question':
            print("Question error:")
            for (d1,d2) in err_data:
                if d1:
                    print(";; - %s" % d1)
                if d2:
                    print(";; + %s" % d2)
        elif err == 'Reply':
            print("Reply error:")
            for (d1,d2) in err_data:
                if d1:
                    print(";; - %s" % d1)
                if d2:
                    print(";; + %s" % d2)
        elif err == 'Question Pack':
            print("Question pack error")
            print("QDATA:",binascii.hexlify(err_data[0]))
            print(DNSRecord.parse(err_data[0]))
            print("QPACK:",binascii.hexlify(err_data[1]))
            print(DNSRecord.parse(err_data[1]))
        elif err == 'Reply Pack':
            print("Response pack error")
            print("RDATA:",binascii.hexlify(err_data[0]))
            print(DNSRecord.parse(err_data[0]))
            print("RPACK:",binascii.hexlify(err_data[1]))
            print(DNSRecord.parse(err_data[1]))

def test_generator(f):
    def test(self):
        self.assertEqual(check_decode(f),[])
    return test

if __name__ == '__main__':

    testdir = os.path.join(os.path.dirname(__file__),"test")

    p = argparse.ArgumentParser(description="Test Decode")
    p.add_argument("--new","-n",nargs=2,
                    metavar="<domain/type>",
                    help="Create new test case (args: <domain> <type>)")
    p.add_argument("--dnssec",action='store_true',default=False,
                    help="With --new send DNSSEC request (DO)")
    p.add_argument("--nodig",action='store_true',default=False,
                    help="Don't test new data against DiG")
    p.add_argument("--unittest",action='store_true',default=True,
                    help="Run unit tests")
    p.add_argument("--verbose",action='store_true',default=False,
                    help="Verbose unit test output")
    p.add_argument("--failfast",action='store_true',default=False,
                    help="Stop unit tests on first failure")
    p.add_argument("--interactive",action='store_true',default=False,
                    help="Run in interactive mode")
    p.add_argument("--debug",action='store_true',default=False,
                    help="Debug errors (interactive mode)")
    p.add_argument("--glob","-g",default="*",
                    help="Glob pattern")
    p.add_argument("--testdir","-t",default=testdir,
                    help="Test dir (%s)" % testdir)
    p.add_argument("--testfile","-f",default=None,
                    help="Test single file")
    args = p.parse_args()

    if args.testfile:
        e = check_decode(args.testfile,args.debug)
        if not args.debug:
            if e:
                print("ERROR\n")
                print_errors(e)
                print()
            else:
                print("OK")
    else:
        os.chdir(args.testdir)
        if args.new:
            new_test(*args.new,nodig=args.nodig,dnssec=args.dnssec)
        elif args.interactive:
            for f in glob.iglob(args.glob):
                if os.path.isfile(f):
                    print("-- %s: " % f,end='')
                    e = check_decode(f,args.debug)
                    if not args.debug:
                        if e:
                            print("ERROR\n")
                            print_errors(e)
                            print()
                        else:
                            print("OK")
        elif args.unittest:
            for f in glob.iglob(args.glob):
                if os.path.isfile(f):
                    test_name = 'test_%s' % f
                    test = test_generator(f)
                    setattr(TestContainer,test_name,test)
            unittest.main(argv=[__name__],
                          verbosity=2 if args.verbose else 1,
                          failfast=args.failfast)



