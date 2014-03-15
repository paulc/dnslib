# -*- coding: utf-8 -*-

from __future__ import print_function

try:
    from subprocess import getoutput
except ImportError:
    from commands import getoutput

import code,pprint

from dnslib import DNSRecord,DNSQuestion,QTYPE,DigParser

if __name__ == '__main__':

    import argparse,sys,time

    p = argparse.ArgumentParser(description="DNS Client")
    p.add_argument("--address","-a",default="8.8.8.8",
                    metavar="<address>",
                    help="Server address (default:8.8.8.8)")
    p.add_argument("--port","-p",type=int,default=53,
                    metavar="<port>",
                    help="Server port (default:53)")
    p.add_argument("--query",action='store_true',default=False,
                    help="Show query (default: False)")
    p.add_argument("--tcp",action='store_true',default=False,
                    help="TCP (default: UDP)")
    p.add_argument("--dig",action='store_true',default=False,
                    help="Run query with DiG and compare result (default: false)")
    p.add_argument("--debug",action='store_true',default=False,
                    help="Drop into CLI after request (default: false)")
    p.add_argument("domain",metavar="<domain>",
                    help="Query domain")
    p.add_argument("qtype",metavar="<type>",default="A",nargs="?",
                    help="Query type (default: A)")
    args = p.parse_args()

    q = DNSRecord(q=DNSQuestion(args.domain,getattr(QTYPE,args.qtype)))
    if args.query:
        print(";; Sending:\n")
        print(q)
        print()
    a = q.send(args.address,args.port)
    if a.header.tc:
        print(";; Truncated - trying TCP:\n")
        a = q.send(args.address,args.port,tcp=True)
    if args.dig:
        dig = getoutput("dig +qr -p %d %s %s @%s" % (
                            args.port, args.domain, args.qtype, args.address))
        dig_reply = list(iter(DigParser(dig)))
        # DiG might have retried in TCP mode so get last q/a
        q_dig = dig_reply[-2]
        a_dig = dig_reply[-1]
        if q != q_dig:
            print(">>> ERROR: Question differs")
            pprint.pprint(q.diff(q_dig))
        if a != a_dig:
            print(">>> ERROR: Response differs")
            pprint.pprint(a.diff(a_dig))
        else:
            print(";; Got answer:")
            print(a)
            print()
    else:
        print(";; Got answer:")
        print(a)
        print()

    if args.debug:
        code.interact(local=locals())
