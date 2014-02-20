# -*- coding: utf-8 -*-

from __future__ import print_function

import copy

from dnslib import RR,QTYPE
from dnslib.server import DNSServer,BaseResolver

class ZoneResolver(BaseResolver):
    """
        Simple fixed zone file resolver.
    """

    def __init__(self,zone,glob=False):
        """
            Initialise resolver from zone file. 
            Stores RRs as a list of (label,type,rr) tuples
            If 'glob' is True use glob match against zone file 
        """
        self.zone = [(rr.rname,QTYPE[rr.rtype],rr) for rr in RR.fromZone(zone)]
        self.glob = glob
        self.eq = 'matchGlob' if glob else '__eq__'

    def resolve(self,request,handler):
        """
            Respond to DNS request - parameters are request packet & handler.
            Method is expected to return DNS response
        """
        self.log_request(request,handler)
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        for name,rtype,rr in self.zone:
            if getattr(qname,self.eq)(name) and (qtype == rtype or 
                                                 qtype == 'ANY' or 
                                                 rtype == 'CNAME'):
                # If we have a glob match fix reply label
                if self.glob:
                    a = copy.copy(rr)
                    a.rname = qname
                    reply.add_answer(a)
                else:
                    reply.add_answer(rr)
                # Check for A/AAAA records associated with reply and
                # add in additional section
                if rtype in ['CNAME','NS','MX','PTR']:
                    for a_name,a_rtype,a_rr in self.zone:
                        if a_name == rr.rdata.label and a_rtype in ['A','AAAA']:
                            reply.add_ar(a_rr)
        self.log_reply(reply,handler)
        return reply

if __name__ == '__main__':

    import argparse,sys,time

    p = argparse.ArgumentParser(description="Zone DNS Resolver")
    p.add_argument("--zone","-z",required=True,
                        metavar="<zone-file>",
                        help="Zone file ('-' for stdin)")
    p.add_argument("--port","-p",type=int,default=53,
                        metavar="<port>",
                        help="Server port (default:53)")
    p.add_argument("--address","-a",default="",
                        metavar="<address>",
                        help="Listen address (default:all)")
    p.add_argument("--glob",action='store_true',default=False,
                        help="Glob match against zone file (default: false)")
    p.add_argument("--tcp",action='store_true',default=False,
                        help="TCP server (default: UDP only)")
    args = p.parse_args()
    
    if args.zone == '-':
        args.zone = sys.stdin
    else:
        args.zone = open(args.zone)

    resolver = ZoneResolver(args.zone,args.glob)

    print("Starting Zone Resolver (%s:%d) [%s]" % (
                        args.address or "*",
                        args.port,
                        "UDP/TCP" if args.tcp else "UDP"))

    for rr in resolver.zone:
        print("    | ",rr[2].toZone(),sep="")
    print()

    udp_server = DNSServer(resolver,port=args.port,address=args.address)
    udp_server.start_thread()

    if args.tcp:
        tcp_server = DNSServer(resolver,port=args.port,address=args.address,
                                        tcp=True)
        tcp_server.start_thread()

    while udp_server.isAlive():
        time.sleep(1)

