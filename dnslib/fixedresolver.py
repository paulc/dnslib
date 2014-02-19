# -*- coding: utf-8 -*-

from __future__ import print_function

import copy

from dnslib import RR
from dnslib.server import DNSServer,BaseResolver

class FixedResolver(BaseResolver):
    """
        Respond with fixed response to all requests
    """
    def __init__(self,zone):
        self.rrs = RR.fromZone(zone)

    def resolve(self,request,handler):
        self.log_request(request,handler)
        reply = request.reply()
        qname = request.q.qname
        # Replace labels with request label
        for rr in self.rrs:
            a = copy.copy(rr)
            a.rname = qname
            reply.add_answer(a)
        self.log_reply(reply,handler)
        return reply

if __name__ == '__main__':

    import argparse,sys,time

    p = argparse.ArgumentParser(description="Fixed DNS Resolver")
    p.add_argument("--response","-r",default=". 60 IN A 127.0.0.1",
                    metavar="<response>",
                    help="DNS response (zone format) (default: 127.0.0.1)")
    p.add_argument("--zonefile","-f",
                    metavar="<zonefile>",
                    help="DNS response (zone file, '-' for stdin)")
    p.add_argument("--port","-p",type=int,default=53,
                    metavar="<port>",
                    help="Server port (default:53)")
    p.add_argument("--address","-a",default="",
                    metavar="<address>",
                    help="Listen address (default:all)")
    p.add_argument("--tcp",action='store_true',default=False,
                    help="TCP server (default: UDP only)")
    args = p.parse_args()
    
    if args.zonefile:
        if args.zonefile == '-':
            args.response = sys.stdin
        else:
            args.response = open(args.zonefile)

    resolver = FixedResolver(args.response)

    print("Starting Fixed Resolver (%s:%d) [%s]" % (
                        args.address or "*",
                        args.port,
                        "UDP/TCP" if args.tcp else "UDP"))

    for rr in resolver.rrs:
        print("    | ",rr.toZone().strip(),sep="")
    print()

    udp_server = DNSServer(resolver,port=args.port,address=args.address)
    udp_server.start_thread()

    if args.tcp:
        tcp_server = DNSServer(resolver,port=args.port,address=args.address,
                                        tcp=True)
        tcp_server.start_thread()

    while udp_server.isAlive():
        time.sleep(1)

