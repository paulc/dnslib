# -*- coding: utf-8 -*-

"""
    InterceptResolver - proxy requests to upstream server
                        (optionally intercepting)

"""
from __future__ import print_function

import binascii,copy,socket,struct,sys

from dnslib import DNSRecord,RR,QTYPE,RCODE,parse_time
from dnslib.server import DNSServer,DNSHandler,BaseResolver,DNSLogger
from dnslib.label import DNSLabel

class InterceptResolver(BaseResolver):

    """
        Intercepting resolver

        Proxy requests to upstream server optionally intercepting requests
        matching local records
    """

    def __init__(self,address,port,ttl,intercept,skip,nxdomain,forward,all_qtypes,timeout=0):
        """
            address/port    - upstream server
            ttl             - default ttl for intercept records
            intercept       - list of wildcard RRs to respond to (zone format)
            skip            - list of wildcard labels to skip
            nxdomain        - list of wildcard labels to return NXDOMAIN
            forward         - list of wildcard labels to forward
            all_qtypes      - intercept all qtypes if qname matches.
            timeout         - timeout for upstream server(s)
        """
        self.address = address
        self.port = port
        self.ttl = parse_time(ttl)
        self.skip = skip
        self.nxdomain = nxdomain
        self.forward = []
        for i in forward:
            qname, _, upstream = i.partition(':')
            upstream_ip, _, upstream_port = upstream.partition(':')
            self.forward.append((qname, upstream_ip, int(upstream_port or '53')))
        self.all_qtypes = all_qtypes
        self.timeout = timeout
        self.zone = []
        for i in intercept:
            if i == '-':
                i = sys.stdin.read()
            for rr in RR.fromZone(i,ttl=self.ttl):
                self.zone.append((rr.rname,QTYPE[rr.rtype],rr))

    def resolve(self,request,handler):
        matched = False
        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        # Try to resolve locally unless on skip list
        if not any([qname.matchGlob(s) for s in self.skip]):
            for name,rtype,rr in self.zone:
                if qname.matchGlob(name):
                    if qtype in (rtype,'ANY','CNAME'):
                        a = copy.copy(rr)
                        a.rname = qname
                        reply.add_answer(a)
                    matched = True
        # Check for NXDOMAIN
        if any([qname.matchGlob(s) for s in self.nxdomain]):
            reply.header.rcode = getattr(RCODE,'NXDOMAIN')
            return reply
        if matched and self.all_qtypes:
            return reply
        # Otherwise proxy, first checking forwards, then to upstream.
        upstream, upstream_port = self.address,self.port
        if not any([qname.matchGlob(s) for s in self.skip]):
            for name, ip, port in self.forward:
                if qname.matchGlob(name):
                    upstream, upstream_port = ip, port
        if not reply.rr:
            try:
                if handler.protocol == 'udp':
                    proxy_r = request.send(upstream,upstream_port,
                                    timeout=self.timeout)
                else:
                    proxy_r = request.send(upstream,upstream_port,
                                    tcp=True,timeout=self.timeout)
                reply = DNSRecord.parse(proxy_r)
            except socket.timeout:
                reply.header.rcode = getattr(RCODE,'SERVFAIL')

        return reply

if __name__ == '__main__':

    import argparse,sys,time

    p = argparse.ArgumentParser(description="DNS Intercept Proxy")
    p.add_argument("--port","-p",type=int,default=53,
                    metavar="<port>",
                    help="Local proxy port (default:53)")
    p.add_argument("--address","-a",default="",
                    metavar="<address>",
                    help="Local proxy listen address (default:all)")
    p.add_argument("--upstream","-u",default="8.8.8.8:53",
            metavar="<dns server:port>",
                    help="Upstream DNS server:port (default:8.8.8.8:53)")
    p.add_argument("--tcp",action='store_true',default=False,
                    help="TCP proxy (default: UDP only)")
    p.add_argument("--intercept","-i",action="append",
                    metavar="<zone record>",
                    help="Intercept requests matching zone record (glob) ('-' for stdin)")
    p.add_argument("--skip","-s",action="append",
                    metavar="<label>",
                    help="Don't intercept matching label (glob)")
    p.add_argument("--nxdomain","-x",action="append",
                    metavar="<label>",
                    help="Return NXDOMAIN (glob)")
    p.add_argument("--forward","-f",action="append",
                   metavar="<label:dns server:port>",
                   help="forward requests matching label (glob) to dns server")
    p.add_argument("--ttl","-t",default="60s",
                    metavar="<ttl>",
                    help="Intercept TTL (default: 60s)")
    p.add_argument("--timeout","-o",type=float,default=5,
                    metavar="<timeout>",
                    help="Upstream timeout (default: 5s)")
    p.add_argument("--all-qtypes",action='store_true',default=False,
                   help="Return an empty response if qname matches, but qtype doesn't")
    p.add_argument("--log",default="request,reply,truncated,error",
                    help="Log hooks to enable (default: +request,+reply,+truncated,+error,-recv,-send,-data)")
    p.add_argument("--log-prefix",action='store_true',default=False,
                    help="Log prefix (timestamp/handler/resolver) (default: False)")
    args = p.parse_args()

    args.dns,_,args.dns_port = args.upstream.partition(':')
    args.dns_port = int(args.dns_port or 53)

    resolver = InterceptResolver(args.dns,
                                 args.dns_port,
                                 args.ttl,
                                 args.intercept or [],
                                 args.skip or [],
                                 args.nxdomain or [],
                                 args.forward or [],
                                 args.all_qtypes,
                                 args.timeout)
    logger = DNSLogger(args.log,args.log_prefix)

    print("Starting Intercept Proxy (%s:%d -> %s:%d) [%s]" % (
                        args.address or "*",args.port,
                        args.dns,args.dns_port,
                        "UDP/TCP" if args.tcp else "UDP"))

    for rr in resolver.zone:
        print("    | ",rr[2].toZone(),sep="")
    if resolver.nxdomain:
        print("    NXDOMAIN:",", ".join(resolver.nxdomain))
    if resolver.skip:
        print("    Skipping:",", ".join(resolver.skip))
    if resolver.forward:
        print("    Forwarding:")
        for i in resolver.forward:
            print("    | ","%s:%s:%s" % i,sep="")
    print()


    DNSHandler.log = {
        'log_request',      # DNS Request
        'log_reply',        # DNS Response
        'log_truncated',    # Truncated
        'log_error',        # Decoding error
    }

    udp_server = DNSServer(resolver,
                           port=args.port,
                           address=args.address,
                           logger=logger)
    udp_server.start_thread()

    if args.tcp:
        tcp_server = DNSServer(resolver,
                               port=args.port,
                               address=args.address,
                               tcp=True,
                               logger=logger)
        tcp_server.start_thread()

    while udp_server.isAlive():
        time.sleep(1)

