# -*- coding: utf-8 -*-

from __future__ import print_function

try:
    from subprocess import getoutput
except ImportError:
    from commands import getoutput

from dnslib import RR,QTYPE,TXT
from dnslib.label import DNSLabel
from dnslib.server import DNSServer,BaseResolver
from dnslib.zone import parse_time

class ShellResolver(BaseResolver):
    """
        Example dynamic resolver. 
        Maps DNS labels to shell commands and returns result as TXT record
    """
    def __init__(self,routes,origin,ttl):
        self.origin = DNSLabel(origin)
        self.ttl = parse_time(ttl)
        self.routes = {}
        for r in routes:
            route,_,cmd = r.partition(":")
            if route.endswith('.'):
                route = DNSLabel(route)
            else:
                route = self.origin.add(route)
            self.routes[route] = cmd

    def resolve(self,request,handler):
        self.log_request(request,handler)
        reply = request.reply()
        qname = request.q.qname
        cmd = self.routes.get(qname)
        if cmd:
            output = getoutput(cmd).encode()
            reply.add_answer(RR(qname,QTYPE.TXT,ttl=self.ttl,
                                rdata=TXT(output[:254])))
        self.log_request(reply,handler)
        return reply

if __name__ == '__main__':

    import argparse,sys,time

    p = argparse.ArgumentParser(description="Shell DNS Resolver")
    p.add_argument("--map","-m",action="append",required=True,
                    metavar="<label>:<shell command>",
                    help="Map label to shell command (multiple supported)")
    p.add_argument("--origin","-o",default=".",
                    metavar="<origin>",
                    help="Origin domain label (default: .)")
    p.add_argument("--ttl","-t",default="60s",
                    metavar="<ttl>",
                    help="Response TTL (default: 60s)")
    p.add_argument("--port","-p",type=int,default=53,
                    metavar="<port>",
                    help="Server port (default:53)")
    p.add_argument("--address","-a",default="",
                    metavar="<address>",
                    help="Listen address (default:all)")
    p.add_argument("--tcp",action='store_true',default=False,
                    help="TCP server (default: UDP only)")
    args = p.parse_args()

    resolver = ShellResolver(args.map,args.origin,args.ttl)

    print("Starting Shell Resolver (%s:%d) [%s]" % (
                        args.address or "*",
                        args.port,
                        "UDP/TCP" if args.tcp else "UDP"))

    for route,cmd in resolver.routes.items():
        print("    | ",route,"-->",cmd)
    print()

    udp_server = DNSServer(resolver,port=args.port,address=args.address)
    udp_server.start_thread()

    if args.tcp:
        tcp_server = DNSServer(resolver,port=args.port,address=args.address,
                                        tcp=True)
        tcp_server.start_thread()

    while udp_server.isAlive():
        time.sleep(1)

