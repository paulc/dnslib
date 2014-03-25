# -*- coding: utf-8 -*-

from __future__ import print_function

import copy

from dnslib import DNSRecord
from dnslib.server import DNSServer,BaseResolver

class ProxyResolver(BaseResolver):

    def __init__(self,address,port):
        self.address = address
        self.port = port

    def resolve(self,request,handler):
        self.log_request(request,handler)
        proxy_r = request.send(self.address,self.port)
        reply = DNSRecord.parse(proxy_r)
        self.log_reply(reply,handler)
        return reply

if __name__ == '__main__':

    import argparse,sys,time

    p = argparse.ArgumentParser(description="Fixed DNS Resolver")
    p.add_argument("--port","-p",type=int,default=53,
                    metavar="<port>",
                    help="Proxy port (default:53)")
    p.add_argument("--address","-a",default="",
                    metavar="<address>",
                    help="Proxy listen address (default:all)")
    p.add_argument("--tcp",action='store_true',default=False,
                    help="TCP proxy (default: UDP only)")
    args = p.parse_args()
    
    resolver = ProxyResolver('8.8.8.8',53)

    print("Starting Proxy Resolver (%s:%d -> %s:%d [%s]" % (
                        args.address or "*",args.port,'8.8.8.8',53,
                        "UDP/TCP" if args.tcp else "UDP"))

    udp_server = DNSServer(resolver,port=args.port,
                                    address=args.address)
    udp_server.start_thread()

    if args.tcp:
        tcp_server = DNSServer(resolver,port=args.port,address=args.address,
                                        tcp=True)
        tcp_server.start_thread()

    while udp_server.isAlive():
        time.sleep(1)

