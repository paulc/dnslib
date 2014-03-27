# -*- coding: utf-8 -*-

from __future__ import print_function

import copy

from dnslib import DNSRecord
from dnslib.server import DNSServer,DNSHandler,BaseResolver

class ProxyResolver(BaseResolver):

    def __init__(self,address,port):
        self.address = address
        self.port = port

    def resolve(self,request,handler):
        if handler.protocol == 'udp':
            proxy_r = request.send(self.address,self.port)
        else:
            proxy_r = request.send(self.address,self.port,tcp=True)
        reply = DNSRecord.parse(proxy_r)
        return reply

class PassthroughDNSHandler(DNSHandler):

    def get_reply(self,data):
        return data

if __name__ == '__main__':

    import argparse,sys,time

    p = argparse.ArgumentParser(description="Fixed DNS Resolver")
    p.add_argument("--port","-p",type=int,default=53,
                    metavar="<port>",
                    help="Proxy port (default:53)")
    p.add_argument("--dns","-d",default="8.8.8.8",
                    metavar="<dns server>",
                    help="DNS server (default:8.8.8.8)")
    p.add_argument("--dns-port",type=int,default=53,
                    metavar="<dns port>",
                    help="DNS server port (default:53)")
    p.add_argument("--address","-a",default="",
                    metavar="<address>",
                    help="Proxy listen address (default:all)")
    p.add_argument("--tcp",action='store_true',default=False,
                    help="TCP proxy (default: UDP only)")
    p.add_argument("--passthrough",action='store_true',default=False,
                    help="Dont decode/re-encode requesr/response (default: off)")
    args = p.parse_args()

    print("Starting Proxy Resolver (%s:%d -> %s:%d) [%s]" % (
                        args.address or "*",args.port,
                        args.dns,args.dns_port,
                        "UDP/TCP" if args.tcp else "UDP"))

    resolver = ProxyResolver(args.dns,args.dns_port)
    handler=PassthroughDNSHandler if args.passthrough else DNSHandler
    udp_server = DNSServer(resolver,
                           port=args.port,
                           address=args.address,
                           handler=handler)
    udp_server.start_thread()

    if args.tcp:
        tcp_server = DNSServer(resolver,
                               port=args.port,
                               address=args.address,
                               tcp=True,
                               handler=handler)
        tcp_server.start_thread()

    while udp_server.isAlive():
        time.sleep(1)

