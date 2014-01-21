
from __future__ import print_function

import socket,struct,threading,time

try:
    import socketserver
except ImportError:
    import SocketServer as socketserver

from dnslib import DNSRecord,DNSError,QTYPE,RR

class StaticResolver(object):
    """
        Simple resolver implementation. Provides 'resolve' method which is called
        by DNSHandler and returns answer (example just searches for match in list
        of RRs provided at initialisation. 

        Replace with approptiate resolver code for application.

        Note that a single instance is used by all DNSHandler instances so need
        to consider thread safety if data changes.
    """

    def __init__(self,*rrs):
        """
            Initialise resolver. Takes list of RR objects to respond with
        """
        self.zone = []
        for rr in rrs:
            self.zone.append((rr.rname,QTYPE[rr.rtype],rr))

    def resolve(self,request,handler):
        """
            Respond to DNS request - parameters are request packet & handler.
            Method is expected to return DNS response
        """
        a = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        for name,rtype,rr in self.zone:
            if qname == name and (qtype == rtype or 
                                  qtype == '*' or 
                                  rtype == 'CNAME'):
                a.add_answer(rr)
        return a

class DynamicResolver(object):
    """
        Example dynamic resolver
    """
    def resolve(self,request,handler):
        a = request.reply()
        qname = request.q.qname
        if qname.label[0] == b'date':
            a.add_answer(RR(qname,"TXT",ttl=0,rdata=TXT(
                time.ctime().encode('utf8'))))
        elif qname.label[0] == b'hello':
            a.add_answer(RR(qname,"TXT",ttl=0,rdata=TXT(
                b"Hello " + str(handler.client_address).encode('utf8'))))
        return a

class DNSHandler(socketserver.BaseRequestHandler):
    """
        Handler for socketserver. Handles both TCP/UDP requests (TCP requests have
        length prepended) and hands off lookup to resolver instance specified
        in <SocketServer>.resolver 
    """
    def handle(self):
        if self.server.socket_type == socket.SOCK_STREAM:
            self.protocol = 'tcp'
            data = self.request.recv(8192)
            length = struct.unpack("!H",data[:2])[0]
            while len(data) - 2 < length:
                data += self.request.recv(8192)
            data = data[2:]
        else:
            self.protocol = 'udp'
            data,connection = self.request

        try:
            request = DNSRecord.parse(data)

            self.log_request(request)

            resolver = self.server.resolver
            reply = resolver.resolve(request,self)
            data = reply.pack()

            self.log_reply(reply)

            if self.protocol == 'tcp':
                data = struct.pack("!H",len(data)) + data
                self.request.sendall(data)
            else:
                connection.sendto(data,self.client_address)

        except DNSError as e:
            self.handle_error(e)

    def log_request(self,request):
        print("<<< Request: [%s:%d] (%s) / '%s' (%s)" % (
                                                  self.client_address[0],
                                                  self.client_address[1],
                                                  self.protocol,
                                                  request.q.qname,
                                                  QTYPE[request.q.qtype]))
        print(request.format("    : "))

    def log_reply(self,reply):
        print(">>> Reply: [%s:%d] (%s) / '%s' (%s) / RRs: %s" % (
                                                  self.client_address[0],
                                                  self.client_address[1],
                                                  self.protocol,
                                                  reply.q.qname,
                                                  QTYPE[reply.q.qtype],
                                                  ",".join([QTYPE[a.rtype] for a in reply.rr])))
        print(reply.format("    : "))

    def handle_error(self,e):
        print("Invalid Request:",e)


class DNSServer(object):

    """
        Convenience wrapper for socketserver instance allowing
        server to be started in blocking or threaded mode
    """
    def __init__(self,resolver,
                      server=socketserver.UDPServer,
                      host="",
                      port=53,
                      handler=DNSHandler):
        """
            server:     server class (socketserver.XXXserver)
            host:       listen address
            port:       listen port
            handler:    handler class
            resolver:   resolver *instance*
        """
        self.server = server((host,port),handler)
        self.server.resolver = resolver
    
    def start(self):
        self.server.serve_forever()

    def start_thread(self):
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    def isAlive(self):
        return self.thread.isAlive()

if __name__ == "__main__":

    import time
    from dnslib import A,AAAA,TXT,CNAME,MX,PTR,NS,SOA,NAPTR

    # Initialise resolver instance
    resolver = StaticResolver(
            RR("abc.def.com","A",ttl=60,rdata=A("1.2.3.4.")),
            RR("abc.def.com","A",ttl=60,rdata=A((9,8,7,6))),
            RR("abc.def.com","AAAA",ttl=60,rdata=AAAA((1,)*16)),
            RR("abc.def.com","MX",ttl=60,rdata=MX("mx1.abc.com")),
            RR("abc.def.com","MX",ttl=60,rdata=MX("mx2.abc.com",20)),
            RR("abc.def.com","TXT",ttl=60,rdata=TXT(b"A message")),
            RR("abc.def.com","NS",ttl=60,rdata=NS("ns.abc.com")),
            RR("abc.def.com","SOA",ttl=60,rdata=SOA("abc.com","abc.com",(60,)*5)),
            RR("4.3.2.1.in-addr.arpa","PTR",ttl=60,rdata=PTR("host1.abc.com")),
            RR("xyz.def.com","CNAME",ttl=60,rdata=CNAME("abc.def.com")),
    )

    #resolver = DynamicResolver()

    # Configure UDP server
    # (can also be Threaded server if needed)
    socketserver.UDPServer.allow_reuse_address = True
    udp_server = DNSServer(port=8053,resolver=resolver)
    udp_server.start_thread()

    # Configure TCP server
    # (can also be Threaded server if needed)
    socketserver.TCPServer.allow_reuse_address = True
    tcp_server = DNSServer(server=socketserver.TCPServer,port=8053,resolver=resolver)
    tcp_server.start_thread()

    while udp_server.isAlive():
        time.sleep(1)

