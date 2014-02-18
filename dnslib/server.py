
from __future__ import print_function

import copy,socket,struct,threading,time

try:
    import socketserver
except ImportError:
    import SocketServer as socketserver

from dnslib import DNSRecord,DNSError,QTYPE,RCODE,RR

class BaseResolver(object):
    """
        Base resolver implementation. Provides 'resolve' method which is
        called by DNSHandler and returns answer.

        Subclass is expected to replace resolve method with appropriate
        resolver code for application.

        Note that a single instance is used by all DNSHandler instances so need
        to consider thread safety.
    """
    def log_request(self,request,handler):
        """
            Utility function to log request. Call from resolve
            method if needed
        """
        print("<<< Request: [%s:%d] (%s) / '%s' (%s)" % (
                  handler.client_address[0],
                  handler.client_address[1],
                  handler.protocol,
                  request.q.qname,
                  QTYPE[request.q.qtype]))
        #print(request.format("    : "))
        print()
        print(request.toZone("    "))
        print()

    def log_reply(self,reply,handler):
        """
            Utility function to log reply. Call from resolve
            method if needed
        """
        print(">>> Reply: [%s:%d] (%s) / '%s' (%s) / RRs: %s" % (
                  handler.client_address[0],
                  handler.client_address[1],
                  handler.protocol,
                  reply.q.qname,
                  QTYPE[reply.q.qtype],
                  ",".join([QTYPE[a.rtype] for a in reply.rr])))
        #print(reply.format("    : "))
        print()
        print(reply.toZone("    "))
        print()

    def resolve(self,request,handler):
        """
            Respond to all requests with NOTIMP rcode
        """
        self.log_request(request,handler)
        reply = request.reply()
        reply.header.rcode = getattr(RCODE,'Not Implemented')
        self.log_reply(reply,handler)
        return reply

class ZoneResolver(BaseResolver):
    """
        Simple fixed zone file resolver.
    """

    def __init__(self,zone):
        """
            Initialise resolver from zone file. 

            Stores RRs as a list of (label,type,rr) tuples
        """
        self.zone = []
        for rr in RR.fromZone(zone):
            self.zone.append((rr.rname,QTYPE[rr.rtype],rr))

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
            if qname == name and (qtype == rtype or 
                                  qtype == 'ANY' or 
                                  rtype == 'CNAME'):
                reply.add_answer(rr)
                # Check for A/AAAA records associated with reply and
                # add in additional section
                if rtype in ['CNAME','NS','MX','PTR']:
                    for a_name,a_rtype,a_rr in self.zone:
                        if a_name == rr.rdata.label and a_rtype in ['A','AAAA']:
                            reply.add_ar(a_rr)
        self.log_reply(reply,handler)
        return reply

class DynamicResolver(object):
    """
        Example dynamic resolver
    """
    def resolve(self,request,handler):
        self.log.request(request)
        a = request.reply()
        qname = request.q.qname
        if qname.label[0] == b'date':
            a.add_answer(RR(qname,"TXT",ttl=0,rdata=TXT(
                time.ctime().encode('utf8'))))
        elif qname.label[0] == b'hello':
            a.add_answer(RR(qname,"TXT",ttl=0,rdata=TXT(
                b"Hello " + str(handler.client_address).encode('utf8'))))
        self.log_reply(a)
        return a

class DNSHandler(socketserver.BaseRequestHandler):
    """
        Handler for socketserver. Handles both TCP/UDP requests (TCP requests
        have length prepended) and hands off lookup to resolver instance
        specified in <SocketServer>.resolver 
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

            resolver = self.server.resolver
            reply = resolver.resolve(request,self)
            data = reply.pack()

            if self.protocol == 'tcp':
                data = struct.pack("!H",len(data)) + data
                self.request.sendall(data)
            else:
                connection.sendto(data,self.client_address)

        except DNSError as e:
            self.handle_error(e)

    def handle_error(self,e):
        print("Invalid Request:",e)

class UDPServer(socketserver.UDPServer):
    allow_reuse_address = True

class TCPServer(socketserver.TCPServer):
    allow_reuse_address = True

class DNSServer(object):

    """
        Convenience wrapper for socketserver instance allowing
        server to be started in blocking or threaded mode
    """
    def __init__(self,resolver,
                      address="",
                      port=53,
                      tcp=False,
                      server=None,
                      handler=DNSHandler):
        """
            address:    listen address
            port:       listen port
            handler:    handler class
            tcp:        UDP (false) / TCP (true)
            server:     custom socketserver class
            resolver:   resolver *instance*
        """
        if not server:
            if tcp:
                server = TCPServer
            else:
                server = UDPServer
        self.server = server((address,port),handler)
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

    import time,textwrap
    from dnslib import RR

    # Initialise resolver instance
    zone = textwrap.dedent("""
            $ORIGIN     def.com
            $TTL        60

            @           IN  SOA     ( def.com def.com 1234
                                      60 60 60 60 )
                        IN  NS      ns1.def.com
                        IN  MX      10 mx1.def.com.
            ns1         IN  CNAME   abc.def.com.
            mx1         IN  CNAME   abc.def.com.

            abc         IN  A       1.2.3.4
                        IN  A       5.6.7.8
                        IN  AAAA    1234:5678::1
                        IN  TXT     "A TXT Record"
            
            $ORIGIN in-addr.arpa.
            4.3.2.1     IN PTR  abc.def.com.

    """)

    #resolver = BaseResolver()
    #resolver = FixedResolver(". 60 IN A 127.0.0.1")
    resolver = ZoneResolver(zone)
    #resolver = DynamicResolver()

    # Configure UDP server
    udp_server = DNSServer(resolver,port=8053)
    udp_server.start_thread()

    # Configure TCP server
    tcp_server = DNSServer(resolver,port=8053,tcp=True)
    tcp_server.start_thread()

    while udp_server.isAlive():
        time.sleep(1)

