
from __future__ import print_function

import socket,struct,threading

try:
    import socketserver
except ImportError:
    import SocketServer as socketserver


from dnslib import DNSRecord,QTYPE,RR

class StaticResolver(object):

    def __init__(self,*rrs):
        self.zone = []
        for rr in rrs:
            self.zone.append((rr.rname,QTYPE[rr.rtype],rr))

    def resolve(self,request):
        a = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        for name,rtype,rr in self.zone:
            if qname == name and (qtype == rtype or qtype == '*' or rtype == 'CNAME'):
                a.add_answer(rr)
        return a

class DNSHandler(socketserver.BaseRequestHandler):

    def handle(self):
        if self.server.socket_type == socket.SOCK_STREAM:
            data = self.request.recv(8192)
            length = struct.unpack("!H",data[:2])[0]
            while len(data) - 2 < length:
                data += self.request.recv(8192)
            request = DNSRecord.parse(data[2:])
        else:
            data,connection = self.request
            request = DNSRecord.parse(data)

        resolver = self.server.resolver

        print("------ Request (%s): %r (%s)" % (self.client_address,
                                                request.q.qname.label,
                                                QTYPE[request.q.qtype]))
        print("\n".join([ "  %s" % l for l in str(request).split("\n")]))

        reply = resolver.resolve(request)
        data = reply.pack()

        print(">>>>>> Response")
        print("\n".join([ "  %s" % l for l in str(reply).split("\n")]))

        if self.server.socket_type == socket.SOCK_STREAM:
            data = struct.pack("!H",len(data)) + data
            self.request.sendall(data)
        else:
            connection.sendto(data,self.client_address)

class DNSServer(object):

    def __init__(self,server,host,port,handler,resolver):
        server.allow_reuse_address = True
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

    host, port = "10.0.1.4", 8053

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

    udp_server = DNSServer(socketserver.UDPServer,host,port,DNSHandler,resolver)
    udp_server.start_thread()

    tcp_server = DNSServer(socketserver.TCPServer,host,port,DNSHandler,resolver)
    tcp_server.start_thread()

    while udp_server.isAlive():
        time.sleep(1)

