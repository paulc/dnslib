# -*- coding: utf-8 -*-

from __future__ import print_function

import binascii,socket,struct,threading

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
    def resolve(self,request,handler):
        """
            Respond to all requests with NOTIMP rcode
        """
        reply = request.reply()
        reply.header.rcode = getattr(RCODE,'Not Implemented')
        return reply

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

        self.log_recv(data)

        try:
            rdata = self.get_reply(data)
            self.log_send(rdata)

            if self.protocol == 'tcp':
                rdata = struct.pack("!H",len(rdata)) + rdata
                self.request.sendall(rdata)
            else:
                connection.sendto(rdata,self.client_address)

        except DNSError as e:
            self.log_error(e)

    def get_reply(self,data):
        request = DNSRecord.parse(data)
        self.log_request(request)

        resolver = self.server.resolver
        reply = resolver.resolve(request,self)
        self.log_reply(reply)

        if self.protocol == 'udp':
            rdata = reply.pack()
            if self.server.udplen and len(rdata) > self.server.udplen:
                truncated_reply = reply.truncate()
                rdata = truncated_reply.pack()
                self.log_truncated(truncated_reply)
        else:
            rdata = reply.pack()

        return rdata

    def log_recv(self,data):
        print("<<< Received: [%s:%d] (%s) <%d> : %s" % (
                    self.client_address[0],
                    self.client_address[1],
                    self.protocol,
                    len(data),
                    binascii.hexlify(data)))

    def log_send(self,data):
        print(">>> Sent: [%s:%d] (%s) <%d> : %s" % (
                    self.client_address[0],
                    self.client_address[1],
                    self.protocol,
                    len(data),
                    binascii.hexlify(data)))

    def log_request(self,request):
        print("<<< Request: [%s:%d] (%s) / '%s' (%s)" % (
                    self.client_address[0],
                    self.client_address[1],
                    self.protocol,
                    request.q.qname,
                    QTYPE[request.q.qtype]))
        print("\n",request.toZone("    "),"\n",sep="")

    def log_reply(self,reply):
        print(">>> Reply: [%s:%d] (%s) / '%s' (%s) / RRs: %s" % (
                    self.client_address[0],
                    self.client_address[1],
                    self.protocol,
                    reply.q.qname,
                    QTYPE[reply.q.qtype],
                    ",".join([QTYPE[a.rtype] for a in reply.rr])))
        print("\n",reply.toZone("    "),"\n",sep="")

    def log_truncated(self,reply):
        print(">>> Truncated Reply: [%s:%d] (%s) / '%s' (%s) / RRs: %s" % (
                    self.client_address[0],
                    self.client_address[1],
                    self.protocol,
                    reply.q.qname,
                    QTYPE[reply.q.qtype],
                    ",".join([QTYPE[a.rtype] for a in reply.rr])))
        print("\n",reply.toZone("    "),"\n",sep="")

    def log_error(self,e):
        print("--- Invalid Request: [%s:%d] (%s) :: %s" % (
                    self.client_address[0],
                    self.client_address[1],
                    self.protocol,
                    e))

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
                      udplen=None,
                      server=None,
                      handler=DNSHandler):
        """
            @resolver:   resolver instance
            @address:    listen address
            @port:       listen port
            @handler:    handler class
            @tcp:        UDP (false) / TCP (true)
            @udplen:     Max UDP packet length
            @server:     custom socketserver class
        """
        if not server:
            if tcp:
                server = TCPServer
            else:
                server = UDPServer
        self.server = server((address,port),handler)
        self.server.udplen = udplen
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

    pass
