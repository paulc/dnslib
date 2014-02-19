# -*- coding: utf-8 -*-

from __future__ import print_function

import socket,struct,threading

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
        print("\n",request.toZone("    "),"\n",sep="")

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
        print("\n",reply.toZone("    "),"\n",sep="")

    def resolve(self,request,handler):
        """
            Respond to all requests with NOTIMP rcode
        """
        self.log_request(request,handler)
        reply = request.reply()
        reply.header.rcode = getattr(RCODE,'Not Implemented')
        self.log_reply(reply,handler)
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
            @resolver:   resolver instance
            @address:    listen address
            @port:       listen port
            @handler:    handler class
            @tcp:        UDP (false) / TCP (true)
            @server:     custom socketserver class
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

    pass
