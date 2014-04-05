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
        called by DNSHandler with the decode request (DNSRecord instance) 
        and returns a DNSRecord instance as reply.

        In most cases you should be able to create a custom resolver by
        just replacing the resolve method with appropriate resolver code for
        application (see fixedresolver/zoneresolver/shellresolver for
        examples)

        Note that a single instance is used by all DNSHandler instances so 
        need to consider blocking & thread safety.
    """
    def resolve(self,request,handler):
        """
            Example resolver - respond to all requests with NXDOMAIN
        """
        reply = request.reply()
        reply.header.rcode = getattr(RCODE,'NXDOMAIN')
        return reply

class DNSHandler(socketserver.BaseRequestHandler):
    """
        Handler for socketserver. Transparently handles both TCP/UDP requests
        (TCP requests have length prepended) and hands off lookup to resolver
        instance specified in <SocketServer>.resolver 
    """

    log = { 'log_recv',         # Raw packet received
            'log_send',         # Raw packet sent
            'log_request',      # DNS Request
            'log_reply',        # DNS Response
            'log_truncated',    # Truncated
            'log_error',        # Decoding error
            'log_data'          # Dump full request/response
          }

    udplen = 0                  # Max udp packet length (0 = ignore)

    def handle(self):
        if self.server.socket_type == socket.SOCK_STREAM:
            self.protocol = 'tcp'
            data = self.request.recv(8192)
            length = struct.unpack("!H",bytes(data[:2]))[0]
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
            if self.udplen and len(rdata) > self.udplen:
                truncated_reply = reply.truncate()
                rdata = truncated_reply.pack()
                self.log_truncated(truncated_reply)
        else:
            rdata = reply.pack()

        return rdata

    def log_recv(self,data):
        if 'log_recv' in self.log:
            print("<<< Received: [%s:%d] (%s) <%d> : %s" % (
                    self.client_address[0],
                    self.client_address[1],
                    self.protocol,
                    len(data),
                    binascii.hexlify(data)))

    def log_send(self,data):
        if 'log_send' in self.log:
            print(">>> Sent: [%s:%d] (%s) <%d> : %s" % (
                    self.client_address[0],
                    self.client_address[1],
                    self.protocol,
                    len(data),
                    binascii.hexlify(data)))

    def log_request(self,request):
        if 'log_request' in self.log:
            print("<<< Request: [%s:%d] (%s) / '%s' (%s)" % (
                    self.client_address[0],
                    self.client_address[1],
                    self.protocol,
                    request.q.qname,
                    QTYPE[request.q.qtype]))
        if 'log_data' in self.log:
            print("\n",request.toZone("    "),"\n",sep="")

    def log_reply(self,reply):
        if 'log_reply' in self.log:
            print(">>> Reply: [%s:%d] (%s) / '%s' (%s) / RRs: %s" % (
                    self.client_address[0],
                    self.client_address[1],
                    self.protocol,
                    reply.q.qname,
                    QTYPE[reply.q.qtype],
                    ",".join([QTYPE[a.rtype] for a in reply.rr])))
        if 'log_data' in self.log:
            print("\n",reply.toZone("    "),"\n",sep="")

    def log_truncated(self,reply):
        if 'log_reply' in self.log:
            print(">>> Truncated Reply: [%s:%d] (%s) / '%s' (%s) / RRs: %s" % (
                    self.client_address[0],
                    self.client_address[1],
                    self.protocol,
                    reply.q.qname,
                    QTYPE[reply.q.qtype],
                    ",".join([QTYPE[a.rtype] for a in reply.rr])))
        if 'log_data' in self.log:
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
        either UDP/TCP server to be started in blocking more
        or as a background thread
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
