
from __future__ import print_function

import socket,SocketServer,struct,threading,time

from dnslib import DNSRecord,QTYPE,RR,A
from dnslib.bit import hexdump

class DNSHandler(SocketServer.BaseRequestHandler):

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

        print("------ Request (%s): %r (%s)" % (self.client_address,
                                                request.q.qname.label,
                                                QTYPE[request.q.qtype]))
        print(hexdump(data,prefix="  "))
        print("\n".join([ "  %s" % l for l in str(request).split("\n")]))

        reply = request.reply(data="1.2.3.4")
        data = reply.pack()

        print(">>>>>> Response")
        print(hexdump(data,prefix="  "))
        print("\n".join([ "  %s" % l for l in str(reply).split("\n")]))

        if self.server.socket_type == socket.SOCK_STREAM:
            data = struct.pack("!H",len(data)) + data
            self.request.sendall(data)
        else:
            connection.sendto(data,self.client_address)


if __name__ == "__main__":

    host, port = "10.0.1.4", 8053

    SocketServer.TCPServer.allow_reuse_address = True
    tcp_server = SocketServer.TCPServer((host,port), DNSHandler)
    tcp_thread = threading.Thread(target=tcp_server.serve_forever)
    tcp_thread.daemon = True

    SocketServer.UDPServer.allow_reuse_address = True
    udp_server = SocketServer.UDPServer((host,port), DNSHandler)
    udp_thread = threading.Thread(target=udp_server.serve_forever)
    udp_thread.daemon = True

    tcp_thread.start()
    udp_thread.start()

    while udp_thread.isAlive():
        time.sleep(1)

        
