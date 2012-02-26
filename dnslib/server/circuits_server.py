#!/usr/bin/env python

from circuits.net.sockets import UDPServer

from dnslib import A, CNAME, MX, RR
from dnslib import DNSHeader, DNSRecord, QTYPE

AF_INET = 2
SOCK_DGRAM = 2

IP = "127.0.0.1"
TXT = "circuits_server.py"


class DNSServer(UDPServer):

    channel = "dns"

    def read(self, sock, data):
        request = DNSRecord.parse(data)
        id = request.header.id
        qname = request.q.qname
        qtype = request.q.qtype
        print "------ Request (%s): %r (%s)" % (str(sock),
                qname.label, QTYPE[qtype])

        reply = DNSRecord(DNSHeader(id=id, qr=1, aa=1, ra=1), q=request.q)

        if qtype == QTYPE.A:
            reply.add_answer(RR(qname, qtype,      rdata=A(IP)))
        elif qtype == QTYPE['*']:
            reply.add_answer(RR(qname, QTYPE.A,    rdata=A(IP)))
            reply.add_answer(RR(qname, QTYPE.MX,   rdata=MX(IP)))
            reply.add_answer(RR(qname, QTYPE.TXT,  rdata=TXT(TXT)))
        else:
            reply.add_answer(RR(qname, QTYPE.CNAME, rdata=CNAME(TXT)))

        return reply.pack()

DNSServer(("0.0.0.0", 53)).run()
