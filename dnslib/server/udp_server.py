#!/usr/bin/env python

import socket

from dnslib import A, AAAA, CNAME, MX, RR, TXT
from dnslib import DNSHeader, DNSRecord, QTYPE

AF_INET = 2
SOCK_DGRAM = 2

IP = "127.0.0.1"
IPV6 = (0,) * 16
MSG = "gevent_server.py"


def dns_handler(s, peer, data):
    request = DNSRecord.parse(data)
    id = request.header.id
    qname = request.q.qname
    qtype = request.q.qtype
    print "------ Request (%s): %r (%s)" % (str(peer),
            qname.label, QTYPE[qtype])
    print "\n".join([ "  %s" % l for l in str(request).split("\n")])

    reply = DNSRecord(DNSHeader(id=id, qr=1, aa=1, ra=1), q=request.q)
    if qtype == QTYPE.A:
        reply.add_answer(RR(qname, qtype,       rdata=A(IP)))
    if qtype == QTYPE.AAAA:
        reply.add_answer(RR(qname, qtype,       rdata=AAAA(IPV6)))
    elif qtype == QTYPE['*']:
        reply.add_answer(RR(qname, QTYPE.A,     rdata=A(IP)))
        reply.add_answer(RR(qname, QTYPE.MX,    rdata=MX(IP)))
        reply.add_answer(RR(qname, QTYPE.TXT,   rdata=TXT(MSG)))
    else:
        reply.add_answer(RR(qname, QTYPE.CNAME, rdata=CNAME(MSG)))

    print "------ Reply"
    print "\n".join([ "  %s" % l for l in str(reply).split("\n")])

    s.sendto(reply.pack(), peer)

s = socket.socket(AF_INET, SOCK_DGRAM)
s.bind(('', 53))

while True:
    print "====== Waiting for connection"
    data, peer = s.recvfrom(8192)
    dns_handler(s,peer,data)
