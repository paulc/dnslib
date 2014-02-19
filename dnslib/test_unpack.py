# -*- coding: utf-8 -*-

from __future__ import print_function

import binascii

from dnslib import DNSRecord

def test_unpack(s):
    """
    Test decoding with sample DNS packets captured from server/udp_proxy.py

    >>> def _unpack(s):
    ...     return  DNSRecord.parse(binascii.unhexlify(s))

    >>> def _dump(s):
    ...     r = _unpack(s)
    ...     print(repr(r))

    >>> def _dumpzone(s):
    ...     r = _unpack(s)
    ...     print(r)

    Standard query A www.google.com

        >>> p = b'd5ad010000010000000000000377777706676f6f676c6503636f6d0000010001'
        >>> _dump(p)
        <DNS Header: id=0xd5ad type=QUERY opcode=QUERY flags=RD rcode='NOERROR' q=1 a=0 ns=0 ar=0>
        <DNS Question: 'www.google.com' qtype=A qclass=IN>
        
        >>> _dumpzone(p)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 54701
        ;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION
        ;www.google.com                 IN      A

    Standard query response CNAME www.l.google.com A 66.249.91.104 A 66.249.91.99 A 66.249.91.103 A 66.249.91.147

        >>> p = b'd5ad818000010005000000000377777706676f6f676c6503636f6d0000010001c00c0005000100000005000803777777016cc010c02c0001000100000005000442f95b68c02c0001000100000005000442f95b63c02c0001000100000005000442f95b67c02c0001000100000005000442f95b93'
        >>> _dump(p)
        <DNS Header: id=0xd5ad type=RESPONSE opcode=QUERY flags=RD,RA rcode='NOERROR' q=1 a=5 ns=0 ar=0>
        <DNS Question: 'www.google.com' qtype=A qclass=IN>
        <DNS RR: 'www.google.com' rtype=CNAME rclass=IN ttl=5 rdata='www.l.google.com'>
        <DNS RR: 'www.l.google.com' rtype=A rclass=IN ttl=5 rdata='66.249.91.104'>
        <DNS RR: 'www.l.google.com' rtype=A rclass=IN ttl=5 rdata='66.249.91.99'>
        <DNS RR: 'www.l.google.com' rtype=A rclass=IN ttl=5 rdata='66.249.91.103'>
        <DNS RR: 'www.l.google.com' rtype=A rclass=IN ttl=5 rdata='66.249.91.147'>

        >>> _dumpzone(p)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 54701
        ;; flags: rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION
        ;www.google.com                 IN      A
        ;; ANSWER SECTION
        www.google.com          5       IN      CNAME   www.l.google.com
        www.l.google.com        5       IN      A       66.249.91.104
        www.l.google.com        5       IN      A       66.249.91.99
        www.l.google.com        5       IN      A       66.249.91.103
        www.l.google.com        5       IN      A       66.249.91.147

    Standard query MX google.com

        >>> p = b'95370100000100000000000006676f6f676c6503636f6d00000f0001'
        >>> _dump(p)
        <DNS Header: id=0x9537 type=QUERY opcode=QUERY flags=RD rcode='NOERROR' q=1 a=0 ns=0 ar=0>
        <DNS Question: 'google.com' qtype=MX qclass=IN>
            
        >>> _dumpzone(p)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 38199
        ;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION
        ;google.com                     IN      MX

    Standard query response MX 10 smtp2.google.com MX 10 smtp3.google.com MX 10 smtp4.google.com MX 10 smtp1.google.com

        >>> p = b'95378180000100040000000006676f6f676c6503636f6d00000f0001c00c000f000100000005000a000a05736d747032c00cc00c000f000100000005000a000a05736d747033c00cc00c000f000100000005000a000a05736d747034c00cc00c000f000100000005000a000a05736d747031c00c'
        >>> _dump(p)
        <DNS Header: id=0x9537 type=RESPONSE opcode=QUERY flags=RD,RA rcode='NOERROR' q=1 a=4 ns=0 ar=0>
        <DNS Question: 'google.com' qtype=MX qclass=IN>
        <DNS RR: 'google.com' rtype=MX rclass=IN ttl=5 rdata='10 smtp2.google.com'>
        <DNS RR: 'google.com' rtype=MX rclass=IN ttl=5 rdata='10 smtp3.google.com'>
        <DNS RR: 'google.com' rtype=MX rclass=IN ttl=5 rdata='10 smtp4.google.com'>
        <DNS RR: 'google.com' rtype=MX rclass=IN ttl=5 rdata='10 smtp1.google.com'>

        >>> _dumpzone(p)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 38199
        ;; flags: rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION
        ;google.com                     IN      MX
        ;; ANSWER SECTION
        google.com              5       IN      MX      10 smtp2.google.com
        google.com              5       IN      MX      10 smtp3.google.com
        google.com              5       IN      MX      10 smtp4.google.com
        google.com              5       IN      MX      10 smtp1.google.com

    Standard query PTR 103.91.249.66.in-addr.arpa

        >>> p = (b'b38001000001000000000000033130330239310332343902363607696e2d61646472046172706100000c0001')
        >>> _dump(p)
        <DNS Header: id=0xb380 type=QUERY opcode=QUERY flags=RD rcode='NOERROR' q=1 a=0 ns=0 ar=0>
        <DNS Question: '103.91.249.66.in-addr.arpa' qtype=PTR qclass=IN>

        >>> _dumpzone(p)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 45952
        ;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION
        ;103.91.249.66.in-addr.arpa     IN      PTR

    Standard query response PTR ik-in-f103.google.com

        >>> p = (b'b38081800001000100000000033130330239310332343902363607696e2d61646472046172706100000c0001c00c000c00010000000500170a696b2d696e2d6631303306676f6f676c6503636f6d00')
        >>> _dump(p)
        <DNS Header: id=0xb380 type=RESPONSE opcode=QUERY flags=RD,RA rcode='NOERROR' q=1 a=1 ns=0 ar=0>
        <DNS Question: '103.91.249.66.in-addr.arpa' qtype=PTR qclass=IN>
        <DNS RR: '103.91.249.66.in-addr.arpa' rtype=PTR rclass=IN ttl=5 rdata='ik-in-f103.google.com'>

        >>> _dumpzone(p)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 45952
        ;; flags: rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION
        ;103.91.249.66.in-addr.arpa     IN      PTR
        ;; ANSWER SECTION
        103.91.249.66.in-addr.arpa 5       IN      PTR     ik-in-f103.google.com

    Standard query TXT google.com

        >>> p = (b'c89f0100000100000000000006676f6f676c6503636f6d0000100001')
        >>> _dump(p)
        <DNS Header: id=0xc89f type=QUERY opcode=QUERY flags=RD rcode='NOERROR' q=1 a=0 ns=0 ar=0>
        <DNS Question: 'google.com' qtype=TXT qclass=IN>

        >>> _dumpzone(p)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 51359
        ;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION
        ;google.com                     IN      TXT

    Standard query response TXT

        >>> p = (b'c89f8180000100010000000006676f6f676c6503636f6d0000100001c00c0010000100000005002a29763d7370663120696e636c7564653a5f6e6574626c6f636b732e676f6f676c652e636f6d207e616c6c')
        >>> _dump(p)
        <DNS Header: id=0xc89f type=RESPONSE opcode=QUERY flags=RD,RA rcode='NOERROR' q=1 a=1 ns=0 ar=0>
        <DNS Question: 'google.com' qtype=TXT qclass=IN>
        <DNS RR: 'google.com' rtype=TXT rclass=IN ttl=5 rdata='v=spf1 include:_netblocks.google.com ~all'>

        >>> _dumpzone(p)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 51359
        ;; flags: rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION
        ;google.com                     IN      TXT
        ;; ANSWER SECTION
        google.com              5       IN      TXT     "v=spf1 include:_netblocks.google.com ~all"

    Standard query SOA google.com

        >>> p = (b'28fb0100000100000000000006676f6f676c6503636f6d0000060001')
        >>> _dump(p)
        <DNS Header: id=0x28fb type=QUERY opcode=QUERY flags=RD rcode='NOERROR' q=1 a=0 ns=0 ar=0>
        <DNS Question: 'google.com' qtype=SOA qclass=IN>

        >>> _dumpzone(p)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 10491
        ;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION
        ;google.com                     IN      SOA

    Standard query response SOA ns1.google.com

        >>> p = (b'28fb8180000100010000000006676f6f676c6503636f6d0000060001c00c00060001000000050026036e7331c00c09646e732d61646d696ec00c77b1566d00001c2000000708001275000000012c')
        >>> _dump(p)
        <DNS Header: id=0x28fb type=RESPONSE opcode=QUERY flags=RD,RA rcode='NOERROR' q=1 a=1 ns=0 ar=0>
        <DNS Question: 'google.com' qtype=SOA qclass=IN>
        <DNS RR: 'google.com' rtype=SOA rclass=IN ttl=5 rdata='ns1.google.com dns-admin.google.com 2008110701 7200 1800 1209600 300'>

        >>> _dumpzone(p)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 10491
        ;; flags: rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION
        ;google.com                     IN      SOA
        ;; ANSWER SECTION
        google.com              5       IN      SOA     ns1.google.com dns-admin.google.com 2008110701 7200 1800 1209600 300

    Standard query response NAPTR sip2sip.info

        >>> p = (b'740481800001000300000000077369703273697004696e666f0000230001c00c0023000100000c940027001e00640173075349502b44325500045f736970045f756470077369703273697004696e666f00c00c0023000100000c940027000a00640173075349502b44325400045f736970045f746370077369703273697004696e666f00c00c0023000100000c94002900140064017308534950532b44325400055f73697073045f746370077369703273697004696e666f00')
        >>> _dump(p)
        <DNS Header: id=0x7404 type=RESPONSE opcode=QUERY flags=RD,RA rcode='NOERROR' q=1 a=3 ns=0 ar=0>
        <DNS Question: 'sip2sip.info' qtype=NAPTR qclass=IN>
        <DNS RR: 'sip2sip.info' rtype=NAPTR rclass=IN ttl=3220 rdata='30 100 "s" "SIP+D2U" "" _sip._udp.sip2sip.info'>
        <DNS RR: 'sip2sip.info' rtype=NAPTR rclass=IN ttl=3220 rdata='10 100 "s" "SIP+D2T" "" _sip._tcp.sip2sip.info'>
        <DNS RR: 'sip2sip.info' rtype=NAPTR rclass=IN ttl=3220 rdata='20 100 "s" "SIPS+D2T" "" _sips._tcp.sip2sip.info'>

        >>> _dumpzone(p)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 29700
        ;; flags: rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION
        ;sip2sip.info                   IN      NAPTR
        ;; ANSWER SECTION
        sip2sip.info            3220    IN      NAPTR   30 100 "s" "SIP+D2U" "" _sip._udp.sip2sip.info
        sip2sip.info            3220    IN      NAPTR   10 100 "s" "SIP+D2T" "" _sip._tcp.sip2sip.info
        sip2sip.info            3220    IN      NAPTR   20 100 "s" "SIPS+D2T" "" _sips._tcp.sip2sip.info

    Standard query response NAPTR 0.0.0.0.1.1.1.3.9.3.0.1.8.7.8.e164.org

        >>> p = (b'aef0818000010001000000000130013001300130013101310131013301390133013001310138013701380465313634036f72670000230001c00c002300010000a6a300320064000a0175074532552b53495022215e5c2b3f282e2a2924217369703a5c5c31406677642e70756c7665722e636f6d2100')
        >>> _dump(p)
        <DNS Header: id=0xaef0 type=RESPONSE opcode=QUERY flags=RD,RA rcode='NOERROR' q=1 a=1 ns=0 ar=0>
        <DNS Question: '0.0.0.0.1.1.1.3.9.3.0.1.8.7.8.e164.org' qtype=NAPTR qclass=IN>
        <DNS RR: '0.0.0.0.1.1.1.3.9.3.0.1.8.7.8.e164.org' rtype=NAPTR rclass=IN ttl=42659 rdata='100 10 "u" "E2U+SIP" "!^\+?(.*)$!sip:\\\\1@fwd.pulver.com!" .'>

        >>> _dumpzone(p)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 44784
        ;; flags: rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION
        ;0.0.0.0.1.1.1.3.9.3.0.1.8.7.8.e164.org IN      NAPTR
        ;; ANSWER SECTION
        0.0.0.0.1.1.1.3.9.3.0.1.8.7.8.e164.org 42659   IN      NAPTR   100 10 "u" "E2U+SIP" "!^\\+?(.*)$!sip:\\\\1@fwd.pulver.com!" .

    EDNS0 OPT record 

        ** Not sure if this is right but don't have any other sample data **

        >>> p = (b'896f010000010000000000010661613332343703636f6d0000010001000029100000000000000c50fa000800012000d99f29cf')
        >>> _dump(p)
        <DNS Header: id=0x896f type=QUERY opcode=QUERY flags=RD rcode='NOERROR' q=1 a=0 ns=0 ar=1>
        <DNS Question: 'aa3247.com' qtype=A qclass=IN>
        <DNS OPT: edns_ver=0 do=0 ext_rcode=0 udp_len=4096>
        <EDNS Option: Code=20730 Data='00012000d99f29cf'>

        >>> _dumpzone(p)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 35183
        ;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
        ;; QUESTION SECTION
        ;aa3247.com                     IN      A
        ;; ADDITIONAL SECTION
        ;OPT PSEUDOSECTION
        ;EDNS: version: 0, flags: ; udp: 4096
        ;EDNS: code: 20730; data: 00012000d99f29cf

    """
    pass

if __name__ == '__main__':
    import doctest
    doctest.testmod(optionflags=doctest.ELLIPSIS)
