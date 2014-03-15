# -*- coding: utf-8 -*-

from __future__ import print_function

from dnslib.lex import WordLexer
from dnslib.label import DNSLabel
import dnslib.dns

#DNSRecord,DNSHeader,DNSQuestion,RR,CLASS,RDMAP,QR,RCODE 

secs = {'s':1,'m':60,'h':3600,'d':86400,'w':604800}

def parse_time(s):
    if s[-1].lower() in secs:
        return int(s[:-1]) * secs[s[-1].lower()]
    else:
        return int(s)

class ZoneParser:

    """
        Zone file parser

        >>> z = ZoneParser("www.example.com. 60 IN A 1.2.3.4")
        >>> list(z.parse())
        [<DNS RR: 'www.example.com.' rtype=A rclass=IN ttl=60 rdata='1.2.3.4'>]

        >>> z = ZoneParser(zone)
        >>> for rr in z:
        ...     print(rr)
        example.com.            5400    IN      SOA     ns1.example.com. admin.example.com. 2014020901 10800 1800 604800 86400
        example.com.            1800    IN      NS      ns1.example.com.
        example.com.            5400    IN      MX      10 mail.example.com.
        abc.example.com.        5400    IN      A       1.2.3.4
        abc.example.com.        5400    IN      TXT     "A B C"
        ns1.example.com.        60      IN      A       6.7.8.9
        ipv6.example.com.       5400    IN      AAAA    1234:5678::1
        www.example.com.        5400    IN      CNAME   abc.example.com.
        4.3.2.1.5.5.5.0.0.8.1.e164.arpa. 300     IN      NAPTR   100 10 "U" "E2U+sip" "!^.*$!sip:customer-service@example.com!" .

    """

    def __init__(self,zone,origin="",ttl=0):
        self.l = WordLexer(zone)
        self.l.commentchars = ';'
        self.l.nltok = ('NL',None)
        self.l.spacetok = ('SPACE',None)
        self.i = iter(self.l)
        if type(origin) is DNSLabel:
            self.origin = origin
        else:
            self.origin= DNSLabel(origin)
        self.ttl = ttl
        self.label = DNSLabel("")
        self.prev = None

    def expect(self,expect):
        t,val = next(self.i)
        if t != expect:
            raise ValueError("Invalid Token: %s (expecting: %s)" % (t,expect))
        return val

    def parse_label(self,label):
        if label.endswith("."):
            self.label = DNSLabel(label)
        elif label == "@":
            self.label = self.origin
        elif label == '':
            pass
        else:
            self.label = self.origin.add(label)
        return self.label

    def parse_rr(self,rr):
        label = self.parse_label(rr.pop(0))
        ttl = int(rr.pop(0)) if rr[0].isdigit() else self.ttl
        rclass = rr.pop(0) if rr[0] in ('IN','CH','HS') else 'IN'
        rtype = rr.pop(0)
        rdata = rr
        rd = RDMAP.get(rtype,RD)
        return RR(rname=label,
                         ttl=ttl,
                         rclass=getattr(CLASS,rclass),
                         rtype=getattr(QTYPE,rtype),
                         rdata=rd.fromZone(rdata,self.origin))

    def __iter__(self):
        return self.parse()

    def parse(self):
        rr = []
        paren = False
        try:
            while True:
                tok,val = next(self.i)
                if tok == 'NL':
                    if not paren and rr:
                        self.prev = tok
                        yield self.parse_rr(rr)
                        rr = []
                elif tok == 'SPACE' and self.prev == 'NL' and not paren:
                    rr.append('')
                elif tok == 'ATOM':
                    if val == '(':
                        paren = True
                    elif val == ')':
                        paren = False
                    elif val == '$ORIGIN':
                        self.expect('SPACE')
                        origin = self.expect('ATOM')
                        self.origin = self.label = DNSLabel(origin)
                    elif val == '$TTL':
                        self.expect('SPACE')
                        ttl = self.expect('ATOM')
                        self.ttl = parse_time(ttl)
                    else:
                        rr.append(val)
                self.prev = tok
        except StopIteration:
            if rr:
                yield self.parse_rr(rr)

class DigParser:

    """
        >>> for d in dig1,dig2,dig3:
        ...     for r in DigParser(d):
        ...         print("=== Found record:")
        ...         print(r)
        === Found record:
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 3773
        ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION:
        ;abc.def.com.                   IN      ANY
        ;; ANSWER SECTION:
        abc.def.com.            60      IN      A       1.2.3.4
        abc.def.com.            60      IN      A       5.6.7.8
        abc.def.com.            60      IN      AAAA    1234:5678::1
        abc.def.com.            60      IN      TXT     "A TXT Record"
        === Found record:
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 13699
        ;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION:
        ;abc.com.                       IN      A
        === Found record:
        ;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 13699
        ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 1, ADDITIONAL: 1
        ;; QUESTION SECTION:
        ;abc.com.                       IN      A
        ;; ANSWER SECTION:
        abc.def.com.            60      IN      A       1.2.3.4
        abc.def.com.            60      IN      A       5.6.7.8
        abc.def.com.            60      IN      AAAA    1234:5678::1
        abc.def.com.            60      IN      TXT     "A TXT Record"
        ;; AUTHORITY SECTION:
        abc.def.com.            60      IN      NS      ns.def.com.
        ;; ADDITIONAL SECTION:
        abc.def.com.            60      IN      MX      10 mx.def.com.
        === Found record:
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16569
        ;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION:
        ;abc.def.com.                   IN      A
        === Found record:
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16569
        ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION:
        ;abc.def.com.                   IN      A
        ;; ANSWER SECTION:
        abc.def.com.            60      IN      A       1.2.3.4
        abc.def.com.            60      IN      A       5.6.7.8
        === Found record:
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 61080
        ;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION:
        ;def.com.                       IN      A
        === Found record:
        ;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 61080
        ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION:
        ;def.com.                       IN      A
    """

    def __init__(self,dig):
        self.l = WordLexer(dig)
        self.l.commentchars = ';'
        self.l.nltok = ('NL',None)
        self.i = iter(self.l)
        
    def parseHeader(self,l1,l2):
        _,_,_,opcode,_,status,_,_id = l1.split()
        _,flags,_ = l2.split(';')
        header = DNSHeader(id=int(_id),bitmap=0)
        header.opcode = getattr(QR,opcode.rstrip(','))
        header.rcode = getattr(RCODE,status.rstrip(','))
        for f in ('qr','aa','tc','rd','ra'):
            if f in flags:
                setattr(header,f,1)
        return header

    def expect(self,expect):
        t,val = next(self.i)
        if t != expect:
            raise ValueError("Invalid Token: %s (expecting: %s)" % (t,expect))
        return val

    def parseQuestions(self,q,dns):
        for qname,qclass,qtype in q:
            dns.add_question(DNSQuestion(qname,
                                                getattr(QTYPE,qtype),
                                                getattr(CLASS,qclass)))

    def parseAnswers(self,a,auth,ar,dns):
        sect_map = {'a':'add_answer','auth':'add_auth','ar':'add_ar'}
        for sect in 'a','auth','ar':
            f = getattr(dns,sect_map[sect])
            for rr in locals()[sect]:
                rname,ttl,rclass,rtype = rr[:4]
                rdata = rr[4:]
                rd = RDMAP.get(rtype,RD)
                f(RR(rname=rname,
                            ttl=int(ttl),
                            rtype=getattr(QTYPE,rtype),
                            rclass=getattr(CLASS,rclass),
                            rdata=rd.fromZone(rdata)))

    def __iter__(self):
        return self.parse()

    def parse(self):
        dns = None
        section = None
        rr = []
        try:
            while True:
                tok,val = next(self.i)
                if tok == 'COMMENT':
                    if 'Sending:' in val or 'Got answer:' in val:
                        if dns:
                            self.parseQuestions(q,dns)
                            self.parseAnswers(a,auth,ar,dns)
                            yield(dns)
                        dns = DNSRecord()
                        q,a,auth,ar = [],[],[],[]
                    elif val.startswith('; ->>HEADER<<-'):
                        self.expect('NL')
                        val2 = self.expect('COMMENT')
                        dns.header = self.parseHeader(val,val2)
                    elif val.startswith('; QUESTION'):
                        section = q
                    elif val.startswith('; ANSWER'):
                        section = a
                    elif val.startswith('; AUTHORITY'):
                        section = auth
                    elif val.startswith('; ADDITIONAL'):
                        section = ar
                    elif val.startswith(';') or tok[1].startswith('<<>>'):
                        pass
                    elif dns and section == q:
                        q.append(val.split())
                elif tok == 'ATOM':
                    rr.append(val)
                elif tok == 'NL' and rr:
                    section.append(rr)
                    rr = []
        except StopIteration:
            if rr:
                self.section.append(rr)
            if dns:
                self.parseQuestions(q,dns)
                self.parseAnswers(a,auth,ar,dns)
                yield(dns)

if __name__ == '__main__':

    import doctest,textwrap
    zone = textwrap.dedent("""
        $ORIGIN example.com.        ; Comment
        $TTL 90m

        @           IN  SOA     ns1.example.com. admin.example.com. (
                                    2014020901  ; Serial
                                    10800   ; Refresh
                                    1800    ; Retry
                                    604800  ; Expire
                                    86400 ) ; Minimum TTL

             1800   IN  NS      ns1.example.com.
                    IN  MX      ( 10  mail.example.com. )

        abc         IN  A       1.2.3.4
                    IN  TXT     "A B C"

        ns1   60    IN  A       6.7.8.9
        ipv6        IN  AAAA    1234:5678::1
        www         IN  CNAME   abc

        $TTL 5m
        $ORIGIN 4.3.2.1.5.5.5.0.0.8.1.e164.arpa.
                    IN  NAPTR   ( 100 10 "U" "E2U+sip" 
                                  "!^.*$!sip:customer-service@example.com!" 
                                  . )
    """)

    dig1 = textwrap.dedent("""

        ; <<>> DiG 9.8.1-P1 <<>> abc.def.com @localhost ANY -p 8053
        ;; global options: +cmd
        ;; Got answer:
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 3773
        ;; flags:  qr aa rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION:
        ;abc.def.com.                   IN      ANY

        ;; ANSWER SECTION:
        abc.def.com.            60      IN      A       1.2.3.4
        abc.def.com.            60      IN      A       5.6.7.8
        abc.def.com.            60      IN      AAAA    1234:5678::1
        abc.def.com.            60      IN      TXT     "A TXT Record"

        ;; Query time: 19 msec
        ;; SERVER: 127.0.0.1#8053(127.0.0.1)
        ;; WHEN: Mon Mar  3 13:40:11 2014
        ;; MSG SIZE  rcvd: 114

    """)

    dig2 = textwrap.dedent("""
        ; <<>> DiG 9.8.1-P1 <<>> -p 8053 @localhost abc.com +qr
        ; (2 servers found)
        ;; global options: +cmd
        ;; Sending:
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 13699
        ;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0

        ;; QUESTION SECTION:
        ;abc.com.                       IN      A

        ;; Got answer:
        ;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 13699
        ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 1, ADDITIONAL: 1

        ;; QUESTION SECTION:
        ;abc.com.                       IN      A

        ;; ANSWER SECTION:
        abc.def.com.            60      IN      A       1.2.3.4
        abc.def.com.            60      IN      A       5.6.7.8
        abc.def.com.            60      IN      AAAA    1234:5678::1
        abc.def.com.            60      IN      TXT     "A TXT Record"

        ;; AUTHORITY SECTION:
        abc.def.com.            60      IN      NS      ns.def.com

        ;; ADDITIONAL SECTION:
        abc.def.com.            60      IN      MX      10 mx.def.com

        ;; Query time: 2 msec
        ;; SERVER: 127.0.0.1#8053(127.0.0.1)
        ;; WHEN: Mon Mar  3 18:02:12 2014
        ;; MSG SIZE  rcvd: 25

    """)

    dig3 = textwrap.dedent("""
        ;; Sending:
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16569
        ;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0

        ;; QUESTION SECTION:
        ;abc.def.com.                   IN      A

        ;; Got answer:
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16569
        ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0

        ;; QUESTION SECTION:
        ;abc.def.com.                   IN      A

        ;; ANSWER SECTION:
        abc.def.com.            60      IN      A       1.2.3.4
        abc.def.com.            60      IN      A       5.6.7.8

        ;; Query time: 7 msec
        ;; SERVER: 127.0.0.1#8053(127.0.0.1)
        ;; WHEN: Mon Mar  3 19:04:17 2014
        ;; MSG SIZE  rcvd: 61

        ;; Sending:
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 61080
        ;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0

        ;; QUESTION SECTION:
        ;def.com.                       IN      A

        ;; Got answer:
        ;; ->>HEADER<<- opcode: QUERY, status: NXDOMAIN, id: 61080
        ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0

        ;; QUESTION SECTION:
        ;def.com.                       IN      A

        ;; Query time: 1 msec
        ;; SERVER: 127.0.0.1#8053(127.0.0.1)
        ;; WHEN: Mon Mar  3 19:04:18 2014
        ;; MSG SIZE  rcvd: 25
    """)

    doctest.testmod()

