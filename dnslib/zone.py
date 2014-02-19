
from __future__ import print_function

from dnslib.lex import WordLexer
from dnslib.label import DNSLabel

secs = {'s':1,'m':60,'h':3600,'d':86400,'w':604800}

def parse_time(s):
    if s[-1].lower() in secs:
        return int(s[:-1]) * secs[s[-1].lower()]
    else:
        return int(s)

class ZoneParser:

    """
        Zone file parser

        >>> z = ZoneParser(zone)
        >>> for rr in z:
        ...     print(rr)
        (<DNSLabel: example.com>, 5400, 'IN', 'SOA', ['ns1.example.com.', 'admin.example.com.', '2014020901', '10800', '1800', '604800', '86400'])
        (<DNSLabel: example.com>, 1800, 'IN', 'NS', ['ns1.example.com.'])
        (<DNSLabel: example.com>, 5400, 'IN', 'MX', ['10', 'mail.example.com.'])
        (<DNSLabel: abc.example.com>, 5400, 'IN', 'A', ['1.2.3.4'])
        (<DNSLabel: abc.example.com>, 5400, 'IN', 'TXT', ['A B C'])
        (<DNSLabel: ns1.example.com>, 60, 'IN', 'A', ['6.7.8.9'])
        (<DNSLabel: ipv6.example.com>, 5400, 'IN', 'AAAA', ['1234:5678::1'])
        (<DNSLabel: www.example.com>, 5400, 'IN', 'CNAME', ['abc'])
        (<DNSLabel: 4.3.2.1.5.5.5.0.0.8.1.e164.arpa>, 300, 'IN', 'NAPTR', ['100', '10', 'U', 'E2U+sip', '!^.*$!sip:customer-service@example.com!', '.'])

        >>> z = ZoneParser("www.example.com. 60 IN A 1.2.3.4")
        >>> z.next()
        (<DNSLabel: www.example.com>, 60, 'IN', 'A', ['1.2.3.4'])
    """

    def __init__(self,zone,origin="",ttl=0):
        self.l = WordLexer(zone)
        self.l.commentchars = ';'
        self.l.nltok = ('NL',)
        self.l.spacetok = ('SPACE',)
        self.i = iter(self.l)
        if type(origin) is DNSLabel:
            self.origin = origin
        else:
            self.origin= DNSLabel(origin)
        self.ttl = ttl
        self.label = DNSLabel("")
        self.prev = None

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
        cl = rr.pop(0) if rr[0] in ('IN','CH','HS') else 'IN'
        rtype = rr.pop(0)
        rdata = rr
        return((label,ttl,cl,rtype,rdata))

    def __iter__(self):
        return self.parse()

    def parse(self):
        while True:
            yield self.next()

    def next(self):
        rr = []
        paren = False
        try:
            while True:
                tok = next(self.i)
                if tok[0] == 'NL':
                    if not paren and rr:
                        self.prev = tok[0]
                        return self.parse_rr(rr)
                elif tok[0] == 'SPACE' and self.prev == 'NL' and not paren:
                    rr.append('')
                elif tok[0] == 'ATOM':
                    if tok[1] == '(':
                        paren = True
                    elif tok[1] == ')':
                        paren = False
                    elif tok[1] == '$ORIGIN':
                        _ = next(self.i) # Skip space
                        self.origin = self.label = DNSLabel(next(self.i)[1])
                    elif tok[1] == '$TTL':
                        _ = next(self.i) # Skip space
                        self.ttl = parse_time(next(self.i)[1])
                    else:
                        rr.append(tok[1])
                self.prev = tok[0]
        except StopIteration:
            if rr:
                return self.parse_rr(rr)
            else:
                raise StopIteration

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

    doctest.testmod()

