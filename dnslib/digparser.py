
from dnslib.lex import WordLexer
from dnslib.dns import (DNSRecord,DNSHeader,DNSQuestion,RR,RD,RDMAP,
                        QR,RCODE,CLASS,QTYPE)

class DigParser:

    """
        Parse Dig output
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
                try:
                    f(RR(rname=rname,
                                ttl=int(ttl),
                                rtype=getattr(QTYPE,rtype),
                                rclass=getattr(CLASS,rclass),
                                rdata=rd.fromZone(rdata)))
                except DNSError:
                    # Skip records we dont understand
                    pass

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

    import argparse,doctest,sys

    p = argparse.ArgumentParser(description="DigParser Test")
    p.add_argument("--dig",action='store_true',default=False,
                    help="Parse DiG output (stdin)")

    args = p.parse_args()

    if args.dig:
        l = DigParser(sys.stdin)
        for record in l:
            print(repr(record))
    else:
        doctest.testmod()
