
"""
    DNS - main dnslib module

    Contains core DNS packet handling code
"""

from __future__ import print_function

import base64,binascii,calendar,collections,copy,os.path,random,socket,\
       string,struct,textwrap,time

from itertools import chain

try:
    from itertools import zip_longest
except ImportError:
    from itertools import izip_longest as zip_longest

from dnslib.bit import get_bits,set_bits
from dnslib.bimap import Bimap,BimapError
from dnslib.buffer import Buffer,BufferError
from dnslib.label import DNSLabel,DNSLabelError,DNSBuffer
from dnslib.lex import WordLexer
from dnslib.ranges import BYTES,B,H,I,IP4,IP6,ntuple_range,check_range,\
                          check_bytes

class DNSError(Exception):
    pass

# DNS codes

def unknown_qtype(name,key,forward):
    if forward:
        try:
            return "TYPE%d" % (key,)
        except:
            raise DNSError("%s: Invalid forward lookup: [%s]" % (name,key))
    else:
        if key.startswith("TYPE"):
            try:
                return int(key[4:])
            except:
                pass
        raise DNSError("%s: Invalid reverse lookup: [%s]" % (name,key))

QTYPE =  Bimap('QTYPE',
        {1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 10:'NULL', 12:'PTR', 13:'HINFO',
                    15:'MX', 16:'TXT', 17:'RP', 18:'AFSDB', 24:'SIG', 25:'KEY',
                    28:'AAAA', 29:'LOC', 33:'SRV', 35:'NAPTR', 36:'KX',
                    37:'CERT', 38:'A6', 39:'DNAME', 41:'OPT', 42:'APL',
                    43:'DS', 44:'SSHFP', 45:'IPSECKEY', 46:'RRSIG', 47:'NSEC',
                    48:'DNSKEY', 49:'DHCID', 50:'NSEC3', 51:'NSEC3PARAM',
                    52:'TLSA', 53:'HIP', 55:'HIP', 59:'CDS', 60:'CDNSKEY',
                    61:'OPENPGPKEY', 62:'CSYNC', 63:'ZONEMD', 64:'SVCB',
                    65:'HTTPS', 99:'SPF', 108:'EUI48', 109:'EUI64', 249:'TKEY',
                    250:'TSIG', 251:'IXFR', 252:'AXFR', 255:'ANY', 256:'URI',
                    257:'CAA', 32768:'TA', 32769:'DLV'}, unknown_qtype)

CLASS =  Bimap('CLASS',
                {1:'IN', 2:'CS', 3:'CH', 4:'Hesiod', 254:'None', 255:'*'},
                DNSError)
QR =     Bimap('QR',
                {0:'QUERY', 1:'RESPONSE'},
                DNSError)
RCODE =  Bimap('RCODE',
                {0:'NOERROR', 1:'FORMERR', 2:'SERVFAIL', 3:'NXDOMAIN',
                 4:'NOTIMP', 5:'REFUSED', 6:'YXDOMAIN', 7:'YXRRSET',
                 8:'NXRRSET', 9:'NOTAUTH', 10:'NOTZONE'},
                DNSError)
OPCODE = Bimap('OPCODE',{0:'QUERY', 1:'IQUERY', 2:'STATUS', 4:'NOTIFY', 5:'UPDATE'},
                DNSError)

def label(label,origin=None):
    if label.endswith("."):
        return DNSLabel(label)
    else:
        return (origin if isinstance(origin,DNSLabel)
                       else DNSLabel(origin)).add(label)

class DNSRecord(object):

    """
        Main DNS class - corresponds to DNS packet & comprises DNSHeader,
        DNSQuestion and RR sections (answer,ns,ar)

        >>> d = DNSRecord()
        >>> d.add_question(DNSQuestion("abc.com")) # Or DNSRecord.question("abc.com")
        >>> d.add_answer(RR("abc.com",QTYPE.CNAME,ttl=60,rdata=CNAME("ns.abc.com")))
        >>> d.add_auth(RR("abc.com",QTYPE.SOA,ttl=60,rdata=SOA("ns.abc.com","admin.abc.com",(20140101,3600,3600,3600,3600))))
        >>> d.add_ar(RR("ns.abc.com",ttl=60,rdata=A("1.2.3.4")))
        >>> print(d)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
        ;; flags: rd; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 1
        ;; QUESTION SECTION:
        ;abc.com.                       IN      A
        ;; ANSWER SECTION:
        abc.com.                60      IN      CNAME   ns.abc.com.
        ;; AUTHORITY SECTION:
        abc.com.                60      IN      SOA     ns.abc.com. admin.abc.com. 20140101 3600 3600 3600 3600
        ;; ADDITIONAL SECTION:
        ns.abc.com.             60      IN      A       1.2.3.4
        >>> str(d) == str(DNSRecord.parse(d.pack()))
        True
    """

    @classmethod
    def parse(cls,packet):
        """
            Parse DNS packet data and return DNSRecord instance
            Recursively parses sections (calling appropriate parse method)
        """
        buffer = DNSBuffer(packet)
        try:
            header = DNSHeader.parse(buffer)
            questions = []
            rr = []
            auth = []
            ar = []
            for i in range(header.q):
                questions.append(DNSQuestion.parse(buffer))
            for i in range(header.a):
                rr.append(RR.parse(buffer))
            for i in range(header.auth):
                auth.append(RR.parse(buffer))
            for i in range(header.ar):
                ar.append(RR.parse(buffer))
            return cls(header,questions,rr,auth=auth,ar=ar)
        except DNSError:
            raise
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking DNSRecord [offset=%d]: %s" % (
                                    buffer.offset,e))

    @classmethod
    def question(cls,qname,qtype="A",qclass="IN"):
        """
            Shortcut to create question

            >>> q = DNSRecord.question("www.google.com")
            >>> print(q)
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
            ;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
            ;; QUESTION SECTION:
            ;www.google.com.                IN      A

            >>> q = DNSRecord.question("www.google.com","NS")
            >>> print(q)
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
            ;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
            ;; QUESTION SECTION:
            ;www.google.com.                IN      NS
        """
        return DNSRecord(q=DNSQuestion(qname,getattr(QTYPE,qtype),
                                             getattr(CLASS,qclass)))


    def __init__(self,header=None,questions=None,
                      rr=None,q=None,a=None,auth=None,ar=None):
        """
            Create new DNSRecord
        """
        self.header = header or DNSHeader()
        self.questions = questions or []
        self.rr = rr or []
        self.auth = auth or []
        self.ar = ar or []
        # Shortcuts to add a single Question/Answer
        if q:
            self.questions.append(q)
        if a:
            self.rr.append(a)
        self.set_header_qa()

    def reply(self,ra=1,aa=1):
        """
            Create skeleton reply packet

            >>> q = DNSRecord.question("abc.com")
            >>> a = q.reply()
            >>> a.add_answer(RR("abc.com",QTYPE.A,rdata=A("1.2.3.4"),ttl=60))
            >>> print(a)
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
            ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
            ;; QUESTION SECTION:
            ;abc.com.                       IN      A
            ;; ANSWER SECTION:
            abc.com.                60      IN      A       1.2.3.4
        """
        return DNSRecord(DNSHeader(id=self.header.id,
                                   bitmap=self.header.bitmap,
                                   qr=1,ra=ra,aa=aa),
                         q=self.q)

    def replyZone(self,zone,ra=1,aa=1):
        """
            Create reply with response data in zone-file format
            >>> q = DNSRecord.question("abc.com")
            >>> a = q.replyZone("abc.com 60 A 1.2.3.4")
            >>> print(a)
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
            ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
            ;; QUESTION SECTION:
            ;abc.com.                       IN      A
            ;; ANSWER SECTION:
            abc.com.                60      IN      A       1.2.3.4
        """
        return DNSRecord(DNSHeader(id=self.header.id,
                                   bitmap=self.header.bitmap,
                                   qr=1,ra=ra,aa=aa),
                         q=self.q,
                         rr=RR.fromZone(zone))

    def add_question(self,*q):
        """
            Add question(s)

            >>> q = DNSRecord()
            >>> q.add_question(DNSQuestion("abc.com"),
            ...                DNSQuestion("abc.com",QTYPE.MX))
            >>> print(q)
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
            ;; flags: rd; QUERY: 2, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
            ;; QUESTION SECTION:
            ;abc.com.                       IN      A
            ;abc.com.                       IN      MX
        """
        self.questions.extend(q)
        self.set_header_qa()

    def add_answer(self,*rr):
        """
            Add answer(s)

            >>> q = DNSRecord.question("abc.com")
            >>> a = q.reply()
            >>> a.add_answer(*RR.fromZone("abc.com A 1.2.3.4"))
            >>> print(a)
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
            ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
            ;; QUESTION SECTION:
            ;abc.com.                       IN      A
            ;; ANSWER SECTION:
            abc.com.                0       IN      A       1.2.3.4
        """
        self.rr.extend(rr)
        self.set_header_qa()

    def add_auth(self,*auth):
        """
            Add authority records

            >>> q = DNSRecord.question("abc.com")
            >>> a = q.reply()
            >>> a.add_answer(*RR.fromZone("abc.com 60 A 1.2.3.4"))
            >>> a.add_auth(*RR.fromZone("abc.com 3600 NS nsa.abc.com"))
            >>> print(a)
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
            ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 0
            ;; QUESTION SECTION:
            ;abc.com.                       IN      A
            ;; ANSWER SECTION:
            abc.com.                60      IN      A       1.2.3.4
            ;; AUTHORITY SECTION:
            abc.com.                3600    IN      NS      nsa.abc.com.
        """
        self.auth.extend(auth)
        self.set_header_qa()

    def add_ar(self,*ar):
        """
            Add additional records

            >>> q = DNSRecord.question("abc.com")
            >>> a = q.reply()
            >>> a.add_answer(*RR.fromZone("abc.com 60 CNAME x.abc.com"))
            >>> a.add_ar(*RR.fromZone("x.abc.com 3600 A 1.2.3.4"))
            >>> print(a)
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
            ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
            ;; QUESTION SECTION:
            ;abc.com.                       IN      A
            ;; ANSWER SECTION:
            abc.com.                60      IN      CNAME   x.abc.com.
            ;; ADDITIONAL SECTION:
            x.abc.com.              3600    IN      A       1.2.3.4
        """
        self.ar.extend(ar)
        self.set_header_qa()

    def set_header_qa(self):
        """
            Reset header q/a/auth/ar counts to match number of records
            (normally done transparently)
        """
        self.header.q = len(self.questions)
        self.header.a = len(self.rr)
        self.header.auth = len(self.auth)
        self.header.ar = len(self.ar)

    # Shortcut to get first question
    def get_q(self):
        return self.questions[0] if self.questions else DNSQuestion()
    q = property(get_q)

    # Shortcut to get first answer
    def get_a(self):
        return self.rr[0] if self.rr else RR()
    a = property(get_a)

    def pack(self):
        """
            Pack record into binary packet
            (recursively packs each section into buffer)

            >>> q = DNSRecord.question("abc.com")
            >>> q.header.id = 1234
            >>> a = q.replyZone("abc.com A 1.2.3.4")
            >>> a.header.aa = 0
            >>> pkt = a.pack()
            >>> print(DNSRecord.parse(pkt))
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234
            ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
            ;; QUESTION SECTION:
            ;abc.com.                       IN      A
            ;; ANSWER SECTION:
            abc.com.                0       IN      A       1.2.3.4
        """
        self.set_header_qa()
        buffer = DNSBuffer()
        self.header.pack(buffer)
        for q in self.questions:
            q.pack(buffer)
        for rr in self.rr:
            rr.pack(buffer)
        for auth in self.auth:
            auth.pack(buffer)
        for ar in self.ar:
            ar.pack(buffer)
        return buffer.data

    def truncate(self):
        """
            Return truncated copy of DNSRecord (with TC flag set)
            (removes all Questions & RRs and just returns header)

            >>> q = DNSRecord.question("abc.com")
            >>> a = q.reply()
            >>> a.add_answer(*RR.fromZone('abc.com IN TXT %s' % ('x' * 255)))
            >>> a.add_answer(*RR.fromZone('abc.com IN TXT %s' % ('x' * 255)))
            >>> a.add_answer(*RR.fromZone('abc.com IN TXT %s' % ('x' * 255)))
            >>> len(a.pack())
            829
            >>> t = a.truncate()
            >>> print(t)
            ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
            ;; flags: qr aa tc rd ra; QUERY: 0, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0

        """
        return DNSRecord(DNSHeader(id=self.header.id,
                                   bitmap=self.header.bitmap,
                                   tc=1))

    def send(self,dest,port=53,tcp=False,timeout=None,ipv6=False):
        """
            Send packet to nameserver and return response
        """
        data = self.pack()
        if ipv6:
            inet = socket.AF_INET6
        else:
            inet = socket.AF_INET
        try:
            sock = None
            if tcp:
                if len(data) > 65535:
                     raise ValueError("Packet length too long: %d" % len(data))
                data = struct.pack("!H",len(data)) + data
                sock = socket.socket(inet,socket.SOCK_STREAM)
                if timeout is not None:
                    sock.settimeout(timeout)
                sock.connect((dest,port))
                sock.sendall(data)
                response = sock.recv(8192)
                length = struct.unpack("!H",bytes(response[:2]))[0]
                while len(response) - 2 < length:
                    response += sock.recv(8192)
                response = response[2:]
            else:
                sock = socket.socket(inet,socket.SOCK_DGRAM)
                if timeout is not None:
                    sock.settimeout(timeout)
                sock.sendto(self.pack(),(dest,port))
                response,server = sock.recvfrom(8192)
        finally:
            if (sock is not None):
                sock.close()

        return response

    def format(self,prefix="",sort=False):
        """
            Formatted 'repr'-style representation of record
            (optionally with prefix and/or sorted RRs)
        """
        s = sorted if sort else lambda x:x
        sections = [ repr(self.header) ]
        sections.extend(s([repr(q) for q in self.questions]))
        sections.extend(s([repr(rr) for rr in self.rr]))
        sections.extend(s([repr(rr) for rr in self.auth]))
        sections.extend(s([repr(rr) for rr in self.ar]))
        return prefix + ("\n" + prefix).join(sections)

    def toZone(self,prefix=""):
        """
            Formatted 'DiG' (zone) style output
            (with optional prefix)
        """
        z = self.header.toZone().split("\n")
        if self.questions:
            z.append(";; QUESTION SECTION:")
            [ z.extend(q.toZone().split("\n")) for q in self.questions ]
        if self.rr:
            z.append(";; ANSWER SECTION:")
            [ z.extend(rr.toZone().split("\n")) for rr in self.rr ]
        if self.auth:
            z.append(";; AUTHORITY SECTION:")
            [ z.extend(rr.toZone().split("\n")) for rr in self.auth ]
        if self.ar:
            z.append(";; ADDITIONAL SECTION:")
            [ z.extend(rr.toZone().split("\n")) for rr in self.ar ]
        return prefix + ("\n" + prefix).join(z)

    def short(self):
        """
            Just return RDATA
        """
        return "\n".join([rr.rdata.toZone() for rr in self.rr])

    def __eq__(self,other):
        """
            Test for equality by diffing records
        """
        if type(other) != type(self):
            return False
        else:
            return self.diff(other) == []

    def __ne__(self,other):
        return not(self.__eq__(other))

    def diff(self,other):
        """
            Diff records - recursively diff sections (sorting RRs)
        """
        err = []
        if self.header != other.header:
            err.append((self.header,other.header))
        for section in ('questions','rr','auth','ar'):
            if section == 'questions':
                k = lambda x:tuple(map(str,(x.qname,x.qtype)))
            else:
                k = lambda x:tuple(map(str,(x.rname,x.rtype,x.rdata)))
            a = dict([(k(rr),rr) for rr in getattr(self,section)])
            b = dict([(k(rr),rr) for rr in getattr(other,section)])
            sa = set(a)
            sb = set(b)
            for e in sorted(sa.intersection(sb)):
                if a[e] != b[e]:
                    err.append((a[e],b[e]))
            for e in sorted(sa.difference(sb)):
                err.append((a[e],None))
            for e in sorted(sb.difference(sa)):
                err.append((None,b[e]))
        return err

    def __repr__(self):
        return self.format()

    def __str__(self):
        return self.toZone()

class DNSHeader(object):

    """
        DNSHeader section
    """

    # Ensure attribute values match packet
    id = H('id')
    bitmap = H('bitmap')
    q = H('q')
    a = H('a')
    auth = H('auth')
    ar = H('ar')

    @classmethod
    def parse(cls,buffer):
        """
            Implements parse interface
        """
        try:
            (id,bitmap,q,a,auth,ar) = buffer.unpack("!HHHHHH")
            return cls(id,bitmap,q,a,auth,ar)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking DNSHeader [offset=%d]: %s" % (
                                buffer.offset,e))

    def __init__(self,id=None,bitmap=None,q=0,a=0,auth=0,ar=0,**args):
        if id is None:
            self.id = random.randint(0,65535)
        else:
            self.id = id
        if bitmap is None:
            self.bitmap = 0
            self.rd = 1
        else:
            self.bitmap = bitmap
        self.q = q
        self.a = a
        self.auth = auth
        self.ar = ar
        for k,v in args.items():
            if k.lower() == "qr":
                self.qr = v
            elif k.lower() == "opcode":
                self.opcode = v
            elif k.lower() == "aa":
                self.aa = v
            elif k.lower() == "tc":
                self.tc = v
            elif k.lower() == "rd":
                self.rd = v
            elif k.lower() == "ra":
                self.ra = v
            elif k.lower() == "z":
                self.z = v
            elif k.lower() == "ad":
                self.ad = v
            elif k.lower() == "cd":
                self.cd = v
            elif k.lower() == "rcode":
                self.rcode = v

    # Accessors for header properties (automatically pack/unpack
    # into bitmap)
    def get_qr(self):
        return get_bits(self.bitmap,15)

    def set_qr(self,val):
        self.bitmap = set_bits(self.bitmap,val,15)

    qr = property(get_qr,set_qr)

    def get_opcode(self):
        return get_bits(self.bitmap,11,4)

    def set_opcode(self,val):
        self.bitmap = set_bits(self.bitmap,val,11,4)

    opcode = property(get_opcode,set_opcode)

    def get_aa(self):
        return get_bits(self.bitmap,10)

    def set_aa(self,val):
        self.bitmap = set_bits(self.bitmap,val,10)

    aa = property(get_aa,set_aa)

    def get_tc(self):
        return get_bits(self.bitmap,9)

    def set_tc(self,val):
        self.bitmap = set_bits(self.bitmap,val,9)

    tc = property(get_tc,set_tc)

    def get_rd(self):
        return get_bits(self.bitmap,8)

    def set_rd(self,val):
        self.bitmap = set_bits(self.bitmap,val,8)

    rd = property(get_rd,set_rd)

    def get_ra(self):
        return get_bits(self.bitmap,7)

    def set_ra(self,val):
        self.bitmap = set_bits(self.bitmap,val,7)

    ra = property(get_ra,set_ra)

    def get_z(self):
        return get_bits(self.bitmap,6)

    def set_z(self,val):
        self.bitmap = set_bits(self.bitmap,val,6)

    z = property(get_z,set_z)

    def get_ad(self):
        return get_bits(self.bitmap,5)

    def set_ad(self,val):
        self.bitmap = set_bits(self.bitmap,val,5)

    ad = property(get_ad,set_ad)

    def get_cd(self):
        return get_bits(self.bitmap,4)

    def set_cd(self,val):
        self.bitmap = set_bits(self.bitmap,val,4)

    cd = property(get_cd,set_cd)

    def get_rcode(self):
        return get_bits(self.bitmap,0,4)

    def set_rcode(self,val):
        self.bitmap = set_bits(self.bitmap,val,0,4)

    rcode = property(get_rcode,set_rcode)

    def pack(self,buffer):
        buffer.pack("!HHHHHH",self.id,self.bitmap,
                              self.q,self.a,self.auth,self.ar)

    def __repr__(self):
        f = [ self.aa and 'AA',
              self.tc and 'TC',
              self.rd and 'RD',
              self.ra and 'RA',
              self.z and 'Z',
              self.ad and 'AD',
              self.cd and 'CD']
        if OPCODE.get(self.opcode) == 'UPDATE':
            f1='zo'
            f2='pr'
            f3='up'
            f4='ad'
        else:
            f1='q'
            f2='a'
            f3='ns'
            f4='ar'
        return "<DNS Header: id=0x%x type=%s opcode=%s flags=%s " \
                            "rcode='%s' %s=%d %s=%d %s=%d %s=%d>" % (
                    self.id,
                    QR.get(self.qr),
                    OPCODE.get(self.opcode),
                    ",".join(filter(None,f)),
                    RCODE.get(self.rcode),
                    f1, self.q, f2, self.a, f3, self.auth, f4, self.ar )

    def toZone(self):
        f = [ self.qr and 'qr',
              self.aa and 'aa',
              self.tc and 'tc',
              self.rd and 'rd',
              self.ra and 'ra',
              self.z and 'z',
              self.ad and 'ad',
              self.cd and 'cd' ]
        z1 = ';; ->>HEADER<<- opcode: %s, status: %s, id: %d' % (
                    OPCODE.get(self.opcode),RCODE.get(self.rcode),self.id)
        z2 = ';; flags: %s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d' % (
                      " ".join(filter(None,f)),
                      self.q,self.a,self.auth,self.ar)
        return z1 + "\n" + z2

    def __str__(self):
        return self.toZone()

    def __ne__(self,other):
        return not(self.__eq__(other))

    def __eq__(self,other):
        if type(other) != type(self):
            return False
        else:
            # Ignore id
            attrs = ('qr','aa','tc','rd','ra','z','ad','cd','opcode','rcode')
            return all([getattr(self,x) == getattr(other,x) for x in attrs])

class DNSQuestion(object):

    """
        DNSQuestion section
    """

    @classmethod
    def parse(cls,buffer):
        try:
            qname = buffer.decode_name()
            qtype,qclass = buffer.unpack("!HH")
            return cls(qname,qtype,qclass)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking DNSQuestion [offset=%d]: %s" % (
                                buffer.offset,e))

    def __init__(self,qname=None,qtype=1,qclass=1):
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass

    def set_qname(self,qname):
        if isinstance(qname,DNSLabel):
            self._qname = qname
        else:
            self._qname = DNSLabel(qname)

    def get_qname(self):
        return self._qname

    qname = property(get_qname,set_qname)

    def pack(self,buffer):
        buffer.encode_name(self.qname)
        buffer.pack("!HH",self.qtype,self.qclass)

    def toZone(self):
       return ';%-30s %-7s %s' % (self.qname,CLASS.get(self.qclass),
                                             QTYPE[self.qtype])

    def __repr__(self):
        return "<DNS Question: '%s' qtype=%s qclass=%s>" % (
                    self.qname, QTYPE.get(self.qtype), CLASS.get(self.qclass))

    def __str__(self):
        return self.toZone()

    def __ne__(self,other):
        return not(self.__eq__(other))

    def __eq__(self,other):
        if type(other) != type(self):
            return False
        else:
            # List of attributes to compare when diffing
            attrs = ('qname','qtype','qclass')
            return all([getattr(self,x) == getattr(other,x) for x in attrs])

class EDNSOption(object):

    """
        EDNSOption pseudo-section

        Very rudimentary support for EDNS0 options however this has not been
        tested due to a lack of data (anyone wanting to improve support or
        provide test data please raise an issue)

        >>> EDNSOption(1,b"1234")
        <EDNS Option: Code=1 Data='31323334'>
        >>> EDNSOption(99999,b"1234")
        Traceback (most recent call last):
        ...
        ValueError: Attribute 'code' must be between 0-65535 [99999]
        >>> EDNSOption(1,None)
        Traceback (most recent call last):
        ...
        ValueError: Attribute 'data' must be instance of ...

    """

    code = H('code')
    data = BYTES('data')

    def __init__(self,code,data):
        self.code = code
        self.data = data

    def pack(self,buffer):
        buffer.pack("!HH",self.code,len(self.data))
        buffer.append(self.data)

    def __repr__(self):
        return "<EDNS Option: Code=%d Data='%s'>" % (
                    self.code,binascii.hexlify(self.data).decode())

    def toZone(self):
        return "; EDNS: code: %s; data: %s" % (
                    self.code,binascii.hexlify(self.data).decode())

    def __str__(self):
        return self.toZone()

    def __ne__(self,other):
        return not(self.__eq__(other))

    def __eq__(self,other):
        if type(other) != type(self):
            return False
        else:
            # List of attributes to compare when diffing
            attrs = ('code','data')
            return all([getattr(self,x) == getattr(other,x) for x in attrs])

class RR(object):

    """
        DNS Resource Record
        Contains RR header and RD (resource data) instance
    """

    rtype = H('rtype')
    rclass = H('rclass')
    ttl = I('ttl')
    rdlength = H('rdlength')

    @classmethod
    def parse(cls,buffer):
        try:
            rname = buffer.decode_name()
            rtype,rclass,ttl,rdlength = buffer.unpack("!HHIH")
            if rtype == QTYPE.OPT:
                options = []
                option_buffer = Buffer(buffer.get(rdlength))
                while option_buffer.remaining() > 4:
                    code,length = option_buffer.unpack("!HH")
                    data = option_buffer.get(length)
                    options.append(EDNSOption(code,data))
                rdata = options
            else:
                if rdlength:
                    rdata = RDMAP.get(QTYPE.get(rtype),RD).parse(
                                            buffer,rdlength)
                else:
                    raise DNSError("Error: Empty RR")
            return cls(rname,rtype,rclass,ttl,rdata)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking RR [offset=%d]: %s" % (
                                buffer.offset,e))

    @classmethod
    def fromZone(cls,zone,origin="",ttl=0):
        """
            Parse RR data from zone file and return list of RRs
        """
        return list(ZoneParser(zone,origin=origin,ttl=ttl))

    def __init__(self,rname=None,rtype=1,rclass=1,ttl=0,rdata=None):
        self.rname = rname
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        # Check rdata is valid
        if self.rtype == QTYPE.OPT:
            if not isinstance(rdata,list) or any([not isinstance(rd,EDNSOption) for rd in rdata]):
                raise DNSError("Error: OPT Record expects list of EDNSOption objects")
        elif not isinstance(rdata,RD):
            raise DNSError("Error: RDATA must be RD instance [%s]" % type(rdata).__name__)
        self.rdata = rdata
        # TODO Add property getters/setters (done for DO flag)
        if self.rtype == QTYPE.OPT:
            self.edns_len = self.rclass
            self.edns_ver = get_bits(self.ttl,16,8)
            self.edns_rcode = get_bits(self.ttl,24,8)

    def set_rname(self,rname):
        if isinstance(rname,DNSLabel):
            self._rname = rname
        else:
            self._rname = DNSLabel(rname)

    def get_rname(self):
        return self._rname

    rname = property(get_rname,set_rname)

    def get_do(self):
        if self.rtype == QTYPE.OPT:
            return get_bits(self.ttl,15)
        return 0

    def set_do(self,val):
        if self.rtype == QTYPE.OPT:
            self.ttl = set_bits(self.ttl,val,15)

    edns_do = property(get_do,set_do)

    def pack(self,buffer):
        buffer.encode_name(self.rname)
        buffer.pack("!HHI",self.rtype,self.rclass,self.ttl)
        rdlength_ptr = buffer.offset
        buffer.pack("!H",0)
        start = buffer.offset
        if self.rtype == QTYPE.OPT:
            for opt in self.rdata:
                opt.pack(buffer)
        else:
            self.rdata.pack(buffer)
        end = buffer.offset
        buffer.update(rdlength_ptr,"!H",end-start)

    def __repr__(self):
        if self.rtype == QTYPE.OPT:
            s = ["<DNS OPT: edns_ver=%d do=%d ext_rcode=%d udp_len=%d>" % (
                        self.edns_ver,self.edns_do,self.edns_rcode,self.edns_len)]
            s.extend([repr(opt) for opt in self.rdata])
            return "\n".join(s)
        else:
            return "<DNS RR: '%s' rtype=%s rclass=%s ttl=%d rdata='%s'>" % (
                    self.rname, QTYPE.get(self.rtype), CLASS.get(self.rclass),
                    self.ttl, self.rdata)

    def toZone(self):
        if self.rtype == QTYPE.OPT:
            edns = [ ";; OPT PSEUDOSECTION",
                     "; EDNS: version: %d, flags: %s; udp: %d" % (
                             self.edns_ver,
                             "do" if self.edns_do else "",
                             self.edns_len)
                    ]
            edns.extend([str(opt) for opt in self.rdata])
            return "\n".join(edns)
        else:
            return '%-23s %-7s %-7s %-7s %s' % (self.rname,self.ttl,
                                                CLASS.get(self.rclass),
                                                QTYPE[self.rtype],
                                                self.rdata.toZone())

    def __str__(self):
        return self.toZone()

    def __ne__(self,other):
        return not(self.__eq__(other))

    def __eq__(self,other):
        # Handle OPT specially as may be different types (RR/EDNS0)
        if self.rtype == QTYPE.OPT and getattr(other,"rtype",False) == QTYPE.OPT:
            attrs = ('rname','rclass','rtype','ttl','rdata')
            return all([getattr(self,x) == getattr(other,x) for x in attrs])
        else:
            if type(other) != type(self):
                return False
            else:
                # List of attributes to compare when diffing (ignore ttl)
                attrs = ('rname','rclass','rtype','rdata')
                return all([getattr(self,x) == getattr(other,x) for x in attrs])

class EDNS0(RR):

    """

        ENDS0 pseudo-record

        Wrapper around the ENDS0 support in RR to make it more convenient to
        create EDNS0 pseudo-record - this just makes it easier to specify the
        EDNS0 parameters directly

        EDNS flags should be passed as a space separated string of options
        (currently only 'do' is supported)

        >>> EDNS0("abc.com",flags="do",udp_len=2048,version=1)
        <DNS OPT: edns_ver=1 do=1 ext_rcode=0 udp_len=2048>
        >>> print(_)
        ;; OPT PSEUDOSECTION
        ; EDNS: version: 1, flags: do; udp: 2048
        >>> opt = EDNS0("abc.com",flags="do",ext_rcode=1,udp_len=2048,version=1,opts=[EDNSOption(1,b'abcd')])
        >>> opt
        <DNS OPT: edns_ver=1 do=1 ext_rcode=1 udp_len=2048>
        <EDNS Option: Code=1 Data='61626364'>
        >>> print(opt)
        ;; OPT PSEUDOSECTION
        ; EDNS: version: 1, flags: do; udp: 2048
        ; EDNS: code: 1; data: 61626364
        >>> r = DNSRecord.question("abc.com").replyZone("abc.com A 1.2.3.4")
        >>> r.add_ar(opt)
        >>> print(r)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
        ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
        ;; QUESTION SECTION:
        ;abc.com.                       IN      A
        ;; ANSWER SECTION:
        abc.com.                0       IN      A       1.2.3.4
        ;; ADDITIONAL SECTION:
        ;; OPT PSEUDOSECTION
        ; EDNS: version: 1, flags: do; udp: 2048
        ; EDNS: code: 1; data: 61626364
        >>> DNSRecord.parse(r.pack()) == r
        True
    """

    def __init__(self,rname=None,rtype=QTYPE.OPT,
            ext_rcode=0,version=0,flags="",udp_len=0,opts=None):
        check_range('ext_rcode',ext_rcode,0,255)
        check_range('version',version,0,255)
        edns_flags = { 'do' : 1 << 15 }
        flag_bitmap = sum([edns_flags[x] for x in flags.split()])
        ttl = (ext_rcode << 24) + (version << 16) + flag_bitmap
        if opts and not all([isinstance(o,EDNSOption) for o in opts]):
            raise ValueError("Option must be instance of EDNSOption")
        super(EDNS0,self).__init__(rname,rtype,udp_len,ttl,opts or [])

class RD(object):
    """
        Base RD object - also used as placeholder for unknown RD types

        To create a new RD type subclass this and add to RDMAP (below)

        Subclass should implement (as a minimum):

            parse (parse from packet data)
            __init__ (create class)
            __repr__ (return in zone format)
            fromZone (create from zone format)

            (toZone uses __repr__ by default)

        Unknown rdata types default to RD and store rdata as a binary
        blob (this allows round-trip encoding/decoding)
    """

    @classmethod
    def parse(cls,buffer,length):
        """
            Unpack from buffer
        """
        try:
            data = buffer.get(length)
            return cls(data)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking RD [offset=%d]: %s" %
                                    (buffer.offset,e))

    @classmethod
    def fromZone(cls,rd,origin=None):
        """
            Create new record from zone format data
            RD is a list of strings parsed from DiG output
        """
        # Unknown rata - assume hexdump in zone format
        # (DiG prepends "\\# <len>" to the hexdump so get last item)
        return cls(binascii.unhexlify(rd[-1].encode('ascii')))

    def __init__(self,data=b""):
        # Assume raw bytes
        check_bytes('data',data)
        self.data = bytes(data)

    def pack(self,buffer):
        """
            Pack record into buffer
        """
        buffer.append(self.data)

    def __repr__(self):
        """
            Default 'repr' format should be equivalent to RD zone format
        """
        if len(self.data) > 0:
            return "\\# %d %s" % (len(self.data), binascii.hexlify(self.data).decode().upper())
        else:
            return "\\# 0"

    def toZone(self):
        return repr(self)

    # Comparison operations - in most cases only need to override 'attrs'
    # in subclass (__eq__ will automatically compare defined atttrs)

    # Attributes for comparison
    attrs = ('data',)

    def __eq__(self,other):
        if type(other) != type(self):
            return False
        else:
            return all([getattr(self,x) == getattr(other,x) for x in self.attrs])

    def __ne__(self,other):
        return not(self.__eq__(other))

def _force_bytes(x):
    if isinstance(x,bytes):
        return x
    else:
        return x.encode()

# Python 2 does not have isprintable()
def _isprint(c):
    return (32 <= ord(c) <= 126) or (ord(c) > 127)


def _bytes_to_printable(b):
    return '"' + ''.join([ (c if _isprint(c) else "\\{0:03o}".format(ord(c))) for c in b.decode(errors='replace') ]) + '"'

class TXT(RD):
    """
        DNS TXT record. Pass in either a single byte/unicode string, or a tuple/list of byte/unicode strings.
        (byte strings are preferred as this avoids possible encoding issues)

        >>> TXT(b'txtvers=1')
        "txtvers=1"
        >>> TXT((b'txtvers=1',))
        "txtvers=1"
        >>> TXT([b'txtvers=1',])
        "txtvers=1"
        >>> TXT([b'txtvers=1',b'swver=2.5'])
        "txtvers=1","swver=2.5"
        >>> TXT(['txtvers=1','swver=2.5'])
        "txtvers=1","swver=2.5"
        >>> a = DNSRecord()
        >>> a.add_answer(*RR.fromZone('example.com 60 IN TXT "txtvers=1"'))
        >>> a.add_answer(*RR.fromZone('example.com 120 IN TXT "txtvers=1" "swver=2.3"'))
        >>> print(a)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
        ;; flags: rd; QUERY: 0, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0
        ;; ANSWER SECTION:
        example.com.            60      IN      TXT     "txtvers=1"
        example.com.            120     IN      TXT     "txtvers=1" "swver=2.3"
    """

    @classmethod
    def parse(cls,buffer,length):
        try:
            data = list()
            start_bo = buffer.offset
            now_length = 0
            while buffer.offset < start_bo + length:
                (txtlength,) = buffer.unpack("!B")
                # First byte is TXT length (not in RFC?)
                if now_length + txtlength < length:
                    now_length += txtlength
                    data.append(buffer.get(txtlength))
                else:
                    raise DNSError("Invalid TXT record: len(%d) > RD len(%d)" %
                                            (txtlength,length))
            return cls(data)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking TXT [offset=%d]: %s" %
                                        (buffer.offset,e))

    @classmethod
    def fromZone(cls,rd,origin=None):
        return cls(list(map(lambda x: x.encode(), rd)))

    def __init__(self,data):
        if type(data) in (tuple,list):
            self.data = [ _force_bytes(x) for x in data ]
        else:
            self.data = [ _force_bytes(data) ]
        if any([len(x)>255 for x in self.data]):
            raise DNSError("TXT record too long: %s" % self.data)

    def pack(self,buffer):
        for ditem in self.data:
            if len(ditem) > 255:
                raise DNSError("TXT record too long: %s" % ditem)
            buffer.pack("!B",len(ditem))
            buffer.append(ditem)

    def toZone(self):
        return " ".join([ _bytes_to_printable(x) for x in self.data ])

    def __repr__(self):
        return ",".join([ _bytes_to_printable(x) for x in self.data ])

class A(RD):

    data = IP4('data')

    @classmethod
    def parse(cls,buffer,length):
        try:
            data = buffer.unpack("!BBBB")
            return cls(data)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking A [offset=%d]: %s" %
                                (buffer.offset,e))

    @classmethod
    def fromZone(cls,rd,origin=None):
        return cls(rd[0])

    def __init__(self,data):
        if type(data) in (tuple,list):
            self.data = tuple(data)
        else:
            self.data = tuple(map(int,data.rstrip(".").split(".")))

    def pack(self,buffer):
        buffer.pack("!BBBB",*self.data)

    def __repr__(self):
        return "%d.%d.%d.%d" % self.data

def _parse_ipv6(a):
    """
        Parse IPv6 address. Ideally we would use the ipaddress module in
        Python3.3 but can't rely on having this.

        Does not handle dotted-quad addresses or subnet prefix

        >>> _parse_ipv6("::") == (0,) * 16
        True
        >>> _parse_ipv6("1234:5678::abcd:0:ff00")
        (18, 52, 86, 120, 0, 0, 0, 0, 0, 0, 171, 205, 0, 0, 255, 0)

    """
    l,_,r = a.partition("::")
    l_groups = list(chain(*[divmod(int(x,16),256) for x in l.split(":") if x]))
    r_groups = list(chain(*[divmod(int(x,16),256) for x in r.split(":") if x]))
    zeros = [0] * (16 - len(l_groups) - len(r_groups))
    return tuple(l_groups + zeros + r_groups)

def _format_ipv6(a):
    """
        Format IPv6 address (from tuple of 16 bytes) compressing sequence of
        zero bytes to '::'. Ideally we would use the ipaddress module in
        Python3.3 but can't rely on having this.

        >>> _format_ipv6([0]*16)
        '::'
        >>> _format_ipv6(_parse_ipv6("::0012:5678"))
        '::12:5678'
        >>> _format_ipv6(_parse_ipv6("1234:0:5678::ff:0:1"))
        '1234:0:5678::ff:0:1'
    """
    left = []
    right = []
    current = 'left'
    for i in range(0,16,2):
        group = (a[i] << 8) + a[i+1]
        if current == 'left':
            if group == 0 and i < 14:
                if (a[i+2] << 8) + a[i+3] == 0:
                    current = 'right'
                else:
                    left.append("0")
            else:
                left.append("%x" % group)
        else:
            if group == 0 and len(right) == 0:
                pass
            else:
                right.append("%x" % group)
    if len(left) < 8:
        return ":".join(left) + "::" + ":".join(right)
    else:
        return ":".join(left)

class AAAA(RD):

    """
        Basic support for AAAA record - accepts IPv6 address data as either
        a tuple of 16 bytes or in text format
    """

    data = IP6('data')

    @classmethod
    def parse(cls,buffer,length):
        try:
            data = buffer.unpack("!16B")
            return cls(data)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking AAAA [offset=%d]: %s" %
                                        (buffer.offset,e))

    @classmethod
    def fromZone(cls,rd,origin=None):
        return cls(rd[0])

    def __init__(self,data):
        if type(data) in (tuple,list):
            self.data = tuple(data)
        else:
            self.data = _parse_ipv6(data)

    def pack(self,buffer):
        buffer.pack("!16B",*self.data)

    def __repr__(self):
        return _format_ipv6(self.data)

class MX(RD):

    preference = H('preference')

    @classmethod
    def parse(cls,buffer,length):
        try:
            (preference,) = buffer.unpack("!H")
            mx = buffer.decode_name()
            return cls(mx,preference)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking MX [offset=%d]: %s" %
                                        (buffer.offset,e))

    @classmethod
    def fromZone(cls,rd,origin=None):
        return cls(label(rd[1],origin),int(rd[0]))

    def __init__(self,label=None,preference=10):
        self.label = label
        self.preference = preference

    def set_label(self,label):
        if isinstance(label,DNSLabel):
            self._label = label
        else:
            self._label = DNSLabel(label)

    def get_label(self):
        return self._label

    label = property(get_label,set_label)

    def pack(self,buffer):
        buffer.pack("!H",self.preference)
        buffer.encode_name(self.label)

    def __repr__(self):
        return "%d %s" % (self.preference,self.label)

    attrs = ('preference','label')

class CNAME(RD):

    @classmethod
    def parse(cls,buffer,length):
        try:
            label = buffer.decode_name()
            return cls(label)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking CNAME [offset=%d]: %s" %
                                        (buffer.offset,e))

    @classmethod
    def fromZone(cls,rd,origin=None):
        return cls(label(rd[0],origin))

    def __init__(self,label=None):
        self.label = label

    def set_label(self,label):
        if isinstance(label,DNSLabel):
            self._label = label
        else:
            self._label = DNSLabel(label)

    def get_label(self):
        return self._label

    label = property(get_label,set_label)

    def pack(self,buffer):
        buffer.encode_name(self.label)

    def __repr__(self):
        return "%s" % (self.label)

    attrs = ('label',)

class PTR(CNAME):
    pass

class NS(CNAME):
    pass

class DNAME(CNAME):
    pass

class SOA(RD):

    times = ntuple_range('times',5,0,4294967295)
    @classmethod
    def parse(cls,buffer,length):
        try:
            mname = buffer.decode_name()
            rname = buffer.decode_name()
            times = buffer.unpack("!IIIII")
            return cls(mname,rname,times)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking SOA [offset=%d]: %s" %
                                        (buffer.offset,e))

    @classmethod
    def fromZone(cls,rd,origin=None):
        return cls(label(rd[0],origin),label(rd[1],origin),[parse_time(t) for t in rd[2:]])

    def __init__(self,mname=None,rname=None,times=None):
        self.mname = mname
        self.rname = rname
        self.times = tuple(times) if times else (0,0,0,0,0)

    def set_mname(self,mname):
        if isinstance(mname,DNSLabel):
            self._mname = mname
        else:
            self._mname = DNSLabel(mname)

    def get_mname(self):
        return self._mname

    mname = property(get_mname,set_mname)

    def set_rname(self,rname):
        if isinstance(rname,DNSLabel):
            self._rname = rname
        else:
            self._rname = DNSLabel(rname)

    def get_rname(self):
        return self._rname

    rname = property(get_rname,set_rname)

    def pack(self,buffer):
        buffer.encode_name(self.mname)
        buffer.encode_name(self.rname)
        buffer.pack("!IIIII", *self.times)

    def __repr__(self):
        return "%s %s %s" % (self.mname,self.rname,
                             " ".join(map(str,self.times)))

    attrs = ('mname','rname','times')

class SRV(RD):

    priority = H('priority')
    weight = H('weight')
    port = H('port')

    @classmethod
    def parse(cls,buffer,length):
        try:
            priority,weight,port = buffer.unpack("!HHH")
            target = buffer.decode_name()
            return cls(priority,weight,port,target)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking SRV [offset=%d]: %s" %
                                        (buffer.offset,e))

    @classmethod
    def fromZone(cls,rd,origin=None):
        return cls(int(rd[0]),int(rd[1]),int(rd[2]),rd[3])

    def __init__(self,priority=0,weight=0,port=0,target=None):
        self.priority = priority
        self.weight = weight
        self.port = port
        self.target = target

    def set_target(self,target):
        if isinstance(target,DNSLabel):
            self._target = target
        else:
            self._target = DNSLabel(target)

    def get_target(self):
        return self._target

    target = property(get_target,set_target)

    def pack(self,buffer):
        buffer.pack("!HHH",self.priority,self.weight,self.port)
        buffer.encode_name_nocompress(self.target)

    def __repr__(self):
        return "%d %d %d %s" % (self.priority,self.weight,self.port,self.target)

    attrs = ('priority','weight','port','target')

class NAPTR(RD):

    order = H('order')
    preference = H('preference')

    @classmethod
    def parse(cls, buffer, length):
        try:
            order, preference = buffer.unpack('!HH')
            (length,) = buffer.unpack('!B')
            flags = buffer.get(length)
            (length,) = buffer.unpack('!B')
            service = buffer.get(length)
            (length,) = buffer.unpack('!B')
            regexp = buffer.get(length)
            replacement = buffer.decode_name()
            return cls(order, preference, flags, service, regexp, replacement)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking NAPTR [offset=%d]: %s" %
                                    (buffer.offset,e))

    @classmethod
    def fromZone(cls,rd,origin=None):
        encode = lambda s : s.encode()
        _label = lambda s : label(s,origin)
        m = (int,int,encode,encode,encode,_label)
        return cls(*[ f(v) for f,v in zip(m,rd)])

    def __init__(self,order,preference,flags,service,regexp,replacement=None):
        self.order = order
        self.preference = preference
        self.flags = flags
        self.service = service
        self.regexp = regexp
        self.replacement = replacement

    def set_replacement(self,replacement):
        if isinstance(replacement,DNSLabel):
            self._replacement = replacement
        else:
            self._replacement = DNSLabel(replacement)

    def get_replacement(self):
        return self._replacement

    replacement = property(get_replacement,set_replacement)

    def pack(self, buffer):
        buffer.pack('!HH', self.order, self.preference)
        buffer.pack('!B', len(self.flags))
        buffer.append(self.flags)
        buffer.pack('!B', len(self.service))
        buffer.append(self.service)
        buffer.pack('!B', len(self.regexp))
        buffer.append(self.regexp)
        buffer.encode_name(self.replacement)

    def __repr__(self):
        return '%d %d "%s" "%s" "%s" %s' %(
            self.order,self.preference,self.flags.decode(),
            self.service.decode(),
            self.regexp.decode().replace('\\','\\\\'),
            self.replacement or '.'
        )

    attrs = ('order','preference','flags','service','regexp','replacement')

class DS(RD):
    """
        DS (delegation signer) record as specified in RFC 4034 Section 5.
        https://www.rfc-editor.org/rfc/rfc4034#section-5
    """

    key_tag = H('key_tag')
    algorithm = B('algorithm')
    digest_type = B('digest_type')

    @classmethod
    def parse(cls,buffer,length):
        try:
            (key_tag,algorithm,digest_type) = buffer.unpack("!HBB")
            digest = buffer.get(length - 4)
            return cls(key_tag,algorithm,digest_type,digest)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking DS [offset=%d]: %s" %
                                        (buffer.offset,e))

    @classmethod
    def fromZone(cls,rd,origin=None):
        return cls(int(rd[0]),int(rd[1]),int(rd[2]),
                   binascii.unhexlify("".join(rd[3:]).encode('ascii')))

    def __init__(self,key_tag,algorithm,digest_type,digest):
        self.key_tag = key_tag
        self.algorithm = algorithm
        self.digest_type = digest_type
        self.digest = _force_bytes(digest)

    def pack(self,buffer):
        buffer.pack("!HBB",self.key_tag,self.algorithm,self.digest_type)
        buffer.append(self.digest)

    def __repr__(self):
        return "%d %d %d %s" % (
                        self.key_tag,
                        self.algorithm,
                        self.digest_type,
                        binascii.hexlify(self.digest).decode().upper())

    attrs = ('key_tag','algorithm','digest_type','digest')

class DNSKEY(RD):

    flags = H('flags')
    protocol = B('protocol')
    algorithm = B('algorithm')

    @classmethod
    def parse(cls,buffer,length):
        try:
            (flags,protocol,algorithm) = buffer.unpack("!HBB")
            key = buffer.get(length - 4)
            return cls(flags,protocol,algorithm,key)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking DNSKEY [offset=%d]: %s" %
                                        (buffer.offset,e))

    @classmethod
    def fromZone(cls,rd,origin=None):
        return cls(int(rd[0]),int(rd[1]),int(rd[2]),
                   base64.b64decode(("".join(rd[3:])).encode('ascii')))

    def __init__(self,flags,protocol,algorithm,key):
        self.flags = flags
        self.protocol = protocol
        self.algorithm = algorithm
        self.key = _force_bytes(key)

    def pack(self,buffer):
        buffer.pack("!HBB",self.flags,self.protocol,self.algorithm)
        buffer.append(self.key)

    def __repr__(self):
        return "%d %d %d %s" % (self.flags,self.protocol,self.algorithm,
                                base64.b64encode(self.key).decode())

    attrs = ('flags','protocol','algorithm','key')

class RRSIG(RD):

    covered = H('covered')
    algorithm = B('algorithm')
    labels = B('labels')
    orig_ttl = I('orig_ttl')
    sig_exp = I('sig_exp')
    sig_inc = I('sig_inc')
    key_tag = H('key_tag')

    @classmethod
    def parse(cls,buffer,length):
        try:
            start = buffer.offset
            (covered,algorithm,labels,
                orig_ttl,sig_exp,sig_inc,key_tag) = buffer.unpack("!HBBIIIH")
            name = buffer.decode_name()
            sig = buffer.get(length - (buffer.offset - start))
            return cls(covered,algorithm,labels,orig_ttl,sig_exp,sig_inc,key_tag,
                            name,sig)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking DNSKEY [offset=%d]: %s" %
                                        (buffer.offset,e))

    @classmethod
    def fromZone(cls,rd,origin=None):
        return cls(getattr(QTYPE,rd[0]),int(rd[1]),int(rd[2]),int(rd[3]),
                        int(calendar.timegm(time.strptime(rd[4]+'UTC',"%Y%m%d%H%M%S%Z"))),
                        int(calendar.timegm(time.strptime(rd[5]+'UTC',"%Y%m%d%H%M%S%Z"))),
                        int(rd[6]),rd[7],
                        base64.b64decode(("".join(rd[8:])).encode('ascii')))

    def __init__(self,covered,algorithm,labels,orig_ttl,
                      sig_exp,sig_inc,key_tag,name,sig):
        self.covered = covered
        self.algorithm = algorithm
        self.labels = labels
        self.orig_ttl = orig_ttl
        self.sig_exp = sig_exp
        self.sig_inc = sig_inc
        self.key_tag = key_tag
        self.name = DNSLabel(name)
        self.sig = sig

    def pack(self,buffer):
        buffer.pack("!HBBIIIH",self.covered,self.algorithm,self.labels,
                               self.orig_ttl,self.sig_exp,self.sig_inc,
                               self.key_tag)
        buffer.encode_name_nocompress(self.name)
        buffer.append(self.sig)

    def __repr__(self):
        timestamp_fmt = "{0.tm_year}{0.tm_mon:02}{0.tm_mday:02}{0.tm_hour:02}{0.tm_min:02}{0.tm_sec:02}"
        return "%s %d %d %d %s %s %d %s %s" % (
                        QTYPE.get(self.covered),
                        self.algorithm,
                        self.labels,
                        self.orig_ttl,
                        timestamp_fmt.format(time.gmtime(self.sig_exp)),
                        timestamp_fmt.format(time.gmtime(self.sig_inc)),
                        self.key_tag,
                        self.name,
                        base64.b64encode(self.sig).decode())

    attrs = ('covered','algorithm','labels','orig_ttl','sig_exp','sig_inc',
             'key_tag','name','sig')

def decode_type_bitmap(type_bitmap):
    """
        Parse RR type bitmap in NSEC record

        >>> decode_type_bitmap(binascii.unhexlify(b'0006400080080003'))
        ['A', 'TXT', 'AAAA', 'RRSIG', 'NSEC']
        >>> decode_type_bitmap(binascii.unhexlify(b'000762008008000380'))
        ['A', 'NS', 'SOA', 'TXT', 'AAAA', 'RRSIG', 'NSEC', 'DNSKEY']
    """
    rrlist = []
    buf = DNSBuffer(type_bitmap)
    while buf.remaining():
        winnum,winlen = buf.unpack('BB')
        bitmap = bytearray(buf.get(winlen))
        for (pos,value) in enumerate(bitmap):
            for i in range(8):
                if (value << i) & 0x80:
                    bitpos = (256*winnum) + (8*pos) + i
                    rrlist.append(QTYPE[bitpos])
    return rrlist

def encode_type_bitmap(rrlist):
    """
        Encode RR type bitmap in NSEC record

        >>> p = lambda x: print(binascii.hexlify(x).decode())
        >>> p(encode_type_bitmap(['A','TXT','AAAA','RRSIG','NSEC']))
        0006400080080003
        >>> p(encode_type_bitmap(['A','NS','SOA','TXT','AAAA','RRSIG','NSEC','DNSKEY']))
        000762008008000380
        >>> p(encode_type_bitmap(['A','ANY','URI','CAA','TA','DLV']))
        002040000000000000000000000000000000000000000000000000000000000000010101c08001c0
    """
    rrlist = sorted([getattr(QTYPE,rr) for rr in rrlist])
    buf = DNSBuffer()
    curWindow = rrlist[0]//256
    bitmap = bytearray(32)
    n = len(rrlist)-1
    for i, rr in enumerate(rrlist):
        v = rr - curWindow*256
        bitmap[v//8] |= 1 << (7 - v%8)

        if i == n or rrlist[i+1] >= (curWindow+1)*256:
            while bitmap[-1] == 0:
                bitmap = bitmap[:-1]
            buf.pack("BB", curWindow, len(bitmap))
            buf.append(bitmap)

            if i != n:
                curWindow = rrlist[i+1]//256
                bitmap = bytearray(32)

    return buf.data

class NSEC(RD):

    @classmethod
    def parse(cls,buffer,length):
        try:
            end = buffer.offset + length
            name = buffer.decode_name()
            rrlist = decode_type_bitmap(buffer.get(end - buffer.offset))
            return cls(name,rrlist)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking NSEC [offset=%d]: %s" %
                                        (buffer.offset,e))

    @classmethod
    def fromZone(cls,rd,origin=None):
        return cls(rd.pop(0),rd)

    def __init__(self,label,rrlist):
        self.label = label
        self.rrlist = rrlist

    def set_label(self,label):
        if isinstance(label,DNSLabel):
            self._label = label
        else:
            self._label = DNSLabel(label)

    def get_label(self):
        return self._label

    label = property(get_label,set_label)

    def pack(self,buffer):
        buffer.encode_name_nocompress(self.label)
        buffer.append(encode_type_bitmap(self.rrlist))

    def __repr__(self):
        return "%s %s" % (self.label," ".join(self.rrlist))

    attrs = ('label','rrlist')

class CAA(RD):
    """
        CAA record.

        >>> CAA(0, 'issue', 'letsencrypt.org')
        0 issue \"letsencrypt.org\"
        >>> a = DNSRecord()
        >>> a.add_answer(*RR.fromZone('example.com 60 IN CAA 0 issue "letsencrypt.org"'))
        >>> print(a)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
        ;; flags: rd; QUERY: 0, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
        ;; ANSWER SECTION:
        example.com.            60      IN      CAA     0 issue "letsencrypt.org"
    """

    @classmethod
    def parse(cls,buffer,length):
        try:
            (flags, tag_length) = buffer.unpack("!BB")
            tag = buffer.get(tag_length).decode()
            value = buffer.get(length - tag_length - 2).decode()
            return cls(flags, tag, value)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking CAA [offset=%d]: %s" %
                               (buffer.offset,e))

    @classmethod
    def fromZone(cls,rd,origin=None):
        if len(rd) == 1:
            try:
                hex_parsed = bytes.fromhex(rd[0])
                flags = hex_parsed[0]
                tag_length = hex_parsed[1]
            except:
                hex_parsed = rd[0].decode('hex').encode()
                flags = ord(hex_parsed[0])
                tag_length = ord(hex_parsed[1])
            tag = hex_parsed[2:2+tag_length].decode()
            value = hex_parsed[tag_length+2:].decode()
        else:
            (flags, tag, value) = rd
        return cls(int(flags), tag, value.replace('"', ''))

    def __init__(self, flags, tag, value):
        self.flags = flags
        self.tag = tag
        self.value = value
        self.data = None

    def pack(self,buffer):
        buffer.pack("!BB", self.flags, len(self.tag))
        buffer.append(self.tag.encode())
        buffer.append(self.value.encode())

    def toZone(self):
        return "%d %s \"%s\"" % (self.flags, self.tag, self.value)

    def __repr__(self):
        return "%d %s \"%s\"" % (self.flags, self.tag, self.value)


class HTTPS(RD):
    """
        HTTPS record.

        >>> HTTPS.fromZone(["1", "cloudflare.com."])
        1 cloudflare.com.
        >>> HTTPS.fromZone(["1", ".", "mandatory=key65444,echconfig"])
        1 . mandatory=key65444,echconfig
        >>> HTTPS.fromZone(["1", ".", "alpn=h3,h3-29,h2"])
        1 . alpn=h3,h3-29,h2
        >>> HTTPS.fromZone(["1", ".", "no-default-alpn"])
        1 . no-default-alpn
        >>> HTTPS.fromZone(["1", ".", "port=443"])
        1 . port=443
        >>> HTTPS.fromZone(["1", ".", "ipv4hint=104.16.132.229,104.16.133.229"])
        1 . ipv4hint=104.16.132.229,104.16.133.229
        >>> HTTPS.fromZone(["1", ".", "echconfig=Z2FyYmFnZQ=="])
        1 . echconfig=Z2FyYmFnZQ==
        >>> HTTPS.fromZone(["1", ".", "ipv6hint=2606:4700::6810:84e5,2606:4700::6810:85e5"])
        1 . ipv6hint=2606:4700::6810:84e5,2606:4700::6810:85e5
        >>> HTTPS.fromZone(["1", ".", "key9999=X"])
        1 . key9999=X
        >>> pcap = binascii.unhexlify(b"0001000001000c0268330568332d323902683200040008681084e5681085e500060020260647000000000000000000681084e5260647000000000000000000681085e5")
        >>> obj = HTTPS.parse(Buffer(pcap), len(pcap))
        >>> obj
        1 . alpn=h3,h3-29,h2 ipv4hint=104.16.132.229,104.16.133.229 ipv6hint=2606:4700::6810:84e5,2606:4700::6810:85e5
        >>> b = Buffer()
        >>> obj.pack(b)
        >>> b.data == pcap
        True
        >>> pcap = binascii.unhexlify(b"00010000040004c0a80126")
        >>> obj = HTTPS.parse(Buffer(pcap), len(pcap))
        >>> obj
        1 . ipv4hint=192.168.1.38
        >>> b = Buffer()
        >>> obj.pack(b)
        >>> b.data == pcap
        True

        # Issue 43: HTTPS reads after RD end 
        >>> msg = binascii.unhexlify("93088410000100020000000107646973636f726403636f6d0000410001c00c004100010000012c002b0001000001000c0268330568332d323902683200040014a29f80e9a29f87e8a29f88e8a29f89e8a29f8ae8c00c002e00010000012c005f00410d020000012c632834e5632575c586c907646973636f726403636f6d0044d488ce4a5b9085289c671f0296b2b06cffaca28880c57643befd43d6de433d84ae078b282fc2cdd744f3bea2f201042a7a0d6f3e17ebd887b082bbe30dfda100002904d0000080000000")
        >>> print(DNSRecord.parse(msg))
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 37640
        ;; flags: qr aa cd; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1
        ;; QUESTION SECTION:
        ;discord.com.                   IN      HTTPS
        ;; ANSWER SECTION:
        discord.com.            300     IN      HTTPS   1 . alpn=h3,h3-29,h2 ipv4hint=162.159.128.233,162.159.135.232,162.159.136.232,162.159.137.232,162.159.138.232
        discord.com.            300     IN      RRSIG   HTTPS 13 2 300 20220919092245 20220917072245 34505 discord.com. RNSIzkpbkIUonGcfApaysGz/rKKIgMV2Q779Q9beQz2ErgeLKC/CzddE876i8gEEKnoNbz4X69iHsIK74w39oQ==
        ;; ADDITIONAL SECTION:
        ;; OPT PSEUDOSECTION
        ; EDNS: version: 0, flags: do; udp: 1232

    """

    attrs = ('priority', 'target', 'params')

    def __init__(self, priority, target, params):
        self.priority = priority
        self.target = target
        self.params = params

    @classmethod
    def parse(cls,buffer,length):
        try:
            end = buffer.offset + length
            priority, = buffer.unpack("!H")
            target = []
            while True:
                n, = buffer.unpack("B")
                if n == 0:
                    break
                seg = bytearray(buffer.get(n))
                target.append(seg)
            params = []
            while buffer.offset < end:
                k, = buffer.unpack("!H")
                n, = buffer.unpack("!H")
                v = bytearray(buffer.get(n))
                params.append((k, v))
            return cls(priority, target, params)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking HTTPS: " + str(e) + str(binascii.hexlify(buffer.data[buffer.offset:])))

    def pack(self,buffer):
        buffer.pack("!H", self.priority)
        for seg in self.target:
            buffer.pack("B", len(seg))
            buffer.append(seg)
        buffer.pack("B", 0)
        for k, v in self.params:
            buffer.pack("!H", k)
            buffer.pack("!H", len(v))
            buffer.append(v)

    @classmethod
    def zf_parse_valuelist(cls, s):
        """
            >>> HTTPS.zf_parse_valuelist(bytearray(b'"part1,part2\\\\,part3"'))
            [bytearray(b'part1'), bytearray(b'part2,part3')]
            >>> HTTPS.zf_parse_valuelist(bytearray(b'part1,part2\\\\044part3'))
            [bytearray(b'part1'), bytearray(b'part2,part3')]
        """
        quot = 0x22
        slash = 0x5c
        comma = 0x2c
        if len(s) == 0:
            return []
        if s[0] == quot:
            if len(s) < 2 or s[-1] != quot:
                raise DNSError("Error decoding HTTPS SvcParamKey value list: unmatched \"")
            s = s[1:-1]
        if len(s) == 0:
            return []
        esc = False
        i = 0
        ret = [bytearray()]
        while i < len(s):
            c = s[i]
            if esc:
                esc = False
                if c >= 0x30 and c <= 0x32: #0 1 2
                    ret[-1].append(int(s[i:i+3]))
                    i += 3
                else:
                    ret[-1].append(c)
                    i += 1
            else:
                if c == slash:
                    esc = True
                    i += 1
                elif c == comma:
                    ret.append(bytearray())
                    i += 1
                else:
                    ret[-1].append(c)
                    i += 1
        if esc:
            raise DNSError("Error decoding HTTPS SvcParamKey value list: hanging slash")
        return ret

    @classmethod
    def zf_parse_charstr(cls, s):
        """
            >>> HTTPS.zf_parse_charstr(bytearray(b'"part1,part2\\\\,part3"'))
            bytearray(b'part1,part2,part3')
            >>> HTTPS.zf_parse_charstr(bytearray(b'part1,part2\\\\044part3'))
            bytearray(b'part1,part2,part3')
        """
        quot = 0x22
        slash = 0x5c
        if len(s) == 0:
            return bytearray()
        if s[0] == quot:
            if len(s) < 2 or s[-1] != quot:
                raise DNSError("Error decoding HTTPS SvcParamKey charstring: unmatched \"")
            s = s[1:-1]
        esc = False
        i = 0
        ret = bytearray()
        while i < len(s):
            c = s[i]
            if esc:
                esc = False
                if c >= 0x30 and c <= 0x32: #0 1 2
                    ret.append(int(s[i:i+3]))
                    i += 3
                else:
                    ret.append(c)
                    i += 1
            else:
                if c == slash:
                    esc = True
                    i += 1
                else:
                    ret.append(c)
                    i += 1
        if esc:
            raise DNSError("Error decoding HTTPS SvcParamKey charstring: hanging slash")
        return ret

    @classmethod
    def zf_tobytes(cls, s):
        ''' for py2-3 compatibility '''
        return bytearray(s.encode("ASCII"))

    @classmethod
    def zf_tostr(cls, b):
        return b.decode("ASCII")

    paramkeys = [
        (0, b"mandatory"),
        (1, b"alpn"),
        (2, b"no-default-alpn"),
        (3, b"port"),
        (4, b"ipv4hint"),
        (5, b"echconfig"),
        (6, b"ipv6hint")
    ]

    @classmethod
    def zf_parse_key(cls, k):
        if k.startswith(b"key"):
            return int(k[3:])
        for i, n in cls.paramkeys:
            if k == n:
                return i
        raise DNSError("Error reading HTTPS from zone: unrecognized SvcParamKey")

    @classmethod
    def zf_parse_param(cls, k, v):
        b = Buffer()
        i = cls.zf_parse_key(k)
        if   i == 0: #mandatory
            for s in cls.zf_parse_valuelist(v):
                si = cls.zf_parse_key(s)
                b.pack("!H", si)
        elif i == 1: #alpn
            for s in cls.zf_parse_valuelist(v):
                b.pack("B", len(s))
                b.append(s)
        elif i == 2: #no alpn
            if v:
                raise DNSError("Error encoding HTTPS SvcParamKey: no-default-alpn should not have a value")
        elif i == 3: #port
            b.pack("!H", int(v))
        elif i == 4: #ipv4
            for ip in cls.zf_parse_valuelist(v):
                b.pack("!4B", *[int(x) for x in ip.split(b".")])
        elif i == 5: #ech
            s = cls.zf_parse_charstr(v)
            b.data = binascii.a2b_base64(s)
        elif i == 6: #ipv6
            for ip in cls.zf_parse_valuelist(v):
                oc = _parse_ipv6(cls.zf_tostr(ip))
                b.pack("!16B", *oc)
        else:
            b.data = v
        return (i, b.data)

    @classmethod
    def fromZone(cls,rd,origin=None):
        pri = int(rd[0])
        targ = [] if rd[1] == "." else cls.zf_tobytes(rd[1]).split(b".")[:-1]
        params = []
        for kv in [cls.zf_tobytes(v) for v in rd[2:]]:
            eq = kv.find(b"=")
            if eq < 0:
                k = kv
                v = bytearray()
            else:
                k = kv[:eq]
                v = kv[eq+1:]
            params.append(cls.zf_parse_param(k, v))
        return cls(pri, targ, params)

    @classmethod
    def zf_is_special(cls, c):
        return not (c == 0x21 or \
            c >= 0x23 and c<=0x27 or \
            c >= 0x2A and c<=0x3A or \
            c >= 0x3C and c<=0x5B or \
            c >= 0x5D and c<=0x7E)

    @classmethod
    def zf_escape_charstr(cls, s, escape_commas=False):
        ret = bytearray()
        for c in s:
            if cls.zf_is_special(c) or escape_commas and c == 0x2c:
                ret.extend(b"\\")
                ret.extend(b"%.3d" % c)
            else:
                ret.append(c)
        return cls.zf_tostr(ret)

    @classmethod
    def zf_format_valuelist(cls, lst):
        return ",".join(cls.zf_escape_charstr(s, True) for s in lst)

    @classmethod
    def zf_format_key(cls, k):
        for i, n in cls.paramkeys:
            if k == i:
                return cls.zf_tostr(n)
        return "key" + str(k)

    @classmethod
    def zf_format_param(cls, i, v):
        b = Buffer(v)
        k = cls.zf_format_key(i)
        if i == 0: #mandatory
            ret = []
            while b.remaining() > 0:
                ki, = b.unpack("!H")
                ret.append(cls.zf_format_key(ki))
            ret = ",".join(ret)
        elif i == 1: #alpn
            ret = []
            while b.remaining() > 0:
                n, = b.unpack("B")
                ret.append(bytearray(b.get(n)))
            ret = cls.zf_format_valuelist(ret)
        elif i == 2: #no-alpn
            if b.remaining() > 0:
                raise DNSError("Error decoding HTTPS SvcParamKey: no-default-alpn should not have a value")
            ret = ""
        elif i == 3: #port
            ret = str(b.unpack("!H")[0])
        elif i == 4: #ipv4
            ret = []
            while b.remaining() > 0:
                ip = "%d.%d.%d.%d" % b.unpack("!4B")
                ret.append(ip)
            ret = ",".join(ret)
        elif i == 5: #ech
            ret = cls.zf_tostr(binascii.b2a_base64(v).rstrip())
        elif i == 6: #ipv6
            ret = []
            while b.remaining() > 0:
                ip = b.unpack("!16B")
                ret.append(_format_ipv6(ip))
            ret = ",".join(ret)
        else:
            ret = cls.zf_tostr(v)
        return k + ("=" + ret if ret else "")

    def __repr__(self):
        pri = str(self.priority)
        targ = ".".join([self.zf_tostr(t) for t in self.target]) + "."
        return " ".join([pri, targ] + [self.zf_format_param(k, v) for k,v in self.params])

class SSHFP(RD):
    """
        SSHFP record as specified in RFC 4255
        https://www.rfc-editor.org/rfc/rfc4255.html
    """

    algorithm = B('algorithm')
    fp_type = B('fp_type')

    @classmethod
    def parse(cls,buffer,length):
        try:
            (algorithm,fp_type) = buffer.unpack("!BB")
            fingerprint = buffer.get(length - 2)
            return cls(algorithm,fp_type,fingerprint)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking DS [offset=%d]: %s" %
                                        (buffer.offset,e))

    @classmethod
    def fromZone(cls,rd,origin=None):
        return cls(int(rd[0]),int(rd[1]),
                   binascii.unhexlify("".join(rd[2:]).encode('ascii')))

    def __init__(self,algorithm,fp_type,fingerprint):
        self.algorithm = algorithm
        self.fp_type = fp_type
        self.fingerprint = _force_bytes(fingerprint)

    def pack(self,buffer):
        buffer.pack("!BB",self.algorithm,self.fp_type)
        buffer.append(self.fingerprint)

    def __repr__(self):
        return "%d %d %s" % (
                        self.algorithm,
                        self.fp_type,
                        binascii.hexlify(self.fingerprint).decode().upper())

    attrs = ('algorithm','fp_type','fingerprint')

class TLSA(RD):
    """
        TLSA record as specified in RFC 6698
        https://www.rfc-editor.org/rfc/rfc6698
    """

    cert_usage = B('cert_usage')
    selector = B('selector')
    matching_type = B('matching_type')

    @classmethod
    def parse(cls,buffer,length):
        try:
            (cert_usage,selector,matching_type) = buffer.unpack("!BBB")
            cert_data = buffer.get(length - 3)
            return cls(cert_usage,selector,matching_type,cert_data)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking DS [offset=%d]: %s" %
                                        (buffer.offset,e))

    @classmethod
    def fromZone(cls,rd,origin=None):
        return cls(int(rd[0]),int(rd[1]),int(rd[2]),
                   binascii.unhexlify("".join(rd[3:]).encode('ascii')))

    def __init__(self,cert_usage,selector,matching_type,cert_data):
        self.cert_usage = cert_usage
        self.selector = selector
        self.matching_type = matching_type
        self.cert_data = _force_bytes(cert_data)

    def pack(self,buffer):
        buffer.pack("!BBB",self.cert_usage,self.selector,self.matching_type)
        buffer.append(self.cert_data)

    def __repr__(self):
        return "%d %d %d %s" % (
                        self.cert_usage,
                        self.selector,
                        self.matching_type,
                        binascii.hexlify(self.cert_data).decode().upper())

    attrs = ('cert_usage','selector','matching_type','cert_data')

class LOC(RD):
    """
        LOC record as specified in RFC 1876

        >>> LOC(37.236693, -115.804069, 1381.0)
        37 14 12.094 N 115 48 14.649 W 1381.00m
        >>> LOC(37.236693, -115.804069, 1381.0, 3000.0, 1.0, 1.0)
        37 14 12.094 N 115 48 14.649 W 1381.00m 3000.00m 1.00m 1.00m
        >>> a = DNSRecord(DNSHeader(id=1456))
        >>> a.add_answer(*RR.fromZone('area51.local. 60 IN LOC 37 14 12.094 N 115 48 14.649 W 1381.00m'))
        >>> a.add_answer(*RR.fromZone('area51.local. 60 IN LOC 37 N 115 48 W 1381.00m'))
        >>> a.add_answer(*RR.fromZone('area51.local. 60 IN LOC 37 14 12.094 N 115 48 14.649 W 1381.00m 1m 10000m 10m'))
        >>> print(a)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1456
        ;; flags: rd; QUERY: 0, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 0
        ;; ANSWER SECTION:
        area51.local.           60      IN      LOC     37 14 12.094 N 115 48 14.649 W 1381.00m
        area51.local.           60      IN      LOC     37 N 115 48 W 1381.00m
        area51.local.           60      IN      LOC     37 14 12.094 N 115 48 14.649 W 1381.00m
    """

    @classmethod
    def parse(cls, buffer, length):
        try:
            (_, siz, hp, vp) = buffer.unpack('!BBBB')
            (lat, lon, alt) = buffer.unpack('!III')
            self = cls.__new__(cls)
            self._lat = lat
            self._lon = lon
            self._alt = alt
            self._siz = siz
            self._hp = hp
            self._vp = vp
            return self
        except (BufferError, BimapError) as e:
            raise DNSError("Error unpacking LOC [offset=%d]: %s" %
                                        (buffer.offset,e))

    @classmethod
    def fromZone(cls, rd, origin=None):
        args = []
        # We still support Python 2.7 so use nonlocal workaround 
        class context:
            idx = 0
        tofloat = lambda x: float(x[:-1])  # get float from "100.0m"
        def todecimal(chars):
            decimal = 0.0
            multiplier = 1
            for c in chars:
                if c in rd:
                    nxt = rd.index(c)
                    if c in ('S', 'W'):
                        multiplier = -1
                    break
            else:
                raise DNSError('Missing cardinality [{chars}]'.format(chars=chars))
            for n, d in zip(rd[context.idx:nxt], (1, 60, 3600)):
                decimal += float(n) / d
            context.idx = nxt + 1
            return decimal * multiplier

        args.append(todecimal('NS'))
        args.append(todecimal('EW'))

        try:
            while True:
                args.append(tofloat(rd[context.idx]))
                context.idx += 1
        except IndexError:
            return cls(*args)

    def __init__(self, lat, lon, alt, siz=1.0, hp=10000.0, vp=10.0):
        self._lat = int(lat * 3600000 + pow(2, 31))
        self._lon = int(lon * 3600000 + pow(2, 31))
        self._alt = int((alt + 100000) * 100)
        self._siz = LOC.__tosiz(siz)
        self._hp = LOC.__tosiz(hp)
        self._vp = LOC.__tosiz(vp)

    def pack(self, buffer):
        buffer.pack("!BBBB", 0, self._siz, self._hp, self._vp)
        buffer.pack("!III", self._lat, self._lon, self._alt)

    @property
    def siz(self):
        return self.__reprsiz(self._siz)

    @property
    def hp(self):
        return self.__reprsiz(self._hp)

    @property
    def vp(self):
        return self.__reprsiz(self._vp)

    @property
    def lat(self):
        c = 'N' if self._lat > pow(2, 31) else 'S'
        return self._reprcoord(self._lat, c)

    @property
    def lon(self):
        c = 'E' if self._lon > pow(2, 31) else 'W'
        return self._reprcoord(self._lon, c)

    @property
    def alt(self):
        return self._alt / 100 - 100000

    @staticmethod
    def _reprcoord(value, c):
        base = abs(pow(2, 31) - value)
        d = base // 3600000
        m = base % 3600000 // 60000
        s = base % 3600000 % 60000 / 1000.0

        if int(s) == 0:
            if m == 0:
                return '{d} {c}'.format(c=c,d=d)
            else:
                return '{d} {m} {c}'.format(d=d,m=m,c=c)
        return '{d} {m} {s:.3f} {c}'.format(d=d,m=m,s=s,c=c)

    def __repr__(self):
        DEFAULT_SIZ = 0x12  # 1m
        DEFAULT_HP = 0x16   # 10,000m
        DEFAULT_VP = 0x13   # 10m

        result = '{self.lat} {self.lon} {self.alt:.2f}m'.format(self=self)

        if self._vp != DEFAULT_VP:
            result += ' {self.siz:.2f}m {self.hp:.2f}m {self.vp:.2f}m'.format(self=self)
        elif self._hp != DEFAULT_HP:
            result += ' {self.siz:.2f}m {self.hp:.2f}m'.format(self=self)
        elif self._siz != DEFAULT_SIZ:
            result += ' {self.siz:.2f}m'.format(self=self)

        return result

    @staticmethod
    def __tosiz(v):
        if int(v) == 0:
            return 0
        e = 0
        v *= 100
        while v >= 10 and e < 9:
            v /= 10
            e += 1
        v = int(round(v))
        if v >= 10:
            raise DNSError("Value out of range")
        return v << 4 | e

    @staticmethod
    def __reprsiz(v):
        b = v >> 4
        e = v & 0x0F
        if b > 9 or e > 9 or (b == 0 and e > 0):
            raise DNSError("Value out of range")
        return b * pow(10, e) / 100

class RP(RD):
     """
     RP record as specified in RFC 1183.
     https://datatracker.ietf.org/doc/html/rfc1183
     """
     @classmethod
     def parse(cls,buffer,length):
         try:
             mbox = buffer.decode_name()
             txt = buffer.decode_name()
             return cls(mbox, txt)
         except (BufferError,BimapError) as e:
             raise DNSError("Error unpacking RP [offset=%d]: %s" %
                                         (buffer.offset,e))

     @classmethod
     def fromZone(cls,rd,origin=None):
         return cls(label(rd[0],origin),label(rd[1],origin))

     def __init__(self,mbox=None, txt=None):
         self.mbox = mbox
         self.txt = txt

     def set_mbox(self,mbox):
         if isinstance(mbox,DNSLabel):
             self._mbox = mbox
         else:
             self._mbox = DNSLabel(mbox)

     def get_mbox(self):
         return self._mbox

     mbox = property(get_mbox,set_mbox)

     def set_txt(self,txt):
         if isinstance(txt,DNSLabel):
             self._txt = txt
         else:
             self._txt = DNSLabel(txt)

     def get_txt(self):
         return self._txt

     txt = property(get_txt,set_txt)

     def pack(self,buffer):
         buffer.encode_name(self.mbox)
         buffer.encode_name(self.txt)

     def __repr__(self):
         return "%s %s" % (self.mbox,self.txt)

     attrs = ('mbox','txt')

# Map from RD type to class (used to pack/unpack records)
# If you add a new RD class you must add to RDMAP

RDMAP = { 'CNAME':CNAME, 'A':A, 'AAAA':AAAA, 'TXT':TXT, 'MX':MX,
          'PTR':PTR, 'SOA':SOA, 'NS':NS, 'NAPTR': NAPTR, 'SRV':SRV,
          'DNSKEY':DNSKEY, 'RRSIG':RRSIG, 'NSEC':NSEC, 'CAA':CAA,
          'HTTPS': HTTPS, 'DS':DS, 'SSHFP':SSHFP, 'TLSA':TLSA, 'LOC':LOC,
          'RP':RP,
        }

##
## Zone parser
## TODO  - ideally this would be in a separate file but have to deal
##         with circular dependencies
##

secs = {'s':1,'m':60,'h':3600,'d':86400,'w':604800}

def parse_time(s):
    """
        Parse time spec with optional s/m/h/d/w suffix
    """
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

if __name__ == '__main__':
    import doctest,sys
    sys.exit(0 if doctest.testmod(optionflags=doctest.ELLIPSIS).failed == 0 else 1)
