# -*- coding: utf-8 -*-

from __future__ import print_function

import binascii,random,socket,struct,textwrap
from itertools import chain

from dnslib.bit import get_bits,set_bits
from dnslib.bimap import Bimap, BimapError
from dnslib.buffer import Buffer, BufferError
from dnslib.label import DNSLabel,DNSLabelError,DNSBuffer
from dnslib.zone import ZoneParser

QTYPE =  Bimap('QTYPE', {1:'A', 2:'NS', 5:'CNAME', 6:'SOA', 12:'PTR', 15:'MX',
                16:'TXT', 17:'RP', 18:'AFSDB', 24:'SIG', 25:'KEY', 28:'AAAA',
                29:'LOC', 33:'SRV', 35:'NAPTR', 36:'KX', 37:'CERT', 39:'DNAME',
                41:'OPT', 42:'APL', 43:'DS', 44:'SSHFP', 45:'IPSECKEY',
                46:'RRSIG', 47:'NSEC', 48:'DNSKEY', 49:'DHCID', 50:'NSEC3',
                51:'NSEC3PARAM', 55:'HIP', 99:'SPF', 249:'TKEY', 250:'TSIG',
                251:'IXFR', 252:'AXFR', 255:'ANY', 32768:'TA', 32769:'DLV'})

CLASS =  Bimap('CLASS',{1:'IN', 2:'CS', 3:'CH', 4:'Hesiod', 254:'None', 255:'*'})
QR =     Bimap('QR',{0:'QUERY', 1:'RESPONSE'})
RCODE =  Bimap('RCODE',{0:'No Error', 1:'Format Error', 2:'Server failure', 
                 3:'Name Error', 4:'Not Implemented', 5:'Refused', 6:'YXDOMAIN',
                 7:'YXRRSET', 8:'NXRRSET', 9:'NOTAUTH', 10:'NOTZONE'})
OPCODE = Bimap('OPCODE',{0:'QUERY', 1:'IQUERY', 2:'STATUS', 5:'UPDATE'})

class DNSError(Exception):
    pass

class DNSRecord(object):

    """
        Main DNSRecord class

        Comprises following sections

            header      : DNSHeader
            question    : DNSQuestion x n
            answer      : RR x n
            ns          : RR x n
            ar          : RR x n
    """

    @classmethod
    def parse(cls,packet):
        """
            Parse DNS packet data and return DNSRecord instance
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
                ns.append(RR.parse(buffer))
            for i in range(header.ar):
                ar.append(RR.parse(buffer))
            return cls(header,questions,rr,auth=auth,ar=ar)
        except DNSError:
            raise
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking DNSRecord [offset=%d]: %s" % (
                                    buffer.offset,e))

    def __init__(self,header=None,questions=None,
                      rr=None,q=None,a=None,auth=None,ar=None):
        """
            Create DNSRecord
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

    def replyZone(self,zone,ra=1,aa=1):
        return DNSRecord(DNSHeader(id=self.header.id,
                                   bitmap=self.header.bitmap,
                                   qr=1,ra=ra,aa=aa),
                         q=self.q,
                         rr=RR.fromZone(zone))

    def reply(self,data=None,ra=1,aa=1):
        if data:
            answer = RDMAP.get(QTYPE[self.q.qtype],RD)(data)
            return DNSRecord(DNSHeader(id=self.header.id,
                                       bitmap=self.header.bitmap,
                                       qr=1,ra=ra,aa=aa),
                             q=self.q,
                             a=RR(self.q.qname,self.q.qtype,rdata=answer))
        else:
            return DNSRecord(DNSHeader(id=self.header.id,
                                       bitmap=self.header.bitmap,
                                       qr=1,ra=ra,aa=aa),
                             q=self.q)

    def add_question(self,q):
        self.questions.append(q)
        self.set_header_qa()

    def add_answer(self,rr):
        self.rr.append(rr)
        self.set_header_qa()

    def add_auth(self,auth):
        self.auth.append(auth)
        self.set_header_qa()

    def add_ar(self,ar):
        self.ar.append(ar)
        self.set_header_qa()

    def set_header_qa(self):
        self.header.q = len(self.questions)
        self.header.a = len(self.rr)
        self.header.auth = len(self.auth)
        self.header.ar = len(self.ar)

    # Shortcut to get first question
    def get_q(self):
        return self.questions[0]
    q = property(get_q)

    # Shortcut to get first answer
    def get_a(self):
        return self.rr[0]
    a = property(get_a)

    def pack(self):
        self.set_header_qa()
        buffer = DNSBuffer()
        self.header.pack(buffer)
        for q in self.questions:
            q.pack(buffer)
        for rr in self.rr:
            rr.pack(buffer)
        for ns in self.auth:
            auth.pack(buffer)
        for ar in self.ar:
            ar.pack(buffer)
        return buffer.data

    def send(self,dest,port=53):
        sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        sock.sendto(self.pack(),(dest,port))
        response,server = sock.recvfrom(8192)
        sock.close()
        return DNSRecord.parse(response)
        
    def format(self,prefix=""):
        sections = [ str(self.header) ]
        sections.extend([str(q) for q in self.questions])
        sections.extend([str(rr) for rr in self.rr])
        sections.extend([str(rr) for rr in self.auth])
        sections.extend([str(rr) for rr in self.ar])
        return prefix + ("\n" + prefix).join(sections)

    def toZone(self,prefix=""):
        sections = self.header.toZone()
        if self.questions:
            sections.append(";; QUESTION SECTION")
            sections.extend([q.toZone() for q in self.questions])
        if self.rr:
            sections.append(";; ANSWER SECTION")
            sections.extend([rr.toZone() for rr in self.rr])
        if self.auth:
            sections.append(";; AUTHORITY SECTION")
            sections.extend([rr.toZone() for rr in self.auth])
        if self.ar:
            sections.append(";; ADDITIONAL SECTION")
            sections.extend([rr.toZone() for rr in self.ar])
        return prefix + ("\n" + prefix).join(sections)

    def __repr__(self):
        return self.format()

class DNSHeader(object):

    @classmethod
    def parse(cls,buffer):
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
            elif k.lower() == "rcode":
                self.rcode = v
    
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
              self.ra and 'RA' ] 
        if OPCODE[self.opcode] == 'UPDATE':
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
                    QR[self.qr],
                    OPCODE[self.opcode],
                    ",".join(filter(None,f)),
                    RCODE[self.rcode],
                    f1, self.q, f2, self.a, f3, self.auth, f4, self.ar )

    def toZone(self):
        f = [ self.aa and 'aa', 
              self.tc and 'tc', 
              self.rd and 'rd', 
              self.ra and 'ra' ] 
        z1 = ';; ->>HEADER<<- opcode: %s, status: %s, id: %d' % (
                    QR[self.qr],RCODE[self.rcode],self.id)
        z2 = ';; flags: %s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d' % (
                      " ".join(filter(None,f)),
                      self.q,self.a,self.auth,self.ar)
        return [z1,z2]

class DNSQuestion(object):
    
    @classmethod
    def parse(cls,buffer):
        try:
            qname = buffer.decode_name()
            qtype,qclass = buffer.unpack("!HH")
            return cls(qname,qtype,qclass)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking DNSQuestion [offset=%d]: %s" % (
                                buffer.offset,e))

    def __init__(self,qname=[],qtype=1,qclass=1):
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

    def __repr__(self):
        return "<DNS Question: %r qtype=%s qclass=%s>" % (
                    self.qname, QTYPE[self.qtype], CLASS[self.qclass])

    def toZone(self):
       return ';%-31s%-8s%-8s' % (self.qname,CLASS[self.qclass],
                                             QTYPE[self.qtype])
            
class EDNSOption(object):

    def __init__(self,code,data):
        self.code = code
        self.data = data

    def pack(self,buffer):
        buffer.pack("!HH",self.code,len(self.data))
        buffer.append(self.data)

    def __repr__(self):
        return "<EDNS Option: Code=%d Data='%s'>" % (self.code,self.data)

class RR(object):

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
                    rdata = RDMAP.get(QTYPE[rtype],RD).parse(buffer,rdlength)
                else:
                    rdata = ''
            return cls(rname,rtype,rclass,ttl,rdata)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking RR [offset=%d]: %s" % (
                                buffer.offset,e))

    @classmethod
    def fromZone(cls,zone):
        return [ cls(rname=rr[0],
                     ttl=rr[1], 
                     rclass=getattr(CLASS,rr[2]),
                     rtype=getattr(QTYPE,rr[3]),
                     rdata=RDMAP.get(rr[3],RD).fromZone(rr[4])) 
                 for rr in ZoneParser(zone) ]

    def __init__(self,rname=None,rtype=1,rclass=1,ttl=0,rdata=None):
        self.rname = rname or []
        if type(rtype) != int:
            self.rtype = QTYPE[rtype]
        else:
            self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.rdata = rdata

    def set_rname(self,rname):
        if isinstance(rname,DNSLabel):
            self._rname = rname
        else:
            self._rname = DNSLabel(rname)

    def get_rname(self):
        return self._rname

    rname = property(get_rname,set_rname)

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
            s = ["<DNS OPT: udp_len=%d rcode=%d>" % (self.rclass,self.ttl)]
            s.extend([str(opt) for opt in self.rdata])
            return "\n".join(s)
        else:
            return "<DNS RR: %r rtype=%s rclass=%s ttl=%d rdata='%s'>" % (
                    self.rname, QTYPE[self.rtype], CLASS[self.rclass], 
                    self.ttl, self.rdata)

    def toZone(self):
       return '%-24s%-8s%-8s%-8s%s' % (self.rname,self.ttl,CLASS[self.rclass],
                                       QTYPE[self.rtype],self.rdata.toZone())

class RD(object):

    @classmethod
    def parse(cls,buffer,length):
        try:
            data = buffer.get(length)
            return cls(data)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking RD [offset=%d]: %s" % 
                                    (buffer.offset,e))

    @classmethod
    def fromZone(cls,rd):
        return cls(rd)

    def __init__(self,data=b""):
        if type(data) != bytes:
            self.data = data.encode()
        else:
            self.data = data

    def pack(self,buffer):
        buffer.append(self.data)

    def __repr__(self):
        try:
            return self.data.decode()
        except UnicodeDecodeError:
            return binascii.hexlify(self.data).decode()

    def toZone(self):
        return repr(self)

class TXT(RD):

    @classmethod
    def parse(cls,buffer,length):
        try:
            (txtlength,) = buffer.unpack("!B")
            # First byte is TXT length (not in RFC?)
            if txtlength < length:
                data = buffer.get(txtlength)
            else:
                raise DNSError("Invalid TXT record: len(%d) > RD len(%d)" % 
                                        (txtlength,length))
            return cls(data)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking TXT [offset=%d]: %s" % 
                                        (buffer.offset,e))

    @classmethod
    def fromZone(cls,rd):
        return cls(rd[0])

    def pack(self,buffer):
        if len(self.data) > 255:
            raise DNSError("TXT record too long: %s" % self.data)
        buffer.pack("!B",len(self.data))
        buffer.append(self.data)

    def toZone(self):
        return '"%s"' % repr(self)

class A(RD):

    @classmethod
    def parse(cls,buffer,length):
        try:
            data = buffer.unpack("!BBBB")
            return cls(data)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking A [offset=%d]: %s" % 
                                (buffer.offset,e))

    @classmethod
    def fromZone(cls,rd):
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

        >>> _parse_ipv6("::") == [0] * 16
        True
        >>> _parse_ipv6("1234:5678::abcd:0:ff00")
        [18, 52, 86, 120, 0, 0, 0, 0, 0, 0, 171, 205, 0, 0, 255, 0]

    """
    l,_,r = a.partition("::")
    l_groups = list(chain(*[divmod(int(x,16),256) for x in l.split(":") if x]))
    r_groups = list(chain(*[divmod(int(x,16),256) for x in r.split(":") if x]))
    zeros = [0] * (16 - len(l_groups) - len(r_groups))
    return l_groups + zeros + r_groups 

def _format_ipv6(a):
    """
        Format IPv6 address (from tuple of 16 bytes) compressing sequence of
        sero bytes to '::'. Ideally we would use the ipaddress module in
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
 
    @classmethod
    def parse(cls,buffer,length):
        try:
            data = buffer.unpack("!16B")
            return cls(data)
        except (BufferError,BimapError) as e:
            raise DNSError("Error unpacking AAAA [offset=%d]: %s" % 
                                        (buffer.offset,e))
 
    @classmethod
    def fromZone(cls,rd):
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
    def fromZone(cls,rd):
        return cls(rd[1],int(rd[0]))

    def __init__(self,label=None,preference=10):
        self.label = label or []
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
        return "%d:%s" % (self.preference,self.label)

    def toZone(self):
        return "%d %s" % (self.preference,self.label)

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
    def fromZone(cls,rd):
        return cls(rd[0])

    def __init__(self,label=[]):
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

class PTR(CNAME):
    pass

class NS(CNAME):
    pass

class SOA(RD):
        
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
    def fromZone(cls,rd):
        return cls(rd[0],rd[1],[int(t) for t in rd[2:]])

    def __init__(self,mname=None,rname=None,times=None):
        self.mname = mname or []
        self.rname = rname or []
        self.times = times or (0,0,0,0,0)

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
        return "%s:%s:%s"%(self.mname,self.rname,":".join(map(str,self.times)))

    def toZone(self):
        return "( %s %s %s )" % (self.mname,self.rname,
                                 " ".join(map,str,self.times))

class NAPTR(RD):

    def __init__(self,order,preference,flags,service,regexp,replacement=None):
        self.order = order
        self.preference = preference
        self.flags = flags
        self.service = service
        self.regexp = regexp
        self.replacement = replacement or DNSLabel([])

    @classmethod
    def fromZone(cls,rd):
        raise ValueError

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
            self.service.decode(),self.regexp.decode(),
            self.replacement or '.'
        )

RDMAP = { 'CNAME':CNAME, 'A':A, 'AAAA':AAAA, 'TXT':TXT, 'MX':MX, 
          'PTR':PTR, 'SOA':SOA, 'NS':NS, 'NAPTR': NAPTR}

def _unpack(s):
    return  DNSRecord.parse(binascii.unhexlify(s))

def test_unpack(s):
    """
    Test decoding with sample DNS packets captured from server/udp_proxy.py

    >>> def _dump(s):
    ...     print(_unpack(s))

    Standard query A www.google.com
        >>> _dump(b'd5ad010000010000000000000377777706676f6f676c6503636f6d0000010001')
        <DNS Header: id=0xd5ad type=QUERY opcode=QUERY flags=RD rcode='No Error' q=1 a=0 ns=0 ar=0>
        <DNS Question: 'www.google.com' qtype=A qclass=IN>

    Standard query response CNAME www.l.google.com A 66.249.91.104 A 66.249.91.99 A 66.249.91.103 A 66.249.91.147
        >>> _dump(b'd5ad818000010005000000000377777706676f6f676c6503636f6d0000010001c00c0005000100000005000803777777016cc010c02c0001000100000005000442f95b68c02c0001000100000005000442f95b63c02c0001000100000005000442f95b67c02c0001000100000005000442f95b93')
        <DNS Header: id=0xd5ad type=RESPONSE opcode=QUERY flags=RD,RA rcode='No Error' q=1 a=5 ns=0 ar=0>
        <DNS Question: 'www.google.com' qtype=A qclass=IN>
        <DNS RR: 'www.google.com' rtype=CNAME rclass=IN ttl=5 rdata='www.l.google.com'>
        <DNS RR: 'www.l.google.com' rtype=A rclass=IN ttl=5 rdata='66.249.91.104'>
        <DNS RR: 'www.l.google.com' rtype=A rclass=IN ttl=5 rdata='66.249.91.99'>
        <DNS RR: 'www.l.google.com' rtype=A rclass=IN ttl=5 rdata='66.249.91.103'>
        <DNS RR: 'www.l.google.com' rtype=A rclass=IN ttl=5 rdata='66.249.91.147'>

    Standard query MX google.com
        >>> _dump(b'95370100000100000000000006676f6f676c6503636f6d00000f0001')
        <DNS Header: id=0x9537 type=QUERY opcode=QUERY flags=RD rcode='No Error' q=1 a=0 ns=0 ar=0>
        <DNS Question: 'google.com' qtype=MX qclass=IN>

    Standard query response MX 10 smtp2.google.com MX 10 smtp3.google.com MX 10 smtp4.google.com MX 10 smtp1.google.com
        >>> _dump(b'95378180000100040000000006676f6f676c6503636f6d00000f0001c00c000f000100000005000a000a05736d747032c00cc00c000f000100000005000a000a05736d747033c00cc00c000f000100000005000a000a05736d747034c00cc00c000f000100000005000a000a05736d747031c00c')
        <DNS Header: id=0x9537 type=RESPONSE opcode=QUERY flags=RD,RA rcode='No Error' q=1 a=4 ns=0 ar=0>
        <DNS Question: 'google.com' qtype=MX qclass=IN>
        <DNS RR: 'google.com' rtype=MX rclass=IN ttl=5 rdata='10:smtp2.google.com'>
        <DNS RR: 'google.com' rtype=MX rclass=IN ttl=5 rdata='10:smtp3.google.com'>
        <DNS RR: 'google.com' rtype=MX rclass=IN ttl=5 rdata='10:smtp4.google.com'>
        <DNS RR: 'google.com' rtype=MX rclass=IN ttl=5 rdata='10:smtp1.google.com'>

    Standard query PTR 103.91.249.66.in-addr.arpa
        >>> _dump(b'b38001000001000000000000033130330239310332343902363607696e2d61646472046172706100000c0001')
        <DNS Header: id=0xb380 type=QUERY opcode=QUERY flags=RD rcode='No Error' q=1 a=0 ns=0 ar=0>
        <DNS Question: '103.91.249.66.in-addr.arpa' qtype=PTR qclass=IN>

    Standard query response PTR ik-in-f103.google.com
        >>> _dump(b'b38081800001000100000000033130330239310332343902363607696e2d61646472046172706100000c0001c00c000c00010000000500170a696b2d696e2d6631303306676f6f676c6503636f6d00')
        <DNS Header: id=0xb380 type=RESPONSE opcode=QUERY flags=RD,RA rcode='No Error' q=1 a=1 ns=0 ar=0>
        <DNS Question: '103.91.249.66.in-addr.arpa' qtype=PTR qclass=IN>
        <DNS RR: '103.91.249.66.in-addr.arpa' rtype=PTR rclass=IN ttl=5 rdata='ik-in-f103.google.com'>

    Standard query TXT google.com

        >>> _dump(b'c89f0100000100000000000006676f6f676c6503636f6d0000100001')
        <DNS Header: id=0xc89f type=QUERY opcode=QUERY flags=RD rcode='No Error' q=1 a=0 ns=0 ar=0>
        <DNS Question: 'google.com' qtype=TXT qclass=IN>

    Standard query response TXT
        >>> _dump(b'c89f8180000100010000000006676f6f676c6503636f6d0000100001c00c0010000100000005002a29763d7370663120696e636c7564653a5f6e6574626c6f636b732e676f6f676c652e636f6d207e616c6c')
        <DNS Header: id=0xc89f type=RESPONSE opcode=QUERY flags=RD,RA rcode='No Error' q=1 a=1 ns=0 ar=0>
        <DNS Question: 'google.com' qtype=TXT qclass=IN>
        <DNS RR: 'google.com' rtype=TXT rclass=IN ttl=5 rdata='v=spf1 include:_netblocks.google.com ~all'>

    Standard query SOA google.com
        >>> _dump(b'28fb0100000100000000000006676f6f676c6503636f6d0000060001')
        <DNS Header: id=0x28fb type=QUERY opcode=QUERY flags=RD rcode='No Error' q=1 a=0 ns=0 ar=0>
        <DNS Question: 'google.com' qtype=SOA qclass=IN>

    Standard query response SOA ns1.google.com
        >>> _dump(b'28fb8180000100010000000006676f6f676c6503636f6d0000060001c00c00060001000000050026036e7331c00c09646e732d61646d696ec00c77b1566d00001c2000000708001275000000012c')
        <DNS Header: id=0x28fb type=RESPONSE opcode=QUERY flags=RD,RA rcode='No Error' q=1 a=1 ns=0 ar=0>
        <DNS Question: 'google.com' qtype=SOA qclass=IN>
        <DNS RR: 'google.com' rtype=SOA rclass=IN ttl=5 rdata='ns1.google.com:dns-admin.google.com:2008110701:7200:1800:1209600:300'>

    Standard query response NAPTR sip2sip.info
        >>> _dump(b'740481800001000300000000077369703273697004696e666f0000230001c00c0023000100000c940027001e00640173075349502b44325500045f736970045f756470077369703273697004696e666f00c00c0023000100000c940027000a00640173075349502b44325400045f736970045f746370077369703273697004696e666f00c00c0023000100000c94002900140064017308534950532b44325400055f73697073045f746370077369703273697004696e666f00')
        <DNS Header: id=0x7404 type=RESPONSE opcode=QUERY flags=RD,RA rcode='No Error' q=1 a=3 ns=0 ar=0>
        <DNS Question: 'sip2sip.info' qtype=NAPTR qclass=IN>
        <DNS RR: 'sip2sip.info' rtype=NAPTR rclass=IN ttl=3220 rdata='30 100 "s" "SIP+D2U" "" _sip._udp.sip2sip.info'>
        <DNS RR: 'sip2sip.info' rtype=NAPTR rclass=IN ttl=3220 rdata='10 100 "s" "SIP+D2T" "" _sip._tcp.sip2sip.info'>
        <DNS RR: 'sip2sip.info' rtype=NAPTR rclass=IN ttl=3220 rdata='20 100 "s" "SIPS+D2T" "" _sips._tcp.sip2sip.info'>

    Standard query response NAPTR 0.0.0.0.1.1.1.3.9.3.0.1.8.7.8.e164.org
        >>> _dump(b'aef0818000010001000000000130013001300130013101310131013301390133013001310138013701380465313634036f72670000230001c00c002300010000a6a300320064000a0175074532552b53495022215e5c2b3f282e2a2924217369703a5c5c31406677642e70756c7665722e636f6d2100')
        <DNS Header: id=0xaef0 type=RESPONSE opcode=QUERY flags=RD,RA rcode='No Error' q=1 a=1 ns=0 ar=0>
        <DNS Question: '0.0.0.0.1.1.1.3.9.3.0.1.8.7.8.e164.org' qtype=NAPTR qclass=IN>
        <DNS RR: '0.0.0.0.1.1.1.3.9.3.0.1.8.7.8.e164.org' rtype=NAPTR rclass=IN ttl=42659 rdata='100 10 "u" "E2U+SIP" "!^\+?(.*)$!sip:\\\\1@fwd.pulver.com!" .'>

    EDNS0 OPT record 
    ** this doesnt look right but don't have any other sample data **

        >>> _dump(b'896f010000010000000000010661613332343703636f6d0000010001000029100000000000000c50fa000800012000d99f29cf')
        <DNS Header: id=0x896f type=QUERY opcode=QUERY flags=RD rcode='No Error' q=1 a=0 ns=0 ar=1>
        <DNS Question: 'aa3247.com' qtype=A qclass=IN>
        <DNS OPT: udp_len=4096 rcode=0>
        <EDNS Option: Code=20730 Data=...>

    """
    pass


if __name__ == '__main__':
    import doctest
    doctest.testmod(optionflags=doctest.ELLIPSIS)
