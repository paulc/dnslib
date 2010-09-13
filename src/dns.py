
import struct 

from bit import get_bits,set_bits
from map import Map

TYPE =   Map({ 1:'A', 2:'NS', 3:'MD', 4:'MF', 5:'CNAME', 6:'SOA', 7:'MB', 
               8:'MG', 9:'MR', 10:'NULL', 11:'WKS', 12:'PTR', 13:'HINFO',
               14:'MINFO', 15:'MX', 16:'TXT',252:'AXFR',253:'MAILB',
               254:'MAILA',255:'*'})
CLASS =  Map({ 1:'IN', 2:'CS', 3:'CH', 4:'Hesiod', 255:'*'})
QR =     Map({ 0:'QUERY', 1:'RESPONSE' })
RCODE =  Map({ 0:'None', 1:'Format Error', 2:'Server failure', 
               3:'Name Error', 4:'Not Implemented', 5:'Refused' })
OPCODE = Map({ 0:'QUERY', 1:'IQUERY', 2:'STATUS' })

def encode_name(name):
    label = name.split(".")
    data = []
    for l in label:
        if len(l) > 255:
            raise DNSError("Label too long: %s: " % name)
        data.append(struct.pack("!B",len(l)))
        data.append(l)
    data.append("\x00")
    return "".join(data)

def decode_name(packet,offset=0):
    label = []
    data = packet[offset:]
    index = 0
    done = False
    while not done:
        len = struct.unpack("!B",data[index])[0]
        if get_bits(len,6,2) == 3:
            pointer = get_bits(struct.unpack("!H",data[index:index+2])[0],0,14)
            ref,_ = decode_name(packet,pointer)
            label.append(ref)
            index += 2
            done = True
        else:
            index += 1
            if len > 0:
                label.append(data[index:index+len])
                index += len
            else:
                done = True
    return ".".join(label),offset+index

class DNSError(Exception):
    pass

class DNSRecord(object):

    @classmethod
    def parse(cls,packet):
        c = cls()
        c.unpack(packet)
        return c

    def __init__(self,header=None,question=None,rr=None):
        self.header = header or DNSHeader()
        self.question = question or []
        self.rr = rr or []

    def pack(self):
        # TODO: Track q/rr count automatically in header
        self.header.q = len(self.question)
        self.header.a = len(self.rr)
        fields = [ self.header.pack() ]
        for q in self.question:
            fields.append(q.pack())
        for rr in self.rr:
            fields.append(rr.pack())
        return "".join(fields)

    def unpack(self,packet):
        self.header.unpack(packet)
        offset = 12
        for i in range(self.header.q):
            q = DNSQuestion()
            offset = q.unpack(packet,offset)
            self.question.append(q)
        for i in range(self.header.a):
            rr = RR()
            offset = rr.unpack(packet,offset)
            self.rr.append(rr)
        
    def __str__(self):
        sections = [ str(self.header) ]
        sections.extend([str(q) for q in self.question])
        sections.extend([str(rr) for rr in self.rr])
        return "\n".join(sections)

class DNSQuestion(object):
    
    @classmethod
    def parse(cls,packet,offset=0):
        c = cls()
        c.unpack(packet,offset)
        return c

    def __init__(self,qname="",qtype=1,qclass=1):
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass

    def pack(self):
        return encode_name(self.qname) + struct.pack("!HH",self.qtype,self.qclass)

    def unpack(self,packet,offset):
        self.qname, offset = decode_name(packet,offset)
        self.qtype,self.qclass = struct.unpack("!HH",packet[offset:offset+4])
        return offset+4

    def __str__(self):
        return "<DNS Question: '%s' qtype=%s qclass=%s>" % (
                    self.qname, TYPE[self.qtype], CLASS[self.qclass])
            
class DNSHeader(object):

    @classmethod
    def parse(cls,packet):
        c = cls()
        c.unpack(packet)
        return c

    def __init__(self,id=0,flags=0,q=0,a=0,ns=0,ar=0):
        self.id = id 
        self.flags = flags
        self.q = q
        self.a = a
        self.ns = ns
        self.ar = ar
    
    def get_qr(self):
        return get_bits(self.flags,15)

    def set_qr(self,val):
        self.flags = set_bits(self.flags,val,15)

    qr = property(get_qr,set_qr)

    def get_opcode(self):
        return get_bits(self.flags,11,4)

    def set_opcode(self,val):
        self.flags = set_bits(self.flags,val,11,4)

    opcode = property(get_opcode,set_opcode)

    def get_aa(self):
        return get_bits(self.flags,10)

    def set_aa(self,val):
        self.flags = set_bits(self.flags,val,10)

    aa = property(get_aa,set_aa)
        
    def get_tc(self):
        return get_bits(self.flags,9)

    def set_tc(self,val):
        self.flags = set_bits(self.flags,val,9)

    tc = property(get_tc,set_tc)
        
    def get_rd(self):
        return get_bits(self.flags,8)

    def set_rd(self,val):
        self.flags = set_bits(self.flags,val,8)

    rd = property(get_rd,set_rd)
        
    def get_ra(self):
        return get_bits(self.flags,7)

    def set_ra(self,val):
        self.flags = set_bits(self.flags,val,7)

    ra = property(get_ra,set_ra)

    def get_rcode(self):
        return get_bits(self.flags,0,4)

    def set_rcode(self,val):
        self.flags = set_bits(self.flags,val,0,4)

    rcode = property(get_rcode,set_rcode)

    def pack(self):
        return struct.pack("!HHHHHH",self.id, self.flags, self.q, self.a, self.ns, self.ar)

    def unpack(self,header):
        ( self.id, 
          self.flags,
          self.q,
          self.a,
          self.ns,
          self.ar ) = struct.unpack("!HHHHHH",header[:12])

    def __str__(self):
        f = [ self.aa and 'AA', 
              self.tc and 'TC', 
              self.rd and 'RD', 
              self.ra and 'RA' ] 
        return "<DNS Header: id=0x%x type=%s opcode=%s flags=%s " \
                            "rcode=%s q=%d a=%d ns=%d ar=%d>" % ( 
                    self.id,
                    QR[self.qr],
                    OPCODE[self.opcode],
                    ",".join(filter(None,f)),
                    RCODE[self.rcode],
                    self.q, self.a, self.ns, self.ar )



class RR(object):

    @classmethod
    def parse(cls,packet,offset=0):
        c = cls()
        c.unpack(packet,offset)
        return c

    def __init__(self,rname="",rtype=1,rclass=1,ttl=0,rdata=None):
        self.rname = rname
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.rdata = rdata

    def get_rdlength(self):
        if self.rdata:
            return self.rdata.get_length()
        else:
            return 0

    def pack(self):
        return encode_name(self.rname) + \
               struct.pack("!HHIH",self.rtype,self.rclass,self.ttl,self.get_rdlength()) + \
               self.rdata.pack()

    def unpack(self,packet,offset):
        self.rname,offset = decode_name(packet,offset)
        data = packet[offset:]
        ( self.rtype,
          self.rclass,
          self.ttl,
          rdlength ) = struct.unpack("!HHIH",data[:10])
        offset += 10
        type = TYPE[self.rtype]
        if type == 'CNAME':
            self.rdata = CNAME()
        elif type == 'A':
            self.rdata = A()
        elif type == 'TXT':
            self.rdata = TXT()
        elif type == 'MX':
            self.rdata = MX()
        elif type == 'PTR':
            self.rdata = PTR()
        elif type == 'SOA':
            self.rdata = SOA()
        else:
            self.rdata = RD()
        self.rdata.unpack(packet,offset,rdlength)
        return offset+rdlength

    def __str__(self):
        return "<DNS RR: '%s' rtype=%s rclass=%s ttl=%d rdlength=%d rdata='%s'>" % (
                    self.rname, TYPE[self.rtype], CLASS[self.rclass],
                    self.ttl, self.get_rdlength(), self.rdata )

class RD(object):

    def __init__(self,data=""):
        self.data = data
        self.rdlength = 0

    def get_length(self):
        return len(self.data)

    def pack(self):
        return self.data

    def unpack(self,packet,offset,rdlength):
        self.data = packet[offset:offset+rdlength]

    def __str__(self):
        return '%s' % self.data

class TXT(RD):

    def get_length(self):
        return len(self.data)+1

    def pack(self):
        if len(self.data) > 255:
            raise DNSError("TXT record too long: %s" % self.data)
        return struct.pack("!B",len(self.data)) + self.data

    def unpack(self,packet,offset,rdlength):
        txtlength = struct.unpack("!B",packet[offset])[0]
        # First byte is TXT length (not in RFC?)
        if txtlength < rdlength:
            self.data = packet[offset+1:offset+txtlength+1]
        else:
            raise DNSError("Invalid TXT record: length (%d) > RD length (%d)" % (txtlength,rdlength))

class A(RD):

    def get_length(self):
        return 4

    def pack(self):
        return struct.pack("!BBBB",*map(int,self.data.split(".")))

    def unpack(self,packet,offset,rdlength):
        ip = struct.unpack("!BBBB",packet[offset:offset+rdlength])
        self.data = "%d.%d.%d.%d" % ip

class MX(RD):

    def __init__(self,mx="",preference="10"):
        self.mx = mx
        self.preference = preference
        self.rdlength = 0

    def get_length(self):
        if self.rdlength:
            return self.rdlength
        else:
            return len(encode_name(self.mx)) + 2

    def pack(self):
        return struct.pack("!H",self.preference) + self.encode_name(self.mx)
        
    def unpack(self,packet,offset,rdlength):
        self.rdlength = rdlength
        self.preference = struct.unpack("!H",packet[offset:offset+2])[0]
        self.mx,_ = decode_name(packet,offset+2)

    def __str__(self):
        return "%d:%s" % (self.preference,self.mx)

class CNAME(RD):
        
    def get_length(self):
        if self.rdlength:
            return self.rdlength
        else:
            return len(encode_name(self.data)) 

    def pack(self):
        return self.encode_name(self.data)

    def unpack(self,packet,offset,rdlength):
        self.rdlength = rdlength
        self.data,_ = decode_name(packet,offset)

class PTR(CNAME):
    pass

class SOA(RD):
        
    def __init__(self,mname="",rname="",times=None):
        self.mname = mname
        self.rname = rname
        self.times = times or (0,0,0,0,0)
        self.rdlength = 0

    def get_length(self):
        if self.rdlength:
            return self.rdlength
        else:
            return len(encode_name(self.mname)) + len(encode_name(self.rname)) + 20

    def pack(self):
        return encode_name(self.mname) + encode_name(self.rname) + \
                    struct.pack("!IIIII", *self.times)

    def unpack(self,packet,offset,rdlength):
        self.rdlength = rdlength
        self.mname,offset = decode_name(packet,offset)
        self.rname,offset = decode_name(packet,offset)
        self.times = struct.unpack("!IIIII",packet[offset:offset+20])

    def __str__(self):
        return "%s:%s:%s" % (self.mname,self.rname,":".join(map(str,self.times)))



if __name__ == '__main__':
    """

    Test decoding with sample DNS packets captured from Wireshark

    >>> def unpack(s):
    ...     d = DNSRecord.parse(s.decode('hex'))
    ...     print d

    Standard query A www.google.com
        >>> unpack('d5ad010000010000000000000377777706676f6f676c6503636f6d0000010001')
        <DNS Header: id=0xd5ad type=QUERY opcode=QUERY flags=RD rcode=None q=1 a=0 ns=0 ar=0>
        <DNS Question: 'www.google.com' qtype=A qclass=IN>

    Standard query response CNAME www.l.google.com A 66.249.91.104 A 66.249.91.99 A 66.249.91.103 A 66.249.91.147
        >>> unpack('d5ad818000010005000000000377777706676f6f676c6503636f6d0000010001c00c0005000100000005000803777777016cc010c02c0001000100000005000442f95b68c02c0001000100000005000442f95b63c02c0001000100000005000442f95b67c02c0001000100000005000442f95b93')
        <DNS Header: id=0xd5ad type=RESPONSE opcode=QUERY flags=RD,RA rcode=None q=1 a=5 ns=0 ar=0>
        <DNS Question: 'www.google.com' qtype=A qclass=IN>
        <DNS RR: 'www.google.com' rtype=CNAME rclass=IN ttl=5 rdlength=8 rdata='www.l.google.com'>
        <DNS RR: 'www.l.google.com' rtype=A rclass=IN ttl=5 rdlength=4 rdata='66.249.91.104'>
        <DNS RR: 'www.l.google.com' rtype=A rclass=IN ttl=5 rdlength=4 rdata='66.249.91.99'>
        <DNS RR: 'www.l.google.com' rtype=A rclass=IN ttl=5 rdlength=4 rdata='66.249.91.103'>
        <DNS RR: 'www.l.google.com' rtype=A rclass=IN ttl=5 rdlength=4 rdata='66.249.91.147'>

    Standard query MX google.com
        >>> unpack('95370100000100000000000006676f6f676c6503636f6d00000f0001')
        <DNS Header: id=0x9537 type=QUERY opcode=QUERY flags=RD rcode=None q=1 a=0 ns=0 ar=0>
        <DNS Question: 'google.com' qtype=MX qclass=IN>

    Standard query response MX 10 smtp2.google.com MX 10 smtp3.google.com MX 10 smtp4.google.com MX 10 smtp1.google.com
        >>> unpack('95378180000100040000000006676f6f676c6503636f6d00000f0001c00c000f000100000005000a000a05736d747032c00cc00c000f000100000005000a000a05736d747033c00cc00c000f000100000005000a000a05736d747034c00cc00c000f000100000005000a000a05736d747031c00c')
        <DNS Header: id=0x9537 type=RESPONSE opcode=QUERY flags=RD,RA rcode=None q=1 a=4 ns=0 ar=0>
        <DNS Question: 'google.com' qtype=MX qclass=IN>
        <DNS RR: 'google.com' rtype=MX rclass=IN ttl=5 rdlength=10 rdata='10:smtp2.google.com'>
        <DNS RR: 'google.com' rtype=MX rclass=IN ttl=5 rdlength=10 rdata='10:smtp3.google.com'>
        <DNS RR: 'google.com' rtype=MX rclass=IN ttl=5 rdlength=10 rdata='10:smtp4.google.com'>
        <DNS RR: 'google.com' rtype=MX rclass=IN ttl=5 rdlength=10 rdata='10:smtp1.google.com'>

    Standard query PTR 103.91.249.66.in-addr.arpa
        >>> unpack('b38001000001000000000000033130330239310332343902363607696e2d61646472046172706100000c0001')
        <DNS Header: id=0xb380 type=QUERY opcode=QUERY flags=RD rcode=None q=1 a=0 ns=0 ar=0>
        <DNS Question: '103.91.249.66.in-addr.arpa' qtype=PTR qclass=IN>

    Standard query response PTR ik-in-f103.google.com
        >>> unpack('b38081800001000100000000033130330239310332343902363607696e2d61646472046172706100000c0001c00c000c00010000000500170a696b2d696e2d6631303306676f6f676c6503636f6d00')
        <DNS Header: id=0xb380 type=RESPONSE opcode=QUERY flags=RD,RA rcode=None q=1 a=1 ns=0 ar=0>
        <DNS Question: '103.91.249.66.in-addr.arpa' qtype=PTR qclass=IN>
        <DNS RR: '103.91.249.66.in-addr.arpa' rtype=PTR rclass=IN ttl=5 rdlength=23 rdata='ik-in-f103.google.com'>

    Standard query TXT google.com

        >>> unpack('c89f0100000100000000000006676f6f676c6503636f6d0000100001')
        <DNS Header: id=0xc89f type=QUERY opcode=QUERY flags=RD rcode=None q=1 a=0 ns=0 ar=0>
        <DNS Question: 'google.com' qtype=TXT qclass=IN>

    Standard query response TXT
        >>> unpack('c89f8180000100010000000006676f6f676c6503636f6d0000100001c00c0010000100000005002a29763d7370663120696e636c7564653a5f6e6574626c6f636b732e676f6f676c652e636f6d207e616c6c')
        <DNS Header: id=0xc89f type=RESPONSE opcode=QUERY flags=RD,RA rcode=None q=1 a=1 ns=0 ar=0>
        <DNS Question: 'google.com' qtype=TXT qclass=IN>
        <DNS RR: 'google.com' rtype=TXT rclass=IN ttl=5 rdlength=42 rdata='v=spf1 include:_netblocks.google.com ~all'>

    Standard query SOA google.com
        >>> unpack('28fb0100000100000000000006676f6f676c6503636f6d0000060001')
        <DNS Header: id=0x28fb type=QUERY opcode=QUERY flags=RD rcode=None q=1 a=0 ns=0 ar=0>
        <DNS Question: 'google.com' qtype=SOA qclass=IN>

    Standard query response SOA ns1.google.com
        >>> unpack('28fb8180000100010000000006676f6f676c6503636f6d0000060001c00c00060001000000050026036e7331c00c09646e732d61646d696ec00c77b1566d00001c2000000708001275000000012c')
        <DNS Header: id=0x28fb type=RESPONSE opcode=QUERY flags=RD,RA rcode=None q=1 a=1 ns=0 ar=0>
        <DNS Question: 'google.com' qtype=SOA qclass=IN>
        <DNS RR: 'google.com' rtype=SOA rclass=IN ttl=5 rdlength=38 rdata='ns1.google.com:dns-admin.google.com:2008110701:7200:1800:1209600:300'>

    """
    import doctest
    doctest.testmod()
