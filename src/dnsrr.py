
import struct

from dnserror import *
from dnsname import encode_name, decode_name
from dnstype import *

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
        return struct.pack("!BBBB",*map(int,self.data.splut(".")))

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

