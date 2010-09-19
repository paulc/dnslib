
import struct
from bit import get_bits,set_bits

class Buffer(object):

    """
    A simple data buffer - supports packing/unpacking in struct format and 
    DNS name encoding/decoding (with caching)

    >>> b = Buffer()
    >>> b.pack("!BHI",1,2,3)
    >>> b.offset
    7
    >>> b.append("0123456789")
    >>> b.offset
    17
    >>> b.offset = 0
    >>> b.unpack("!BHI")
    (1, 2, 3)
    >>> b.get(5)
    '01234'
    >>> b.get(5)
    '56789'

    >>> b = Buffer()
    >>> b.encode_name("aaa.bbb.ccc")
    >>> b.encode_name("xxx.yyy.zzz")
    >>> b.encode_name("zzz.xxx.bbb.ccc")
    >>> b.encode_name("aaa.xxx.bbb.ccc")
    >>> b.data.encode("hex")
    '036161610362626203636363000378787803797979037a7a7a00037a7a7a03787878c00403616161c01e'
    >>> b.offset = 0
    >>> b.decode_name()
    'aaa.bbb.ccc'
    >>> b.decode_name()
    'xxx.yyy.zzz'
    >>> b.decode_name()
    'zzz.xxx.bbb.ccc'
    >>> b.decode_name()
    'aaa.xxx.bbb.ccc'
    """

    def __init__(self,data=""):
        self.names = {}
        self.data = data
        self.offset = 0

    def get(self,len):
        start = self.offset
        end = self.offset + len
        self.offset += len
        return self.data[start:end]

    def pack(self,fmt,*args):
        self.offset += struct.calcsize(fmt)
        self.data += struct.pack(fmt,*args)

    def append(self,s):
        self.offset += len(s)
        self.data += s

    def unpack(self,fmt):
        return struct.unpack(fmt,self.get(struct.calcsize(fmt)))

    def decode_name(self):
        label = []
        done = False
        while not done:
            (len,) = self.unpack("!B")
            if get_bits(len,6,2) == 3:
                self.offset -= 1
                pointer = get_bits(self.unpack("!H")[0],0,14)
                save = self.offset
                self.offset = pointer
                label.append(self.decode_name())
                self.offset = save
                done = True
            else:
                if len > 0:
                    label.append(self.get(len))
                else:
                    done = True
        return ".".join(label)

    def encode_name(self,name):
        while name:
            if self.names.has_key(name):
                pointer = self.names[name]
                pointer = set_bits(pointer,3,14,2)
                self.pack("!H",pointer)
                return
            else:
                self.names[name] = self.offset
                try:
                    element,name = name.split(".",1)
                except ValueError:
                    element,name = name,""
                if len(element) > 255:
                    raise DNSError("Label too long: %s: " % element)
                self.pack("!B",len(element))
                self.append(element)
        self.append("\x00")

if __name__ == '__main__':
    import doctest
    doctest.testmod()
