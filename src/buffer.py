
import struct

class Buffer(object):

    """
    A simple data buffer - supports packing/unpacking in struct format 

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

    def update(self,ptr,fmt,*args):
        s = struct.pack(fmt,*args)
        self.data = self.data[:ptr] + s + self.data[ptr+len(s):]

    def unpack(self,fmt):
        return struct.unpack(fmt,self.get(struct.calcsize(fmt)))

if __name__ == '__main__':
    import doctest
    doctest.testmod()
