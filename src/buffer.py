
import struct
from bit import get_bits,set_bits

class Buffer(object):

    def __init__(self,data=""):
        self.data = data
        self.offset = 0

    def get(self,len):
        start = self.offset
        end = self.offset + len
        self.offset += len
        return self.data[start:end]

    def pack(self,fmt,*args):
        self.data += struct.pack(fmt,*args)

    def append(self,s):
        self.data += s

    def unpack(self,fmt):
        return struct.unpack(fmt,self.get(struct.calcsize(fmt)))

    def get_byte(self):
        return struct.unpack("!B",self.get(1))[0]

    def get_short(self):
        return struct.unpack("!H",self.get(2))[0]

    def get_int(self):
        return struct.unpack("!I",self.get(4))[0]

    def decode_name(self):
        label = []
        done = False
        while not done:
            len = self.get_byte()
            if get_bits(len,6,2) == 3:
                self.offset -= 1
                pointer = get_bits(self.get_short(),0,14)
                try:
                    save = self.offset
                    self.offset = pointer
                    label.append(self.decode_name())
                finally:
                    self.offset = save
                done = True
            else:
                if len > 0:
                    label.append(self.get(len))
                else:
                    done = True
        return ".".join(label)

    def encode_name(name):
        ## TODO: Cache names
        label = name.split(".")
        for l in label:
            if len(l) > 255:
                raise DNSError("Label too long: %s: " % name)
            self.pack("!B",len(l))
            self.append(l)
            self.append("\x00")


