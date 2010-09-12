
import struct

from bit import get_bits
from dnserror import *

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
