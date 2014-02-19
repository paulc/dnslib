# -*- coding: utf-8 -*-

from __future__ import print_function

from dnslib.bit import get_bits,set_bits
from dnslib.buffer import Buffer, BufferError

class DNSLabelError(Exception):
    pass

class DNSLabel(object):

    """
    Container for DNS label 

    Supports IDNA encoding for unicode domain names

    >>> l1 = DNSLabel("aaa.bbb.ccc.")
    >>> l2 = DNSLabel([b"aaa",b"bbb",b"ccc"])
    >>> l1 == l2
    True
    >>> x = { l1 : 1 }
    >>> x[l1]
    1
    >>> l1
    <DNSLabel: aaa.bbb.ccc>
    >>> str(l1)
    'aaa.bbb.ccc'
    >>> l3 = l1.add("xxx.yyy")
    >>> l3
    <DNSLabel: xxx.yyy.aaa.bbb.ccc>
    >>> l3.matchSuffix(l1)
    True
    >>> l3.matchSuffix("xxx.yyy")
    False
    >>> l3.stripSuffix("bbb.ccc")
    <DNSLabel: xxx.yyy.aaa>

    # Too hard to get unicode doctests to work on Python 3.2  
    # (works on 3.3)
    # >>> u1 = DNSLabel(u'\u2295.com')
    # >>> u1.__str__() == u'\u2295.com'
    # True
    # >>> u1.label == ( b"xn--keh", b"com" )
    # True

    """
    def __init__(self,label):
        """
            Create DNS label instance 

            Label can be specified as:
            - a list/tuple of byte strings
            - a byte string (split into components separated by b'.')
            - a unicode string which will be encoded according to RFC3490/IDNA
        """
        if type(label) == DNSLabel:
            self.label = label.label
        elif type(label) in (list,tuple):
            self.label = tuple(label)
        else:
            if not label or label in (b'.','.'):
                self.label = ()
            elif type(label) is not bytes:
                self.label = tuple(label.encode("idna").\
                                rstrip(b".").split(b"."))
            else:
                self.label = tuple(label.rstrip(b".").split(b"."))

    def add(self,name):
        """
            Prepend name to label 
        """
        new = DNSLabel(name)
        if self.label:
            new.label += self.label
        return new

    def matchSuffix(self,suffix):
        """
            Return True if label suffix matches 
        """
        suffix = DNSLabel(suffix)
        return self.label[-len(suffix.label):] == suffix.label

    def stripSuffix(self,suffix):
        """
            Strip suffix from label
        """
        suffix = DNSLabel(suffix)
        if self.label[-len(suffix.label):] == suffix.label:
            return DNSLabel(self.label[:-len(suffix.label)])
        else:
            return self

    def __str__(self):
        return ".".join([ s.decode("idna") for s in self.label ])

    def __repr__(self):
        return "<DNSLabel: %s>" % str(self)

    def __hash__(self):
        return hash(self.label)

    def __eq__(self,other):
        if type(other) != DNSLabel:
            return self.label == DNSLabel(other).label
        else:
            return self.label == other.label

    def __len__(self):
        return len(b'.'.join(self.label))

class DNSBuffer(Buffer):

    """
    Extends Buffer to provide DNS name encoding/decoding (with caching)

    # Needed for Python 2/3 doctest compatibility
    >>> def p(s):
    ...     if not isinstance(s,str):
    ...         return s.decode()
    ...     return s

    >>> b = DNSBuffer()
    >>> b.encode_name(b'aaa.bbb.ccc')
    >>> b.encode_name(b'xxx.yyy.zzz')
    >>> b.encode_name(b'zzz.xxx.bbb.ccc')
    >>> b.encode_name(b'aaa.xxx.bbb.ccc')
    >>> p(b.hex())
    '036161610362626203636363000378787803797979037a7a7a00037a7a7a03787878c00403616161c01e'
    >>> b.offset = 0
    >>> print(b.decode_name())
    aaa.bbb.ccc
    >>> print(b.decode_name())
    xxx.yyy.zzz
    >>> print(b.decode_name())
    zzz.xxx.bbb.ccc
    >>> print(b.decode_name())
    aaa.xxx.bbb.ccc

    >>> b = DNSBuffer()
    >>> b.encode_name([b'a.aa',b'b.bb',b'c.cc'])
    >>> b.offset = 0
    >>> len(b.decode_name().label)
    3
    """

    def __init__(self,data=b''):
        """
            Add 'names' dict to cache stored labels
        """
        super(DNSBuffer,self).__init__(data)
        self.names = {}

    def decode_name(self,last=-1):
        """
            Decode label at current offset in buffer (following pointers
            to cached elements where necessary)
        """
        label = []
        done = False
        while not done:
            (length,) = self.unpack("!B")
            if get_bits(length,6,2) == 3:
                # Pointer
                self.offset -= 1
                pointer = get_bits(self.unpack("!H")[0],0,14)
                save = self.offset
                if last == save:
                    raise BufferError("Recursive pointer in DNSLabel [pointer=%d,length=%d]" % 
                            (pointer,len(self.data)))
                if pointer < len(self.data):
                    self.offset = pointer
                else:
                    raise BufferError("Invalid pointer in DNSLabel [pointer=%d,length=%d]" % 
                            (pointer,len(self.data)))
                label.extend(self.decode_name(save).label)
                self.offset = save
                done = True
            else:
                if length > 0:
                    l = self.get(length)
                    try:
                        l.decode()
                    except UnicodeDecodeError:
                        raise BufferError("Invalid label <%s>" % l)
                    label.append(l)
                else:
                    done = True
        return DNSLabel(label)

    def encode_name(self,name):
        """
            Encode label and store at end of buffer (compressing
            cached elements where needed) and store elements
            in 'names' dict
        """
        if not isinstance(name,DNSLabel):
            name = DNSLabel(name)
        if len(name) > 253:
            raise DNSLabelError("Domain label too long: %r" % name)
        name = list(name.label)
        while name:
            if tuple(name) in self.names:
                # Cached - set pointer
                pointer = self.names[tuple(name)]
                pointer = set_bits(pointer,3,14,2)
                self.pack("!H",pointer)
                return
            else:
                self.names[tuple(name)] = self.offset
                element = name.pop(0)
                if len(element) > 63:
                    raise DNSLabelError("Label component too long: %r" % element)
                self.pack("!B",len(element))
                self.append(element)
        self.append(b'\x00')

if __name__ == '__main__':
    import doctest
    doctest.testmod()
