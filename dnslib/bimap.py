# -*- coding: utf-8 -*-

from dnslib.error import DNSError

class BimapError(Exception):
    pass

class Bimap(object):

    """

    Automatic bi-directional mapping between value and text. 

        >>> TEST = Bimap('TEST',{1:'A', 2:'B', 3:'C'})
        >>> TEST[1]
        'A'
        >>> TEST.A
        1
    
    """

    def __init__(self,name,forward):
        self.name = name
        self.forward = forward.copy()
        self.reverse = dict([(v,k) for (k,v) in list(forward.items())])

    def __getitem__(self,k):
        try:
            return self.forward[k]
        except KeyError as e:
            raise DNSError("%s: Invalid forward lookup: [%s]" % (self.name,k))

    def __getattr__(self,k):
        try:
            return self.reverse[k]
        except KeyError as e:
            raise DNSError("%s: Invalid reverse lookup: [%s]" % (self.name,k))

if __name__ == '__main__':
    import doctest
    doctest.testmod()
