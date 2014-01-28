# -*- coding: utf-8 -*-

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
        return self.forward[k]

    def __getattr__(self,k):
        return self.reverse[k]

if __name__ == '__main__':
    import doctest
    doctest.testmod()
