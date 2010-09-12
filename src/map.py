
class Map(object):

    """

    A simple bi-directional map which returns either forward or
    reverse lookup of key through explicit 'lookup' method or 
    through __getattr__ or __getitem__.

    >>> m = Map({1:'a',2:'b',3:'c'})
    >>> m[1]
    'a'
    >>> m.lookup('a')
    1
    >>> m.a
    1
    >>> m.x
    Traceback (most recent call last):
    ...
    KeyError: 'x'

    """

    def __init__(self,forward):
        self.forward = forward
        self.reverse = dict([(v,k) for (k,v) in forward.items()])

    def lookup(self,k):
        try:
            return self.forward[k]
        except KeyError:
            return self.reverse[k]
    
    def __getitem__(self,k):
        return self.lookup(k)

    def __getattr__(self,k):
        return self.lookup(k)

if __name__ == '__main__':
    import doctest
    doctest.testmod()
