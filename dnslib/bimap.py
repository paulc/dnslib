
class BimapError(Exception):
    pass

class Bimap(object):

    """

    A simple bi-directional map which returns either forward or
    reverse lookup of key through explicit 'lookup' method or 
    through __getattr__ or __getitem__. If the key is not found
    in either the forward/reverse dictionaries default is returned.

    >>> m = Bimap("test",{1:'a',2:'b',3:'c'})
    >>> m[1]
    'a'
    >>> m.lookup('a')
    1
    >>> m.a
    1

    """

    def __init__(self,name,forward):
        self.name = name
        self.forward = forward
        self.reverse = dict([(v,k) for (k,v) in list(forward.items())])

    def lookup(self,k,default=None):
        try:
            try:
                return self.forward[k]
            except KeyError:
                return self.reverse[k]
        except KeyError:
            if default:
                return default
            else:
                raise BimapError("%s: Invalid value <%s>" % (self.name,k))

    def f(self,k):
        return self.forward.get(k,str(k))

    def __getitem__(self,k):
        return self.lookup(k)

    def __getattr__(self,k):
        return self.lookup(k)

if __name__ == '__main__':
    import doctest
    doctest.testmod()
