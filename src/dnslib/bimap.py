# -*- coding: utf-8 -*-

"""
    Bimap - bidirectional mapping between code/value
"""

import sys,types

class BimapError(Exception):
    pass

class Bimap(object):

    """
        Bi-directional mapping between code/text.

        Initialised using:

            name:   Used for exceptions
            dict:   Dict mapping from code (numeric) to text
            error:  Error type to raise if key not found
                    _or_ callable which either generates mapping
                    return error

        The class provides:

            * A 'forward' map (code->text) which is accessed through
              __getitem__ (bimap[code])
            * A 'reverse' map (code>value) which is accessed through
              __getattr__ (bimap.text)
            * A 'get' method which does a forward lookup (code->text)
              and returns a textual version of code if there is no
              explicit mapping (or default provided)

        >>> class TestError(Exception):
        ...     pass

        >>> TEST = Bimap('TEST',{1:'A', 2:'B', 3:'C'},TestError)
        >>> TEST[1]
        'A'
        >>> TEST.A
        1
        >>> TEST.X
        Traceback (most recent call last):
        ...
        TestError: TEST: Invalid reverse lookup: [X]
        >>> TEST[99]
        Traceback (most recent call last):
        ...
        TestError: TEST: Invalid forward lookup: [99]
        >>> TEST.get(99)
        '99'

        # Test with callable error
        >>> def _error(name,key,forward):
        ...     if forward:
        ...         try:
        ...             return "TEST%d" % (key,)
        ...         except:
        ...             raise TestError("%s: Invalid forward lookup: [%s]" % (name,key))
        ...     else:
        ...         if key.startswith("TEST"):
        ...             try:
        ...                 return int(key[4:])
        ...             except:
        ...                 pass
        ...         raise TestError("%s: Invalid reverse lookup: [%s]" % (name,key))
        >>> TEST2 = Bimap('TEST2',{1:'A', 2:'B', 3:'C'},_error)
        >>> TEST2[1]
        'A'
        >>> TEST2[9999]
        'TEST9999'
        >>> TEST2['abcd']
        Traceback (most recent call last):
        ...
        TestError: TEST2: Invalid forward lookup: [abcd]
        >>> TEST2.A
        1
        >>> TEST2.TEST9999
        9999
        >>> TEST2.X
        Traceback (most recent call last):
        ...
        TestError: TEST2: Invalid reverse lookup: [X]

    """

    def __init__(self,name,forward,error=AttributeError):
        self.name = name
        self.error = error
        self.forward = forward.copy()
        self.reverse = dict([(v,k) for (k,v) in list(forward.items())])

    def get(self,k,default=None):
        try:
            return self.forward[k]
        except KeyError as e:
            return default or str(k)

    def __getitem__(self,k):
        try:
            return self.forward[k]
        except KeyError as e:
            if isinstance(self.error,types.FunctionType):
                return self.error(self.name,k,True)
            else:
                raise self.error("%s: Invalid forward lookup: [%s]" % (self.name,k))

    def __getattr__(self,k):
        try:
            # Python 3.7 inspect module (called by doctest) checks for __wrapped__ attribute
            if k == "__wrapped__":
                raise AttributeError()
            return self.reverse[k]
        except KeyError as e:
            if isinstance(self.error,types.FunctionType):
                return self.error(self.name,k,False)
            else:
                raise self.error("%s: Invalid reverse lookup: [%s]" % (self.name,k))

if __name__ == '__main__':
    import doctest,sys
    sys.exit(0 if doctest.testmod().failed == 0 else 1)
