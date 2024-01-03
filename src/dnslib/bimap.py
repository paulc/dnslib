import sys
import types
from typing import Dict, Callable, Type, Union, Optional, cast


class BimapError(Exception):
    pass


ErrorCallable = Callable[[str, Union[int, str], bool], Union[str, int]]


class Bimap:
    """Bi-directional mapping between numerical codes and text.

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
    ...         if isinstance(key, int):
    ...             return f"TEST{key}"
    ...         raise TestError(f"{name}: Invalid forward lookup: [{key}]")
    ...     else:
    ...         if key.startswith("TEST"):
    ...             try:
    ...                 return int(key[4:])
    ...             except:
    ...                 pass
    ...         raise TestError(f"{name}: Invalid reverse lookup: [{key}]")
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

    def __init__(
        self,
        name: str,
        forward: Dict[int, str],
        error: Union[ErrorCallable, Type[Exception]] = AttributeError,
    ) -> None:
        """
        Args:
            name: name of this Bimap (used in exceptions)
            forward: mapping from code (numeric) to text
            error: Error type to raise if key not found
                _or_ callable which either generates mapping
                or raises an error

        """
        self.name = name
        self.error = error
        self.forward = forward.copy()
        self.reverse: Dict[str, int] = {v: k for (k, v) in list(forward.items())}

    def get(self, key: str, default: Optional[str] = None) -> str:
        return self.forward.get(key, default or str(key))

    def __getitem__(self, key: int) -> str:
        try:
            return self.forward[key]
        except KeyError as e:
            if isinstance(self.error, types.FunctionType):
                return cast(str, self.error(self.name, key, True))
            raise self.error(f"{self.name}: Invalid forward lookup: [{key}]")

    def __getattr__(self, key: str) -> int:
        try:
            # Python 3.7 inspect module (called by doctest) checks for __wrapped__ attribute
            if key == "__wrapped__":
                raise AttributeError()
            return self.reverse[key]
        except KeyError as e:
            if isinstance(self.error, types.FunctionType):
                return cast(int, self.error(self.name, key, False))
            raise self.error(f"{self.name}: Invalid reverse lookup: [{key}]")


if __name__ == "__main__":
    import doctest, sys

    sys.exit(0 if doctest.testmod().failed == 0 else 1)
