import sys
from typing import Dict, Callable, Type, Union, Optional, cast


class BimapError(Exception):
    pass


ErrorCallable = Callable[[str, Union[int, str]], Union[str, int]]


class Bimap:
    """Bi-directional mapping between numerical codes and text.

    The class provides:

    * A 'forward' map (code->text) which is accessed through
        `__getitem__` (`bimap[code]`)
    * A 'reverse' map (code>value) which is accessed through
        `__getattr__` (`bimap.text`)
    * A 'get' method which does a forward lookup (code->text)
        and returns a textual version of code if there is no
        explicit mapping (or default provided)

    ```pycon
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
    >>> def _error(name,key):
    ...     if isinstance(key, int):
    ...         return f"TEST{key}"
    ...     if key.startswith("TEST"):
    ...         try:
    ...             return int(key.removeprefix("TEST"))
    ...         except:
    ...             pass
    ...     raise TestError(f"{name}: Invalid lookup: [{key!r}]")
    >>> TEST2 = Bimap('TEST2',{1:'A', 2:'B', 3:'C'},_error)
    >>> TEST2[1]
    'A'
    >>> TEST2[9999]
    'TEST9999'
    >>> TEST2['abcd']
    Traceback (most recent call last):
    ...
    TestError: TEST2: Invalid lookup: ['abcd']
    >>> TEST2.A
    1
    >>> TEST2.TEST9999
    9999
    >>> TEST2.X
    Traceback (most recent call last):
    ...
    TestError: TEST2: Invalid lookup: ['X']

    ```
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
        self.reverse: Dict[str, int] = {v: k for k, v in forward.items()}
        return

    def get(self, key: int, default: Optional[str] = None) -> str:
        """Get string for given numerical key

        Args:
            key:
            default: default value to return if key is missing
        """
        return self.forward.get(key, default or str(key))

    def __getitem__(self, key: int) -> str:
        if key in self.forward:
            return self.forward[key]
        if isinstance(self.error, type) and issubclass(self.error, Exception):
            raise self.error(f"{self.name}: Invalid forward lookup: [{key}]")
        return cast(str, self.error(self.name, key))

    def __getattr__(self, key: str) -> int:
        # Python 3.7 inspect module (called by doctest) checks for __wrapped__ attribute
        if key == "__wrapped__":
            raise AttributeError()
        if key in self.reverse:
            return self.reverse[key]
        if isinstance(self.error, type) and issubclass(self.error, Exception):
            raise self.error(f"{self.name}: Invalid reverse lookup: [{key}]")
        return cast(int, self.error(self.name, key))


if __name__ == "__main__":
    import doctest, sys

    sys.exit(0 if doctest.testmod().failed == 0 else 1)
