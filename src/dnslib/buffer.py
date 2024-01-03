import struct
from typing import Any


class BufferError(Exception):
    pass


class Buffer:
    """A simple data buffer - supports packing/unpacking in struct format

    >>> b = Buffer()
    >>> b.pack("!BHI",1,2,3)
    >>> b.offset
    7
    >>> b.append(b"0123456789")
    >>> b.offset
    17
    >>> b.hex()
    '0100020000000330313233343536373839'
    >>> b.offset = 0
    >>> b.unpack("!BHI")
    (1, 2, 3)
    >>> bytearray(b.get(5))
    bytearray(b'01234')
    >>> bytearray(b.get(5))
    bytearray(b'56789')
    >>> b.update(7,"2s",b"xx")
    >>> b.offset = 7
    >>> bytearray(b.get(5))
    bytearray(b'xx234')
    """

    def __init__(self, data: bytes = b"") -> None:
        """
        Args:
            data: initial data
        """
        self.data = bytearray(data)
        self.offset = 0
        return

    @property
    def remaining(self) -> int:
        """Number of bytes from the current offset until the end of the buffer"""
        return len(self.data) - self.offset

    def get(self, length: int) -> bytes:
        """Get bytes from the buffer starting at the current offset and increment offset

        Args:
            length: number of bytes to get

        Raises:
            BufferError: if length is greater than remaining bytes.
        """
        if length > self.remaining:
            raise BufferError(
                f"Not enough bytes [offset={self.offset},remaining={self.remaining},requested={length}]"
            )
        start = self.offset
        end = self.offset + length
        self.offset += length
        return bytes(self.data[start:end])

    def hex(self) -> str:
        """Return data as hex string"""
        return self.data.hex()

    def pack(self, fmt: str, *args) -> None:
        """Pack a struct and append it to the buffer

        Args:
            fmt: struct format
            args: data to pack into the struct
        """
        self.offset += struct.calcsize(fmt)
        self.data += struct.pack(fmt, *args)
        return

    def append(self, s: bytes) -> None:
        """Append data to end of the buffer and increment offset

        Args:
            s: data to append
        """
        self.offset += len(s)
        self.data += s
        return

    def update(self, ptr: int, fmt: str, *args: Any) -> None:
        """Modify data at offset `ptr`

        Args:
            ptr: the offset the start the modification at
            fmt: struct format
            args: data to pack into struct format
        """
        s = struct.pack(fmt, *args)
        self.data[ptr : ptr + len(s)] = s
        return

    def unpack(self, fmt: str):
        """Unpack a struct from the current offset and increment offset

        Args:
            fmt: struct format to unpack

        Raises:
            struct.error: if could not unpack struct
        """
        try:
            data = self.get(struct.calcsize(fmt))
            return struct.unpack(fmt, data)
        except struct.error as e:
            raise BufferError(f"Error unpacking struct {fmt!r} <{data.hex()}>")

    def __len__(self):
        return len(self.data)


if __name__ == "__main__":
    import doctest, sys

    sys.exit(0 if doctest.testmod().failed == 0 else 1)
