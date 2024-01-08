"""
    DNS - main dnslib module

    Contains core DNS packet handling code
"""


import base64
import binascii
import calendar
import collections
import copy
from ipaddress import IPv4Address, IPv6Address
from itertools import chain, zip_longest
import os.path
import random
import socket
import string
import struct
import sys
import textwrap
import time
from typing import overload, Type, TypeVar, Optional, Union, List, Tuple, Dict, Any, Sequence, cast

# Sequence deprecated in 3.9, keep track in case it is removed.

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self

from dnslib.bit import get_bits, set_bits
from dnslib.bimap import Bimap, BimapError
from dnslib.buffer import Buffer, BufferError
from dnslib.label import DNSLabel, DNSLabelCreateTypes, DNSLabelError, DNSBuffer
from dnslib.lex import WordLexer
from dnslib.ranges import BYTES, B, H, I, IP4, IP6, ntuple_range, check_range, check_bytes


class DNSError(Exception):
    pass


def make_parse_error(name: Union[str, Type], buffer, error: Exception) -> DNSError:
    """Generate a standardised DNSError for errors when parsing/unpacking from a buffer

    Args:
        name: name of the thing being parsed/unpacked (e.g. `DNSQuestion`, `MX`)
        buffer: the buffer being parsed/unpacked
        error: the exception that was thrown

    Returns:
        Prepared `DNSError`
    """
    if isinstance(name, type):
        name = name.__name__
    return DNSError(f"Error unpacking {name} [offset={buffer.offset}]: {error!r}")


# DNS codes


def unknown_qtype(name: str, key: Union[str, int]) -> Union[str, int]:
    if isinstance(key, int):
        return f"TYPE{key}"

    if key.startswith("TYPE"):
        try:
            return int(key.removeprefix("TYPE"))
        except:
            pass
    raise DNSError(f"{name!r}: Invalid lookup: [{key!r}]")


QTYPE = Bimap(
    "QTYPE",
    {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        10: "NULL",
        12: "PTR",
        13: "HINFO",
        15: "MX",
        16: "TXT",
        17: "RP",
        18: "AFSDB",
        24: "SIG",
        25: "KEY",
        28: "AAAA",
        29: "LOC",
        33: "SRV",
        35: "NAPTR",
        36: "KX",
        37: "CERT",
        38: "A6",
        39: "DNAME",
        41: "OPT",
        42: "APL",
        43: "DS",
        44: "SSHFP",
        45: "IPSECKEY",
        46: "RRSIG",
        47: "NSEC",
        48: "DNSKEY",
        49: "DHCID",
        50: "NSEC3",
        51: "NSEC3PARAM",
        52: "TLSA",
        53: "HIP",
        55: "HIP",
        59: "CDS",
        60: "CDNSKEY",
        61: "OPENPGPKEY",
        62: "CSYNC",
        63: "ZONEMD",
        64: "SVCB",
        65: "HTTPS",
        99: "SPF",
        108: "EUI48",
        109: "EUI64",
        249: "TKEY",
        250: "TSIG",
        251: "IXFR",
        252: "AXFR",
        255: "ANY",
        256: "URI",
        257: "CAA",
        32768: "TA",
        32769: "DLV",
    },
    unknown_qtype,
)

CLASS = Bimap("CLASS", {1: "IN", 2: "CS", 3: "CH", 4: "Hesiod", 254: "None", 255: "*"}, DNSError)
QR = Bimap("QR", {0: "QUERY", 1: "RESPONSE"}, DNSError)
RCODE = Bimap(
    "RCODE",
    {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
        6: "YXDOMAIN",
        7: "YXRRSET",
        8: "NXRRSET",
        9: "NOTAUTH",
        10: "NOTZONE",
    },
    DNSError,
)
OPCODE = Bimap("OPCODE", {0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE"}, DNSError)


def create_label(label: str, origin: DNSLabelCreateTypes = None) -> DNSLabel:
    """Create a DNSLabel from a string

    Args:
        label:
        origin: base of label if label is not connected to root (`.`).

    Changed in 1.0: renamed from `label` to `create_label` (avoids name collisions within classes)
    """
    # TODO: Should this be a classmethod on DNSLabel? Could it just be apart of init?
    if label.endswith("."):
        return DNSLabel(label)
    if not isinstance(origin, DNSLabel):
        origin = DNSLabel(origin)
    return origin.add(label)


def create_label_property(attr: str = "label"):
    """Property creator for DNSLabel properties

    Args:
        attr: name of attribute
    """
    obj_attr = f"_{attr}"

    def getter(self) -> DNSLabel:
        return getattr(self, obj_attr)

    def setter(self, label: DNSLabelCreateTypes) -> None:
        if not isinstance(label, DNSLabel):
            label = DNSLabel(label)
        setattr(self, obj_attr, label)
        return

    return property(getter, setter)


# TODO: This should potentially be renamed to the RFC1035 name of `DNSMessage`
# TODO: At the same time should we give better names to the attributes. i.e.
#       answer_records, authority_records, additional_records
class DNSRecord:
    """A DNS Message - corresponds to DNS packet

    Comprises of `DNSHeader`, `DNSQuestion`, and `RR` sections (answer,authority,additional)

    References:

     - <https://datatracker.ietf.org/doc/html/rfc1035#section-4>

    Attributes:
            header: header
            questions: questions
            rr: answer records
            auth: authority records
            ar: additional records

    ```pycon
    >>> d = DNSRecord()
    >>> d.add_question(DNSQuestion("abc.com")) # Or DNSRecord.question("abc.com")
    >>> d.add_answer(RR("abc.com",QTYPE.CNAME,ttl=60,rdata=CNAME("ns.abc.com")))
    >>> d.add_auth(RR("abc.com",QTYPE.SOA,ttl=60,rdata=SOA("ns.abc.com","admin.abc.com",(20140101,3600,3600,3600,3600))))
    >>> d.add_ar(RR("ns.abc.com",ttl=60,rdata=A("1.2.3.4")))
    >>> print(d)
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
    ;; flags: rd; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 1
    ;; QUESTION SECTION:
    ;abc.com.                       IN      A
    ;; ANSWER SECTION:
    abc.com.                60      IN      CNAME   ns.abc.com.
    ;; AUTHORITY SECTION:
    abc.com.                60      IN      SOA     ns.abc.com. admin.abc.com. 20140101 3600 3600 3600 3600
    ;; ADDITIONAL SECTION:
    ns.abc.com.             60      IN      A       1.2.3.4
    >>> str(d) == str(DNSRecord.parse(d.pack()))
    True

    ```
    """

    @classmethod
    def parse(cls, packet: bytes) -> Self:
        """Parse a DNS packet data into DNSRecord instance
        Recursively parses sections (calling appropriate parse method)

        Args:
            packet: DNS packet to parse

        Raises:
            DNSError: invalid DNS packet
        """
        buffer = DNSBuffer(packet)
        try:
            header = DNSHeader.parse(buffer)
            questions = []
            rr = []
            auth = []
            ar = []
            for i in range(header.q):
                questions.append(DNSQuestion.parse(buffer))
            for i in range(header.a):
                rr.append(RR.parse(buffer))
            for i in range(header.auth):
                auth.append(RR.parse(buffer))
            for i in range(header.ar):
                ar.append(RR.parse(buffer))
            return cls(header, questions, rr, auth=auth, ar=ar)
        except DNSError:
            raise
        except (BufferError, BimapError) as e:
            raise make_parse_error(cls, buffer, e)

    @staticmethod
    def question(qname: str, qtype: str = "A", qclass: str = "IN") -> "DNSRecord":
        """Shortcut to create question

        Args:
            qname: name to query
            qtype: type to query
            qclass: class of query

        ```pycon
        >>> q = DNSRecord.question("www.google.com")
        >>> print(q)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
        ;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION:
        ;www.google.com.                IN      A

        >>> q = DNSRecord.question("www.google.com","NS")
        >>> print(q)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
        ;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION:
        ;www.google.com.                IN      NS

        ```
        """
        return DNSRecord(q=DNSQuestion(qname, getattr(QTYPE, qtype), getattr(CLASS, qclass)))

    def __init__(
        self,
        header: "Optional[DNSHeader]" = None,
        questions: "Optional[List[DNSQuestion]]" = None,
        rr: "Optional[List[RR]]" = None,
        q: "Optional[DNSQuestion]" = None,
        a: "Optional[RR]" = None,
        auth: "Optional[List[RR]]" = None,
        ar: "Optional[List[RR]]" = None,
    ) -> None:
        """
        Args:
            header: header
            questions: questions
            rr: resource records
            q: shortcut for single question
            a: shortcut for single answer
            auth: authority records
            ar: additional records
        """
        self.header: DNSHeader = header or DNSHeader()
        self.questions: List[DNSQuestion] = questions or []
        self.rr: List[RR] = rr or []
        self.auth: List[RR] = auth or []
        self.ar: List[RR] = ar or []
        # Shortcuts to add a single Question/Answer
        if q:
            self.questions.append(q)
        if a:
            self.rr.append(a)
        self.set_header_qa()
        return

    def reply(self, ra: int = 1, aa: int = 1) -> "DNSRecord":
        """Create skeleton reply packet

        Args:
            ra: `DNSHeader.ra`
            aa: `DNSHeader.aa`

        ```pycon
        >>> q = DNSRecord.question("abc.com")
        >>> a = q.reply()
        >>> a.add_answer(RR("abc.com",QTYPE.A,rdata=A("1.2.3.4"),ttl=60))
        >>> print(a)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
        ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION:
        ;abc.com.                       IN      A
        ;; ANSWER SECTION:
        abc.com.                60      IN      A       1.2.3.4

        ```
        """
        return DNSRecord(
            DNSHeader(id=self.header.id, bitmap=self.header.bitmap, qr=1, ra=ra, aa=aa), q=self.q
        )

    def replyZone(self, zone: str, ra: int = 1, aa: int = 1) -> "DNSRecord":
        """Create a reply with response data in zone-file format

        Args:
            zone: zone to parse into answer
            ra: `DNSHeader.ra`
            aa: `DNSHeader.aa`

        ```pycon
        >>> q = DNSRecord.question("abc.com")
        >>> a = q.replyZone("abc.com 60 A 1.2.3.4")
        >>> print(a)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
        ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION:
        ;abc.com.                       IN      A
        ;; ANSWER SECTION:
        abc.com.                60      IN      A       1.2.3.4

        ```
        """
        return DNSRecord(
            DNSHeader(id=self.header.id, bitmap=self.header.bitmap, qr=1, ra=ra, aa=aa),
            q=self.q,
            rr=RR.fromZone(zone),
        )

    def add_question(self, *q: "DNSQuestion") -> None:
        """Add question(s) to this record

        Args:
            q: question(s) to add

        ```pycon
        >>> q = DNSRecord()
        >>> q.add_question(DNSQuestion("abc.com"),
        ...                DNSQuestion("abc.com",QTYPE.MX))
        >>> print(q)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
        ;; flags: rd; QUERY: 2, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION:
        ;abc.com.                       IN      A
        ;abc.com.                       IN      MX

        ```
        """
        self.questions.extend(q)
        self.set_header_qa()
        return

    def add_answer(self, *rr: "RR") -> None:
        """Add answer(s)

        Args:
            rr: records to add to answer section

        ```pycon
        >>> q = DNSRecord.question("abc.com")
        >>> a = q.reply()
        >>> a.add_answer(*RR.fromZone("abc.com A 1.2.3.4"))
        >>> print(a)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
        ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION:
        ;abc.com.                       IN      A
        ;; ANSWER SECTION:
        abc.com.                0       IN      A       1.2.3.4

        ```
        """
        self.rr.extend(rr)
        self.set_header_qa()
        return

    def add_auth(self, *auth: "RR") -> None:
        """Add authority records

        Args:
            rr: records to add to authority section

        ```pycon
        >>> q = DNSRecord.question("abc.com")
        >>> a = q.reply()
        >>> a.add_answer(*RR.fromZone("abc.com 60 A 1.2.3.4"))
        >>> a.add_auth(*RR.fromZone("abc.com 3600 NS nsa.abc.com"))
        >>> print(a)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
        ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 1, ADDITIONAL: 0
        ;; QUESTION SECTION:
        ;abc.com.                       IN      A
        ;; ANSWER SECTION:
        abc.com.                60      IN      A       1.2.3.4
        ;; AUTHORITY SECTION:
        abc.com.                3600    IN      NS      nsa.abc.com.

        ```
        """
        self.auth.extend(auth)
        self.set_header_qa()
        return

    def add_ar(self, *ar: "RR") -> None:
        """Add additional records

        Args:
            ar: records to add to additional section

        ```pycon
        >>> q = DNSRecord.question("abc.com")
        >>> a = q.reply()
        >>> a.add_answer(*RR.fromZone("abc.com 60 CNAME x.abc.com"))
        >>> a.add_ar(*RR.fromZone("x.abc.com 3600 A 1.2.3.4"))
        >>> print(a)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
        ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
        ;; QUESTION SECTION:
        ;abc.com.                       IN      A
        ;; ANSWER SECTION:
        abc.com.                60      IN      CNAME   x.abc.com.
        ;; ADDITIONAL SECTION:
        x.abc.com.              3600    IN      A       1.2.3.4

        ```
        """
        self.ar.extend(ar)
        self.set_header_qa()
        return

    def set_header_qa(self) -> None:
        """Reset header q/a/auth/ar counts to match number of records

        This is normally done transparently, however if you've manually modified
        the the question, answer, authority, or additional lists in this record
        then you *might* need to call this function.
        """
        self.header.q = len(self.questions)
        self.header.a = len(self.rr)
        self.header.auth = len(self.auth)
        self.header.ar = len(self.ar)
        return

    @property
    def q(self) -> "DNSQuestion":
        """Get first question from this record if it exists, otherwise empty question"""
        return self.questions[0] if self.questions else DNSQuestion()

    @property
    def a(self) -> "RR":
        """Get the first answer from this record if exists otherwise empty resource"""
        return self.rr[0] if self.rr else RR()

    def pack(self) -> bytes:
        """Pack record into binary packet

        ```pycon
        >>> q = DNSRecord.question("abc.com")
        >>> q.header.id = 1234
        >>> a = q.replyZone("abc.com A 1.2.3.4")
        >>> a.header.aa = 0
        >>> pkt = a.pack()
        >>> print(DNSRecord.parse(pkt))
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1234
        ;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
        ;; QUESTION SECTION:
        ;abc.com.                       IN      A
        ;; ANSWER SECTION:
        abc.com.                0       IN      A       1.2.3.4

        ```
        """
        self.set_header_qa()
        buffer = DNSBuffer()
        self.header.pack(buffer)
        for q in self.questions:
            q.pack(buffer)
        for rr in self.rr:
            rr.pack(buffer)
        for auth in self.auth:
            auth.pack(buffer)
        for ar in self.ar:
            ar.pack(buffer)
        return buffer.data

    def truncate(self) -> "DNSRecord":
        """Return truncated copy of DNSRecord (with TC flag set)

        The truncated copy will have all questions & RRs removed

        ```pycon
        >>> q = DNSRecord.question("abc.com")
        >>> a = q.reply()
        >>> a.add_answer(*RR.fromZone(f"abc.com IN TXT {'x' *255}"))
        >>> a.add_answer(*RR.fromZone(f"abc.com IN TXT {'x' *255}"))
        >>> a.add_answer(*RR.fromZone(f"abc.com IN TXT {'x' *255}"))
        >>> len(a.pack())
        829
        >>> t = a.truncate()
        >>> print(t)
        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
        ;; flags: qr aa tc rd ra; QUERY: 0, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0

        ```
        """
        return DNSRecord(DNSHeader(id=self.header.id, bitmap=self.header.bitmap, tc=1))

    def send(
        self,
        dest: str,
        port: int = 53,
        tcp: bool = False,
        timeout: Optional[int] = None,
        ipv6: bool = False,
    ):
        """Send packet to a nameserver and return the response

        Args:
            dest: hostname of nameserver
            port: port to connect to on nameserver
            tcp: If `True` uses TCP, otherwise UDP
            timeout: socket timeout
            ipv6: if `True` uses IPv6, otherwise IPv4
        """
        data = self.pack()
        if ipv6:
            inet = socket.AF_INET6
        else:
            inet = socket.AF_INET
        try:
            sock = None
            if tcp:
                if len(data) > 65535:
                    raise ValueError(f"Packet length too long: {len(data)}")
                data = struct.pack("!H", len(data)) + data
                sock = socket.socket(inet, socket.SOCK_STREAM)
                if timeout is not None:
                    sock.settimeout(timeout)
                sock.connect((dest, port))
                sock.sendall(data)
                response = sock.recv(8192)
                length = struct.unpack("!H", bytes(response[:2]))[0]
                while len(response) - 2 < length:
                    response += sock.recv(8192)
                response = response[2:]
            else:
                sock = socket.socket(inet, socket.SOCK_DGRAM)
                if timeout is not None:
                    sock.settimeout(timeout)
                sock.sendto(self.pack(), (dest, port))
                response, server = sock.recvfrom(8192)
        finally:
            if sock is not None:
                sock.close()

        return response

    def format(self, prefix: str = "", sort: bool = False) -> str:
        """Formatted 'repr'-style representation of record

        Args:
            prefix: add this prefix to each section
            sort: if `True` sort each section first
        """
        sections = [repr(self.header)]
        for section in (self.questions, self.rr, self.auth, self.ar):
            items = [repr(i) for i in section]  # type: ignore[attr-defined]
            if sort:
                items.sort()
            sections.extend(items)
        return prefix + f"\n{prefix}".join(sections)

    def toZone(self, prefix: str = "") -> str:
        """Formatted 'DiG' (zone) style output

        Args:
            prefix: add this prefix to each line
        """
        lines = self.header.toZone().split("\n")
        sections = (
            (self.questions, ";; QUESTION SECTION:"),
            (self.rr, ";; ANSWER SECTION:"),
            (self.auth, ";; AUTHORITY SECTION:"),
            (self.ar, ";; ADDITIONAL SECTION:"),
        )
        for section, header in sections:
            if section:
                lines.append(header)
                for item in section:  # type: ignore[attr-defined]
                    lines.extend(item.toZone().split("\n"))
        return prefix + f"\n{prefix}".join(lines)

    def short(self) -> str:
        """Return RDATA with Zone formatting"""
        lines: List[str] = []
        for rr in self.rr:
            if rr.rdata is None or isinstance(rr.rdata, list):
                # if list, then was QTYPE.OPT and List[EDNSOption]
                continue
            lines.extend(rr.rdata.toZone())
        return "\n".join(lines)

    def __eq__(self, other: Any) -> bool:
        # Note: we compare classes to prevent allowing subclasses
        if type(other) != type(self):
            return False
        return not self.diff(other)

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)

    def diff(self, other: "DNSRecord") -> List[Tuple[Any, Any]]:
        """Diff records - recursively diff sections (sorting RRs)

        Args:
            other: record to diff against

        Returns:
            differences between the two records
        """
        err: List[Tuple[Any, Any]] = []
        if self.header != other.header:
            err.append((self.header, other.header))
        for section in ("questions", "rr", "auth", "ar"):
            if section == "questions":
                k = lambda x: tuple(map(str, (x.qname, x.qtype)))
            else:
                k = lambda x: tuple(map(str, (x.rname, x.rtype, x.rdata)))
            a = {k(rr): rr for rr in getattr(self, section)}
            b = {k(rr): rr for rr in getattr(other, section)}
            sa = set(a)
            sb = set(b)
            for e in sorted(sa.intersection(sb)):
                if a[e] != b[e]:
                    err.append((a[e], b[e]))
            for e in sorted(sa.difference(sb)):
                err.append((a[e], None))
            for e in sorted(sb.difference(sa)):
                err.append((None, b[e]))
        return err

    def __repr__(self) -> str:
        return self.format()

    def __str__(self) -> str:
        return self.toZone()


def _dns_header_bitmap_field(name: str, pos: int, bits: int = 1):
    """Create a property for a field in the DNSHeader bitmap

    Args:
        name: name of field (in lowercase)
        pos: position of field in the bitmap
        bits: size of field in bits

    Returns:
        property with getter and setter
    """

    ## Create Property
    def getter(obj) -> int:
        return get_bits(obj.bitmap, pos, bits)

    def setter(obj, val: int) -> None:
        check_range(name, val, 0, 2**bits - 1)
        obj.bitmap = set_bits(obj.bitmap, val, pos, bits)
        return

    return property(getter, setter, doc=f"{name} field in bitmap")


class DNSHeader:
    """DNS Message Header

    References:

    - <https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1>
    - <https://datatracker.ietf.org/doc/html/rfc2535#section-6.1>

    Attributes:
        id: (`ID`) message id

            Queries should generate this field, responses should copy this from
            the corresponding query.

        bitmap: bytes containing combined qr,opcode,aa,tc,rd,ra,z,ad,cd,rcode fields

            warning: You should not work with the bitmap directly.
                Instead use the corresponding property attributes.
                e.g. (`header.rd = 1`)

        qr: (`QR`) query or response
        opcode: (`OPCODE`) kind of query
        aa: (`AA`) if message is authorative answer
        tc: (`TC`) if message is truncated
        rd: (`RD`) recursion desired
        ra: (`RA`) recursion available
        z: (`Z`) (reserved)
        ad: (`AD`) authentic data (RFC2535, RFC3655)
        cd: (`CD`) checking disabled (RFC2535, RFC3655)
        rcode: (`RCODE`) response code
        q: (`QDCOUNT`) number of questions
        a: (`ANCOUNT`) number of answer records
        auth: (`NSCOUNT`) number of name server resource record in authority section
        ar: (`ARCOUNT`) number of additional records

    Changed in 1.0: Removed `[get,set]_[qr,opcode,aa,tc,rd,ra,z,ad,cd,rcode]`.
    """

    # Ensure attribute values match packet
    id = H("id")
    bitmap = H("bitmap")
    q = H("q")
    a = H("a")
    auth = H("auth")
    ar = H("ar")

    # note: bitmap fields are in "opposite" order to RFC, but thats just internal
    # implementation detail here - the correct order will be produced when packed.
    qr = _dns_header_bitmap_field("qr", 15)
    opcode = _dns_header_bitmap_field("opcode", 11, 4)
    aa = _dns_header_bitmap_field("aa", 10)
    tc = _dns_header_bitmap_field("tc", 9)
    rd = _dns_header_bitmap_field("rd", 8)
    ra = _dns_header_bitmap_field("ra", 7)
    z = _dns_header_bitmap_field("z", 6)
    ad = _dns_header_bitmap_field("ad", 5)
    cd = _dns_header_bitmap_field("cd", 4)
    rcode = _dns_header_bitmap_field("rcode", 0, 4)

    @classmethod
    def parse(cls, buffer: DNSBuffer) -> Self:
        """Implements parse interface

        Args:
            buffer: buffer to read from
        """
        try:
            id, bitmap, q, a, auth, ar = buffer.unpack("!HHHHHH")
            return cls(id, bitmap, q, a, auth, ar)
        except (BufferError, BimapError) as e:
            raise make_parse_error(cls, buffer, e)

    def __init__(
        self,
        id: Optional[int] = None,
        bitmap: Optional[int] = None,
        q: Optional[int] = 0,
        a: Optional[int] = 0,
        auth: Optional[int] = 0,
        ar: Optional[int] = 0,
        **kwargs: int,
    ) -> None:
        """
        Args:
            id: message id. If `None` will be randomly generated.
            bitmap: integer representing fields. See `self.bitmap` for more details.
            q: question count
            a: answer record cound
            auth: authority name server record count
            ar: additional record count
            kwargs: fields to in bitmap. See `self.bitmap` for list of fields.
        """
        self.id = id if id is not None else random.randint(0, 65535)
        if bitmap is None:
            self.bitmap = 0
            self.rd = 1
        else:
            self.bitmap = bitmap

        self.q = q
        self.a = a
        self.auth = auth
        self.ar = ar

        for name in ("qr", "opcode", "aa", "tc", "rd", "ra", "z", "ad", "cd", "rcode"):
            if name in kwargs:
                setattr(self, name, kwargs.pop(name))

        if kwargs:
            raise ValueError(f"Unkown kwargs: {kwargs}")
        return

    def pack(self, buffer: DNSBuffer) -> None:
        """Pack this header into a buffer

        Args:
            buffer:
        """
        buffer.pack("!HHHHHH", self.id, self.bitmap, self.q, self.a, self.auth, self.ar)
        return

    def __repr__(self) -> str:
        f = [
            self.aa and "AA",
            self.tc and "TC",
            self.rd and "RD",
            self.ra and "RA",
            self.z and "Z",
            self.ad and "AD",
            self.cd and "CD",
        ]
        if OPCODE.get(self.opcode) == "UPDATE":
            f1 = "zo"
            f2 = "pr"
            f3 = "up"
            f4 = "ad"
        else:
            f1 = "q"
            f2 = "a"
            f3 = "ns"
            f4 = "ar"
        return (
            "<DNS Header: id=0x%x type=%s opcode=%s flags=%s "
            "rcode='%s' %s=%d %s=%d %s=%d %s=%d>"
            % (
                self.id,
                QR.get(self.qr),
                OPCODE.get(self.opcode),
                ",".join(filter(None, f)),
                RCODE.get(self.rcode),
                f1,
                self.q,
                f2,
                self.a,
                f3,
                self.auth,
                f4,
                self.ar,
            )
        )

    def toZone(self) -> str:
        """Encode into Zone format"""
        f = [
            self.qr and "qr",
            self.aa and "aa",
            self.tc and "tc",
            self.rd and "rd",
            self.ra and "ra",
            self.z and "z",
            self.ad and "ad",
            self.cd and "cd",
        ]
        zone = (
            f";; ->>HEADER<<- opcode: {OPCODE.get(self.opcode)}, status: {RCODE.get(self.rcode)}, id: {self.id}"
            "\n"
            f";; flags: {' '.join(filter(None, f))}; QUERY: {self.q}, ANSWER: {self.a}, AUTHORITY: {self.auth}, ADDITIONAL: {self.ar}"
        )
        return zone

    def __str__(self) -> str:
        return self.toZone()

    def __ne__(self, other: Any) -> bool:
        return not (self.__eq__(other))

    def __eq__(self, other: Any) -> bool:
        """Check if this header is equal to another header.

        note:
            This checks for equality for all header fields **except** the `id` field.
        """
        if type(other) != type(self):
            return False

        # Ignore id
        attrs = ("qr", "aa", "tc", "rd", "ra", "z", "ad", "cd", "opcode", "rcode")
        return all([getattr(self, x) == getattr(other, x) for x in attrs])


class DNSQuestion:
    """DNS MEssage Question section

    Attributes:
        qname:
        qtype:
        qclass:

    Changed in 1.0: Removed `[set,get]_qname`.
    """

    qname = create_label_property("qname")

    @classmethod
    def parse(cls, buffer: DNSBuffer) -> Self:
        try:
            qname = buffer.decode_name()
            qtype, qclass = buffer.unpack("!HH")
            return cls(qname, qtype, qclass)
        except (BufferError, BimapError) as e:
            raise make_parse_error(cls, buffer, e)

    def __init__(self, qname: DNSLabelCreateTypes = None, qtype: int = 1, qclass: int = 1) -> None:
        """
        Args:
            qname:
            qtype:
            qclass:
        """
        self.qname = qname
        self.qtype = qtype
        self.qclass = qclass
        return

    def pack(self, buffer: DNSBuffer) -> None:
        """Pack this question into a buffer

        Args:
            buffer:
        """
        buffer.encode_name(self.qname)
        buffer.pack("!HH", self.qtype, self.qclass)
        return

    def toZone(self) -> str:
        """Encode into Zone format."""
        return ";%-30s %-7s %s" % (self.qname, CLASS.get(self.qclass), QTYPE[self.qtype])

    def __repr__(self) -> str:
        return f"<DNS Question: '{self.qname}' qtype={QTYPE.get(self.qtype)} qclass={CLASS.get(self.qclass)}>"

    def __str__(self) -> str:
        return self.toZone()

    def __ne__(self, other: Any) -> bool:
        return not (self.__eq__(other))

    def __eq__(self, other: Any) -> bool:
        if type(other) != type(self):
            return False
        # List of attributes to compare when diffing
        attrs = ("qname", "qtype", "qclass")
        return all([getattr(self, x) == getattr(other, x) for x in attrs])


class EDNSOption:
    """EDNSOption pseudo-section

    Very rudimentary support for EDNS0 options however this has not been
    tested due to a lack of data (anyone wanting to improve support or
    provide test data please raise an issue)

    Attributes:
        code:
        data:

    ```pycon
    >>> EDNSOption(1,b"1234")
    <EDNS Option: Code=1 Data='31323334'>
    >>> EDNSOption(99999,b"1234")
    Traceback (most recent call last):
    ...
    ValueError: Attribute 'code' must be between 0-65535 [99999]
    >>> EDNSOption(1,None)
    Traceback (most recent call last):
    ...
    ValueError: Attribute 'data' must be instance of ...

    ```
    """

    code = H("code")
    data = BYTES("data")

    def __init__(self, code: int, data: bytes) -> None:
        """
        Args:
            code:
            data:
        """
        self.code = code
        self.data = data
        return

    def pack(self, buffer: DNSBuffer) -> None:
        """Pack into buffer

        Args:
            buffer:
        """
        buffer.pack("!H", self.code)
        buffer.append_with_length("!H", self.data)
        return

    def __repr__(self) -> str:
        return f"<EDNS Option: Code={self.code} Data='{self.data.hex()}'>"

    def toZone(self) -> str:
        """Encode into Zone format"""
        return f"; EDNS: code: {self.code}; data: {self.data.hex()}"

    def __str__(self) -> str:
        return self.toZone()

    def __ne__(self, other: Any) -> bool:
        return not (self.__eq__(other))

    def __eq__(self, other: Any) -> bool:
        if type(other) != type(self):
            return False
        # List of attributes to compare when diffing
        attrs = ("code", "data")
        return all([getattr(self, x) == getattr(other, x) for x in attrs])


class RR:
    """DNS Resource Record

    Contains RR header and RD (resource data) instance

    Attributes:
        rname: (`NAME`) the name of the node to which this resource record pertains.
        rtype: (`TYPE`) two octets containing one of the RR TYPE codes.
        rclass: (`CLASS`) two octets containing one of the RR CLASS codes.
        ttl: (`TTL`) a 32 bit signed integer that specifies the time interval
            that the resource record may be cached before the source
            of the information should again be consulted.  Zero
            values are interpreted to mean that the RR can only be
            used for the transaction in progress, and should not be
            cached.  For example, SOA records are always distributed
            with a zero TTL to prohibit caching.  Zero values can
            also be used for extremely volatile data.

        rdlength: (`RDLENGTH`) an unsigned 16 bit integer that specifies the length in
                octets of the RDATA field.

        edns_do: ???

    References:

    - https://datatracker.ietf.org/doc/html/rfc1035#section-3.2

    Changed in 1.0:

        - remove `[get,set]_[rname,do]`
        - EDNS Pseudo records (`QTYPE.OPT`) now use `EDNSRD` to hold options.
        - `self.rdata` is now never `None`. If `rdata` is `None` then an empty `RD()` is used.
    """

    rtype = H("rtype")
    rclass = H("rclass")
    ttl = I("ttl")
    rdlength = H("rdlength")

    rname = create_label_property("rname")

    @classmethod
    def parse(cls, buffer: DNSBuffer) -> Self:
        """Parse from buffer

        Args:
            buffer:
        """
        try:
            rname = buffer.decode_name()
            rtype, rclass, ttl, rdlength = buffer.unpack("!HHIH")
            rdata = RDMAP.get(QTYPE.get(rtype), RD).parse(buffer, rdlength)
            return cls(rname, rtype, rclass, ttl, rdata)
        except (BufferError, BimapError) as e:
            raise make_parse_error(cls, buffer, e)

    @classmethod
    def fromZone(cls, zone: str, origin: DNSLabelCreateTypes = None, ttl: int = 0) -> List[Self]:
        """Parse RR data from zone file and return list of RRs"""
        return list(ZoneParser(zone, origin=origin, ttl=ttl))

    def __init__(
        self,
        rname: DNSLabelCreateTypes = None,
        rtype: int = 1,
        rclass: int = 1,
        ttl: int = 0,
        rdata: "Optional[RD]" = None,
    ) -> None:
        """
        Args:
            rname:
            rtype:
            rclass:
            ttl:
            rdata: ???
        """
        self.rname = rname
        self.rtype = rtype
        self.rclass = rclass
        self.ttl = ttl
        self.rdata = rdata or RD()
        # TODO Add property getters/setters (done for DO flag)
        if self.rtype == QTYPE.OPT:
            self.edns_len = self.rclass
            self.edns_ver = get_bits(self.ttl, 16, 8)
            self.edns_rcode = get_bits(self.ttl, 24, 8)
        return

    @property
    def edns_do(self) -> int:
        if self.rtype == QTYPE.OPT:
            return get_bits(self.ttl, 15)
        raise AttributeError("Cannot access edns_do on non-OPT QTYPE.")

    @edns_do.setter
    def edns_do(self, val: int) -> None:
        if self.rtype == QTYPE.OPT:
            self.ttl = set_bits(self.ttl, val, 15)
            return
        raise AttributeError("Cannot access edns_do on non-OPT QTYPE.")

    def pack(self, buffer: DNSBuffer) -> None:
        """Pack into a buffer"""
        buffer.encode_name(self.rname)
        buffer.pack("!HHI", self.rtype, self.rclass, self.ttl)
        rdlength_ptr = buffer.offset
        buffer.pack("!H", 0)
        start = buffer.offset
        self.rdata.pack(buffer)
        end = buffer.offset
        buffer.update(rdlength_ptr, "!H", end - start)
        return

    def __repr__(self) -> str:
        if self.rtype == QTYPE.OPT:
            edns = "<DNS OPT: edns_ver=%d do=%d ext_rcode=%d udp_len=%d>" % (
                self.edns_ver,
                self.edns_do,
                self.edns_rcode,
                self.edns_len,
            )
            options = repr(self.rdata)
            return f"{edns}\n{options}" if options else edns

        return "<DNS RR: '%s' rtype=%s rclass=%s ttl=%d rdata='%s'>" % (
            self.rname,
            QTYPE.get(self.rtype),
            CLASS.get(self.rclass),
            self.ttl,
            self.rdata if self.rdata is not None else "",
        )

    def toZone(self) -> str:
        """Encode into Zone format"""
        if self.rtype == QTYPE.OPT:
            edns = [
                ";; OPT PSEUDOSECTION",
                "; EDNS: version: %d, flags: %s; udp: %d"
                % (self.edns_ver, "do" if self.edns_do else "", self.edns_len),
            ]
            options = self.rdata.toZone()
            if options:
                edns.append(options)
            return "\n".join(edns)
        return "%-23s %-7s %-7s %-7s %s" % (
            self.rname,
            self.ttl,
            CLASS.get(self.rclass),
            QTYPE[self.rtype],
            self.rdata.toZone() if self.rdata is not None else "",
        )

    def __str__(self):
        return self.toZone()

    def __ne__(self, other):
        return not (self.__eq__(other))

    def __eq__(self, other):
        # Handle OPT specially as may be different types (RR/EDNS0)
        if self.rtype == QTYPE.OPT and getattr(other, "rtype", False) == QTYPE.OPT:
            attrs = ("rname", "rclass", "rtype", "ttl", "rdata")
            return all([getattr(self, x) == getattr(other, x) for x in attrs])
        else:
            if type(other) != type(self):
                return False
            else:
                # List of attributes to compare when diffing (ignore ttl)
                attrs = ("rname", "rclass", "rtype", "rdata")
                return all([getattr(self, x) == getattr(other, x) for x in attrs])


class EDNS0(RR):
    """ENDS0 pseudo-record

    Wrapper around the ENDS0 support in RR to make it more convenient to
    create EDNS0 pseudo-record - this just makes it easier to specify the
    EDNS0 parameters directly

    EDNS flags should be passed as a space separated string of options
    (currently only 'do' is supported)

    ```pycon
    >>> EDNS0("abc.com",flags="do",udp_len=2048,version=1)
    <DNS OPT: edns_ver=1 do=1 ext_rcode=0 udp_len=2048>
    >>> print(_)
    ;; OPT PSEUDOSECTION
    ; EDNS: version: 1, flags: do; udp: 2048
    >>> opt = EDNS0("abc.com",flags="do",ext_rcode=1,udp_len=2048,version=1,opts=[EDNSOption(1,b'abcd')])
    >>> opt
    <DNS OPT: edns_ver=1 do=1 ext_rcode=1 udp_len=2048>
    <EDNS Option: Code=1 Data='61626364'>
    >>> print(opt)
    ;; OPT PSEUDOSECTION
    ; EDNS: version: 1, flags: do; udp: 2048
    ; EDNS: code: 1; data: 61626364
    >>> r = DNSRecord.question("abc.com").replyZone("abc.com A 1.2.3.4")
    >>> r.add_ar(opt)
    >>> print(r)
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
    ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 1
    ;; QUESTION SECTION:
    ;abc.com.                       IN      A
    ;; ANSWER SECTION:
    abc.com.                0       IN      A       1.2.3.4
    ;; ADDITIONAL SECTION:
    ;; OPT PSEUDOSECTION
    ; EDNS: version: 1, flags: do; udp: 2048
    ; EDNS: code: 1; data: 61626364
    >>> DNSRecord.parse(r.pack()) == r
    True

    ```
    """

    def __init__(
        self,
        rname=None,
        rtype=QTYPE.OPT,
        ext_rcode: int = 0,
        version=0,
        flags="",
        udp_len=0,
        opts=None,
    ) -> None:
        """
        Args:
            rname:
            rtype:
            ext_code:
            version:
            flags:
            udp_len:
            opts:
        """
        check_range("ext_rcode", ext_rcode, 0, 255)
        check_range("version", version, 0, 255)
        edns_flags = {"do": 1 << 15}
        flag_bitmap = sum([edns_flags[x] for x in flags.split()])
        ttl = (ext_rcode << 24) + (version << 16) + flag_bitmap
        if opts and not all([isinstance(o, EDNSOption) for o in opts]):
            raise ValueError("Option must be instance of EDNSOption")
        super().__init__(rname, rtype, udp_len, ttl, EDNSRD(opts or []))
        return


class RD:
    """Base RD object - also used as placeholder for unknown RD types

    To create a new RD type subclass this and add to RDMAP (below)

    Subclass should implement (as a minimum):

        parse (parse from packet data)
        __init__ (create class)
        __repr__ (return in zone format)
        fromZone (create from zone format)

        (toZone uses __repr__ by default)

    Unknown rdata types default to RD and store rdata as a binary
    blob (this allows round-trip encoding/decoding)
    """

    # Attributes for comparison
    attrs: Tuple[str, ...] = ("data",)

    @classmethod
    def parse(cls, buffer: DNSBuffer, length: int) -> Self:
        """Unpack from buffer"""
        try:
            data = buffer.get(length)
            return cls(data)
        except (BufferError, BimapError) as e:
            raise make_parse_error(cls, buffer, e)

    @classmethod
    def fromZone(cls, rd: List[str], origin=None) -> Self:
        """Create new record from zone format data
        RD is a list of strings parsed from DiG output
        """
        # Unknown rata - assume hexdump in zone format
        # (DiG prepends "\\# <len>" to the hexdump so get last item)
        return cls(bytes.fromhex(rd[-1]))

    def __init__(self, data: bytes = b"") -> None:
        """
        Args:
            data: raw resource record data
        """
        # Assume raw bytes
        check_bytes("data", data)
        self.data = bytes(data)

    def pack(self, buffer: DNSBuffer) -> None:
        """Pack record into buffer"""
        buffer.append(self.data)
        return

    def __repr__(self) -> str:
        """
        Default 'repr' format should be equivalent to RD zone format
        """
        if len(self.data) > 0:
            return f"\\# {len(self.data)} {self.data.hex().upper()}"
        return "\\# 0"

    def toZone(self) -> str:
        return repr(self)

    # Comparison operations - in most cases only need to override 'attrs'
    # in subclass (__eq__ will automatically compare defined attrs)

    def __eq__(self, other: Any) -> bool:
        if type(other) != type(self):
            return False
        return all([getattr(self, x) == getattr(other, x) for x in self.attrs])

    def __ne__(self, other: Any) -> bool:
        return not self.__eq__(other)


class _LabelOnlyRd(RD):
    """Base class for RD types that only have a label

    Attributes:
        attrs:
        label:

    New in 1.0
    """

    attrs = ("label",)
    label = create_label_property()

    @classmethod
    def parse(cls, buffer: DNSBuffer, length: int) -> Self:
        """Parse from buffer

        Args:
            buffer:
            length:
        """
        try:
            label = buffer.decode_name()
            return cls(label)
        except (BufferError, BimapError) as e:
            raise make_parse_error(cls, buffer, e)

    @classmethod
    def fromZone(cls, rd: List[str], origin=None) -> Self:
        """Parse from Zone

        Args:
            rd:
            origin:
        """
        return cls(create_label(rd[0], origin))

    def __init__(self, label: DNSLabelCreateTypes = None) -> None:
        """
        Args:
            label:
        """
        self.label = label
        return

    def pack(self, buffer):
        buffer.encode_name(self.label)
        return

    def toZone(self) -> str:
        return repr(self)

    def __repr__(self):
        return str(self.label)


class EDNSRD(RD):
    """Pseudo RDATA for EDNS Options

    References:

    - https://datatracker.ietf.org/doc/html/rfc6891#section-6.1.2

    New in 1.0
    """

    attrs = ("options",)

    @classmethod
    def parse(cls, buffer: DNSBuffer, length: int) -> Self:
        """Parse from buffer

        Args:
            buffer:
            length:
        """
        try:
            options: List[EDNSOption] = []
            option_buffer = Buffer(buffer.get(length))
            while option_buffer.remaining:
                code = option_buffer.unpack_one("!H")
                data = option_buffer.get_with_length("!H")
                options.append(EDNSOption(code, data))
            return cls(options)
        except (BufferError, BimapError) as e:
            raise make_parse_error(cls, buffer, e)

    @classmethod
    def fromZone(cls, rd: List[str], origin=None) -> Self:
        """Parse from Zone

        Args:
            rd:
            origin:
        """
        raise NotImplementedError("Cannot parse EDNS Options from Zone")

    def __init__(self, options: Optional[List[EDNSOption]] = None) -> None:
        """
        Args:
            options: list of `EDNSOption`
        """
        self.options = options or []
        return

    def pack(self, buffer: DNSBuffer) -> None:
        """Pack into buffer

        Args:
            buffer:
        """
        for option in self.options:
            option.pack(buffer)
        return

    def toZone(self) -> str:
        return "\n".join(str(option) for option in self.options)

    def __repr__(self) -> str:
        return "\n".join(repr(option) for option in self.options)


class TXT(RD):
    """Text Record

    Pass in either a single byte/unicode string, or a tuple/list of byte/unicode strings.
    (byte strings are preferred as this avoids possible encoding issues)

    References:

    - https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.14

    Note:

    > <character-string> is a single length octet followed by that number of
    > characters.  <character-string> is treated as binary information, and
    > can be up to 256 characters in length (including the length octet).

    ```pycon
    >>> TXT(b'txtvers=1')
    "txtvers=1"
    >>> TXT((b'txtvers=1',))
    "txtvers=1"
    >>> TXT([b'txtvers=1',])
    "txtvers=1"
    >>> TXT([b'txtvers=1',b'swver=2.5'])
    "txtvers=1","swver=2.5"
    >>> TXT(['txtvers=1','swver=2.5'])
    "txtvers=1","swver=2.5"
    >>> a = DNSRecord()
    >>> a.add_answer(*RR.fromZone('example.com 60 IN TXT "txtvers=1"'))
    >>> a.add_answer(*RR.fromZone('example.com 120 IN TXT "txtvers=1" "swver=2.3"'))
    >>> print(a)
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
    ;; flags: rd; QUERY: 0, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0
    ;; ANSWER SECTION:
    example.com.            60      IN      TXT     "txtvers=1"
    example.com.            120     IN      TXT     "txtvers=1" "swver=2.3"

    ```
    """

    attrs = ("texts",)

    @classmethod
    def parse(cls, buffer: DNSBuffer, length: int) -> Self:
        """Parse from buffer

        Args:
            buffer:
            length:
        """
        try:
            texts = []
            remaining = length
            while remaining > 0:
                text = buffer.get_with_length("!B")
                remaining -= len(text) + 1  # +1 because of consumed length encoding
                texts.append(text)

            return cls(texts)
        except (BufferError, BimapError) as e:
            raise make_parse_error(cls, buffer, e)

    @classmethod
    def fromZone(cls, rd: List[str], origin=None) -> Self:
        """Create from Zone

        Args:
            rd:
            origin:
        """
        return cls(list(map(lambda x: x.encode(), rd)))

    def __init__(self, texts: Union[Sequence[bytes], Sequence[str], bytes, str]) -> None:
        """
        Args:
            data:
        """
        self.texts: List[bytes]
        if isinstance(texts, bytes):
            self.texts = [texts]
        elif isinstance(texts, str):
            self.texts = [texts.encode()]
        else:
            self.texts = [i.encode() if isinstance(i, str) else i for i in texts]

        if any([len(x) > 255 for x in self.texts]):
            raise DNSError(f"TXT record too long: {self.texts!r}")
        return

    def pack(self, buffer: DNSBuffer) -> None:
        """Pack into buffer

        Args:
            buffer:
        """
        for item in self.texts:
            if len(item) > 255:
                raise DNSError("TXT record too long: {self.item!r}")
            buffer.append_with_length("!B", item)
        return

    def toZone(self) -> str:
        """Encode into Zone format"""
        return " ".join([self._bytes_to_str(x) for x in self.texts])

    def __repr__(self) -> str:
        return ",".join([self._bytes_to_str(x) for x in self.texts])

    @staticmethod
    def _bytes_to_str(b: bytes) -> str:
        """Convert bytes into a printable character-string

        Note:

        > <character-string> is expressed in one or two ways: as a contiguous set
        > of characters without interior spaces, or as a string beginning with a "
        > and ending with a ".  Inside a " delimited string any character can
        > occur, except for a " itself, which must be quoted using \ (back slash).

        Args:
            b: byte string to convert

        Changed in 1.0: made this a staticmethod of TXT instead of a standalone function
        """
        return (
            '"'
            + "".join(
                [
                    (c if c.isprintable() else '\\"' if c == '"' else f"\\{ord(c):03o}")
                    for c in b.decode(errors="replace")
                ]
            )
            + '"'
        )


class A(RD):
    """(IPv4) Host Address

    References:

    - https://datatracker.ietf.org/doc/html/rfc1035#section-3.4.1

    Changed in 1.0: `self.data` property is now an `IPv4Address`.
    """

    data = IP4("data")

    @classmethod
    def parse(cls, buffer: DNSBuffer, length: int) -> Self:
        """Parse from buffer

        Args:
            buffer:
            length:
        """
        try:
            data = buffer.unpack_one("!4s")
            return cls(data)
        except (BufferError, BimapError) as e:
            raise make_parse_error(cls, buffer, e)

    @classmethod
    def fromZone(cls, rd: List[str], origin=None) -> Self:
        """Parse from Zone format

        Args:
            rd:
            origin:
        """
        return cls(rd[0])

    def __init__(self, data: Union[str, bytes, int, IPv4Address]) -> None:
        """
        Args:
            data: IPv4 Address

        Changed in 1.0: `data` must be one of `str`, `bytes`, `int`, `IPv4Address`
        (it can no longer be `tuple`, `list`).
        """
        self.data = data
        return

    def pack(self, buffer: DNSBuffer) -> None:
        """Pack into buffer:

        Args:
            buffer:
        """
        buffer.pack("!4s", self.data.packed)
        return

    def __repr__(self) -> str:
        return str(self.data)


class AAAA(RD):
    """IPv6 host Address

    References:

    - https://datatracker.ietf.org/doc/html/rfc3596

    Changed in 1.0: `self.data` property is now an `IPv46ddress`.
    """

    data = IP6("data")

    @classmethod
    def parse(cls, buffer: DNSBuffer, length: int) -> Self:
        """Parse from buffer

        Args:
            buffer:
            length:
        """
        try:
            data = buffer.unpack_one("!16s")
            return cls(data)
        except (BufferError, BimapError) as e:
            raise make_parse_error(cls, buffer, e)

    @classmethod
    def fromZone(cls, rd: List[str], origin=None) -> Self:
        """Parse from Zone

        Args:
            rd:
            origin:
        """
        return cls(rd[0])

    def __init__(self, data: Union[str, bytes, int, IPv6Address]) -> None:
        """
        Args:
            data: the IPv6 Address

        Changed in 1.0: `data` must be one of `str`, `bytes`, `int`, `IPv6Address`
        (it can no longer be `tuple`, `list`).
        """
        self.data = data
        return

    def pack(self, buffer: DNSBuffer) -> None:
        """Pack into buffer:

        Args:
            buffer:
        """
        buffer.pack("!16s", self.data.packed)
        return

    def __repr__(self) -> str:
        return str(self.data)


class MX(RD):
    """Mail eXchange

    Attributes:
        label:
        preference:

    References:

    - https://datatracker.ietf.org/doc/html/rfc1035#autoid-27

    Changed in 1.0: Removed `[get,set]_label`
    """

    attrs = ("preference", "label")

    preference = H("preference")
    label = create_label_property()

    @classmethod
    def parse(cls, buffer: DNSBuffer, length: int) -> Self:
        """Parse from buffer

        Args:
            buffer:
            length:
        """
        try:
            preference = buffer.unpack_one("!H")
            mx = buffer.decode_name()
            return cls(mx, preference)
        except (BufferError, BimapError) as e:
            raise make_parse_error(cls, buffer, e)

    @classmethod
    def fromZone(cls, rd: List[str], origin=None) -> Self:
        """Parse from Zone

        Args:
            rd:
            origin:
        """
        return cls(create_label(rd[1], origin), int(rd[0]))

    def __init__(self, label: DNSLabelCreateTypes = None, preference: int = 10) -> None:
        self.label = label
        self.preference = preference
        return

    def pack(self, buffer: DNSBuffer) -> None:
        """Pack into buffer

        Args:
            buffer:
        """
        buffer.pack("!H", self.preference)
        buffer.encode_name(self.label)
        return None

    def __repr__(self) -> str:
        return f"{self.preference} {self.label}"


class CNAME(_LabelOnlyRd):
    """Canonical Name for an alias

    Attributes:
        label:

    References:

    - https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.1

    Changed in 1.0: Removed `[get,set]_label`
    """


class PTR(_LabelOnlyRd):
    """Domain Name Pointer

    Attributes:
        label:

    References:

    - https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.12

    Changed in 1.0: Removed `[get,set]_label`
    """


class NS(_LabelOnlyRd):
    """Authoritive Name Server

    Attributes:
        label:

    References:

    - https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.11

    Changed in 1.0: Removed `[get,set]_label`
    """


class DNAME(_LabelOnlyRd):
    """Domain NAME record

    Attributes:
        label:

    References:

    - https://datatracker.ietf.org/doc/html/rfc6672

    Changed in 1.0: Removed `[get,set]_label`
    """


class SOA(RD):
    """Start Of Authority record

    Attributes:
        times:
        label:

    References:

    - https://datatracker.ietf.org/doc/html/rfc1035#section-3.3.13

    Changed in 1.0: Removed `[get,set]_[mname,rname]`
    """

    attrs = ("mname", "rname", "times")

    times = ntuple_range("times", 5, 0, 4294967295)
    mname = create_label_property("mname")
    rname = create_label_property("rname")

    @classmethod
    def parse(cls, buffer: DNSBuffer, length: int) -> Self:
        """Parse from buffer

        Args:
            buffer:
            length:
        """
        try:
            mname = buffer.decode_name()
            rname = buffer.decode_name()
            times = buffer.unpack("!IIIII")
            return cls(mname, rname, times)
        except (BufferError, BimapError) as e:
            raise make_parse_error(cls, buffer, e)

    @classmethod
    def fromZone(cls, rd: List[str], origin: DNSLabelCreateTypes = None) -> Self:
        """Parse from Zone

        Args:
            rd:
            origin:
        """
        return cls(
            create_label(rd[0], origin),
            create_label(rd[1], origin),
            [parse_time(t) for t in rd[2:]],
        )

    def __init__(
        self,
        mname: DNSLabelCreateTypes = None,
        rname: DNSLabelCreateTypes = None,
        times: Union[List[int], Tuple[int, int, int, int, int], None] = None,
    ) -> None:
        self.mname = mname
        self.rname = rname
        self.times = tuple(times) if times else (0, 0, 0, 0, 0)
        return

    def pack(self, buffer: DNSBuffer) -> None:
        """Pack into buffer

        Args:
            buffer:
        """
        buffer.encode_name(self.mname)
        buffer.encode_name(self.rname)
        buffer.pack("!IIIII", *self.times)
        return

    def __repr__(self) -> str:
        return f"{self.mname} {self.rname} {' '.join(map(str, self.times))}"


class SRV(RD):
    """Service Location record

    Attributes:
        priority:
        weight:
        port:
        target:

    References:

    - https://datatracker.ietf.org/doc/html/rfc2782

    Changed in 1.0: Removed `[get,set]_target`
    """

    attrs = ("priority", "weight", "port", "target")

    priority = H("priority")
    weight = H("weight")
    port = H("port")
    target = create_label_property("target")

    @classmethod
    def parse(cls, buffer: DNSBuffer, length: int) -> Self:
        """Parse from buffer

        Args:
            buffer:
            length:
        """
        try:
            priority, weight, port = buffer.unpack("!HHH")
            target = buffer.decode_name()
            return cls(priority, weight, port, target)
        except (BufferError, BimapError) as e:
            raise make_parse_error(cls, buffer, e)

    @classmethod
    def fromZone(cls, rd: List[str], origin: DNSLabelCreateTypes = None) -> Self:
        """Parse from Zone

        Args:
            rd:
            origin:
        """
        return cls(int(rd[0]), int(rd[1]), int(rd[2]), rd[3])

    def __init__(
        self, priority: int = 0, weight: int = 0, port: int = 0, target: DNSLabelCreateTypes = None
    ) -> None:
        """
        Args:
            priority:
            weight:
            port:
            target:
        """
        self.priority = priority
        self.weight = weight
        self.port = port
        self.target = target

    def pack(self, buffer: DNSBuffer) -> None:
        """Pack into buffer

        Args:
            buffer:
        """
        buffer.pack("!HHH", self.priority, self.weight, self.port)
        buffer.encode_name(self.target)
        return

    def __repr__(self) -> str:
        return f"{self.priority} {self.weight} {self.port} {self.target}"


class NAPTR(RD):
    """Naming Authority Pointer

    NAPTR is part of the Dynamic Delegation Discovery System (DDDS).

    Attributes:
        order:
        preference:
        flags:
        service:
        regexp:
        replacement:

    References:

    - https://datatracker.ietf.org/doc/html/rfc3403

    Changed in 1.0: Removed `[get,set]_replacement`
    """

    attrs = ("order", "preference", "flags", "service", "regexp", "replacement")

    order = H("order")
    preference = H("preference")
    replacement = create_label_property("replacement")

    @classmethod
    def parse(cls, buffer: DNSBuffer, length: int) -> Self:
        """Parse from buffer

        Args:
            buffer:
            length:
        """
        try:
            order, preference = buffer.unpack("!HH")
            flags = buffer.get_with_length("!B")
            service = buffer.get_with_length("!B")
            regexp = buffer.get_with_length("!B")
            replacement = buffer.decode_name()
            return cls(order, preference, flags, service, regexp, replacement)
        except (BufferError, BimapError) as e:
            raise make_parse_error(cls, buffer, e)

    @classmethod
    def fromZone(cls, rd: List[str], origin: DNSLabelCreateTypes = None) -> Self:
        """Parse from Zone

        Args:
            rd:
            origin:
        """
        result = cls(
            int(rd[0]),
            int(rd[1]),
            rd[2].encode(),
            rd[3].encode(),
            rd[4].encode(),
            create_label(rd[5], origin),
        )
        return result

    def __init__(
        self,
        order: int,
        preference: int,
        flags: bytes,
        service: bytes,
        regexp: bytes,
        replacement: DNSLabelCreateTypes = None,
    ) -> None:
        """
        Args:
            order:
            preference:
            flags:
            service:
            regexp:
            replacement:
        """
        self.order = order
        self.preference = preference
        self.flags = flags
        self.service = service
        self.regexp = regexp
        self.replacement = replacement
        return

    def pack(self, buffer: DNSBuffer) -> None:
        """Pack into buffer

        Args:
            buffer:
        """
        buffer.pack("!HH", self.order, self.preference)
        buffer.append_with_length("!B", self.flags)
        buffer.append_with_length("!B", self.service)
        buffer.append_with_length("!B", self.regexp)
        buffer.encode_name(self.replacement)
        return

    def __repr__(self) -> str:
        return '%d %d "%s" "%s" "%s" %s' % (
            self.order,
            self.preference,
            self.flags.decode(),
            self.service.decode(),
            self.regexp.decode().replace("\\", "\\\\"),
            self.replacement or ".",
        )


class DS(RD):
    """Delegation Signer record

    `DS` records are a part of DNSSEC

    Attributes:
        key_tag:
        algorithm:
        digest_type:
        digest:

    References:

    - https://datatracker.ietf.org/doc/html/rfc4034#section-5
    """

    attrs = ("key_tag", "algorithm", "digest_type", "digest")

    key_tag = H("key_tag")
    algorithm = B("algorithm")
    digest_type = B("digest_type")

    @classmethod
    def parse(cls, buffer: DNSBuffer, length: int) -> Self:
        """Parse from buffer

        Args:
            buffer:
            length:
        """
        try:
            key_tag, algorithm, digest_type = buffer.unpack("!HBB")
            digest = buffer.get(length - 4)
            return cls(key_tag, algorithm, digest_type, digest)
        except (BufferError, BimapError) as e:
            raise make_parse_error(cls, buffer, e)

    @classmethod
    def fromZone(cls, rd: List[str], origin: DNSLabelCreateTypes = None) -> Self:
        """Parse from Zone

        Args:
            rd:
            origin:
        """
        return cls(int(rd[0]), int(rd[1]), int(rd[2]), bytes.fromhex("".join(rd[3:])))

    def __init__(self, key_tag: int, algorithm: int, digest_type: int, digest: bytes) -> None:
        """
        Args:
            key_tag:
            algorithm:
            digest_type:
            digest:
        """
        self.key_tag = key_tag
        self.algorithm = algorithm
        self.digest_type = digest_type
        self.digest = digest
        return

    def pack(self, buffer: DNSBuffer) -> None:
        """Pack into buffer

        Args:
            buffer:
        """
        buffer.pack("!HBB", self.key_tag, self.algorithm, self.digest_type)
        buffer.append(self.digest)
        return

    def __repr__(self) -> str:
        return " ".join(
            map(
                str,
                (
                    self.key_tag,
                    self.algorithm,
                    self.digest_type,
                    self.digest.hex().upper(),
                ),
            )
        )


class DNSKEY(RD):
    """DNSSEC Key

    `DNSKEY` records are a part of DNSSEC

    Atrributes:
        flags:
        protocol:
        algorithm:
        key:

    References:

    - https://datatracker.ietf.org/doc/html/rfc4034#section-2
    """

    attrs = ("flags", "protocol", "algorithm", "key")

    flags = H("flags")
    protocol = B("protocol")
    algorithm = B("algorithm")

    @classmethod
    def parse(cls, buffer: DNSBuffer, length: int) -> Self:
        """Parse from buffer

        Args:
            buffer:
            length:
        """
        try:
            flags, protocol, algorithm = buffer.unpack("!HBB")
            key = buffer.get(length - 4)
            return cls(flags, protocol, algorithm, key)
        except (BufferError, BimapError) as e:
            raise make_parse_error(cls, buffer, e)

    @classmethod
    def fromZone(cls, rd: List[str], origin: DNSLabelCreateTypes = None) -> Self:
        """Parse from Zone

        Args:
            rd:
            origin:
        """
        return cls(
            int(rd[0]), int(rd[1]), int(rd[2]), base64.b64decode(("".join(rd[3:])).encode("ascii"))
        )

    def __init__(self, flags: int, protocol: int, algorithm: int, key: bytes) -> None:
        self.flags = flags
        self.protocol = protocol
        self.algorithm = algorithm
        self.key = key
        return

    def pack(self, buffer: DNSBuffer) -> None:
        """Pack into buffer

        Args:
            buffer:
        """
        buffer.pack("!HBB", self.flags, self.protocol, self.algorithm)
        buffer.append(self.key)
        return

    def __repr__(self):
        return " ".join(
            map(
                str,
                (
                    self.flags,
                    self.protocol,
                    self.algorithm,
                    base64.b64encode(self.key).decode(),
                ),
            )
        )


class RRSIG(RD):
    """Resource Record Set Signature

    `RRSIG` records are a part of DNSSEC

    Attributes:
        covered:
        algorithm:
        labels:
        orig_ttl:
        sig_exp:
        sig_inc:
        key_tag:

    References:

    - https://datatracker.ietf.org/doc/html/rfc4034#section-3
    """

    attrs = (
        "covered",
        "algorithm",
        "labels",
        "orig_ttl",
        "sig_exp",
        "sig_inc",
        "key_tag",
        "name",
        "sig",
    )

    covered = H("covered")
    algorithm = B("algorithm")
    labels = B("labels")
    orig_ttl = I("orig_ttl")
    sig_exp = I("sig_exp")
    sig_inc = I("sig_inc")
    key_tag = H("key_tag")
    name = create_label_property("name")

    @classmethod
    def parse(cls, buffer: DNSBuffer, length: int) -> Self:
        """Parse from buffer

        Args:
            buffer:
            length:
        """
        try:
            start = buffer.offset
            covered, algorithm, labels, orig_ttl, sig_exp, sig_inc, key_tag = buffer.unpack(
                "!HBBIIIH"
            )
            name = buffer.decode_name()
            sig = buffer.get(length - (buffer.offset - start))
            return cls(covered, algorithm, labels, orig_ttl, sig_exp, sig_inc, key_tag, name, sig)
        except (BufferError, BimapError) as e:
            raise make_parse_error(cls, buffer, e)

    @classmethod
    def fromZone(cls, rd: List[str], origin: DNSLabelCreateTypes = None) -> Self:
        """Parse from Zone

        Args:
            rd:
            origin:
        """
        return cls(
            getattr(QTYPE, rd[0]),
            int(rd[1]),
            int(rd[2]),
            int(rd[3]),
            int(calendar.timegm(time.strptime(rd[4] + "UTC", "%Y%m%d%H%M%S%Z"))),
            int(calendar.timegm(time.strptime(rd[5] + "UTC", "%Y%m%d%H%M%S%Z"))),
            int(rd[6]),
            rd[7],
            base64.b64decode(("".join(rd[8:])).encode("ascii")),
        )

    def __init__(
        self,
        covered: int,
        algorithm: int,
        labels: int,
        orig_ttl: int,
        sig_exp: int,
        sig_inc: int,
        key_tag: int,
        name: DNSLabelCreateTypes,
        sig: bytes,
    ) -> None:
        """
        Args:
            covered:
            algorithm:
            labels:
            orig_ttl:
            sig_exp:
            sig_inc:
            key_tag:
            name:
            sig:
        """
        self.covered = covered
        self.algorithm = algorithm
        self.labels = labels
        self.orig_ttl = orig_ttl
        self.sig_exp = sig_exp
        self.sig_inc = sig_inc
        self.key_tag = key_tag
        self.name = DNSLabel(name)
        self.sig = sig
        return

    def pack(self, buffer: DNSBuffer) -> None:
        """Pack into buffer

        Args:
            buffer:
        """
        buffer.pack(
            "!HBBIIIH",
            self.covered,
            self.algorithm,
            self.labels,
            self.orig_ttl,
            self.sig_exp,
            self.sig_inc,
            self.key_tag,
        )
        buffer.encode_name_nocompress(self.name)
        buffer.append(self.sig)
        return

    def __repr__(self) -> str:
        timestamp_fmt = (
            "{0.tm_year}{0.tm_mon:02}{0.tm_mday:02}{0.tm_hour:02}{0.tm_min:02}{0.tm_sec:02}"
        )
        return " ".join(
            map(
                str,
                (
                    QTYPE.get(self.covered),
                    self.algorithm,
                    self.labels,
                    self.orig_ttl,
                    timestamp_fmt.format(time.gmtime(self.sig_exp)),
                    timestamp_fmt.format(time.gmtime(self.sig_inc)),
                    self.key_tag,
                    self.name,
                    base64.b64encode(self.sig).decode(),
                ),
            )
        )


class NSEC(RD):
    """NSEC record

    `NSEC` records are a part of DNSSEC

    Attributes:
        label:
        rrlist:

    References:

    - https://datatracker.ietf.org/doc/html/rfc4034#section-4

    Changed in 1.0: Removed `[get,set]_replacement`
    """

    attrs = ("label", "rrlist")
    label = create_label_property()

    @classmethod
    def parse(cls, buffer: DNSBuffer, length: int) -> Self:
        """Parse from buffer

        Args:
            buffer:
            length:
        """
        try:
            end = buffer.offset + length
            name = buffer.decode_name()
            rrlist = cls.decode_type_bitmap(buffer.get(end - buffer.offset))
            return cls(name, rrlist)
        except (BufferError, BimapError) as e:
            raise make_parse_error(cls, buffer, e)

    @classmethod
    def fromZone(cls, rd: List[str], origin: DNSLabelCreateTypes = None) -> Self:
        """Parse from Zone

        Args:
            rd:
            origin:
        """
        return cls(rd.pop(0), rd)

    def __init__(self, label: DNSLabelCreateTypes, rrlist: List[str]) -> None:
        """
        Args:
            label:
            rrlist:
        """
        self.label = label
        self.rrlist = rrlist
        return

    def pack(self, buffer: DNSBuffer) -> None:
        """Pack into buffer

        Args:
            buffer:
        """
        buffer.encode_name_nocompress(self.label)
        buffer.append(self.encode_type_bitmap(self.rrlist))
        return

    def __repr__(self) -> str:
        return f"{self.label} {' '.join(self.rrlist)}"

    @staticmethod
    def decode_type_bitmap(type_bitmap: bytes) -> List[str]:
        """Parse RR type bitmap in NSEC record

        Args:
            type_bitmap:

        ```pycon
        >>> NSEC.decode_type_bitmap(bytes.fromhex('0006400080080003'))
        ['A', 'TXT', 'AAAA', 'RRSIG', 'NSEC']
        >>> NSEC.decode_type_bitmap(bytes.fromhex('000762008008000380'))
        ['A', 'NS', 'SOA', 'TXT', 'AAAA', 'RRSIG', 'NSEC', 'DNSKEY']

        ```

        Changed in 1.0: moved to static method on `NSEC`
        """
        rrlist = []
        buf = DNSBuffer(type_bitmap)
        while buf.remaining:
            winnum, winlen = buf.unpack("BB")
            bitmap = bytearray(buf.get(winlen))
            for pos, value in enumerate(bitmap):
                for i in range(8):
                    if (value << i) & 0x80:
                        bitpos = (256 * winnum) + (8 * pos) + i
                        rrlist.append(QTYPE[bitpos])
        return rrlist

    @staticmethod
    def encode_type_bitmap(rrlist: List[str]) -> bytes:
        """Encode RR type bitmap in NSEC record

        Args:
            rrlist:

        ```pycon
        >>> p = lambda x: print(x.hex())
        >>> p(NSEC.encode_type_bitmap(['A','TXT','AAAA','RRSIG','NSEC']))
        0006400080080003
        >>> p(NSEC.encode_type_bitmap(['A','NS','SOA','TXT','AAAA','RRSIG','NSEC','DNSKEY']))
        000762008008000380
        >>> p(NSEC.encode_type_bitmap(['A','ANY','URI','CAA','TA','DLV']))
        002040000000000000000000000000000000000000000000000000000000000000010101c08001c0

        ```

        Changed in 1.0: moved to static method on `NSEC`
        """
        rrlist_ints = sorted([getattr(QTYPE, rr) for rr in rrlist])
        buf = DNSBuffer()
        curWindow = rrlist_ints[0] // 256
        bitmap = bytearray(32)
        n = len(rrlist) - 1
        for i, rr in enumerate(rrlist_ints):
            v = rr - curWindow * 256
            bitmap[v // 8] |= 1 << (7 - v % 8)

            if i == n or rrlist_ints[i + 1] >= (curWindow + 1) * 256:
                while bitmap[-1] == 0:
                    bitmap = bitmap[:-1]
                buf.pack("BB", curWindow, len(bitmap))
                buf.append(bitmap)

                if i != n:
                    curWindow = rrlist_ints[i + 1] // 256
                    bitmap = bytearray(32)

        return buf.data


class CAA(RD):
    """Certification Authority Authorization record

    Attributes:
        flags:
        tag:
        value:

    References:

    - https://datatracker.ietf.org/doc/html/rfc6844

    ```pycon
    >>> CAA(0, 'issue', 'letsencrypt.org')
    0 issue \"letsencrypt.org\"
    >>> a = DNSRecord()
    >>> a.add_answer(*RR.fromZone('example.com 60 IN CAA 0 issue "letsencrypt.org"'))
    >>> print(a)
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
    ;; flags: rd; QUERY: 0, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
    ;; ANSWER SECTION:
    example.com.            60      IN      CAA     0 issue "letsencrypt.org"

    ```
    """

    attrs = ("flags", "tag", "value")

    @classmethod
    def parse(cls, buffer: DNSBuffer, length: int) -> Self:
        """Parse from buffer

        Args:
            buffer:
            length:
        """
        try:
            flags = buffer.unpack_one("!B")
            tag = buffer.get_with_length("!B").decode()
            value = buffer.get(length - len(tag) - 2).decode()
            return cls(flags, tag, value)
        except (BufferError, BimapError) as e:
            raise make_parse_error(cls, buffer, e)

    @classmethod
    def fromZone(cls, rd: List[str], origin: DNSLabelCreateTypes = None) -> Self:
        """Parse from Zone

        Args:
            rd:
            origin:
        """
        if len(rd) == 1:
            hex_parsed = bytes.fromhex(rd[0])
            flags = hex_parsed[0]
            tag_length = hex_parsed[1]
            tag = hex_parsed[2 : 2 + tag_length].decode()
            value = hex_parsed[tag_length + 2 :].decode()
        else:
            flags = int(rd[0])
            tag = rd[1]
            value = rd[2]
        return cls(flags, tag, value.replace('"', ""))

    def __init__(self, flags: int, tag: str, value: str) -> None:
        self.flags = flags
        self.tag = tag
        self.value = value
        return

    def pack(self, buffer: DNSBuffer) -> None:
        """Pack into buffer

        Args:
            buffer:
        """
        buffer.pack("!B", self.flags)
        buffer.append_with_length("!B", self.tag.encode())
        buffer.append(self.value.encode())
        return

    def toZone(self) -> str:
        """Encode as Zone"""
        return repr(self)

    def __repr__(self) -> str:
        return f'{self.flags} {self.tag} "{self.value}"'


class HTTPS(RD):
    """HTTPS record

    This is a type of `SVCB` record.

    Attributes:
        priority:
        target:
        params:

    References:

    - https://datatracker.ietf.org/doc/html/rfc9460

    ```pycon
    >>> HTTPS.fromZone(["1", "cloudflare.com."])
    1 cloudflare.com.
    >>> HTTPS.fromZone(["1", ".", "mandatory=key65444,echconfig"])
    1 . mandatory=key65444,echconfig
    >>> HTTPS.fromZone(["1", ".", "alpn=h3,h3-29,h2"])
    1 . alpn=h3,h3-29,h2
    >>> HTTPS.fromZone(["1", ".", "no-default-alpn"])
    1 . no-default-alpn
    >>> HTTPS.fromZone(["1", ".", "port=443"])
    1 . port=443
    >>> HTTPS.fromZone(["1", ".", "ipv4hint=104.16.132.229,104.16.133.229"])
    1 . ipv4hint=104.16.132.229,104.16.133.229
    >>> HTTPS.fromZone(["1", ".", "echconfig=Z2FyYmFnZQ=="])
    1 . echconfig=Z2FyYmFnZQ==
    >>> HTTPS.fromZone(["1", ".", "ipv6hint=2606:4700::6810:84e5,2606:4700::6810:85e5"])
    1 . ipv6hint=2606:4700::6810:84e5,2606:4700::6810:85e5
    >>> HTTPS.fromZone(["1", ".", "key9999=X"])
    1 . key9999=X
    >>> pcap = bytes.fromhex("0001000001000c0268330568332d323902683200040008681084e5681085e500060020260647000000000000000000681084e5260647000000000000000000681085e5")
    >>> obj = HTTPS.parse(DNSBuffer(pcap), len(pcap))
    >>> obj
    1 . alpn=h3,h3-29,h2 ipv4hint=104.16.132.229,104.16.133.229 ipv6hint=2606:4700::6810:84e5,2606:4700::6810:85e5
    >>> b = DNSBuffer()
    >>> obj.pack(b)
    >>> b.data == pcap
    True
    >>> pcap = bytes.fromhex("00010000040004c0a80126")
    >>> obj = HTTPS.parse(DNSBuffer(pcap), len(pcap))
    >>> obj
    1 . ipv4hint=192.168.1.38
    >>> b = DNSBuffer()
    >>> obj.pack(b)
    >>> b.data == pcap
    True

    # Issue 43: HTTPS reads after RD end
    >>> msg = bytes.fromhex("93088410000100020000000107646973636f726403636f6d0000410001c00c004100010000012c002b0001000001000c0268330568332d323902683200040014a29f80e9a29f87e8a29f88e8a29f89e8a29f8ae8c00c002e00010000012c005f00410d020000012c632834e5632575c586c907646973636f726403636f6d0044d488ce4a5b9085289c671f0296b2b06cffaca28880c57643befd43d6de433d84ae078b282fc2cdd744f3bea2f201042a7a0d6f3e17ebd887b082bbe30dfda100002904d0000080000000")
    >>> print(DNSRecord.parse(msg))
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 37640
    ;; flags: qr aa cd; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1
    ;; QUESTION SECTION:
    ;discord.com.                   IN      HTTPS
    ;; ANSWER SECTION:
    discord.com.            300     IN      HTTPS   1 . alpn=h3,h3-29,h2 ipv4hint=162.159.128.233,162.159.135.232,162.159.136.232,162.159.137.232,162.159.138.232
    discord.com.            300     IN      RRSIG   HTTPS 13 2 300 20220919092245 20220917072245 34505 discord.com. RNSIzkpbkIUonGcfApaysGz/rKKIgMV2Q779Q9beQz2ErgeLKC/CzddE876i8gEEKnoNbz4X69iHsIK74w39oQ==
    ;; ADDITIONAL SECTION:
    ;; OPT PSEUDOSECTION
    ; EDNS: version: 0, flags: do; udp: 1232

    ```

    Changed in 1.0: `target` is now a `DNSLabel` property.
    """

    attrs = ("priority", "target", "params")
    paramkeys: Dict[int, bytes] = {
        0: b"mandatory",
        1: b"alpn",
        2: b"no-default-alpn",
        3: b"port",
        4: b"ipv4hint",
        5: b"echconfig",
        6: b"ipv6hint",
    }
    paramkeys_reversed: Dict[bytes, int] = {v: k for k, v in paramkeys.items()}

    target = create_label_property("target")

    @classmethod
    def parse(cls, buffer: DNSBuffer, length: int) -> Self:
        """Parse from buffer

        Args:
            buffer:
            length:
        """
        try:
            end = buffer.offset + length
            priority = buffer.unpack_one("!H")
            target = buffer.decode_name()
            params: List[Tuple[int, bytearray]] = []
            while buffer.offset < end:
                k = buffer.unpack_one("!H")
                v = bytearray(buffer.get_with_length("!H"))
                params.append((k, v))
            return cls(priority, target, params)
        except (BufferError, BimapError) as e:
            raise make_parse_error(cls, buffer, e)

    @classmethod
    def fromZone(cls, rd: List[str], origin: DNSLabelCreateTypes = None) -> Self:
        """Parse from Zone

        Args:
            rd:
            origin:
        """
        priority = int(rd[0])
        target = rd[1]
        # targ = [] if rd[1] == "." else cls.zf_tobytes(rd[1]).split(b".")[:-1]
        params = []
        for kv in [cls.zf_tobytes(v) for v in rd[2:]]:
            k, v = kv.split(b"=", 1) if b"=" in kv else (kv, bytearray())
            params.append(cls.zf_parse_param(k, v))
        return cls(priority, target, params)

    def __init__(
        self, priority: int, target: DNSLabelCreateTypes, params: List[Tuple[int, bytearray]]
    ) -> None:
        """
        Args:
            priority:
            target:
            params:
        """
        self.priority = priority
        self.target = DNSLabel(target)
        self.params = params
        return

    def pack(self, buffer: DNSBuffer) -> None:
        """Pack into buffer

        Args:
            buffer:
        """
        buffer.pack("!H", self.priority)
        buffer.encode_name_nocompress(self.target)
        for k, v in self.params:
            buffer.pack("!H", k)
            buffer.append_with_length("!H", v)
        return

    def __repr__(self) -> str:
        return " ".join(
            [str(self.priority), str(self.target)]
            + [self.zf_format_param(k, v) for k, v in self.params]
        )

    ## Zone File related
    ## -------------------------------------------------------------------------
    @staticmethod
    def zf_parse_valuelist(s: bytearray) -> List[bytearray]:
        """Parse value list from zone file

        Args:
            s:

        ```pycon
        >>> HTTPS.zf_parse_valuelist(bytearray(b'"part1,part2\\\\,part3"'))
        [bytearray(b'part1'), bytearray(b'part2,part3')]
        >>> HTTPS.zf_parse_valuelist(bytearray(b'part1,part2\\\\044part3'))
        [bytearray(b'part1'), bytearray(b'part2,part3')]

        ```
        """
        quot = 0x22
        slash = 0x5C
        comma = 0x2C
        if len(s) == 0:
            return []
        if s[0] == quot:
            if len(s) < 2 or s[-1] != quot:
                raise DNSError('Error decoding HTTPS SvcParamKey value list: unmatched "')
            s = s[1:-1]
        if len(s) == 0:
            return []
        esc = False
        i = 0
        ret = [bytearray()]
        while i < len(s):
            c = s[i]
            if esc:
                esc = False
                if c >= 0x30 and c <= 0x32:  # 0 1 2
                    ret[-1].append(int(s[i : i + 3]))
                    i += 3
                else:
                    ret[-1].append(c)
                    i += 1
            else:
                if c == slash:
                    esc = True
                    i += 1
                elif c == comma:
                    ret.append(bytearray())
                    i += 1
                else:
                    ret[-1].append(c)
                    i += 1
        if esc:
            raise DNSError("Error decoding HTTPS SvcParamKey value list: hanging slash")
        return ret

    @staticmethod
    def zf_parse_charstr(s: bytearray) -> bytearray:
        """Parse character string

        Args:
            s:

        ```pycon
        >>> HTTPS.zf_parse_charstr(bytearray(b'"part1,part2\\\\,part3"'))
        bytearray(b'part1,part2,part3')
        >>> HTTPS.zf_parse_charstr(bytearray(b'part1,part2\\\\044part3'))
        bytearray(b'part1,part2,part3')

        ```
        """
        quot = 0x22
        slash = 0x5C
        if len(s) == 0:
            return bytearray()
        if s[0] == quot:
            if len(s) < 2 or s[-1] != quot:
                raise DNSError('Error decoding HTTPS SvcParamKey charstring: unmatched "')
            s = s[1:-1]
        esc = False
        i = 0
        ret = bytearray()
        while i < len(s):
            c = s[i]
            if esc:
                esc = False
                if c >= 0x30 and c <= 0x32:  # 0 1 2
                    ret.append(int(s[i : i + 3]))
                    i += 3
                else:
                    ret.append(c)
                    i += 1
            else:
                if c == slash:
                    esc = True
                    i += 1
                else:
                    ret.append(c)
                    i += 1
        if esc:
            raise DNSError("Error decoding HTTPS SvcParamKey charstring: hanging slash")
        return ret

    @staticmethod
    def zf_tobytes(s: str) -> bytearray:
        """Convert string to bytes

        for py2-3 compatibility

        Args:
            s:
        """
        return bytearray(s.encode("ASCII"))

    @staticmethod
    def zf_tostr(b: bytes) -> str:
        """bytes to string

        Args:
            b:
        """
        return b.decode("ASCII")

    @classmethod
    def zf_parse_key(cls, k: bytearray) -> int:
        if k.startswith(b"key"):
            return int(k.removeprefix(b"key"))
        if bytes(k) in cls.paramkeys_reversed:
            return cls.paramkeys_reversed[bytes(k)]
        raise DNSError(f"Error reading HTTPS from zone: unrecognized SvcParamKey [{k}]")

    @classmethod
    def zf_parse_param(cls, k, v) -> Tuple[int, bytearray]:
        b = Buffer()
        i = cls.zf_parse_key(k)
        if i == 0:  # mandatory
            for s in cls.zf_parse_valuelist(v):
                si = cls.zf_parse_key(s)
                b.pack("!H", si)
        elif i == 1:  # alpn
            for s in cls.zf_parse_valuelist(v):
                b.pack("B", len(s))
                b.append(s)
        elif i == 2:  # no alpn
            if v:
                raise DNSError(
                    "Error encoding HTTPS SvcParamKey: no-default-alpn should not have a value"
                )
        elif i == 3:  # port
            b.pack("!H", int(v))
        elif i == 4:  # ipv4
            for ip in cls.zf_parse_valuelist(v):
                b.pack("!4B", *[int(x) for x in ip.split(b".")])
        elif i == 5:  # ech
            s = cls.zf_parse_charstr(v)
            b.data = bytearray(binascii.a2b_base64(s))
        elif i == 6:  # ipv6
            for ip in cls.zf_parse_valuelist(v):
                oc = tuple(map(int, IPv6Address(cls.zf_tostr(ip)).packed))
                b.pack("!16B", *oc)
        else:
            b.data = v
        return (i, bytearray(b.data))

    @staticmethod
    def zf_is_special(c: int) -> bool:
        return not (
            c == 0x21
            or c >= 0x23
            and c <= 0x27
            or c >= 0x2A
            and c <= 0x3A
            or c >= 0x3C
            and c <= 0x5B
            or c >= 0x5D
            and c <= 0x7E
        )

    @classmethod
    def zf_escape_charstr(cls, s, escape_commas=False) -> str:
        ret = bytearray()
        for c in s:
            if cls.zf_is_special(c) or escape_commas and c == 0x2C:
                ret.extend(b"\\")
                ret.extend(b"%.3d" % c)
            else:
                ret.append(c)
        return cls.zf_tostr(ret)

    @classmethod
    def zf_format_valuelist(cls, lst):
        return ",".join(cls.zf_escape_charstr(s, True) for s in lst)

    @classmethod
    def zf_format_key(cls, k: int) -> str:
        if k in cls.paramkeys:
            return cls.zf_tostr(cls.paramkeys[k])
        return "key" + str(k)

    @classmethod
    def zf_format_param(cls, i, v):
        b = Buffer(v)
        k = cls.zf_format_key(i)
        if i == 0:  # mandatory
            ret = []
            while b.remaining:
                (ki,) = b.unpack("!H")
                ret.append(cls.zf_format_key(ki))
            ret = ",".join(ret)
        elif i == 1:  # alpn
            ret = []
            while b.remaining:
                (n,) = b.unpack("B")
                ret.append(bytearray(b.get(n)))
            ret = cls.zf_format_valuelist(ret)
        elif i == 2:  # no-alpn
            if b.remaining:
                raise DNSError(
                    "Error decoding HTTPS SvcParamKey: no-default-alpn should not have a value"
                )
            ret = ""
        elif i == 3:  # port
            ret = str(b.unpack("!H")[0])
        elif i == 4:  # ipv4
            ret = []
            while b.remaining:
                ret.append(str(IPv4Address(bytes(b.unpack("!4B")))))
            ret = ",".join(ret)
        elif i == 5:  # ech
            ret = cls.zf_tostr(binascii.b2a_base64(v).rstrip())
        elif i == 6:  # ipv6
            ret = []
            while b.remaining:
                ret.append(str(IPv6Address(bytes(b.unpack("!16B")))))
            ret = ",".join(ret)
        else:
            ret = cls.zf_tostr(v)
        return k + ("=" + ret if ret else "")


class SSHFP(RD):
    """
    SSHFP record as specified in RFC 4255
    https://www.rfc-editor.org/rfc/rfc4255.html
    """

    algorithm = B("algorithm")
    fp_type = B("fp_type")

    @classmethod
    def parse(cls, buffer: DNSBuffer, length: int) -> Self:
        """Parse from buffer

        Args:
            buffer:
            length:
        """
        try:
            algorithm, fp_type = buffer.unpack("!BB")
            fingerprint = buffer.get(length - 2)
            return cls(algorithm, fp_type, fingerprint)
        except (BufferError, BimapError) as e:
            raise make_parse_error(cls, buffer, e)

    @classmethod
    def fromZone(cls, rd: List[str], origin: DNSLabelCreateTypes = None) -> Self:
        """Parse from Zone

        Args:
            rd:
            origin:
        """
        return cls(int(rd[0]), int(rd[1]), bytes.fromhex("".join(rd[2:])))

    def __init__(self, algorithm: int, fp_type: int, fingerprint: bytes):
        self.algorithm = algorithm
        self.fp_type = fp_type
        self.fingerprint = fingerprint
        return

    def pack(self, buffer: DNSBuffer) -> None:
        """Pack into buffer

        Args:
            buffer:
        """
        buffer.pack("!BB", self.algorithm, self.fp_type)
        buffer.append(self.fingerprint)
        return

    def __repr__(self) -> str:
        return f"{self.algorithm} {self.fp_type} {self.fingerprint.hex().upper()}"

    attrs = ("algorithm", "fp_type", "fingerprint")


class TLSA(RD):
    """TLSA record

    This is part of The DNS-Based Authentication of Named Entities (DANE) Transport
    Layer Security (TLS) Protocol

    Attributes:
        cert_usage:
        selector:
        matching_type:
        cert_data:

    References:

    - https://datatracker.ietf.org/doc/html/rfc6698
    """

    attrs = ("cert_usage", "selector", "matching_type", "cert_data")

    cert_usage = B("cert_usage")
    selector = B("selector")
    matching_type = B("matching_type")

    @classmethod
    def parse(cls, buffer: DNSBuffer, length: int) -> Self:
        """Parse from buffer

        Args:
            buffer:
            length:
        """
        try:
            cert_usage, selector, matching_type = buffer.unpack("!BBB")
            cert_data = buffer.get(length - 3)
            return cls(cert_usage, selector, matching_type, cert_data)
        except (BufferError, BimapError) as e:
            raise make_parse_error(cls, buffer, e)

    @classmethod
    def fromZone(cls, rd: List[str], origin: DNSLabelCreateTypes = None) -> Self:
        """Parse from Zone

        Args:
            rd:
            origin:
        """
        return cls(int(rd[0]), int(rd[1]), int(rd[2]), bytes.fromhex("".join(rd[3:])))

    def __init__(
        self, cert_usage: int, selector: int, matching_type: int, cert_data: bytes
    ) -> None:
        self.cert_usage = cert_usage
        self.selector = selector
        self.matching_type = matching_type
        self.cert_data = cert_data

    def pack(self, buffer: DNSBuffer) -> None:
        """Pack into buffer

        Args:
            buffer:
        """
        buffer.pack("!BBB", self.cert_usage, self.selector, self.matching_type)
        buffer.append(self.cert_data)
        return

    def __repr__(self) -> str:
        return (
            f"{self.cert_usage} {self.selector} {self.matching_type} {self.cert_data.hex().upper()}"
        )


class LOC(RD):
    """Location record

    Attributes:
        lat: lattitude
        lon: longitude
        alt: altitude
        siz: the diameter of a sphere enclosing the described entity
        hp: horizontal precision - This is the diameter of the horizontal
            "circle of error", rather than a "plus or minus" value

        vp: verticial precision - This is the total potential vertical error,
            rather than a "plus or minus" value.

    References:

    - https://datatracker.ietf.org/doc/html/rfc1876

    ```pycon
    >>> LOC(37.236693, -115.804069, 1381.0)
    37 14 12.094 N 115 48 14.649 W 1381.00m
    >>> LOC(37.236693, -115.804069, 1381.0, 3000.0, 1.0, 1.0)
    37 14 12.094 N 115 48 14.649 W 1381.00m 3000.00m 1.00m 1.00m
    >>> a = DNSRecord(DNSHeader(id=1456))
    >>> a.add_answer(*RR.fromZone('area51.local. 60 IN LOC 37 14 12.094 N 115 48 14.649 W 1381.00m'))
    >>> a.add_answer(*RR.fromZone('area51.local. 60 IN LOC 37 N 115 48 W 1381.00m'))
    >>> a.add_answer(*RR.fromZone('area51.local. 60 IN LOC 37 14 12.094 N 115 48 14.649 W 1381.00m 1m 10000m 10m'))
    >>> print(a)
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1456
    ;; flags: rd; QUERY: 0, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 0
    ;; ANSWER SECTION:
    area51.local.           60      IN      LOC     37 14 12.094 N 115 48 14.649 W 1381.00m
    area51.local.           60      IN      LOC     37 N 115 48 W 1381.00m
    area51.local.           60      IN      LOC     37 14 12.094 N 115 48 14.649 W 1381.00m

    ```
    """

    attrs = ("_lat", "_lon", "_alt", "_siz", "_hp", "_vp")

    @classmethod
    def parse(cls, buffer: DNSBuffer, length: int) -> Self:
        """Parse from buffer

        Args:
            buffer:
            length:
        """
        try:
            version, siz, hp, vp, lat, lon, alt = buffer.unpack("!BBBBIII")

            if version != 0:
                # Per RFC 1876 we must check this field and ensure it is zero
                raise DNSError(f"LOC version is not 0")

            self = cls.__new__(cls)
            self._lat = lat
            self._lon = lon
            self._alt = alt
            self._siz = siz
            self._hp = hp
            self._vp = vp
            return self

        except (BufferError, BimapError) as e:
            raise make_parse_error(cls, buffer, e)

    @classmethod
    def fromZone(cls, rd: List[str], origin: DNSLabelCreateTypes = None) -> Self:
        """Parse from Zone

        Args:
            rd:
            origin:
        """
        args = []
        idx = 0

        tofloat = lambda x: float(x[:-1])  # get float from "100.0m"

        def todecimal(chars):
            nonlocal idx
            decimal = 0.0
            multiplier = 1
            for c in chars:
                if c in rd:
                    nxt = rd.index(c)
                    if c in ("S", "W"):
                        multiplier = -1
                    break
            else:
                raise DNSError(f"Missing cardinality [{chars}]")
            for n, d in zip(rd[idx:nxt], (1, 60, 3600)):
                decimal += float(n) / d
            idx = nxt + 1
            return decimal * multiplier

        args.append(todecimal("NS"))
        args.append(todecimal("EW"))

        try:
            while True:
                args.append(tofloat(rd[idx]))
                idx += 1
        except IndexError:
            return cls(*args)

    def __init__(
        self, lat: int, lon: int, alt: int, siz: float = 1.0, hp: float = 10000.0, vp: float = 10.0
    ) -> None:
        """
        Args:
            lat:
            lon:
            int:
            alt:
            siz:
            hp:
            vp:
        """
        self._lat = int(lat * 3600000 + pow(2, 31))
        self._lon = int(lon * 3600000 + pow(2, 31))
        self._alt = int((alt + 100000) * 100)
        self._siz = LOC.__tosiz(siz)
        self._hp = LOC.__tosiz(hp)
        self._vp = LOC.__tosiz(vp)
        return

    def pack(self, buffer: DNSBuffer) -> None:
        """Pack into buffer

        Args:
            buffer:
        """
        buffer.pack("!BBBBIII", 0, self._siz, self._hp, self._vp, self._lat, self._lon, self._alt)
        return

    @property
    def siz(self):
        return self.__reprsiz(self._siz)

    @property
    def hp(self):
        return self.__reprsiz(self._hp)

    @property
    def vp(self):
        return self.__reprsiz(self._vp)

    @property
    def lat(self):
        c = "N" if self._lat > pow(2, 31) else "S"
        return self._reprcoord(self._lat, c)

    @property
    def lon(self):
        c = "E" if self._lon > pow(2, 31) else "W"
        return self._reprcoord(self._lon, c)

    @property
    def alt(self):
        return self._alt / 100 - 100000

    @staticmethod
    def _reprcoord(value, c):
        base = abs(pow(2, 31) - value)
        d = base // 3600000
        m = base % 3600000 // 60000
        s = base % 3600000 % 60000 / 1000.0

        if int(s) == 0:
            if m == 0:
                return f"{d} {c}"
            else:
                return f"{d} {m} {c}"
        return f"{d} {m} {s:.3f} {c}"

    def __repr__(self):
        DEFAULT_SIZ = 0x12  # 1m
        DEFAULT_HP = 0x16  # 10,000m
        DEFAULT_VP = 0x13  # 10m

        result = "{self.lat} {self.lon} {self.alt:.2f}m".format(self=self)

        if self._vp != DEFAULT_VP:
            result += " {self.siz:.2f}m {self.hp:.2f}m {self.vp:.2f}m".format(self=self)
        elif self._hp != DEFAULT_HP:
            result += " {self.siz:.2f}m {self.hp:.2f}m".format(self=self)
        elif self._siz != DEFAULT_SIZ:
            result += f" {self.siz:.2f}m"

        return result

    @staticmethod
    def __tosiz(v):
        if int(v) == 0:
            return 0
        e = 0
        v *= 100
        while v >= 10 and e < 9:
            v /= 10
            e += 1
        v = int(round(v))
        if v >= 10:
            raise DNSError("Value out of range")
        return v << 4 | e

    @staticmethod
    def __reprsiz(v):
        b = v >> 4
        e = v & 0x0F
        if b > 9 or e > 9 or (b == 0 and e > 0):
            raise DNSError("Value out of range")
        return b * pow(10, e) / 100


class RP(RD):
    """Responsible Person record

    Note:
        This record is classified as experimental

    Attributes:
        mbox: a domain name that specifies the mailbox for the responsible person.
            This is in the same format as the `RNAME` field in a `SOA` record.
        txt: domain name which can be queried for `TXT` records for additional information.

    References:

    - https://datatracker.ietf.org/doc/html/rfc1183

    Changed in 1.0: Removed `[get,set]_[mbox,txt]`
    """

    attrs = ("mbox", "txt")

    mbox = create_label_property("mbox")
    txt = create_label_property("txt")

    @classmethod
    def parse(cls, buffer: DNSBuffer, length: int) -> Self:
        """Parse from buffer

        Args:
            buffer:
            length:
        """
        try:
            mbox = buffer.decode_name()
            txt = buffer.decode_name()
            return cls(mbox, txt)
        except (BufferError, BimapError) as e:
            raise make_parse_error(cls, buffer, e)

    @classmethod
    def fromZone(cls, rd: List[str], origin: DNSLabelCreateTypes = None) -> Self:
        """Parse from Zone

        Args:
            rd:
            origin:
        """
        return cls(create_label(rd[0], origin), create_label(rd[1], origin))

    def __init__(self, mbox: DNSLabelCreateTypes = None, txt: DNSLabelCreateTypes = None) -> None:
        """
        Args:
            mbox:
            txt:
        """
        self.mbox = mbox
        self.txt = txt
        return

    def pack(self, buffer: DNSBuffer) -> None:
        """Pack into buffer

        Args:
            buffer:
        """
        buffer.encode_name(self.mbox)
        buffer.encode_name(self.txt)
        return

    def __repr__(self):
        return f"{self.mbox} {self.txt}"


# Map from RD type to class (used to pack/unpack records)
# If you add a new RD class you must add to RDMAP

RDMAP: Dict[str, Type[RD]] = {
    "A": A,
    "AAAA": AAAA,
    "CAA": CAA,
    "CNAME": CNAME,
    "DNSKEY": DNSKEY,
    "DS": DS,
    "HTTPS": HTTPS,
    "LOC": LOC,
    "MX": MX,
    "NAPTR": NAPTR,
    "NSEC": NSEC,
    "NS": NS,
    "OPT": EDNSRD,
    "PTR": PTR,
    "RP": RP,
    "RRSIG": RRSIG,
    "SOA": SOA,
    "SRV": SRV,
    "SSHFP": SSHFP,
    "TLSA": TLSA,
    "TXT": TXT,
}


##
## Zone parser
## TODO  - ideally this would be in a separate file but have to deal
##         with circular dependencies
##
def parse_time(s) -> int:
    """Parse time spec with optional s/m/h/d/w suffix

    Args:
        s:

    Returns:
        number of seconds
    """
    secs = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
    multiplier = secs.get(s[-1].lower())
    if multiplier is not None:
        return int(s[:-1]) * multiplier
    return int(s)


class ZoneParser:
    """Zone file parser

    ```pycon
    >>> z = ZoneParser("www.example.com. 60 IN A 1.2.3.4")
    >>> list(z.parse())
    [<DNS RR: 'www.example.com.' rtype=A rclass=IN ttl=60 rdata='1.2.3.4'>]

    ```
    """

    def __init__(self, zone: str, origin: DNSLabelCreateTypes = None, ttl: int = 0) -> None:
        """
        Args:
            zone: Zone file to parse
            origin: origin of zone file
            ttl: default ttl
        """
        self.l = WordLexer(zone)
        self.l.commentchars = {";"}
        self.l.nltok = ("NL", None)
        self.l.spacetok = ("SPACE", None)
        self.i = iter(self.l)
        self.origin = DNSLabel(origin)
        self.ttl = ttl
        self.label = DNSLabel("")
        self.prev = None
        return

    def expect(self, expect):
        t, val = next(self.i)
        if t != expect:
            raise ValueError(f"Invalid Token: {t} (expecting: {expect})")
        return val

    def parse_label(self, label: str) -> DNSLabel:
        if label.endswith("."):
            self.label = DNSLabel(label)
        elif label == "@":
            self.label = self.origin
        elif label == "":
            pass
        else:
            self.label = self.origin.add(label)
        return self.label

    def parse_rr(self, rr: List[str]) -> RR:
        label = self.parse_label(rr.pop(0))
        ttl = int(rr.pop(0)) if rr[0].isdigit() else self.ttl
        rclass = rr.pop(0) if rr[0] in ("IN", "CH", "HS") else "IN"
        rtype = rr.pop(0)
        rdata = rr
        rd = RDMAP.get(rtype, RD)
        return RR(
            rname=label,
            ttl=ttl,
            rclass=getattr(CLASS, rclass),
            rtype=getattr(QTYPE, rtype),
            rdata=rd.fromZone(rdata, self.origin),
        )

    def __iter__(self):
        return self.parse()

    def parse(self):
        rr = []
        paren = False
        try:
            while True:
                tok, val = next(self.i)
                if tok == "NL":
                    if not paren and rr:
                        self.prev = tok
                        yield self.parse_rr(rr)
                        rr = []
                elif tok == "SPACE" and self.prev == "NL" and not paren:
                    rr.append("")
                elif tok == "ATOM":
                    if val == "(":
                        paren = True
                    elif val == ")":
                        paren = False
                    elif val == "$ORIGIN":
                        self.expect("SPACE")
                        origin = self.expect("ATOM")
                        self.origin = self.label = DNSLabel(origin)
                    elif val == "$TTL":
                        self.expect("SPACE")
                        ttl = self.expect("ATOM")
                        self.ttl = parse_time(ttl)
                    else:
                        rr.append(val)
                self.prev = tok
        except StopIteration:
            if rr:
                yield self.parse_rr(rr)


if __name__ == "__main__":
    import doctest, sys

    sys.exit(0 if doctest.testmod(optionflags=doctest.ELLIPSIS).failed == 0 else 1)
