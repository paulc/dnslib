

## From Version 0.9.12 the master repository for _dnslib_ has been moved to GitHub (https://github.com/paulc/dnslib). Please update any links to the original BitBucket repository as this will no longer be maintained.


dnslib
------

A library to encode/decode DNS wire-format packets supporting both
Python 2.7 and Python 3.2+.

The library provides:

 * Support for encoding/decoding DNS packets between wire format,
   python objects, and Zone/DiG textual representation (dnslib.dns)

 * A server framework allowing the simple creation of custom DNS
   resolvers (dnslib.server) and a number of example servers
   created using this framework

 * A number of utilities for testing (dnslib.client, dnslib.proxy,
   dnslib.intercept)

Python 3 support was added in Version 0.9.0 which represented a fairly
major update to the library - the key changes include:

 * Python 2.7/3.2+ support (the last version supporting Python 2.6
   or earlier was version 0.8.3)

 * The 'Bimap' interface was changed significantly to explicitly
   split forward (value->text) lookups via __getitem__ and
   reverse (text->value) lookups via __getattr__. Applications
   using the old interface will need to be updated.

 * Hostnames are now returned with a trailing dot by default (in
   line with RFC)

 * Most object attributes are now typed in line with the record
   definitions to make it harder to generate invalid packets

 * Support for encoding/decoding resource records in 'Zone' (BIND)
   file format

 * Support for encoding/decoding packets in 'DiG' format

 * Server framework allowing (in most cases) custom resolvers to
   be created by just subclassing the DNSResolver class and
   overriding the 'resolve' method

 * A lot of fixes to error detection/handling which should make
   the library much more robust to invalid/unsupported data. The
   library should now either return a valid DNSRecord instance
   when parsing a packet or raise DNSError (tested via fuzzing)

 * Improved utilities (dnslib.client, dnslib.proxy, dnslib.intercept)

 * Improvements to encoding/decoding tests including the ability
   to generate test data automatically in test_decode.py (comparing
   outputs against DiG)

 * Ability to compare and diff DNSRecords

Classes
-------

The key DNS packet handling classes are in dnslib.dns and map to the
standard DNS packet sections:

 * DNSRecord - container for DNS packet. Contains:
    - DNSHeader
    - Question section containing zero or more DNSQuestion objects
    - Answer section containing zero or more RR objects
    - Authority section containing zero or more RR objects
    - Additional section containing zero or more RR objects
 * DNS RRs (resource records) contain an RR header and an RD object)
 * Specific RD types are implemented as subclasses of RD
 * DNS labels are represented by a DNSLabel class - in most cases
   this handles conversion to/from textual representation however
   does support arbitatry labels via a tuple of bytes objects

Usage
-----

To decode a DNS packet:

    >>> packet = binascii.unhexlify(b'd5ad818000010005000000000377777706676f6f676c6503636f6d0000010001c00c0005000100000005000803777777016cc010c02c0001000100000005000442f95b68c02c0001000100000005000442f95b63c02c0001000100000005000442f95b67c02c0001000100000005000442f95b93')
    >>> d = DNSRecord.parse(packet)
    >>> d
    <DNS Header: id=0xd5ad type=RESPONSE opcode=QUERY flags=RD,RA rcode='NOERROR' q=1 a=5 ns=0 ar=0>
    <DNS Question: 'www.google.com.' qtype=A qclass=IN>
    <DNS RR: 'www.google.com.' rtype=CNAME rclass=IN ttl=5 rdata='www.l.google.com.'>
    <DNS RR: 'www.l.google.com.' rtype=A rclass=IN ttl=5 rdata='66.249.91.104'>
    <DNS RR: 'www.l.google.com.' rtype=A rclass=IN ttl=5 rdata='66.249.91.99'>
    <DNS RR: 'www.l.google.com.' rtype=A rclass=IN ttl=5 rdata='66.249.91.103'>
    <DNS RR: 'www.l.google.com.' rtype=A rclass=IN ttl=5 rdata='66.249.91.147'>

The default text representation of the DNSRecord is in zone file format:

    >>> print(d)
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 54701
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 5, AUTHORITY: 0, ADDITIONAL: 0
    ;; QUESTION SECTION:
    ;www.google.com.                IN      A
    ;; ANSWER SECTION:
    www.google.com.         5       IN      CNAME   www.l.google.com.
    www.l.google.com.       5       IN      A       66.249.91.104
    www.l.google.com.       5       IN      A       66.249.91.99
    www.l.google.com.       5       IN      A       66.249.91.103
    www.l.google.com.       5       IN      A       66.249.91.147

To create a DNS Request Packet:

    >>> d = DNSRecord.question("google.com")

(This is equivalent to: d = DNSRecord(q=DNSQuestion("google.com") )

    >>> d
    <DNS Header: id=... type=QUERY opcode=QUERY flags=RD rcode='NOERROR' q=1 a=0 ns=0 ar=0>
    <DNS Question: 'google.com.' qtype=A qclass=IN>

    >>> str(DNSRecord.parse(d.pack())) == str(d)
    True

    >>> print(d)
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
    ;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
    ;; QUESTION SECTION:
    ;google.com.                    IN      A

    >>> d = DNSRecord.question("google.com","MX")

(This is equivalent to: d = DNSRecord(q=DNSQuestion("google.com",QTYPE.MX) )

    >>> str(DNSRecord.parse(d.pack())) == str(d)
    True

    >>> print(d)
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
    ;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0
    ;; QUESTION SECTION:
    ;google.com.                    IN      MX

To create a DNS Response Packet:

    >>> d = DNSRecord(DNSHeader(qr=1,aa=1,ra=1),
    ...               q=DNSQuestion("abc.com"),
    ...               a=RR("abc.com",rdata=A("1.2.3.4")))
    >>> d
    <DNS Header: id=... type=RESPONSE opcode=QUERY flags=AA,RD,RA rcode='NOERROR' q=1 a=1 ns=0 ar=0>
    <DNS Question: 'abc.com.' qtype=A qclass=IN>
    <DNS RR: 'abc.com.' rtype=A rclass=IN ttl=0 rdata='1.2.3.4'>
    >>> str(DNSRecord.parse(d.pack())) == str(d)
    True

    >>> print(d)
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
    ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
    ;; QUESTION SECTION:
    ;abc.com.                       IN      A
    ;; ANSWER SECTION:
    abc.com.                0       IN      A       1.2.3.4

It is also possible to create RRs from a string in zone file format

    >>> RR.fromZone("abc.com IN A 1.2.3.4")
    [<DNS RR: 'abc.com.' rtype=A rclass=IN ttl=0 rdata='1.2.3.4'>]

    (Note: this produces a list of RRs which should be unpacked if being
    passed to add_answer/add_auth/add_ar etc)

    >>> q = DNSRecord.question("abc.com")
    >>> a = q.reply()
    >>> a.add_answer(*RR.fromZone("abc.com 60 A 1.2.3.4"))
    >>> print(a)
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
    ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
    ;; QUESTION SECTION:
    ;abc.com.                       IN      A
    ;; ANSWER SECTION:
    abc.com.                60      IN      A       1.2.3.4

The zone file can contain multiple entries and supports most of the normal
format defined in RFC1035 (specifically not $INCLUDE)

    >>> z = '''
    ...         $TTL 300
    ...         $ORIGIN abc.com
    ...
    ...         @       IN      MX      10  mail.abc.com.
    ...         www     IN      A       1.2.3.4
    ...                 IN      TXT     "Some Text"
    ...         mail    IN      CNAME   www.abc.com.
    ... '''
    >>> for rr in RR.fromZone(textwrap.dedent(z)):
    ...     print(rr)
    abc.com.                300     IN      MX      10 mail.abc.com.
    www.abc.com.            300     IN      A       1.2.3.4
    www.abc.com.            300     IN      TXT     "Some Text"
    mail.abc.com.           300     IN      CNAME   www.abc.com.

To create a skeleton reply to a DNS query:

    >>> q = DNSRecord(q=DNSQuestion("abc.com",QTYPE.ANY))
    >>> a = q.reply()
    >>> a.add_answer(RR("abc.com",QTYPE.A,rdata=A("1.2.3.4"),ttl=60))
    >>> str(DNSRecord.parse(a.pack())) == str(a)
    True
    >>> print(a)
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
    ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
    ;; QUESTION SECTION:
    ;abc.com.                       IN      ANY
    ;; ANSWER SECTION:
    abc.com.                60      IN      A       1.2.3.4

Add additional RRs:

    >>> a.add_answer(RR("xxx.abc.com",QTYPE.A,rdata=A("1.2.3.4")))
    >>> a.add_answer(RR("xxx.abc.com",QTYPE.AAAA,rdata=AAAA("1234:5678::1")))
    >>> str(DNSRecord.parse(a.pack())) == str(a)
    True
    >>> print(a)
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
    ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 0
    ;; QUESTION SECTION:
    ;abc.com.                       IN      ANY
    ;; ANSWER SECTION:
    abc.com.                60      IN      A       1.2.3.4
    xxx.abc.com.            0       IN      A       1.2.3.4
    xxx.abc.com.            0       IN      AAAA    1234:5678::1


It is also possible to create a reply from a string in zone file format:

    >>> q = DNSRecord(q=DNSQuestion("abc.com",QTYPE.ANY))
    >>> a = q.replyZone("abc.com 60 IN CNAME xxx.abc.com")
    >>> print(a)
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
    ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0
    ;; QUESTION SECTION:
    ;abc.com.                       IN      ANY
    ;; ANSWER SECTION:
    abc.com.                60      IN      CNAME   xxx.abc.com.

    >>> str(DNSRecord.parse(a.pack())) == str(a)
    True

    >>> q = DNSRecord(q=DNSQuestion("abc.com",QTYPE.ANY))
    >>> a = q.replyZone(textwrap.dedent(z))
    >>> print(a)
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
    ;; flags: qr aa rd ra; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 0
    ;; QUESTION SECTION:
    ;abc.com.                       IN      ANY
    ;; ANSWER SECTION:
    abc.com.                300     IN      MX      10 mail.abc.com.
    www.abc.com.            300     IN      A       1.2.3.4
    www.abc.com.            300     IN      TXT     "Some Text"
    mail.abc.com.           300     IN      CNAME   www.abc.com.

To send a DNSSEC request (EDNS OPT record with DO flag & header AD flag):

    >>> q = DNSRecord(q=DNSQuestion("abc.com",QTYPE.A))
    >>> q.add_ar(EDNS0(flags="do",udp_len=4096))
    >>> q.header.ad = 1
    >>> print(q)
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: ...
    ;; flags: rd ad; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
    ;; QUESTION SECTION:
    ;abc.com.                       IN      A
    ;; ADDITIONAL SECTION:
    ;; OPT PSEUDOSECTION
    ; EDNS: version: 0, flags: do; udp: 4096

Note that when using the library you should always validate the received TXID 

    q = DNSRecord.question("abc.com")
    a_pkt = q.send(address,port,tcp=args.tcp)
    a = DNSRecord.parse(a_pkt)
    if q.header.id != a.header.id:
        raise DNSError('Response transaction id does not match query transaction id')

The library also includes a simple framework for generating custom DNS
resolvers in dnslib.server (see module docs). In most cases this just
requires implementing a custom 'resolve' method which receives a question
object and returns a response.

A number of sample resolvers are provided as examples (see CLI --help):

 * dnslib.fixedresolver    - Respond to all requests with fixed response
 * dnslib.zoneresolver     - Respond from Zone file
 * dnslib.shellresolver    - Call shell script to generate response

The library includes a number of client utilities:

 * DiG like client library

        # python -m dnslib.client --help

 * DNS Proxy Server

        # python -m dnslib.proxy --help

 * Intercepting DNS Proxy Server (replace proxy responses for specified domains)

        # python -m dnslib.intercept --help


Changelog:
----------

 *   0.1     2010-09-19  Initial Release
 *   0.2     2010-09-22  Minor fixes
 *   0.3     2010-10-02  Add DNSLabel class to support arbitrary labels (embedded '.')
 *   0.4     2012-02-26  Merge with dbslib-circuits
 *   0.5     2012-09-13  Add support for RFC2136 DDNS updates
                         Patch provided by Wesley Shields <wxs@FreeBSD.org> - thanks
 *   0.6     2012-10-20  Basic AAAA support
 *   0.7     2012-10-20  Add initial EDNS0 support (untested)
 *   0.8     2012-11-04  Add support for NAPTR, Authority RR and additional RR
                         Patch provided by Stefan Andersson (https://bitbucket.org/norox) - thanks
 *   0.8.1   2012-11-05  Added NAPTR test case and fixed logic error
                         Patch provided by Stefan Andersson (https://bitbucket.org/norox) - thanks
 *   0.8.2   2012-11-11  Patch to fix IPv6 formatting
                         Patch provided by Torbjorn Lonnemark (https://bitbucket.org/tobbezz) - thanks
 *   0.8.3   2013-04-27  Don't parse rdata if rdlength is 0
                         Patch provided by Wesley Shields <wxs@FreeBSD.org> - thanks
 *   0.9.0   2014-05-05  Major update including Py3 support (see docs)
 *   0.9.1   2014-05-05  Minor fixes
 *   0.9.2   2014-08-26  Fix Bimap handling of unknown mappings to avoid exception in printing
                         Add typed attributes to classes
                         Misc fixes from James Mills - thanks
 *   0.9.3   2014-08-26  Workaround for argparse bug which raises AssertionError if [] is
                         present in option text (really?)
 *   0.9.4   2015-04-10  Fix to support multiple strings in TXT record
                         Patch provided by James Cherry (https://bitbucket.org/james_cherry) - thanks
                         NOTE: For consistency this patch changes the 'repr' output for
                               TXT records to always be quoted
 *   0.9.5   2015-10-27  Add threading & timeout handling to DNSServer
 *   0.9.6   2015-10-28  Replace strftime in RRSIG formatting to avoid possible locale issues
                         Identified by Bryan Everly - thanks
 *   0.9.7   2017-01-15  Sort out CAA/TYPE257 DiG parsing mismatch
 *   0.9.8   2019-02-25  Force DNSKEY key to be bytes object
                         Catch Bimap __wrapped__ attr (used by inspect module in 3.7)
 *   0.9.9   2019-03-19  Add support for DNSSEC flag getters/setters (from <raul@dinosec.com> - thanks)
                         Added --dnssec flags to dnslib.client & dnslib.test_decode (sets EDNS0 DO flag)
                         Added EDNS0 support to dnslib.digparser
 *   0.9.10  2019-03-24  Fixes to DNSSEC support
                         Add NSEC RR support
                         Add --dnssec flag to dnslib.client & dnslib.test_decode
                         Quote/unquote non-printable characters in DNS labels
                         Update test data
                         (Thanks to <raul@dinosec.com> for help)
 *   0.9.11  2019-12-17  Encode NOTIFY Opcode (Issue #26)
 *   0.9.12  2019-12-17  Transition master repository to Github (Bitbucket shutting down hg)
 *   0.9.13  2020-06-01  Handle truncated requests in server.py (Issue #9)
                         Replace thred.isAlive with thread.is_alive (Deprecated in Py3.9)
                         Merged Pull Request #4 (Extra options for intercept.py) - thanks to @nolanl
 *   0.9.14  2020-06-09  Merged Pull Request #10 (Return doctest status via exit code)
                         Thanks to @mgorny
 *   0.9.15  2021-05-07  DNSServer fixes - support IPv6 (from Pull Request #21) - thanks to @mikma
                                         - deamon threads (Pull Request #19) - thanks to @wojons
                         Add unsupported RR types (Issue #27)
 *   0.9.16  2021-05-07  Merge pull request #23 from Tugzrida/patch-1
                            Add support for all RR types to NSEC type bitmap
                         Merge pull request #17 from sunds/issue_16
                            Issue 16: uncaught exceptions leak open sockets
 *   0.9.18  2022-01-09  Validate TXID in client.py (Issue #30 - thanks to @daniel4x)
 *   0.9.19  2022-01-09  Allow custom log function (logf) in  DNSLogger
                            (Issue #31 - thanks to @DmitryFrolovTri)
 *   0.9.20  2022-07-17  Fix DeprecationWarnings about invalid escape sequences
                            (Pull-Request #39 - thanks to @brianmaissy)
                         Make DNSLabel matchSuffix and stripSuffix case-insensitive
                            (Pull-Request #37 - thanks to @NiKiZe)
                         Add support for HTTPS RR
                            (Pull-Request #35 - thanks to @jkl-caliber)
                         Fix display of non-printable characters in TXT records
                            (Issue #32 - thanks to @sbv-csis)
                         Add --strip-aaaa option to dnslib.proxy 
 *   0.9.21  2022-09-19  Minor clean-up / add wheels to distro
 *   0.9.22  2022-09027  Issue #43 (0.9.21 Raises TypeError instead of DNSError when failing to parse HTTPS records)
                         Note that we just fix the exception - there still seems to be a problem with parsing HTTPS records
                         (Thanks to @robinlandstrom)
 *   0.9.23  2022-10-28  Issue #43: HTTPS reads after RD end (thanks to @robinlandstrom for pull request)
                         Issue #45: Dnslib fails to handle unknown RR types in NSEC RD type bitmap
                            Bimap now supports a function to map unknown types which we use to
                            dynamically map from rtype <-> TYPExxxx for unknown record types
                            RR zone representation updated to match RFC3597
                         Pull Request #47: Add support for DS, SSHFP, and TLSA records (thanks to @rmbolger)

License:
--------

BSD

Author:
-------

 *   PaulC

Master Repository/Issues:
-------------------------

 *   https://github.com/paulc/dnslib

 (Note: https://bitbucket.org/paulc/dnslib has been deprecated and will not be updated)
