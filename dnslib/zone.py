
import collections,string

try:
    from StringIO import StringIO
except ImportError:
    from io import (StringIO,BytesIO)

class Parser(object):

    """

        >>> p = Parser("Hello there.... this is a test")
        >>> p.match("Hello")
        True
        >>> p.pushback("Hello")
        >>> p.read(4)
        'Hell'
        >>> p.peek(10)
        'o there...'
        >>> p.match("there")
        False
        >>> p.read(2)
        'o '
        >>> p.match("there")
        True
        >>> p.readupto("this")
        '.... this'

    """

    def __init__(self,f):
        if hasattr(f,'read'):
            self.f = f
        elif type(f) == str:
            self.f = StringIO(f)
        elif type(f) == bytes:
            self.f = BytesIO(f.decode())
        else:
            raise ValueError("Invalid input")
        self.q = collections.deque()
        self.state = self.lexStart
        self.eof = False
        self.escaped = False

    def parse(self):
        while self.state is not None and not self.eof:
            (tok,self.state) = self.state()
            if tok:
                yield tok 

    def read(self,n=1):
        s = ""
        while self.q and n > 0:
            s += self.q.popleft()
            n -= 1
        s += self.f.read(n)
        if s == '':
            self.eof = True
        return s

    def readupto(self,s):
        c = []
        if type(s) == str:
            s = [s]
        while not self.eof:
            c.append(self.read())
            if "".join(c[-len(s[0]):]) in s:
                break
        return "".join(c)

    def readescaped(self):
        c = self.read(1)
        if c == '\\':
            self.escaped = True
            n = self.peek(3)
            if n.isdigit():
                n = self.read(3)
                return chr(int(n,8))
            else:
                c = self.read(1)
                if c == 'n':
                    return '\n'
                elif c == 't':
                    return '\t'
                else:
                    return c
        else:
            self.escaped = False
            return c

    def readnotmatching(self,l):
        l = list(l)
        s = []
        while not self.eof:
            c = self.read(1)
            if c not in l:
                s.append(c)
            else:
                self.pushback(c)
                break
        return "".join(s)

    def readmatching(self,l):
        l = list(l)
        s = []
        while not self.eof:
            c = self.read(1)
            if c in l:
                s.append(c)
            else:
                self.pushback(c)
                break
        return "".join(s)

    def peek(self,n=1):
        s = ""
        i = 0
        while len(self.q) > i and n > 0:
            s += self.q[i]
            i += 1
            n -= 1
        r = self.f.read(n)
        self.q.extend(r)
        return s + r

    def pushback(self,s):
        p = collections.deque(s)
        p.extend(self.q)
        self.q = p

    def match(self,m):
        s = self.read(len(m))
        if s == m:
            return True
        else:
            self.pushback(s)
            return False

    def lexStart(self):
        return (None,None)

class WordParser(Parser):
    """
        >>> p = WordParser(r'abc "def\100 ghi" jkl')
        >>> list(p.parse())
        ['abc', 'def@ ghi', 'jkl']
    """

    def lexStart(self):
        return (None,self.lexSpace)

    def lexWord(self):
        s = self.readnotmatching([" ","\n"])
        if self.eof:
            return (s,None)
        else:
            return (s,self.lexSpace)

    def lexQuote(self):
        q = self.read(1)
        s = []
        while not self.eof:
            c = self.readescaped()
            if c == q and not self.escaped:
                break
            else:
                s.append(c)
        return ("".join(s),self.lexSpace)

    def lexSpace(self):
        s = self.readmatching([" ","\n"])
        if self.eof:
            return (s,None)
        else:
            n = self.peek()
            if n == '"':
                return (None,self.lexQuote)
            else:
                return (None,self.lexWord)

zone = """
$ORIGIN example.com.        ; Comment
$TTL 90m

@       IN  SOA     ns1.example.com. admin.example.com. (
                        2014011500  ; Serial
                        12h         ; Stuff
                        15m 
                        3w 
                        3h 
                    )
        86400 IN  NS      ns1.example.com.
xxx        IN  NS      ns1.example.com.

        IN  MX      ( 10  mail.example.com. )
        IN  A       1.2.3.4
        IN  TXT     ( "A  B  C" )
abc  60   IN  A       6.7.8.9
        IN  TXT     "Stuff"
ipv6    IN  AAAA    1234:5678::1
www     IN  CNAME   abc
$TTL    5m
xxx.yyy.com.    IN  A   9.9.9.9
                IN  TXT "Some     
                        Text"
last    40  IN  HINFO   "HW Info" "SW"
        IN A 9.9.9.9

$TTL 5s
$ORIGIN 4.3.2.1.5.5.5.0.0.8.1.e164.arpa.
IN NAPTR ( 100 10 "U" "E2U+sip" "!^.*$!sip:customer-service@example.com!" . )
IN NAPTR ( 102 10 "U" "E2U+email" "!^.*$!mailto:information@example.com!" . )

"""


zone = """
ipv6.pchak.net. 86400   IN  SOA ns1.he.net. hostmaster.he.net. (
                    2014020901  ; Serial
                    10800   ; Refresh
                    1800    ; Retry
                    604800  ; Expire
                    86400 ) ; Minimum TTL
ipv6.pchak.net. 3600    IN  NS  ns2.he.net.
ipv6.pchak.net. 3600    IN  NS  ns3.he.net.
ipv6.pchak.net. 3600    IN  NS  ns4.he.net.
ipv6.pchak.net. 3600    IN  NS  ns5.he.net.
home.ipv6.pchak.net.    3600    IN  AAAA    2001:470:6d:33:95c0:2178:58d1:6803
vds6.ipv6.pchak.net.    3600    IN  AAAA    2a01:4f8:150:1102:0:0:0:fa
ipv6.pchak.net. 3600    IN  AAAA    2001:41d0:a:105f:0:0:0:1
"""

secs = {'s':1,'m':60,'h':3600,'d':86400,'w':604800}

def parse_time(s):
    if s[-1].lower() in secs:
        return int(s[:-1]) * secs[s[-1].lower()]
    else:
        return int(s)

def parse_label(label,origin):
    if label.endswith("."):
        return label
    elif label == "@":
        return origin
    else:
        return label + "." + origin

def parse_rr(rr,state):
    print(">>>",rr)
    i = rr.index('IN')
    ttl = lambda : int(rr[i-1])
    kind = lambda : rr[i+1]
    rd = lambda : [ x.strip('"') for x in rr[i+2:]]
    if i == 0:
        return (state['label'],state['ttl'],kind(),rd())
    elif i == 1:
        if rr[0].isdigit():
            return (state['label'],ttl(),kind(),rd())
        else:
            state['label'] = parse_label(rr[0],state['origin'])
            return (state['label'],state['ttl'],kind(),rd())
    elif i == 2:
        state['label'] = parse_label(rr[0],state['origin'])
        return (state['label'],ttl(),kind(),rd())
    else:
        raise ValueError("Invalid RR",rr)


if __name__ == '__main__':
    import doctest
    doctest.testmod()
