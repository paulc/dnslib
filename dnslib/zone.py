
from __future__ import print_function

from dnslib.lex import WordLexer

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

def parse_zone(zone):

    l = WordLexer(zone)
    l.commentchars = ';'
    l.nltok = ('NL',)
    l.spacetok = ('SPACE',)
    rr = []
    paren = False

    i = iter(l)
    prev = None

    for tok in i:
        if tok[0] == 'NL':
            if not paren and rr:
                print("RR:",rr)
                rr = []
        elif tok[0] == 'SPACE' and prev[0] == 'NL':
            rr.append('<prev>')
        elif tok[0] == 'ATOM':
            if tok[1] == '(':
                paren = True
            elif tok[1] == ')':
                paren = False
            elif tok[1] == '$ORIGIN':
                next(i)
                print("ORIGIN:",next(i)[1])
            elif tok[1] == '$TTL':
                next(i)
                print("TTL:",next(i)[1])
            else:
                rr.append(tok[1])
        prev = tok

zone1 = """
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

zone2 = """
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

