
from dnslib import *

zone = """
$ORIGIN example.com.
$TTL 60
@   IN  SOA ns1.example.com. admin.example.com. ( 2014011500 12h 15m 3w 3h )
@   IN  NS  ns1.example.com.
@   IN  MX  10  mail.example.com.
@   IN  A   1.2.3.4
abc IN  A   6.7.8.9
www IN  CNAME abc
"""

origin = []
ttl = 0

for l in zone.split("\n"):
    f = l.split()
    if f[0] == "$TTL":
        ttl = int(f[2])
    elif f[0] == "$ORIGIN":
        origin = 

