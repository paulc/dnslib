#!/usr/bin/env python

from __future__ import print_function

import binascii,optparse,socket,sys
from dnslib import DNSHeader, DNSRecord, QTYPE

"""
    Simple DNS proxy - listens on proxy port and forwards request/reply to real server
    passing data through dnslib and printing the raw/parsed data

    This is mostly for testing - normal usage would be to use dig to generate request 
    and compare outputs

    Options:

      --port=PORT          Proxy port (default: 8053)
      --bind=BIND          Proxy bind address (default: all)
      --dns=DNS            DNS server (default: 8.8.8.8)
      --dns_port=DNS_PORT  DNS server port (default: 53)

    Usage:

    # python udp_proxy.py

    (from another window)

    # dig @127.0.0.1 www.google.com -p 8053

"""

def udp_listen(host,port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((host,port))
    return s

def udp_recv(s):
    data,client = s.recvfrom(8192)
    return data,client,None

def tcp_listen(host,port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host,port))
    s.listen(0)
    return s

def tcp_recv(s):
    conn,client = proxy.accept()
    data = conn.recv(8192)
    return data,client,conn

def tcp_send(data,host,port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host,port))
    server = s.getpeername()
    s.sendall(data)
    # Wait for reply
    data = s.recv(8192)
    s.close()
    return data,server

def udp_send(data,host,port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(data,(options.dns,options.dns_port))
    # Wait for reply
    data,server = s.recvfrom(8192)
    return data,server

parser = optparse.OptionParser(usage="Usage: %prog [options]")
parser.add_option("--tcp",action="store_true",default=False,help="TCP mode")
parser.add_option("--port",type=int,default=8053,help="Proxy port (default: 8053)")
parser.add_option("--bind",default="127.0.0.1",help="Proxy bind address (default: 127.0.0.1)")
parser.add_option("--dns",default="8.8.8.8",help="DNS server (default: 8.8.8.8)")
parser.add_option("--dns_port",type=int,default=53,help="DNS server port (default: 53)")
options,args = parser.parse_args()

if options.tcp:
    proxy = tcp_listen(options.bind,options.port)
    recv = tcp_recv
else:
    proxy = udp_listen(options.bind,options.port)
    recv = udp_recv

while True:
    # Wait for client connection
    data,client,conn = recv(proxy)
    # Parse and print request
    if options.tcp:
        r = data[2:]
    else:
        r = data
    request = DNSRecord.parse(r)
    id = request.header.id
    qname = request.q.qname
    qtype = request.q.qtype
    print("------ Request (%s): %r (%s)" % (str(client),qname.label,QTYPE[qtype]))
    print(binascii.hexlify(data))
    print("\n".join([ "  %s" % l for l in str(request).split("\n")]))
    # Send request to server
    if options.tcp:
        data,server = tcp_send(data,options.dns,options.dns_port)
        r = data[2:]
    else:
        data,server = udp_send(data,options.dns,options.dns_port)
        r = data
    # Parse and print reply
    reply = DNSRecord.parse(r)
    id = reply.header.id
    qname = reply.q.qname
    qtype = reply.q.qtype
    print("------ Reply (%s): %r (%s)" % (str(server),qname.label,QTYPE[qtype]))
    print(binascii.hexlify(data))
    print("\n".join([ "  %s" % l for l in str(reply).split("\n")]))
    print()
    # Send reply to client
    if options.tcp:
        conn.sendall(data)
        conn.close()
    else:
        proxy.sendto(data,client)


