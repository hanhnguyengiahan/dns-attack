#!/usr/bin/python3
from scapy.all import *
from socket import AF_INET, SOCK_DGRAM, socket

# Create a UDP socket and bind it to address 0.0.0.0 and port 1053
sock = socket(AF_INET, SOCK_DGRAM)
sock.bind(('0.0.0.0', 1053))

while True:
    # Receive requests from clients
    request, addr = sock.recvfrom(4096)
    
    # Parse the DNS request
    DNSreq = DNS(request)
    query = DNSreq.qd.qname
    print(query.decode('ascii'))

    # Create DNS resource records for the response
    Anssec = DNSRR(rrname=DNSreq.qd.qname, type='A', rdata='10.2.3.6', ttl=259200)
    NSsec1 = DNSRR(rrname="example.com", type='NS', rdata='ns1.example.com', ttl=259200)
    NSsec2 = DNSRR(rrname="example.com", type='NS', rdata='ns2.example.com', ttl=259200)
    Addsec1 = DNSRR(rrname='ns1.example.com', type='A', rdata='10.2.3.1', ttl=259200)
    Addsec2 = DNSRR(rrname='ns2.example.com', type='A', rdata='10.2.3.2', ttl=259200)

    # Construct the DNS response packet
    DNSpkt = DNS(
        id=DNSreq.id,
        aa=1,  # Authoritative answer
        rd=0,  # Recursion Desired
        qr=1,  # Query/Response: 1 indicates a response
        qdcount=1,
        ancount=1,
        nscount=2,
        arcount=2,
        qd=DNSreq.qd,
        an=Anssec,
        ns=NSsec1 / NSsec2,
        ar=Addsec1 / Addsec2
    )

    print(repr(DNSpkt))

    # Send the response back to the client
    sock.sendto(bytes(DNSpkt), addr)
