# !/usr/bin/python3 
from scapy.all import * 

IPpkt = IP(dst='8.8.8.8') 
UDPpkt = UDP(dport=53) 
Qdsec = DNSQR(qname='www.syracuse.edu') 
DNSpkt = DNS(id=100, qr=0, qdcount=1, qd=Qdsec) 
Querypkt = IPpkt/UDPpkt/DNSpkt 

reply = sr1(Querypkt)  # Use sr1 to send and receive a single reply
if reply:
    ls(reply[DNS])  # Ensure the reply contains a DNS layer
