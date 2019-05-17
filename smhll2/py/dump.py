#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

dcodeA=0x90A
dcodeB=0x90B
dcodeC=0x90C
dcodeD=0x90D
dcodeE=0x90E
dcodeF=0x90F

# A dump packet has : self's MAC & IP, targeted dstPort, dcode ethertype
# pkt = Ether(type=dcode, dst='ff:ff:ff:ff:ff:ff', src=iface) / IP (src=10.0.1.1/get self) / TCP(dport=dstPort,sport=random) 

def main():
	
    if len(sys.argv)<4:
        print 'pass 3 arguments: <destination> <feature code> <dPort>'
	print 'codes: 0x90X, X from A to F for, respectively, srcIP, dstIP, srcPort, pktLen, syn_count, all of the above '
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print "sending on interface %s to %s" % (iface, str(addr))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type=sys.argv[2])
    pkt = pkt /IP(dst=addr, src="10.0.1.1") / TCP(dport=sys.argv[3], sport=random.randint(49152,65535)) 
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    main()
