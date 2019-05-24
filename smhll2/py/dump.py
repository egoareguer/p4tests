#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, sr, sr1, srp1
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

sCode=int(sys.argv[2]) #For int code. 0x90A=2314
lcode=[i for i in range(2314,2320)]
if sCode not in lcode:
    print("The third and final argument should be a dump flag.")
    print("Matched values: 2314 -> 2319 (int for 0x90A -> 0x90F")
    exit(1)
    
# A dump packet has : self's MAC & IP, targeted dstPort, dcode ethertype
# pkt = Ether(type=dcode, dst='ff:ff:ff:ff:ff:ff', src=iface) / IP (src=10.0.1.1/get self) / TCP(dport=dstPort,sport=random) 

def main():
    if len(sys.argv)<4:
        print 'pass 3 arguments: <destination> <feature code> <dPort>'
	print 'codes: 0x90X, X from A to F for, respectively, srcIP, dstIP, srcPort, pktLen, syn_count, all of the above '
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    l=1000*"a"
    print "sending on interface %s to %s" % (iface, str(addr))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type=int(sys.argv[2])) / IP(dst=addr, src="10.0.1.1") / TCP(dport=int(sys.argv[3]), sport=random.randint(49152,65535))  / l
    pkt.show()
    srp1(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    main()
