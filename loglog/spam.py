#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import time

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

def main():
    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    

#Parameters should be a repartition 
#In the meantime, we pick 2000 keys, set them for 200-2 pkts each, send them randomly
# //TODO There should be consistant HH and Bursty HHs

    keys=[]
    for i in range (24000):
#An IP is 32 bits, a port is 16
	port=str(random.randint(1024, 64444))
	ip=str(random.randint(1,254))+'.'+str(random.randint(1,254))+'.'+str(random.randint(1,254))+'.'+str(random.randint(1,254))
	keys.append((ip,port))
    random.shuffle(keys)

    print(len(keys))
    t=time.time()
    for i in range(len(keys)):
	pkt = Ether(src=get_if_hwaddr(iface),dst='ff:ff:ff:ff:ff:ff')
	pkt = pkt / IP(dst=addr,src=keys[i][0]) / TCP(dport=int(keys[i][1]), sport=random.randint(49152,65535)) / sys.argv[2]
	sendp(pkt, iface=iface, verbose=False)
	if(i%1000 == 0):
		print(i/1000, time.time()-t)


if __name__ == '__main__':
    main()
