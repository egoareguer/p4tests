#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

#In the case of SplitMerge, we'd like to cover a variety of dstPorts with a variety of tuples, but there's no need to overreach low ports numbers for testing

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
    

# Parameters should be a repartition 
# The only key is dstPort in this use case
# In the meantime, we pick N keys, set them for 200-2 pkts each, send them randomly

    keys=[]
    N=128
    for i in range (N):
#An IP is 32 bits, a port is 16
	sport=str(random.randint(1024, 64444))
	dport=str(random.randint(1,128))
	ip1=str(random.randint(1,254))+'.'+str(random.randint(1,254))+'.'+str(random.randint(1,254))+'.'+str(random.randint(1,254))
	ip2=str(random.randint(1,254))+'.'+str(random.randint(1,254))+'.'+str(random.randint(1,254))+'.'+str(random.randint(1,254))
	lenPadding=random.randint(1,20)*"Toto"
	keys.append((sport,dport,ip1,ip2,lenPadding))
	#Let's set 0.5% at 250 pkts, 0.5% 200, 0.5% at 150, 0.5% at 100, 1% at 50, rest at 2-25
    ''' class1=[]; class2=[]; class3=[]; class4=[]; class5=[]; class6=[]; class7=[]
    for i in range(10):
	j=10*i
	class1.append(keys[j+i])
	class2.append(keys[j+i+1])
	class3.append(keys[j+i+2])
	class4.append(keys[j+i+3])
	class5.append(keys[j+i+4]); class5.append(keys[j+i+5])
	class6.append(keys[j+i+6]); class6.append(keys[j+i+7]); class7.append(keys[j+i+8]); class7.append(keys[j+i+9])
    class7= class7+keys[100:]
    keys=250*class1+200*class2+150*class3+100*class4+50*class5+25*class6+2*class7
    random.shuffle(keys) '''

    print(len(keys))
   # print(class1); print(class2); print(class3); print(class4); print(class5)
    print(keys)
	
    for i in range(len(keys)):
	#print(keys[i])
	pkt = Ether(src=get_if_hwaddr(iface),dst='ff:ff:ff:ff:ff:ff')
	pkt = pkt / IP(dst=keys[i][2],src=keys[i][3]) / TCP(sport=int(keys[i][0]), dport=int(keys[i][1]))  / keys[i][3] # sys.argv[2]
	sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
