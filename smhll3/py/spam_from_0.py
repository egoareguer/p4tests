#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import time

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

def set_sip(N):
    return (str(N/2**24)+'.'+str(N%2**24/2**16)+'.'+str(N%2**16/256)+'.'+str(N%256))

def set_dip(N):
    return (str(N%256)+'.'+str(N%2**16/256)+'.'+str(N%2**24/2**16)+'.'+str(N/2**24))


def set_sport(N):
    return(str((32000+N)%64444))

def main():
    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    keys=[]
    N_FLOWS=32
    start=0
    end=30
    for i in range (N_FLOWS):
	for j in range(start,end): # In other words, i random packets to port i
                           # Sport, Src and Dst IPs are completely random
            sport=set_sport(j)
	    sip=set_sip(j)
            dip=set_dip(j)
	    lenPadding=random.randint(1,100)*"pppp"
	    keys.append((sport,i,sip,dip,lenPadding))
        diff=end-start
        print "Port "+str(i)+": "+str(diff)+" packets."
        start=end
        end=end+30*i

    print(str(len(keys))+"th packets to send")
    clock=time.clock()
    for i in range(len(keys)):
        if (i%100==0):
            print(str(i)+"th packet")
        # print(str(i)+"th packet")
	#print(keys[i])
	pkt = Ether(src=get_if_hwaddr(iface),dst='ff:ff:ff:ff:ff:ff')
	pkt = pkt / IP(dst=keys[i][2],src=keys[i][3]) / TCP(sport=int(keys[i][0]), dport=int(keys[i][1]))  / keys[i][3] # sys.argv[2]
	sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
