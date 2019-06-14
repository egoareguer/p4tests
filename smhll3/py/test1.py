#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import time

# The first arg is to specifyhow many ports we test

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
#    return (str(N/2**24)+'.'+str(N%2**24/2**16)+'.'+str(N%2**16/256)+'.'+str(N%256))
    b1=random.randint(1,255)
    b2=random.randint(1,255)
    b3=random.randint(1,255)
    b4=random.randint(1,255)
    res=str(b1)+'.'+str(b2)+'.'+str(b3)+'.'+str(b4)
    return(res)    
#    return(str(random.randint(1,254))+'.'+str(random.randint(1,254))+'.'+str(random.randint(1,254))+'.'+str(random.randint(1,254)))
    
def set_dip(N):
#    return (str(N%256)+'.'+str(N%2**16/256)+'.'+str(N%2**24/2**16)+'.'+str(N/2**24))
    b1=random.randint(1,255)
    b2=random.randint(1,255)
    b3=random.randint(1,255)
    b4=random.randint(1,255)
    res=str(b1)+'.'+str(b2)+'.'+str(b3)+'.'+str(b4)
    return(res)
    
def set_sport(N):
#    return(str((000+N)%64999))
    return(random.randint(1,64999))
    
def main():
    N_PKTS = int(sys.argv[1])
    iface = get_if()
    keys=[]
    N_ENTRIES=32
    for i in range (N_PKTS):
	sport=set_sport(i)
	sip=set_sip(i)
        dip=set_dip(i)
	lenPadding=random.randint(1,100)*"pppp"
	keys.append((sport,0,sip,dip,lenPadding))
        
    print(str(len(keys))+" packets to send")
    clock=time.time()
    for i in range(len(keys)):
        if (i%200==0):
            print(str(i)+" packets sent.", time.time()-clock)
                
	
	pkt = Ether(src=get_if_hwaddr(iface),dst='ff:ff:ff:ff:ff:ff')
	pkt = pkt / IP(dst=keys[i][2],src=keys[i][3]) / TCP(sport=int(keys[i][0]), dport=int(keys[i][1]))  / keys[i][3] # sys.argv[2]
	sendp(pkt, iface=iface, verbose=False)
        if (i%50==0):
            sport=keys[i][0]
            sip=keys[i][3]
            dip=keys[i][2]
            print("sip, dip, sport:",sip,dip,sport)

if __name__ == '__main__':
    main()
