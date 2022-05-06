#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import time
import hashlib
import ipaddress

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet, wrpcap
from scapy.all import Ether, IP, UDP, TCP


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eno2"
    for i in ifs:
        if "eno2" in i:
            iface=i
            break
    if not iface:
        print ("Cannot find eth0 interface")
        exit(1)
    return iface

def get_ipStr(N):
    return(  str(ipaddress.ip_address(N))  )

def get_hashStr(N):
    s = str(N)
    h = hashlib.sha256(s.encode())
    hexd = h.hexdigest()
    return (hexd)

def set_sport(N):
    return(random.randint(1,64999))

def assemble_ipv4_frame(N):
    ipStr=get_ip(N)
    hashStr=hashlib.sha256(str(N)).hexdigest()
    pkt = IP(dst='10.0.1.11',src=ipStr) / (hashStr)

def get_address_block(N,start):
    #mod 16777216 since that's three bytes worth of addresses
    addrBlock=[]
    for i in range(N):
        index=(start+i)%16777216
        addr=get_ipStr(index)
        hashStr=get_hashStr(index)
        addrBlock.append((addr,hashStr))
    return(addrBlock)

def get_address_spread(N,start):
    step = 16777216 / N
    addrSpread=[]
    for i in range (N):
        index = int((start + i*step)%16777216)
        addr=get_ipStr(index)
        hashStr=get_hashStr(index)
        addrSpread.append((addr,hashStr))
    return(addrSpread)

def make_packet(addr,hashVal):
    iface=get_if()
    pkt = Ether(src=get_if_hwaddr(iface),dst="ff:ff:ff:ff:ff:ff",type=1236)
    pkt = pkt / IP(src=addr, dst = "10.0.1.11") / hashVal
    return(pkt)


# Initialization
N_PKTS = 20000
start=addresses = 20000
num=str(N_PKTS)
iface = get_if()

# Preprocessing into PKT = Eth / Key / Hash
addrBlock=get_address_block(N_PKTS,start)
addrSpread=get_address_spread(N_PKTS,start)

blockPkts=[make_packet(i,j) for (i,j) in addrBlock]
spreadPkts=[make_packet(i,j) for (i,j) in addrSpread]

blockFile=wrpcap(num+'block.pcap',blockPkts)
spreadFile=wrpcap(num+'Spread.pcap',spreadPkts)

# Preprocessing into PKT = Eth / Key / Index / Zeroes / Hash
