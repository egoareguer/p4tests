#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import re

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, sr, sr1, srp1
from scapy.all import Packet, bind_layers
from scapy.all import StrFixedLenField, XByteField, IntField
from scapy.all import Ether, IP, UDP, TCP

class P4dump(Packet):
    name = "P4dump"
    #Intfields are four bytes wide
    fields_desc = [ StrFixedLenField("P", "P", length=1),
                    StrFixedLenField("Four", "4", length=1),
                    StrFixedLenField("Dump", "D", length=1),
                    XByteField("version", 0x01),
                    IntField("dump_code", 0),
                    IntField("dump_port", 0),
                    StrFixedLenField("DumpBlock_1", "", length=256)]
bind_layers(Ether, P4dump, type=0x1235)

 # a P4DUMP packet looks like this: 
 #
 #        0                1                  2              3
 # +----------------+----------------+----------------+---------------+
 # |      P         |       4        |      Dump      |    Version    |
 # +----------------+----------------+----------------+---------------+
 # |                             Dump code 			      |
 # +----------------+----------------+----------------+---------------+
 # |                             Dump port                            |
 # +----------------+----------------+----------------+---------------+
 # |                             Dumpblock                            |
 # +----------------+----------------+----------------+---------------+
 # |						 	 Dumpblock    |
 # +----------------+----------------+----------------+---------------+
 # |								      |
 # |                               (...)     			      |
 # |								      |
 #
 # P is an ASCII Letter 'P' (0x50)
 # 4 is an ASCII Letter '4' (0x34)
 # Dump is an ASCII Letter "D" (0x44)
 # Version is currently 0.1 (0x01)
 # Dumpcode is a four byte wide integer field. Values range in [2314,2320]
 # Dump port is a four byte wide integer field for the port to dump
 # They match different HLL registers to read
 # Everythin after that is pre allocated empty space meant to be parsed, 
 # then filled by the switch.

class NumParseError(Exception):
    pass

def code_parser(s):
    pattern = "^\s*(231[4-9])\s*"
    match = re.match(pattern, s)
    if (match | s=="2320"):
        return(match.group(1))
    raise NumParseError('Expected number literal in [|2314, 2320|].')

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

def check_code():
    sCode=int(sys.argv[2]) #For int code. 0x90A=2314
    lcode=[i for i in range(2314,2320)] # Could use a RE. Meh. 
    if sCode not in lcode:
        print("The third and final argument should be a dump flag.")
        print("Matched values: 2314 -> 2319 (int for 0x90A -> 0x90F")
        exit(1)
    return(sCode)

def check_port():
    port=int(sys.argv[1])
    if (port <0 or port > 65534):
        print("First argument should be a port number")
        exit(1)
    return(port)
    
def set_ips():
    l=len(sys.argv)
    ds,dd="0.0.0.0","1.1.1.1"
    if l>3:
        ds=sys.argv(3)
    if l>4:
        dd=sys.argv(4)
    return(ds,dd)

def main():
    print(len(sys.argv))
    if len(sys.argv)<3:
        print 'pass 2 arguments: <dPort> <Feature code in 2314-2320>'
	exit(1)
    else:
        dport=check_port()
        code=check_code()
        ds,dd=set_ips()
    iface = get_if()
    l=1048*"a"
    print "sending on interface %s" % (iface)
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type=int(sys.argv[2])) / IP(dst=dd, src=ds) / TCP(dport=int(sys.argv[1]), sport=random.randint(49152,65535))  / l
    pkt.show()
    pkt2 = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff', type=1235) / P4dump(dump_code=code, dump_port=dport) / l
    # pkt2.show()
    
    srp1(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    main()
