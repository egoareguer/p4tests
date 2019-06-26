#!/usr/bin/python
import sys

hscale=16
bscale=2

# Processes a file containing one hexdump payload per line into the 
# corresponding register value lists, assuming short byte storage
# Use estimate to process these into estimates

# If the register entries for the given port is over 252 bits (ie, NUM_HLL_REGISTERS > 42) 
# Then we'll need more than the value0 header to store it in the p4, on account of 
# 256 bits being the bit slicing limit (in v1model).
# There'll thus be a second block. 
# We'll need to account for the endianness in this case.


# HLL entries are stored in 6 bits (dubbed "short bytes" by the paper's authors) 
# So for N short bytes, there are 3/4 as many bytes encoded in 6/4 chars 

def split(s):
	# split separates s into 48 chars strings + leftover
	# This because we parse the dump request with 192 bits blocks 
	# to accomodate the 256 bit shift limit in p4
	# 48 chars <-> 24 bytes <-> 36 'short bytes <-> 192 bits 
	res=[]
	while len(s)>48:
		res.append(s[0:48])
		s=s[48:]
	if len(s)>0:
		res.append(s)
	return(res)
	

def decode(s):
	# str s is a string of hexadecimal e.g. "1420c3", NOT "0x14 0x20 0xc3"
	# obtained from the raw dump of pcap files

	num_bits=len(s)*4

	sl=[]
	for i in range(len(s)/2):
		sl.append(s[2*i:2*i+2])
	#print("Bytes list:",sl,"\n")

	bl=[]
	for i in range(len(sl)):
		bl.append(bin(int(sl[i],hscale))[2:].zfill(8))
	#print("Binary of bytes list:",bl)

	bs=""
	for i in bl:
		bs=bs+str(i)
	#print("Concatenated bin string bs:",bs,"\n")

	sbl=[]
	for i in range(num_bits/6):
		sbl.append(bs[6*i:6*i+6])
	#print("Short bytes list:",sbl,"\n")

	rsbl=sbl[::-1]
	al=[]
	for i in rsbl:
		al.append(int(i,bscale))
	#print("bl inverted and converted to int again:",al)
	return(al)
	
def decode_blocks(s,n):
	# str s is the concatenation of several hex blocks
    # of length n

	for i in range(len(s)/n):
		decode(s)

sfilename="../records/"+sys.argv[1]
#sfilename="../records/cropped_payloads_96._75.txt"
pfile=open(sfilename,'r')

dfilename="../records/regentries_"+sys.argv[2]+".txt"
#dfilename="../records/regentries_75.txt"
wfile=open(dfilename,'w')

line=pfile.readline()[:-1]
count=0
while (line):
	block_list=split(line)
	entries=[]
	for i in block_list:
		dlist=decode(i)
		entries+=dlist
	wfile.write(str(entries))
	count+=1
	wfile.write("\n")
	line=pfile.readline()[:-1]
pfile.close()
wfile.close()
