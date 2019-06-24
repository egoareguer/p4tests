#!/usr/bin/python

hscale=16
bscale=2

# Processes a file containing one hexdump payload per line into the 
# corresponding register value lists, assuming short byte storage
# Use estimate to process these into estimates

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
s="1420c31440820840c31041460420841a0820820820820820"
decode(s)

sfilename="../records/cropped_payloads_32.txt"
pfile=open(sfilename,'r')

dfilename="../records/regentries_32.txt"
wfile=open(dfilename,'w')

line=pfile.readline()[:-1]
while (line):
	dlist=decode(line)
	wfile.write(str(dlist)+"\n")
	line=pfile.readline()[:-1]
pfile.close()
wfile.close()
