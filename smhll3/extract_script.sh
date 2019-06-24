#!/bin/bash 
cd ./py/

#  !!! Invoke this script from h1 !!!

# Spends batches of a fixed $num_pkt amount of packets with test1.py
# After each batch, asks the switch to dump all four registers
# Once done sending, moves the pcap with the dumps into recorders
# Strip them down to the relevant hexdump payloads 
# You should call py/decode.py to process these into the entries lists

# functions: 
function signal() # 
{
	n=$1
	python test1.py $n
}

function dump()
{
	python dump2.py 0 2314
	python dump2.py 0 2315
	python dump2.py 0 2316
	python dump2.py 0 2317
}
# Send packets, dump registers 
 

if [[ -n $1 ]] ; then
	num_pkt=$1
else
	num_pkt=50
fi
for i in {1..50} 
do 
	signal $num_pkt
	dump 
done

# Move resulting pcap into records, using parameters filename
# Extract the dumpBlocks according to said parameters into
# [filename].dumpBlocks


cd ..
cp s1-eth1_in.pcap ./records/
cd ./records/
filename="payloads_$num_pkt.txt"
# echo 	 "# Pace is $num_pkt large." > $filename
tshark -r s1-eth1_in.pcap -T fields -e data | cut -df -f9 >> $filename 
chown p4 $filename ; chgrp p4 $filename
byte_count=$(grep -m 1 NUM_HLL_REG ../src/constants.p4 | cut -d' ' -f3) 
cut -c 1-$byte_count $filename > "cropped_payloads_$byte_count.txt"
cd ..
