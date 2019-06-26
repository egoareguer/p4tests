#!/bin/bash 

#  !!! Invoke this script from h1 !!!

# Spends batches of a fixed $num_pkt amount of packets with test1.py
# After each batch, asks the switch to dump all four registers
# Once done sending, moves the pcap with the dumps into recorders
# Strip them down to the relevant hexdump payloads 
# You should call py/decode.py to process these into the entries lists


# Setting parameters we need
# NUM_HLL_REGISTERS N ($2)
# INDEX_WIDTH M (= log2(N)-1)
# step ($1) 

step=90
num_entries=64
dbyte_count=$(echo "$num_entries*3/2" | bc -l) 
index_w=$(echo "l($num_entries)/l(2)-1" | bc -l | cut -d'.' -f1)

find ./src/constants.p4 -type f -exec sed -i 's/#define NUM_HLL_REGISTERS [0-9]*/#define NUM_HLL_REGISTERS $num_entries/g' {} \;
find ./src/constants.p4 -type f -exec sed -i 's/#define INDEX_WIDTH [0-9]*/#define INDEX_WIDTH $index_w/g' {} \;

cd ./py/

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

#Assign num_pkt
if [[ -n $1 ]] ; then
	num_pkt=$1
else
	num_pkt=$step
fi

# Send packets, dump registers 
for i in {1..80} 
do 
	signal $num_pkt
	dump 
done

# Move resulting pcap into records, using parameters filename
# Extract the dumpBlocks according to said parameters into
# [filename].dumpBlocks


cd .._
cp s1-eth1_in.pcap ./records/$num_entries.ent_$num_pkt.step.pcap
cd ./records/
filename="payloads_$num_pkt.txt"
# echo 	 "# Pace is $num_pkt large." > $filename
tshark -r s1-eth1_in.pcap -T fields -e data | cut -df -f9 >> $filename 
chown p4 $filename ; chgrp p4 $filename
# dbyte_count=$(grep -m 1 NUM_HLL_REG ../src/constants.p4 | cut -d' ' -f3) 
# dbyte_count=96
cut -c 1-$dbyte_count $filename > "cropped_payloads_$dbyte_count._$num_pkt.txt"
cd ../py/
./decode.py "cropped_payloads_$dbyte_count._$num_pkt.txt" $step
./estimate.py
