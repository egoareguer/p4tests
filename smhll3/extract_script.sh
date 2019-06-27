#!/bin/bash 

#  !!! Invoke this script from h1 !!!

# Spends batches of a fixed $step amount of packets with test1.py
# After each batch, asks the switch to dump all four registers
# Once done sending, moves the pcap with the dumps into recorders
# Strip them down to the relevant hexdump payloads 
# You should call py/decode.py to process these into the entries lists


# Setting parameters we need
# NUM_HLL_REGISTERS N ($2)
# INDEX_WIDTH M (= log2(N)-1)
# step ($1) 

default_step=100
default_repeats=1
num_entries=256
dbyte_count=$(echo "$num_entries*3/2"   | bc -l | cut -d'.' -f1) 
index_w=$(echo "l($num_entries)/l(2)-1" | bc -l | cut -d'.' -f1)

find ./src/constants.p4 -type f -exec sed -i "s/#define NUM_HLL_REGISTERS [0-9]*/#define NUM_HLL_REGISTERS $num_entries/g" {} \;
find ./src/constants.p4 -type f -exec sed -i "s/#define INDEX_WIDTH [0-9]*/#define INDEX_WIDTH $index_w/g" {} \;

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

#Assignments 
if [[ -n $1 ]] ; then
	step=$1
else
	step=$default_step
fi
"""
if [[ -n $2 ]] ; then 
	repeats=$2
else
	repeats=$default_repeats
fi
"""

# Send packets, dump registers 
for i in {1..100} 
do 
	echo "Sending $step pkts of batch n°$i"
	echo ""
	signal $step
	dump 
done


# Move resulting pcap into records, using parameters filename
# Extract the dumpBlocks according to said parameters into
# [filename].dumpBlocks


cd ..

echo -n "Moving pcap to records... "
cp s1-eth1_in.pcap ./records/$num_entries.ent_$step.step.pcap
echo "OK"

cd ./records/
filename="payloads_$step.txt"
# echo 	 "# Pace is $step large." > $filename

echo -n "Stripping dumpBlocks from pcap... "
tshark -r $num_entries.ent_$step.step.pcap -T fields -e data | cut -df -f9-20 >> $filename 
echo "OK"
chown p4 $filename ; chgrp p4 $filename
echo -n "Cropping to useful payload portion only... "
cut -c 1-$dbyte_count $filename > "cropped_payloads_$dbyte_count._$step.txt"
echo "OK"

cd ../py/
echo -n "Calling decode... "
./decode.py "cropped_payloads_$dbyte_count._$step.txt" $step
echo "OK"
echo -n "Calling estimate... "
./estimate.py $num_entries $step
echo "OK"
