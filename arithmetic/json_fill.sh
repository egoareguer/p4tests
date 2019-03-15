#!/bin/bash
rm table_zeroes.json

for i in {1..56}; 
do
	echo -n "table_add zeroes_lpm save_zeroes 0b" >> table_zeroes.json 
	for ((j=2; j<$i+1;j++)); 
	do 
		echo -n "0" >> table_zeroes.json
	done

	echo -n "1" >> table_zeroes.json
	
	for ((j=$i+1; j<57;j++));
	do
		echo -n "0" >> table_zeroes.json
	done

	echo "/$i => $i" >> table_zeroes.json
done

#table_add zeroes_lpm save_zeroes 0b10000000000000000000000000000000000000000000000000000000/1 => 1

