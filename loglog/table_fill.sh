#!/bin/bash
rm table_zeroes_lpm

for i in {1..56}; 
do
	echo -n "56w0b" >> table_zeroes_lpm

	for ((j=2; j<$i+1;j++)); 
	do 
		echo -n "0" >> table_zeroes_lpm 
	done

	echo -n "1" >> table_zeroes_lpm
	
	for ((j=$i+1; j<57;j++));
	do
		echo -n "0" >> table_zeroes_lpm
	done

	echo -n " &&& 56w0b" >> table_zeroes_lpm

	for ((j=1; j<$i+1; j++));
	do
		echo -n "1" >> table_zeroes_lpm
	done
	for ((j=$i; j<56; j++));
	do
		echo -n "0" >> table_zeroes_lpm
	done

	echo " : save_zeroes($i);" >> table_zeroes_lpm
done
