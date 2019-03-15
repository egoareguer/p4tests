#!/bin/bash
rm log_table.entries

: ' We want to write the log table entries. There is 2^m of the form 
 
	0^n ++ 1(0|1)^min-m-1,N-n-1) ++ *^max(0,N-n-m) for 0 <= n < N
	
	* Corresponds to "whatever", so it needs a mask of its length assorted, and a log of the assorted value written behind
'
m=5
l=32

for n in {0..63}; 
do
	#Constants declaration necessary for the nested loop	
	if [[ $((m -1)) -lt $((64 - n - 1)) ]]; 
	then
		min=$((m -1)) ; echo "first min" 
	else
		min=$((64 - n - 1))  ; echo "second min" 
	fi
	if [[ $(( N - n - m )) -lt 0 ]];
	then
		max=0
	else
		max=$((N - n - m)) 
	fi 

	#echo "min = $min , n = $n , m-1 = $(($m -1)), 64 - n - 1 = $((64 - n - 1))"
	
	range=$((2**min)) 
	for ((i=0;i<$range;i++))
	do
		# ----- Address start -----
		#Prefix
		echo -n "(64w0b" >>  log_table.entries
		for ((j=0; j<$n;j++)); 
		do 
			echo -n "0" >> log_table.entries
		done

		echo -n "1" >> log_table.entries
		
		#Sliding precision window step
		echo -n `bc <<< "obase=2; $i "` >> log_table.entries

		#"Dont care" fill in for proper filling after the window
		#Didn't really find a way to make bc cough up how many chars it wrote, need to read it 
		char_count=`tail -n1 log_table.entries | wc -m`
		#The characters are: the prefix, (64w0b
		remaining=$((72 - $char_count ))
		bc_length=$((72 - $remaining - 7 - $n))

		for ((k=0;k<remaining;k++))
		do	
			echo -n "0" >> log_table.entries
		done

		# ----- Mask start -----
		echo -n " &&& 64w0b" >> log_table.entries
		
		#What's must use the prefix set up
		for ((j=0;j<$n+$bc_length+1;j++));
		do
			echo -n "1" >> log_table.entries
		done
		#Zeroes to bring the mask to its proper length
		for ((j=0;j<$remaining;j++));
		do
			echo -n "0" >> log_table.entries
		done

		echo "/$i) : save_zeroes($i); " >> log_table.entries
	done
done
