#!/bin/bash
rm log_table.entries

: ' We want to write the log/exp table entries. There is ~ N*2^m of the form 
 
	0^n ++ 1(0|1)^min-m-1,N-n-1) ++ *^max(0,N-n-m) for 0 <= n < N
	
	for the log table, mapping to a L-long bit floating int with a fixed decimal point that corresponds to the average of the logs for said entry

	The exp table simply maps back said value to an integer.
	
	The * character corresponds to "whatever", so it needs a mask of its length assorted, and a log of the assorted value written behind
'
m=5
l=32

for n in {0..62}; #62 because the last line is an ugly hack 
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
		for ((j=0; j<$n;j++));  #n chars
		do 
			echo -n "0" >> log_table.entries
		done

		#echo -n " " >> log_table.entries
		echo -n "1" >> log_table.entries #n+1 chars
		
		#Sliding precision window step
		#echo -n `bc <<< "obase=2; $i "` >> log_table.entries
		var=`bc <<< "obase=2; $i"` 		
		bc_length=`wc -m <<< $var` #True, because there's a '1' prefixing var, but bc appends a linebreak to the value
		padding=$(($min - 1 - $bc_length))
		
	#	echo -n " " >> log_table.entries
		for ((l=0;l<padding;l++)) 
		do	
			echo -n "0" >> log_table.entries 
		done
		echo -n $var >> log_table.entries #n +6 chars

		#"Dont care" fill in for proper filling after the window
		#Didn't really find a way to make bc cough up how many chars it wrote, need to check the man
		char_count=`tail -n1 log_table.entries | wc -m`

		#The characters are: the prefix, (64w0b
		remaining=$((70 - $char_count ))
	
		#space after precision window
		#echo -n " " >> log_table.entries

	#	echo -n " " >> log_table.entries
		for ((k=0;k<$remaining;k++))
		do	
			echo -n "0" >> log_table.entries
		done

		# ----- Mask start -----
		echo -n " &&& 64w0b" >> log_table.entries
		
		#What's must use the prefix set up
		for ((j=0;j<$n+5 & j<64 ;j++));
		do
			echo -n "1" >> log_table.entries
		done
		#Zeroes to bring the mask to its proper length
		for ((j=0;j<59-$n;j++));
		do
			echo -n "0" >> log_table.entries
		done

		#representative var calculation
		# let a = 0^n ++ 1 ++ (0|1)^min ++ 0^max
		# if n+1+min < 64, then avg = a + 1++0^(max-1)
		median=`tail -n1 log_table.entries | cut -d" " -f1 | cut -d"b" -f2 | cut -c "$((n+1))-"`
		echo median $median
		complement=`bc <<< "obase=2 ;2^$(($max -1)) "`
		echo complement $complement
		arg=`bc -l <<< "ibase=2; obase=2; l ($((median+complement)))"`
		echo arg $arg

		echo " : save_zeroes($arg); " >> log_table.entries
		
		echo "var = $var, n=$n, bc_length = $bc_length, remaining = $remaining, padding = $padding, min = $min" >> log_table.entries
	done
done

echo -n "(64w0b" >> log_table.entries
for n in {0..62}
do
	echo -n "0" >> log_table.entries 
done
echo -n "1 &&& 64w0b" >> log_table.entries 
for n in {0..63}
do
	echo -n "1" >> log_table.entries
done
echo -n " : op (1);" >> log_table.entries
