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
		min=$((m -1)) ;# echo "first min" 
	else
		min=$((64 - n - 1))  ;# echo "second min" 
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
		padding=$(($min - $bc_length + 1))
		
		#echo -n " " >> log_table.entries
		for ((l=0;l<padding;l++)) 
		do	
			echo -n "0" >> log_table.entries 
		done
		echo -n $var >> log_table.entries #n +6 chars

		#echo -n " " >> log_table.entries

		#"Dont care" fill in for proper filling after the window
		#Didn't really find a way to make bc cough up how many chars it wrote, need to check the man
		char_count=`tail -n1 log_table.entries | wc -m`

		#The characters are: the prefix, (64w0b
		remaining=$((70 - $char_count ))
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

		# representative var calculation
		# let a = 0^n ++ 1 ++ (0|1)^min ++ 0^max
		# if n+1+min < 64, then avg = a + 1++0^(max-1)
		median=`tail -n1 log_table.entries | cut -d" " -f1 | cut -d"b" -f2 | cut -c "$((n+1))-"`
		complement=`bc <<< "obase=2 ;2^$((64 - $bc_length - $n -$padding -1  )) "`
		sum=` bc <<< "ibase = 2; obase=2; $median+$complement"`

		#####*****																					*****#####
#######****** Here is where we need to define the precision l for the precision of our exp approximation ******######
#######******  The table will have 2^l entries then
		#####*****																					*****#####
		:	'
			scale = 1  -> 4  chars 0110
			scale = 2  -> 7  chars 0001000
			scale = 3  -> 10 chars 1000010111
			scale = 4  -> 14 chars 00100001001110
			scale = 5  -> 17 chars 00010101100011000 
			scale = 6  -> 20 chars 01101100101110100110
			scale = 7  -> 24 chars 000110010011111010100110
			scale = 8  -> 27 chars 001011111111100010111100101
			scale = 9  -> 30 chars 000011011110111110111100101010
			scale = 10 -> 34 chars 0000110111101111101111001010101110
			...Alternatively, instead of using scale, just use sed to trim it to the desired length
			'
		res=`bc -l <<< "scale=3; ibase=2; obase=2; l ($sum)"`
		# arg=`cut -d\. -f1 <<< $res `
		arg=$res
		#With scale = 10, we get 34 significative numbers past the comma aka more than enough
		

		echo " : save_zeroes(64w0b$arg); " >> log_table.entries
		
		#echo "var = $var, n=$n, bc_length = $bc_length, remaining = $remaining, padding = $padding, min = $min" >> log_table.entries
		#echo "median complement sum " >> log_table.entries
		#echo $median	>> log_table.entries
		#echo $complement>> log_table.entries
		#echo $sum>> log_table.entries
		echo $sum >> log_table.entries
	done
done

echo -n "(64w0b" >> log_table.entries
for n in {0..62}
do
	echo -n "0"  >> log_table.entries 
done
echo -n "1 &&& 64w0b" >> log_table.entries 
for n in {0..63}
do
	echo -n "1"  >> log_table.entries
done
echo -n " : op (1);" >> log_table.entries
