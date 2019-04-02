#!/usr/bin/perl
use strict;
use warnings;

#TODO(s): 
# The rounding is /terrible/ Fix it!
# The decimal precision adjustment should be easy to adjust with just l,m,w 
# To best deal with the rounding, we /could/ try shifting left as much as the current number will allow to go where the gradient is lesser

########## Preface: ##########

# This script writes the approximate log & exp table entries in files in the tables/folder
# Each file pair uses parameters: N, m, l. 
	# > N for N bit integers
	# > m is the width of our moving bits window 
	# > l is the width of the result
# (TODO) Keep in mind, we're going to add the results together, so the leftmost bit of the result should be 0 

# For N bits integers, this writes about ~N*2^m log entries & 2^l entries

# In the case of the log table, it's a lpm match with that maps entries of the form
# Prefix	: O^n++1(0|1)^min(m-1,N-n-1)++*^max(0,N-n-m) ; with 0 <= n < N
# Mask		: 1^(n+min+1) ++ 0^max
# to their log values (of bit width l)
# The reason why is that, since log varies logarithmically, we can get away with only checking the most significant bit and the trailing m bits behind it without messing the approximation noticeably (for our precision, anyway)

# On the other hand, since exp varies wildly for slight change of antecedent, we need to do an exact match for every possible entry, hence why l needs to be small (it already explodes the bit width quickly)

# Also we kinda cheat since we actually use 2^(log2(A)*/log2(B)) for convenience to take advantage of bit shifts

# See also: page 6 of "Evaluating the Power of Flexible Packet Processing for Network Resource Allocation" 
# "What every computer scientist should know about floating point arithmetic"

########## Table variables: N, m, l ##########

my @m=(5,6);
my @N=(16,32,64);
my $l=10;

foreach my $N (@N) {
	foreach my $m (@m) {

	# Additional variable: w. It describes how low we'll go past the decimal point in powers of two
	my $w=6;

		# Where do we write?
		# We're going to vary N, l, and m, and write a table each time. 
		open(my $log_out, ">", "./tables/log_table_$N"."bits_$m"."precision.txt") or die "Can't open output file: $!";
		open(my $exp_out, ">", "./tables/exp_table_$N"."bits_$l"."precision.txt") or die "Can't open output file: $!";
		# For convenience, we also write the variables at the start of the file, commented for .p4
		printf $log_out " // N=$N; m=$m; l=$l; w=$w ; 2**w=%.2f \n", 2**$w;
		print $exp_out " // N=$N; m=$m; l=$l; w=$w \n";

	# *-*-*-*-*-*-* Writing the log table *-*-*-*-*-*-*
		for (my $n=0; $n < $N; $n++) { 

		#	Initialization of $min & $max
			my $min=0; my $max=0;
			if (($m) < ($N-$n)) {
				$min=$m-1;
			} else {
				$min=$N-$n-1;
			}
			if (($N-$n-$m)<0) {
				$max=0;
			} else {
				$max=$N-$n-$m;
			}

		#	Formerly, for clarity there was "my $range = 2**$min" here, which was used as $i's initial value
		#	Its purpose is to describe the range of (0|1)^min values
		#	For clarity, in Perl . is the string concatenation operator and x is the string multiplication operator
			for (my $i=(2**$min-1); $i>=0; $i--) {

			# *** Writing the prefix *** 
				print $log_out "$N"."w0b"."0"x$n."1";					# $Nw0b++0^n++1
				printf $log_out "%0$min"."b", $i unless $n == $N-1;		# binary of $i, which describes (0|1)^min
				print $log_out "1"x$max." &&& 32w0b";					# fill in the max remaining "masked" bits

			# *** SEPARATION *** (prefix -> mask)

				print $log_out "1"x($n+$min+1);							# Meaningful bits
				print $log_out "0"x$max;								# "Don't care" bits

			# *** SEPARATION *** (mask -> action call)
				# $var is the matched number, logval[shifted] its image by log[possibly shifted to avoid logs of small values, which vary too much for our small precision window]
				
				# In bc, the decimal precision : binary bits ratios are
				# 1:4 ; 2:7; 3:10; 4:14; 5:17; 6:20
				# Considering we'll write about 2^l exp entries, let's do 0.1 precision first
				print $log_out " : write_log($l"."w0b";								

				# With our sliding precision window method, a line in log_table represents all values between 
				# 1(0|1)^min++0^max = X and 1(0|1)^min++1^max . 
				#  *** *** Their median is 1(0|1)^min++1++0^max-1 *** *** 
				#  $var is equal to said median
				my $var = ( ((2**$min+$i)*2+1)*2**($max-1)) ;

					# TRUANDERIE
				my $fac=16 ; my $log2 = log(2);
				my $logval = sprintf("%.8f", log($var));	# log($var) with 8 decimal points
				my $logvalshifted = sprintf("%.8f", log($fac*$var));

					# Resume printing	
				printf $log_out "%0*b", $l, $logval*2**$w/$log2;	#log2(var) with a $w bit shift					
	#			printf $log_out "%0*b", $l, $logvalshifted*2**$w/$log2;	
				print  $log_out ");";

			# Testing/debug prints
				#my $binvar = sprintf "%0b", $var;
				#print $log_out " min $min max $max n $n ";
#				print $log_out "\n var=$var; logval=$logval";
#				print $log_out "\n logvalshifted=$logvalshifted";
#				printf $log_out "\n passed log %.8f", $logval*2**$w/$log2 ;  #Current
#				print $log_out "\n $binvar ";

			# line break between entries
				print $log_out "\n";
			}
		}

	# *-*-*-*-*-*-*-* Writing the exp table *-*-*-*-*-*-*-*
		for (my $j=0; $j<(2**$l); $j++) {
			my $binj = sprintf "%0$l"."b", $j;
			my $e=2**($j/(2**$w));
			my $bine = sprintf "%0$N"."b", $e;
			print $exp_out "$N"."w0b"."$binj : write_exp($N"."w0b$bine); \n" ;
			 # %0$l"."b);\n", $j, $e;

			# INVERSION DE LA TRUANDERIE 
			# En notant A=$fac*$a, ab=exp(log(ab))=exp(log(AB/fac²))=exp(log(A)+log(B)-log(fac²)
			my $facSquared=16*16; my $kk=8;
	#		my $eshifted = 2**($j-log($facSquared))/log(2);
			my $eshift = 2**(($j-$kk)/(2**$w));
			my $bines = sprintf "%0$N"."B", $eshift;
#			print $exp_out "$N"."w0b"."$binj : write_exp($N"."w0b$bines); \n";
		}
		close $log_out or die "$log_out: $!";
		close $exp_out or die "$exp_out: $!";
	}
}
