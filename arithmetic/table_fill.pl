#!/usr/bin/perl
use strict;
use warnings;

# Preface: This script writes the approximate log & exp table entries in files
# Each file pair uses parameters: N, m, l. 
	# > N for N bit integers
	# > m is the width of our moving bits window 
	# > l is the width of the result
# Keep in mind, we're going to add the result, so the leftmost bit of the result should be 0 

# For N bits integers, this writes about ~N*2^m log entries & 2^l entries
# Prefix	: O^n++1(0|1)^min(m-1,N-n-1)++*^max(0,N-n-m) ; with 0 <= n < N
# Mask		: 1^(n+min+1) ++ 0^max
# Refer to page 6 of "Evaluating the Power of Flexible Packet Processing for Network Resource Allocation" for more details on the form

#To take advantage of bit shifts, we write a FALSE exp table that's really a 2^(val) table

# Table variables: N, m, l 
my @m=(5,6);
my @N=(16,32,64);
my $l=10;

foreach my $N (@N) {
	foreach my $m (@m) {
	# Additional variable: w. It describes how low we'll go past the decimal point in powers of two
	# ****** $l SHOULD BE EQUAL TO $w + $m ******
	my $w=$l-$m;

		# Where do we write?
		# We're going to vary N, l, and m, and write a table each time. 
		open(my $log_out, ">", "./tables/log_table_$N"."bits_$m"."precision.txt") or die "Can't open output file: $!";
		open(my $exp_out, ">", "./tables/exp_table_$N"."bits_$l"."precision.txt") or die "Can't open output file: $!";

	# *-*-*-*-*-*-* Writing the log table *-*-*-*-*-*-*
		for (my $n=0; $n < $N; $n++) {
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
				print $log_out "$N"."w0b"."0"x$n."1";					# ($Nw0b++0^n++1
				printf $log_out "%0$min"."b", $i unless $n == $N-1;		# binary of $i, which describes (0|1)^min
				print $log_out "1"x$max." &&& 32w0b";					# fill in the max remaining "masked" bits

			# *** SEPARATION *** (prefix -> mask)

				print $log_out "1"x($n+$min+1);							# Meaningful bits
				print $log_out "0"x$max;								# "Don't care" bits

			# *** SEPARATION *** (mask -> action call)
				# $var is the matched number, logval[shifted] its image by log[possibly shifted to avoid logs of small values, which vary too much for our small precision window]
				
				# TODO/Problem: log gives us decimal precision width just fine... the %0b binary conversion doesn't.
				# TODO: Ideally, we'd take the log of the first entry, and take as many bits as it's wide + 1 to use prior the decimal, and the rest after the decimal
				
				# In bc, the decimal precision : binary bits is 
				# 1:4 ; 2:7; 3:10; 4:14; 5:17; 6:20
				# Considering we'll get about 2^l entries, let's do 0.1 precision first
				print $log_out " : write_log($l"."w0b";								
				my $var = ( ((2**$min+$i)*2+1)*2**($max-1)) ;

					# TRUANDERIE
				my $fac=256 ; my $div = 1/(256*256); my $log2 = log(2);
				my $logval = sprintf("%.8f", log($var));
				my $logvalshifted = $fac*$logval/$log2;

					# Resume printing	
				printf $log_out "%0*b", $l, $logval*2**$w/$log2;					#Printing the arg
				print  $log_out ");";

			# Testing prints
				#my $binvar = sprintf "%0b", $var;
				#print $log_out " min $min max $max n $n ";
				#print $log_out " \#$var, $logval $logvalshifted";
				#print $log_out "\n $binvar ";

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
		}
		close $log_out or die "$log_out: $!";
		close $exp_out or die "$exp_out: $!";
	}
}
