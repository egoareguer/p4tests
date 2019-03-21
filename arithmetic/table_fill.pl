#!/usr/bin/perl
use strict;
use warnings;
#Because table_fill.sh was taking too long and perl has a builtin x for string multiplication

# Writes the approximate log table entries. 
# Parameters: N, m, l. 
	# > N for N bit integers
	# > m is the width of our moving bits window 
	# > l is the width of the result
# Keep in mind, we're going to add the result, so the leftmost bit of the result should be 0

# For N bits integers, this writes about ~N*2^m entries. 
# Prefix	: O^n++1(0|1)^min(m-1,N-n-1)++*^max(0,N-n-m) ; with 0 <= n < N
# Mask		: 1^(n+min+1) ++ 0^max

# Where do we write?
open(my $out, ">", "log_table_raw") or die "Can't open output file: $!";

# Table variables: N, m, l 
my $m=5;
my $N=32;
my $l=16;

for (my $n =0; $n < $N; $n++) {
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
		print $out "($N"."w0b"."0"x$n."1";					# ($Nw0b++0^n++1
		printf $out "%0$min"."b", $i unless $n == $N-1;		# binary of $i, which describes (0|1)^min
		print $out "1"x$max." &&& 64w0b";					# fill in the max remaining "masked" bits

	# *** SEPARATION *** (prefix -> mask)

		print $out "1"x($n+$min+1);							# Meaningful bits
		print $out "0"x$max;								# "Don't care" bits

	# *** SEPARATION *** (mask -> action call)
		# $var is the matched number, logval[shifted] its image by log[possibly shifted to avoid logs of small values, which vary too much for our small precision window]
		
		# TODO/Problem: log gives us decimal precision width just fine... the %0b binary conversion doesn't.
		# TODO: Ideally, we'd take the log of the first entry, and take as many bits as it's wide + 1 to use prior the decimal, and the rest after the decimal
	
		print $out ": log(";								
		my $var = ( ((2**$min+$i)*2+1)*2**($max-1)) ;
		my $logval = sprintf("%.8f", log($var));
		my$logvalshifted = 100*$logval;
		printf $out "%0*b", $l, $logval;
		print $out ");";
		
	# Testing prints
		#my $binvar = sprintf "%0b", $var;
		#print $out " min $min max $max n $n ";
		#print $out " \#$var, $logval $logvalshifted";
		#print $out "\n $binvar ";

	# line break between entries
		print $out "\n";
	}
}
