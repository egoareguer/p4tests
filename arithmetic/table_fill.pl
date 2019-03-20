#!/usr/bin/perl
use strict;
use warnings;
#Because table_fill.sh was taking too long and perl has a builtin x for string multiplication

# Writes the log table entries. For N bits integers, about ~N*2^m entries of form
# O^n++1(0|1)^min(m-1,N-n-1)++*^max(0,N-n-m) for 0 <= n < N
# l bit long log values will fit an exp table of size 2^l 

open(my $out, ">", "log_table_perl.txt") or die "Can't open output file: $!";
my $line="";

my $m=5;
my $N=64;
my $l=32;
my $n=0;
my $min=0;
my $max=0;
my $range=0; my $remaining=""; my $var=0;
my $i=0; my $k=0; my $j=0; 

for ($n =0; $n < $N; $n++) {
	if (($m-1) < (64-$n-1)) {
		$min=$m-1;
	} else {
		$min=64-$n-1;
	}
	if ($N -$n -$n) {
		$max=0;
	} else {
		$max=$N-$n-$m;
	}
	$range=2**$min;
	for ($i=0; $i<$range; $i++) {
		$line="0"x$n." 1";
		print $out "(64w0b".$line;
		# Perl's (s)printf has a template to write the binary form: %b
		# Better yet, we can tell him how wide it should be.
		printf $out "%0$min"."b"." ", $i unless $n == 63;
		#Printed chars:6+n+1+min
		print $out "1"x(70-(6+1+$n+$min))." &&& 64w0b";
		print $out "1"x($n+5) unless ($n+5 >63);
		print $out "1"x(64) if ($n+5>63);
		print $out "0"x(59-$n).")";
		print $out ": log(";
		printf $out "%$l"."b", log(2**($min+1)+$min*2**(64-$n-$min-1));
		print $out ");\n"; 
		$var=(2**($min+1)+$min*2**(64-$n-$min-1)) ;print $out "arg=$var \n"; 
	}
}

