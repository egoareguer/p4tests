#!/usr/bin/perl
use strict;
use warnings;

# Four tables. They do an exact match on [[ 0, 31 ]], and output 2^match

my $N=32; # How large the bitmaps are

for ( my $i = 0; $i <4; $i++  ) {
	my $ind=$i+1;
	open (my $out, ">", "./tables/table$ind.txt") or die "Can't open output file: $!"; 
	for ( my $j = 0; $j <32; $j++ ) {
		my $var = 2^(-1+$j);
		my $svar = sprintf "%0$N"."b", $var;
		#print $out "$j : write_tmp($svar); \n";
		print $out "$j : write_tmp".$ind."(32w0b1"."0"x($j)."); \n";
	}
}
