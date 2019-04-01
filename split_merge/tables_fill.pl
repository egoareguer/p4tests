#!/usr/bin/perl
use strict;
use warnings;

# Four tables. They do an exact match on [[ 0, 31 ]], and output 2^match[+32k]

my $N=160; # How large the bitmap is

for ( my $i = 0; $i <4; $i++  ) {
	open (my $out, ">", "./tables/table$i.txt") or die "Can't open output file: $!"; 
	for ( my $j = 0; $j <32; $j++ ) {
		my $var = 2^((32*$i)-1+$j);
		my $svar = sprintf "%0$N"."b", $var;
		#print $out "$j : write_tmp($svar); \n";
		print $out "$j : write_tmp(160w0b1"."0"x(32*$i+$j)."); \n";
	}
}
