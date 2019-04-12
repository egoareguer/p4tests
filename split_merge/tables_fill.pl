#!/usr/bin/perl
use strict;
use warnings;

# Four tables. They do an exact match on [[ 0, 31 ]], and output 2^match

my $N=63; # How large the bitmaps are

for ( my $i = 0; $i <4; $i++  ) {
	my $ind=$i+1;
	open (my $out, ">", "./tables/table$ind"."_".$N.".txt") or die "Can't open output file: $!"; 
	for ( my $j = 0; $j <$N; $j++ ) {
		my $var = 2^(-1+$j);
		my $svar = sprintf "%0$N"."b", $var;
		#print $out "$j : write_tmp($svar); \n";
		print $out "$j : write_tmp".$ind."(".$N."w0b1"."0"x($j)."); \n";
	}
}
