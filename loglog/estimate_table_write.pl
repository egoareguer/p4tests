#!/usr/bin/perl
use warnings;
use strict;

# tmp = 48w".16x"1".32x"0";
# register1.read(tmp, (bit<32>)index);
# sum = sum + tmp>>tmp;

my $m=256;
open (my $estimate_out, ">", "./estimate_256.txt") or die "Can't open output file: $!";
printf $estimate_out "// This file is the sequence of $m actions included in estimate().";

for (my $n=0; $n<$m; $n++){
	printf $estimate_out "register1.read(tmp, (bit<32>)$n); \n";
	printf $estimate_out "sum = sum + tmp>>tmp; \n";
}
printf $estimate_out "estimate_reg.write(0, sum);";
close $estimate_out or die "$estimate_out $!";
