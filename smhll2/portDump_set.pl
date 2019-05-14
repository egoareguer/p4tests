#!/usr/bin/perl

#Do we assume separate hooks for each feature?
use strict;
use warnings;

open (my $file, ">", "./srcIP_portBlock_reads.txt") or die "Can't open output file: $!";
my $N=254;
my $index=0;
my $end=5;

#How each write should look:
# feature's entry read into tmp -> pushed into appropriate slot 

for (my $n=0; $n<$N; $n++){
	$index=$n*6;
	$end=$index+5;
	printf $file "meta.IPsrc_masterReg.read(tmp,dstPort+$n)\n";
	printf $file "meta.portBlock[$end:$index]=tmp;\n";
}
close $file or die "$file $!";
