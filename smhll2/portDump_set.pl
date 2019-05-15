#!/usr/bin/perl

# Writes table for: srcIP_dump, dstIP_dump; srcPort_dump; pktLen_dump; syn_dump; dump_all
# Filenames: srcIP_portBlock_reads.txt, dstIP_, srcPort_, pktLen_, all_

#Do we assume separate hooks for each feature?
use strict;
use warnings;

my $N=250;
my $index=0;
my $end=5;
my @prefixes=("srcIP","dstIP","srcPort","pktLen");

# For single features, it's:
# feature's entry read into tmp -> pushed into appropriate slot 

for my $prefix (@prefixes){
	open (my $file, ">", "./".$prefix."_portBlock_reads.txt") or die "Can't open output file: $!";
	for (my $n=0; $n<$N; $n++){
		$index=($n*6)%252;
		$end=$index+5;
		my $block=($n)/42;
		printf $file $prefix."_masterReg.read(tmp,(bit<32>)hdr.tcp.dstPort+$n);\n";
		printf $file "hdr.dumpBlock.value%1d[$end:$index]=tmp;\n",$block;
		}
	close $file or die "$file $!";
}

# For all dump, it's the same with one action. Better to re-use them with the control
