#!/usr/bin/perl

# Writes table for: srcIP_dump, dstIP_dump; srcPort_dump; pktLen_dump; syn_dump; dump_all
# Filenames: srcIP_portBlock_reads.txt, dstIP_, srcPort_, pktLen_, all_

# N is the parameter that fixes how many bit<6> entries are read total in the table 
# 250 for block0-5

use strict;
use warnings;

my $N=256;
my $index=0;
my $end=5;
my @prefixes=("srcIP","dstIP","srcPort","pktLen");

# For single features, it's:
# feature's entry read into tmp -> pushed into appropriate slot 

for my $prefix (@prefixes){
	open (my $file, ">", "./action_blocks/".$prefix."_portBlock_reads.txt") or die "Can't open output file: $!";
	for (my $n=0; $n<$N; $n++){
		$index=($n*6)%192;
		$end=$index+5;
		my $block=($n)/32;
		printf $file $prefix."_masterReg.read(tmp,(bit<32>)hdr.p4dump.port*(bit<32>)meta.portBlock+$n);\n";
		printf $file "hdr.dumpBlock.value%1d[$end:$index]=tmp;\n",$block;
		}
	close $file or die "$file $!";
}

# For all dump, it's the same with one action. Better to re-use them with the control
