#!/usr/bin/perl
use strict;
use warnings;

#Should coordinate with spam.py
#Takes the N first ports

my $N=254;
open (my $entries_out, ">", "./portBlock_entries.txt") or die "Can't open output file: $!";


for (my $n=0; $n< $N; $n++){
	printf $entries_out "$n : setPortBlock($n) ;\n";
}
close $entries_out or die "$entries_out: $!";
