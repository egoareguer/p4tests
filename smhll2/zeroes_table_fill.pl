#!/usr/bin/perl
use strict;
use warnings;

# Makes the zero match table for a remnant of length N
my $N=12;
open my $table_out, ">", "./tables/zetable_$N".".txt") or die "Can't open output file: $!";
print $table_out "// This table is meant to match how many zeroes are in a remnant of length $N";

for (my $n=0; $n<$N; $n++){
    # all LPM match lines are of format:
    # $Nw0b0^n++1++0^N-n-1: &&& $N0wb1^(n+1)++[0]^($N-$n-1) : save_seenZeroes($n+1);
    print $table_out "$N"."w0b"."0"x$n."1"."0"x($N-$n-1)." &&& $N"."w0b"."1"x($n+1)."0"x($N-$n-1)." : save_seenZeroes($n+1);";
}
close $table_out or die "$table_out: $!";
