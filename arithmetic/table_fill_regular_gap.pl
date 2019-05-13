#!/usr/bin/perl
use strict;
use warnings;

# This time, we plot the log table with regular steps == step

my @m=(5,6);			#Shifting window size
my @N=(16,32,64);		#Total bit width
my $l=10;				#exp table bit width
my $step=0.1;			#delta between log values

foreach my $N (@N){
	foreach my $m (@m){
		my $w=6;		#How far past the decimal in powers of two

		#Opening files
		open(my $log_out, ">", "./tables/paced/log_table_$N"."bits_$m"."precision_$step"."step.txt") or die "Can't open log output file: $!";
		open(my $exp_out, ">", "./tables/paced/exp_table_$N"."bits_$l"."width_withstep.txt") or die "Can't open exp output file: $!";

		printf $log_out " // N=$N; m=$m; l=$l; w=$w ; 2**w=%.2f \n", 2**$w;
        print $exp_out " // N=$N; m=$m; l=$l; w=$w \n";

		my $stop_log=2**($N-$w);
		my $var=0;
		my $expvar=exp($var);
		while ($expvar < $stop_log && $var < 1000){
			$var=$var+$step;
			
			my $logvar=log($expvar);
			$expvar=exp($var);
			print  $log_out "$N"."w0b";
			printf $log_out "%0$N"."b", $expvar;
			printf $log_out "-> write %.3f \n", $var ;

		}
		close $log_out or die "$log_out: $!";
		close $exp_out or die "$log_out: $!";
	}
}


