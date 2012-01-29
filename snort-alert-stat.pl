#!/usr/bin/perl
# (C) 2010. Vlatko Kosturjak - Kost. Distributed under GPL

use strict;

# typical line
# 10/11-22:26:27.779993  [**] [116:151:1] (snort decoder) Bad Traffic Same Src/Dst IP [**] [Priority: 3] {UDP} 127.0.0.1:0 -> 127.0.0.1:0
my $alerts={};
my $debug=0;
my $sep=";";

while (<STDIN>) {
	chomp;
	my $proto;
	my $desc;
	if (/Classification\:/) {
	#       timestamp|separator|eventid  | eventdesc|separator|classification|priority|proto
	$_ =~ /([^\ ]*)\s+([^\ ]*)\s+([^\ ]*)\s+([^\[]*)([^\ ]*)\s+([^\]]*)\]\s+([^\]]*)\]\s+([^\ ]*)\s+/;
	$desc=$4;
	$proto=$8;
	} else {
	#       timestamp|separator|eventid  | eventdesc|separator|priority|proto
	$_ =~ /([^\ ]*)\s+([^\ ]*)\s+([^\ ]*)\s+([^\[]*)([^\ ]*)\s+([^\]]*)\]\s+([^\ ]*)\s+/;
	$desc=$4;
	$proto=$7;
	}
	if ($debug>10) {
		print STDERR $4;
		print STDERR $sep;
		print STDERR "\n";
	}	
	$proto =~ s/(^\{)|(\}$)//g;
	$alerts->{$proto.$sep.$desc}=$alerts->{$proto.$sep.$desc}+1;
}

my @sorted = sort { $alerts->{$b} <=> $alerts->{$a} } keys %{$alerts};
# print Dumper(@sorted);
foreach my $key ( @sorted ) {
	print $key;
	print $sep;
	print $alerts->{$key};	
	print "\n";
}
