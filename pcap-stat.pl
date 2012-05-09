#!/usr/bin/perl
# Multiple PCAP files statistics
# Copyright(C) 2010. Vlatko Kosturjak, Kost. Distributed under GPL. 

use strict;
use Net::Pcap qw(:functions);
use Getopt::Long;

# set config and defaults
my %config;
$config{'optimize'}=1;
$config{'verbose'}=0;

my $err = '';
my $sep = ";";
my $total={
	'sumpackets' => 0, 'sumlen' => 0, 
	'pcapstartsec' => 0, 'pcapstartusec' => 0,
	'pcapendsec' => 0, 'pcapendusec' => 0 
	};
my $byproto={};
my $debug=0;


Getopt::Long::Configure ("bundling");

my $result = GetOptions (
	"f|filter=s" => \$config{'filter'},
	"o|optimize!" => \$config{'optimize'},
        "v|verbose+"  => \$config{'verbose'},
        "h|help" => \&help
);
if ($config{'filter'}) {
	print STDERR "[v] Using filter: $config{'filter'}\n" if ($config{'verbose'}>0);
}

while (<STDIN>) {
	chomp;
	my $filename=$_;
	my ($filter_t, $netmask);
	# my $pcap = pcap_open_live($dev, 1024, 1, 0, \$err);
	print STDERR "[v] Processing: $filename\n" if ($config{'verbose'}>0);
	print $filename;
	print $sep;
	$total->{'pcaplen'}=0;
	$total->{'pcapcount'}=0;
	my $pcap = pcap_open_offline($filename, \$err) or die "Can't read '$filename': $err\n";

	# set filter if we have such option
	if ($config{'filter'}) {
		print STDERR "[v] Using filter: $config{'filter'}\n" if ($config{'verbose'}>2);
	   if ( Net::Pcap::compile($pcap, \$filter_t, $config{'filter'}, $config{'optimize'}, $netmask) == -1 ) {
	die "Unable to compile filter string $config{'filter'}\n";
		# Make sure our sniffer only captures those bytes we want in
		# our filter.
		}
	Net::Pcap::setfilter($pcap, $filter_t);
	}

	pcap_loop($pcap, -1, \&process_packet, "just for the demo"); # forever

	pcap_close($pcap);	
	$total->{'sumpackets'}=$total->{'sumpackets'}+$total->{'pcapcount'};
	$total->{'sumlen'}=$total->{'sumlen'}+$total->{'pcaplen'};
	print $total->{'pcaplen'},$sep,$total->{'pcapcount'};
	print $sep,$total->{'pcaplen'}/($total->{'pcapcount'}+1);
	print "\n";
} 

my $timediff=$total->{'pcapendsec'}-$total->{'pcapstartsec'};
$timediff=1 if ($timediff < 1);
print "GRAND TOTAL\n";
print $total->{'sumpackets'};
print $sep;
print $total->{'sumlen'};
print $sep;
print $total->{'sumlen'}/($total->{'sumpackets'}+1);
print $sep;
print $total->{'sumlen'}/$timediff;
print "\n";
print "Start time: ";
print $total->{'pcapstartsec'},$sep,$total->{'pcapstartusec'};
print "\n";

print "End time: ";
print $total->{'pcapendsec'},$sep,$total->{'pcapendusec'};
print " Time Difference: ";
print $timediff;
print "\n";

print "Average:";
print $total->{'sumpackets'}/$timediff;
print " packets/seconds\n";

print "Protocol number",$sep,"Packet count\n";
foreach my $proto (sort { $byproto->{$b} <=> $byproto->{$a} } keys %{$byproto}) {
	print $proto,$sep,$byproto->{$proto},"\n";
}

sub process_packet {
	my($user_data, $header, $packet) = @_;

	my $proto=unpack("x23C",$packet);
	if ($debug > 10) {	
		print $header->{'len'};
		print $sep;
		print $header->{'tv_sec'};
		print $sep;
		print $header->{'tv_usec'};
		print $sep;
		print $proto;
		print "\n";
	}
	$byproto->{$proto}++;
	if ($total->{'pcapstartsec'} == 0) {
		$total->{'pcapstartsec'} = $header->{'tv_sec'};
	} 
	if ($total->{'pcapstartusec'} == 0) {
		$total->{'pcapstartusec'} = $header->{'tv_usec'};
	} 
	if ($total->{'pcapendsec'} == 0) {
		$total->{'pcapendsec'} = $header->{'tv_sec'};
	} 
	if ($total->{'pcapendusec'} == 0) {
		$total->{'pcapendusec'} = $header->{'tv_usec'};
	} 
	$total->{'pcapcount'}++;
	$total->{'pcaplen'}=$total->{'pcaplen'}+$header->{'len'};

	# packet timestamp is lower than in total?
	if ($header->{'tv_sec'}<=$total->{'pcapstartsec'}) {
		$total->{'pcapstartsec'}=$header->{'tv_sec'};
		if ($header->{'tv_usec'}<=$total->{'pcapstartusec'}) {
			$total->{'pcapstartusec'}=$header->{'tv_usec'};
		}
	} 
	# packet timestamp is bigger than in total?
	if ($header->{'tv_sec'}>=$total->{'pcapendsec'}) {
		$total->{'pcapendsec'}=$header->{'tv_sec'};
		if ($header->{'tv_usec'}>=$total->{'pcapendusec'}) {
			$total->{'pcapendusec'}=$header->{'tv_usec'};
		}
	} 
}

sub help {
        print "PCAP statistics. Copyright (C) Kost. Distributed under GPL.\n\n";
        print "Usage: $0 -f [filter]  \n";
        print "\n";
        print " -f <s>  	Use filter s <s>\n";
        print " --no-optimize  	Do not optimize\n";
        print " -v      	verbose (-vv will be more verbose)\n";
        print "\n";

        print "Example: echo 'pcap1.pcap' | $0 -f 'host 127.0.0.1 and port 80'\n";

        exit 0;
}

