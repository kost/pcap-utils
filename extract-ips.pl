#!/usr/bin/perl
# extract IPs from PCAP files
# Copyright(C) 2010. Vlatko Kosturjak, Kost. Distributed under GPL. 

use strict;
use Net::Pcap qw(:functions);
use NetPacket::Ethernet qw(:strip);
use NetPacket::IP;

use Getopt::Long;

# set config and defaults
my %config;
$config{'optimize'}=1;
$config{'verbose'}=0;

my $err = '';
my $sep = "\n";
my $debug=0;

Getopt::Long::Configure ("bundling");

my $result = GetOptions (
	"f|filter=s" => \$config{'filter'},
	"o|optimize!" => \$config{'optimize'},
	"s|sourceip" => \$config{'sourceip'},
	"d|destip"  => \$config{'destip'},
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
} 

sub process_packet {
	my($user_data, $header, $packet) = @_;

	if ($debug > 10) {	
		print $header->{'len'};
		print $sep;
		print $header->{'tv_sec'};
		print $sep;
		print $header->{'tv_usec'};
		print $sep;
		print "\n";
	}
	my $ip_obj = NetPacket::IP->decode(eth_strip($packet));

	if ($config{'sourceip'}) {
		print $ip_obj->{src_ip};
		print $sep;
	} 

	if ($config{'destip'}) {
		print $ip_obj->{dest_ip};
		print $sep;
	} 
}


sub help {
	print "Extract IPs from PCAP. Copyright (C) Kost. Distributed under GPL.\n\n";
	print "Usage: $0 -f [filter]  \n";
	print "\n";
	print " -f <s>  	Use filter<s>\n";
	print " -s   		Extract source IP\n";
	print " -d	  	Extract destination IP\n";
	print " --no-optimize  	Do not optimize\n";
	print " -v      	verbose (-vv will be more verbose)\n";
	print "\n";

	print "Example: echo 'pcap1.pcap' | $0 -f 'host 127.0.0.1 and port 80' -s\n";

	exit 0;
}

