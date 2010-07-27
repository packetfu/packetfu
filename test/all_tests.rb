#!/usr/bin/env ruby
#
# This test suite passes on:
#   ruby-1.8.6-p399 [ x86_64 ]
#   ruby-1.8.7-p174 [ x86_64 ]
#   ruby-1.8.7-p249 [ x86_64 ]
#   ruby-1.9.1-p378 [ x86_64 ]
# PacketFu (but not pcaprub) passes on:
#   ruby-1.9.2-head [ x86_64 ]

require 'test/unit'
$: << File.expand_path(File.dirname(__FILE__) + "/../lib/")
require 'packetfu'

#Note that the Ruby stock unit tester runs this all out
#of order, does funny things with class variables, etc.

require 'test_structfu'
require 'test_pcap'
require 'test_invalid'
require 'test_eth' # Creates eth_test.pcap
require 'test_octets'
require 'test_packet'
require 'test_arp' # Creates arp_test.pcap
require 'test_ip' # Creates ip_test.pcap
require 'test_icmp' # Creates icmp_test.pcap
require 'test_udp' # Creates udp_test.pcap
require 'test_tcp'
require 'test_ip6'

if Process.euid.zero? 
	require 'test_inject'
else
	$stderr.puts "** WARNING ** test_inject not tested, needs root access."
end

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby
