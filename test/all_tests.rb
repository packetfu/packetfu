#!/usr/bin/env ruby
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

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby

