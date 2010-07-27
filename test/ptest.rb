#!/usr/bin/env ruby
$:.unshift File.expand_path(File.dirname(__FILE__) + "/../lib/")
require 'pcaprub'
require 'packetfu'
include PacketFu

puts Pcap.lookupdev
# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby


