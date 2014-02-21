#!/usr/bin/env ruby
$:.unshift File.expand_path(File.dirname(__FILE__) + "/../lib/")
require 'pcaprub'
require 'packetfu'
include PacketFu

if Process.euid.zero? 
  puts ">> Interface: " << Pcap.lookupdev
else
  puts ">> No interface access"
end	
puts ">> Version: " << PacketFu.version

# vim: nowrap sw=2 sts=0 ts=2 ff=unix ft=ruby


