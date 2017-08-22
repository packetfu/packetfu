#!/usr/bin/env ruby
# Usage:
# rvmsudo ruby examples/readpcap.rb test.pcap test.pcap

# Path setting slight of hand:
$: << File.expand_path("../../lib", __FILE__)

require 'packetfu'
include PacketFu

pcap_filename = ARGV[0] || 'test/sample.pcap'

unless File.exists?(pcap_filename)
  puts "PCAP input file '#{pcap_filename}' could not be found"
  exit 1
end

puts "Loaded: PacketFu v#{PacketFu.version}"

puts "Reading PCAP to packet array from #{File.expand_path(pcap_filename)}"
packet_array = PacketFu::PcapFile.file_to_array(pcap_filename)

packet_array.each do |pkt|
  packet = PacketFu::Packet.parse(pkt)

  # Do some stuff here (really any thing you want)
  puts packet.class
end
