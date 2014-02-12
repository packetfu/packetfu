#!/usr/bin/env ruby
# -*- coding: binary -*-

# Used mainly to test for memory leaks and to demo the preferred ways of
# reading and writing packets to and from pcap files.
require './examples' # For path setting slight-of-hand
require 'packetfu'

include PacketFu
puts "Generating packets... (#{Time.now.utc})"

File.unlink("/tmp/out.pcap") if File.exists? "/tmp/out.pcap"
start_time = Time.now.utc
count = 0

100.times do
  @pcaps = []
  1000.times do 
    u = UDPPacket.new
    u.ip_src = [rand(2**32-1)].pack("N")
    u.ip_dst = [rand(2**32-1)].pack("N")
    u.recalc
    @pcaps << u
  end
  pfile = PcapFile.new
  res = pfile.array_to_file(:filename => "/tmp/out.pcap", :array => @pcaps, :append => true)
  count += res.last
  puts "Wrote #{count} packets in #{Time.now.utc - start_time} seconds"
end

read_bytes_start = Time.now.utc
puts "Reading packet bytes..."
packet_bytes = PcapFile.read_packet_bytes "/tmp/out.pcap"
puts "Read #{packet_bytes.size} packet byte blobs in #{Time.now.utc - read_bytes_start} seconds."

read_packets_start = Time.now.utc
puts "Reading packets..."
packet_bytes = PcapFile.read_packets "/tmp/out.pcap"
puts "Read #{packet_bytes.size} parsed packets in #{Time.now.utc - read_packets_start} seconds."



