#!/usr/bin/env ruby
# -*- coding: binary -*-
# This just allows you to eyeball the dissection stuff to make sure it's all right.
# Some day, there will be a proper test for it.

fname = ARGV[0] || "../test/sample.pcap"
sleep_interval = ARGV[1] || 1

require File.join("..","lib","packetfu")
puts "Loaded: PacketFu v#{PacketFu.version}"
# $: << File.join(File.expand_path(File.dirname(__FILE__)),"..","lib")

include PacketFu

packets = PcapFile.file_to_array fname
packets.each do |packet|
  puts "_" * 75
  puts packet.inspect
  puts "_" * 75
  pkt = Packet.parse(packet)
  puts pkt.dissect
  sleep sleep_interval
end
