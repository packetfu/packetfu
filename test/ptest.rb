#!/usr/bin/env ruby
$: << File.expand_path(File.dirname(__FILE__) + "/../lib/")
require 'packetfu_s'
include PacketFu

@s = PcapFile.new.f2a(:f=>'sample.pcap').first
@u = UDPPacket.new
@u.read @s

#@u.payload = @u.payload.gsub(/metasploit/,"MeatPistol")

