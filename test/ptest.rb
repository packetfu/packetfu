#!/usr/bin/env ruby
$: << File.expand_path(File.dirname(__FILE__) + "/../lib/")
require 'packetfu_s'
include PacketFu

@s = PcapFile.new.f2a(:f=>'sample.pcap')[2]
@i = ICMPPacket.new

